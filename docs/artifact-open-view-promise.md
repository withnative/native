# Open-view update promise for artifacts

This is the engineering contract for what a person sees an **already-open**
artifact do, without reloading the page, when the records it is bound to
change. It exists so that "live" can be said honestly, and so that the tests
named below are the thing that would fail if the promise stopped being true.

It covers the Workbench artifact surface (the record view and the standalone
presentation route) for `native.mdx.v2` and `native.html.v1`. Anything not
stated here is not promised.

## The promise

An open artifact reflects a change to a record it is bound to, in the same
tab, with no user action, after a server re-resolution issued after the
change is received. The page is not reloaded. Which parts of the rendered
surface survive that re-resolution depends on the runtime, and is stated per
runtime below.

Four questions define the promise. Each is answered here.

### What updates

| Runtime | What the person sees | What survives |
| --- | --- | --- |
| `native.mdx.v2` | The host resolves a fresh safe-tree plan from the current input bundle and re-renders it **in place**. | The page, the host DOM, and the component tree. The previous plan stays painted, marked `aria-busy`, until the new one settles. |
| `native.html.v1` | If the server-computed input digest changed and the body digest did not, and the document has subscribed with `nativeArtifact.onInput`, the host delivers the new input **in place** over the bridge and the existing iframe is kept. If the document has not subscribed, does not acknowledge within the bounded wait, or the body digest changed, the host mints a fresh one-use launch and **replaces the iframe** with a new element at the new URL. If neither digest changed, the existing iframe is kept and its `src` is not touched. | The page and host DOM always survive. Frame-internal JavaScript state survives an unchanged refresh and, for a subscribed document, a changed input; an unsubscribed document or a changed body relaunches the document from its authored start. |

Both changed-input legs of the HTML row are proven end to end by the two HTML
tests named below: in-place delivery for a subscribed document, relaunch for
an unsubscribed one. The unchanged-refresh leg, the body-digest leg, the
fallback to relaunch when a subscribed frame refuses or does not acknowledge
an update, and the fail-closed replacement when a refresh carries no digest
or revision evidence rest on the unit tests cited under Proof.

MDX v2 updates are therefore continuous. HTML v1 updates are continuous for a
document that subscribes to input updates, and a relaunch otherwise: correct,
without a page reload, and without frame-local state. An HTML artifact that
must keep state across an input change subscribes with
`nativeArtifact.onInput` and re-renders from the delivered input; the bridge
delivers a frozen bundle and always answers an ordered delivery —
`input-applied`, including idempotently for an already-applied digest, or
`input-unhandled` with a reason (`no-subscriber`, `subscriber-threw`,
`stale`, `freeze-failed`) — so the host knows whether the frame took it, and
relaunches on anything else after one bounded wait. Messages that fail the
trust checks are dropped silently and likewise end in a relaunch.

### On what trigger

The Workbench holds one server-sent event stream per database
(`GET /databases/{db_id}/events`). The stream carries content invalidations,
authorization invalidations, a `ready` fence, and cursor resets. The artifact
host reacts to them as follows.

- **Content invalidation** (any record write in the database, by anyone, from
  any client). Record queries are invalidated and the host raises an artifact
  fence at the event's sequence. An open MDX v2 artifact re-resolves until the
  `content_event_seq` in its input-bundle receipt reaches that fence, and
  refuses to repeat a chase that moved nothing. An open HTML v1 artifact has a
  one-use render key, so each content event mints one fresh resolution; the
  digest comparison above decides whether the frame is kept, updated in
  place, or replaced.
- **Authorization invalidation** (a genuine change to what the caller may
  read). This is a **recheck, not a refresh**. The painted plan stays visible
  and the host re-reads under the new authority. A settled denial clears the
  surface; a slow or transiently failing recheck does not.
- **`ready`** (stream connect or reconnect). Treated as a fence at the stream's
  current head, so an artifact opened while the stream was down converges
  once it is back.
- **Cursor reset**. Everything is refetched from scratch, including footing.

A change to a record the artifact is **not** bound to still raises the fence.
Nothing visible happens. The cost is a fresh re-resolution per content event,
and for MDX v2 no repeated chase once the receipt stops moving. No test counts
re-resolutions; the tests prove that a post-change render lands, not how many.

Interactions dispatched *from* an artifact (`native.mdx.v2` only) reconcile
their own write result through the `refresh.record` path described in
[artifact-runtimes.md](artifact-runtimes.md). That is the write-result path,
not this stream path, and the two compose: an interaction's write is also a
content event for every other open view of the same records.

### Within what latency

No wall-clock bound is promised. The bound is causal: the update lands after
**a server re-resolution issued after the event is received**, and the tests
below assert that ordering rather than a duration or a count.

What that re-resolution costs is the honest part of the promise:

- For `native.mdx.v2` the re-resolution is a server render of the artifact.
  Live Collection-port envelopes are held in a process-global cache keyed by
  origin, head event, authorization epoch, caller principal, meta-tier digest
  (`schema_config` / vocabularies), and binding event seq, so a repeat of an
  unchanged artifact restores those ports instead of re-resolving them. An
  optional `revalidate` token copied from a previous live result can return
  `unchanged` (no tree) when that identity still matches. A large artifact
  can still take seconds on a cold render or when content or authorization
  has moved; the bound remains causal rather than a wall-clock number.
- For `native.html.v1` the re-resolution is an input resolution plus a fresh
  launch descriptor. A subscribed document receives the resolved input over
  the bridge and never fetches that launch; an unsubscribed document fetches
  the one-use document.

If a number is ever published it must come from measured renders on the
artifact in question, not from this document.

### What is not covered

- **Data that is not a bound input.** An artifact sees only records resolved
  through its declared and granted ports. A change to anything else is not
  reflected, because it was never delivered.
- **Non-record state.** Agent presence, run status, and any other state that is
  not a record write does not produce a content event and does not update an
  open artifact.
- **Unauthenticated or public surfaces.** There are none. The presentation
  route requires a signed-in session; a signed-out visitor is sent to sign in.
- **A disconnected stream.** While the stream is down nothing updates. On
  reconnect the `ready` fence triggers convergence; that is a catch-up, not a
  guarantee about what was missed while offline.
- **Frame-local state in HTML v1** across a changed input when the document
  has not subscribed to input updates, and across a changed document body in
  every case, as stated above.
- **`native.mdx.v1` and `native.board.v1`.** Not claimed. Both share the
  retained render key and receive the same invalidations, but `native.board.v1`
  is deprecated and no test asserts fence convergence for `native.mdx.v1`.

## Proof

Three journeys run against a real server in the `security-render` shard of the
real-server Playwright harness (`web/workbench/e2e/real-server.spec.ts`),
with zero retries. Each opens the artifact in a fresh tab, fences the stream
at the sequence already painted, stamps a marker on `window`, performs the
write **out of band** through the tool route, and asserts the visible change,
that the marker survived, that the receipt's `content_event_seq` advanced,
and that its `authorization_revision` did not.

| Runtime | Test title |
| --- | --- |
| `native.mdx.v2` | `a facet-grouped BarChart refreshes from one atomic real-server input snapshot` |
| `native.html.v1`, unsubscribed document (relaunch) | `an open native.html.v1 artifact reflects a bound record change without a reload` |
| `native.html.v1`, subscribed document (in place) | `an open native.html.v1 artifact updates in place when a subscribed document's bound record changes` |

Unit coverage for the host behaviour the tests rely on lives in
`web/workbench/src/App.test.tsx` (`artifact realtime invalidation`,
`artifact render cache under realtime pressure`),
`web/workbench/src/ArtifactContinuity.test.tsx` (`one-use html artifact
continuity`), and `web/workbench/src/artifactRealtime.test.ts`. The
presentation route shares the record view's continuity decision
(`decideHtmlContinuity`), and its unchanged-refresh, in-place, and relaunch
legs rest on the `ArtifactPresentationPage.test.tsx` unit tests — no
real-server journey exercises that route.

## Where the behaviour lives

- `web/workbench/src/artifactRealtime.ts`: the per-event policy.
- `web/workbench/src/query/keys.ts`: `artifactRenderQuery` (retained key for
  inert runtimes, one-use key for HTML) and the record families each event
  invalidates.
- `web/workbench/src/App.tsx`: stream wiring, the fence raise, the fence-chase
  effect, and `ArtifactSurface`, which owns painted-plan continuity and the
  HTML digest comparison. `ArtifactPresentationPage.tsx` carries the same
  fence memory for the standalone route, and holds its own HTML continuity
  state through the same shared `decideHtmlContinuity` decision, so an
  unchanged refresh, an in-place input delivery, and a relaunch behave the
  same on both routes.
- The fence-chase effect is live only for runtimes whose plan carries an
  input-bundle receipt readable by `artifactInputRevision`, which today means
  safe-tree plans (MDX v2). For HTML v1 that function returns `null`, the
  effect never chases, and convergence rides entirely on the one-use key
  moving with each content event. Do not "fix" HTML convergence by teaching
  `artifactInputRevision` to read the isolated-HTML receipt without also
  deciding what a chase should do to a one-use launch.

## Changing this promise

This document and the Native decision record that states the product-facing
promise must say the same thing; this file is authoritative for engineering
detail. Widening the promise requires a test in the table above. Narrowing it
requires updating both and the homepage framing that cites it.
