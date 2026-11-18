# App subscription budgeting and authoring (core kit 1.7.0)

This guide's hook counts and the worked example reproduce **kit 1.7.0**; its
browser regression selects that immutable release explicitly. The pre-sharing
slide-14 cliff below is specific to 1.7.0. Starting with **1.7.1**, identical
active hook queries share one frame subscription.

With **1.7.2** and a host that admits record observations, `useRecord` and
`useRecordList` share one record channel with up to **200 distinct active
watches per frame**. Unmount or idle inactive readers to release their watches.
The **32-subscription cap** still applies to `useQueryFeed`, raw
`window.native.subscribe`, and record hooks on hosts without record observations.
The frame bridge and host holder both enforce that cap.

## 1. Counting happens before query deduplication

The host's `readHub` deduplicates identical normalized `{ sql, parameters }` and
`{ steps, order?, limit?, offset? }` queries so only one backend `query_sql` or
`query_record` runs on the wire. **Per-frame subscription slots are counted
before `readHub` deduplication:**

- Every mounted `useQueryFeed`, `useRecord(id)` (with a usable `id`), and
  `useRecordList(source)` (with a non-empty `folder` or `ids`) opens its own
  bridge subscription and consumes one of the 32 per-frame slots.
- Two mounted components calling `useRecord(sameId)` consume **two** frame slots
  even though `readHub` shares one backend query.
- A component hidden with CSS (`hidden`, `display: none`) remains mounted in
  Preact and keeps its subscription slot open until it unmounts or passes `null`
  to the hook.

## 2. Subscription ownership and cleanup

- **Unmount offscreen readers** (or pass `null` / `''` to `useRecord` and `null`
  to `useRecordList`, which transitions the hook to `idle` and unsubscribes).
  Unmount the owning component to deactivate a `useQueryFeed` read.
- **Bound active item windows.** In a multi-item viewer (such as a slide deck or
  sectioned document), mount live readers only for a small active window (for
  example `current ± 2`, up to 5 items) rather than keeping every visited item
  mounted.
- **Share one reader per item** inside the active window and pass `record` /
  `body` down as props instead of calling `useRecord(id)` again in child
  components (such as a separate title bar, speaker notes pane, or metadata
  badge).
- **Keep pickers and menus lazy.** Mount a picker's `useRecordList` only while
  the picker is open, or reuse the already-subscribed collection list.
- **Pace background metadata hydration.** If an outline needs titles for
  off-window items, use `useRecordList` or at most one `useRecord(nextId, { body: false })`
  probe at a time rather than mounting one hook per item.

## 3. Bounded active readers versus retained snapshots

When an item leaves the active window, unmounting its `useRecord` frees its
subscription slot. If the UI still needs the item's title in an outline or
wants to retain information about previously visited items, retain a plain
snapshot in component state — **without** rewriting the kit's error or
authority semantics:

- **Never mark an error as `ready`.** Keep the kit's snapshot fields, including
  error and missing states. The example stores these without the hook's retry
  closure; its retry control belongs to the current live reader.
- **Let the kit own recovery.** Render a current `r.record` whenever present.
  The kit retains it through ordinary warm transient failures and clears it on
  definite answers. Render `deck.rows` directly for the collection; do not
  maintain another copy of its recovery policy. A newly mounted reader starts
  a new episode and may need to load again; the example does not promote an
  old off-window body into that episode's successful result.
- **Keep metadata separate from body snapshots.** A successful `body:false`
  probe does not establish that an old body is a current successful read. The
  example's metadata map cannot overwrite a failed body snapshot.
- **Clear retained state on scope and source changes.** A copied missing or
  error snapshot with no `record` must not keep an old body. Deck switches and
  observed `scope_changed` clear both maps. Actual account/database boundaries
  are enforced by the host retiring the old frame; app snapshots are not a
  substitute for that fence.
- **Honest limit of off-window snapshots:** while an item is outside the active
  window and unsubscribed, the app is not watching that individual record. An
  off-window cache cannot observe a per-record revocation until the item
  re-enters the active window (or a deck-level `scope_changed` / deck switch
  clears the map). Do not claim global real-time revocation for unsubscribed
  off-window state.

## 4. Safe Retry and why full-cap Retry is inert

Calling `r.retry()` on a failed `useRecord` / `useQueryFeed` starts a new
subscription episode; cleanup ends the previous episode.

- If the frame is still sitting at `32 / 32` open subscriptions (because leaked
  offscreen readers were never unmounted), the new `subscribe` call is refused
  locally inside the frame bridge with `subscription_limit` **before any
  request reaches the host or backend**. Clicking `Try again` appears inert.
- When other active readers leave space, the retry can reach the host. A fresh
  host cache may satisfy it without another backend query. The cold-failure
  browser case specifically proves another actual HTTP dispatch and recovery.
- In browser tests, always verify both that `Try again` increases actual backend
  query dispatches (not merely that no exception was thrown) and that the view
  recovers once the backend answers.

## 5. Why measured peaks on one fixture are not universal bounds

For a bounded window of radius $W$ (`2W + 1` items), 1 collection list, 1
optional background metadata probe, and 1 lazy picker:

$$\text{active\_subscriptions} \le 1_{\text{list}} + (2W + 1)_{\text{window}} + 1_{\text{meta}} + 1_{\text{picker}} + F_{\text{window}}$$

where $F_{\text{window}}$ is the number of mounted embedded-record or figure
subscriptions inside the active window. If each item can mount arbitrary
per-embed `useRecord` hooks, $F_{\text{window}}$ is an **unbounded additive
term**: a 19-slide fixture with at most 3 figures on one slide peaks at 10–11
subscriptions, whereas a window containing 30 embedded figures still exceeds the
32-slot cap unless embeds are also bounded or batched.

## 6. Worked example and developer diagnostics

- **Worked example:** `packages/alpha-tab-kit/examples/subscription-budget.html`
  (declaration `subscription-budget.declaration.json`) implements both the
  bounded `current ± 2` window (`?mode=bounded`) and the deliberately leaking
  anti-pattern (`?mode=leaking`) using supplied kit `1.7.0`.
- **Fake-host diagnostics:** `tab.subscriptionDiagnostics()` (and
  `window.__alphaTabHost.subscriptionDiagnostics()`) reports `budget` (32),
  `countingRule` (`"per_frame_before_dedup"`), `activeCount` (exact `Map`
  membership), `peakOpen`, `openIds`, `duplicateQueries`, `observedLimitRefusals`,
  and an actionable `hint`. Note that bridge `html_subscribe_refused` diagnostic
  events are throttled (1 per 250 ms, max 16 per frame), so
  `observedLimitRefusals` is a lower bound on frame-side refusals; combine it
  with `activeCount`, query dispatch counts, and rendered error states in tests.
- **Demo-shell holder diagnostics:** `holder.__testSubscriptionDiagnostics()`
  on `pendingLiveFrameFor` exposes the same per-frame `Map` counts plus
  `hub: session.hub().stats()`.
  Refusal detail history keeps only the latest 32 observations; separate
  observed totals and truncation metadata remain available. Hub counts cover
  the shared page hub, while `activeCount` and `openIds` belong to the frame.
- **Browser regression checks:**
  - `node --test packages/alpha-tab-kit/test/subscription-budget-example.test.mjs`
  - `node experiments/demo-shell/check-app-subscription-budget-browser.mjs`

`experiments/demo-shell/subscription-budget-harness.mjs` exports
`createSubscriptionBudgetHarness()` for another source fixture: pass HTML and
a record map to `open()`, inspect the HTTP call ledger and holder diagnostics,
and close the case and harness in `finally`. Its record-query responder handles
the supplied record/list SQL shapes and rejects unsupported operations.

The production-host runner uses the visible mode control: admitted live bundle
URLs do not allow query strings. Fake-host tests may use `?fastRetry=1`; the
production-host journey exercises the unchanged source with default kit retry
timings. Its fixture admission, actual HTTP dispatches and source/kit/host
digests are printed with the results. Engine data and install pins are fixtures;
this is not a live-engine or person-adoption check.
