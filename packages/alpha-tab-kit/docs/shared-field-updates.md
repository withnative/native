# Shared field updates (authoring guide)

One shared `WorkItem`/`task` field update through one fixed bounded
steps query over already-loaded metadata, using only the existing
public core kit 1.7 API (`useQueryFeed(StepsQuery)` + `rowsOf` +
`useWrite`/`WriteStatus`). On the currently covered path — a current
unscoped local store plus a supported loaded-metadata update — every
subscriber on the same page's unscoped hub and current store paints the
same predicted value before the server answers; no cross-tab or global
promise is made.

Full source: [`../examples/shared-task-metadata.html`](../examples/shared-task-metadata.html),
declaration: [`../examples/shared-task-metadata.declaration.json`](../examples/shared-task-metadata.declaration.json).
Install one using its matching `.declaration.json`, as with the other
source-only examples. The historical experimental pilot source at
`experiments/demo-shell/pilots/steps-field-toggle.html` is retained as
history; the example above is the documented author source.

## What authors build

```js
const TASK_ID = 'steps-pilot-task'; // replace with one actual known workspace task id
const QUERY = {
  steps: [{ step: 'filter', types: ['WorkItem'], kinds: ['task'], ids: [TASK_ID] }],
  order: 'name_asc',
  limit: 200,
};

const feed = useQueryFeed(QUERY);
const snapshot = feed.status === 'ready' ? feed.result : feed.last;
const rows = rowsOf(snapshot);
const row = rows.find((item) => item && item.id === TASK_ID) || null;

const writer = useWrite({ operation: 'update_record' });
const ticket = writer.submit({
  id: TASK_ID,
  name: draft.name,
  summary: draft.summary || null,
  lifecycle: draft.lifecycle,
  reason: draft.reason || 'Shared field update',
});
```

Render each entry with `WriteStatus` (Retry/Discard). `FeedNotice`,
`Loading`, `Empty`, and `ErrorState` cover the read, as in the example.

## Choosing actual known task id(s)

Pick one (or a few) task id(s) you already know in the workspace —
from the task you are working, a link the person gave you, or a record
your app already holds. Put those literal id(s) in `ids: [...]`. The
example is usable without querying the entire workspace: it never lists
`WorkItem` broadly, never invents an arbitrary SQL membership
prediction, and never predicts a `create`.

If the id has no row in the local answer, the app may still fall back
to the hosted read and wait. An exact empty result from the local
answerer or the hosted read shows Empty and disables submit; a held id
can be filtered out by type/kind/archived status. An unsupported host
is a different case: the feed reports `unsupported`, the app shows that
notice, and hosted recovery is not promised there.

## Exact query subset

- `steps` filter with `types: ['WorkItem']`, `kinds: ['task']`,
  `ids: [<known id(s)>]`, plus `order: 'name_asc'`, `limit: 200`.
  The 200 is this example's bounded choice within the local 500 cap
  (`LOCAL_QUERY_MAX_LIMIT` in
  `experiments/demo-shell/public/lib/localQuery.js`), not a global
  host cap.
- Lifecycle is **displayed**, never a membership filter. No new-record
  membership prediction, no arbitrary SQL, no query-membership
  invention.

## Exact local fields (and omissions)

Projected row columns are exactly:

`id`, `type`, `kind`, `name`, `summary`, `home_id` (visible home or
`null`), `lifecycle`, `maturity`, `updated_at`, `last_activity_at`.

These are the ten columns the read hub normalizes for local and
hosted answers alike (`RECORD_QUERY_COLUMNS` in
`packages/native-launcher/src/readHub.mjs`).

Omitted and never read or manufactured here: `body`, `created_at`,
`updated_at_ms`, `is_current`. Do not invent SQL columns beyond this
list.

## Fallback and timing

- The immediate pre-settlement shared overlay paint holds only on the
  currently covered path: a current unscoped local store plus a
  supported loaded-metadata update. There every subscriber on the same
  page paints the predicted value before the held HTTP answers, while
  confirmed and persisted rows stay old.
- Scoped / folder-grant / behind / uncovered reads keep the normal
  hosted fallback and recovery and may wait. Do not claim locally
  projected values there.
- Paint is **not** durable custody or an accepted save. Per status:
  while pending, an older read or a pre-receipt catch-up keeps the
  prediction and never retires it; a successful receipt waits for the
  post-receipt qualifying canonical catch-up, and only that retires it;
  a definitive refusal removes the prediction at once while the full
  editable draft and its reason stay on screen; an uncertain outcome
  keeps its original key and reconciles on the authorized qualifying
  canonical catch-up, with no receipt required and none claimed. A
  stale answer never restores a prediction.

## Write, refusal, uncertainty, reload

- Writes send only `id` / `reason` / `name` / `summary` / `lifecycle`
  through `update_record`. The submitted request is frozen intent.
- A definitive refusal (for example HTTP 409) restores the projection
  while preserving the full editable draft and its reason beside the
  entry, with Retry/Discard.
- An uncertain outcome keeps its original idempotency key and
  reconciles through the authorized canonical catch-up. Current
  admission can refuse after revocation; there is no guaranteed receipt
  and no no-effect claim from an uncertain answer.
- Automatic retry of the old logical slot is origin-fenced (merged
  host `e0fac02344bec340954bf3b737dcc46f4eefea91`): a held call
  answered while away settles uncertain under its original key with no
  redispatch, no revival on return, and no cross-slot reuse. A manual
  new slot with the original key requires current admission in the same
  database.
- Drafts and helper entries are page-only memory unless the app already
  wires an explicit acknowledged persistence. This example wires none
  and adds no new custody.
- A full child-document reload orphans the frame holder: the reloaded
  frame keeps its static boot content with no kit-driven resubmission
  in the bounded stability window, drafts are gone, and the sibling
  frame keeps rendering the canonical value. No auto-replay or
  remount-recovery promise.
- Account/workspace scope changes clear old intent and disable old
  controls; a detached frame set closes every live holder and a late
  answer sends nothing new. Do not confuse an unsent-draft scope leg
  with a held-scope proof: the former proves nothing auto-sends, the
  latter proves the held slot never redispatches.

## Proof boundary (current merged host)

Proved against the exact promoted source by the existing required R5b
browser proof
(`experiments/demo-shell/check-app-pending-writes-browser.mjs`,
controlled HTTP + live pin + `injectBridge` with current public kit
1.7 pinned): two opaque frames share the pending lifecycle before the
held transport result while confirmed/persisted stay old; refusal
removes the prediction from both views with the full draft kept; an
older read and the pre-receipt catch-up keep the prediction and only
the qualifying canonical catch-up retires it; scope, reset, reload,
detach, and the current-retry legs hold. Fixture canonical
snapshots/deltas are the authoritative read model there; predicted
rows are never pushed by hand. No live-engine, Rust-injector, custody,
or admission proof is claimed. The unchanged raw-host fences stay
green.

Host boundary for this document is the merged host at
`e0fac02344bec340954bf3b737dcc46f4eefea91`.

## What this does not do

- No generic optimism claim: the shared paint holds only on the
  covered path above.
- Shared delivery to other apps stays non-optimistic. From core kit 1.7.9 the
  app's own pending `update_record` is laid over its `useRecord`/`useRecordList`
  until the host confirms it, and raw SQL results are never composed;
  this example updates a loaded task only and never a new record.
- This guide and example use existing shipped API and host behavior and
  do not install or publish an app; the normal reviewed install/update
  consent stays necessary.
