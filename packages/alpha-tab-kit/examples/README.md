# Source-only examples

Complete HTML documents for the supplied kit, like `starters/` but for features the
Native MCP builder guide does not carry as full source. Install one using its
matching `.declaration.json`.

- `work-queue.html`: the complete proposal → edited and approved brief → agent
  → linked result loop over the existing supplied kit. Includes per-task device
  drafts, an explicit save/start sequence, canonical launch-key recovery and
  feedback into the original session. Run `node
  packages/alpha-tab-kit/examples/work-queue-fixture.mjs` from the repository
  root to try the simulated loop. See [the walkthrough and glue findings](../docs/work-queue.md)
  for the live record contract, capability limits and real-agent trial still owed.

- `agent-sessions.html` (core kit 1.3.0, Native Desktop): lists Paseo agent sessions with
  `useAgentSessions`, stays quiet through a transient list failure, opens the folder chooser on
  a machine and starts a session in the chosen folder, and replies to a session; writes render
  with `WriteStatus`. Without the host's `agentSessions` it says it needs Native Desktop; on a
  host still delivering kit 1.2.0 it says to open in Native with core kit 1.3.0. The API
  reference is `app-kit-core-1.3.0` (read it through `read_guide`).

`test/agent-sessions-example.test.mjs` runs the example in Chromium against the real bridge
protocol (it skips, like the other browser tests here, without Playwright).

- `field-toggle.html` (core kit 1.7.0): opens one record by id through two
  WorkItem-only subscribers (`useRecord` plus a one-row `useRecordList`), and
  flips a task lifecycle between `open` and `completed` with `update_record`
  (`id`, `reason`, `lifecycle`, optional plain-text `summary` draft) rendered
  through `useWrite` + `WriteStatus` with Retry/Discard and the refusal reason
  beside the entry. The toggle stays off for anything but task
  open/completed; other shapes stay subject to normal admission. Drafts are
  per-record component state and survive a refusal; an account or workspace
  change drops every entry and draft and locks submission until reload, and a
  reload keeps nothing. Create-list prediction is deferred until the backend V2
  contract accepts an explicit create `id` (ordinary V2 `create_record`
  refuses `id` except for messaging sends); this example toggles a loaded task
  only. It shows safe write feedback plus the host's SQL read delivery — no
  shared optimistic paint (pre-settlement shared delivery is proven only for
  steps queries under R5b). Core kit 1.7.9 lays this app's own pending
  `update_record` over `useRecord`/`useRecordList` for the app itself.

Behavior is proved against the actual file in
`test/field-toggle-example.test.mjs` (Chromium through the fake host's real
bridge; it skips, like the other browser tests here, without Playwright):
validator reports no errors and the package passes admission, the task reads
through two subscribers, the toggle sends the frozen `update_record` plus key,
a refusal keeps the editable draft with Retry and shows its reason, record
navigation keeps per-record drafts and entry targets, unsupported tokens never
send, a held-call timing case captures the observed sequence (Sending shown
and the new lifecycle laid over the record at once, unchanged by the fixture's
fresh rows, until the write is confirmed), an uncertain write retries under its
original key, and a list-only scope fence drops the entry and draft, disables
the toggle, and leaves the late answer changing nothing. Helper/host
internals otherwise stay with the existing suites.

- `subscription-budget.html` (core kit 1.7.0): demonstrates per-frame
  subscription budgeting (`32` live subscriptions per frame counted before
  host `readHub` deduplication) across a multi-slide reader. Supports
  `?mode=bounded` (default: `current ± 2` active window, one background
  metadata probe, lazy picker, and retained off-window snapshots that preserve
  kit `missing`/definite-error/`scope_changed` clearing) and `?mode=leaking`
  (retains visited slide readers and duplicate per-slide hooks until slide 14
  hits `subscription_limit`). Includes an embed-heavy deck (`deck-embeds`)
  showing why embedded figure subscriptions (`F_window`) remain an additive
  term. See `docs/subscription-budget-authoring.md` and
  `test/subscription-budget-example.test.mjs`.

- `shared-task-metadata.html` (core kit 1.7.0): one shared `WorkItem`/`task`
  field update through a fixed bounded steps query (`types`/`kinds`/`ids`
  for author-chosen known task id(s), `order: 'name_asc'`, `limit: 200`)
  with lifecycle displayed, never filtered. Projects exactly `id`, `type`,
  `kind`, `name`, `summary`, `home_id`, `lifecycle`, `maturity`,
  `updated_at`, `last_activity_at`; omits `body`, `created_at`,
  `updated_at_ms`, `is_current`. Writes send only
  `id`/`reason`/`name`/`summary`/`lifecycle` through `update_record`
  with `useWrite` + `WriteStatus`. Documented in
  [`../docs/shared-field-updates.md`](../docs/shared-field-updates.md):
  choose actual known workspace task id(s) instead of querying the whole
  workspace; shared pre-settlement overlay paint holds only on the current
  unscoped local store, scoped/behind reads keep hosted fallback; paint is
  not durable custody; refusal removes the prediction but keeps the full
  draft with reason, uncertain keeps its key for canonical catch-up; reload
  and scope changes drop page-only drafts with no auto replay. Proved
  against the exact file by the existing required R5b browser proof
  (`experiments/demo-shell/check-app-pending-writes-browser.mjs`); default
  SQL reads stay non-optimistic (kit 1.7.9 composes only this app's own pending `update_record` into `useRecord`/`useRecordList`) and this example
  updates a loaded task only, never a new record.
