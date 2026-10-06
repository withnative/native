# @withnative/alpha-tab-kit

Check, digest, host locally, and install one Native **alpha tab** package (a
`native.html.v1` bundle plus its `manage_alpha_tabs` declaration) against the
real hosted contract, from **outside** native-ce.

This is step 1 of decision [8a2ea04](https://n8v.to/8a2ea04): *alpha tabs move
to one separate repo, after a tab kit is extracted from native-ce*. The
overnight SaaS-parity run found the contract was not testable outside this
repo. Install rules surfaced only at upload, and the one-read-in-flight rule
lived only in the shell's code. As a result, three tabs passed their own checks
and broke in `/alpha/`. The kit turns those rules into something a separate
repo can run, and a drift guard in native-ce keeps it in step with the engine.

Plain Node ESM (Node ≥ 20) with no dependencies. Playwright is an optional peer,
needed only for the browser half of the fake host.

## What is in it

| Part | Entry point | What it does |
|---|---|---|
| Digest | `src/digest.mjs`, `alpha-tab-kit digest` | Computes `bundle_sha256`, `declaration_digest` and the install `digest` (`alpha-tab-digest.v1`) byte-for-byte as the engine does. |
| Validator | `src/validate.mjs`, `alpha-tab-kit validate` | Runs locally every install-time rule found in source. Each failure names the rule and the source line it mirrors. |
| Fake host | `src/fake-host/`, `alpha-tab-kit serve` | Serves the tab with the **real bridge script** under the real CSP, behind a parent page that behaves like the alpha shell. |
| Install route | `src/install.mjs`, `alpha-tab-kit install-plan` | Produces the proven chunked, digest-guarded install as exact MCP calls. It can also run them through an MCP client you inject. |
| Limits | `limits.json`, `alpha-tab-kit limits` | Holds every number the kit enforces, each tied to the Rust symbol, bridge literal or shell literal it mirrors. |
| Drift guard | `src/mcp/tools/alpha_tab_kit_drift.rs` (engine), `test/drift-js.test.mjs` (shell and bridge) | Fails when the engine moves and the kit does not. |

## Quick start

```bash
# every local install rule; exit 1 on any error
node packages/alpha-tab-kit/bin/alpha-tab-kit.mjs validate my-tab-descriptor.json

# digests; --write stores them in the descriptor
node packages/alpha-tab-kit/bin/alpha-tab-kit.mjs digest my-tab-descriptor.json --write

# how far the deployed server is behind main (input: a saved render_artifact result)
node packages/alpha-tab-kit/bin/alpha-tab-kit.mjs hosted render.json

# open the tab in a local host that behaves like /alpha/
node packages/alpha-tab-kit/bin/alpha-tab-kit.mjs serve my-tab-descriptor.json --fixtures my-tab-fixtures.mjs

# the install, as exact MCP calls (one JSON file per call)
node packages/alpha-tab-kit/bin/alpha-tab-kit.mjs install-plan my-tab-descriptor.json \
  --home <folder id> --reason "Install my tab 0.1.0" --source <task id>="The task this belongs to" --out plan/
```

A descriptor is the install arguments plus the bundle path. It uses the same
shape the demo tabs use:

```json
{ "package": "agent.my-tab", "version": "0.1.0", "bundle": "my-tab.html",
  "runtime": "native.html.v1", "declaration": { "needs": [...], "effects": [] },
  "digest_version": "alpha-tab-digest.v1", "bundle_sha256": "…", "declaration_digest": "…", "digest": "sha256:…" }
```

## What it guarantees, and where each rule comes from

Line numbers are as of this commit; the symbol or function name is the durable
anchor.

### Digest: exact

- `bundle_sha256` is SHA-256 over the exact body bytes (`alpha_tab_bundle_digest`, `src/mcp/tools/alpha_tabs.rs:720`).
- `declaration_digest` is SHA-256 over the RFC 8785 JCS bytes of the canonical declaration (`alpha_tab_canonical_declaration` :770, `alpha_tab_declaration_digest` :840, `src/canonical_json.rs`). The canonical declaration is built as follows:
  - string `needs` and `effects` are sorted by UTF-8 bytes;
  - `sql_needs` is present only when the declaration has SQL needs;
  - params keep their declared order, since that order is the `?N` binding;
  - text params carry `max_len`.
  - A malformed SQL entry fails closed rather than digesting as absent.
  - `records.facet-set.v1` objects canonicalize with their full bounds (`effect`, `key`, `target`, values sorted by UTF-8 bytes), ordered after the strings by the hex of their JCS SHA-256 — never raw-JSON order. Strings keep their historical sorted order, so a string-only declaration digests byte-identically. An invalid object throws instead of digesting as absent.
  - `comment.create.v1` objects canonicalize with their full bounds (`effect`, sorted `positions`, `target`, `max_body_bytes`) in the same global hex-of-JCS order as facet-set objects: all object rows sort together, after the strings. Widening (cap, positions, need) or permutation moves the digest and requires re-adoption. An invalid object throws instead of digesting as absent.
- `digest` is `sha256:` + SHA-256 over JCS `{bundle_sha256, declaration_digest, runtime}` (`alpha_tab_digest` :851).
- Test vectors (`test/vectors/digest-vectors.json`, recomputed by both the kit and the engine):
  - the host's own vector (`alpha_tab_digest_vectors`, :5397 → `sha256:abd4e377…`);
  - Slack 0.1.0's declaration and install digest as installed on 28 Sep. The server confirmed the declaration digest (`3e78e51d…`), so this vector covers SQL needs with params;
  - a reordered copy of that declaration, which must digest the same;
  - a `records.facet-set.v1` bound (`7eddf1c0…`), which pins object ordering, value sorting and widening sensitivity across languages;
  - a `comment.create.v1` bound, a whole-number `100`/`100.0`/`1e2` parity case, a widened-cap case, and a mixed facet+comment case pinning cross-kind global hex ordering.

### Validator: install-time rules

**Mirrored exactly** (the same checks on the same inputs):

| Rule | Mirrors |
|---|---|
| declaration shape: exactly `needs` + `effects`; ≤ 64 entries each; names 1..128 bytes; entries are strings or sql objects | `require_declaration`, `alpha_tabs.rs:1783-1866` |
| ≤ 8 `sql.snapshot.v1` needs, unique keys, no key shadowing a string need | :1843, :1851, :1862 |
| sql need exactly `need, key, label, sql[, params]`; key `^[a-z][a-z0-9_.]{0,39}$`, not a host need name | `parse_sql_need_entry` :306, :315, :326 |
| **label 1..120 characters** (Unicode scalars, not bytes) | :335, `SQL_SNAPSHOT_LABEL_MAX_CHARS` :122 |
| **SQL 1..4096 bytes** | :344, `SQL_SNAPSHOT_SQL_MAX_BYTES` :123 |
| params: ≤ 8; exactly `name, type[, max_len][, required]`; name `^[a-z][a-z0-9_]{0,31}$`; type `text \| integer \| timestamp_ms`; `max_len` 1..1024, text only; `required` boolean; no duplicates | `parse_sql_param_entry` :223-285, :352, :364 |
| `records.facet-set.v1` bound: exactly `effect, key, values, target{need}`; key trimmed, nonempty, ≤ 128 UTF-8 bytes, an ordinary facet (spine, engine-dispatched, record-field and `triage` keys refused); values a set of 1..64 unique strings ≤ 128 UTF-8 bytes each (empty string allowed), sorted by UTF-8 bytes; target exactly one declared static sql-need key; no bare family string, unknown field/name, duplicate key or value, or undeclared need | `parse_facet_set_bound` :1891, `parse_facet_set_bounds`, `is_ordinary_facet_key`, `src/mcp/tools/tab_effect_catalogue.rs:79` |
| `comment.create.v1` bound: exactly `effect, positions, max_body_bytes, target{need}`; `positions` a nonempty unique subset of `root`/`reply` (1..=2, sorted UTF-8); no position in more than one bound across the declaration; `max_body_bytes` an integer 1..=4096 with whole-number `100`/`100.0`/`1e2` parity; `target` exactly one declared static need key (`^[a-z][a-z0-9_.]{0,39}$`); no bare family string, unknown field/array entry, duplicate position, global overlap, or undeclared need | `parse_comment_create_bound` :2377, `parse_comment_create_bounds` :2490, `COMMENT_CREATE_EFFECT`/`COMMENT_CREATE_MAX_BODY_BYTES` `src/mcp/tools/tab_effect_catalogue.rs:46,51`, `COMMENT_CREATE_POSITIONS` `alpha_tabs.rs:2372` |
| package reverse-DNS id (≥ 2 labels of `[a-z0-9-]`, ≤ 32 each, ≤ 128 total); version `X.Y.Z` (≤ 8 digits a part); digest `sha256:` + 64 lowercase hex | `require_package` :1715, `require_version` :1740, `require_digest` :1755 |
| SQL: starts with SELECT/WITH; no forbidden word (insert, update, pragma, attach, …); no `current_date` / `current_time` / `current_timestamp`; one statement | `classify_single_read_statement`, `crates/query-contract/src/sql_contract.rs:2221-2317`, :4097 |
| SQL placeholders: only `?N` (1-based, ≤ 256, no leading zero); the set of N must equal 1..params.length | `placeholder_end` :2519, `check_positional_arguments` :2403; wrapped at `alpha_tabs.rs:391-400` |
| SQL dropped functions (`group_concat`, `json_*`, `glob`, `date`, `instr`, …) | `DROPPED_FUNCTION_REPAIRS` :2896 |
| HTML preamble: exact `<!doctype html>`, then `<html…>`, then an attribute-free `<head>` | `bootstrap_insertion_offset`, `crates/artifact-html/src/html.rs:1131` |
| HTML size ≤ 524,288 bytes; doctype regex; exactly one `<html`, `<head`, `<body` **counted textually**, so matches in comments and script strings count too | `validate` :1557-1582 |

**Mirrored on a token stream or tag scan.** These rules need SQLite's parser or
html5ever in the engine. The kit approximates them and is designed not to
invent failures (all seven demo tabs pass):

| Rule | Mirrors |
|---|---|
| **LIMIT needs ORDER BY at the same query level**, including subqueries and CTEs | `check_limit_order`, `src/query/turso_ast_rules.rs:117` |
| relations are the 16 logical relations or CTE names | `LOGICAL_RELATIONS` `sql_contract.rs:60`, `authorize_strict` `src/query/sql.rs:1197` |
| functions are the 24 portable ones (+ `like`); two-argument `round`, `now_ms()` arity, `utc_date_label` arity | `FUNCTION_REGISTRY` :2695, `authorize_strict` `sql.rs:1207`, :3340-3558 |
| ≤ 64 output columns; no duplicate output labels (for the forms it can resolve) | `alpha_tabs.rs:408`, `sql.rs:1255` |
| HTML envelope: `html[lang]`, one non-empty `<title>` | `html.rs:1598` |
| forbidden elements, `script[src]`, import maps, `<link>`, `form[action]`, CSP/refresh meta, URL-bearing attributes (except `img src` data assets and `a href="#…"`), host-navigation attributes | `inspect_node` `html.rs:1255-1491` |
| CSS: no `@import` or `image-set`; the text `http:`, `https:` or `url(//` anywhere outside comments is refused; `url()` must be `data:` or `#`; ≤ 5,000 rules | `html.rs:1662-1706` |
| data assets: MIME png, jpeg, webp, avif or woff2; ≤ 256 KiB each; ≤ 384 KiB total | `decode_data_url` `html.rs:1503`, :1544, :1714 |

Legacy Collection input admission allows 20,000 records. Both legacy and named
inputs allow 16 MiB of serialized JSON per render/bridge delivery. Encoded
metadata and duplicated named/aggregate
records count toward the byte budget. These limits provide headroom for larger
workspaces; they do not grant access or limit a document's editable body. The
host still authorizes bound membership and caps aggregate ticket storage.
`compareHosted` reports older servers' input limits separately, so a local kit
upgrade alone never claims that the hosted server accepts the larger input.

**Accessibility rules, strict by default.** Current source (since `ffd9c76cd`,
27 Sep) only *advises* on:
- `<main>` count (`html.rs:1642`);
- a missing `<h1>` (:1655);
- heading order (:1047);
- `img[alt]` and positive `tabindex`.

The overnight install run on 28 Sep, however, reported the hosted server
refusing a missing `<main>`, a second `<h1>`, and a skipped heading level (see
`README-miro-board.md` on `demo-tabs-all`). Production's own runtime descriptor
confirms it predates the change (see *When to flip the strict default* below).
So `validate` treats `<main>`, a missing or second `<h1>`, and heading order as
errors by default (`STRICT_DEFAULT` in `src/html.mjs`). `--no-strict` downgrades
all four to warnings and matches current source, except that a second `<h1>`
is a kit-only warning: source accepts several.

#### When to flip the strict default

Flip `STRICT_DEFAULT` to `false` once hosted production runs `ffd9c76cd` or
later. That commit moved the HTML validator and adapter revision from 2 to 3,
and those two numbers are what the server reports about itself.

1. Call `render_artifact` (`artifacts_execute`; it writes no record) on any
   `native.html.v1` artifact that renders without a bound input, and save the
   JSON result.
2. Run `alpha-tab-kit hosted <saved.json>`. It compares `runtime.validator.version`,
   `runtime.adapter_revision` and the bridge digest (`runtime.delivery_transform.digest`)
   with main's (`limits.json` `bridge.*`, which the drift guard keeps equal to
   the engine). Its `advice` says whether the default can flip.
3. If `validator_version` is 3 or more, flip the default. That is a one-line
   change, `export const STRICT_DEFAULT = true;` becoming `false` in `src/html.mjs`.
   Update the dated comment above it and `test/html.test.mjs`, whose
   default-mode expectations change with it.

**As of 28 Sep 2026, keep it strict.** Production (`native-ce-production`)
reported `adapter_revision 1`, `validator.version 1`, and bridge digest
`89574d1d…`. Main is at 3 and 3, with bridge digest `fcec50a8…`. That response
is kept as `test/fixtures/hosted-render-2026-09-28.json`.

**Warnings.** A snapshot need with no top-level `LIMIT ≤ 200` is flagged,
because the host delivers at most 200 rows and truncates the rest
(`SQL_SNAPSHOT_ROW_CAP`, `alpha_tabs.rs:130`). The result says so in
`truncated`, but only a tab that reads it will tell the viewer (see *Result
completeness* below).

**Not mirrored.** For these, the real `query_sql` or install is the only
authority, so run each statement once with `query_sql` before installing:
- bare `GROUP BY` columns (`turso_ast_rules.rs:644`);
- `SELECT *` under `GROUP BY` (:857);
- whether columns exist;
- `regexp` pattern checks;
- the 2 s deadline and the 256 KiB cell / 4 MiB result ceilings;
- no-quirks parsing, the exact DOM node count, slide-deck structure, and the named-input manifest grammar.
- parameter/time-dependent need gating for `comment.create` (and facet-set): install parses any syntactically valid static need key; the write-transaction membership gate refuses parameterised or time-dependent targets at runtime. The kit does not invent a stricter install refusal.

`validate --json` lists these as `not_mirrored`.

**Comment scope.** The kit covers declaration, digest and validation parity for the `comment.create.v1` effect and its body-cap and position bounds. Engine and host runtime enforcement live outside this package. The repository's `alpha_tab_kit_drift` tests compare these declared limits with the engine constants.

**Reaction tab proposal (`src/message-react.mjs`, 07ae879 I3).** Frame-side only, zero tool calls: `buildMessageReactProposal({ requestId, entryId, messageSlot, messageId, emoji, reacted })` builds `{ request_id, entry_id, slots, values }` for `window.nativeArtifact.propose` — the target message in the entry's single bound slot, the `{ emoji, reacted }` pair in values. `messageSlot` defaults to `"message"` and must name the manifest entry's single `bound_input` slot exactly; a frame using the default against a differently named slot is refused at host preflight. The emoji must be one of the five canonical v1 picker values; `reacted` is the desired state (`true` adds, `false` removes). The host owns the install pin, launch proof, need-row membership, invocation, idempotency key, and receipt; `messageReactOutcomeText(result)` renders honest sequence-free tab copy. Like the comment thread tab, the frame proposes and never invokes.

### Result completeness: surface `truncated` and `row_count_complete`

Every `sql.snapshot.v1` result, snapshot or on-request, carries
`{label, columns, rows, row_count, row_count_complete, truncated, truncation_hint, now_ms_ms, time_dependent}`
(`SQL_NEED_RESULT_FIELDS`, `alpha_tabs.rs:163`; `limits.json`
`reads.sql_result_fields`, drift-checked). Two caps apply, in order:

1. `query_sql` stops at **1,000 rows** (`MAX_ROWS`). `row_count` is then 1,000
   and `row_count_complete` is `false`: the count is a floor, not a total.
2. The host delivers at most **200 rows** (`SQL_SNAPSHOT_ROW_CAP`).
   `truncated` is `true` whenever either cap dropped rows.

| Visible rows the statement matches | `rows` | `row_count` | `truncated` | `row_count_complete` | Say |
|---|---|---|---|---|---|
| 150 | 150 | 150 | false | true | "150" |
| 700 | 200 | 700 | true | true | "200 of 700" |
| 1,050 | 200 | 1,000 | true | **false** | "200 of more than 1,000" |

**A package must surface both.** A tab that reads `rows` and never reads
`truncated` presents a prefix as the whole answer. A tab that reads
`row_count` and never reads `row_count_complete` can print a false "of N"
past 1,000 rows. `validate` warns on each (`reads.surface-truncated`,
`reads.surface-row-count-complete`).

These checks are **advisory**: both findings are warnings, so neither
`validate` nor `planInstall` ever refuses a package because of them. They are
lexical (`src/completeness-lint.mjs`, no parser dependency), and a lexical
check must not be able to refuse a correct package.

- A small tokenizer skips comments and string, template and regex literals,
  and still scans code inside `${…}`. Text in a string never counts as a
  read; a string counts only as a computed key (`result["truncated"]`).
  Telling a regex from division is best-effort: a regex straight after a
  control-flow head (`if (x) /re/.test(s)`) is read as division, so its text
  is scanned as code.
- A read is a property access (`x.truncated`, `x?.truncated`,
  `x["truncated"]`) or a destructuring key: in a declaration, an assignment
  (`({ truncated } = result)`), a parameter, a `for … of`, or a nested
  pattern. A write (`state.rows = []`) or an object literal
  (`report({ truncated: false })`) is not a read.
- The lint cannot tell which object a property belongs to: `table.rows` on a
  DOM table looks the same as `result.rows`. When no read's access chain
  names a result (`result`, `sql`, `section`, `lane`, `page`, `answer`,
  `need`), the warning says it may be a false alarm.
- It proves a field is read somewhere, not that every view shows it, and it
  applies only to packages that declare SQL needs.
- Its work is linear and bounded (`LINT_BUDGET`: script bytes at the hosted
  body limit, tokens and steps at fixed multiples of it), with no recursion,
  so bracket-heavy or deeply nested code cannot stall `validate`. Past a
  bound it gives one warning, `reads.completeness-lint-budget`, instead of an
  answer, and still refuses nothing. Every package within the body limit
  fits the default bounds.

`revision_digest` covers `row_count_complete`, so a result crossing 1,000 rows
moves the digest even when the first 1,000 rows are unchanged. No limit here
is raised by paging; paging is how a tab shows more than one capped answer.

### Keyset paging: the canonical pattern

To show more than 200 rows, page with a **parameterised** need, never a larger
`LIMIT` (the host would truncate it anyway). The pattern:

```json
{ "need": "sql.snapshot.v1", "key": "pager.page", "label": "…; pages of 200",
  "sql": "SELECT id, name FROM records WHERE deleted_at IS NULL AND id > ?1 ORDER BY id ASC LIMIT 200",
  "params": [{ "name": "after_key", "type": "text", "max_len": 128 }] }
```

- **Order by a unique key**, and make the predicate `key > ?1` on that same
  key. `id` is unique, so the order is total and deterministic: no row is
  returned twice and none is skipped. For a composite order, compare the whole
  tuple (`graph-everything.html`'s link pager, `(source, target, relationship)`).
  Use an `integer` param for an integer key.
- **`LIMIT 200`, equal to the delivery cap**, so each page is delivered whole
  and `truncated` stays `false` on every page. A page that comes back
  `truncated: true` means the statement no longer fits the cap; stop and say
  so rather than guessing a cursor.
- **Start with `""`** (or the key type's minimum), not an omitted param: an
  omitted optional param binds `NULL`, and `id > NULL` matches nothing.
- **Advance to the last row's key.** Stop on a page shorter than 200.
- **Each page runs under the viewer's authority at read time.** A record that
  becomes invisible between pages is simply absent from later pages; one
  already shown stays shown until the tab reloads. A key already passed is
  never returned again, so nothing is duplicated, and nothing hidden appears.
- Pages are read at different moments, so the set is not a snapshot of one
  instant: say "read in N pages", not "as of".
- Keep a page budget (the demo shell allows one read in flight, and each page
  is one read).

`experiments/alpha-tab-proof-packages/keyset-pager.html` is a small proof of
this pattern; `experiments/demo-shell/check-keyset-pager-headless.mjs` drives
its pager over more than 1,000 rows, and `tests/tools/alpha_tabs.rs`
(`sql_keyset_paging_*`) proves the engine side.

### Fake host: the real bridge behind a shell-faithful parent

The frame gets the exact `BOOTSTRAP` from **main's** `crates/artifact-html/src/html.rs:81`.
It is vendored as `src/fake-host/bridge-bootstrap.js`, pinned by SHA-256 in
`limits.json`, and injected at the engine's offset (`inject`, `html.rs:1897`).
The frame is served with the engine's CSP (`html.rs:2320`) and
Permissions-Policy (`html.rs:76`) in an iframe with `sandbox="allow-scripts"`
(pending.js:2380). Because the bridge is the real one, its own limits apply
unmodified:

- a 9th pending read **throws synchronously** with "too many reads in flight" (`html.rs:174`). Production served a different bridge on 28 Sep (digest `89574d1d…`, adapter revision 1), so these are main's caps; `alpha-tab-kit hosted` shows whether the deployed bridge matches;
- read params over 4,096 characters throw;
- an answer over 1 MiB resolves to `{status: "unavailable", code: "too_large"}` (:175);
- `setViewState` over 64 KiB throws (:164);
- an undeclared need throws "this host offers no such read".

The parent page (`src/fake-host/shell.js`) mirrors the alpha shell,
`experiments/demo-shell/public/views/pending.js`, which is the code hosted
`/alpha/` runs:

- **On-request reads queue FIFO, up to four dispatched together.** Each tab holds at most 8 accepted reads counting those in flight (`READ_QUEUE_MAX`, the bridge's own pending cap), and dispatches at most `READ_IN_FLIGHT_MAX` (4) at once (`pumpReads`); the rest wait in FIFO order, so a tab that sends several reads at once gets every answer exactly once, on its own ticket. Dispatch is FIFO but answers may now arrive out of order, because up to four reads are on the wire together. A read beyond 8 is answered `{status: "busy", code: "busy"}` and not queued; through the real bridge that cannot happen, because its 9th read throws first. Packages that retry on `busy` keep working (`handleRead`, `pumpReads`, `dispatchRead`).
- Admission applies the bridge's own bounds: request id and need of 1–128 printable characters, params a JSON object of at most 4,096 characters. A queued read keeps only a copy of those three values. Consent, params and the install pin are checked again when the read reaches the front of the queue, and the watch subscription is the one current then. They are checked a third time before the answer is published: a read whose consent, params or pin changed while it was on the wire is refused or answered `pin_mismatch` with no rows, and a keyed read whose stream or subscription changed meanwhile is answered `unavailable`, with no rows and no keyed registration, so the package's re-read carries the current watch. The fake host's declaration and watch do not change, so it mirrors the first two checks only.
- Undeclared needs and out-of-schema params are refused before the network: `undeclared_need`, `missing_sql_param`, `unknown_sql_param`, `invalid_sql_param`, `invalid_params` (`declaredReadRefusalFor`, pendingTabs.js:949; `bind_sql_params`, alpha_tabs.rs:439; `parse_declared_read` :504).
- Backend errors map `[code]` to refused or unavailable. The 10 s timeout starts when a read is dispatched. A read that outlives it is answered `unavailable` and only that ticket is retired: the tab's other reads keep going, and a later read is still admitted. The real shell cannot cancel the tool call it gave up on, so the timed-out slot stays charged against `READ_IN_FLIGHT_MAX` until the abandoned call settles or `READ_TIMEOUT_SLOT_GRACE_MS` (15 s) passes, whichever is first; a hung call therefore delays this tab's reads by at most the grace rather than wedging them until Reload, at the cost of briefly running over the cap. (The fake host aborts its own fetch, so its call settles at once and its slot frees immediately; only the answers and slot accounting are mirrored.) A reload answers the old document's accepted reads `tab_reloaded`, once each, on the old port. With no read on the wire the new document is then re-handshaken on the same tab. With one still on the wire it is not: that read cannot be cancelled, so the shell closes the tab with the notice `reloaded_during_read` rather than let the old read's timer, answer or cleanup touch the new document, and **Retry tab** opens a fresh one (which may read while the abandoned call finishes). The fake host mirrors this by retiring the frame. Every terminal path — handshake timeout, unreadable message, reload during a read — goes through one step in both hosts: answer every accepted read once on its own port, then close that port. After that nothing more is dispatched, and a superseded or retired port's messages are ignored.
- **Snapshot vs on-request:**
  - SQL needs without params arrive in `input.sql[key]` at init.
  - Needs with params, plus `records.search.v1`, `records.resolve_reference.v1`, `canvas.scene.v1`, `records.changes.v1` and `artifact.render.v1`, are offered as `needs` and read on request (pendingTabs.js:754). The fake host checks their params as the engine does and answers from the `search`, `resolve`, `scene`, `changes` and `render` fixtures.
  - `records.changes.v1` takes `{record_id, limit ≤ 50, cursor?}` and answers one page of the record's changes, newest first: `{version, record_id, order, events, limit, complete, next_cursor}`. Each event is `{event_id, type, created_at, actor, run_key, changed_fields, fields_truncated, reason, reason_truncated, payload_bytes, changes}`. `actor` and `run_key` are null when the viewer may not see who acted. `changes` gives `{field, before, before_known, before_truncated, after, after_truncated, observation_only}` for `name`, `lifecycle`, `maturity`, `kind`, `type` and `facet:<key>` (values cut at 256 characters), and `{field: "body", changed: true, bytes}` for a body. Field names are cut at 256 characters (`fields_truncated`), and an event too large for any page arrives as `{event_id, type, created_at, oversized: true}`. Page on with `next_cursor` until `complete` is true. The cursor is sealed: it only resumes the record and install it came from, and a restart of the host invalidates it (`invalid_params`), so read again from the top. A page can end early, `complete: false`, when the host runs out of its scan budget; before-values it could not find within its look-back say `before_known: false`. An event the host will not process in full arrives as `{event_id, type, created_at, unprocessed: true}`, and values it may have written read `before_known: false`. That happens when its payload needs more than 256 record-access checks for this viewer, or when its stored payload exceeds 8 MiB. The 8 MiB cap measures raw stored bytes, before redaction, so such an event is `unprocessed`, with `created_at: null`, for every viewer: the only fact that discloses is that its raw payload is over 8 MiB. For a processed event, `payload_bytes` is the size of the payload as redacted for this viewer, as `get_history` reports it. Unlike `get_history`, it leaves out `occurrence.bound.v1` events: they bind a unit to an artefact and change no field or body, and whether a viewer may see one depends on access to another record. No sequence number appears anywhere in it.
  - `artifact.render.v1` takes `{artifact_id}`, a full record id in canonical lowercase hyphenated form (no short references), and answers the server-rendered safe tree of one `native.mdx.v1` or `native.mdx.v2` artifact, rendered live as the viewer: `{version: "artifact.render.v1", status: "rendered", artifact_id, runtime: {id}, plan: {kind: "safe_tree", version: "1", tree, styles?: {digest, flags}, provenance: {record_id, source_event_id, event_seq, snapshot_event_id, snapshot_event_seq, body_sha256, render_sha256}}}` (provenance members appear when the runtime supplies them). It is display-only: interaction declarations, CAS tokens, editability, the input envelope and the stylesheet `href` are withheld. Every other outcome is an ordinary refused read with a code: `not_found` for a record the viewer cannot see or that does not exist, `not_mdx_artifact` for any other record (HTML tab packages and boards included), `render_failed` when the render does not produce a safe tree, and `too_large` for an answer over 786,432 characters. A short reference is refused `invalid_params`, never resolved. In the fake host, a `render` fixture that throws an `Error` whose message contains `[code]` answers that refusal. Re-read it when the document or its data may have changed.
  - Each SQL result has the engine's shape: `{label, columns, rows ≤ 200, row_count, row_count_complete, truncated, truncation_hint, now_ms_ms, time_dependent}`. `row_count` is the full count, and the result is capped at `query_sql`'s 1,000 rows first, which sets `row_count_complete: false` (`execute_sql_need`, alpha_tabs.rs).
- **Sample vs live:**
  - `mode: "sample"` delivers the engine's own `alpha_tab_sample_input()` (alpha_tabs.rs:1318) and offers no needs, so every read throws in the frame.
  - `mode: "live"` delivers the live envelope.
  - `pushInput()` sends a new snapshot as an `input` message with an increasing `content_event_seq`, as the shell does (pending.js:381).
- **Record handoff:** a trusted click on `[data-native-record-id]` reaches the host as `navigation` and is honoured only with host user activation and a printable id of at most 128 characters (`handleNavigation`, pending.js:2874).
- **`setViewState`** is accepted and logged. The alpha shell drops it; `holdViewState: true` re-delivers it on reload, as the Workbench host does (`mount.ts:1056`).
- Intents are rejected: `unsupported_host` live, `preview_sample_only` in sample mode. Effects are unwired in this slice.

`audit()` / `expectHealthy()` report reads that were answered `busy` and never
retried with the same need and params. The real shell loses exactly those
reads. Before the read queue (task 232e8f5, S2) every read sent while another
was in flight was answered `busy`, and this was the three-tab bug; the queue
removes it for tabs that stay within the bridge's 8 pending reads.

```js
import { chromium } from "playwright";
import { openFakeHost } from "@withnative/alpha-tab-kit/fake-host";

const browser = await chromium.launch();
const page = await browser.newPage();
const tab = await openFakeHost(page, {
  descriptor, html,                        // the package
  mode: "live",                            // or "sample"
  latencyMs: 40,                           // per-read backend latency
  // readTimeoutMs: 10000,                  // host read timeout (default limits.json shell.read_timeout_ms)
  fixtures: {
    sql: {
      "my.list": [{ id: "a", name: "First" }],                  // snapshot rows
      "my.body": ({ id }) => [{ id, body: `Body of ${id}` }],   // on-request: (params) => rows
    },
    search: ({ query }) => ({ results: [] }),                   // records.search.v1, if declared
    scene: ({ canvas_id, cursor }) => ({ /* one page */ }),     // canvas.scene.v1, if declared
    changes: ({ record_id, cursor }) => ({ /* one page */ }),   // records.changes.v1, if declared
    render: ({ artifact_id }) => ({ /* one answer */ }),        // artifact.render.v1, if declared
  },
});
await tab.frame.locator("button").first().click();   // tab.frame is a FrameLocator
await tab.expectHealthy();                            // throws on dropped reads or frame errors
await tab.close();
```

A fixture may return `{ error: "<code>" }`, or throw `new Error("… [code]")`,
to simulate a backend refusal.

### Inbound reveal (task fb8564c)

The bridge offers `nativeArtifact.onReveal(callback)`, a sibling of
`onInput`. The callback receives one deep-frozen `{record_id}` — an exact
persisted id over `[A-Za-z0-9._:-]`, 1–128 chars, matching backend
admission; never names, bodies, ancestors, installs or sequences — after
the host's backend admission for a `surface.reveal.v1` install. There is
no ack and no effect authority, and reveal stays off the input
rows/digest/revision and P7 paths. The shape is checked through the
captured pristine `RegExp.prototype.exec`, so later author tampering with
regex or string helpers cannot change the verdict.

- A reveal arriving after init but before registration is retained
  latest-one and replayed once to the first subscriber; the slot clears
  before the callback runs, so later registrations cannot re-deliver it.
- `type: "reveal-clear"` on the version-matching channel drops the retained
  target with no callbacks and no ack. The retained target also clears on
  pagehide/unload, channel messageerror/close.
- `ready` carries `features: ["surface.reveal.v1"]` exactly when the frame
  implements this API. The transport version is unchanged
  (`native.html.bridge.v1`); old hosts ignore the added field, and old
  frames (no feature) receive no reveal once the host stage gates on it.
- Malformed reveals are dropped with a bounded `html_reveal_dropped`
  diagnostic; a throwing callback yields `html_reveal_failed`. Neither
  grants anything.

The id shape is pinned literally by the engine test
`bootstrap_carries_the_reveal_surface` and proven headless in
`test/reveal.test.mjs` against the vendored bridge, including spaces and
punctuation outside the alphabet and a post-load prototype-tampering
round.

### Request size

Hosted MCP endpoints (`/mcp`, `/mcp/{db_id}`, and `/mcp/lenses/{lens_id}`)
allow request bodies up to 4 MiB. This encoded JSON envelope accommodates a
complete 512 KiB UTF-8 HTML source even with six-byte JSON escapes, plus
ordinary metadata. The HTML validator still independently enforces 524288
decoded bytes. Workbench `/tools/{name}` and database-scoped tool routes retain
their existing request limit. Production ingress/proxy limits in front of
app.withnative.ai are not verified by this application-level change.

### Install route

`planInstall` creates the complete source artifact in one write by default:

1. `records_write create_record` with `type: "Document"`, `kind: "artifact"`, the complete HTML body (sent as `body_encoding: "gzip+base64"` by default, see below), and `facets: {runtime: "native.html.v1", app_icon?}`. The call includes reason and sources, with no stage `idempotency_key`. The whole document is validated on creation.
2. Capture `id` and `source_event_id` from that receipt, and require its `body_digest` to equal the local `bundle_sha256`. Install pins this exact body-carrying event as `source_revision`; no append, re-kind or SQL lookup is needed.
3. Optionally `artifacts_write manage_alpha_tabs.remove`, **only** with explicit `--replace <event id>`. This retains the current remove-then-install behavior, including its adoption consequences: the new install requires browser adoption. It is not an in-place update, and a failed reinstall can leave the package removed.
4. `artifacts_write manage_alpha_tabs.install`. The server's combined `digest` and `declaration_digest` must equal the local ones.
5. `artifacts_read manage_alpha_tabs.inspect`.

**Input bindings.** Every install stages a new source, and input bindings and
`input.read` grants are pinned to one exact source: nothing made for the
previous install carries over. A tab whose manifest reads an input port (Docs
reads `pages`) then cannot render, so every Body Save is refused. Pass
`install-plan … --bind <port>=<collection id>` for each such port
(programmatically `planInstall({ …, bindings: [{port, collection_id}] })`); read
the previous install's Collection with `artifacts_read manage_artifact_inputs.read`.
Between steps 2 and 3 the plan then adds `artifacts_write
manage_artifact_inputs.bind_many` and, per port, `access_admin
manage_artifact_module_grants.grant` (`input.read`, `subject_kind:
"artifact_source"`, the new `source_event_id` and `bundle_sha256`). The grant is
plan-required: `runInstall` prepares it, then executes the returned plan through
`client.execute`. The CLI refuses a plan that leaves a requested port unbound
unless you pass `--allow-unbound`; programmatic plans list such ports as
`unbound_inputs`. `--bind` needs the whole-body route.

To reinstall after an earlier removal, use
`install-plan … --after-removal <removal event id>` (programmatically,
`planInstall({ …, afterRemovalEventId })`). It sets the install's
`expected_install_event_id` without sending another removal. This option is
mutually exclusive with `--replace`. If install fails with
`idempotency_key was reused for different intent`, run
`artifacts_read manage_alpha_tabs.inspect`; if `install.status` is `"removed"`,
re-plan with `--after-removal <install.event_id>`.

#### Updating an installed tab

Find the current generation with `artifacts_read manage_alpha_tabs.inspect`:
use `install.event_id` as `install-plan … --update <current install event id>`
(programmatically, `planInstall({ …, updateInstallEventId })`). The plan stages
the source, sends one guarded `artifacts_write manage_alpha_tabs.update`, then
inspects. It also works with `--chunked`. `--update`, `--replace` and
`--after-removal` are mutually exclusive.

With the same canonical declaration, adoption carries over from an adopted,
eligible generation. Any declaration change requires fresh Preview → Adopt at
`/alpha/`; restored, imported or pending generations still need Preview → Adopt
even when their declaration is unchanged. Disabled tabs stay disabled. Versions
remain numeric X.Y.Z, with no ordering requirement:
rollback and equal-version updates are allowed.

`install-run` reports whether adoption carried or Preview → Adopt is required.
A server predating `manage_alpha_tabs.update` stops the plan: choose `--replace`
explicitly if you want remove-then-install, which requires fresh adoption.
There is no automatic fallback. Digest mismatches stop all subsequent calls.

Retries stage a fresh source record, as in the chunked route. Archive orphaned
source records left by failed or repeated installs.

**Encoded body.** JSON escaping can inflate a raw HTML string several-fold against
the hosted request limit, so the whole-body `create_record` sends `body` as gzip,
then standard base64, with `body_encoding: "gzip+base64"`. The server decodes at the
tool boundary, before validation, the 512 KiB limit, `body_digest` and storage, so
the receipt digest still equals the local `bundle_sha256` and `expect.body_bytes` is
the decoded size. Select another form with `--body-encoding utf8|base64|gzip+base64`
(programmatically `planInstall({ …, bodyEncoding })`); `--raw-body` is shorthand for
`utf8`, which sends the plain string and omits the field. Use it against a server
that predates `body_encoding`, which refuses the unknown argument. `runInstall`
does this for you: when the encoded `create-artifact` step is refused with an error
that names `body_encoding` (and is not one of the new server's own
`[body_encoding_*]` refusals), it prints a one-line notice and retries that one step
once with the raw body, using the step's `fallback.arguments`. Run a saved plan's
steps by hand with `arguments`, or `fallback.arguments` against an older server. The chunked
route is always raw. `manage_alpha_tabs` calls carry no source bytes, so they have
no encoding.

**Size caveat (raw bodies only):** hosted `/mcp` currently applies axum's default request-body
extraction limit: axum-core `DEFAULT_LIMIT` is 2097152 bytes (**2 MiB encoded
JSON**). The HTML limit is 512 KiB decoded UTF-8, so a near-512 KiB
escape-heavy bundle may need the default encoded body (or `--chunked`) until a separate change raises the MCP request
allowance to 4 MiB. Metadata also counts toward the encoded limit.

For constrained servers or clients, explicitly use
`install-plan … --chunked [--chunk-bytes 8000]` (programmatically,
`planInstall({ …, chunked: true, chunkBytes: 8000 })`). This reproduces the
legacy route: create a `Document`/`note` with the first chunk, append each
remaining chunk with `if_body_digest` of the prefix, query the last
body-carrying source event **before** re-kind, then switch to artifact with the
runtime facet and install. Partial artifacts cannot be staged directly because
every artifact write validates the whole HTML document. Chunks never split a
code point. `--chunk-bytes` alone does not select this route. Old saved plans
continue to execute their original append/query/re-kind steps unchanged.

`runInstall(plan, client)` runs the plan through any
`client.call(executor, operation, args)` that returns the parsed result. It
checks every receipt, and nothing after a mismatched digest is sent.

**Programmatically, as yourself (preferred):** the bytes never pass through
an agent's tool calls, so there is nothing to mistype and no escape to be
decoded in transit (task 1619b59).
1. Once per host, in a terminal: `alpha-tab-kit login --email <you>`. It
   emails a code, prompts for it, and stores your 30-day session bearer at
   `~/.config/native-principal/production-bearer` (0600, never printed).
   Without a terminal, finish with `--code <code>`.
2. `install-plan … --out plan/`, then `alpha-tab-kit install-run plan/`. It
   bootstraps one run, declares the intent, and runs `runInstall` over
   `https://app.withnative.ai/mcp`. Writes are attributed to whoever's bearer
   it is, so never use another identity's.
   Each request times out after 120 seconds by default; set
   `install-run … --timeout-ms <milliseconds>` or
   `createMcpClient({ …, timeoutMs })` to override it. A timed-out write may or
   may not have committed: inspect before retrying.

**For an agent with Native MCP tools and no programmatic client:**
1. Run `install-plan --out plan/`.
2. Execute the files in order, passing each file's `arguments` unchanged. Replace `{{record_id}}` with the create receipt's `id`, and `{{source_revision}}` with its `source_event_id`. For a legacy chunked plan, use `rows[0].id` from its `source-revision` step instead.
3. Compare every receipt's `body_digest` with the file's `expect.body_digest`. Stop at the first mismatch. An escape decoded in transit, such as a literal `\n` or `￿` in the file, can change the source bytes; never install after that mismatch.

The kit holds no credentials and performs no writes itself.

**What it cannot do:** preview and adoption. Preview receipts are issued only to
a cookie session from a trusted origin. Agents are refused with
`preview_authority_missing`, and a direct install is recorded as
`adoption: "caller_asserted"`. Launch then refuses with `adoption_unverified`
until the viewer previews and adopts the tab in a signed-in browser at
`/alpha/`.

## What it cannot guarantee

- **Hosted preview and adoption** need a signed-in browser (above). Nothing
  local can stand in for that step or for real viewer authority.
- **Real data and real SQL.** The fake host answers from fixtures. Use `npm run
  dev:real` in `web/workbench` (the published backend image) or `query_sql` for
  real rows, the 2 s deadline, value ceilings and column existence.
- **The deployed server may lag main**, and on 28 Sep it did: validator 1 vs 3,
  and a different bridge. The drift guard follows `main`, not production. Use
  `alpha-tab-kit hosted` to see how far behind the deployed server is.
- **Not emulated:**
  - **keyed-freshness reconciliation.** In `pending.js`, keyed needs
    (`graph.neighbours`, `folders.children`, `browse.children`) carry
    `keyed_freshness`, register variants, and on a revision race answer
    `unavailable/keyed_revision_mismatch` and replace the frame. A pin change
    answers `unavailable/pin_mismatch`. The fake host does none of this: it
    never sends `keyed_freshness`, `pin_mismatch` or `keyed_revision_mismatch`,
    so a tab's handling of those codes is untested here;
  - live subscriptions (the `stream` / `watch` path);
  - `attention.query.v1` semantics beyond delivering fixture records;
  - consented write effects;
  - the Workbench host's other differences (`mount.ts`).
- The SQL and HTML rules marked "token stream / tag scan" can miss a case the
  engine refuses. The corpus below shows where they have been checked against
  the engine.

## Drift guard

**Choice:** one Rust unit test, `src/mcp/tools/alpha_tab_kit_drift.rs` (a
child module of `alpha_tabs.rs`, test-only), which `include_str!`s the kit's
`limits.json`, the vendored bridge, and the shared vectors and corpus. It
asserts:

- every engine-backed value equals the constant it names (`SQL_SNAPSHOT_*`,
  `MAX_*`, `BODY_LIMIT`, `LOGICAL_RELATIONS`, `PORTABLE_FUNCTIONS`, the CSP,
  `alpha_tab_sample_input`, …);
- literal-only limits (package/version/reason/effect/param-name lengths, param
  types) sit exactly on the engine's boundary;
- forbidden SQL words, clock keywords, forbidden elements, URL attributes and
  data MIME types each get the refusal the kit claims from the real validators;
- the vendored bridge's SHA-256 equals `html::bootstrap_digest()`, and the
  bridge limits the fake host relies on are still literal in it;
- `bridge.adapter_revision` and `bridge.validator_version` equal
  `ADAPTER_REVISION` and the validator version in `html::descriptor()`, which
  keeps `alpha-tab-kit hosted` comparing against main's real numbers;
- the digest vectors recompute with `alpha_tab_*_digest`;
- every corpus case (29 SQL statements, 36 declarations, 14 package/version ids)
  gets the verdict the kit's own tests expect, from `parse_sql_need_entry`,
  `require_declaration`, `require_package` and `require_version`;
- coverage: every engine-backed leaf in `limits.json` is asserted, so the kit
  cannot grow an unchecked limit.

**Why this over a generated JSON of limits.**
- A generator needs a `dev-tools` binary run and a "did you regenerate?" check. A test that reads the kit's own file needs neither.
- It runs in the existing required `test` lane with no new CI plumbing, because the classifier's fail-closed default covers `packages/alpha-tab-kit/`.
- The corpus half guards *behaviour* (what is admitted), which a list of constants cannot.

Locally:

```bash
cargo test --lib alpha_tab_kit_drift
```

Default features only, per `AGENTS.md`.

The shell half (`test/drift-js.test.mjs`) checks, when run inside native-ce,
that every `js_literal` in `limits.json` is still present in the demo shell
source: the one-dispatch pump, the 8-read queue cap, the 200-row cap, the 10 s
and 5 s timeouts, and the navigation bound. It also checks that the queue cap
equals the bridge's pending-read cap. The whole kit suite runs in CI as the "Alpha tab kit" step of
the `workbench-fixtures` job.

## Running the tests

```bash
cd packages/alpha-tab-kit
npm test               # node --test; the browser tests need Playwright
```

Playwright is found through, in order:
1. `ALPHA_TAB_KIT_PLAYWRIGHT` (a directory whose `node_modules` has it);
2. the current directory;
3. inside native-ce, `web/workbench` (`npm ci` there once);
4. a plain `import("playwright")`.

Without it, the browser tests skip locally. In CI (`CI` set, as GitHub Actions
does), or with `ALPHA_TAB_KIT_REQUIRE_BROWSER=1`, an unresolvable Playwright is
a failing test instead, so the fidelity tests cannot pass by not running.

`npm run proof` reruns the evidence below. It reads the packages from
`origin/demo-tabs-all` with `git show`, so run `git fetch origin demo-tabs-all`
first.

## Evidence (28 Sep 2026)

`proof/prove-demo-tabs.mjs` runs each package through the validator and the
fake host. Each package's own synthetic fixture world is lifted from its check
script, so only the host differs from what its author tested against.

| Package (rev) | Validator | Fake host |
|---|---|---|
| prism 0.1.0 (`demo-tabs-all`) | pass, 0 findings; digest matches descriptor | pass: record opens, 6 detail reads, 0 busy |
| slack-workspace 0.1.1 (`demo-tabs-all`) | pass, 0 findings | pass: thread opens with body and comments, 0 busy |
| slack-workspace 0.1.0 (`e8921807f`, the installed pin) | pass; digest `sha256:e6856cb7…` equals the installed pin's | **fail**: the body read was answered `busy` and dropped, and the pane says "could not be read", as it did in `/alpha/` |

The slack-workspace 0.1.0 row predates the read queue: the same package no
longer loses its body read against the queued host, but this table has not been
re-run.

All seven `demo-tabs-all` packages (calendar-week, miro-board, notion-pages,
prism, roadmap-base, slack-workspace, task-reader) pass `validate`. That is,
the kit reports no false positive on any package the hosted server accepted.

### Read scheduling (task 232e8f5, S2)

`probe-queued.html` reading `probe.body` N times at once through the real
bridge, in headless Chromium on one development machine, at two simulated
backend latencies. These numbers show **scheduling only**: the fake host sleeps
for the latency and answers from fixtures. They say nothing about how fast the
real engine serves a read. "Calls" counts host dispatches; completion is from
the first read to the last answer, measured in the frame.

| Latency | N | Before: calls / ok / busy / dropped | After: calls / ok / busy / dropped | After: order | After: completion |
|---|---|---|---|---|---|
| 40 ms | 1 | 1 / 1 / 0 / 0 | 1 / 1 / 0 / 0 | 0 | 88 ms |
| 40 ms | 4 | 1 / 1 / 3 / 3 | 4 / 4 / 0 / 0 | 0,1,2,3 | 253 ms |
| 40 ms | 8 | 1 / 1 / 7 / 7 | 8 / 8 / 0 / 0 | 0–7 | 497 ms |
| 250 ms | 1 | 1 / 1 / 0 / 0 | 1 / 1 / 0 / 0 | 0 | 304 ms |
| 250 ms | 4 | 1 / 1 / 3 / 3 | 4 / 4 / 0 / 0 | 0,1,2,3 | 1,160 ms |
| 250 ms | 8 | 1 / 1 / 7 / 7 | 8 / 8 / 0 / 0 | 0–7 | 2,235 ms |

"Before" is the busy-not-queued host (a naive tab loses N−1 reads); the
"After" columns above predate parallel dispatch: they were measured when one
read was dispatched at a time, and completion grew by about one latency per
read. Since the in-flight cap (`READ_IN_FLIGHT_MAX`, 4) landed, reads inside
one window overlap, so completion grows by about one latency per *window*.
The fake-host test now re-measures the peak concurrency and completion on
every run and prints them as `# fake-host S2` lines; treat the table above as
the historical serial baseline, not a current expectation.

## Consuming it from a separate tabs repo

| Option | For | Against |
|---|---|---|
| **npm package** published from native-ce (GitHub Packages, `@withnative` scope) | Pinned, versioned, one line in `package.json`; the kit has no dependencies, so it is cheap; the tabs repo's CI runs `alpha-tab-kit validate` per tab folder and the fake-host tests | Needs a publish workflow and a registry token in the tabs repo |
| Vendored copy | No registry | Copies drift silently: exactly the failure the drift guard exists to stop, moved into the tabs repo |
| git subtree | History stays linked | Needs a split of native-ce history, is awkward to update, and ties the tabs repo to native-ce's layout |

**Recommendation: the npm package.**
- Publish from native-ce CI on merges that touch `packages/alpha-tab-kit/`, with the version bumped in the same PR. The drift guard makes an unbumped engine change fail first.
- The tabs repo pins an exact version. Its CI runs `validate` and the fake-host tests for every tab folder, and a `dev:real` smoke test against the published backend image.
- `"private": true` stays in `package.json` until the publish route is decided. **Nothing has been published.**

## Layout

```
limits.json                 every enforced number, with its source (read by src/limits.mjs)
bin/alpha-tab-kit.mjs       CLI
src/digest.mjs jcs.mjs      alpha-tab-digest.v1
src/declaration.mjs         declaration shape rules
src/sql-lint.mjs            SQL admission rules
src/completeness-lint.mjs   advisory: warns when a package never reads `truncated` / `row_count_complete`
src/html.mjs                native.html.v1 write policy
src/validate.mjs            all of the above, per package
src/install.mjs             install route planner and runner
src/hosted.mjs              compare a deployed server's runtime descriptor with main
src/fake-host/              bridge-bootstrap.js (vendored), shell.js, rules.mjs, server.mjs, playwright.mjs
test/                       node --test suites; vectors/ shared with the Rust drift test
proof/                      evidence script for the PR (not part of the package)
```

**Why `packages/`.**
- `packages/` holds the standalone Node packages native-ce publishes for use outside the repo (`advisor-runner`, `native-standby`), and this kit is meant to be depended on from another repo.
- `experiments/` holds harnesses and evidence, which is where the proof packages and the demo shell still live.

## Launcher icon authoring

Supply an optional plain PascalCase Lucide name or `brand:<slug>` on the package descriptor:

```json
{ "package": "agent.my-tab", "version": "0.1.0", "icon": "BookOpen",
  "bundle": "my-tab.html", "runtime": "native.html.v1",
  "declaration": { "needs": [], "effects": [] } }
```

Run `node packages/alpha-tab-kit/bin/alpha-tab-kit.mjs icons` to list the
**finite supported catalogue** from Lucide 0.544.0. The host owns the library;
apps need no icon dependency. This is not full Lucide support.

A second, host-owned **brand** catalogue supplies recognisable SaaS marks: the
launcher's curated defaults use it (Airtable, Slack, GitHub, Datadog, Notion,
Miro, Salesforce, Zendesk, Google Calendar). The Database, Database (Preact),
and roadmap-base apps use the Airtable mark when no explicit `app_icon` is set.
`web/shell` pins the
`@iconify-json/simple-icons` npm package at 1.2.98 (its artwork is upstream
Simple Icons 16.33.0) and renders it monochrome in `currentColor`. The kit
carries no brand artwork. Set `"icon": "brand:airtable"` to select Airtable,
or another Simple Icons slug such as `brand:slack` or `brand:github`.
The literal `brand:` prefix identifies that catalogue; other catalogue prefixes
are invalid. The slug must be lowercase ASCII letters/digits with single
hyphens between groups (`[a-z0-9]+(?:-[a-z0-9]+)*`), at most 64 bytes
excluding the prefix. No whitespace, trimming, case conversion or URL resolution
is performed. `parseIconFacet` is the shared scalar parser; registry/wire
descriptors remain `{kind: "brand", name: "airtable"}`.

`planInstall` adds `app_icon` to the artifact create facets (or the legacy
chunked re-kind update) only when the descriptor supplies a structurally valid
scalar choice. Lucide names remain an ASCII capital followed by ASCII
letters/digits, at most 64 bytes. Unknown Lucide names such as `FutureIcon` are
preserved with an advisory warning and render a monogram. Brand validation in
the standalone kit checks identity and slug shape; catalogue availability is
checked by the host renderer. A valid unknown brand slug is preserved and
renders a monogram. Malformed/non-string/oversized descriptor values warn and
are omitted; they never make an otherwise valid package fail validation.
Object descriptors, SVG, external artwork URLs and code are not authoring values.
Other record facets are preserved.

The artifact's open `app_icon` facet uses the **same scalar string** as
descriptor `icon`. It needs no object facet declaration or vocabulary/schema
migration. After installation, choose a workspace-local icon with a metadata-only
`records_write` call:

```json
{ "operation": "update_record", "arguments": {
  "id": "<workspace artifact record id>",
  "facets": { "app_icon": "brand:airtable" },
  "reason": "Choose this workspace's app icon", "sources": []
} }
```

Supply your run key in the executor envelope when using Native. The existing
launcher metadata refresh reads the applied current workspace index and
updates the rail without a page reload or install-list refetch. The compatible
host must include the scalar brand parser and its pinned catalogue; older
Lucide-only hosts show a monogram for `brand:<slug>`. A host release enables
this contract once; choosing among its supported icons then needs only a
record metadata edit.

`app_icon` is mutable artifact presentation metadata, outside HTML source,
consent declarations and `alpha-tab-digest.v1`. Editing it does not change
package versions, install pins or adoption; every install referencing that
artifact in that workspace sees the same presentation choice. Import the same
reference into separate workspace-owned artifact records to make independent
choices; reference files and other workspace records do not synchronize.
Icon edits do not advance executable revisions, installed source/declaration
pins, permissions or adoption. Any explicit facet, including a
custom or invalid value, prevents a curated default. Deleting it restores the
package default, or a deterministic package monogram on a contrasting tile.
Deleting the facet uses `facets: { "app_icon": null }` in `update_record`.
Malformed explicit record values also render a monogram and block the package default;
they differ from malformed descriptor values omitted at installation.
Brand marks come only from the host-pinned catalogue above, never from
app-supplied artwork, URLs or executable code.

The provisional `records.body-set.v1` raw UTF-8 ceiling is 512 KiB. Existing
consented declarations retain their smaller caps until a person adopts a
reviewed package update. The dedicated Body request admits a complete encoded
JSON envelope of up to `6 * 512 KiB + 64 KiB`; its raw UTF-8 check also rejects
NUL and unpaired surrogates. The engine retains finite 4 MiB encoded value and
replay-payload budgets, checks the complete inverse, and reconstructs Undo at
the same raw ceiling. Complete larger editor sources use the governed paged
reader explicitly; increasing the kit's limit does not upgrade an older host
or change an installed app's permissions. Generic intent, arm and view-state
bridge limits remain separate.

## Portable shared source contracts

`src/shell-routing.rs` contains the dependency-free Alpha static-asset and
record-reference classifiers shared with hosted serving. The Desktop asset
producer checks this public source input, so it does not require a held server
checkout. It defines path classification only; authentication, headers, asset
embedding and the operated HTTP composition remain in the host.

`shared-source-license.json` binds the closed three-module browser body client
to this package's AGPL-3.0-only identity and `LICENSE.md`. The Docs and Spaces
production notice builder pins the complete contract, package metadata and
licence bytes, and rechecks module identities and hashes before injection.
This portable licence contract replaces a private source-policy build input.
It is not a publication receipt or an approval to publish arbitrary sources.
