# Native Canvas v1 — batch protocol

Status: Experimental (milestone 3 of 3). The wire shapes below are implemented on the reference SQLite engine and may change before the protocol is declared stable. Postgres is declared unsupported; Turso follows SQLite once its projector accepts extended content events.

A canvas is an ordinary `Document kind:canvas` record. Its scene is an append-only stream of typed operation batches; each accepted batch is one `canvas.batch.committed.v1` content event on the canvas record's own stream, folded by the ordinary content projector into `canvas_objects` (the current scene, tombstones kept) and `canvas_batches` (the idempotency ledger). Ops are never individual events. The architecture and its decisions are recorded in Native (architecture note `0a355ee`, decision `97b5cb2`, implementation decisions `b6b27cf`).

## Tools

| Tool | Actions | Requires |
|---|---|---|
| `read_canvas` | `get_scene`, `changes`, `describe`, `export` | View on the canvas |
| `manage_canvas` | `commit_batch` | Edit on the canvas; View on every record a new `record_card` names |
| `manage_canvas` | `assert_connector` | Edit on the canvas; Edit on the source record; View on the target |
| `manage_canvas` | `promote` | Edit on the canvas; Edit on each destination home; View on each existing link target |
| Canvas presence (hosting route) | `POST /databases/{db_id}/canvases/{canvas_id}/presence` — write own cursor, selection and viewport; `leave` | View on the canvas |

Presence was ratified as requiring Edit and was relaxed to View before implementation, on the product argument that a View-only collaborator looking at a canvas is present and their cursor is useful. The relaxation also makes the write agree with the frame fan-out, which was already keyed on View.

Both tools are registered on the stable tool surface (rather than through experimental registration), advertised in the Complete profile only; the protocol itself is Experimental as stated above. Over the executor facade their addresses are `canvas_read.read_canvas.get_scene`, `canvas_read.read_canvas.changes`, `canvas_read.read_canvas.describe`, `canvas_read.read_canvas.export`, `canvas_write.manage_canvas.commit_batch`, `canvas_write.manage_canvas.assert_connector` and `canvas_write.manage_canvas.promote`. Promotion is registered **plan-required**: over the executor facade it is prepared and then executed, never called in one step.

## Scene object

```json
{
  "id": "client-minted, unique per canvas",
  "kind": "note | shape | stroke | connector | frame | record_card",
  "x": 0, "y": 0, "w": 200, "h": 120,
  "z": "fractional-index string",
  "parent": null,
  "props": {},
  "versions": { "geometry": "canvas:N", "content": "canvas:N" },
  "deleted": false
}
```

Units are world pixels at zoom 1, finite doubles. `parent` is a live `frame` id or `null`; frames cannot have a parent. `versions` and `deleted` are server-assigned. Each version is the `content_events.seq` of the batch that last touched that group: `geometry` covers `x, y, w, h, z, parent`; `content` covers `props`.

`props` by kind (unknown keys are refused):

- `note`: `{ text, color? }`, text ≤ 8 KiB.
- `shape`: `{ shape: "rect" | "ellipse", label?, color? }`.
- `stroke`: `{ points: [[dx, dy], …], width?, color? }`, ≤ 2000 points relative to `x, y`.
- `connector`: `{ from: Endpoint, to: Endpoint, label?, style?: "line" | "arrow", semantic }` where `Endpoint` is `{ object, side? }` or `{ x, y }`, and `semantic` is `null` or `{ relationship, link_id, status }`. See "Connectors and assertion" below.
- `frame`: `{ title?, color? }`.
- `record_card`: `{ record_id }`. `promoted_from` is written only by promotion.

### Engine-authored props

`connector.semantic` and `record_card.promoted_from` are governed: they record that something happened in the governed layer, so a client may not write them. A batch submitted to `commit_batch` that sets either is refused `invalid_envelope` — and so is a batch whose `origin.kind` is `assertion` or `promotion`, because those origins are what license the governed props and they are written only by the engine's own canvas actions. The projector may trust a stored origin precisely because nothing else can have produced one.

## Batch envelope (`manage_canvas.commit_batch`, argument `batch`)

```json
{
  "version": "native.canvas-batch.v1",
  "canvas_id": "…",
  "batch_id": "client-minted uuid",
  "base_version": "canvas:N",
  "origin": { "kind": "gesture" | "agent" | "undo" | "promotion" | "assertion", "gesture"?: "…", "undo_of"?: "batch_id", "note"?: "…" },
  "ops": [ … ]
}
```

`base_version` is informational and echoed on conflicts; it is not a precondition. `origin.gesture` is at most 64 bytes and `origin.note` at most 1 KiB.

### Ops

- `{ "op": "create", "object": { id, kind, x, y, w, h, z, parent?, props? } }` — the id must be unused; a tombstoned id is `object_deleted`. A `record_card` additionally requires View on the record at commit.
- `{ "op": "patch", "id", "expected": { "geometry"?: "canvas:N", "content"?: "canvas:N" }, "set": { x?, y?, w?, h?, z?, parent?, props? } }` — `expected` must name every group `set` touches. `props` merges one level deep and `null` deletes a key. `kind` and a card's `record_id` are immutable.
- `{ "op": "delete", "id", "expected": { "geometry", "content" } }` — tombstone. Deleting a frame detaches its children in the same fold step; the result's `objects` reports their new `geometry` token, and the batch records them under `detached` with a pre-image naming the frame.
- `{ "op": "restore", "id", "expected": { "geometry", "content" } }` — un-tombstone.

Rules: at most one op per object per batch (`duplicate_object`); ops are validated in order against the transaction snapshot plus the batch's own creates; a connector endpoint may name any object id (dangling endpoints are the reader's concern). Limits: ≤ 200 ops, ≤ 256 KiB canonical bytes per batch, ≤ 5 000 live objects per canvas.

### Result

```json
{
  "version": "native.canvas-batch-result.v1",
  "outcome": "committed" | "replayed" | "conflict" | "rejected",
  "batch_id": "…",
  "canvas_version": "canvas:N",
  "event_id": "…",
  "objects": { "<id>": { "geometry": "canvas:N", "content": "canvas:N" } },
  "conflicts": [ { "id", "group"?: "geometry" | "content", "code": "version_mismatch" | "object_deleted", "current": { "geometry", "content" }, "competing_actor": { "id", "display_name" } | null } ],
  "error"?: { "code", "message", "object_id"?, "limit"? }
}
```

Every outcome is a 200 result. `committed` and `replayed` carry the versions the batch left. `conflict` means one or more `expected` tokens no longer hold (or the object is tombstoned); nothing was written, `current` reports the live versions, and `competing_actor` is the actor whose batch produced them, disclosed only when the caller may identify that actor. `rejected` means the batch was refused before any precondition question arose; `error.code` is one of `invalid_envelope`, `invalid_precondition`, `invalid_geometry`, `limit_exceeded` (with `limit`), `duplicate_object`, `unknown_object`, `object_exists`, `object_deleted`, `record_not_visible`, `permission_denied`, `unknown_canvas`, `batch_id_reused`.

Idempotency: `batch_id` is the ledger key. The same `batch_id` from the same actor with the same ops (JCS digest) returns the original result as `replayed` and appends nothing; any other reuse is `batch_id_reused`.

Server order: Edit on canvas → envelope, limit and referential validation → `BEGIN IMMEDIATE` → View and Edit re-checked as the authenticated principal → ledger lookup → compare-and-set per group → dry fold in a savepoint (the projector's own rules) → append → project → resulting versions read inside the transaction → commit.

## Reads (`read_canvas`)

- `get_scene { canvas_id, include_deleted?: false, as_of? }` → `{ canvas_version, objects: [...], live_objects, limits }`. Record cards carry `record: { id, type, kind, name, summary, archived, maturity, version }` when the caller holds View on the record; otherwise `props.record_id` is the literal `"withheld"` and no `record` is present. With `as_of`, geometry and props come from the historical replay while authorization and record faces stay live.
- `changes { canvas_id, after: "canvas:N", limit?: 200 }` → `{ canvas_version, batches: [ { batch_id, event_id, event_seq, canvas_version, actor, at, origin, base_version, ops, pre_images, detached } ], more, next_after }`. `after: "canvas:0"` is full history. `pre_images` carries, per patched, deleted or restored object, the previous versions and the previous values of every field the op changed (`null` for a props key that did not exist), so a batch is invertible op by op.

`canvas_version` is batch-only: the highest `canvas.batch.committed.v1` seq on the canvas, `canvas:0` for an untouched canvas. It deliberately differs from the shell record's `rec:N`, which advances on renames and links.

## Disclosure

One rule on every read path: a record id appears in a canvas response only if the caller holds View on that record at read time; otherwise it reads `"withheld"` and nothing else about the record is emitted. Geometry is visible to anyone with View on the canvas, so a withheld card still renders and can be moved. Generic `get_history` returns batch events with their payload replaced by `{ actor, at, op_count, origin: { kind }, batch, canvas_version, see: "read_canvas.changes" }` at both detail levels. Loss of Edit mid-session makes the next batch `rejected/permission_denied`; loss of View makes every read and write report a non-existent record.

## Realtime

The existing SSE stream carries a `content` invalidation for the canvas record on every accepted batch. Clients pull `changes { after: <own canvas_version> }` on that frame, on reconnect, and on an `authorization` frame.

## Presence

Presence is ephemeral and process-local. The registry lives on the hosting tier (`held/hosting/src/hosting/presence.rs`), keyed `(database_id, canvas_id)` to `(account, client_id)`, behind a mutex, with one broadcast sender per database feeding the realtime stream. There are no rows, no events, no history, no `whats_changed` entry, no conformance table and no interchange section. A process restart empties it. Presence is invisible to `export`, `describe` and `changes`.

The write route is `POST /databases/{db_id}/canvases/{canvas_id}/presence`. It requires the session credential with the same DNS-rebinding guard and cookie same-origin proof the tools route requires, and View on the canvas through the engine's own capability evaluation — the first canvas write route that does not require Edit. Absence, tombstones and denial stay one fail-closed answer mirroring the canvas reads: without View the route reports a missing canvas. A live canvas row is additionally required, so naming a record that is not a live canvas is a `400`. Authorization is decided before the body is parsed.

The body is labelled `native.canvas-presence.v1` and carries `client_id` (1–64 bytes, naming one tab), `cursor` (`{ x, y }` in finite world pixels, or null), `selection` (at most 200 object ids, each 1–128 bytes; absent reads as empty), `viewport` (`{ x, y, zoom }` with finite `x` and `y` and a positive finite `zoom`, or null) and `leave`. Anything else is a `400`. A successful write is a `204`. `leave: true` still names the `client_id` to remove; it removes that participant and broadcasts the removal at once. A write sweeps expired entries for that canvas first.

The frame is a `presence` event on the existing stream: a snapshot of that canvas's live participants, not a delta, so a dropped frame is harmless and self-heals on the next write. It is id-less like the `authorization` frame and never advances `Last-Event-ID`. Each frame carries `version: "native.canvas-presence.v1"`, the `canvas_id`, `ttl_ms: 10000`, and `participants` — each with `client_id`, `actor`, `cursor`, `selection`, `viewport` and `seen_ms_ago`. The subscriber's own `client_id` is included; the client filters itself out.

Fan-out is filtered per subscriber to canvases on which that subscriber holds View, decided through the engine's capability evaluation once per (subscriber, canvas) and cached. The decision is re-taken when the authorization vector moves: the authorization arm of the stream clears the cache, so losing View stops the frames. Actor identity goes through the ordinary disclosure policy — View on the person the account is bound to, with being the actor as the trivial case — and a subscriber who may not identify an account sees `null` for that participant, which the client labels "Someone".

TTL is 10 s, declared on every frame as `ttl_ms` rather than enforced by a server timer. There is no sweeper task. Entries expire lazily on the next write or read for that canvas against an injectable clock that defaults to the wall clock, following the house convention shared with the catalog and backup sweeps — which is what makes expiry deterministic and testable without fixed waits.

Two bounds are worth stating rather than leaving to be found. A subscriber who loses View can receive one further snapshot before the stream learns of it: the presence invalidation is an in-process broadcast sent at write time, while the authorization vector travels the commit and wake path, so a write landing immediately after a revocation can be decided against the cached allow. The cached decision is discarded before the authorization frame is yielded, not after, so the window does not extend across the interval in which the subscriber has already been told authorization moved. What remains is bounded by that pump latency, and what it discloses is activity — who is on the canvas and where their cursors are — not identity, because actor disclosure is re-decided against current capability every time a frame is built. The second bound: a canvas whose participants all go quiet is never swept, because sweeping happens on a read or write for that canvas. Those entries are retained but never observable, since any observation is itself a read that sweeps first.

This is process-local state, so it does not span replicas. That is the single-replica limit, stated rather than left to be discovered.

There is no server-side rate limiting in v1. The client coalesces pointer, selection and viewport writes to at most one per 250 ms while moving, with a 3 s idle keepalive so a quiet tab never lapses out of the snapshot.

## Schemas

JSON Schemas for the batch envelope, the result, and the export bundle live under `protocol/canvas/experimental-canvas-1/schemas/`. They describe the shapes above and are not yet enforced by a conformance suite. The export schema references the batch envelope's `origin` and `ops` shapes rather than restating them.

## `read_canvas.describe`

`describe { canvas_id }` returns a prose outline for an agent that needs to know what is on a canvas without rendering it: `{ outline, live_objects, counts, withheld_cards, frames, clusters, connectors }`.

The outline names frames first with their contents — an author's explicit grouping outranks any proximity the engine would infer — then groups the remaining loose objects into single-linkage proximity clusters, then states each connector as a sentence, decorative or asserted. It is built from the same redacted values `get_scene` returns, so a card on a record the caller may not see is counted in `withheld_cards` and described as unnameable, never named.

`as_of` is refused: `describe` outlines the current scene.

## `read_canvas.export`

A bundle whose `disclosure.complete` is false is not replayable in full: a `create` of a record card whose id reads `withheld` cannot be re-folded, because the record is unnamed and the fold requires View on it at commit.

`export { canvas_id, include_history?: true }` returns one JSON document labelled `native.canvas-export.v1`, not paged: the canvas shell, the scene, the full history and the derived references. View on the canvas is required, and a caller without it gets the same non-existent-record refusal `get_scene` gives. `as_of` is refused: an export bundles the current scene. `exported_at` is RFC 3339 and `exported_by` is the exporting caller's disclosed actor face (`{ id, display_name }`), or null where that actor may not be disclosed to the caller.

The `scene` section is `{ version: "native.canvas-scene.v1", objects }`, byte for byte the shape `get_scene` with `include_deleted: true` produces — tombstones included, because a faithful serialisation of the stream must carry what the history wrote. The `history` section is `{ version: "native.canvas-changes.v1", batches }`, every batch from `canvas:0` in order, each in exactly the `changes` batch shape. Both sections are built by calling those same reads on a single snapshot transaction, so the bundle cannot straddle a concurrent commit and inherits their redaction structurally rather than through a second copy of the rules. `include_history: false` returns shell plus scene with `history: null`; that shell is the fallback for an over-long history and is not replayable. The `canvas` shell names the record (`id`, `type: "Document"`, `kind: "canvas"`, `name`, `summary`, `archived`, `record_version: "rec:N"`); `canvas.home_id` reads as the id only for a caller holding View on the home, otherwise as the literal `"withheld"`. `record_version` is the highest `content_events` seq on the canvas record and advances on renames and links, while `canvas_version` counts batches only.

`references` are derived, not stored: `records` lists the distinct visible record ids named by live and tombstoned cards, plus every `promoted_from` target, each with the name from the same record face the scene uses; `links` lists the visible asserted connector link ids with their relationship; `attestations` lists every attestation id named by a visible `promoted_from`. Asserted connectors contribute none: `assert_connector` writes `semantic` as exactly `{relationship, link_id, status}` and nothing records an attestation id there. Withheld entries are counted in `disclosure` and never listed.

`disclosure.complete` is true only when nothing caller-specific was withheld for this caller: no `record_id` reading `"withheld"`, no withheld scene `semantic`, no withheld `promoted_from`, no withheld `home_id`. A withheld `semantic` in the HISTORY section does not count, while one in the SCENE does, and the asymmetry is deliberate. `changes` withholds a connector's `semantic` whole and unconditionally for every caller, including the owner, because an op does not carry enough endpoint context to resolve View on each end — so it is a property of the change feed, not caller-specific redaction. Counting it would make `complete` false for the owner of any canvas that has ever had an asserted connector, which would leave the flag unable to distinguish anything. The bundle nonetheless stays self-sufficient, because the scene carries the visible `semantic` and a replayer restores it from there — but that restoration is a required step, not a free one, and the replay recipe below spells it out. The scene-level withholding does count, because there the engine withholds only when the caller cannot see both endpoint records, which is caller-specific.

`complete` speaks about withheld **records, assertions and the home**. It does not cover actor identity: a batch whose author may not be disclosed to the caller carries `actor: null`, and that alone does not make a bundle incomplete, because it costs replay nothing — the fold never reads `actor` from an op.

`limits` is a block of five declared caps, not a measurement of the document: `ops_per_batch` (200), `batch_bytes` (256 KiB), `live_objects` (5 000), `export_bytes` (8 MiB) and `export_batches` (10 000). The bundle's actual size appears only in the over-cap refusal. An export whose canonical bytes exceed 8 MiB, or whose history exceeds 10 000 batches, is refused with an ordinary read error naming the limit (`export_bytes` or `export_batches`) with the measured count, pointing at `changes` paging — and at `include_history: false` for shell plus scene. The 8 MiB figure is a chosen cap rather than a derived one: nothing on the hosted tools route caps tool-result bytes (the body limit in `held/hosting/src/http.rs` guards a request body, image insert, not responses).

A full-database snapshot (`export_snapshot`, whose interchange sections `canvas_objects` and `canvas_batches` plus `content_events` already carry every canvas) is the lossless, unredacted, host-owner form; the canvas bundle is the record-scoped, caller-redacted, JSON form for anyone holding View on the canvas. SQLite packaging of the bundle stays a later option. There is no import tool in v1.

## Replay recipe

Absolute `canvas:N` tokens are `content_events.seq` values and cannot survive a move between databases, so a replayer compares by batch ordinal, not by token: map each object's `geometry` and `content` token to the ordinal of the exported batch carrying that `canvas_version`; map the replayed scene's tokens to the ordinal of the replayed batch; compare objects field by field with ordinals in place of tokens.

For a bundle whose batches are all client-authored (`gesture`, `agent`, `undo`), the recipe an external replayer can run today is re-submission through `manage_canvas.commit_batch` into a new canvas: each batch goes in as a new `agent` batch, rewriting every `expected` token from the previous result's `objects` map (`{ "<id>": { "geometry", "content" } }`). Batches with engine-authored origins (`assertion`, `promotion`) cannot travel this route — a client batch carrying such an origin is refused `invalid_envelope`, because those origins license governed props only the engine may write — so engine replay instead re-folds the exported ops with engine authority.

**Restore withheld connector semantics before folding an assertion.** An assertion batch cannot be re-folded verbatim: the change feed withholds a connector's `semantic` unconditionally, and `validate_props` refuses the literal `"withheld"` under engine authority just as it does under client authority. So before folding, replace any `semantic` reading `"withheld"` — in a create's `object.props` or a patch's `set.props` — with the value the bundle's own scene carries for that object. Fail closed if the scene's value is itself `"withheld"`: that bundle's assertion is not replayable by this caller, and `disclosure.complete` will be false to say so. Nothing regenerates `semantic` from the engine side; the fold stores only what the ops carry.

Three further details the proof relies on. The target canvas must exist and the replaying actor must hold Edit on it. Re-submission sends `ops` only — `pre_images` and `detached` are outcomes of the original fold, not inputs. And a `batch_id` may be reused on a different canvas, because the idempotency ledger is keyed by `(canvas_id, batch_id)`; minting a fresh one is equally safe.

The bundle carries references, not records. A replayed record card names a record id that may not exist in the target database: re-folding lands the card with no face to resolve — exactly as a card on a since-deleted record reads today — and `commit_batch` requires View on the record at commit for a `record_card` create. Provision the records first, or accept faceless cards.

## Connectors and assertion

A connector is decorative until asserted. `semantic` is `null`, or:

```json
{ "relationship": "relates_to", "link_id": "lnk:… | rel:…", "status": "proposed | asserted" }
```

`assert_connector { canvas_id, object_id, relationship, note?, expected? }` turns a decorative connector between two record cards into a governed link. Both endpoints must anchor to live `record_card` objects naming two different records. The link is written through the same governed path `manage_links.add` uses, so it carries that tool's thresholds — Edit on the source record, View on the target — on top of Edit on the canvas. The link write and the `assertion`-origin batch recording it share one transaction and one action attestation, so `inspect_action_attestation` answers "which canvas gesture asserted this link".

`expected` is an optional `{ geometry?, content? }` of `canvas:N` tokens, checked against the connector as the caller last read it. Without it the action has no precondition: the batch it writes pins the connector's own content version, but that version is read inside the same transaction and can only agree with itself. Supply `expected` if it matters that the connector still joins the two cards you saw — otherwise a stale client can assert a governed link between records it never chose.

Outcomes reuse the batch result vocabulary: `committed` on success; `replayed` when the connector already carries that relationship and its link still exists, so re-asserting never writes a second link; `conflict` when `expected` no longer holds; `rejected` otherwise.

A connector already asserted under a **different** live relationship is refused `invalid_precondition` rather than overwritten. Overwriting would replace `semantic` wholesale, leaving the first governed link in place with nothing on the canvas recording it. Remove that link through `manage_links.remove` first.

`link_id` records the id of the row that actually occupies the `(source, target, relationship)` triple, which is not always the one this action would mint: a federated or pre-existing content-owned row may already hold that coordinate, and the relationship-owned projection declines to replace it. Where no id can be cited within `MAX_ID_BYTES`, `link_id` is `null` and `status` is still `asserted` — a link that cannot be cited is honest; a citation that resolves to nothing is not.

**`broken` is derived, never stored.** `status` only ever persists `proposed` or `asserted`. A read reports `broken` when an asserted connector's link row no longer joins its two records — the link may have been removed through `manage_links.remove`, which has no hook to author a compensating canvas batch.

### Disclosure

An assertion is withheld **whole**. `get_scene` returns a connector's `semantic` object only to a caller holding View on **both** endpoint records; otherwise the whole value reads `"withheld"` — the literal string in place of the object.

Withholding only `link_id` would not be enough. A content-owned id spells `lnk:{source}:{target}:{relationship}` and so names both endpoint records, but `relationship` and `status` carry the same fact in another form: "a `blocks` link exists between the records these two cards name" is a fact about those records, and the caller was not permitted it.

`changes` withholds `semantic.link_id` unconditionally, because an op does not carry enough context to resolve its endpoints and check View on each — and a client cannot author `semantic` anyway, so nothing is lost.

`broken` is likewise derived only when both endpoints are visible, since "these two records are no longer linked" is a fact about those records too.

`assert_connector` authorizes the endpoint records **before** any branch that reports something derived from them, including the idempotent replay. Replay returns a link id, so reaching it without View on both records would hand a canvas editor exactly the ids `get_scene` withholds.

## `manage_canvas.promote`

Promotion is the boundary the whole protocol exists for: it turns provisional canvas objects into governed records, in one transaction, under one action attestation.

```json
{
  "action": "promote",
  "canvas_id": "…",
  "reason": "why these become records",
  "dry_run": true,
  "items": [{ "object_id": "…", "type": "WorkItem", "kind": "task", "name": "…", "summary": "…", "facets": {}, "home_id": "…" }],
  "links": [{ "from": "…", "to": "…", "relationship": "depends_on", "note": "…" }],
  "expected": { "canvas_version": "canvas:N", "objects": { "<object_id>": { "geometry": "canvas:N", "content": "canvas:N" } } },
  "plan_digest": "…"
}
```

At most 50 items in a plan — well below the batch op limit, because a plan a person is expected to review should stay reviewable. A link endpoint naming a promoted object resolves to that object's new record; anything else is read as a record that already exists, and needs Edit on a source and View on a target as `manage_links.add` would.

### Prepare, then execute

`dry_run: true` assesses every item **and every link** against the current scene and returns `outcome: "planned"` with a per-entry `would_accept | would_conflict | would_stale`, and a `plan_digest`. It writes nothing: the handler rolls its transaction back before returning. `links` comes back as the assessed plan rather than a count, because approving a promotion means approving what it writes onto records that already exist.

`dry_run: false` requires that `plan_digest` back. The digest binds the canvas version, every promoted object's two version groups, the `reason`, **and** the planned records and links together, so drift in either the scene or the request changes it. The reason is bound because it is durable: it lands in every minted record, every `derived_from` note and the batch origin, so two different committed effects cannot share a digest. A mismatch is `Error::Conflict` (HTTP 409) carrying the literal `revision conflict`, and writes nothing.

`would_conflict` means the plan was never coherent. `would_stale` means an object the caller pinned has moved, been tombstoned, or already become a record card since — drift the caller had seen, which is why it reads as stale and reaches the runtime as a 409 rather than as a revalidation failure. Preparation refuses either rather than handing back a plan already known to fail.

Two conversions are refused outright, because they would strand governed state: a frame that still holds children (a record card cannot parent them, and dissolving someone's grouping is not what promotion was asked to do), and a connector carrying an asserted link (nulling its props would drop the `semantic` that names the link while the link itself stayed in place).

### What one promotion writes

In a single `BEGIN IMMEDIATE`, under one reserved action attestation:

1. Each item is minted through the shared record kernel, so kind resolution, home authorization and facet governance apply exactly as `create_record` applies them. Records are minted **before** any link is written, because an intra-cluster link cannot exist until both of its endpoints do — which is why promotion is composite rather than a loop.
2. Each planned link is written through the same governed path `manage_links.add` uses, and owes its refusals: a blank relationship, and a comment whose bearer is immutable.
3. Each new record gets a `derived_from` link back to the canvas.
4. One `canvas.batch.committed.v1` with `origin.kind: "promotion"` converts each promoted object into a `record_card` **in place**, at the same object id. Every prop the object carried is nulled in the same patch, so a note's text cannot survive onto a card, and the pre-image keeps the old values so `changes` can still invert it.
5. Each new record gets its `canvas.promoted_from` facet, written after the batch so it can name the batch event.

The required-facet guard `create_record` and `create_exploration` apply runs over the minted records before any link is written, so promotion is not a door around it.

Because every output shares one attestation, `inspect_action_attestation` answers "which promotion created this record". The card's `promoted_from` names `{object_id, attestation_id}` rather than the batch event, since a batch payload cannot contain its own event id; the record's facet carries the fuller `{canvas_id, object_id, batch_event_id, attestation_id}`.

## Hand-off boundary: what is real, what is assumed, what is deferred

Canvas v1 is three milestones, all shipped. This section is where the next slice starts; it lists plainly what that slice may build on, what it should treat with care, and what was left out on purpose.

### What is real

- A canvas is an ordinary `Document kind:canvas` record whose scene is an append-only stream of typed operation batches, one `canvas.batch.committed.v1` content event per accepted batch, folded into the current scene and the idempotency ledger.
- `manage_canvas.commit_batch` with per-group version tokens, idempotent replay on `batch_id` reuse, and conflict outcomes that name the competing actor where disclosure allows.
- Record cards that resolve as the caller and read `"withheld"` otherwise, under the one disclosure rule in "Disclosure" above.
- Connectors, decorative until asserted: `manage_canvas.assert_connector` writes a governed link and an `assertion`-origin batch in one transaction, with `broken` derived on read and never stored.
- `manage_canvas.promote`, prepared then executed under one action attestation, turning provisional objects into governed records with record cards left in place.
- `read_canvas` reads — `get_scene`, `changes`, `describe` — the caller-redacted `export` bundle with its `disclosure.complete` honesty flag and its replay recipe, and the size caps the bundle is refused under.
- Presence as described in the section above: a View-gated write route and an id-less snapshot frame, ephemeral and process-local, with the TTL declared on every frame.

### What is assumed or provisional

- Presence is a first cut. It carries cursor, selection and viewport and nothing richer, and its client cadence is a throttle plus a keepalive rather than a delivery guarantee.
- Presence does not span replicas. Two processes serving the same database hold disjoint registries and disjoint subscribers; nothing reconciles them.
- The export cap of 8 MiB is a chosen number, not a derived one. It bounds one caller-redacted document, not the underlying history, and the refusal points at `changes` paging and at `include_history: false`.

### What is deferred

- Frames with predicates: filtering the stream beyond per-canvas View fan-out.
- `retract_connector`: there is an assertion action and no corresponding retraction; removing the governed link is done through `manage_links.remove`, which leaves the canvas `semantic` in place and reads back as `broken`.
- SQLite packaging of the export bundle, which stays a later option; the bundle ships as JSON.
- Multi-replica presence, which the process-local registry cannot serve.
- Postgres and the Turso projector, both declared unsupported for canvas in v1.
- There is no import tool. A bundle is replayed through the recipe above, not submitted whole.
