# NOTES — refusal rebuild (B2b-i, B2b-ii, correctness unit)

## Layers
- `confirmed` = server-acknowledged state. `visible` = what the user sees.
- `pending: Map<update_id, {update: bytes, ops: SemanticOp[]}>`.
- Local edits captured as intent (`ops`), never replayed as raw structs.

## Sound rule (measured, not assumed)
Dropping a refused update leaves a permanent Yjs clock gap: any later update from the
same author id starting after that gap is parked in `pendingStructs` and its text is
lost, even when its own text origin is independent. Reusing the retired id can then
double-insert. Reproduced with plain node/yjs scripts.

## Deletes are captured and replayed by ITEM IDENTITY (F0, F1)
`captureOps` reads the deleted items from the transaction delete set
(`tx.deleteSet`), storing `{client, clock, len}` — never a length or a pair of span
endpoints. Fixes:
- **F0**: post-delete text coordinates made a mid-span delete replay one span too wide
  (`abcde` delete b → `ade`). Identity deletes replay exactly the deleted items.
- **F1**: span endpoints swallowed a concurrent confirmed insert inside the span. Deleting
  each original item individually leaves the concurrent insert standing.
Replay resolves each item id via a minimal relative position (`{tname, item:{client,clock},
assoc}`) and deletes it in place.

## Rebuild classification (rebuild)
On `session.refused`:
1. Drop refused entries; draft = their inserted text; count their delete units (F3).
2. Absorb `sync` into `confirmed`.
3. For each remaining pending entry:
   - **covered** (`isCovered`) → server already has it → drop;
   - **integrates** (all structs start at/before `confirmed`'s frontier, all deleted
     targets already known) → keep the original id and bytes, re-apply to the rebuilt
     visible doc with `REPLAY_ORIGIN` so the user still sees it; do NOT re-author;
   - otherwise (depends on a refused clock range) → re-author its ops under a fresh id.
4. Replace `visible` with a fresh doc seeded from `confirmed`, apply kept survivors, rotate
   to a fresh leased author id, replay re-authored ops, destroy the stale doc.
5. Emit `rebuilt`, then `refused { code, refused, draft, unreplayedDeletes }`.

Rotating the author id means the abandoned id's gap is never closed, so its in-flight
followers can never integrate.

## isCovered
`decodeUpdate` gives the update's structs and delete set (a per-transaction update is a
diff, so `encodeStateVectorFromUpdate` can be empty). Not covered if any struct end-clock
is beyond `confirmed`'s vector, or any deleted range targets items beyond it (a dependent
delete against an unconfirmed item), or (for known targets) applying to a clone changes the
text. Errs toward replay.

## Duplicate/stale refusals (F2)
If no id in `session.refused` is still pending, the refusal is ignored (only trusted `sync`
is absorbed). This prevents a duplicated refusal from burning a lease and replaying
survivors twice; the handler is idempotent.

## Delete intent surfaced (F3)
`refused.unreplayedDeletes` counts delete units that could not be replayed (targets absent
from the rebuilt doc, or deletes inside refused updates). Drafts carry inserted text only;
delete intent is reported by count, never silently dropped.

## Lease exhaustion fails closed (L1)
Author ids are the leased pool minus its last entry (reserved for `confirmed`). An id is
never reused. With no fresh id, the rebuild drops refused structs, replays nothing, surfaces
ALL unconfirmed text as draft, sets status `blocked`, and emits `exhausted`. While `blocked`
or `closed`, `handleVisibleUpdate` neither queues nor sends (no unleased id can be sent).

## Remaining scope (explicit; no convergence claim)
- **Parent remapping.** A re-authored survivor whose ops anchor on a refused item is
  surfaced (`unreplayedDeletes` for deletes; draft text for inserts) but not rebuilt as a
  new valid op. Mapping old surviving parent edits onto newly re-authored ids is not done.
- **Formatting/attribute deltas** are not captured as ops (only text insert/delete).
- **Retry.** Kept integratable survivors are assumed delivered; there is no explicit
  resend/retry if a sent update is lost without refusal.
- **Lease refresh** protocol addition is an integration dependency; `blocked` has no
  in-session resume API.
- **Fixture vs core.** `FakeHome` issues an id pool per open (test scaffolding). Contract
  M8a leases per host device durably; the Rust core may issue a single lease. No end-to-end
  compatibility claim.
- **Concurrency.** Insert-only convergence holds (200/50-round tests). Deletes are covered
  only by the identity fix and its edge tests, not a general concurrent convergence claim.

## Lifecycle (A1–A6)
- **A1** `open()` is single-use: repeat calls are ignored (the transport has no unsubscribe,
  so observers/handlers cannot be stacked).
- **A2 / L2** Pre-live edits never touch the wire. The pre-live visible doc starts empty and
  sees no server state, so at `opened` its **net plaintext** is snapshotted and re-authored
  under the leased id at the START of the body (existing first-insert semantics). Provisional
  insert/delete identities are never replayed, so a pre-live self-delete cannot resurrect
  text and canceled text is not surfaced as recovery. `close()` before the handshake recovers
  that same net snapshot (empty net → empty draft, no phantom delete intent).
- **A3** `confirmed` is private; `visible`/`text` is the edit surface.
- **A4** `handleMessage` honours only the first `session.opened`; other frames must match the
  live session and are ignored after `closed` (only `session.closed` is accepted then).
- **A5** `close()` (and a server `session.closed`) preserves every unconfirmed edit as
  `closed.draft` (+ `unreplayedDeletes`) before clearing `pending`; a later `open()` is a
  no-op, so no old-lease entry can be flushed under a new session.
- **A6** The class comment now describes the rotating author id, not `doc_client_ids[0]`.

## Exhaustion ordering, blocked recovery, close (E1/E2/L3/V4)
- **E1a** On exhaustion nothing can be re-sent, so integratable-resend survivors are NOT
  re-applied to `visible`; `visible` equals `confirmed`, and their inserted text is surfaced
  in the draft instead of being shown as unsendable text.
- **E1b** Clock-gap (re-authorable) survivors contribute their `deletedUnits` to
  `unreplayedDeletes` on the exhaustion path, not just their inserted text.
- **E2** While `blocked`, edits are not sent but their captured intent is buffered
  (`blockedOps`) and surfaced via `closed.draft` on close; `close()` from `blocked` sends
  `session.close` so the server peer does not linger. **Apps must disable editing on
  `blocked`** (documented in README).
- **L3** A delayed `session.opened` is ignored when the client is already `closed` (or has
  already handshook), so a close-before-opened race cannot revive a terminal client.
- **V4** A stale/unknown refusal absorbs its trusted `sync` into BOTH `confirmed` and
  `visible` (`SYNC_ORIGIN`) so the visible layer cannot lag confirmed.
- `close()` is idempotent (no second `session.close`).
- **Pre-live self-delete (L2).** Resolved by the net-snapshot collapse above; a pre-live
  insert-then-delete no longer resurrects text. Awaits independent review.
