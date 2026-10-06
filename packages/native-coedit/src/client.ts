import * as Y from "yjs";

import type { ClientMsg, ServerMsg } from "./protocol.js";

/** Origins marking updates applied from the wire, so they are never re-captured. */
const REMOTE_ORIGIN = Symbol("coedit.remote");
const SYNC_ORIGIN = Symbol("coedit.sync");
/** Re-applying an already-sent survivor to the rebuilt visible doc. */
const REPLAY_ORIGIN = Symbol("coedit.replay");

/** A relative position referring to a specific item id (minimal encoding). */
function identityPosition(client: number, clock: number, assoc: number): Y.RelativePosition {
  return { type: null, tname: "body", item: { client, clock }, assoc } as unknown as Y.RelativePosition;
}

/** Flatten a Yjs transaction delete set into ordered mutable ranges. */
function flattenDeleteSet(ds: { clients: Map<number, Array<{ clock: number; len: number }>> }): DeletedRange[] {
  const out: DeletedRange[] = [];
  for (const [client, ranges] of ds.clients) {
    for (const r of ranges) out.push({ client, clock: r.clock, len: r.len });
  }
  return out;
}

export interface CoeditTransport {
  send(msg: ClientMsg): void;
  onMessage(cb: (msg: ServerMsg) => void): void;
}

export type CoeditStatus = "connecting" | "live" | "blocked" | "closed";

export type CoeditEvent =
  | { type: "remote"; from: { person_ref: string | null; kind: string } }
  | { type: "refused"; code: string; refused: string[]; draft: string; unreplayedDeletes: number }
  | { type: "rebuilt" }
  | { type: "exhausted"; draft: string }
  | { type: "versioned"; version: number; body_sha256: string }
  | { type: "closed"; reason: string; draft?: string; unreplayedDeletes?: number }
  | { type: "status"; status: CoeditStatus };

/** Identity of a run of deleted items (Yjs struct id + length). */
interface DeletedRange {
  client: number;
  clock: number;
  len: number;
}

/**
 * A local edit, captured as intent (not structs) so it can be re-authored
 * after a refusal.
 *
 * - insert: `relStart` anchors to the left neighbour in the doc at capture
 *   time (`assoc=-1`), so it tracks concurrent remote shifts. If it cannot be
 *   resolved after a rebuild, the text becomes recovery draft.
 * - delete: `deleted` is the identity of the deleted items read from the
 *   transaction's delete set — never a length or span. Replay deletes each
 *   original item by identity, so a concurrent insert that landed *inside*
 *   the original span survives (F1) and a mid-span delete is not over-wide
 *   (F0). An item that is not present in the rebuilt doc (its authoring
 *   pending edit was refused) is counted as unreplayed deletion intent (F3).
 */
interface SemanticOp {
  relStart?: Y.RelativePosition;
  insert?: string;
  attributes?: Record<string, unknown>;
  deleted?: DeletedRange;
}

interface PendingEntry {
  update: Uint8Array;
  ops: SemanticOp[];
}

export interface CoeditClientOptions {
  key: string;
  record_id: string;
  mode: "edit" | "view";
}

/**
 * Transport-agnostic coedit client. Single-use: `open()` may be called once.
 *
 * - `confirmed` (private) is server-acknowledged state; `visible`/`text` is
 *   what the user edits and sees. Local edits on `text` are captured per Yjs
 *   update event into `pending` and sent; an ack moves the update into
 *   `confirmed`. Remote updates apply to both docs.
 * - Structs are authored with a leased id from `doc_client_ids`; the id
 *   rotates after a refusal rebuild (`authorId`/`authorIndex`), so a refused
 *   id's clock gap can never be closed.
 * - Edits made before `opened` arrives are held as *intent* and re-authored
 *   under the leased id once live (never sent under the provisional id).
 *   Callers should still await the `live` status before editing.
 */
export class CoeditClient {
  private confirmed = new Y.Doc();
  private visibleDoc = new Y.Doc();

  private readonly transport: CoeditTransport;
  private readonly opts: CoeditClientOptions;
  private readonly nonce: string;
  private readonly pending = new Map<string, PendingEntry>();
  private readonly listeners = new Set<(e: CoeditEvent) => void>();
  /** Post-exhaustion (blocked) edits: never sent, preserved for recovery (E2). */
  private blockedOps: SemanticOp[] = [];
  /** Local semantic ops gathered during the current transaction. */
  private readonly txOps = new Map<Y.Transaction, SemanticOp[]>();

  private seq = 0;
  private session = "";
  private peer = "";
  private status: CoeditStatus = "connecting";
  private leased: number[] = [];
  private authorIndex = 0;
  private opened = false;
  private handshook = false;

  constructor(transport: CoeditTransport, opts: CoeditClientOptions) {
    this.transport = transport;
    this.opts = opts;
    this.nonce = Math.random().toString(36).slice(2, 10);
  }

  /** The visible doc. Replaced wholesale by `rebuild()`; re-read, don't cache. */
  get visible(): Y.Doc {
    return this.visibleDoc;
  }

  /** The visible doc root: confirmed + pending. */
  get text(): Y.Text {
    return this.visibleDoc.getText("body");
  }

  get pendingCount(): number {
    return this.pending.size;
  }

  get connectionStatus(): CoeditStatus {
    return this.status;
  }

  on(cb: (e: CoeditEvent) => void): () => void {
    this.listeners.add(cb);
    return () => {
      this.listeners.delete(cb);
    };
  }

  /**
   * Single-use. A second call is ignored: the transport interface has no
   * unsubscribe, so stacking observers/handlers could not be undone (A1).
   */
  open(): void {
    if (this.opened) return;
    this.opened = true;
    this.attach(this.visibleDoc);
    this.transport.onMessage(this.handleMessage);
    this.transport.send({
      op: "session.open",
      key: this.opts.key,
      record_id: this.opts.record_id,
      mode: this.opts.mode,
    });
  }

  /** Wire the capture observers onto a (possibly fresh) visible doc. */
  private attach(doc: Y.Doc): void {
    doc.on("update", this.handleVisibleUpdate);
    doc.getText("body").observe(this.captureOps);
  }

  private captureOps = (event: Y.YTextEvent, tx: Y.Transaction): void => {
    if (tx.origin === REMOTE_ORIGIN || tx.origin === SYNC_ORIGIN || tx.origin === REPLAY_ORIGIN) return;
    const text = this.visibleDoc.getText("body");
    const ops: SemanticOp[] = [];
    // Deleted item identities come from the transaction's delete set (original
    // struct ids), never from post-delete text coordinates.
    const queue = flattenDeleteSet(tx.deleteSet);
    let cursor = 0;
    let index = 0;
    for (const d of event.delta) {
      if (d.retain !== undefined) {
        index += d.retain;
      } else if (d.insert !== undefined) {
        const str = typeof d.insert === "string" ? d.insert : "";
        ops.push({
          // assoc -1: anchor to the left neighbour so the insert tracks shifts.
          relStart: Y.createRelativePositionFromTypeIndex(text, index, -1),
          insert: str,
          attributes: d.attributes as Record<string, unknown> | undefined,
        });
        index += str.length;
      } else if (d.delete !== undefined) {
        let remaining = d.delete;
        while (remaining > 0 && cursor < queue.length) {
          const r = queue[cursor];
          const take = Math.min(remaining, r.len);
          ops.push({ deleted: { client: r.client, clock: r.clock, len: take } });
          r.clock += take;
          r.len -= take;
          remaining -= take;
          if (r.len === 0) cursor++;
        }
        // Deleted content is absent from the new text, so the position does
        // not advance (a following insert sits at the gap start).
      }
    }
    this.txOps.set(tx, ops);
  };

  private handleVisibleUpdate = (update: Uint8Array, origin: unknown, _doc: Y.Doc, tx?: Y.Transaction): void => {
    if (origin === REMOTE_ORIGIN || origin === SYNC_ORIGIN || origin === REPLAY_ORIGIN) return;
    // Blocked (post-exhaustion) edits must never send, but their captured
    // intent is preserved for recovery (E2); closed edits are dropped.
    if (this.status === "blocked" || this.status === "closed") {
      const dropped = (tx !== undefined ? this.txOps.get(tx) : undefined) ?? [];
      if (tx !== undefined) this.txOps.delete(tx);
      if (this.status === "blocked") this.blockedOps.push(...dropped);
      return;
    }
    const ops = (tx !== undefined ? this.txOps.get(tx) : undefined) ?? [];
    if (tx !== undefined) this.txOps.delete(tx);
    // Pre-live edits never touch the wire. The visible doc holds their NET
    // plaintext; raw provisional-id structs are discarded and the net snapshot
    // is re-authored under the leased id on `opened` (A2/L2). Provisional
    // insert/delete identities are not replayed, so a pre-live self-delete
    // cannot resurrect text.
    if (this.status === "connecting") return;
    const update_id = `${this.nonce}:${++this.seq}`;
    this.pending.set(update_id, { update, ops });
    this.transport.send({ op: "session.update", session: this.session, update, update_id });
  };

  requestVersion(reason: string): void {
    if (this.status !== "live") return;
    this.transport.send({ op: "session.version", session: this.session, reason });
  }

  close(): void {
    if (this.status === "closed") return;
    // Send the close whenever a session exists, including from `blocked`, so
    // the server peer does not linger to an idle close (E2).
    if (this.status !== "connecting") {
      this.transport.send({ op: "session.close", session: this.session });
    }
    this.finishClosed("closed");
  }

  /**
   * Terminal close. Preserves every unconfirmed edit as recovery draft before
   * clearing `pending`, so intent is not lost (A5). The client is single-use:
   * `open()` is ignored after the first call, so a stale old-lease entry can
   * never be flushed under a new session.
   */
  private finishClosed(reason: string): void {
    if (this.status === "closed") return;
    const { draft, unreplayedDeletes } = this.collectRecovery();
    this.pending.clear();
    this.blockedOps = [];
    this.setStatus("closed");
    this.emit({ type: "closed", reason, draft, unreplayedDeletes });
  }

  /**
   * Unconfirmed inserted text + delete-unit count. Before the handshake the
   * pre-live visible doc holds the user's NET pre-live text (server state has
   * not arrived), so its snapshot is the recovery draft — raw intermediate
   * inserts/deletes are never surfaced, so canceled text cannot resurrect.
   */
  private collectRecovery(): { draft: string; unreplayedDeletes: number } {
    let draft = "";
    let unreplayedDeletes = 0;
    for (const [, entry] of this.pending) {
      draft += this.insertedText(entry.ops);
      unreplayedDeletes += this.deletedUnits(entry.ops);
    }
    if (!this.handshook) draft += this.visibleDoc.getText("body").toString();
    draft += this.insertedText(this.blockedOps);
    unreplayedDeletes += this.deletedUnits(this.blockedOps);
    return { draft, unreplayedDeletes };
  }

  private handleMessage = (msg: ServerMsg): void => {
    // A4: only the first opened handshake is honoured; every other frame must
    // belong to the live session and is ignored after close.
    if (msg.op === "session.opened") {
      if (this.handshook || this.status === "closed") return; // L3
    } else {
      if (msg.session !== this.session) return;
      if (this.status === "closed" && msg.op !== "session.closed") return;
    }
    switch (msg.op) {
      case "session.opened": {
        this.session = msg.session;
        this.peer = msg.peer;
        this.leased = [...msg.doc_client_ids];
        this.authorIndex = 0;
        this.handshook = true;
        // confirmed never authors; reserve the last leased id so applying
        // acked updates (which carry an author id) can't trip yjs's
        // client-id-collision guard.
        this.confirmed.clientID = this.leased[this.leased.length - 1] ?? this.authorId();
        this.confirmed.transact(() => Y.applyUpdate(this.confirmed, msg.sync), SYNC_ORIGIN);
        // Collapse the pre-live visible doc to its NET plaintext before it is
        // replaced. It started empty and saw no server state, so its text is
        // the user's intended pre-live content. Re-authored under the leased id
        // at the START of the body (existing first-insert semantics); canceled
        // text is already collapsed away, so it never resurrects (L2).
        const preliveNet = this.visibleDoc.getText("body").toString();
        // Fresh visible doc = confirmed.
        const next = new Y.Doc();
        next.clientID = this.authorId();
        next.transact(() => Y.applyUpdate(next, Y.encodeStateAsUpdate(this.confirmed)), SYNC_ORIGIN);
        const stale = this.visibleDoc;
        this.visibleDoc = next;
        stale.destroy();
        this.attach(next);
        this.setStatus("live");
        // Re-author the collapsed pre-live net at the body start; this captures
        // and sends under the leased id. `pending` is empty here (pre-live ops
        // were never queued), so no flush loop is needed.
        if (preliveNet !== "") next.getText("body").insert(0, preliveNet);
        break;
      }
      case "session.ack": {
        const entry = this.pending.get(msg.update_id);
        if (entry === undefined) break; // unknown or already retired
        this.pending.delete(msg.update_id);
        Y.applyUpdate(this.confirmed, entry.update);
        break;
      }
      case "session.refused": {
        // Idempotent: a duplicate or stale refusal naming only ids we no longer
        // hold is ignored. Rebuilding on it would burn a lease and replay
        // survivors a second time (F2). Trusted sync is still applied, since
        // absorbing server state is safe and distinct from re-authoring.
        if (!msg.refused.some((id) => this.pending.has(id))) {
          // Stale/duplicate refusal: absorb the trusted sync into both docs so
          // visible does not lag confirmed (V4).
          Y.applyUpdate(this.confirmed, msg.sync);
          this.visibleDoc.transact(() => Y.applyUpdate(this.visibleDoc, msg.sync), SYNC_ORIGIN);
          break;
        }
        this.rebuild(msg.code, [...msg.refused], msg.sync);
        break;
      }
      case "session.remote": {
        Y.applyUpdate(this.confirmed, msg.update);
        this.visibleDoc.transact(() => Y.applyUpdate(this.visibleDoc, msg.update), REMOTE_ORIGIN);
        this.emit({ type: "remote", from: msg.from });
        break;
      }
      case "session.versioned": {
        this.emit({ type: "versioned", version: msg.version, body_sha256: msg.body_sha256 });
        break;
      }
      case "session.closed": {
        this.finishClosed(msg.reason);
        break;
      }
    }
  };

  /**
   * Author ids are the leased pool minus its last entry (reserved for the
   * `confirmed` doc identity). An id is never reused: after a refusal rebuild
   * we advance, so the abandoned id's clock gap can never be closed by a later
   * edit (which would resurrect its refused followers). When the pool is
   * exhausted `rebuild` fails closed rather than reusing an id.
   */
  private authorPool(): number[] {
    return this.leased.length > 1 ? this.leased.slice(0, -1) : [...this.leased];
  }

  private authorId(): number {
    return this.authorPool()[this.authorIndex];
  }

  /**
   * Refusal rebuild. Drops refused entries, absorbs the server sync into
   * `confirmed`, then replaces `visible` with a fresh doc seeded from
   * `confirmed` and re-authors the surviving (uncovered) pending edits under a
   * fresh leased id. Emits `rebuilt` (visible identity changed) then `refused`
   * with the recovery draft.
   *
   * The replaced doc is destroyed so no stale listener can author silently.
   *
   * If no fresh leased id remains, this fails closed: it still rebuilds the
   * visible doc from `confirmed` (dropping refused structs) but replays
   * nothing, instead surfacing ALL unconfirmed text (refused + surviving) as
   * the recovery draft and emitting `exhausted`. It never reuses a retired or
   * unleased id. A live session recovers only with fresh server-issued leases;
   * the lease-refresh protocol addition is an explicit integration dependency.
   */
  private rebuild(code: string, refused: string[], sync: Uint8Array): void {
    let draft = "";
    // Deletion units from refused updates have no text form; count them (F3).
    let unreplayedDeletes = 0;
    /** Survivors whose original bytes can integrate: keep, don't re-author. */
    const resend: PendingEntry[] = [];
    /** Survivors that must be re-authored under a fresh id (clock gap, F0/F1). */
    const survivors: SemanticOp[] = [];
    for (const id of refused) {
      const entry = this.pending.get(id);
      if (entry !== undefined) {
        draft += this.insertedText(entry.ops);
        unreplayedDeletes += this.deletedUnits(entry.ops);
      }
      this.pending.delete(id);
    }
    this.confirmed.transact(() => Y.applyUpdate(this.confirmed, sync), SYNC_ORIGIN);
    // Working frontier advances as integratable survivors are accepted, so a
    // later survivor from the same author stays contiguous.
    const frontier = Y.decodeStateVector(Y.encodeStateVector(this.confirmed));
    for (const [id, entry] of [...this.pending]) {
      if (this.isCovered(entry)) {
        this.pending.delete(id); // server already has it (arrived in sync)
      } else if (this.integrates(entry, frontier)) {
        resend.push(entry); // keep original id + bytes; shown again below
      } else {
        survivors.push(...entry.ops);
        this.pending.delete(id); // re-authored under a new id
      }
    }

    const hasFreshId = this.authorIndex + 1 < this.authorPool().length;
    // A real rebuild always rotates to a fresh author id for future edits; the
    // refused id's clock range is never reused, so its gap cannot be closed.
    const next = new Y.Doc();
    next.clientID = hasFreshId ? this.authorPool()[this.authorIndex + 1] : this.leased[this.leased.length - 1] ?? 0;
    next.transact(() => Y.applyUpdate(next, Y.encodeStateAsUpdate(this.confirmed)), SYNC_ORIGIN);
    // Integratable survivors were already sent (or are buffered); re-apply them
    // to the rebuilt visible doc so the user still sees them, without recapture.
    // Gated on a fresh lease: on exhaustion nothing can be re-sent, so visible
    // must equal confirmed (E1a) or it would show unsendable text also in draft.
    if (hasFreshId) {
      for (const entry of resend) next.transact(() => Y.applyUpdate(next, entry.update), REPLAY_ORIGIN);
    }
    const stale = this.visibleDoc;
    this.visibleDoc = next;
    stale.destroy(); // detach listeners; a stale doc must never author again
    this.attach(next);
    this.emit({ type: "rebuilt" });

    if (!hasFreshId) {
      // Fail closed: preserve every unconfirmed edit as draft text (refused,
      // integratable-survivor and re-authorable-survivor inserts alike), replay
      // none, and stop authoring so no unleased id can be sent (L1).
      // Clock-gap survivors' delete intent is counted too (E1b).
      let all = draft + this.insertedText(survivors);
      unreplayedDeletes += this.deletedUnits(survivors);
      for (const [id, entry] of [...this.pending]) {
        all += this.insertedText(entry.ops);
        unreplayedDeletes += this.deletedUnits(entry.ops);
        this.pending.delete(id);
      }
      this.setStatus("blocked");
      this.emit({ type: "exhausted", draft: all });
      this.emit({ type: "refused", code, refused: [...refused], draft: all, unreplayedDeletes });
      return;
    }
    this.authorIndex++;
    const replayed = this.replay(survivors);
    draft += replayed.orphaned;
    unreplayedDeletes += replayed.unreplayedDeletes;
    this.emit({ type: "refused", code, refused: [...refused], draft, unreplayedDeletes });
  }

  /**
   * True when a survivor's original bytes can integrate against `confirmed`:
   * every struct starts at or before the known frontier for its author, and
   * every deleted range targets items `confirmed` already holds. Otherwise the
   * update depends on a refused struct's clock range and must be re-authored.
   * Advances `frontier` for accepted structs.
   */
  private integrates(entry: PendingEntry, frontier: Map<number, number>): boolean {
    const { structs, ds } = Y.decodeUpdate(entry.update);
    for (const s of structs) {
      if (s.id.clock > (frontier.get(s.id.client) ?? 0)) return false;
    }
    for (const [client, ranges] of ds.clients) {
      for (const r of ranges) {
        if (r.clock + r.len > (frontier.get(client) ?? 0)) return false;
      }
    }
    for (const s of structs) {
      const end = s.id.clock + s.length;
      frontier.set(s.id.client, Math.max(frontier.get(s.id.client) ?? 0, end));
    }
    return true;
  }

  private insertedText(ops: SemanticOp[]): string {
    let out = "";
    for (const op of ops) if (op.insert !== undefined) out += op.insert;
    return out;
  }

  /** Number of deleted item units across ops (delete intent, not text). */
  private deletedUnits(ops: SemanticOp[]): number {
    let n = 0;
    for (const op of ops) if (op.deleted !== undefined) n += op.deleted.len;
    return n;
  }

  /**
   * True when `confirmed` already contains everything in a pending update.
   *
   * Two-part check. (1) Structs: `encodeStateVectorFromUpdate` reads the
   * update's new structs even when they cannot integrate yet (a clock gap),
   * so a clock beyond `confirmed`'s vector means not covered. (2) Deletes: a
   * delete-only update adds no structs, so its state vector is empty and part
   * (1) would pass vacuously; instead apply it to a clone of `confirmed` and
   * compare the text. A delete whose effect is absent means not covered — so a
   * pending delete is replayed, never silently dropped.
   */
  private isCovered(entry: PendingEntry): boolean {
    const covered = Y.decodeStateVector(Y.encodeStateVector(this.confirmed));
    // `decodeUpdate` reports the update's own structs and delete set even when
    // `encodeStateVectorFromUpdate` does not (a per-transaction update is a
    // diff, not a standalone state, and its encoded state vector can be empty).
    const { structs, ds } = Y.decodeUpdate(entry.update);
    for (const s of structs) {
      const end = s.id.clock + s.length;
      if ((covered.get(s.id.client) ?? 0) < end) return false;
    }
    if (ds.clients.size === 0) return true; // no new structs, no deletes
    // If the delete set targets items `confirmed` does not hold (a clock beyond
    // its vector), the delete is against a still-unconfirmed item (a dependent
    // delete): not covered, so it becomes a survivor and its intent surfaces.
    for (const [client, ranges] of ds.clients) {
      for (const r of ranges) {
        if ((covered.get(client) ?? 0) < r.clock + r.len) return false;
      }
    }
    // Delete-only (or delete-bearing): apply to a clone of `confirmed`; an
    // absent text effect means the server has not applied it.
    const clone = new Y.Doc();
    Y.applyUpdate(clone, Y.encodeStateAsUpdate(this.confirmed));
    const before = clone.getText("body").toString();
    Y.applyUpdate(clone, entry.update);
    return clone.getText("body").toString() === before;
  }

  /**
   * Re-apply captured intent as fresh local edits (re-enters pending + sends).
   *
   * Deletes are replayed by *item identity*: each deleted struct is located in
   * the rebuilt doc and deleted individually. A concurrent insert that landed
   * inside the original span is a separate item and survives (F1); a mid-span
   * delete is never widened (F0).
   *
   * Returns editorial text that could not be replayed (insert ops whose anchor
   * was refused → recovery draft) and the count of deletion units whose items
   * were not present in the rebuilt doc (dependent/conflicting delete intent,
   * surfaced rather than silently dropped — F3).
   */
  private replay(ops: SemanticOp[]): { orphaned: string; unreplayedDeletes: number } {
    const text = this.visibleDoc.getText("body");
    let orphaned = "";
    let unreplayedDeletes = 0;
    for (const op of ops) {
      if (op.insert !== undefined) {
        const start = op.relStart !== undefined
          ? Y.createAbsolutePositionFromRelativePosition(op.relStart, this.visibleDoc)
          : null;
        if (start === null) {
          orphaned += op.insert;
          continue;
        }
        if (op.attributes !== undefined) text.insert(start.index, op.insert, op.attributes);
        else text.insert(start.index, op.insert);
      } else if (op.deleted !== undefined) {
        const { client, clock, len } = op.deleted;
        for (let k = clock; k < clock + len; k++) {
          const start = Y.createAbsolutePositionFromRelativePosition(identityPosition(client, k, 1), this.visibleDoc);
          const end = Y.createAbsolutePositionFromRelativePosition(identityPosition(client, k, -1), this.visibleDoc);
          if (start === null || end === null) {
            unreplayedDeletes++; // item not in the rebuilt doc: intent surfaced
            continue;
          }
          const span = end.index - start.index;
          if (span > 0) text.delete(start.index, span);
        }
      }
    }
    return { orphaned, unreplayedDeletes };
  }

  private setStatus(status: CoeditStatus): void {
    this.status = status;
    this.emit({ type: "status", status });
  }

  private emit(e: CoeditEvent): void {
    for (const cb of this.listeners) cb(e);
  }
}
