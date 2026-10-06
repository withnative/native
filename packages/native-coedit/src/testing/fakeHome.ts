import { createHash } from "node:crypto";
import * as Y from "yjs";

import type { CoeditTransport } from "../client.js";
import type { ClientMsg, ServerMsg } from "../protocol.js";

/** Deterministic RNG for delivery delays (mulberry32). */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export interface FakeHomeOptions {
  seed?: number;
  maxDelayMs?: number;
  maxUpdateBytes?: number;
  /** Leased ids per peer. The kit reserves one, so authors = size - 1. */
  leasePoolSize?: number;
}

interface Link {
  peer: string | null;
  inbox: ((msg: ServerMsg) => void) | null;
}

interface Peer {
  leased: number[];
  mode: "edit" | "view";
  sessions: Set<string>;
  /** Shadow doc of exactly the updates home has acked for this peer. */
  acked: Y.Doc;
}

/**
 * In-process home test double: leases client ids, validates updates,
 * acks, and broadcasts remote updates to the other peers of a session.
 * Both directions deliver with seeded random delay; `quiescent()` waits
 * until every scheduled delivery has landed.
 */
export class FakeHome {
  readonly doc = new Y.Doc();

  /** Refuse the next update with this code (unapplied). One-shot. */
  refuseNext(code: string): void {
    this.refuseCode = code;
  }

  private refuseCode: string | null = null;

  private readonly rng: () => number;
  private readonly maxDelayMs: number;
  private readonly maxUpdateBytes: number;
  private readonly leasePoolSize: number;
  private readonly peers = new Map<string, Peer>();
  private readonly links: Link[] = [];
  private readonly sessionPeers = new Map<string, Set<string>>();
  private readonly rooms = new Map<string, string>();

  private nextId = 1;
  private clock = 0;
  private inFlight = 0;

  constructor(opts: FakeHomeOptions = {}) {
    this.rng = mulberry32(opts.seed ?? 1);
    this.maxDelayMs = opts.maxDelayMs ?? 5;
    this.maxUpdateBytes = opts.maxUpdateBytes ?? 64 * 1024;
    this.leasePoolSize = Math.max(2, opts.leasePoolSize ?? 8);
  }

  get text(): string {
    return this.doc.getText("body").toString();
  }

  /** Wire a client transport to this home (loopback pair with delays). */
  connect(): CoeditTransport {
    const link: Link = { peer: null, inbox: null };
    this.links.push(link);
    return {
      send: (msg: ClientMsg) => this.schedule(() => this.receive(link, msg)),
      onMessage: (cb: (msg: ServerMsg) => void) => {
        link.inbox = cb;
      },
    };
  }

  private schedule(fn: () => void): void {
    this.inFlight++;
    const delay = Math.floor(this.rng() * (this.maxDelayMs + 1));
    setTimeout(() => {
      try {
        fn();
      } finally {
        this.inFlight--;
      }
    }, delay);
  }

  private sendTo(link: Link, msg: ServerMsg): void {
    this.schedule(() => link.inbox?.(msg));
  }

  private receive(link: Link, msg: ClientMsg): void {
    switch (msg.op) {
      case "session.open":
        this.handleOpen(link, msg);
        break;
      case "session.update":
        this.handleUpdate(link, msg);
        break;
      case "session.version":
        this.handleVersion(link, msg);
        break;
      case "session.close":
        this.handleClose(link, msg);
        break;
    }
  }

  private handleOpen(link: Link, msg: Extract<ClientMsg, { op: "session.open" }>): void {
    const n = this.nextId++;
    const peer = `peer${n}`;
    // One session per record: a second open for the same key+record joins.
    // (Single-doc double: every session shares this doc; one record per home.)
    const room = `${msg.key} ${msg.record_id}`;
    let session = this.rooms.get(room);
    if (session === undefined) {
      session = `session${n}`;
      this.rooms.set(room, session);
      this.sessionPeers.set(session, new Set());
    }
    // A pool: the client authors with the first, reserves the last as its
    // confirmed-doc identity, and rotates to the next after a refusal rebuild.
    const base = 0x1000 + n * 16;
    const leased = Array.from({ length: this.leasePoolSize }, (_, i) => base + i);
    link.peer = peer;
    this.peers.set(peer, { leased, mode: msg.mode, sessions: new Set([session]), acked: new Y.Doc() });
    this.sessionPeers.get(session)?.add(peer);
    this.sendTo(link, {
      op: "session.opened",
      session,
      peer,
      doc_client_ids: leased,
      sync: Y.encodeStateAsUpdate(this.doc),
      base: { version: this.clock, body_sha256: this.sha() },
      limits: { max_update_bytes: this.maxUpdateBytes },
      presence: { sharing: true },
    });
  }

  private sha(): string {
    return createHash("sha256").update(this.text, "utf8").digest("hex");
  }

  private handleUpdate(link: Link, msg: Extract<ClientMsg, { op: "session.update" }>): void {
    const peer = link.peer !== null ? this.peers.get(link.peer) : undefined;
    if (peer === undefined || !peer.sessions.has(msg.session)) return; // unknown session: drop
    if (peer.mode === "view") {
      this.refuse(link, msg, "forbidden");
      return;
    }
    if (this.refuseCode !== null) {
      const code = this.refuseCode;
      this.refuseCode = null;
      this.refuse(link, msg, code);
      return;
    }
    if (msg.update.byteLength > this.maxUpdateBytes) {
      this.refuse(link, msg, "too_large");
      return;
    }
    let ids: Iterable<number>;
    try {
      ids = Y.decodeStateVector(Y.encodeStateVectorFromUpdate(msg.update)).keys();
    } catch {
      this.refuse(link, msg, "bad_doc_shape");
      return;
    }
    for (const id of ids) {
      if (!peer.leased.includes(id)) {
        this.refuse(link, msg, "foreign_client_id");
        return;
      }
    }
    // Doc shape: the update must not introduce roots beyond `body: Y.Text`.
    // NOTE: the `body` root is pre-created because lazily-decoded roots come
    // back as bare AbstractType shells (content intact, class lost), which
    // defeats instanceof. Smuggled extra roots still show up as share keys.
    const scratch = new Y.Doc();
    scratch.getText("body");
    Y.applyUpdate(scratch, Y.encodeStateAsUpdate(this.doc));
    try {
      Y.applyUpdate(scratch, msg.update);
    } catch {
      this.refuse(link, msg, "bad_doc_shape");
      return;
    }
    if (!this.isBodyOnly(scratch)) {
      this.refuse(link, msg, "bad_doc_shape");
      return;
    }
    this.clock++;
    Y.applyUpdate(this.doc, msg.update);
    Y.applyUpdate(peer.acked, msg.update);
    this.sendTo(link, { op: "session.ack", session: msg.session, update_id: msg.update_id, clock: this.clock });
    const from = { person_ref: link.peer, kind: "peer" };
    for (const other of this.links) {
      if (other !== link && other.peer !== null && this.peers.get(other.peer)?.sessions.has(msg.session)) {
        this.sendTo(other, { op: "session.remote", session: msg.session, update: msg.update, from });
      }
    }
  }

  private isBodyOnly(doc: Y.Doc): boolean {
    const keys = Array.from(doc.share.keys());
    return keys.length === 1 && keys[0] === "body" && doc.share.get("body") instanceof Y.Text;
  }

  private refuse(link: Link, msg: Extract<ClientMsg, { op: "session.update" }>, code: string): void {
    // Sync is home state diffed against what this peer has had acked (a lower
    // bound of its confirmed state; re-sending known structs is idempotent).
    // The refused update is never applied, so it is never in the diff.
    const acked = link.peer !== null ? this.peers.get(link.peer)?.acked : undefined;
    const sync =
      acked !== undefined
        ? Y.encodeStateAsUpdate(this.doc, Y.encodeStateVector(acked))
        : Y.encodeStateAsUpdate(this.doc);
    this.sendTo(link, {
      op: "session.refused",
      session: msg.session,
      code,
      refused: [msg.update_id],
      sync,
    });
  }

  private handleVersion(link: Link, msg: Extract<ClientMsg, { op: "session.version" }>): void {
    this.sendTo(link, { op: "session.versioned", session: msg.session, version: this.clock, body_sha256: this.sha() });
  }

  private handleClose(link: Link, msg: Extract<ClientMsg, { op: "session.close" }>): void {
    if (link.peer !== null) {
      this.peers.get(link.peer)?.sessions.delete(msg.session);
      this.sessionPeers.get(msg.session)?.delete(link.peer);
    }
    this.sendTo(link, { op: "session.closed", session: msg.session, reason: "closed" });
  }

  /** Resolve once every scheduled delivery has landed (throw on timeout). */
  async quiescent(timeoutMs = 5000): Promise<void> {
    const start = Date.now();
    while (this.inFlight > 0) {
      if (Date.now() - start > timeoutMs) throw new Error(`FakeHome not quiescent: ${this.inFlight} in flight`);
      await new Promise((r) => setTimeout(r, 5));
    }
    // One more macrotask: a landed message may have synchronously scheduled another.
    await new Promise((r) => setTimeout(r, 0));
    if (this.inFlight > 0) await this.quiescent(Math.max(0, timeoutMs - (Date.now() - start)));
  }
}
