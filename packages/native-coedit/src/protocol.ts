// session.body.v1 message shapes (app → host → home, same shape relayed).
//
// PROPOSED CONTRACT ADDITION (client-assigned `update_id`):
// `session.update` carries `update_id` (string, unique per client session),
// and `session.ack` echoes it so the sender can retire exactly one pending
// update. `session.refused.refused` likewise names `update_id`s (not Yjs
// client ids or clocks), so the client knows which pending updates the
// server rejected without any positional coupling. FakeHome implements this
// extended contract; a home that does not echo `update_id` cannot drive the
// pending queue and must be treated as incompatible.

/** SHA-256 hex of a body, as carried in base / versioned. */
export interface BodyBase {
  version: number;
  body_sha256: string;
}

export interface OpenLimits {
  max_update_bytes: number;
}

export type ClientMsg =
  | { op: "session.open"; key: string; record_id: string; mode: "edit" | "view" }
  | { op: "session.update"; session: string; update: Uint8Array; update_id: string }
  | { op: "session.version"; session: string; reason: string }
  | { op: "session.close"; session: string };

export type RefusalCode =
  | "forbidden"
  | "too_large"
  | "foreign_client_id"
  | "bad_doc_shape"
  | "rate_limited"
  | "access_lost";

export type ServerMsg =
  | {
      op: "session.opened";
      session: string;
      peer: string;
      doc_client_ids: number[];
      sync: Uint8Array;
      base: BodyBase;
      limits: OpenLimits;
      presence: { sharing: boolean };
    }
  | { op: "session.ack"; session: string; update_id: string; clock: number }
  | {
      op: "session.refused";
      session: string;
      code: RefusalCode | string;
      refused: string[];
      sync: Uint8Array;
    }
  | {
      op: "session.remote";
      session: string;
      update: Uint8Array;
      from: { person_ref: string | null; kind: string };
    }
  | { op: "session.versioned"; session: string; version: number; body_sha256: string }
  | { op: "session.closed"; session: string; reason: string };
