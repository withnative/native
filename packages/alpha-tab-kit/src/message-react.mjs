// Frame-side message.react.v1 proposal helper (07ae879 I3).
//
// Pure, DOM-free, zero tool calls: the tab builds
// `{ request_id, entry_id, slots, values }` and passes it to the host's
// propose bridge. The host owns the install pin, the launch proof,
// need-row membership, the invocation, the idempotency key scope, and
// the receipt. This module performs no I/O: no tool invocation, no
// bridge management calls, no SQL reads, no network reads, no storage.
//
// Mirrors the comment-thread tab shape (`comment-thread.html`): the
// target message travels in the entry's single bound_input slot; the
// desired `{ emoji, reacted }` pair travels in values.
import { MESSAGE_REACT_EMOJIS } from "./declaration.mjs";

export { MESSAGE_REACT_EMOJIS };
export const MESSAGE_REACT_EFFECT = "message.react.v1";
export const MESSAGE_REACT_MANIFEST_EFFECT = "message.react";

const isSlotName = (v) => typeof v === "string" && /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(v);
const isId = (v) => typeof v === "string" && v.trim().length > 0 && v.trim() === v && v.length <= 128;

/**
 * @typedef {object} MessageReactProposal
 * @property {string} request_id Fresh per-click id (the host answers on it).
 * @property {string} entry_id The manifest `message.react` entry id.
 * @property {Record<string,string>} slots Exactly one bound slot: message id.
 * @property {{ emoji: string, reacted: boolean }} values Desired emoji + state.
 */

/**
 * Build a frame-side reaction proposal. Throws on anything outside the
 * bounded shape — unknown fields, a non-canonical emoji, a non-boolean
 * `reacted`, or a blank id — so the tab fails closed before proposing.
 */
export function buildMessageReactProposal({ requestId, entryId, messageSlot = "message", messageId, emoji, reacted }) {
  if (!isId(requestId)) throw new TypeError("buildMessageReactProposal: requestId must be a nonblank id");
  if (!isId(entryId)) throw new TypeError("buildMessageReactProposal: entryId must be a nonblank id");
  if (!isSlotName(messageSlot)) throw new TypeError("buildMessageReactProposal: messageSlot must name the bound slot");
  if (typeof messageId !== "string" || messageId.length === 0 || messageId.length > 512 || messageId.trim() !== messageId) {
    throw new TypeError("buildMessageReactProposal: messageId must be a nonblank id");
  }
  if (typeof emoji !== "string" || !MESSAGE_REACT_EMOJIS.includes(emoji)) {
    throw new TypeError("buildMessageReactProposal: emoji must be one of the canonical v1 picker values");
  }
  if (typeof reacted !== "boolean") throw new TypeError("buildMessageReactProposal: reacted must be a boolean");
  return {
    request_id: requestId,
    entry_id: entryId,
    slots: { [messageSlot]: messageId },
    values: { emoji, reacted },
  };
}

/**
 * Render a host reaction result into honest tab copy. Sequence-free:
 * reports only the settled state, never an observation or record
 * sequence number. Returns null when the result carries no usable
 * reaction change.
 */
export function messageReactOutcomeText(result) {
  const change = result?.changes?.[0];
  if (result?.status === "committed" && change && typeof change === "object" && change.key === "reaction") {
    const after = change.after;
    if (after && typeof after === "object" && typeof after.emoji === "string" && typeof after.reacted === "boolean") {
      if (after.reacted === true) return after.changed === false ? "Already reacted." : "Reacted.";
      return after.changed === false ? "Already removed." : "Removed.";
    }
    return "Recorded.";
  }
  if (!result || typeof result !== "object") return "Outcome unknown — no answer. Refresh to recheck before retrying.";
  if (result.status === "busy" || result.code === "busy") return "Another proposal is being verified — wait for its answer, then try again.";
  if (result.status === "uncertain" || result.code === "uncertain") return "Outcome unknown — it may have reacted. Refresh to recheck before retrying.";
  if (result.status === "rejected") return `Not applied (${String(result.code || "rejected")}). Nothing changed.`;
  return `Outcome unknown (${String(result.code || result.status || "unavailable")}) — refresh to recheck before retrying.`;
}
