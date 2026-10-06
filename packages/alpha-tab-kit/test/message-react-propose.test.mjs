// Frame-side react proposal helper: pure build, strict refusals,
// honest outcome copy, zero tool calls.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildMessageReactProposal, messageReactOutcomeText, MESSAGE_REACT_EFFECT } from "../src/message-react.mjs";

test("buildMessageReactProposal carries message + emoji + reacted only", () => {
  const proposal = buildMessageReactProposal({ requestId: "req-1", entryId: "react_toggle", messageId: "m-1", emoji: "👍", reacted: true });
  assert.deepEqual(proposal, { request_id: "req-1", entry_id: "react_toggle",
    slots: { message: "m-1" }, values: { emoji: "👍", reacted: true } });
  const custom = buildMessageReactProposal({ requestId: "req-2", entryId: "react_toggle", messageSlot: "target", messageId: "m-2", emoji: "❤️", reacted: false });
  assert.deepEqual(custom.slots, { target: "m-2" });
  assert.equal(MESSAGE_REACT_EFFECT, "message.react.v1");
});

test("buildMessageReactProposal fails closed outside the bound", () => {
  assert.throws(() => buildMessageReactProposal({ requestId: "r", entryId: "e", messageId: "m", emoji: "nope", reacted: true }), /emoji/);
  assert.throws(() => buildMessageReactProposal({ requestId: "r", entryId: "e", messageId: "", emoji: "👍", reacted: true }), /messageId/);
  assert.throws(() => buildMessageReactProposal({ requestId: "r", entryId: "e", messageId: "m", emoji: "👍", reacted: "yes" }), /reacted/);
  assert.throws(() => buildMessageReactProposal({ requestId: "", entryId: "e", messageId: "m", emoji: "👍", reacted: true }), /requestId/);
});

test("messageReactOutcomeText stays sequence-free and honest", () => {
  const committed = (after) => ({ status: "committed", changes: [{ record_id: "m-1", key: "reaction", before: null, after }] });
  assert.equal(messageReactOutcomeText(committed({ message_id: "m-1", emoji: "👍", reacted: true, changed: true })), "Reacted.");
  assert.equal(messageReactOutcomeText(committed({ message_id: "m-1", emoji: "👍", reacted: true, changed: false })), "Already reacted.");
  assert.equal(messageReactOutcomeText(committed({ message_id: "m-1", emoji: "👍", reacted: false, changed: false })), "Already removed.");
  assert.match(messageReactOutcomeText({ status: "uncertain", code: "uncertain" }), /may have reacted/);
  assert.match(messageReactOutcomeText({ status: "rejected", code: "nope" }), /Nothing changed/);
  assert.match(messageReactOutcomeText({ status: "busy", code: "busy" }), /wait for its answer/);
  assert.match(messageReactOutcomeText({ status: "conflict", code: "react_conflict" }), /unknown/i);
  for (const text of [messageReactOutcomeText(committed({ message_id: "m-1", emoji: "👍", reacted: true, changed: true })),
    messageReactOutcomeText({ status: "uncertain", code: "uncertain" })]) {
    assert.doesNotMatch(text, /obs:\d|rec:\d/);
  }
});

test("the helper makes zero tool calls from the frame", () => {
  const source = readFileSync(new URL("../src/message-react.mjs", import.meta.url), "utf8");
  for (const token of ["callTool", "manage_alpha_tabs", "query_sql", "invoke_artifact_interaction", "fetch(", "XMLHttpRequest", "localStorage"]) {
    assert.equal(source.includes(token), false, `frame helper holds no ${token}`);
  }
});
