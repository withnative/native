// message.react.v1 object bounds through the kit's public surface:
// parse, validate and digest. Corpus matrices live in vectors/corpus.json
// (judged identically by the engine); digest vectors live in
// vectors/digest-vectors.json (recomputed by both).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseDeclaration,
  parseMessageReactBound,
  parseMessageReactBounds,
  MESSAGE_REACT_EFFECT,
  MESSAGE_REACT_EMOJIS,
} from "../src/declaration.mjs";
import { declarationDigest, canonicalDeclaration } from "../src/digest.mjs";

const channelNeed = {
  need: "sql.snapshot.v1",
  key: "messages.channel",
  label: "Channel",
  sql: "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 40",
};
const otherNeed = {
  need: "sql.snapshot.v1",
  key: "other.channel",
  label: "Other",
  sql: "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 4",
};
const bound = (emoji, need = "messages.channel", extra = {}) => ({
  effect: "message.react.v1",
  emoji,
  target: { need },
  ...extra,
});
const declaration = (effects, needs = ["attention.query.v1", channelNeed]) => ({ needs, effects });
const errors = (findings) => findings.filter((item) => item.severity === "error");

test("react emoji list matches the engine canonical picker", () => {
  assert.deepEqual([...MESSAGE_REACT_EMOJIS], ["👍", "❤️", "😂", "🎉", "👀"]);
});

test("parseMessageReactBound admits the exact shape and sorts emoji", () => {
  const parsed = parseMessageReactBound(bound(["🎉", "👍"]));
  assert.deepEqual(parsed.bound, { emoji: ["🎉", "👍"], need: "messages.channel" });
});

test("parseMessageReactBound fails closed on every contract refusal", () => {
  const refused = [
    "a string entry",
    { ...bound(["👍"]), effect: "message.other.v1" },
    { ...bound(["👍"]), note: "x" },
    { effect: "message.react.v1", emoji: ["👍"] },
    bound([]),
    bound(["👍", "👍"]),
    bound(["nope"]),
    bound(["👍", 1]),
    bound(["👍"], "Missing.Key"),
    { ...bound(["👍"]), target: {} },
    { ...bound(["👍"]), target: { need: "messages.channel", other: 1 } },
  ];
  for (const entry of refused) {
    const parsed = parseMessageReactBound(entry);
    assert.ok(parsed.error, JSON.stringify(entry));
    assert.match(parsed.error.message, /\[invalid_effect\]/, JSON.stringify(entry));
  }
});

test("parseDeclaration collects bounds, refuses bare/undeclared/overlap", () => {
  const parsed = parseDeclaration(declaration([bound(["👍"]), "task.triage-set.v1"]));
  assert.deepEqual(errors(parsed.findings), []);
  assert.deepEqual(parsed.effects, ["message.react.v1", "task.triage-set.v1"]);
  assert.deepEqual(parsed.messageReacts, [{ emoji: ["👍"], need: "messages.channel" }]);

  const bare = parseDeclaration(declaration(["message.react.v1"]));
  assert.ok(errors(bare.findings).some((item) => item.message.includes("bare 'message.react.v1'")));

  const undeclared = parseDeclaration(declaration([bound(["👍"], "messages.absent")]));
  assert.ok(errors(undeclared.findings).some((item) => item.message.includes("undeclared need")));

  const duplicate = parseDeclaration(declaration([bound(["👍"]), bound(["👍"])]));
  assert.ok(errors(duplicate.findings).some((item) => item.message.includes("more than one bound")));

  const overlap = parseDeclaration({
    needs: ["attention.query.v1", channelNeed, otherNeed],
    effects: [bound(["👍", "🎉"]), bound(["🎉"], "other.channel")],
  });
  assert.ok(errors(overlap.findings).some((item) => item.message.includes("more than one bound")));

  const split = parseDeclaration({
    needs: ["attention.query.v1", channelNeed, otherNeed],
    effects: [bound(["👍"]), bound(["🎉"], "other.channel")],
  });
  assert.deepEqual(errors(split.findings), []);
  assert.equal(split.messageReacts.length, 2);
});

test("parseMessageReactBounds reports global overlap", () => {
  const ok = parseMessageReactBounds(declaration([bound(["👍"]), "task.triage-set.v1"]));
  assert.equal(ok.error, undefined);
  assert.equal(ok.bounds.length, 1);
  const bad = parseMessageReactBounds(declaration([bound(["👍"]), bound(["👍"])]));
  assert.match(bad.error.message, /more than one bound/);
});

test("react digest pins the canonical shape and widens on emoji", () => {
  const base = declaration([bound(["👍"])]);
  const canonical = canonicalDeclaration(base);
  assert.deepEqual(canonical.effects, [{
    effect: "message.react.v1", emoji: ["👍"], target: { need: "messages.channel" },
  }]);
  const wide = declaration([bound(["👍", "🎉"])]);
  assert.notEqual(declarationDigest(wide), declarationDigest(base));
});

test("the digest fails closed on an invalid react object, as the engine does", () => {
  const need = { need: "sql.snapshot.v1", key: "messages.channel", label: "Channel", sql: "SELECT id FROM records ORDER BY id LIMIT 200" };
  assert.throws(() => declarationDigest({ needs: [need], effects: [bound(["👍", "👍"])] }), /invalid_effect/);
  assert.throws(() => declarationDigest({ needs: [need], effects: [bound(["nope"])] }), /invalid_effect/);
  // The bare family string is refused at install/validation, never in the
  // canonical form: it digests as the string it is, leaving legacy bytes untouched.
  assert.deepEqual(
    canonicalDeclaration({ needs: [], effects: ["message.react.v1"] }).effects,
    ["message.react.v1"],
  );
  assert.ok(MESSAGE_REACT_EFFECT === "message.react.v1");
});
