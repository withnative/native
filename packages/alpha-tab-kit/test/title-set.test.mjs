// records.title-set.v1 object bounds through the kit's public surface:
// parse, validate and digest. Corpus matrices live in vectors/corpus.json
// (judged identically by the engine); digest vectors live in
// vectors/digest-vectors.json (recomputed by both).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseDeclaration,
  parseTitleSetBound,
  parseTitleSetBounds,
  TITLE_SET_EFFECT,
} from "../src/declaration.mjs";
import { declarationDigest, canonicalDeclaration } from "../src/digest.mjs";

const gridNeed = {
  need: "sql.snapshot.v1",
  key: "grid.items",
  label: "Grid",
  sql: "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 40",
};
const otherNeed = {
  need: "sql.snapshot.v1",
  key: "other.items",
  label: "Other",
  sql: "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 4",
};
const bound = (need = "grid.items", extra = {}) => ({
  effect: "records.title-set.v1",
  target: { need },
  ...extra,
});
const declaration = (effects, needs = ["attention.query.v1", gridNeed]) => ({ needs, effects });
const errors = (findings) => findings.filter((item) => item.severity === "error");

test("parseTitleSetBound admits the exact shape", () => {
  const parsed = parseTitleSetBound(bound());
  assert.deepEqual(parsed.bound, { need: "grid.items" });
});

test("parseTitleSetBound fails closed on every contract refusal", () => {
  const refused = [
    "a string entry",
    { ...bound(), effect: "records.other.v1" },
    { ...bound(), note: "x" },
    { effect: "records.title-set.v1" },
    { ...bound(), target: {} },
    { ...bound(), target: { need: "grid.items", other: 1 } },
    { ...bound("Missing.Key") },
    { effect: "records.title-set.v1", target: { need: 7 } },
  ];
  for (const entry of refused) {
    const parsed = parseTitleSetBound(entry);
    assert.ok(parsed.error, JSON.stringify(entry));
    assert.match(parsed.error.message, /\[invalid_effect\]/, JSON.stringify(entry));
  }
});

test("parseDeclaration collects the bound, refuses bare/undeclared/double", () => {
  const parsed = parseDeclaration(declaration([bound(), "task.triage-set.v1"]));
  assert.deepEqual(errors(parsed.findings), []);
  assert.deepEqual(parsed.effects, ["records.title-set.v1", "task.triage-set.v1"]);
  assert.deepEqual(parsed.titleSets, [{ need: "grid.items" }]);

  const bare = parseDeclaration(declaration(["records.title-set.v1"]));
  assert.ok(errors(bare.findings).some((item) => item.message.includes("bare 'records.title-set.v1'")));

  const undeclared = parseDeclaration(declaration([bound("grid.absent")]));
  assert.ok(errors(undeclared.findings).some((item) => item.message.includes("undeclared need")));

  const duplicate = parseDeclaration(declaration([bound(), bound()]));
  assert.ok(errors(duplicate.findings).some((item) => item.message.includes("more than once")));
});

test("parseTitleSetBounds reports the singularity refusal", () => {
  const ok = parseTitleSetBounds(declaration([bound(), "task.triage-set.v1"]));
  assert.equal(ok.error, undefined);
  assert.equal(ok.bounds.length, 1);
  const bad = parseTitleSetBounds(declaration([bound(), bound()]));
  assert.match(bad.error.message, /more than once/);
});

test("title digest pins the canonical shape and widens on need change", () => {
  const base = declaration([bound()]);
  const canonical = canonicalDeclaration(base);
  assert.deepEqual(canonical.effects, [{
    effect: "records.title-set.v1", target: { need: "grid.items" },
  }]);
  const wide = { needs: ["attention.query.v1", gridNeed, otherNeed], effects: [bound("other.items")] };
  assert.notEqual(declarationDigest(wide), declarationDigest(base));
});

test("the digest fails closed on an invalid title object, as the engine does", () => {
  const need = { need: "sql.snapshot.v1", key: "grid.items", label: "Grid rows", sql: "SELECT id FROM records ORDER BY id LIMIT 200" };
  assert.throws(() => declarationDigest({ needs: [need], effects: [{ effect: "records.title-set.v1", target: { need: "grid.items" }, extra: 1 }] }), /invalid_effect/);
  // The bare family string is refused at install/validation, never in the
  // canonical form: it digests as the string it is, leaving legacy bytes untouched.
  assert.deepEqual(
    canonicalDeclaration({ needs: [], effects: ["records.title-set.v1"] }).effects,
    ["records.title-set.v1"],
  );
  assert.ok(TITLE_SET_EFFECT === "records.title-set.v1");
});
