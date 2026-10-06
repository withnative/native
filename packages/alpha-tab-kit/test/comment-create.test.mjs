// comment.create.v1 object bounds through the kit's public surface:
// parse, validate and digest. Corpus matrices live in vectors/corpus.json
// (judged identically by the engine); digest vectors live in
// vectors/digest-vectors.json (recomputed by both).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  parseDeclaration,
  parseCommentCreateBound,
  parseCommentCreateBounds,
  COMMENT_CREATE_EFFECT,
} from "../src/declaration.mjs";
import { validatePackage } from "../src/validate.mjs";
import { declarationDigest, canonicalDeclaration } from "../src/digest.mjs";

const vectors = JSON.parse(readFileSync(new URL("vectors/digest-vectors.json", import.meta.url), "utf8"));

const gridNeed = {
  need: "sql.snapshot.v1",
  key: "thread.items",
  label: "Thread",
  sql: "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 40",
};
const otherNeed = {
  need: "sql.snapshot.v1",
  key: "other.items",
  label: "Other",
  sql: "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 4",
};
const bound = (positions, maxBody = 100, need = "thread.items", extra = {}) => ({
  effect: "comment.create.v1",
  positions,
  max_body_bytes: maxBody,
  target: { need },
  ...extra,
});
const declaration = (effects, needs = ["attention.query.v1", gridNeed]) => ({ needs, effects });
const errors = (findings) => findings.filter((item) => item.severity === "error");

test("parseCommentCreateBound admits the exact shape and sorts positions", () => {
  const parsed = parseCommentCreateBound(bound(["reply", "root"], 4096));
  assert.deepEqual(parsed.bound, { positions: ["reply", "root"], max_body_bytes: 4096, need: "thread.items" });
});

test("whole-number parity: 100, 100.0 and 1e2 agree with one digest", () => {
  assert.equal(parseCommentCreateBound(bound(["root"], 100)).bound.max_body_bytes, 100);
  assert.equal(parseCommentCreateBound(bound(["root"], 100.0)).bound.max_body_bytes, 100);
  const raw = JSON.parse('{"effect": "comment.create.v1", "positions": ["root"], "max_body_bytes": 1e2, "target": {"need": "thread.items"}}');
  assert.equal(parseCommentCreateBound(raw).bound.max_body_bytes, 100);
  const base = declaration([bound(["root"], 100)]);
  const floatForm = declaration([bound(["root"], 100.0)]);
  assert.equal(declarationDigest(floatForm), declarationDigest(base));
});

test("parseCommentCreateBound fails closed on every contract refusal", () => {
  const refused = [
    "a string entry",
    { ...bound(["root"], 100), effect: "comment.other.v1" },
    { ...bound(["root"], 100), note: "x" },
    { effect: "comment.create.v1", positions: ["root"], max_body_bytes: 100 },
    bound([], 100),
    bound(["root", "reply", "root"], 100),
    bound(["root", "root"], 100),
    bound(["pinned"], 100),
    bound([7], 100),
    bound(["root"], 0),
    bound(["root"], 4097),
    bound(["root"], 100.5),
    bound(["root"], -4),
    bound(["root"], true),
    bound(["root"], "lots"),
    bound(["root"], 100, "Missing.Key"),
    { ...bound(["root"], 100), target: {} },
    { ...bound(["root"], 100), target: { need: "thread.items", other: 1 } },
  ];
  for (const entry of refused) {
    const parsed = parseCommentCreateBound(entry);
    assert.ok(parsed.error, JSON.stringify(entry));
    assert.match(parsed.error.message, /\[invalid_effect\]/, JSON.stringify(entry));
  }
});

test("parseDeclaration collects bounds, refuses bare/undeclared/overlap", () => {
  const parsed = parseDeclaration(declaration([bound(["root"], 100), "task.triage-set.v1"]));
  assert.deepEqual(errors(parsed.findings), []);
  assert.deepEqual(parsed.effects, ["comment.create.v1", "task.triage-set.v1"]);
  assert.deepEqual(parsed.commentCreates, [{ positions: ["root"], max_body_bytes: 100, need: "thread.items" }]);

  const bare = parseDeclaration(declaration(["comment.create.v1"]));
  assert.ok(errors(bare.findings).some((item) => item.message.includes("bare 'comment.create.v1'")));

  const undeclared = parseDeclaration(declaration([bound(["root"], 100, "thread.absent")]));
  assert.ok(errors(undeclared.findings).some((item) => item.message.includes("undeclared need")));

  const duplicate = parseDeclaration(declaration([bound(["root"], 100), bound(["root"], 100)]));
  assert.ok(errors(duplicate.findings).some((item) => item.message.includes("more than one bound")));

  const overlap = parseDeclaration({
    needs: ["attention.query.v1", gridNeed, otherNeed],
    effects: [bound(["root", "reply"], 100), bound(["reply"], 200, "other.items")],
  });
  assert.ok(errors(overlap.findings).some((item) => item.message.includes("more than one bound")));

  const split = parseDeclaration({
    needs: ["attention.query.v1", gridNeed, otherNeed],
    effects: [bound(["root"], 100), bound(["reply"], 200, "other.items")],
  });
  assert.deepEqual(errors(split.findings), []);
  assert.equal(split.commentCreates.length, 2);
});

test("parseCommentCreateBounds reports global overlap", () => {
  const ok = parseCommentCreateBounds(declaration([bound(["root"], 100), "task.triage-set.v1"]));
  assert.equal(ok.error, undefined);
  assert.equal(ok.bounds.length, 1);
  const bad = parseCommentCreateBounds(declaration([bound(["root"], 100), bound(["root"], 100)]));
  assert.match(bad.error.message, /more than one bound/);
});

test("validatePackage admits a comment bound and refuses an undeclared need", () => {
  const descriptor = {
    package: "agent.comment-thread",
    version: "0.1.0",
    runtime: "native.html.v1",
    declaration: declaration([bound(["root"], 100)]),
  };
  const admitted = validatePackage({ descriptor });
  assert.equal(admitted.ok, true, JSON.stringify(admitted.findings));

  const refused = validatePackage({
    descriptor: { ...descriptor, declaration: declaration([bound(["root"], 100, "thread.absent")]) },
  });
  assert.equal(refused.ok, false);
  assert.ok(errors(refused.findings).some((item) => item.message.includes("undeclared need")));
});

test("comment digest pins the fixed cross-language vectors", () => {
  const [vector] = vectors.declaration.filter((item) => item.name.startsWith("comment.create bound"));
  assert.equal(declarationDigest(vector.declaration), vector.declaration_digest);
  assert.deepEqual(canonicalDeclaration(vector.declaration).effects, [{
    effect: "comment.create.v1", positions: ["root"], target: { need: "grid.items" }, max_body_bytes: 100,
  }]);
  const [mixed] = vectors.declaration.filter((item) => item.name.startsWith("mixed facet-set"));
  assert.equal(declarationDigest(mixed.declaration), mixed.declaration_digest);
});

test("comment digest is order-insensitive across members, objects and kinds", () => {
  const need = { need: "sql.snapshot.v1", key: "grid.items", label: "Grid rows", sql: "SELECT id FROM records ORDER BY id LIMIT 200" };
  const facet = { effect: "records.facet-set.v1", key: "priority", values: ["high", "low"], target: { need: "grid.items" } };
  const base = { needs: [need], effects: [facet, bound(["root"], 100, "grid.items")] };
  const shuffledMembers = { needs: [need], effects: [{ target: { need: "grid.items" }, max_body_bytes: 100, positions: ["root"], effect: "comment.create.v1" }, facet] };
  assert.equal(declarationDigest(shuffledMembers), declarationDigest(base));
  // Cross-kind: facet-first and comment-first digest identically; strings stay ahead of objects.
  const flipped = { needs: [need], effects: [bound(["root"], 100, "grid.items"), facet] };
  assert.equal(declarationDigest(flipped), declarationDigest(base));
  const withString = { needs: [need], effects: ["task.triage-set.v1", facet, bound(["root"], 100, "grid.items")] };
  assert.deepEqual(canonicalDeclaration(withString).effects[0], "task.triage-set.v1");
});

test("comment widening changes the digest (cap, positions, need)", () => {
  const need = { need: "sql.snapshot.v1", key: "grid.items", label: "Grid rows", sql: "SELECT id FROM records ORDER BY id LIMIT 200" };
  const decl = (effects) => ({ needs: [need], effects });
  const base = declarationDigest(decl([bound(["root"], 100, "grid.items")]));
  assert.notEqual(declarationDigest(decl([bound(["root"], 200, "grid.items")])), base);
  assert.notEqual(declarationDigest(decl([bound(["reply"], 100, "grid.items")])), base);
  assert.notEqual(declarationDigest(decl([bound(["root"], 100, "grid.items"), bound(["reply"], 50, "grid.items")])), base);
});

test("the digest fails closed on an invalid comment object, as the engine does", () => {
  const need = { need: "sql.snapshot.v1", key: "grid.items", label: "Grid rows", sql: "SELECT id FROM records ORDER BY id LIMIT 200" };
  assert.throws(() => declarationDigest({ needs: [need], effects: [bound(["root", "root"], 100, "grid.items")] }), /invalid_effect/);
  assert.throws(() => declarationDigest({ needs: [need], effects: [bound(["root"], 0, "grid.items")] }), /invalid_effect/);
  // The bare family string is refused at install/validation, never in the
  // canonical form: it digests as the string it is, leaving legacy bytes untouched.
  assert.deepEqual(
    canonicalDeclaration({ needs: [], effects: ["comment.create.v1"] }).effects,
    ["comment.create.v1"],
  );
  assert.ok(COMMENT_CREATE_EFFECT === "comment.create.v1");
});
