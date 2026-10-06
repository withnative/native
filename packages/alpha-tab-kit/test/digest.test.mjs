import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { bundleSha256, declarationDigest, installDigest, computeDigests, canonicalDeclaration } from "../src/digest.mjs";
import { canonicalJson } from "../src/jcs.mjs";
import { parseBodySetBounds, parseDeclaration } from "../src/declaration.mjs";

// Shared with src/mcp/tools/alpha_tab_kit_drift.rs, which recomputes every
// expected value with the engine's own functions.
const vectors = JSON.parse(readFileSync(new URL("vectors/digest-vectors.json", import.meta.url), "utf8"));

test("the host's alpha-tab-digest.v1 test vector (alpha_tabs.rs alpha_tab_digest_vectors)", () => {
  const [bundle] = vectors.bundle;
  const [declaration] = vectors.declaration;
  const [digest] = vectors.digest;
  assert.equal(bundleSha256(bundle.body), bundle.bundle_sha256);
  assert.equal(declarationDigest(declaration.declaration), declaration.declaration_digest);
  assert.equal(installDigest(digest.bundle_sha256, digest.declaration_digest, digest.runtime), digest.digest);
  assert.deepEqual(computeDigests(bundle.body, declaration.declaration), {
    digest_version: "alpha-tab-digest.v1",
    bundle_sha256: bundle.bundle_sha256,
    declaration_digest: declaration.declaration_digest,
    digest: digest.digest,
  });
});

test("every shared vector, including a server-confirmed declaration with SQL params", () => {
  for (const item of vectors.bundle) assert.equal(bundleSha256(item.body), item.bundle_sha256, item.name);
  for (const item of vectors.declaration) assert.equal(declarationDigest(item.declaration), item.declaration_digest, item.name);
  for (const item of vectors.digest) assert.equal(installDigest(item.bundle_sha256, item.declaration_digest, item.runtime), item.digest, item.name);
});

test("canonical form: sorted names, sql_needs only when present, param order kept", () => {
  const canonical = canonicalDeclaration({
    needs: ["b.v1", { need: "sql.snapshot.v1", key: "z.k", label: "L", sql: "SELECT id FROM records WHERE id = ?1 OR name = ?2", params: [{ name: "b", type: "text" }, { name: "a", type: "integer" }] }, "a.v1"],
    effects: [],
  });
  assert.deepEqual(canonical.needs, ["a.v1", "b.v1"]);
  assert.deepEqual(canonical.sql_needs[0].params, [
    { name: "b", type: "text", max_len: 256, required: true },
    { name: "a", type: "integer", required: true },
  ]);
  assert.equal("sql_needs" in canonicalDeclaration({ needs: ["a"], effects: [] }), false);
});

test("the digest fails closed on a malformed SQL entry, as the engine does", () => {
  assert.throws(() => declarationDigest({ needs: [{ need: "sql.snapshot.v1", key: "Bad", label: "L", sql: "SELECT 1" }], effects: [] }), /invalid_sql_need/);
});

const facetDecl = (effects) => ({
  needs: [{ need: "sql.snapshot.v1", key: "grid.items", label: "Grid rows", sql: "SELECT id FROM records ORDER BY id LIMIT 200" }],
  effects,
});
const bound = (overrides = {}) => ({
  effect: "records.facet-set.v1", key: "priority", values: ["high", "low"], target: { need: "grid.items" }, ...overrides,
});

test("facet-set bound pins the fixed cross-language vector", () => {
  const [vector] = vectors.declaration.filter((item) => item.name.startsWith("facet-set bound"));
  assert.equal(declarationDigest(vector.declaration), vector.declaration_digest);
  assert.deepEqual(canonicalDeclaration(vector.declaration).effects, [{
    effect: "records.facet-set.v1", key: "priority", target: { need: "grid.items" }, values: ["high", "low"],
  }]);
});

test("facet-set digest is order-insensitive (member order, value order, object order)", () => {
  const base = facetDecl([bound()]);
  const shuffledMembers = facetDecl([{ target: { need: "grid.items" }, values: ["low", "high"], key: "priority", effect: "records.facet-set.v1" }]);
  assert.equal(declarationDigest(shuffledMembers), declarationDigest(base));
  const two = (first, second) => facetDecl([bound(first), bound({ key: "status", values: ["open"], ...second })]);
  assert.equal(
    declarationDigest(two({}, {})),
    declarationDigest(facetDecl([bound({ key: "status", values: ["open"] }), bound()])),
  );
});

test("facet-set widening changes the digest (value, key, need)", () => {
  const base = declarationDigest(facetDecl([bound()]));
  assert.notEqual(declarationDigest(facetDecl([bound({ values: ["high", "low", "medium"] })])), base);
  assert.notEqual(declarationDigest(facetDecl([bound({ key: "status" })])), base);
  assert.notEqual(declarationDigest(facetDecl([bound({ target: { need: "other.items" } })])), base);
  // Strings keep the historical order ahead of objects, so a string-only
  // declaration digests exactly as before this slice.
  assert.deepEqual(canonicalDeclaration({ needs: ["b.v1", "a.v1"], effects: ["task.triage-set.v1"] }).effects, ["task.triage-set.v1"]);
});

test("facet-set values sort by UTF-8 bytes, as Rust Vec<String>::sort does", () => {
  // U+E000 (EE 80 80) sorts before U+10000 (F0 90 80 80) by bytes, but after
  // it by UTF-16 code units (D800 < E000): the default Array#sort is wrong.
  const canonical = canonicalDeclaration(facetDecl([bound({ values: ["𐀀", ""] })]));
  assert.deepEqual(canonical.effects[0].values, ["", "𐀀"]);
});

test("the digest fails closed on an invalid facet-set object, as the engine does", () => {
  assert.throws(() => declarationDigest(facetDecl([bound({ key: "triage" })])), /invalid_effect/);
  assert.throws(() => declarationDigest(facetDecl([bound({ values: ["a", "a"] })])), /invalid_effect/);
  // The bare family string is refused at install/validation, never in the
  // canonical form: it digests as the string it is, leaving legacy bytes
  // untouched.
  assert.deepEqual(
    canonicalDeclaration({ needs: [], effects: ["records.facet-set.v1"] }).effects,
    ["records.facet-set.v1"],
  );
});

test("JCS: key order by UTF-16 code unit, no whitespace, strings as JSON", () => {
  assert.equal(canonicalJson({ b: 1, a: [true, null, "é\n"], "": {} }), '{"":{},"a":[true,null,"é\\n"],"b":1}');
});

test("dormant BodySet pins exact canonical bytes, cap and target", () => {
  const body = (cap = 32768, need = "grid.items") => ({
    effect: "records.body-set.v1", max_body_bytes: cap, target: { need },
  });
  const base = facetDecl([body()]);
  assert.equal(canonicalJson(canonicalDeclaration(base)),
    '{"effects":[{"effect":"records.body-set.v1","max_body_bytes":32768,"target":{"need":"grid.items"}}],"needs":[],"sql_needs":[{"key":"grid.items","label":"Grid rows","need":"sql.snapshot.v1","sql":"SELECT id FROM records ORDER BY id LIMIT 200"}]}');
  const reordered = facetDecl([{ target: { need: "grid.items" }, max_body_bytes: 32768, effect: "records.body-set.v1" }]);
  assert.equal(declarationDigest(reordered), declarationDigest(base));
  assert.notEqual(declarationDigest(facetDecl([body(32767)])), declarationDigest(base));
  // Both needs exist in BOTH inputs: only the target changes, not the read list.
  const twoNeeds = [...base.needs, { ...base.needs[0], key: "other.items" }];
  assert.notEqual(
    declarationDigest({ needs: twoNeeds, effects: [body(32768, "other.items")] }),
    declarationDigest({ needs: twoNeeds, effects: [body()] }),
  );
});

test("BodySet shares the existing global object hash order after sorted strings", () => {
  const body = { effect: "records.body-set.v1", max_body_bytes: 100, target: { need: "grid.items" } };
  const mixed = facetDecl([body, "z.act", bound(), "a.act"]);
  const reversed = { needs: [...mixed.needs].reverse(), effects: [...mixed.effects].reverse() };
  const canonical = canonicalDeclaration(mixed);
  assert.equal(canonicalJson(canonical), canonicalJson(canonicalDeclaration(reversed)));
  assert.deepEqual(canonical.effects.slice(0, 2), ["a.act", "z.act"]);
  assert.equal(canonical.effects.length, 4);
  assert.deepEqual(canonical.effects.filter((entry) => entry.effect === "records.body-set.v1"), [body]);
  // The ordering rule is SHA256(JCS(object)), not raw JSON or family order.
  const objectHashes = canonical.effects.slice(2).map((entry) => bundleSha256(canonicalJson(entry)));
  assert.deepEqual(objectHashes, [...objectHashes].sort());
});

test("direct canonical and digest calls refuse invalid BodySet lists, not only objects", () => {
  const body = { effect: "records.body-set.v1", max_body_bytes: 100, target: { need: "grid.items" } };
  const malformed = [
    facetDecl([body, { ...body }]), facetDecl(["records.body-set.v1"]),
    { needs: [], effects: [body] }, { needs: ["grid.items"], effects: [body] },
    facetDecl([{ ...body, max_body_bytes: 0 }]), facetDecl([{ ...body, max_body_bytes: 524289 }]),
    facetDecl([{ ...body, max_body_bytes: "100" }]), facetDecl([{ ...body, target: { need: "grid.absent" } }]),
  ];
  for (const input of malformed) {
    assert.throws(() => canonicalDeclaration(input), /invalid_effect/);
    assert.throws(() => declarationDigest(input), /invalid_effect/);
  }
});

test("explicit non-array BodySet cannot canonicalize or digest as an absent effect", () => {
  const body = { effect: "records.body-set.v1", max_body_bytes: 100, target: { need: "grid.items" } };
  const invalid = [
    body, "records.body-set.v1",
    { ...body, max_body_bytes: 0 }, { ...body, max_body_bytes: 524289 },
    { ...body, max_body_bytes: "100" }, { ...body, max_body_bytes: { value: 100 } },
    { ...body, target: { need: "grid.absent" } },
    { ...body, target: { need: ["grid.items"] } }, { ...body, target: null },
    { ...body, target: { need: "grid.items", extra: true } },
  ];
  for (const effects of invalid) {
    const input = { ...facetDecl([]), effects };
    assert.ok(parseBodySetBounds(input).error);
    assert.ok(parseDeclaration(input).findings.some((item) => item.severity === "error"));
    assert.throws(() => canonicalDeclaration(input), /body-set declaration.*arrays.*invalid_effect/);
    assert.throws(() => declarationDigest(input), /body-set declaration.*arrays.*invalid_effect/);
  }
  // Proper array control still retains the entire body bound.
  const valid = facetDecl([body]);
  assert.deepEqual(parseBodySetBounds(valid).bounds, [{ need: "grid.items", max_body_bytes: 100 }]);
  assert.deepEqual(parseDeclaration(valid).findings, []);
  assert.deepEqual(canonicalDeclaration(valid).effects, [body]);
  assert.match(declarationDigest(valid), /^[a-f0-9]{64}$/);
  // Nested array entries are malformed, too; existing object parsing refuses.
  for (const effects of [[body], ["records.body-set.v1"]]) {
    const input = facetDecl([effects]);
    assert.throws(() => canonicalDeclaration(input), /invalid_effect/);
    assert.throws(() => declarationDigest(input), /invalid_effect/);
  }
});

test("historical malformed no-Body effects keep their absent canonical behavior", () => {
  const absent = facetDecl([]);
  for (const effects of [undefined, null, {}, "task.triage-set.v1", { effect: "records.title-set.v1" }]) {
    const input = { ...absent, effects };
    assert.equal(canonicalJson(canonicalDeclaration(input)), canonicalJson(canonicalDeclaration(absent)));
    assert.equal(declarationDigest(input), declarationDigest(absent));
  }
});

test("old literal canonical bytes and independently pinned digests stay unchanged", () => {
  const legacy = { needs: ["attention.query.v1"], effects: ["task.triage-set.v1"] };
  assert.equal(canonicalJson(canonicalDeclaration(legacy)),
    '{"effects":["task.triage-set.v1"],"needs":["attention.query.v1"]}');
  assert.equal(declarationDigest(legacy), "9c6045ec2a73034d6e1a55463fec891dc38db088202f556a0e89bee7ae7bcb15");
  assert.equal(canonicalJson(canonicalDeclaration(facetDecl([bound()]))),
    '{"effects":[{"effect":"records.facet-set.v1","key":"priority","target":{"need":"grid.items"},"values":["high","low"]}],"needs":[],"sql_needs":[{"key":"grid.items","label":"Grid rows","need":"sql.snapshot.v1","sql":"SELECT id FROM records ORDER BY id LIMIT 200"}]}');
  assert.equal(declarationDigest(facetDecl([bound()])), "7eddf1c091d661988ade18b9feb7930c21d6fb23341df5914e2fb923ea10940b");
  const mixed = facetDecl([bound(), {
    effect: "comment.create.v1", positions: ["root"], max_body_bytes: 100, target: { need: "grid.items" },
  }]);
  assert.equal(declarationDigest(mixed), "5735f407f65cfd97242297d29f4ea60e4c6c317450b9be479abe62de874594ee");
  assert.equal(declarationDigest({ ...mixed, effects: [...mixed.effects].reverse() }),
    "5735f407f65cfd97242297d29f4ea60e4c6c317450b9be479abe62de874594ee");
});
