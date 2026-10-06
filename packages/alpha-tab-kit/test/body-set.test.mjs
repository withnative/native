// Source-only dormant S2 contract: these are not Save/runtime proofs.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  BODY_SET_EFFECT, BODY_SET_MAX_BODY_BYTES, parseBodySetBound,
  parseBodySetBounds, parseDeclaration, LIMITS, LIMIT_SOURCES,
} from "../src/index.mjs";
import { canonicalDeclaration, declarationDigest } from "../src/digest.mjs";

const need = (key = "docs.body") => ({
  need: "sql.snapshot.v1", key, label: "Complete small source",
  sql: "SELECT id, body FROM records WHERE id = ?1 ORDER BY id LIMIT 1",
  params: [{ name: "record_id", type: "text", max_len: 128, required: true }],
});
const bound = (max_body_bytes = 32768, target = "docs.body") => ({
  effect: "records.body-set.v1", max_body_bytes, target: { need: target },
});
const declaration = (effects, needs = [need()]) => ({ needs, effects });

test("public dormant shape preserves exact cap and parameterized SQL need", () => {
  assert.equal(BODY_SET_EFFECT, "records.body-set.v1");
  assert.equal(BODY_SET_MAX_BODY_BYTES, 524288);
  for (const cap of [1, 100, 32768, BODY_SET_MAX_BODY_BYTES]) {
    const input = declaration([bound(cap)]);
    const original = JSON.stringify(input);
    const parsed = parseDeclaration(input);
    assert.deepEqual(parsed.findings, []);
    assert.deepEqual(parsed.bodySets, [{ need: "docs.body", max_body_bytes: cap }]);
    assert.deepEqual(parseBodySetBounds(input).bounds, parsed.bodySets);
    assert.deepEqual(parseBodySetBound(input.effects[0]).bound, parsed.bodySets[0]);
    assert.equal(JSON.stringify(input), original);
  }
  // Membership restrictions are later S3, not a stronger install parser.
  const staticNeed = { ...need(), sql: "SELECT id FROM records ORDER BY id LIMIT 1" };
  delete staticNeed.params;
  assert.deepEqual(parseDeclaration(declaration([bound()], [staticNeed])).findings, []);
});

test("exact bound rejects wrong shape, extra fields and every invalid cap", () => {
  const invalid = [null, [], BODY_SET_EFFECT, {},
    { ...bound(), effect: "records.title-set.v1" },
    { ...bound(), extra: 1 }, { effect: BODY_SET_EFFECT, target: { need: "docs.body" } },
    { ...bound(), target: null }, { ...bound(), target: [] },
    { ...bound(), target: { need: "docs.body", id: "caller" } },
    ...["", "Docs.Body", " docs.body", "docs.body ", 7, null].map((value) => bound(100, value)),
    ...[0, -1, BODY_SET_MAX_BODY_BYTES + 1, 1.5, NaN, Infinity, -Infinity, "100", true, null, undefined].map((cap) => ({ ...bound(), max_body_bytes: cap })),
  ];
  for (const input of invalid) {
    assert.ok(parseBodySetBound(input).error, JSON.stringify(input));
    const parsed = parseDeclaration(declaration([input]));
    assert.ok(parsed.findings.some((item) => item.severity === "error"), JSON.stringify(input));
    assert.throws(() => canonicalDeclaration(declaration([input])), undefined, JSON.stringify(input));
  }
  for (const encoded of ["100", "100.0", "1e2"]) {
    const input = JSON.parse(`{"effect":"records.body-set.v1","max_body_bytes":${encoded},"target":{"need":"docs.body"}}`);
    assert.equal(parseBodySetBound(input).bound.max_body_bytes, 100);
  }
});

test("list parser and direct canonical API refuse duplicates and unqualified needs", () => {
  const invalid = [
    declaration([BODY_SET_EFFECT]),
    declaration([bound(), bound()]),
    declaration([bound(1), bound(2, "docs.other")], [need(), need("docs.other")]),
    declaration([bound()], []),
    declaration([bound()], ["docs.body"]),
    declaration([bound()], [{ ...need(), need: "host.snapshot.v1" }]),
    declaration([bound()], [{ ...need(), params: [{ name: "id", type: "bytes" }] }]),
    declaration([bound()], [need(), need()]),
    declaration([bound()], [need(), "docs.body"]),
    { ...declaration([bound()]), extra: 1 },
  ];
  for (const input of invalid) {
    assert.ok(parseBodySetBounds(input).error, JSON.stringify(input));
    const parsed = parseDeclaration(input);
    assert.ok(parsed.findings.some((item) => item.severity === "error"));
    assert.deepEqual(parsed.bodySets, []);
    assert.throws(() => canonicalDeclaration(input));
    assert.throws(() => declarationDigest(input));
  }
  for (const input of [null, {}, { needs: [], effects: {} }]) {
    assert.ok(parseBodySetBounds(input).error);
  }
});

test("body bound cannot use the existing Title or ordinary Facet envelopes", () => {
  for (const input of [
    { ...bound(), effect: "records.title-set.v1" },
    { ...bound(), effect: "records.facet-set.v1", key: "body", values: ["draft"] },
    { ...bound(), key: "body", values: ["draft"] },
  ]) {
    assert.ok(parseDeclaration(declaration([input])).findings.some((item) => item.severity === "error"));
    assert.throws(() => canonicalDeclaration(declaration([input])), /invalid_effect/);
  }
});

test("limits honestly distinguish raw agreement from encoded or engine qualification", () => {
  assert.equal(LIMITS.proposed_body_set.max_body_bytes, BODY_SET_MAX_BODY_BYTES);
  assert.equal(LIMITS.proposed_body_set.status, "provisional-raw-utf8-bound");
  assert.match(LIMITS.proposed_body_set.engine_mirror, /BODY_SET_MAX_BODY_BYTES/);
  assert.match(LIMITS.proposed_body_set.encoded_budget_status, /rollout and host compatibility require qualification/);
  assert.match(LIMITS.proposed_body_set.activation_requirements, /mandatory Restorable Undo/);
  assert.equal("rust" in LIMIT_SOURCES.proposed_body_set, false);
  assert.equal("value" in LIMIT_SOURCES.proposed_body_set, false);
  // A full raw-cap body can overflow the 65536-unit proposal limit even
  // before ids/slots/keys. No transport preflight implementation is implied.
  const controls = "\u0001".repeat(BODY_SET_MAX_BODY_BYTES);
  assert.equal(Buffer.byteLength(controls, "utf8"), BODY_SET_MAX_BODY_BYTES);
  assert.equal(JSON.stringify(controls).length, 6 * BODY_SET_MAX_BODY_BYTES + 2);
  assert.ok(JSON.stringify({ values: { body: controls } }).length > 65536);
});
