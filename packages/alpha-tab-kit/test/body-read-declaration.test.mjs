import { test } from "node:test";
import assert from "node:assert/strict";
import { BODY_READ_NEED, BODY_READ_SCOPE, classifyDeclarationNeed, parseDeclaration, splitNeeds } from "../src/declaration.mjs";
import { canonicalDeclaration, declarationDigest } from "../src/digest.mjs";
import { LIMITS } from "../src/limits.mjs";
import { startFakeHost } from "../src/fake-host/server.mjs";
import { planInstall } from "../src/install.mjs";

const body = { need: BODY_READ_NEED, scope: BODY_READ_SCOPE };
const sql = (key) => ({ need: "sql.snapshot.v1", key, label: "Rows", sql: "SELECT id FROM records ORDER BY id LIMIT 1" });
const declaration = (...needs) => ({ needs, effects: [] });
const errors = (parsed) => parsed.findings.filter((f) => f.severity === "error");

test("closed descriptor has digest representation but no offered/executable need", async () => {
  const candidate = declaration(body);
  assert.equal(classifyDeclarationNeed(body).kind, "body-read");
  assert.deepEqual(canonicalDeclaration(candidate), { needs: [], effects: [], body_read_needs: [body] });
  const parsed = parseDeclaration(candidate);
  assert.deepEqual(parsed.bodyReadNeeds, [body]);
  assert.deepEqual(parsed.sqlNeeds, []);
  assert.deepEqual(errors(parsed).map((f) => f.rule), ["body-read.admission-unavailable"]);
  assert.deepEqual(splitNeeds(parsed), { snapshot: [], onRequestSql: [], onRequestHost: [] });
  const descriptor = { package: "agent.reader", version: "1.0.0", runtime: "native.html.v1", declaration: candidate };
  await assert.rejects(startFakeHost({ descriptor, html: "<!doctype html><html><head></head><body></body></html>" }), /body_admission_unavailable/);
  assert.throws(() => planInstall({ descriptor, html: "<!doctype html><html><head></head><body></body></html>", homeId: "home", reason: "Test" }), (error) => error.findings.some((f) => f.rule === "body-read.admission-unavailable"));
});

test("bare spelling remains inert and absent descriptor preserves historic form", () => {
  const bare = declaration(BODY_READ_NEED, "unknown.future", "unknown.future");
  assert.equal(errors(parseDeclaration(bare)).length, 0);
  assert.deepEqual(canonicalDeclaration(bare), { needs: [BODY_READ_NEED, "unknown.future", "unknown.future"], effects: [] });
  assert.deepEqual(splitNeeds(parseDeclaration(bare)), { snapshot: [], onRequestSql: [], onRequestHost: [] });
  assert.notEqual(declarationDigest(declaration(body)), declarationDigest(declaration(BODY_READ_NEED)));
  assert.ok(!LIMITS.declaration.host_need_names.includes(BODY_READ_NEED));
  assert.ok(!LIMITS.reads.on_request_host_needs.includes(BODY_READ_NEED));
});

test("legacy SQL key retains its exact shape, digest and SQL role", () => {
  const need = sql(BODY_READ_NEED);
  assert.equal(errors(parseDeclaration(declaration(need))).length, 0);
  assert.deepEqual(canonicalDeclaration(declaration(need)), { needs: [], effects: [], sql_needs: [need] });
  assert.deepEqual(splitNeeds(parseDeclaration(declaration(need))).snapshot.map((n) => n.key), [BODY_READ_NEED]);
  // Historic standalone digest accepts SQL duplicates even though install
  // validation refuses them; new descriptor checks do not rewrite that rule.
  assert.doesNotThrow(() => declarationDigest(declaration(need, need)));
});

test("malformed and unknown descriptors fail closed rather than digest as absent", () => {
  for (const item of [
    { need: BODY_READ_NEED }, { need: BODY_READ_NEED, scope: null },
    { need: BODY_READ_NEED, scope: " viewer-visible-current-bodies" },
    { need: BODY_READ_NEED, scope: "VIEWER-VISIBLE-CURRENT-BODIES" },
    { ...body, label: "Read" }, { ...body, params: [] },
    { need: "records.body.read.v2", scope: BODY_READ_SCOPE },
    { need: "Records.body.read.v1", scope: BODY_READ_SCOPE },
    [], null, 42,
  ]) {
    assert.ok(errors(parseDeclaration(declaration(item))).length);
    assert.throws(() => declarationDigest(declaration(item)));
  }
});

test("duplicates and cross-kind collisions fail independently of entry order", () => {
  for (const other of [body, BODY_READ_NEED, sql(BODY_READ_NEED)]) {
    for (const candidate of [declaration(body, other), declaration(other, body)]) {
      assert.ok(errors(parseDeclaration(candidate)).some((f) => f.rule === "body-read.shape"));
      assert.throws(() => declarationDigest(candidate), /invalid_body_read_need/);
    }
  }
});

test("descriptor counts toward 64 needs but not the eight SQL needs", () => {
  const eight = Array.from({ length: 8 }, (_, i) => sql(`rows.${i}`));
  const parsed = parseDeclaration(declaration(...eight, body));
  assert.equal(parsed.sqlNeeds.length, 8);
  assert.deepEqual(errors(parsed).map((f) => f.rule), ["body-read.admission-unavailable"]);
  assert.ok(errors(parseDeclaration(declaration(...eight, sql("rows.ninth"), body))).some((f) => f.rule === "declaration.sql-need-count"));
  const sixtyFour = declaration(body, ...Array.from({ length: 63 }, (_, i) => `unknown.${i}`));
  assert.doesNotThrow(() => declarationDigest(sixtyFour));
  assert.throws(() => declarationDigest({ ...sixtyFour, needs: [...sixtyFour.needs, "unknown.extra"] }), /64 entries/);
});

test("descriptor cannot become effect target; unrelated SQL targets survive ordering", () => {
  const effects = [
    { effect: "records.title-set.v1", target: { need: "rows.target" } },
    { effect: "message.react.v1", target: { need: "rows.target" }, emoji: ["👍"] },
  ];
  for (const needs of [[body, sql("rows.target")], [sql("rows.target"), body]]) {
    assert.deepEqual(errors(parseDeclaration({ needs, effects })).map((f) => f.rule), ["body-read.admission-unavailable"]);
  }
  const targetingBody = effects.map((effect) => ({ ...effect, target: { need: BODY_READ_NEED } }));
  assert.ok(errors(parseDeclaration({ needs: [body], effects: targetingBody })).some((f) => f.rule === "declaration.effects"));
  assert.equal(errors(parseDeclaration({ needs: [sql(BODY_READ_NEED)], effects: targetingBody })).length, 0);
});

test("parsed objects carry no raw-JSON duplicate-key guarantee", () => {
  // JSON.parse has already discarded repeated members. Shape validation is
  // over that parsed value, not evidence that source JSON lacked duplicates.
  const parsed = JSON.parse('{"need":"ignored","need":"records.body.read.v1","scope":"viewer-visible-current-bodies"}');
  assert.equal(classifyDeclarationNeed(parsed).kind, "body-read");
});
