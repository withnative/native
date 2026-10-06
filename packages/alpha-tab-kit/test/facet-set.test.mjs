// records.facet-set.v1 object bounds through the kit's public surface:
// parse, validate and the fake host. Digest properties live in
// digest.test.mjs; admitted/refused matrices live in the corpus
// (vectors/corpus.json, judged identically by the engine).
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseDeclaration, parseFacetSetBound } from "../src/declaration.mjs";
import { validatePackage } from "../src/validate.mjs";
import { startFakeHost } from "../src/fake-host/server.mjs";

const gridNeed = {
  need: "sql.snapshot.v1",
  key: "kit.grid",
  label: "Grid rows",
  sql: "SELECT id FROM records ORDER BY id LIMIT 200",
};
const bound = (overrides = {}) => ({
  effect: "records.facet-set.v1",
  key: "priority",
  values: ["low"],
  target: { need: "kit.grid" },
  ...overrides,
});
const declaration = (effects, needs = [gridNeed]) => ({ needs, effects });
const errors = (findings) => findings.filter((item) => item.severity === "error");

test("parseFacetSetBound admits the exact shape and sorts values by UTF-8 bytes", () => {
  const parsed = parseFacetSetBound(bound({ values: ["high", "low"] }));
  assert.deepEqual(parsed.bound, { key: "priority", values: ["high", "low"], need: "kit.grid" });
});

test("parseFacetSetBound fails closed on every contract refusal", () => {
  const refused = [
    "a string entry",
    bound({ effect: "records.other.v1" }),
    { ...bound(), note: "x" },
    { effect: "records.facet-set.v1", key: "priority", values: ["low"] },
    bound({ key: "  " }),
    bound({ key: "lifecycle" }),
    bound({ key: "triage" }),
    bound({ key: "archived" }),
    bound({ key: "name" }),
    bound({ values: [] }),
    bound({ values: ["low", "low"] }),
    bound({ values: [7] }),
    bound({ target: {} }),
    bound({ target: { need: "kit.grid", extra: 1 } }),
    bound({ target: { need: "Grid" } }),
  ];
  for (const entry of refused) {
    const parsed = parseFacetSetBound(entry);
    assert.ok(parsed.error, JSON.stringify(entry));
    assert.match(parsed.error.message, /\[invalid_effect\]/, JSON.stringify(entry));
  }
});

test("parseDeclaration collects bounds, names the family, and pins the need", () => {
  const parsed = parseDeclaration(declaration([bound(), "task.triage-set.v1"]));
  assert.deepEqual(errors(parsed.findings), []);
  assert.deepEqual(parsed.effects, ["records.facet-set.v1", "task.triage-set.v1"]);
  assert.deepEqual(parsed.facetSets, [{ key: "priority", values: ["low"], need: "kit.grid" }]);

  const bare = parseDeclaration(declaration(["records.facet-set.v1"]));
  assert.ok(errors(bare.findings).some((item) => item.message.includes("bare 'records.facet-set.v1'")));
  const undeclared = parseDeclaration(declaration([bound({ target: { need: "kit.elsewhere" } })]));
  assert.ok(errors(undeclared.findings).some((item) => item.message.includes("undeclared need")));
  const duplicated = parseDeclaration(declaration([bound({ values: ["low"] }), bound({ values: ["high"] })]));
  assert.ok(errors(duplicated.findings).some((item) => item.message.includes("duplicated")));
});

test("validatePackage admits a bound declaration and refuses an undeclared need", () => {
  const descriptor = {
    package: "agent.facet-grid",
    version: "0.1.0",
    runtime: "native.html.v1",
    declaration: declaration([bound()]),
  };
  const admitted = validatePackage({ descriptor });
  assert.equal(admitted.ok, true, JSON.stringify(admitted.findings));

  const refused = validatePackage({
    descriptor: { ...descriptor, declaration: declaration([bound({ target: { need: "kit.elsewhere" } })]) },
  });
  assert.equal(refused.ok, false);
  assert.ok(errors(refused.findings).some((item) => item.message.includes("undeclared need")));
});

test("the fake host serves a declaration carrying an object bound", async () => {
  const host = await startFakeHost({
    descriptor: {
      package: "agent.facet-grid",
      version: "0.1.0",
      declaration: declaration([bound()]),
    },
    html: "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Grid</title></head><body></body></html>",
    fixtures: { sql: { "kit.grid": [{ id: "a1" }] } },
    latencyMs: 0,
  });
  try {
    const live = await (await fetch(`${host.origin}/__host/snapshot`, { method: "POST" })).json();
    assert.deepEqual(live.input.sql["kit.grid"].rows, [{ id: "a1" }]);
  } finally {
    await host.close();
  }
});
