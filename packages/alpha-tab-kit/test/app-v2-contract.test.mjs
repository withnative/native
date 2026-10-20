import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { planInstall } from "../src/install.mjs";
import { parseDeclaration, APP_CONTRACT_V2, isAppV2Declaration } from "../src/declaration.mjs";
import { canonicalDeclaration, declarationDigest } from "../src/digest.mjs";
import { validatePackage } from "../src/validate.mjs";

const v2 = { contract: "native.app.v2", needs: [], effects: [] };
const probe = JSON.parse(readFileSync(new URL("fixtures/probe-descriptor.json", import.meta.url), "utf8"));
const html = readFileSync(new URL("fixtures/probe-queued.html", import.meta.url), "utf8");
const descriptor = (declaration) => ({ ...probe, declaration });
const plan = (declaration, options = {}) => planInstall({
  descriptor: descriptor(declaration), html, homeId: "c59dffa3-a401-431a-a44b-c79cae9b8346", reason: "Install a v2 app", ...options,
});
const errors = (parsed) => parsed.findings.filter((item) => item.severity === "error");

test("the validator accepts exactly the v2 declaration", () => {
  assert.equal(APP_CONTRACT_V2, "native.app.v2");
  assert.equal(isAppV2Declaration(v2), true);
  assert.equal(isAppV2Declaration({ needs: [], effects: [] }), false);
  assert.deepEqual(errors(parseDeclaration(v2)), []);
});

test("an unknown, mistyped or non-empty v2 declaration is refused", () => {
  for (const bad of [
    { ...v2, contract: "native.app.v3" },
    { ...v2, contract: "" },
    { ...v2, contract: 2 },
    { ...v2, contract: null },
    { ...v2, needs: ["attention.query.v1"] },
    { ...v2, effects: ["task.triage-set.v1"] },
    { ...v2, sessions: [] },
    { ...v2, sessions: [{ session: "session.body.v1", key: "k", scope: { type: "A", kind: "note" }, mode: "edit", presence: true }] },
    { contract: "native.app.v2", needs: [] },
  ]) {
    const found = errors(parseDeclaration(bad));
    assert.ok(found.length > 0, JSON.stringify(bad));
    assert.ok(found.every((item) => item.rule.startsWith("declaration.")), JSON.stringify(found));
  }
});

test("v1 declarations are untouched by the contract key", () => {
  const v1 = { needs: [], effects: [] };
  assert.deepEqual(canonicalDeclaration(v1), { needs: [], effects: [] });
  assert.deepEqual(errors(parseDeclaration(v1)), []);
  assert.notEqual(declarationDigest(v1), declarationDigest(v2));
});

test("the canonical v2 declaration binds the contract; others refuse to digest", () => {
  assert.deepEqual(canonicalDeclaration(v2), { needs: [], effects: [], contract: "native.app.v2" });
  assert.throws(() => canonicalDeclaration({ ...v2, contract: "native.app.v3" }), /invalid_contract/);
  for (const bad of [{ ...v2, needs: ["attention.query.v1"] }, { ...v2, effects: ["task.triage-set.v1"] }, { ...v2, sessions: [] }]) {
    assert.throws(() => canonicalDeclaration(bad), /invalid_contract/, JSON.stringify(bad));
  }
  assert.throws(() => canonicalDeclaration(Object.defineProperty({ needs: [], effects: [] }, "contract", { enumerable: true, get: () => "native.app.v2" })), /invalid_contract/);
});

test("a v2 package validates", () => {
  const result = validatePackage({ descriptor: descriptor(v2), html });
  assert.deepEqual(result.findings.filter((item) => item.severity === "error"), []);
  assert.equal(result.digests.declaration_digest, declarationDigest(v2));
});

test("planInstall for a v2 package emits no bind or grant steps", () => {
  const result = plan(v2);
  assert.deepEqual(result.steps.map((step) => step.step), ["create-artifact", "install", "inspect"]);
  assert.ok(!result.steps.some((step) => /bind|grant/.test(`${step.step} ${step.operation}`)));
  assert.equal(result.unbound_inputs, undefined);
  const install = result.steps.find((step) => step.step === "install");
  assert.deepEqual(install.arguments.declaration, v2);
  assert.equal(install.expect.declaration_digest, declarationDigest(v2));
});

test("a binding is refused for a v2 package rather than dropped", () => {
  assert.throws(() => plan(v2, { bindings: [{ port: "default", collection_id: "c" }] }), /native\.app\.v2/);
});

test("planInstall for a v2 package refuses an unknown contract", () => {
  assert.throws(() => plan({ ...v2, contract: "native.app.v3" }), /does not validate/);
});
