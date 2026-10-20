import { test } from "node:test";
import { DEFAULT_KIT_DELIVERY } from '../src/fake-host/kit-assets.mjs';
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { sourceKitPolicy, validateHtml, requireAvailableKit } from "../src/html.mjs";
import { validatePackage } from "../src/validate.mjs";
import { computeDigests } from "../src/digest.mjs";
import { injectBridge, startFakeHost } from "../src/fake-host/server.mjs";

const cases = JSON.parse(readFileSync(new URL("vectors/kit-policy.json", import.meta.url), "utf8"));
const source = cases.find(item => item.name === "major 1").source;
const legacy = cases.find(item => item.name === "legacy source").source;
const descriptor = { package: "agent.kit-probe", version: "1.0.0", runtime: "native.html.v1", declaration: { needs: [], effects: [] } };

test("shared source policy corpus: Rust/JS integer grammar, inert marker, duplicates and legacy", () => {
  for (const item of cases) {
    const parsed = sourceKitPolicy(item.source);
    assert.equal(parsed.findings.length === 0, item.valid, item.name);
    assert.equal(validateHtml(item.source).every(finding => finding.severity !== "error"), item.valid, item.name);
    if (item.valid) assert.equal(parsed.policy?.major ?? 0, item.major, item.name);
  }
});

test("source policy is authoritative: descriptor copy is optional, closed and must match", () => {
  assert.equal(validatePackage({ descriptor, html: source }).ok, true);
  assert.equal(validatePackage({ descriptor: { ...descriptor, kit: { major: 1 } }, html: source }).ok, true);
  for (const kit of [null, [], {}, { major: "1" }, { major: 0 }, { major: 65536 }, { major: 1, release: "1.0.0" }]) {
    const result = validatePackage({ descriptor: { ...descriptor, kit }, html: source });
    assert.equal(result.ok, false, JSON.stringify(kit));
    assert.ok(result.findings.some(finding => finding.rule === "descriptor.kit-policy"));
  }
  for (const html of [source, legacy]) {
    assert.ok(validatePackage({ descriptor: { ...descriptor, kit: { major: 2 } }, html }).findings.some(finding => finding.rule === "descriptor.kit-policy-mismatch"));
  }
});

test("author policy changes digest v1; resolved host release is not an input", () => {
  const first = computeDigests(source, descriptor.declaration, descriptor.runtime);
  const secondSource = source.replace('"major":1', '"major":2');
  const second = computeDigests(secondSource, descriptor.declaration, descriptor.runtime);
  assert.equal(first.digest_version, "alpha-tab-digest.v1");
  assert.notEqual(first.bundle_sha256, second.bundle_sha256);
  assert.notEqual(first.digest, second.digest);
  assert.equal(first.declaration_digest, second.declaration_digest);
  // The digest inputs stay the exact author source, permission declaration and runtime id.
  for (const hostRelease of ["1.0.0", "1.1.0"]) {
    const host = { resolvedKitRelease: hostRelease, descriptor, html: source };
    assert.deepEqual(validatePackage(host).digests, first);
  }
  assert.deepEqual(validatePackage({ descriptor: { ...descriptor, kit: { major: 1 } }, html: source }).digests, first);
});

test("kit marker counts toward the ordinary author limit", () => {
  const oversized = source.replace("</main>", `${" ".repeat(524288)}</main>`);
  assert.equal(validateHtml(oversized)[0].rule, "body-size");
  assert.equal(validateHtml(oversized, { package: true }).every(finding => finding.severity !== "error"), true);
});

test("fake hosting delivers admitted major and refuses unavailable major; legacy injection unchanged", async () => {
  assert.throws(() => requireAvailableKit(source), /major 1.*kit_major_unavailable/);
  assert.match(injectBridge(source, "http://localhost:1234"), new RegExp(DEFAULT_KIT_DELIVERY.resolve(1).release.js_sha256));
  const host = await startFakeHost({ descriptor, html: source });
  await host.close();
  await assert.rejects(startFakeHost({ descriptor: { ...descriptor, kit: { major: 1 } }, html: legacy }), /descriptor.kit-policy-mismatch/);
  for (const item of cases.filter(item => !item.valid)) {
    assert.throws(() => injectBridge(item.source, "http://localhost:1234"), /html_invalid_kit_policy/, item.name);
  }
  requireAvailableKit(legacy);
  const bootstrap = readFileSync(new URL("../src/fake-host/bridge-bootstrap.js", import.meta.url), "utf8").replace("__NATIVE_WORKBENCH_ORIGIN__", JSON.stringify("http://localhost:1234")).replace("__NATIVE_KIT_FACTORY__", "null").replace("__NATIVE_KIT_RELEASE__", "null");
  assert.equal(injectBridge(legacy, "http://localhost:1234"), legacy.replace("<head>", `<head><script>${bootstrap}</script>`));
});
