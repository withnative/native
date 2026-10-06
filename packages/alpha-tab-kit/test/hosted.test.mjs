import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { compareHosted } from "../src/hosted.mjs";
import { LIMITS } from "../src/limits.mjs";

const production = JSON.parse(readFileSync(new URL("fixtures/hosted-render-2026-09-28.json", import.meta.url), "utf8"));

test("the 28 Sep production descriptor predates ffd9c76cd: keep strict", () => {
  const report = compareHosted(production);
  assert.equal(report.hosted.validator_version, 1);
  assert.equal(report.accessibility_rules, "refused");
  assert.equal(report.matches_main, false);
  assert.equal(report.bridge_matches, false);
  assert.deepEqual(report.limit_diffs, [
    { limit: "input_json_bytes", hosted: 4194304, kit: LIMITS.html.input_json_max_bytes },
    { limit: "input_records", hosted: 5000, kit: LIMITS.html.input_records_max },
    { limit: "bridge_message_bytes", hosted: 4194304, kit: LIMITS.html.bridge_message_max_bytes },
  ]);
  assert.match(report.advice, /keep the strict default/);
});

test("a descriptor built from main matches and says the default can flip", () => {
  const main = { runtime: { ...production.runtime, limits: { ...production.runtime.limits, input_json_bytes: LIMITS.html.input_json_max_bytes, input_records: LIMITS.html.input_records_max, bridge_message_bytes: LIMITS.html.bridge_message_max_bytes }, adapter_revision: LIMITS.bridge.adapter_revision, validator: { ...production.runtime.validator, version: LIMITS.bridge.validator_version }, delivery_transform: { ...production.runtime.delivery_transform, digest: LIMITS.bridge.bootstrap_sha256 } } };
  const report = compareHosted(main);
  assert.equal(report.matches_main, true);
  assert.equal(report.accessibility_rules, "advisory");
  assert.match(report.advice, /can flip/);
});

test("anything but a native.html.v1 descriptor is refused", () => {
  assert.throws(() => compareHosted({ runtime: { id: "native.mdx.v2" } }), /native.html.v1/);
});
