import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeIcon, parseIconFacet, appIconFor, isBrandName, BRAND_LIBRARY_VERSION } from "../src/icons.mjs";

test("scalar facets select only bounded Lucide names or Simple Icons brand slugs", () => {
  for (const name of ["airtable", "googlecalendar", "not-a-real-brand", "a".repeat(64)]) {
    assert.deepEqual(parseIconFacet(`brand:${name}`), { kind: "brand", name });
    assert.deepEqual(appIconFor("agent.slack-workspace", `brand:${name}`, true), { kind: "brand", name });
  }
  assert.deepEqual(parseIconFacet("BookOpen"), { kind: "lucide", name: "BookOpen" });
  assert.deepEqual(parseIconFacet("FutureIcon"), { kind: "lucide", name: "FutureIcon" });
  for (const value of [null, 42, {}, { kind: "brand", name: "airtable" }, "", "brand:",
    "brand:Airtable", "brand:airtable ", " brand:airtable", "brand:-airtable", "brand:airtable-",
    "brand:air--table", "brand:air_table", "brand:áirtable", `brand:${"a".repeat(65)}`,
    "simple-icons:airtable", "lucide:BookOpen", "brand:simple-icons:airtable",
    "brand:https://example.com/icon.svg", "https://example.com/icon.svg", "<svg/>", "brand:<svg/>",
    "brand:javascript:alert(1)", "brand:airtable\n", "BookOpen\n"]) {
    assert.equal(parseIconFacet(value), null, String(value));
    if (typeof value === "string" || value === null || typeof value === "number") {
      assert.equal(appIconFor("agent.slack-workspace", value, true), null, String(value));
    }
  }
});

test("brand descriptors are accepted and validated by slug shape", () => {
  assert.deepEqual(normalizeIcon({ kind: "brand", name: "slack" }), { kind: "brand", name: "slack" });
  assert.deepEqual(normalizeIcon({ kind: "brand", name: "google-calendar" }), { kind: "brand", name: "google-calendar" });
  assert.equal(normalizeIcon({ kind: "brand", name: "Slack" }), null);
  assert.equal(normalizeIcon({ kind: "brand", name: "slack icon" }), null);
  assert.equal(normalizeIcon({ kind: "svg", name: "slack" }), null);
  assert.equal(isBrandName("simple-icons"), true);
  assert.equal(isBrandName("book-open"), true);
  assert.equal(BRAND_LIBRARY_VERSION, "1.2.98");
});

test("curated brand defaults reach SaaS installed tabs, generic apps stay Lucide", () => {
  assert.deepEqual(appIconFor("agent.slack-workspace"), { kind: "brand", name: "slack" });
  assert.deepEqual(appIconFor("agent.github-review"), { kind: "brand", name: "github" });
  assert.deepEqual(appIconFor("agent.docs"), { kind: "lucide", name: "FileText" });
  assert.equal(appIconFor("unknown.app"), null);
});

test("an explicit choice still outranks a curated default", () => {
  assert.deepEqual(appIconFor("agent.slack-workspace", "BookOpen", true), { kind: "lucide", name: "BookOpen" });
  assert.deepEqual(appIconFor("agent.docs", { kind: "brand", name: "slack" }, true), { kind: "brand", name: "slack" });
  assert.equal(appIconFor("agent.docs", { kind: "brand", name: "Slack" }, true), null);
  // An invalid explicit facet must not fall through to a *brand* default either.
  assert.equal(appIconFor("agent.slack-workspace", { kind: "brand", name: "Slack" }, true), null);
  assert.equal(appIconFor("agent.slack-workspace", "BookOpen", true).kind, "lucide");
});
