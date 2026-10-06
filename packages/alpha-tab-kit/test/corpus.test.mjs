import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { lintSql } from "../src/sql-lint.mjs";
import { parseDeclaration, parseSqlParamEntry } from "../src/declaration.mjs";
import { packageFindings, versionFindings } from "../src/validate.mjs";

// The engine gets the same corpus in src/mcp/tools/alpha_tab_kit_drift.rs.
const corpus = JSON.parse(readFileSync(new URL("vectors/corpus.json", import.meta.url), "utf8"));
const errors = (findings) => findings.filter((item) => item.severity === "error");

for (const item of corpus.sql) {
  test(`sql: ${item.name} → ${item.admitted ? "admitted" : "refused"}`, () => {
    const params = (item.params ?? []).map((param) => parseSqlParamEntry(param).param);
    const found = errors(lintSql(item.sql, params));
    assert.equal(found.length === 0, item.admitted, JSON.stringify(found));
    if (!item.admitted) assert.ok(found.some((finding) => finding.rule === item.rule), `expected ${item.rule}, got ${found.map((finding) => finding.rule)}`);
  });
}

for (const item of corpus.declaration) {
  test(`declaration: ${item.name} → ${item.admitted ? "admitted" : "refused"}`, () => {
    const parsed = parseDeclaration(item.declaration);
    const found = errors([...parsed.findings, ...parsed.sqlNeeds.flatMap((need) => lintSql(need.sql, need.params))]);
    assert.equal(found.length === 0, item.admitted, JSON.stringify(found));
  });
}

test("package and version ids", () => {
  for (const item of corpus.packages) assert.equal(packageFindings(item.value).length === 0, item.admitted, item.value);
  for (const item of corpus.versions) assert.equal(versionFindings(item.value).length === 0, item.admitted, item.value);
});

test("every finding names the source it mirrors", () => {
  for (const item of corpus.sql.filter((entry) => !entry.admitted)) {
    const params = (item.params ?? []).map((param) => parseSqlParamEntry(param).param);
    for (const finding of lintSql(item.sql, params)) assert.match(finding.mirrors, /\.(rs|js)(:\d+)?/);
  }
});
