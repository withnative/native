import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { LIMITS } from "../src/limits.mjs";
import { completenessAnalysis, completenessFindings, inlineScripts, LINT_BUDGET, readsField, tokenize } from "../src/completeness-lint.mjs";
import { validatePackage } from "../src/validate.mjs";
import { planInstall } from "../src/install.mjs";
import { computeDigests } from "../src/digest.mjs";
import { shapeSqlResult } from "../src/fake-host/rules.mjs";

const doc = (script) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>T</title></head><body><main><h1>T</h1><ul id="list"></ul></main><script>${script}</script></body></html>`;
const SQL_NEED = { need: "sql.snapshot.v1", key: "lane.all", label: "All", sql: "SELECT id, name FROM records ORDER BY id LIMIT 200" };
const descriptorFor = (html, needs = [SQL_NEED]) => {
  const declaration = { needs, effects: [] };
  return { package: "agent.lint", version: "0.1.0", runtime: "native.html.v1", declaration, ...computeDigests(html, declaration, "native.html.v1") };
};
const lint = (script, needs = [SQL_NEED]) => completenessFindings(doc(script), needs);
const rules = (script, needs) => lint(script, needs).map((item) => item.rule);
const TRUNCATED = "reads.surface-truncated";
const COUNT = "reads.surface-row-count-complete";

test("advisory: a package reading rows but never truncated is warned, never refused", () => {
  const html = doc("var s = input.sql['lane.all']; s.rows.forEach(function (r) { list.append(r.name); });");
  const result = validatePackage({ descriptor: descriptorFor(html), html });
  const found = result.findings.filter((item) => item.rule.startsWith("reads.surface"));
  assert.deepEqual(found.map((item) => `${item.severity}:${item.rule}`), [`warning:${TRUNCATED}`]);
  assert.equal(result.ok, true, "a lexical warning must not fail validate");
  const plan = planInstall({ descriptor: descriptorFor(html), html, homeId: "c59dffa3-a401-431a-a44b-c79cae9b8346", reason: "Install the lint probe" });
  assert.ok(plan.steps.length > 0, "planInstall still plans the install");
});

test("every completeness finding is a warning", () => {
  for (const script of ["x.rows;", "x.row_count;", "x.rows; x.row_count;", "table.rows;"]) {
    for (const item of lint(script)) assert.equal(item.severity, "warning", script);
  }
});

test("reading truncated clears the rows warning; row_count needs row_count_complete", () => {
  assert.deepEqual(rules("var s = input.sql['lane.all']; if (s.truncated) note(); s.rows.map(String);"), []);
  assert.deepEqual(rules("var s = input.sql['lane.all']; note(s.rows.length + ' of ' + s.row_count, s.truncated);"), [COUNT]);
  assert.deepEqual(rules("var s = x; note(s.rows, s.truncated, s.row_count, s.row_count_complete);"), []);
});

test("regression: a regex literal does not swallow the code after it", () => {
  assert.deepEqual(rules("draw(result.rows); const url = /https?:\\/\\//; if (result.truncated) warn();"), []);
  assert.deepEqual(rules("draw(result.rows); const re = /[/'\"`]/g; if (result.truncated) warn();"), []);
  assert.deepEqual(rules("const half = total / 2; draw(result.rows); if (result.truncated / 1) warn();"), []);
  // `/` after `return` opens a regex, not division.
  assert.deepEqual(rules("function f() { return /x/.test(s); } draw(result.rows); if (result.truncated) warn();"), []);
});

test("regression: text in strings, templates, comments and regexes is not a read", () => {
  assert.deepEqual(rules('draw(result.rows); console.log("result.truncated is the completeness field");'), [TRUNCATED]);
  assert.deepEqual(rules("draw(result.rows); label('truncated');"), [TRUNCATED]);
  assert.deepEqual(rules("draw(result.rows); const t = `see result.truncated`;"), [TRUNCATED]);
  assert.deepEqual(rules("draw(result.rows); // result.truncated\n/* result.truncated */"), [TRUNCATED]);
  assert.deepEqual(rules("draw(result.rows); const re = /result.truncated/;"), [TRUNCATED]);
  assert.deepEqual(rules("draw(result.rows); const keys = ['truncated'];"), [TRUNCATED]);
});

test("a string literal counts only as a computed key", () => {
  assert.deepEqual(rules('draw(result["rows"]); if (result["truncated"]) warn();'), []);
  assert.deepEqual(rules("draw(result?.['rows']); if (result?.['truncated']) warn();"), []);
  assert.deepEqual(rules('draw(read(k)["rows"]); if (read(k)["truncated"]) warn();'), []);
});

test("code inside template ${} is scanned, including nested templates", () => {
  assert.deepEqual(rules("draw(result.rows); const t = `x ${result.truncated ? `cut ${ {a: 1}.a }` : ''} y`;"), []);
  assert.deepEqual(rules("const t = `${ result.rows.length } rows`; if (result.truncated) warn();"), []);
});

test("regression: destructuring counts, including assignment destructuring", () => {
  assert.deepEqual(rules("let truncated; draw(result.rows); ({ truncated } = result);"), []);
  assert.deepEqual(rules("const { rows, truncated } = input.sql['lane.all']; draw(rows, truncated);"), []);
  assert.deepEqual(rules("const { result: { rows, truncated } } = answer;"), []);
  assert.deepEqual(rules("const { rows: list, truncated: cut = false } = s;"), []);
  assert.deepEqual(rules("for (const { rows, truncated } of lanes) draw(rows, truncated);"), []);
  assert.deepEqual(rules("const view = ({ rows, truncated }) => [rows, truncated];"), []);
  assert.deepEqual(rules("function view({ rows }) { return rows; } view(input.sql['lane.all']);"), [TRUNCATED]);
  assert.deepEqual(rules("function view(a, { rows, truncated }) { return rows; }"), []);
  assert.deepEqual(rules("const [{ rows, truncated }] = pages;"), []);
});

test("regression: writes and object literals are not reads", () => {
  assert.deepEqual(rules("state.rows = []; state.truncated = false;"), []);
  assert.deepEqual(rules("draw(result.rows); state.truncated = false;"), [TRUNCATED]);
  assert.deepEqual(rules("draw(result.rows); state.truncated ||= false;"), [TRUNCATED]);
  assert.deepEqual(rules("draw(result.rows); report({ truncated: false });"), [TRUNCATED]);
  assert.deepEqual(rules("const { rows } = x; report({ truncated: false });"), [TRUNCATED]);
  assert.deepEqual(rules("draw(result.rows); if (result.truncated === true) warn();"), [], "a comparison is a read");
});

test("regression: an ambiguous receiver says so in the warning", () => {
  const [dom] = lint("var t = document.querySelector('table'); t.rows.length;");
  assert.equal(dom.rule, TRUNCATED);
  assert.match(dom.message, /may belong to another object/);
  const [result] = lint("draw(answer.result.rows);");
  assert.doesNotMatch(result.message, /may belong to another object/);
  const [section] = lint("draw(input.sql['lane.all'].rows);");
  assert.doesNotMatch(section.message, /may belong to another object/);
});

test("the lint applies only to packages that declare SQL needs", () => {
  const html = doc("var t = document.querySelector('table'); t.rows.length;");
  const result = validatePackage({ descriptor: descriptorFor(html, ["attention.query.v1"]), html });
  assert.deepEqual(result.findings.filter((item) => item.rule.startsWith("reads.surface")), []);
  assert.deepEqual(rules("t.rows.length;", []), []);
});

test("non-JavaScript script blocks are not scanned", () => {
  const html = doc("var s = x; if (s.truncated) warn();").replace("<main>", '<script type="application/json">{"rows": [], "x": 1}</script><main>');
  assert.deepEqual(completenessFindings(html, [SQL_NEED]), []);
});

test("tokenizer: strings, templates and regexes are single tokens; field matching is whole-word", () => {
  assert.deepEqual(tokenize("a /* b */ 'c // d' `e ${f} g`; /h/i").map((token) => token.type),
    ["word", "string", "template", "punct", "word", "punct", "template", "punct", "regex"]);
  // After a value (a template, a closing paren, a word), `/` is division.
  assert.deepEqual(tokenize("`t` / 2; (a) / b").map((token) => token.type),
    ["template", "punct", "number", "punct", "punct", "word", "punct", "punct", "word"]);
  assert.equal(readsField("x.row_count_complete", "row_count"), false);
  assert.equal(readsField("x.rowsets", "rows"), false);
});

test("every finding names the engine source it mirrors", () => {
  for (const item of lint("x.rows; x.row_count;")) assert.match(item.mirrors, /alpha_tabs\.rs/);
});

test("the fake host shapes results with exactly the engine's fields", () => {
  const small = shapeSqlResult("L", Array.from({ length: 205 }, (_, i) => ({ id: i })), LIMITS);
  assert.deepEqual(Object.keys(small), LIMITS.reads.sql_result_fields);
  assert.equal(small.rows.length, 200);
  assert.equal(small.row_count, 205);
  assert.equal(small.truncated, true);
  assert.equal(small.row_count_complete, true, "the 200-row delivery cap leaves row_count a true total");
  const large = shapeSqlResult("L", Array.from({ length: 1050 }, (_, i) => ({ id: i })), LIMITS);
  assert.equal(large.row_count, LIMITS.sql.max_rows);
  assert.equal(large.row_count_complete, false, "query_sql's own cap makes row_count a floor");
  assert.equal(large.truncated, true);
});

test("the keyset paging proof package passes the kit validator with no findings", () => {
  const dir = new URL("../../../experiments/alpha-tab-proof-packages/", import.meta.url);
  const descriptor = JSON.parse(readFileSync(new URL("keyset-pager-descriptor.json", dir), "utf8"));
  const html = readFileSync(new URL(descriptor.bundle, dir), "utf8");
  const result = validatePackage({ descriptor, html });
  assert.deepEqual(result.findings, []);
});

// ---- Bounded work (review of e268c0c: the lint was quadratic) ----
//
// These assert the work the analysis counts, not wall-clock time: the
// counter is deterministic, and a linear analysis must do about twice the
// work on twice the input.

const HOME = "c59dffa3-a401-431a-a44b-c79cae9b8346";
const bracketHeavy = (n) => `var data = [${"{rows:[]},".repeat(n)}]; var s = input.sql['lane.all']; note(s.rows, s.truncated, s.row_count, s.row_count_complete, data);`;
const both = (html, extra = {}) => {
  const descriptor = descriptorFor(html);
  const result = validatePackage({ descriptor, html, ...extra });
  const plan = planInstall({ descriptor, html, homeId: HOME, reason: "Install the lint probe", ...extra });
  return { result, plan };
};

test("regression: bracket-heavy valid code validates and plans with linear lint work", () => {
  const small = completenessAnalysis(doc(bracketHeavy(1_000)), [SQL_NEED]);
  const large = completenessAnalysis(doc(bracketHeavy(20_000)), [SQL_NEED]);
  for (const report of [small, large]) {
    assert.equal(report.exhausted, null);
    assert.deepEqual(report.findings, []);
    assert.ok(report.work <= 8 * report.tokens, `work ${report.work} for ${report.tokens} tokens`);
  }
  const ratio = large.work / small.work;
  assert.ok(ratio < 21 && ratio > 19, `20x the input costs ${ratio.toFixed(2)}x the work`);
  const html = doc(bracketHeavy(20_000));
  assert.ok(Buffer.byteLength(html) < LIMITS.html.body_max_bytes);
  const { result, plan } = both(html);
  assert.equal(result.ok, true);
  assert.deepEqual(result.findings.filter((item) => item.rule.startsWith("reads.")), []);
  assert.ok(plan.steps.length > 0);
});

test("regression: nested destructuring and object literals are analysed once each", () => {
  // Every `{rows}` key sits in a pattern nested 2,000 deep; the outward walk
  // is memoised, so the work stays linear rather than depth x keys.
  const depth = 2_000;
  const pattern = `var ${"{a:".repeat(depth)}{rows, truncated}${"}".repeat(depth)} = input;`;
  const literals = `var list = [${"{rows: 1, truncated: 2},".repeat(5_000)}];`;
  for (const script of [pattern, literals, pattern + literals]) {
    const report = completenessAnalysis(doc(script), [SQL_NEED]);
    assert.equal(report.exhausted, null);
    assert.ok(report.work <= 8 * report.tokens, `work ${report.work} for ${report.tokens} tokens`);
  }
  assert.deepEqual(rules(pattern), [], "the deep pattern still counts as reading rows and truncated");
  assert.deepEqual(rules(literals + "x.rows;"), [TRUNCATED], "object literal keys still do not count");
});

test("regression: deep valid nesting does not overflow the stack at either entrypoint", () => {
  const depth = 50_000;
  const html = doc(`var deep = ${"[".repeat(depth)}${"]".repeat(depth)}; var s = input.sql['lane.all']; note(s.rows, s.truncated);`);
  const { result, plan } = both(html);
  assert.equal(result.ok, true);
  assert.deepEqual(result.findings.filter((item) => item.rule.startsWith("reads.")), []);
  assert.ok(plan.steps.length > 0);
});

test("regression: an exhausted budget is one advisory warning at both entrypoints, never a refusal", () => {
  const html = doc(bracketHeavy(200));
  const tokens = completenessAnalysis(html, [SQL_NEED]).tokens;
  for (const [budget, bound] of [
    [{ scriptBytes: 64 }, "script size"],
    [{ tokens: tokens - 1 }, "token"],
    [{ steps: tokens }, "step"],
  ]) {
    const report = completenessAnalysis(html, [SQL_NEED], budget);
    assert.equal(report.exhausted, bound);
    assert.deepEqual(report.findings.map((item) => `${item.severity}:${item.rule}`), ["warning:reads.completeness-lint-budget"]);
    const { result, plan } = both(html, { completenessBudget: budget });
    assert.equal(result.ok, true, `${bound}: exhaustion must not fail validate`);
    assert.deepEqual(result.findings.filter((item) => item.rule.startsWith("reads.")).map((item) => item.severity), ["warning"]);
    assert.ok(plan.steps.length > 0, `${bound}: planInstall still plans`);
  }
});

test("the default budget admits every package the hosted body limit admits", () => {
  assert.equal(LINT_BUDGET.scriptBytes, LIMITS.html.body_max_bytes);
  // Densest valid tokens: one per byte, with a read at the end.
  const script = `var z = [${"[],".repeat(Math.floor((LIMITS.html.body_max_bytes - 1_000) / 3))}]; var s = input.sql['lane.all']; note(s.rows);`;
  const report = completenessAnalysis(doc(script), [SQL_NEED]);
  assert.equal(report.exhausted, null);
  assert.deepEqual(report.findings.map((item) => item.rule), [TRUNCATED]);
});

test("inline scripts: linear over unclosed tags, closed as a browser closes them", () => {
  assert.deepEqual(inlineScripts("<p>İİ</p><SCRIPT type=module>a.rows</SCRIPT ><script>x</scripts></script><script type=\"application/json\">j</script><script>tail"),
    ["a.rows", "x</scripts>"]);
  assert.deepEqual(inlineScripts("<script>".repeat(60_000)), []);
  assert.deepEqual(inlineScripts("<script".repeat(60_000)), []);
});
