// Result completeness: every `sql.snapshot.v1` result says how much of the
// answer it carries (`execute_sql_need`, src/mcp/tools/alpha_tabs.rs; fields
// in `limits.json` `reads.sql_result_fields`).
//
// - `truncated` is true when the delivered `rows` are not all the rows: the
//   200-row delivery cap or `query_sql`'s own 1,000-row cap stopped them.
// - `row_count_complete` is false when `query_sql` itself stopped, so
//   `row_count` is a floor ("more than 1,000"), not a total.
//
// A tab that shows rows without surfacing `truncated` presents a prefix as
// the whole; one that shows `row_count` without `row_count_complete` can
// print a false "of N". This lint advises on both.
//
// Advisory only: every finding is a warning, so neither `validate` nor
// `planInstall` refuses a package because of it. It is lexical, and a
// lexical check must not be able to refuse a correct package. It tokenizes
// inline script (skipping comments, string, template and regex literals,
// but scanning `${…}` code), then looks for real reads of a field:
//
// - property reads, `x.rows`, `x?.rows`, `x["rows"]`, but not writes
//   (`x.rows = []`, `x.rows += …`);
// - destructuring, in declarations (`const { rows } = x`), assignments
//   (`({ rows } = x)`), parameters (`function f({ rows })`,
//   `({ rows }) => …`) and nested patterns (`{ result: { rows } }`).
//
// Telling a regex from division is best-effort: `/` after `)` is read as
// division, so a regex straight after a control-flow head (`if (x) /re/`)
// is scanned as code and text inside it could count as a read. Outside that
// case, text in strings, comments and regexes does not count. The lint
// cannot tell which object a property belongs to (`table.rows` is a DOM
// read), so it checks that the package reads the field somewhere, not that
// every view shows it, and it says when no read's receiver looks like a SQL
// result. It applies only to packages that declare SQL needs.
//
// Its work is linear and bounded (`LINT_BUDGET`): one pass indexes the
// brackets, pattern answers are memoised, receiver chains are read at most
// CHAIN_MAX_WORDS back, and nothing recurses. Past a bound it reports one
// advisory warning instead of an answer.
import { warning } from "./findings.mjs";
import { LIMITS } from "./limits.mjs";

const AT = "src/mcp/tools/alpha_tabs.rs execute_sql_need, SQL_NEED_RESULT_FIELDS";
const JS_TYPES = new Set(["", "module", "text/javascript", "application/javascript"]);

// After these keywords an expression starts, so `/` opens a regex.
const REGEX_AFTER_WORDS = new Set([
  "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else",
  "yield", "await",
]);
// After these a value has ended, so `/` is division.
const VALUE_END_PUNCT = new Set([")", "]", "}"]);
const PUNCTUATORS = [
  ">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
  "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=", "%=",
  "&=", "|=", "^=", "**", "<<", ">>",
];
// Multi-character punctuators by first character, longest first.
const PUNCTUATORS_BY_FIRST = new Map();
for (const p of PUNCTUATORS) {
  if (!PUNCTUATORS_BY_FIRST.has(p[0])) PUNCTUATORS_BY_FIRST.set(p[0], []);
  PUNCTUATORS_BY_FIRST.get(p[0]).push(p);
}
for (const list of PUNCTUATORS_BY_FIRST.values()) list.sort((a, b) => b.length - a.length);
const isSpace = (c) => c === " " || (c >= "\t" && c <= "\r") || (c > "~" && /\s/.test(c));
const isDigit = (c) => c >= "0" && c <= "9";
const isWordStart = (c) => (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || c === "_" || c === "$";
const isWordPart = (c) => isWordStart(c) || isDigit(c);
const ASSIGNMENT = new Set(["=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^=", "&&=", "||=", "??="]);
const RESULT_WORDS = new Set(["result", "sql", "section", "lane", "page", "answer", "need"]);

/**
 * Inline script bodies that run as JavaScript. A linear scan, as a browser
 * reads them: a script ends at the first `</script` followed by space, `/`
 * or `>`, and once none follows there is nothing more to read.
 */
export function inlineScripts(html) {
  const source = String(html ?? "");
  const opener = /<script(?=[\s>/])/gi;
  const closer = /<\/script(?=[\s>/]|$)/gi;
  const out = [];
  for (;;) {
    const open = opener.exec(source);
    if (!open) break;
    const tagEnd = source.indexOf(">", opener.lastIndex);
    if (tagEnd < 0) break;
    closer.lastIndex = tagEnd + 1;
    const close = closer.exec(source);
    if (!close) break;
    const attributes = source.slice(opener.lastIndex, tagEnd);
    const type = /\btype\s*=\s*["']?([^"'\s>]*)/i.exec(attributes)?.[1]?.toLowerCase() ?? "";
    if (JS_TYPES.has(type)) out.push(source.slice(tagEnd + 1, close.index));
    const closeEnd = source.indexOf(">", closer.lastIndex);
    if (closeEnd < 0) break;
    opener.lastIndex = closeEnd + 1;
  }
  return out;
}

/**
 * Tokenize JavaScript well enough to tell code from text. Tokens are
 * `{type, value}` with type `word`, `number`, `punct`, `string` (value is
 * the decoded-enough body), `template` (literal text only; `${}` code is
 * tokenized in line) or `regex`. Comments are dropped.
 */
export function tokenize(code) {
  const tokens = [];
  // Brace depths at which a template literal resumes after `${…}`.
  const templateResume = [];
  let depth = 0;
  let i = 0;
  const last = () => tokens[tokens.length - 1];
  const regexAllowed = () => {
    const prev = last();
    if (!prev) return true;
    if (prev.type === "word") return REGEX_AFTER_WORDS.has(prev.value);
    if (prev.type === "punct") return !VALUE_END_PUNCT.has(prev.value) && prev.value !== "++" && prev.value !== "--";
    return false;
  };
  // Read template text from `i` (just after "`" or "}") to "`" or "${".
  const templateText = () => {
    let text = "";
    while (i < code.length) {
      const c = code[i];
      if (c === "\\") { text += code.slice(i, i + 2); i += 2; continue; }
      if (c === "`") { i += 1; tokens.push({ type: "template", value: text }); return; }
      if (c === "$" && code[i + 1] === "{") {
        i += 2;
        tokens.push({ type: "template", value: text });
        templateResume.push(depth);
        depth += 1;
        tokens.push({ type: "punct", value: "(" }); // `${` starts an expression
        return;
      }
      text += c;
      i += 1;
    }
    tokens.push({ type: "template", value: text });
  };
  while (i < code.length) {
    const c = code[i];
    if (isSpace(c)) { i += 1; continue; }
    if (c === "/" && code[i + 1] === "/") { while (i < code.length && code[i] !== "\n") i += 1; continue; }
    if (c === "/" && code[i + 1] === "*") { const end = code.indexOf("*/", i + 2); i = end < 0 ? code.length : end + 2; continue; }
    if (c === "'" || c === '"') {
      let text = "";
      i += 1;
      while (i < code.length && code[i] !== c && code[i] !== "\n") {
        if (code[i] === "\\") { text += code[i + 1] ?? ""; i += 2; continue; }
        text += code[i];
        i += 1;
      }
      i += 1;
      tokens.push({ type: "string", value: text });
      continue;
    }
    if (c === "`") { i += 1; templateText(); continue; }
    if (c === "/" && regexAllowed()) {
      let inClass = false;
      i += 1;
      while (i < code.length && code[i] !== "\n") {
        if (code[i] === "\\") { i += 2; continue; }
        if (code[i] === "[") inClass = true;
        else if (code[i] === "]") inClass = false;
        else if (code[i] === "/" && !inClass) break;
        i += 1;
      }
      i += 1;
      while (i < code.length && /[A-Za-z]/.test(code[i])) i += 1; // flags
      tokens.push({ type: "regex", value: "" });
      continue;
    }
    if (isWordStart(c)) {
      const start = i;
      while (i < code.length && isWordPart(code[i])) i += 1;
      tokens.push({ type: "word", value: code.slice(start, i) });
      continue;
    }
    if (isDigit(c) || (c === "." && isDigit(code[i + 1] ?? ""))) {
      const start = i;
      while (i < code.length && (isWordPart(code[i]) || code[i] === ".")) i += 1;
      tokens.push({ type: "number", value: code.slice(start, i) });
      continue;
    }
    if (c === "{") { depth += 1; tokens.push({ type: "punct", value: "{" }); i += 1; continue; }
    if (c === "}") {
      depth -= 1;
      if (templateResume.length && templateResume[templateResume.length - 1] === depth) {
        templateResume.pop();
        tokens.push({ type: "punct", value: ")" });
        i += 1;
        templateText();
        continue;
      }
      tokens.push({ type: "punct", value: "}" });
      i += 1;
      continue;
    }
    const punct = PUNCTUATORS_BY_FIRST.get(c)?.find((p) => code.startsWith(p, i)) ?? c;
    // `?.` followed by a digit is `?` then a number (`a?.5:b`).
    const value = punct === "?." && /[0-9]/.test(code[i + 2] ?? "") ? "?" : punct;
    tokens.push({ type: "punct", value });
    i += value.length;
  }
  return tokens;
}

const isPunct = (token, value) => token?.type === "punct" && token.value === value;
const OPENERS = { "(": ")", "[": "]", "{": "}" };
const CLOSERS = new Set(Object.values(OPENERS));

// Work bounds. Every stage is linear in the script, and these make that a
// promise rather than an observation: a package past any of them gets one
// advisory warning instead of an analysis (never a refusal). Bytes match
// the hosted body limit, so every installable package fits; tokens and
// steps are generous multiples of what that many bytes can produce.
export const LINT_BUDGET = Object.freeze({
  scriptBytes: LIMITS.html.body_max_bytes,
  tokens: 2 * LIMITS.html.body_max_bytes,
  steps: 64 * LIMITS.html.body_max_bytes,
});
// A receiver chain is only a hint, so it is read at most this far back.
const CHAIN_MAX_WORDS = 16;

class LintBudgetExceeded extends Error {}

/**
 * One pass over `tokens`: `match[k]` pairs each bracket with its partner
 * (-1 when unbalanced) and `parent[k]` is the innermost opener enclosing
 * token `k` (-1 at top level). Iterative, so deep nesting cannot overflow
 * the stack, and every later lookup is O(1).
 */
function bracketIndex(tokens) {
  const match = new Int32Array(tokens.length).fill(-1);
  const parent = new Int32Array(tokens.length).fill(-1);
  const stack = [];
  for (let k = 0; k < tokens.length; k++) {
    parent[k] = stack.length ? stack[stack.length - 1] : -1;
    const token = tokens[k];
    if (token.type !== "punct") continue;
    if (token.value in OPENERS) stack.push(k);
    else if (CLOSERS.has(token.value) && stack.length) {
      const open = stack.pop();
      if (OPENERS[tokens[open].value] === token.value) {
        match[open] = k;
        match[k] = open;
      }
    }
  }
  return { match, parent };
}

/** Shared state for one analysis: the tokens, their bracket index, memoised pattern answers and a step budget. */
function analysis(tokens, steps = Infinity) {
  return { tokens, ...bracketIndex(tokens), pattern: new Map(), steps, work: 0 };
}

function spend(a, n = 1) {
  a.work += n;
  if (a.work > a.steps) throw new LintBudgetExceeded();
}

// Whether the `(` at `open` is a parameter list: `function f(`, `f(…) {`
// as a method, or `(…) =>`.
function isParameterList(a, open) {
  const { tokens, match } = a;
  const close = match[open];
  if (close < 0) return false;
  if (isPunct(tokens[close + 1], "=>")) return true;
  const before = tokens[open - 1];
  if (before?.type === "word" && before.value === "function") return true;
  if (before?.type === "word" && tokens[open - 2]?.type === "word" && tokens[open - 2].value === "function") return true;
  return false;
}

// Whether the `{` or `[` at `open` is a destructuring pattern: declared
// (`const {`), assigned (`{…} =`), a parameter, a `for (const {…} of`, or
// nested inside a pattern (`{ a: {…} }`, `[{…}]`). A nested opener has
// the answer of the pattern around it, so the walk goes outward
// iteratively and memoises every opener it passes.
function isPattern(a, first) {
  const { tokens, match, parent, pattern } = a;
  const chain = [];
  let open = first;
  let answer = false;
  for (;;) {
    if (pattern.has(open)) { answer = pattern.get(open); break; }
    spend(a);
    chain.push(open);
    const close = match[open];
    if (close < 0) break;
    const before = tokens[open - 1];
    if (before?.type === "word" && ["const", "let", "var"].includes(before.value)) { answer = true; break; }
    if (isPunct(tokens[close + 1], "=")) { answer = true; break; }
    const outer = parent[open];
    if (outer < 0) break;
    if (tokens[outer].value === "(") {
      answer = (isPunct(before, "(") || isPunct(before, ",")) && isParameterList(a, outer);
      break;
    }
    // Nested: `{ key: {…} }` or `[ {…} ]` inside a pattern.
    if ((tokens[outer].value === "{" && isPunct(before, ":")) || (tokens[outer].value === "[" && (isPunct(before, "[") || isPunct(before, ",")))) {
      open = outer;
      continue;
    }
    break;
  }
  for (const k of chain) pattern.set(k, answer);
  return answer;
}

// Words in the access chain ending just before `at` (`input.sql["k"]` →
// ["input", "sql"]), walking back over `.`, `?.` and bracket groups, at
// most CHAIN_MAX_WORDS steps.
function chainWords(a, at) {
  const { tokens, match } = a;
  const words = [];
  let k = at;
  for (let step = 0; k >= 0 && step < CHAIN_MAX_WORDS; step++) {
    spend(a);
    const token = tokens[k];
    if (isPunct(token, ")") || isPunct(token, "]")) {
      // A call or index: its callee or receiver comes straight before it.
      const open = match[k];
      if (open < 0) break;
      k = open - 1;
      if (isPunct(tokens[k], "?.")) k -= 1;
      continue;
    }
    if (token.type !== "word") break;
    words.push(token.value);
    k -= 1;
    if (!(isPunct(tokens[k], ".") || isPunct(tokens[k], "?."))) break;
    k -= 1;
  }
  return words;
}

function readsOf(a, name) {
  const { tokens, parent } = a;
  const reads = [];
  for (let k = 0; k < tokens.length; k++) {
    spend(a);
    const token = tokens[k];
    if (token.value !== name) continue;
    let end = -1;
    let receiver = [];
    if (token.type === "word" && (isPunct(tokens[k - 1], ".") || isPunct(tokens[k - 1], "?."))) {
      end = k;
      receiver = chainWords(a, k - 2);
    } else if (token.type === "string" && isPunct(tokens[k - 1], "[") && isPunct(tokens[k + 1], "]")) {
      const prev = tokens[k - 2];
      // A computed key needs a receiver: `x["rows"]`, `x?.["rows"]`, `f()["rows"]`.
      if (prev && (prev.type === "word" || isPunct(prev, "?.") || isPunct(prev, ")") || isPunct(prev, "]"))) {
        end = k + 1;
        receiver = chainWords(a, isPunct(prev, "?.") ? k - 3 : k - 2);
      }
    }
    if (end >= 0) {
      const next = tokens[end + 1];
      if (next?.type === "punct" && ASSIGNMENT.has(next.value)) continue; // a write
      reads.push({ kind: "property", receiver });
      continue;
    }
    // Destructuring key: `{ name }`, `{ name: x }`, `{ name = d }`, `{ "name": x }`.
    const isKey = (token.type === "word" || token.type === "string")
      && (isPunct(tokens[k - 1], "{") || isPunct(tokens[k - 1], ","))
      && ["}", ",", ":", "="].some((value) => isPunct(tokens[k + 1], value));
    if (isKey) {
      const open = parent[k];
      if (open >= 0 && tokens[open].value === "{" && isPattern(a, open)) reads.push({ kind: "destructure", receiver: [] });
    }
  }
  return reads;
}

/**
 * Reads of property `name` in `tokens`: `{kind, receiver}` per read, where
 * `receiver` lists the words of the access chain before it (`[]` for a
 * destructuring read).
 */
export function fieldReads(tokens, name) {
  return readsOf(analysis(tokens), name);
}

/** Whether `code` reads property `name` (convenience over `tokenize`). */
export function readsField(code, name) {
  return fieldReads(tokenize(code), name).length > 0;
}

// A read whose receiver names a result (`result.rows`, `sql["k"].rows`,
// `section.rows`) or that destructures one, rather than any object.
const resultShaped = (read) => read.kind === "destructure"
  || read.receiver.some((word) => RESULT_WORDS.has(word.toLowerCase()));

/**
 * Advisory findings for one package with the work it took: `html` is the
 * bundle, `sqlNeeds` the parsed SQL needs from its declaration, `budget`
 * overrides [`LINT_BUDGET`] (tests use a small one). `exhausted` names the
 * bound that stopped the analysis, which then reports one warning instead
 * of guessing. Every finding is a warning.
 */
export function completenessAnalysis(html, sqlNeeds, budget) {
  budget = { ...LINT_BUDGET, ...budget };
  const report = { findings: [], tokens: 0, work: 0, exhausted: null };
  if (!Array.isArray(sqlNeeds) || sqlNeeds.length === 0) return report;
  const scripts = inlineScripts(html);
  const bytes = scripts.reduce((sum, script) => sum + script.length, 0);
  const stop = (bound) => {
    report.exhausted = bound;
    report.findings = [warning("reads.completeness-lint-budget", AT,
      `the completeness lint stopped at its ${bound} bound without an answer, so it cannot say whether the package surfaces \`truncated\` and \`row_count_complete\`. Nothing is refused; check by hand that every SQL result view says when it is capped`)];
    return report;
  };
  if (bytes > budget.scriptBytes) return stop("script size");
  const tokens = scripts.flatMap((script) => tokenize(script));
  report.tokens = tokens.length;
  if (tokens.length > budget.tokens) return stop("token");
  const a = analysis(tokens, budget.steps);
  try {
    const out = [];
    const caveat = (reads, field) => (reads.some(resultShaped)
      ? ""
      : ` (no read of \`${field}\` has a receiver the kit recognises as a SQL result, so it may belong to another object, such as a table's rows; if so, ignore this)`);
    const rows = readsOf(a, "rows");
    if (rows.length > 0 && readsOf(a, "truncated").length === 0) {
      out.push(warning("reads.surface-truncated", AT,
        `the package reads \`rows\` but never reads \`truncated\`: a capped SQL result (200 delivered rows, or query_sql's 1,000) would show as the whole answer. Read \`truncated\` and say so when it is true${caveat(rows, "rows")}`));
    }
    const counts = readsOf(a, "row_count");
    if (counts.length > 0 && readsOf(a, "row_count_complete").length === 0) {
      out.push(warning("reads.surface-row-count-complete", AT,
        `the package reads \`row_count\` but never \`row_count_complete\`: past query_sql's 1,000 rows \`row_count\` is a floor, so "of N" would be false. Say "more than N" when \`row_count_complete\` is false${caveat(counts, "row_count")}`));
    }
    report.findings = out;
  } catch (error) {
    if (!(error instanceof LintBudgetExceeded)) throw error;
    report.work = a.work;
    return stop("step");
  }
  report.work = a.work;
  return report;
}

/**
 * Advisory findings for one package: `html` is the bundle, `sqlNeeds` the
 * parsed SQL needs from its declaration. Every finding is a warning.
 */
export function completenessFindings(html, sqlNeeds) {
  return completenessAnalysis(html, sqlNeeds).findings;
}
