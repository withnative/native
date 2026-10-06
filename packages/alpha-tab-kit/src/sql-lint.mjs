// A lexical mirror of the SQL admission an alpha-tab `sql.snapshot.v1` need
// goes through at install: `parse_sql_need_entry` (src/mcp/tools/alpha_tabs.rs
// :377-414) runs `crate::query::sql::validate`, `check_positional_arguments`
// and `validated_output_columns`.
//
// Several of those rules are themselves lexical in Rust (the statement
// classifier, placeholders, the dropped-function scan), and are mirrored
// exactly. Others need SQLite's parser or the live schema (LIMIT/ORDER BY on
// the AST, the relation and function authorizer, output-column expansion);
// here they are approximated on a paren-depth token stream, which can miss
// cases but is designed not to invent them. Rules that need the real engine
// (bare GROUP BY columns, `SELECT *` under GROUP BY, column existence, the
// 2 s deadline, cell and result byte ceilings) are listed in NOT_MIRRORED and
// only the real `query_sql` can check them: run each statement once with
// `query_sql` before install.
import { LIMITS } from "./limits.mjs";
import { finding } from "./findings.mjs";

const S = LIMITS.sql;
const CQ = "crates/query-contract/src/sql_contract.rs";
const AT = "src/mcp/tools/alpha_tabs.rs";

export const NOT_MIRRORED = [
  { rule: "sql.group-by-columns", mirrors: "src/query/turso_ast_rules.rs:644 check_group_columns", note: "every select-list column must be grouped or aggregated" },
  { rule: "sql.select-star-grouped", mirrors: "src/query/turso_ast_rules.rs:857", note: "SELECT * with GROUP BY or aggregates needs explicit output columns" },
  { rule: "sql.columns-exist", mirrors: "src/query/sql.rs validate_strict", note: "columns must exist on the logical relations" },
  { rule: "sql.regexp-pattern", mirrors: `${CQ}:3781`, note: "regexp arity and pattern checks" },
  { rule: "sql.runtime-limits", mirrors: `${CQ}:21-25`, note: `runtime: ${S.max_rows} rows, ${S.max_cell_encoded_bytes}-byte cells, ${S.max_result_encoded_bytes}-byte results, ${S.deadline_ms} ms deadline` },
];

// Keywords that may directly precede `(` without being a function call.
const NON_CALL_WORDS = new Set([
  "all", "and", "any", "as", "between", "by", "case", "cast", "collate", "distinct", "else", "escape",
  "except", "exists", "filter", "from", "glob", "group", "groups", "having", "in", "intersect", "is", "join",
  "like", "limit", "materialized", "not", "offset", "on", "or", "order", "over", "partition", "range",
  "recursive", "rows", "select", "some", "then", "union", "using", "values", "when", "where", "window", "with",
]);
const CLAUSE_WORDS = new Set([
  "where", "group", "order", "limit", "having", "window", "union", "intersect", "except", "on", "using",
  "join", "inner", "left", "right", "full", "cross", "natural", "outer", "select", "values",
]);

function tokenize(sql) {
  const tokens = [];
  let depth = 0;
  let i = 0;
  const push = (type, value, start) => tokens.push({ type, value, depth, start });
  while (i < sql.length) {
    const c = sql[i];
    if (c === "-" && sql[i + 1] === "-") { while (i < sql.length && sql[i] !== "\n") i += 1; continue; }
    if (c === "/" && sql[i + 1] === "*") { const end = sql.indexOf("*/", i + 2); i = end < 0 ? sql.length : end + 2; continue; }
    if (/\s/.test(c)) { i += 1; continue; }
    if (c === "'" || c === '"' || c === "`") {
      const start = i;
      i += 1;
      while (i < sql.length) {
        if (sql[i] === c) { if (sql[i + 1] === c) { i += 2; continue; } i += 1; break; }
        i += 1;
      }
      const inner = sql.slice(start + 1, i - 1).split(c + c).join(c);
      push(c === "'" ? "string" : "ident", inner, start);
      continue;
    }
    if (c === "[") { const end = sql.indexOf("]", i); push("ident", sql.slice(i + 1, end < 0 ? sql.length : end), i); i = end < 0 ? sql.length : end + 1; continue; }
    if (/[A-Za-z_]/.test(c)) {
      const start = i;
      while (i < sql.length && /[A-Za-z0-9_$]/.test(sql[i])) i += 1;
      push("word", sql.slice(start, i).toLowerCase(), start);
      continue;
    }
    if (/[0-9]/.test(c)) {
      const start = i;
      while (i < sql.length && /[0-9.eE]/.test(sql[i])) i += 1;
      push("number", sql.slice(start, i), start);
      continue;
    }
    if (c === "?" || c === ":" || c === "@" || c === "$") {
      const start = i;
      if (c === ":" && sql[i + 1] === ":") { push("punct", "::", start); i += 2; continue; }
      i += 1;
      while (i < sql.length && /[A-Za-z0-9_]/.test(sql[i])) i += 1;
      const text = sql.slice(start, i);
      if (text.length === 1 && c !== "?") push("punct", c, start);
      else push("placeholder", text, start);
      continue;
    }
    if (c === "(") { push("open", c, i); depth += 1; i += 1; continue; }
    if (c === ")") { depth -= 1; push("close", c, i); i += 1; continue; }
    push("punct", c, i);
    i += 1;
  }
  return tokens;
}

const isWord = (token, ...words) => token?.type === "word" && (words.length === 0 || words.includes(token.value));

function matchingClose(tokens, openIndex) {
  const depth = tokens[openIndex].depth;
  for (let j = openIndex + 1; j < tokens.length; j += 1) {
    if (tokens[j].type === "close" && tokens[j].depth === depth) return j;
  }
  return tokens.length - 1;
}

function cteNames(tokens) {
  const names = new Set();
  tokens.forEach((token, index) => {
    if (!(token.type === "word" || token.type === "ident")) return;
    const prev = tokens[index - 1];
    if (!(isWord(prev, "with", "recursive") || (prev?.type === "punct" && prev.value === ","))) return;
    let next = index + 1;
    if (tokens[next]?.type === "open") next = matchingClose(tokens, next) + 1;
    if (isWord(tokens[next], "as") && (tokens[next + 1]?.type === "open" || isWord(tokens[next + 1], "materialized", "not"))) names.add(token.value.toLowerCase());
  });
  return names;
}

/**
 * Lint one statement as `parse_sql_need_entry` would admit it.
 * `params` is the parsed param list (declaration order = `?N` order).
 */
export function lintSql(sql, params = [], where = "sql") {
  const findings = [];
  const fail = (rule, mirrors, message) => findings.push(finding(rule, mirrors, message, { where }));
  const classifier = `${CQ}:2221 classify_single_read_statement`;

  if (Buffer.byteLength(sql, "utf8") > S.max_sql_bytes) fail("sql.bytes", `${CQ}:2227`, `SQL input exceeds the ${S.max_sql_bytes}-byte limit`);
  const tokens = tokenize(sql);
  if (tokens.length === 0) { fail("sql.empty", `${CQ}:2246`, "empty query"); return findings; }

  const first = tokens[0];
  const explainPlan = isWord(first, "explain") && isWord(tokens[1], "query") && isWord(tokens[2], "plan");
  const lead = explainPlan ? tokens[3] : first;
  if (isWord(first, "explain") && !explainPlan) {
    fail("sql.first-word", `${CQ}:2323`, "EXPLAIN without QUERY PLAN is not admitted; use EXPLAIN QUERY PLAN over a SELECT or WITH statement");
  } else if (!isWord(lead, "select", "with")) {
    fail("sql.first-word", `${CQ}:2252`, `read-only statement must start with SELECT or WITH, got '${lead?.value ?? ""}'`);
  }
  for (const token of tokens) {
    if (token.type !== "word") continue;
    if (S.forbidden_words.includes(token.value)) { fail("sql.forbidden-word", `${CQ}:2262`, `read-only statement contains prohibited token '${token.value}'`); break; }
  }
  for (const token of tokens) {
    if (token.type === "word" && S.clock_keywords.includes(token.value)) {
      fail("sql.clock-keyword", `${CQ}:4097`, `${token.value} is unavailable — use now_ms() for the current time in milliseconds since the Unix epoch`);
      break;
    }
  }
  if (isWord(first, "replace") || tokens.some((token, index) => isWord(token, "replace") && isWord(tokens[index + 1], "into"))) {
    fail("sql.forbidden-word", `${CQ}:4119 reject_bare_replace`, "read-only statement contains prohibited token 'replace'");
  }
  const semicolons = tokens.map((token, index) => (token.type === "punct" && token.value === ";" ? index : -1)).filter((index) => index >= 0);
  if (semicolons.length > 1 || (semicolons.length === 1 && semicolons[0] !== tokens.length - 1)) {
    fail("sql.single-statement", `${CQ}:2303`, "a single statement only");
  }

  // Placeholders: only ?N (1-based, ≤ 256, no leading zero), and the set of
  // N must be exactly {1..params.length}.
  const numbers = new Set();
  for (const token of tokens) {
    if (token.type !== "placeholder") continue;
    const text = token.value;
    if (text === "?") { fail("sql.placeholder", `${CQ}:2543 placeholder_end`, "`?` is not admitted: placeholders are positional `?N`"); continue; }
    if (text[0] === "?" && /^\?[0-9]+$/.test(text)) {
      if (text[1] === "0") { fail("sql.placeholder", `${CQ}:2551 placeholder_end`, `non-portable placeholder \`${text}\` — use positional \`?N\` placeholders (1-based, contiguous)`); continue; }
      const n = Number(text.slice(1));
      if (n > S.max_placeholder) { fail("sql.placeholder", `${CQ}:2554 placeholder_end`, `non-portable placeholder \`${text}\` — placeholder numbers must not exceed ${S.max_placeholder}`); continue; }
      numbers.add(n);
      continue;
    }
    fail("sql.placeholder", `${CQ}:2520 placeholder_end`, `non-portable placeholder \`${text}\` — use positional \`?N\` placeholders (1-based, contiguous)`);
  }
  const expected = params.map((_, index) => index + 1);
  const exact = numbers.size === expected.length && expected.every((n) => numbers.has(n));
  if (!exact) {
    fail("sql.placeholder-params", params.length ? `${AT}:398 (${CQ}:2403 check_positional_arguments)` : `${AT}:394 (${CQ}:2403 check_positional_arguments)`,
      params.length
        ? `placeholders must match declared params exactly: uses {${[...numbers].sort((a, b) => a - b).map((n) => `?${n}`).join(", ")}}, declares ${params.length} param(s)`
        : `must not contain placeholders when no params are declared (uses ${[...numbers].map((n) => `?${n}`).join(", ")})`);
  }

  // `x GLOB y` is SQLite's glob() function in operator form; the authorizer
  // denies it like the call (src/query/sql.rs:1207; repair "use LIKE").
  if (tokens.some((token, index) => isWord(token, "glob") && tokens[index + 1]?.type !== "open")) {
    fail("sql.dropped-function", `${CQ}:2896 DROPPED_FUNCTION_REPAIRS; src/query/sql.rs:1207 authorize_strict`, "the GLOB operator is unavailable on the portable profile — use LIKE");
  }

  // Function calls: dropped names (exact mirror of the classifier scan) and
  // anything the authorizer would deny (approximate).
  const ctes = cteNames(tokens);
  tokens.forEach((token, index) => {
    if (!(token.type === "word" || token.type === "ident") || tokens[index + 1]?.type !== "open") return;
    const name = token.value.toLowerCase();
    if (isWord(tokens[index - 1], "as")) return;
    const close = matchingClose(tokens, index + 1);
    if (isWord(tokens[close + 1], "as") && (ctes.has(name) || isWord(tokens[index - 1], "with", "recursive") || tokens[index - 1]?.value === ",")) return;
    if (token.type === "word" && NON_CALL_WORDS.has(name)) return;
    if (tokens[index - 1]?.type === "punct" && tokens[index - 1].value === ".") return;
    const dropped = S.dropped_functions.includes(name) || name.startsWith("json_");
    if (dropped) { fail("sql.dropped-function", `${CQ}:2896 DROPPED_FUNCTION_REPAIRS`, `function '${name}' is unavailable on the portable profile`); return; }
    if (!S.portable_functions.includes(name)) { fail("sql.unknown-function", "src/query/sql.rs:1207 authorize_strict", `function '${name}' is not in the portable function set; the authorizer will deny it`); return; }
    const inner = tokens.slice(index + 2, close);
    const args = inner.length === 0 ? 0 : 1 + inner.filter((t) => t.type === "punct" && t.value === "," && t.depth === token.depth + 1).length;
    if (name === "round" && args >= 2) fail("sql.function-arity", `${CQ}:3340`, "two-argument round is not portable — CAST the value to the catalog numeric type first");
    if (name === "now_ms" && args !== 0) fail("sql.function-arity", `${CQ}:3365`, "now_ms() takes no arguments");
    if (name === "utc_date_label" && args !== 1) fail("sql.function-arity", `${CQ}:3519`, "utc_date_label takes exactly one argument");
  });

  // Relations after FROM / JOIN must be logical relations or CTE names.
  const relations = new Set(S.relations);
  let expectTable = false;
  let fromDepth = -1;
  tokens.forEach((token, index) => {
    if (isWord(token, "from", "join")) { expectTable = true; fromDepth = token.depth; return; }
    if (!expectTable) return;
    if (token.depth !== fromDepth) return;
    if (token.type === "open") { expectTable = false; return; }
    if (token.type === "word" && CLAUSE_WORDS.has(token.value)) { expectTable = false; return; }
    if (expectTable === "after") {
      // `name [AS] alias`, then a comma continues the FROM list.
      if (token.type === "punct" && token.value === ",") expectTable = true;
      else if (token.type === "punct" && token.value !== ".") expectTable = false;
      return;
    }
    if (tokens[index - 1]?.type === "punct" && tokens[index - 1].value === ".") return;
    if (token.type === "word" || token.type === "ident") {
      let name = token.value.toLowerCase();
      if (tokens[index + 1]?.type === "punct" && tokens[index + 1].value === ".") {
        const schema = name;
        name = String(tokens[index + 2]?.value ?? "").toLowerCase();
        if (schema !== "temp") fail("sql.relation", "src/query/sql.rs:1197 authorize_strict", `schema-qualified relation '${schema}.${name}' is not authorized`);
      }
      if (!relations.has(name) && !ctes.has(name)) {
        fail("sql.relation", `${CQ}:60 LOGICAL_RELATIONS (authorize_strict, src/query/sql.rs:1197)`, `'${name}' is not a logical relation (${S.relations.join(", ")})`);
      }
      expectTable = "after";
      return;
    }
    expectTable = false;
  });

  // LIMIT needs ORDER BY at the same query level.
  tokens.forEach((token, index) => {
    if (!isWord(token, "limit")) return;
    let ordered = false;
    for (let j = index - 1; j >= 0; j -= 1) {
      const t = tokens[j];
      if (t.depth < token.depth) break;
      if (t.depth > token.depth) continue;
      if (t.type === "open" && t.depth === token.depth - 1) break;
      if (isWord(t, "limit")) break;
      if (isWord(t, "order") && isWord(tokens[j + 1], "by")) { ordered = true; break; }
    }
    if (!ordered) fail("sql.limit-order", "src/query/turso_ast_rules.rs:117 check_limit_order", "LIMIT without ORDER BY: add ORDER BY over a unique key");
  });

  // Output columns of the outermost SELECT: count, and duplicate labels.
  const selectIndex = tokens.findIndex((token) => isWord(token, "select") && token.depth === 0);
  if (selectIndex >= 0) {
    const items = [[]];
    for (let j = selectIndex + 1; j < tokens.length; j += 1) {
      const t = tokens[j];
      if (t.depth === 0 && (isWord(t, "from", "union", "intersect", "except", "where", "order", "limit", "group") || (t.type === "punct" && t.value === ";"))) break;
      if (t.depth === 0 && t.type === "punct" && t.value === ",") { items.push([]); continue; }
      if (!(t.depth === 0 && isWord(t, "distinct", "all") && items.length === 1 && items[0].length === 0)) items[items.length - 1].push(t);
    }
    const star = items.some((item) => item.some((t) => t.type === "punct" && t.value === "*" && t.depth === 0) && item.length <= 3);
    if (!star) {
      if (items.length > S.max_columns) fail("sql.columns", `${AT}:408`, `statement returns ${items.length} columns, at most ${S.max_columns}`);
      const labels = items.map((item) => {
        const last = item[item.length - 1];
        const beforeLast = item[item.length - 2];
        if (isWord(beforeLast, "as") || (item.length === 2 && (last?.type === "word" || last?.type === "ident"))) return String(last.value).toLowerCase();
        const plain = item.filter((t) => t.depth === 0);
        if (plain.length === 1 && (plain[0].type === "word" || plain[0].type === "ident")) return String(plain[0].value).toLowerCase();
        if (plain.length === 3 && plain[1].value === "." && (plain[2].type === "word" || plain[2].type === "ident")) return String(plain[2].value).toLowerCase();
        return null;
      });
      const seen = new Set();
      for (const label of labels) {
        if (label === null) continue;
        if (seen.has(label)) { fail("sql.duplicate-columns", "src/query/sql.rs:1255", `duplicate output column label '${label}'`); break; }
        seen.add(label);
      }
    }
  }
  return findings;
}
