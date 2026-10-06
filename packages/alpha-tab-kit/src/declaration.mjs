import { BODY_READ_NEED, classifyDeclarationNeed, bodyReadDescriptorIn } from "./body-feature-grammar.mjs";
export { BODY_READ_NEED, BODY_READ_SCOPE, classifyDeclarationNeed, bodyReadDescriptorIn, parseBodyFeatureDeclaration } from "./body-feature-grammar.mjs";
// Declaration shape rules, mirroring `require_declaration`,
// `parse_sql_need_entry` and `parse_sql_param_entry` in
// src/mcp/tools/alpha_tabs.rs. Every refusal there carries
// `[invalid_sql_need]` or a plain engine error; here each one is a finding
// that names the rule and the line it mirrors.
//
// SQL admission (`crate::query::sql::validate`) is not run here: see
// sql-lint.mjs, which the validator calls on each parsed need.
// Exception: BodySet is a dormant proposed shape, sourced to owner agreement
// below. Parsing it does not assert current Rust parity or write support.
import { LIMITS } from "./limits.mjs";
import { finding } from "./findings.mjs";
import { compareUtf8 } from "./jcs.mjs";

const D = LIMITS.declaration;
const RS = "src/mcp/tools/alpha_tabs.rs";

const utf8Length = (text) => Buffer.byteLength(text, "utf8");
// Rust `str::chars().count()` counts Unicode scalar values, as does spreading.
const charCount = (text) => [...text].length;
const isPlainObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

// `valid_sql_need_key`: ^[a-z][a-z0-9_.]{0,39}$
export function validSqlNeedKey(key) {
  return key.length >= 1 && key.length <= D.sql_need_key_max_chars && /^[a-z][a-z0-9_.]*$/.test(key);
}

// `valid_sql_param_name`: ^[a-z][a-z0-9_]{0,31}$
export function validSqlParamName(name) {
  return name.length >= 1 && name.length <= D.param_name_max_chars && /^[a-z][a-z0-9_]*$/.test(name);
}

// Mirrors `parse_sql_param_entry` (alpha_tabs.rs:223).
export function parseSqlParamEntry(entry, where) {
  const fail = (rule, line, message) => ({ error: finding(rule, `${RS}:${line} parse_sql_param_entry`, message, { where }) });
  if (!isPlainObject(entry)) return fail("sql-param.shape", 226, "sql param entry must be an object");
  const hasMaxLen = hasOwn(entry, "max_len");
  const hasRequired = hasOwn(entry, "required");
  const allowed = 2 + Number(hasMaxLen) + Number(hasRequired);
  if (Object.keys(entry).length !== allowed || !hasOwn(entry, "name") || !hasOwn(entry, "type")) {
    return fail("sql-param.shape", 232, "sql param entry must hold exactly 'name', 'type' with optional 'max_len' and 'required'");
  }
  if (typeof entry.name !== "string") return fail("sql-param.name", 238, "sql param 'name' must be a string");
  if (!validSqlParamName(entry.name)) return fail("sql-param.name", 241, `sql param '${entry.name}' must match ^[a-z][a-z0-9_]{0,31}$`);
  if (typeof entry.type !== "string") return fail("sql-param.type", 247, "sql param 'type' must be a string");
  if (!D.param_types.includes(entry.type)) return fail("sql-param.type", 249, `sql param 'type' must be one of ${D.param_types.join(", ")}`);
  let maxLen = D.param_text_default_max_len;
  if (hasMaxLen) {
    // `Value::as_u64`: a non-negative integer that fits u64.
    if (!Number.isInteger(entry.max_len) || entry.max_len < 0) return fail("sql-param.max_len", 255, "sql param 'max_len' must be an integer");
    if (entry.max_len === 0 || entry.max_len > D.param_text_hard_cap) {
      return fail("sql-param.max_len", 262, `sql param 'max_len' must be 1..=${D.param_text_hard_cap}`);
    }
    maxLen = entry.max_len;
  }
  if (entry.type !== "text" && hasMaxLen) return fail("sql-param.max_len", 270, "sql param 'max_len' applies only to text params");
  let required = true;
  if (hasRequired) {
    if (typeof entry.required !== "boolean") return fail("sql-param.required", 278, "sql param 'required' must be a boolean");
    required = entry.required;
  }
  return { param: { name: entry.name, type: entry.type, max_len: maxLen, required } };
}

// Mirrors `parse_sql_need_entry` (alpha_tabs.rs:293) up to, not including,
// the SQL validator call at line 382.
export function parseSqlNeedEntry(entry, where = "needs[]") {
  const fail = (rule, line, message) => ({ error: finding(rule, `${RS}:${line} parse_sql_need_entry`, message, { where }) });
  if (!isPlainObject(entry)) return fail("sql-need.shape", 295, "declaration 'needs' sql entry must be an object");
  const hasParams = hasOwn(entry, "params");
  const allowed = 4 + Number(hasParams);
  if (Object.keys(entry).length !== allowed || entry.need !== D.sql_snapshot_need
    || !hasOwn(entry, "key") || !hasOwn(entry, "label") || !hasOwn(entry, "sql")) {
    return fail("sql-need.shape", 306, "declaration 'needs' sql entry must hold exactly 'need', 'key', 'label' and 'sql' with optional 'params'");
  }
  if (typeof entry.key !== "string") return fail("sql-need.key", 312, "sql need 'key' must be a string");
  where = `needs[key=${entry.key}]`;
  if (!validSqlNeedKey(entry.key)) return fail("sql-need.key", 315, `sql need key '${entry.key}' must match ^[a-z][a-z0-9_.]{0,39}$`);
  if (D.host_need_names.includes(entry.key)) return fail("sql-need.key", 326, `sql need key '${entry.key}' must not collide with a host need name`);
  if (typeof entry.label !== "string") return fail("sql-need.label", 332, "sql need 'label' must be a string");
  const labelChars = charCount(entry.label);
  if (labelChars === 0 || labelChars > D.label_max_chars) {
    return fail("sql-need.label", 335, `sql need 'label' must be 1..=${D.label_max_chars} characters (has ${labelChars})`);
  }
  if (typeof entry.sql !== "string") return fail("sql-need.sql", 341, "sql need 'sql' must be a string");
  const sqlBytes = utf8Length(entry.sql);
  if (sqlBytes === 0 || sqlBytes > D.sql_max_bytes) {
    return fail("sql-need.sql-bytes", 344, `sql need 'sql' must be 1..=${D.sql_max_bytes} bytes (has ${sqlBytes})`);
  }
  let params = [];
  if (hasParams) {
    if (!Array.isArray(entry.params)) return fail("sql-need.params", 373, "sql need 'params' must be an array");
    if (entry.params.length > D.max_params) return fail("sql-need.params", 352, `sql need '${entry.key}' holds at most ${D.max_params} params`);
    for (const raw of entry.params) {
      const parsed = parseSqlParamEntry(raw, where);
      if (parsed.error) return parsed;
      params.push(parsed.param);
    }
    const names = params.map((param) => param.name).sort(compareUtf8);
    for (let index = 1; index < names.length; index += 1) {
      if (names[index] === names[index - 1]) return fail("sql-need.params", 364, `sql need '${entry.key}' param '${names[index]}' is duplicated`);
    }
  }
  return { need: { key: entry.key, label: entry.label, sql: entry.sql, params } };
}

export const FACET_SET_EFFECT = "records.facet-set.v1";
export const COMMENT_CREATE_EFFECT = "comment.create.v1";
export const COMMENT_CREATE_MAX_BODY_BYTES = 4096;
export const COMMENT_CREATE_POSITIONS = ["reply", "root"];
export const MESSAGE_REACT_EFFECT = "message.react.v1";
// Must stay identical to `MESSAGE_REACT_EMOJIS` in
// `src/mcp/tools/effect_bounds.rs` and `MESSAGE_REACTION_EMOJIS` in
// `src/events.rs`.
export const MESSAGE_REACT_EMOJIS = ["👍", "❤️", "😂", "🎉", "👀"];
export const TITLE_SET_EFFECT = "records.title-set.v1";

// Dormant agreement shape only, NOT an existing Rust/host capability.
// The raw UTF-8 bound does not prove encoded transport or inverse fit.
export const BODY_SET_EFFECT = LIMITS.proposed_body_set.effect;
export const BODY_SET_MAX_BODY_BYTES = LIMITS.proposed_body_set.max_body_bytes;
const BODY_SET_SOURCE = LIMITS.proposed_body_set.source;
const bodySetFailure = (rule, message, where) => ({
  error: finding(rule, BODY_SET_SOURCE, `${message} [invalid_effect]`, { where }),
});

/** Parse the exact dormant BodySet object; need resolution is list-level.
 * @param {unknown} entry
 * @returns {{bound: {need: string, max_body_bytes: number}} | {error: object}}
 */
export function parseBodySetBound(entry, where = "effects[]") {
  const fail = (rule, message) => bodySetFailure(rule, message, where);
  if (!isPlainObject(entry) || Object.keys(entry).length !== 3
    || !hasOwn(entry, "effect") || !hasOwn(entry, "max_body_bytes") || !hasOwn(entry, "target")) {
    return fail("body-set.shape", "body-set bound must hold exactly 'effect', 'max_body_bytes' and 'target'");
  }
  if (entry.effect !== BODY_SET_EFFECT) return fail("body-set.effect", "unsupported body-set effect");
  if (!Number.isInteger(entry.max_body_bytes) || entry.max_body_bytes < 1 || entry.max_body_bytes > BODY_SET_MAX_BODY_BYTES) {
    return fail("body-set.max_body_bytes", `body-set 'max_body_bytes' must be an integer 1..=${BODY_SET_MAX_BODY_BYTES}`);
  }
  if (!isPlainObject(entry.target) || Object.keys(entry.target).length !== 1 || !hasOwn(entry.target, "need")
    || typeof entry.target.need !== "string" || !validSqlNeedKey(entry.target.need)) {
    return fail("body-set.target", "body-set 'target' must hold exactly one valid sql need key 'need'");
  }
  return { bound: { need: entry.target.need, max_body_bytes: entry.max_body_bytes } };
}

/** Resolve the singleton against declared SQL needs, including ambiguity checks.
 * No SQL execution, runtime membership, encoded-budget or write admission.
 * @param {unknown} declaration
 * @returns {{bounds: Array<{need: string, max_body_bytes: number}>} | {error: object}}
 */
export function parseBodySetBounds(declaration, where = "effects[]") {
  const fail = (rule, message) => bodySetFailure(rule, message, where);
  if (!isPlainObject(declaration) || Object.keys(declaration).length !== 2
    || !Array.isArray(declaration.needs) || !Array.isArray(declaration.effects)) {
    return fail("body-set.declaration", "body-set declaration must hold exactly arrays 'needs' and 'effects'");
  }
  if (declaration.needs.length > D.max_entries || declaration.effects.length > D.max_entries) {
    return fail("body-set.declaration", `declaration arrays hold at most ${D.max_entries} entries`);
  }
  const bounds = [];
  for (const [index, entry] of declaration.effects.entries()) {
    if (entry === BODY_SET_EFFECT) return fail("body-set.shape", "bare 'records.body-set.v1' has no cap or need; declare the object bound");
    if (!isPlainObject(entry) || entry.effect !== BODY_SET_EFFECT) continue;
    const parsed = parseBodySetBound(entry, `effects[${index}]`);
    if (parsed.error) return parsed;
    bounds.push(parsed.bound);
  }
  if (bounds.length > 1) return fail("body-set.shape", "body-set bound occurs more than once; a declaration holds at most one");
  if (!bounds.length) return { bounds };
  const keys = new Set();
  const stringNeeds = declaration.needs.filter((entry) => typeof entry === "string");
  for (const [index, entry] of declaration.needs.entries()) {
    if (typeof entry === "string") continue;
    const parsed = parseSqlNeedEntry(entry, `needs[${index}]`);
    if (parsed.error) return parsed;
    const key = parsed.need.key;
    if (keys.has(key) || stringNeeds.includes(key)) return fail("body-set.need", `sql need key '${key}' is duplicated or shadows a string need`);
    keys.add(key);
  }
  if (keys.size > D.sql_snapshot_max_needs) return fail("body-set.need", `declaration holds at most ${D.sql_snapshot_max_needs} SQL needs`);
  if (!keys.has(bounds[0].need)) return fail("body-set.need", `body-set bound targets undeclared SQL need '${bounds[0].need}'`);
  return { bounds };
}

// Mirrors `parse_facet_set_bound` (alpha_tabs.rs:1891) plus the scope closure
// (`is_ordinary_facet_key` in src/mcp/tools/tab_effect_catalogue.rs:79,
// shared by the matcher so consent cannot drift): spine columns
// (`spine_facet_column`, src/schema/ddl.rs:2673), engine-dispatched keys
// (`ENGINE_DISPATCHED_FACET_KEYS`, crates/artifact-runtime/src/mdx_v2.rs:1845),
// record fields (`RECORD_CREATE_FIELD_KEYS`, mdx_v2.rs:1847) and the dedicated
// triage facet (`ALPHA_GUARD_FACET`, tab_effect_catalogue.rs:20) are refused.
// Lengths are UTF-8 bytes, matching Rust `.len()`; values may be empty
// strings, but the set itself must be nonempty.
const SPINE_FACET_KEYS = ["lifecycle", "owner", "persistence", "maturity"];
const ENGINE_DISPATCHED_FACET_KEYS = ["archived", "blob_ref", "runtime", "canvas.promoted_from"];
const RECORD_FIELD_KEYS = ["name", "body", "summary", "lifecycle", "persistence", "maturity"];
const TRIAGE_FACET = "triage";

export function parseFacetSetBound(entry, where = "effects[]") {
  const fail = (rule, message) => ({ error: finding(rule, `${RS} parse_facet_set_bound`, `${message} [invalid_effect]`, { where }) });
  if (!isPlainObject(entry)) return fail("facet-set.shape", "declaration 'effects' entries must be strings or facet-set objects");
  const keys = Object.keys(entry);
  if (keys.length !== 4 || !hasOwn(entry, "effect") || !hasOwn(entry, "key") || !hasOwn(entry, "values") || !hasOwn(entry, "target")) {
    return fail("facet-set.shape", "facet-set bound must hold exactly 'effect', 'key', 'values' and 'target'");
  }
  if (entry.effect !== FACET_SET_EFFECT) return fail("facet-set.effect", `unsupported object effect '${entry.effect}'`);
  if (typeof entry.key !== "string") return fail("facet-set.key", "facet-set bound 'key' must be a string");
  if (entry.key.trim() === "" || utf8Length(entry.key) > D.name_max_bytes) {
    return fail("facet-set.key", `facet-set bound 'key' must be 1..${D.name_max_bytes} characters`);
  }
  if (SPINE_FACET_KEYS.includes(entry.key) || ENGINE_DISPATCHED_FACET_KEYS.includes(entry.key)
    || RECORD_FIELD_KEYS.includes(entry.key) || entry.key === TRIAGE_FACET) {
    return fail("facet-set.key", `facet-set bound key '${entry.key}' is not an ordinary facet`);
  }
  if (!Array.isArray(entry.values) || entry.values.length === 0 || entry.values.length > D.facet_set_values_max) {
    return fail("facet-set.values", `facet-set bound 'values' must hold 1..=${D.facet_set_values_max} strings`);
  }
  const values = [];
  for (const value of entry.values) {
    if (typeof value !== "string") return fail("facet-set.values", "facet-set bound 'values' entries must be strings");
    if (utf8Length(value) > D.name_max_bytes) return fail("facet-set.values", "facet-set bound 'values' entries must be at most 128 characters");
    values.push(value);
  }
  // Rust `Vec<String>::sort` orders by UTF-8 bytes; the default
  // `Array#sort` orders by UTF-16 code units and disagrees for astral
  // planes against U+E000..U+FFFF, so the digest must sort the Rust way.
  values.sort(compareUtf8);
  for (let index = 1; index < values.length; index += 1) {
    if (values[index] === values[index - 1]) return fail("facet-set.values", "facet-set bound 'values' must not duplicate");
  }
  if (!isPlainObject(entry.target)) return fail("facet-set.target", "facet-set bound 'target' must be an object");
  if (Object.keys(entry.target).length !== 1 || !hasOwn(entry.target, "need")) {
    return fail("facet-set.target", "facet-set bound 'target' must hold exactly 'need'");
  }
  if (typeof entry.target.need !== "string" || !validSqlNeedKey(entry.target.need)) {
    return fail("facet-set.target", "facet-set bound 'target.need' must be a sql need key");
  }
  return { bound: { key: entry.key, values, need: entry.target.need } };
}

// Mirrors `parse_comment_create_bound` (alpha_tabs.rs:2203). Whole-number
// parity with the manifest bound: JSON parses 100, 100.0 and 1e2 to the
// same JS number, so Number.isInteger accepts all three; fractional,
// boolean and string values fail closed. Existing SQL/facet numeric
// parsing is untouched. Parameter/time membership restrictions are WRITE
// runtime, not stricter install parsing: any syntactically valid need key
// parses here; undeclared needs refuse below.
export function parseCommentCreateBound(entry, where = "effects[]") {
  const fail = (rule, message) => ({ error: finding(rule, `${RS} parse_comment_create_bound`, `${message} [invalid_effect]`, { where }) });
  if (!isPlainObject(entry)) return fail("comment-create.shape", "declaration 'effects' entries must be strings or comment.create objects");
  const keys = Object.keys(entry);
  if (keys.length !== 4 || !hasOwn(entry, "effect") || !hasOwn(entry, "positions") || !hasOwn(entry, "max_body_bytes") || !hasOwn(entry, "target")) {
    return fail("comment-create.shape", "comment.create bound must hold exactly 'effect', 'positions', 'max_body_bytes' and 'target'");
  }
  if (typeof entry.effect !== "string") return fail("comment-create.effect", "comment.create bound 'effect' must be a string");
  if (entry.effect !== COMMENT_CREATE_EFFECT) return fail("comment-create.effect", `unsupported object effect '${entry.effect}'`);
  if (!Array.isArray(entry.positions)) return fail("comment-create.positions", "comment.create bound 'positions' must be an array");
  if (entry.positions.length === 0 || entry.positions.length > COMMENT_CREATE_POSITIONS.length) {
    return fail("comment-create.positions", "comment.create bound 'positions' must hold 1..=2 of 'root'/'reply'");
  }
  const positions = [];
  for (const position of entry.positions) {
    if (typeof position !== "string") return fail("comment-create.positions", "comment.create bound 'positions' entries must be strings");
    if (!COMMENT_CREATE_POSITIONS.includes(position)) {
      return fail("comment-create.positions", `comment.create bound position '${position}' must be 'root' or 'reply'`);
    }
    positions.push(position);
  }
  positions.sort(compareUtf8);
  for (let index = 1; index < positions.length; index += 1) {
    if (positions[index] === positions[index - 1]) return fail("comment-create.positions", "comment.create bound 'positions' must not duplicate");
  }
  const raw = entry.max_body_bytes;
  if (typeof raw !== "number" || !Number.isFinite(raw) || !Number.isInteger(raw)) {
    return fail("comment-create.max_body_bytes", "comment.create bound 'max_body_bytes' must be an integer");
  }
  if (raw < 1 || raw > COMMENT_CREATE_MAX_BODY_BYTES) {
    return fail("comment-create.max_body_bytes", `comment.create bound 'max_body_bytes' must hold 1..=${COMMENT_CREATE_MAX_BODY_BYTES}`);
  }
  if (!isPlainObject(entry.target)) return fail("comment-create.target", "comment.create bound 'target' must be an object");
  if (Object.keys(entry.target).length !== 1 || !hasOwn(entry.target, "need")) {
    return fail("comment-create.target", "comment.create bound 'target' must hold exactly 'need'");
  }
  if (typeof entry.target.need !== "string") return fail("comment-create.target", "comment.create bound 'target.need' must be a string");
  if (!validSqlNeedKey(entry.target.need)) return fail("comment-create.target", "comment.create bound 'target.need' must be a sql need key");
  return { bound: { positions, max_body_bytes: raw, need: entry.target.need } };
}

// Mirrors `parse_comment_create_bounds` (alpha_tabs.rs:2316): no position
// may occur in more than one bound across effects[], regardless of need
// or cap. Duplicate identical objects refuse here too.
export function parseCommentCreateBounds(declaration, where = "effects[]") {
  const bounds = [];
  const entries = Array.isArray(declaration?.effects) ? declaration.effects : [];
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (!isPlainObject(entry)) continue;
    if (entry.effect !== COMMENT_CREATE_EFFECT) continue;
    const parsed = parseCommentCreateBound(entry, `effects[${index}]`);
    if (parsed.error) return parsed;
    bounds.push(parsed.bound);
  }
  const seen = bounds.flatMap((bound) => bound.positions).sort(compareUtf8);
  for (let index = 1; index < seen.length; index += 1) {
    if (seen[index] === seen[index - 1]) {
      return { error: finding("comment-create.positions", `${RS} parse_comment_create_bounds`, `comment.create position '${seen[index]}' occurs in more than one bound [invalid_effect]`, { where }) };
    }
  }
  return { bounds };
}

// Mirrors `parse_message_react_bound` (`src/mcp/tools/effect_bounds.rs`).
// Object form only; the bare string is refused below. Unknown fields fail
// closed. Any syntactically valid need key parses here; undeclared needs
// refuse below.
export function parseMessageReactBound(entry, where = "effects[]") {
  const fail = (rule, message) => ({ error: finding(rule, `${RS} parse_message_react_bound`, `${message} [invalid_effect]`, { where }) });
  if (!isPlainObject(entry)) return fail("message-react.shape", "declaration 'effects' entries must be strings or message.react objects");
  const keys = Object.keys(entry);
  if (keys.length !== 3 || !hasOwn(entry, "effect") || !hasOwn(entry, "emoji") || !hasOwn(entry, "target")) {
    return fail("message-react.shape", "message.react bound must hold exactly 'effect', 'emoji' and 'target'");
  }
  if (typeof entry.effect !== "string") return fail("message-react.effect", "message.react bound 'effect' must be a string");
  if (entry.effect !== MESSAGE_REACT_EFFECT) return fail("message-react.effect", `unsupported object effect '${entry.effect}'`);
  if (!Array.isArray(entry.emoji)) return fail("message-react.emoji", "message.react bound 'emoji' must be an array");
  if (entry.emoji.length === 0 || entry.emoji.length > MESSAGE_REACT_EMOJIS.length) {
    return fail("message-react.emoji", "message.react bound 'emoji' must hold 1..=5 canonical values");
  }
  const emoji = [];
  for (const value of entry.emoji) {
    if (typeof value !== "string") return fail("message-react.emoji", "message.react bound 'emoji' entries must be strings");
    if (!MESSAGE_REACT_EMOJIS.includes(value)) {
      return fail("message-react.emoji", `message.react bound emoji '${value}' is not a canonical v1 picker value`);
    }
    emoji.push(value);
  }
  emoji.sort(compareUtf8);
  for (let index = 1; index < emoji.length; index += 1) {
    if (emoji[index] === emoji[index - 1]) return fail("message-react.emoji", "message.react bound 'emoji' must not duplicate");
  }
  if (!isPlainObject(entry.target)) return fail("message-react.target", "message.react bound 'target' must be an object");
  if (Object.keys(entry.target).length !== 1 || !hasOwn(entry.target, "need")) {
    return fail("message-react.target", "message.react bound 'target' must hold exactly 'need'");
  }
  if (typeof entry.target.need !== "string") return fail("message-react.target", "message.react bound 'target.need' must be a string");
  if (!validSqlNeedKey(entry.target.need)) return fail("message-react.target", "message.react bound 'target.need' must be a sql need key");
  return { bound: { emoji, need: entry.target.need } };
}

// Mirrors `parse_message_react_bounds` (`src/mcp/tools/effect_bounds.rs`):
// no emoji may occur in more than one bound across effects[].
export function parseMessageReactBounds(declaration, where = "effects[]") {
  const bounds = [];
  const entries = Array.isArray(declaration?.effects) ? declaration.effects : [];
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (!isPlainObject(entry)) continue;
    if (entry.effect !== MESSAGE_REACT_EFFECT) continue;
    const parsed = parseMessageReactBound(entry, `effects[${index}]`);
    if (parsed.error) return parsed;
    bounds.push(parsed.bound);
  }
  const seen = bounds.flatMap((bound) => bound.emoji).sort(compareUtf8);
  for (let index = 1; index < seen.length; index += 1) {
    if (seen[index] === seen[index - 1]) {
      return { error: finding("message-react.emoji", `${RS} parse_message_react_bounds`, `message.react emoji '${seen[index]}' occurs in more than one bound [invalid_effect]`, { where }) };
    }
  }
  return { bounds };
}

// Mirrors `parse_title_set_bound` (`src/mcp/tools/effect_bounds.rs`).
// Object form only; the bare string is refused below. Unknown fields fail
// closed. Any syntactically valid need key parses here; undeclared needs
// refuse below.
export function parseTitleSetBound(entry, where = "effects[]") {
  const fail = (rule, message) => ({ error: finding(rule, `${RS} parse_title_set_bound`, `${message} [invalid_effect]`, { where }) });
  if (!isPlainObject(entry)) return fail("title-set.shape", "declaration 'effects' entries must be strings or title-set objects");
  const keys = Object.keys(entry);
  if (keys.length !== 2 || !hasOwn(entry, "effect") || !hasOwn(entry, "target")) {
    return fail("title-set.shape", "title-set bound must hold exactly 'effect' and 'target'");
  }
  if (typeof entry.effect !== "string") return fail("title-set.effect", "title-set bound 'effect' must be a string");
  if (entry.effect !== TITLE_SET_EFFECT) return fail("title-set.effect", `unsupported object effect '${entry.effect}'`);
  if (!isPlainObject(entry.target)) return fail("title-set.target", "title-set bound 'target' must be an object");
  if (Object.keys(entry.target).length !== 1 || !hasOwn(entry.target, "need")) {
    return fail("title-set.target", "title-set bound 'target' must hold exactly 'need'");
  }
  if (typeof entry.target.need !== "string") return fail("title-set.target", "title-set bound 'target.need' must be a string");
  if (!validSqlNeedKey(entry.target.need)) return fail("title-set.target", "title-set bound 'target.need' must be a sql need key");
  return { bound: { need: entry.target.need } };
}

// Mirrors `parse_title_set_bounds` (`src/mcp/tools/effect_bounds.rs`): at
// most one bound — with no discriminator two bounds could never be told
// apart.
export function parseTitleSetBounds(declaration, where = "effects[]") {
  const bounds = [];
  const entries = Array.isArray(declaration?.effects) ? declaration.effects : [];
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (!isPlainObject(entry)) continue;
    if (entry.effect !== TITLE_SET_EFFECT) continue;
    const parsed = parseTitleSetBound(entry, `effects[${index}]`);
    if (parsed.error) return parsed;
    bounds.push(parsed.bound);
  }
  if (bounds.length > 1) {
    return { error: finding("title-set.shape", `${RS} parse_title_set_bounds`, `title-set bound occurs more than once; a declaration holds at most one [invalid_effect]`, { where }) };
  }
  return { bounds };
}
// stops at the first refusal, this collects one finding per bad entry so an
// author sees them all at once; the first finding is the one Rust reports.
// Mirrors `require_declaration` (alpha_tabs.rs:1783). Unlike Rust, which
// stops at the first refusal, this collects one finding per bad entry so an
// author sees them all at once; the first finding is the one Rust reports.
export function parseDeclaration(declaration) {
  const findings = [];
  const out = { needs: [], effects: [], facetSets: [], commentCreates: [], messageReacts: [], titleSets: [], bodySets: [], sqlNeeds: [], findings };
  const fail = (rule, line, message, where) => findings.push(finding(rule, `${RS}:${line} require_declaration`, message, where ? { where } : {}));
  if (!isPlainObject(declaration)) {
    fail("declaration.shape", 1786, "declaration must be an object");
    return out;
  }
  if (Object.keys(declaration).length !== 2 || !hasOwn(declaration, "needs") || !hasOwn(declaration, "effects")) {
    fail("declaration.shape", 1789, "declaration must hold exactly 'needs' and 'effects'");
    return out;
  }
  if (!Array.isArray(declaration.effects)) {
    fail("declaration.effects", 1794, "declaration 'effects' must be an array");
  } else {
    if (declaration.effects.length > D.max_entries) fail("declaration.effects", 1797, `declaration 'effects' holds at most ${D.max_entries} entries`);
    declaration.effects.forEach((entry, index) => {
      const where = `effects[${index}]`;
      if (typeof entry === "string") {
        if (entry === BODY_SET_EFFECT) {
          findings.push(bodySetFailure("body-set.shape", "bare 'records.body-set.v1' has no cap or need; declare the object bound", where).error);
          return;
        }
        if (entry === FACET_SET_EFFECT) {
          return fail("declaration.effects", 0, "bare 'records.facet-set.v1' consents to no key, values or need; declare the object bound instead", where);
        }
        if (entry === COMMENT_CREATE_EFFECT) {
          return fail("declaration.effects", 0, "bare 'comment.create.v1' consents to no positions, cap or need; declare the object bound instead", where);
        }
        if (entry === MESSAGE_REACT_EFFECT) {
          return fail("declaration.effects", 0, "bare 'message.react.v1' consents to no emoji or need; declare the object bound instead", where);
        }
        if (entry === TITLE_SET_EFFECT) {
          return fail("declaration.effects", 0, "bare 'records.title-set.v1' consents to no need; declare the object bound instead", where);
        }
        if (entry.trim() === "" || utf8Length(entry) > D.name_max_bytes) {
          return fail("declaration.effects", 1809, `declaration 'effects' entries must be 1..${D.name_max_bytes} characters`, where);
        }
        out.effects.push(entry);
        return;
      }
      if (isPlainObject(entry)) {
        if (entry.effect === BODY_SET_EFFECT) {
          const parsed = parseBodySetBound(entry, where);
          if (parsed.error) findings.push(parsed.error);
          else out.effects.push(BODY_SET_EFFECT);
          return;
        }
        if (entry.effect === COMMENT_CREATE_EFFECT) {
          const parsed = parseCommentCreateBound(entry, where);
          if (parsed.error) {
            findings.push(parsed.error);
            return;
          }
          out.effects.push(COMMENT_CREATE_EFFECT);
          out.commentCreates.push(parsed.bound);
          return;
        }
        if (entry.effect === MESSAGE_REACT_EFFECT) {
          const parsed = parseMessageReactBound(entry, where);
          if (parsed.error) {
            findings.push(parsed.error);
            return;
          }
          out.effects.push(MESSAGE_REACT_EFFECT);
          out.messageReacts.push(parsed.bound);
          return;
        }
        if (entry.effect === TITLE_SET_EFFECT) {
          const parsed = parseTitleSetBound(entry, where);
          if (parsed.error) {
            findings.push(parsed.error);
            return;
          }
          out.effects.push(TITLE_SET_EFFECT);
          out.titleSets.push(parsed.bound);
          return;
        }
        const parsed = parseFacetSetBound(entry, where);
        if (parsed.error) {
          findings.push(parsed.error);
          return;
        }
        out.effects.push(FACET_SET_EFFECT);
        out.facetSets.push(parsed.bound);
        return;
      }
      fail("declaration.effects", 1804, "declaration 'effects' entries must be strings or facet-set objects", where);
    });
    const boundKeys = out.facetSets.map((bound) => bound.key).sort(compareUtf8);
    for (let index = 1; index < boundKeys.length; index += 1) {
      if (boundKeys[index] === boundKeys[index - 1]) {
        fail("declaration.effects", 0, `facet-set bound for key '${boundKeys[index]}' is duplicated`);
      }
    }
    const seenPositions = out.commentCreates.flatMap((bound) => bound.positions).sort(compareUtf8);
    for (let index = 1; index < seenPositions.length; index += 1) {
      if (seenPositions[index] === seenPositions[index - 1]) {
        fail("declaration.effects", 0, `comment.create position '${seenPositions[index]}' occurs in more than one bound`);
      }
    }
    const seenEmoji = out.messageReacts.flatMap((bound) => bound.emoji).sort(compareUtf8);
    for (let index = 1; index < seenEmoji.length; index += 1) {
      if (seenEmoji[index] === seenEmoji[index - 1]) {
        fail("declaration.effects", 0, `message.react emoji '${seenEmoji[index]}' occurs in more than one bound`);
      }
    }
    if (out.titleSets.length > 1) {
      fail("declaration.effects", 0, `title-set bound occurs more than once; a declaration holds at most one`);
    }

  }
  if (!Array.isArray(declaration.needs)) {
    fail("declaration.needs", 1816, "declaration 'needs' must be an array");
    return out;
  }
  if (declaration.needs.length > D.max_entries) fail("declaration.needs", 1819, `declaration 'needs' holds at most ${D.max_entries} entries`);
  declaration.needs.forEach((entry, index) => {
    if (typeof entry === "string") {
      if (entry.trim() === "" || utf8Length(entry) > D.name_max_bytes) {
        return fail("declaration.needs", 1828, `declaration 'needs' entries must be 1..${D.name_max_bytes} characters`, `needs[${index}]`);
      }
      out.needs.push(entry);
    } else if (isPlainObject(entry) && entry.need === BODY_READ_NEED) {
      const parsed = classifyDeclarationNeed(entry, `needs[${index}]`);
      if (parsed.error) findings.push(parsed.error);
      else {
        (out.bodyReadNeeds ??= []).push(parsed.descriptor);
        fail("body-read.admission-unavailable", 0, "body read descriptor admission is unavailable [body_admission_unavailable]");
      }
    } else if (isPlainObject(entry)) {
      const parsed = parseSqlNeedEntry(entry, `needs[${index}]`);
      if (parsed.error) findings.push(parsed.error);
      else out.sqlNeeds.push(parsed.need);
    } else {
      fail("declaration.needs", 1837, "declaration 'needs' entries must be strings or sql.snapshot.v1 objects", `needs[${index}]`);
    }
  });
  const bodyRead = bodyReadDescriptorIn(declaration);
  if (bodyRead.error) findings.push(bodyRead.error);
  if (out.sqlNeeds.length > D.sql_snapshot_max_needs) {
    fail("declaration.sql-need-count", 1843, `declaration holds at most ${D.sql_snapshot_max_needs} sql.snapshot.v1 needs (has ${out.sqlNeeds.length})`);
  }
  const keys = out.sqlNeeds.map((need) => need.key).sort(compareUtf8);
  for (let index = 1; index < keys.length; index += 1) {
    if (keys[index] === keys[index - 1]) fail("declaration.sql-need-key", 1851, `sql need key '${keys[index]}' is duplicated`);
  }
  for (const key of keys) {
    if (out.needs.includes(key)) fail("declaration.sql-need-key", 1862, `sql need key '${key}' duplicates a string need`);
  }
  // A bound may only target a declared static need, mirroring the install
  // cross-check: the membership gate re-runs that need's SQL.
  for (const bound of out.facetSets) {
    if (!out.sqlNeeds.some((need) => need.key === bound.need)) {
      fail("declaration.effects", 0, `facet-set bound targets undeclared need '${bound.need}'`);
    }
  }
  for (const bound of out.commentCreates) {
    if (!out.sqlNeeds.some((need) => need.key === bound.need)) {
      fail("declaration.effects", 0, `comment.create bound targets undeclared need '${bound.need}'`);
    }
  }
  for (const bound of out.messageReacts) {
    if (!out.sqlNeeds.some((need) => need.key === bound.need)) {
      fail("declaration.effects", 0, `message.react bound targets undeclared need '${bound.need}'`);
    }
  }
  for (const bound of out.titleSets) {
    if (!out.sqlNeeds.some((need) => need.key === bound.need)) {
      fail("declaration.effects", 0, `title-set bound targets undeclared need '${bound.need}'`);
    }
  }
  if (Array.isArray(declaration.effects) && declaration.effects.some((entry) => entry === BODY_SET_EFFECT || entry?.effect === BODY_SET_EFFECT)) {
    const parsed = parseBodySetBounds(declaration);
    if (parsed.error) findings.push(parsed.error);
    else out.bodySets = parsed.bounds;
  }
  return out;
}

// Snapshot vs on-request, as the shell splits them
// (experiments/demo-shell/public/lib/pendingTabs.js sqlParamNeedsOf):
// an SQL need with a non-empty `params` array is read on request; one
// without is delivered in `input.sql[key]`.
export function splitNeeds(parsed) {
  return {
    snapshot: parsed.sqlNeeds.filter((need) => need.params.length === 0),
    onRequestSql: parsed.sqlNeeds.filter((need) => need.params.length > 0),
    onRequestHost: parsed.needs.filter((need) => LIMITS.reads.on_request_host_needs.includes(need)),
  };
}
