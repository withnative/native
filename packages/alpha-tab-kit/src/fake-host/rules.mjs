// Host-side read rules, shared by the Node fake-host server and the shell
// page it serves (so this module imports nothing). `limits` is the flattened
// limits.json.

/**
 * Mirrors `validateSqlNeedParams` (experiments/demo-shell/public/lib/
 * pendingTabs.js:782), which mirrors `bind_sql_params`
 * (src/mcp/tools/alpha_tabs.rs:439). Null when the values bind.
 */
export function sqlParamRefusal(need, params, limits) {
  const schema = need.params;
  if (!params || typeof params !== "object" || Array.isArray(params)) return "invalid_sql_param";
  if (Object.keys(params).length > limits.declaration.max_params) return "invalid_sql_param";
  for (const name of Object.keys(params)) {
    if (!schema.some((param) => param.name === name)) return "unknown_sql_param";
  }
  for (const param of schema) {
    const value = params[param.name];
    if (value === undefined) {
      if (param.required === false) continue;
      return "missing_sql_param";
    }
    if (param.type === "text") {
      if (typeof value !== "string" || [...value].length > param.max_len) return "invalid_sql_param";
    } else if (typeof value !== "number" || !Number.isSafeInteger(value)) {
      return "invalid_sql_param";
    }
  }
  return null;
}

/**
 * Mirrors `declaredReadRefusalFor` (pendingTabs.js:949): the shell refuses
 * before any network call. `plan` is `{ onRequestHost: string[],
 * onRequestSql: [{key, params}] }`.
 */
export function declaredReadRefusal(plan, need, params, limits) {
  if (typeof need !== "string") return "undeclared_need";
  if (plan.onRequestHost.includes(need)) {
    return (!params || typeof params !== "object" || Array.isArray(params)) ? "invalid_params" : null;
  }
  const sqlNeed = plan.onRequestSql.find((candidate) => candidate.key === need);
  if (!sqlNeed) return "undeclared_need";
  return sqlParamRefusal(sqlNeed, params, limits);
}

/**
 * Mirrors `SceneCursor::decode` (src/mcp/tools/canvas.rs): a cursor is only
 * what a previous page handed out, hex over the JSON pair `[z, id]`.
 */
export function sceneCursorValid(cursor, limits) {
  if (typeof cursor !== "string" || cursor.length > limits.reads.canvas_scene_cursor_max_chars) return false;
  if (cursor.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(cursor)) return false;
  const bytes = new Uint8Array(cursor.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = parseInt(cursor.slice(index * 2, index * 2 + 2), 16);
  let pair;
  try {
    pair = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return false;
  }
  const utf8 = (text) => new TextEncoder().encode(text).length;
  return Array.isArray(pair) && pair.length === 2
    && pair.every((part) => typeof part === "string" && part.length > 0 && utf8(part) <= 128);
}

/** Hex over UTF-8 JSON, as the engine's cursors are encoded; null if not. */
function hexJson(cursor, maxChars) {
  if (typeof cursor !== "string" || cursor.length > maxChars) return null;
  if (cursor.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(cursor)) return null;
  const bytes = new Uint8Array(cursor.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = parseInt(cursor.slice(index * 2, index * 2 + 2), 16);
  try {
    return { value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) };
  } catch {
    return null;
  }
}

/**
 * Mirrors `RecordChangesCursor::well_formed` (src/mcp/tools/alpha_tabs.rs):
 * a cursor is sealed by the engine for one install and record, so a host
 * can only check its shape: hex longer than its 24-byte nonce and 16-byte
 * tag together. Whether it
 * opens is the engine's to say, after its gates.
 */
export function recordChangesCursorWellFormed(cursor, limits) {
  return typeof cursor === "string"
    && cursor.length > 80
    && cursor.length <= limits.reads.record_changes_cursor_max_chars
    && cursor.length % 2 === 0
    && /^[0-9a-fA-F]*$/.test(cursor);
}

const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Mirrors `parse_declared_read` (src/mcp/tools/alpha_tabs.rs:504), the
 * backend bound on the host needs. Returns a refusal code or null.
 */
export function hostNeedRefusal(need, params, limits) {
  const p = params ?? {};
  const only = (allowed) => Object.keys(p).every((key) => allowed.includes(key));
  if (need === "records.search.v1") {
    if (!only(["query", "limit"])) return "invalid_params";
    const query = typeof p.query === "string" ? p.query.trim() : null;
    if (!query || [...query].length > limits.reads.search_query_max_chars) return "invalid_params";
    const limit = p.limit === undefined ? limits.reads.search_limit_max : p.limit;
    if (!Number.isInteger(limit) || limit < 1 || limit > limits.reads.search_limit_max) return "invalid_params";
    return null;
  }
  if (need === "records.resolve_reference.v1") {
    if (!only(["reference"])) return "invalid_params";
    const reference = typeof p.reference === "string" ? p.reference.trim() : null;
    if (!reference || [...reference].length > limits.reads.reference_max_chars) return "invalid_params";
    return null;
  }
  if (need === "canvas.scene.v1") {
    if (!only(["canvas_id", "limit", "cursor"])) return "invalid_params";
    const canvasId = typeof p.canvas_id === "string" ? p.canvas_id.trim() : null;
    if (!canvasId || [...canvasId].length > limits.reads.canvas_id_max_chars) return "invalid_params";
    const limit = p.limit === undefined ? limits.reads.canvas_scene_limit_max : p.limit;
    if (!Number.isInteger(limit) || limit < 1 || limit > limits.reads.canvas_scene_limit_max) return "invalid_params";
    if (p.cursor !== undefined && p.cursor !== null && !sceneCursorValid(p.cursor, limits)) return "invalid_params";
    return null;
  }
  if (need === "records.changes.v1") {
    if (!only(["record_id", "limit", "cursor"])) return "invalid_params";
    const recordId = typeof p.record_id === "string" ? p.record_id.trim() : null;
    if (!recordId || [...recordId].length > limits.reads.record_id_max_chars) return "invalid_params";
    const limit = p.limit === undefined ? limits.reads.record_changes_limit_max : p.limit;
    if (!Number.isInteger(limit) || limit < 1 || limit > limits.reads.record_changes_limit_max) return "invalid_params";
    if (p.cursor !== undefined && p.cursor !== null && !recordChangesCursorWellFormed(p.cursor, limits)) return "invalid_params";
    return null;
  }
  if (need === "artifact.render.v1") {
    // A full record id in canonical lowercase hyphenated form, untrimmed:
    // the backend resolves no short reference.
    if (!only(["artifact_id"])) return "invalid_params";
    if (typeof p.artifact_id !== "string" || !CANONICAL_UUID.test(p.artifact_id)) return "invalid_params";
    return null;
  }
  return "unknown_need";
}

/**
 * Shape rows the way `execute_sql_need` (alpha_tabs.rs:3171) delivers one
 * need: `query_sql` caps at MAX_ROWS first, then the snapshot cap truncates
 * to SQL_SNAPSHOT_ROW_CAP with `row_count` reporting the returned count.
 * `row_count_complete` is false exactly when that first cap truncated, so
 * `row_count` is a floor rather than a total. Fields and their order are
 * `limits.reads.sql_result_fields` (SQL_NEED_RESULT_FIELDS).
 */
export function shapeSqlResult(label, rows, limits) {
  const list = Array.isArray(rows) ? rows : [];
  const columns = [];
  for (const row of list) for (const key of Object.keys(row ?? {})) if (!columns.includes(key)) columns.push(key);
  const queryTruncated = list.length > limits.sql.max_rows;
  const full = queryTruncated ? list.slice(0, limits.sql.max_rows) : list;
  const cap = limits.reads.sql_snapshot_row_cap;
  const truncated = queryTruncated || full.length > cap;
  return {
    label,
    columns,
    rows: full.slice(0, cap),
    row_count: full.length,
    row_count_complete: !queryTruncated,
    truncated,
    truncation_hint: truncated ? limits.reads.truncation_hint : null,
    now_ms_ms: null,
    time_dependent: false,
    assumed_order: null,
  };
}
