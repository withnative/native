// Browser-safe candidate client: transport, source authority and mount lifetime
// belong to the injected caller. No imports from the Node-based kit index.
const CONTRACT = "records.body.read.v1";
const PAGE_BYTES = 32768;
const RESPONSE_BYTES = 262144;
const BODY_BYTES = 16777216;
const TOKEN_BYTES = 1024;
const EMPTY_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const encoder = new TextEncoder();
const ownFailures = new WeakSet();

/** Sanitized failures only; no transport/server diagnostic is retained. */
export class BodyReadError extends Error {
  constructor(code, reason) {
    super(`Body read failed: ${code} (${reason})`);
    this.name = "BodyReadError";
    this.code = code;
    this.reason = reason;
  }
}

const fail = (code, reason) => {
  const error = new BodyReadError(code, reason);
  ownFailures.add(error);
  throw error;
};
const protocol = (reason) => fail("protocol_error", reason);
const safeInteger = (value) => Number.isSafeInteger(value) && value >= 0;
const ascii = (value, max) => typeof value === "string" && value.length > 0
  && value.length <= max && /^[\x00-\x7f]+$/.test(value);
const keys = (value, required, optional = []) => {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Reflect.ownKeys(descriptors);
  return names.length >= required.length && names.length <= required.length + optional.length
    && required.every((key) => Object.hasOwn(descriptors, key))
    && names.every((key) => typeof key === "string" && [...required, ...optional].includes(key)
      && descriptors[key].enumerable && Object.hasOwn(descriptors[key], "value"));
};

function validUtf16(text) {
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

const extraLimits = ["max_body_bytes", "max_source_bytes", "max_provenance_payload_bytes",
  "max_provenance_events", "request_timeout_ms"];
function checkLimits(limits) {
  if (!keys(limits, ["max_page_bytes", "max_response_bytes"], extraLimits)
    || !safeInteger(limits.max_page_bytes) || limits.max_page_bytes < 4 || limits.max_page_bytes > PAGE_BYTES
    || !safeInteger(limits.max_response_bytes) || limits.max_response_bytes < 1
    || limits.max_response_bytes > RESPONSE_BYTES
    || extraLimits.some((key) => Object.hasOwn(limits, key) && (!safeInteger(limits[key]) || limits[key] < 1))) {
    protocol("invalid_limits");
  }
  // Fixed member order for comparison; parsed object key order is irrelevant.
  return Object.fromEntries(["max_page_bytes", "max_response_bytes", ...extraLimits]
    .filter((key) => Object.hasOwn(limits, key)).map((key) => [key, limits[key]]));
}

// Exact Failure::code_reason pairs from the private engine. Shared canonical
// refusals live in fixtures/body-read-v1.json for client and future Rust tests.
// Unknown pairs remain static remote_refusal; no diagnostic text is retained.
const remoteReasons = {
  invalid_params: ["request"],
  invalid_cursor: ["cursor"],
  cursor_expired: ["cursor"],
  resource_exhausted: ["result_budget", "process_busy", "source_work_limit",
    "provenance_work_limit", "vm_work_limit"],
  unsupported_profile: ["primary_sqlite_required"],
  unsupported_capability: ["portability_policy"],
  source_integrity: ["source"],
  undeclared_read: ["descriptor"],
  adoption_required: ["source"],
  record_unavailable: ["target"],
  access_lost: ["target"],
  scope_denied: ["scope"],
  revision_changed: ["incarnation"],
  too_large: ["body_read_work_limit"],
  timeout: ["request"],
  engine: ["integrity_or_execution"],
};

function checkRefusal(response) {
  if (!keys(response, ["contract", "error"]) || response.contract !== CONTRACT
    || !keys(response.error, ["code", "reason"])) protocol("invalid_error");
  const { code, reason } = response.error;
  if (typeof code !== "string" || typeof reason !== "string") protocol("invalid_error");
  if (!Object.hasOwn(remoteReasons, code) || !remoteReasons[code].includes(reason)) {
    fail("remote_refusal", "unknown_refusal");
  }
  fail(code, reason);
}

const pageFields = ["contract", "record_id", "revision", "body_digest", "body_present", "encoding",
  "start_byte", "end_byte", "total_bytes", "text", "complete", "next_cursor", "limits"];
function checkPage(response, recordId, pageBytes) {
  if (response === null || response === undefined) fail("incomplete", "missing_completion");
  // Data-only own fields: JSON serialization must not execute a toJSON/getter.
  if (response && Object.hasOwn(response, "error")) checkRefusal(response);
  if (!keys(response, pageFields)) protocol("invalid_page");
  const page = Object.fromEntries(pageFields.map((key) => [key, response[key]]));
  if (page.contract !== CONTRACT || page.record_id !== recordId || page.encoding !== "utf-8"
    || !ascii(page.revision, TOKEN_BYTES) || typeof page.body_digest !== "string"
    || !/^[0-9a-f]{64}$/.test(page.body_digest) || typeof page.body_present !== "boolean"
    || typeof page.complete !== "boolean"
    || ![page.start_byte, page.end_byte, page.total_bytes].every(safeInteger)
    || page.start_byte > page.end_byte || page.end_byte > page.total_bytes
    || typeof page.text !== "string" || page.text.length > PAGE_BYTES || !validUtf16(page.text)) {
    protocol("invalid_page");
  }
  page.limits = checkLimits(page.limits);
  const bytes = encoder.encode(page.text);
  if (bytes.length !== page.end_byte - page.start_byte
    || bytes.length > pageBytes || bytes.length > page.limits.max_page_bytes) protocol("invalid_offsets");
  if (page.complete ? page.end_byte !== page.total_bytes || page.next_cursor !== null
    : page.end_byte >= page.total_bytes || !ascii(page.next_cursor, TOKEN_BYTES) || bytes.length === 0) {
    protocol("invalid_completion");
  }
  if (!page.body_present && (!page.complete || page.total_bytes !== 0 || page.text !== "")) {
    protocol("invalid_presence");
  }
  if (page.total_bytes === 0 && page.body_digest !== EMPTY_DIGEST) protocol("invalid_presence");
  // Bound all strings/fields before serializing the complete canonical object.
  if (encoder.encode(JSON.stringify(page)).length > Math.min(RESPONSE_BYTES, page.limits.max_response_bytes)) {
    protocol("response_budget");
  }
  if (Object.hasOwn(page.limits, "max_body_bytes") && page.total_bytes > page.limits.max_body_bytes) {
    protocol("published_body_limit");
  }
  return { page, bytes };
}

function checkAbort(signal) {
  if (signal?.aborted) fail("cancelled", "aborted");
}

async function fetchPage(readPage, request, signal) {
  checkAbort(signal);
  // Race even when the injected transport ignores AbortSignal. Observe late
  // settlement, but never validate/use it or resume this assembly afterward.
  let listener;
  const aborted = new Promise((_, reject) => {
    listener = () => reject(new BodyReadError("cancelled", "aborted"));
    signal?.addEventListener("abort", listener, { once: true });
  });
  try {
    const result = Promise.resolve().then(() => {
      checkAbort(signal);
      return readPage(request, { signal });
    });
    const page = await Promise.race([result, aborted]);
    checkAbort(signal);
    return page;
  } catch {
    checkAbort(signal);
    // Never inspect injected exceptions. Native signal cancellation takes
    // precedence; every other callback failure has one static transport error.
    fail("transport_error", "read_page_failed");
  } finally {
    signal?.removeEventListener("abort", listener);
  }
}

class ByteChunks {
  constructor(total) { this.total = total; this.stored = 0; this.chunks = []; this.used = 0; }
  append(bytes) {
    let position = 0;
    while (position < bytes.length) {
      let last = this.chunks.at(-1);
      if (!last || this.used === last.length) {
        last = new Uint8Array(Math.min(65536, this.total - this.stored));
        this.chunks.push(last);
        this.used = 0;
      }
      const count = Math.min(bytes.length - position, last.length - this.used);
      last.set(bytes.subarray(position, position + count), this.used);
      this.used += count;
      this.stored += count;
      position += count;
    }
  }
  text() {
    // Streaming decoding preserves a scalar split across internal byte chunks.
    const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
    return this.chunks.map((bytes, index) => decoder.decode(bytes,
      { stream: index < this.chunks.length - 1 })).join("");
  }
  clear() { this.chunks.length = 0; }
}

/**
 * Fixture/candidate API. readPage supplies canonical objects, not a broker
 * wrapper. maxBodyBytes is a UTF-8 buffering cap (at most 16MiB), not storage
 * policy or an exact JavaScript heap bound. No partial text/guard is published.
 */
export async function readBody(options = {}) {
  if (options === null || typeof options !== "object") fail("client_error", "invalid_options");
  const { recordId, readPage, pageBytes = PAGE_BYTES, maxBodyBytes = BODY_BYTES, signal, onProgress } = options;
  if (typeof recordId !== "string" || !/^[\x21-\x7e]{1,128}$/.test(recordId)
    || typeof readPage !== "function" || !safeInteger(pageBytes) || pageBytes < 4 || pageBytes > PAGE_BYTES
    || !safeInteger(maxBodyBytes) || maxBodyBytes > BODY_BYTES
    || (onProgress !== undefined && typeof onProgress !== "function")
    || (signal !== undefined && (typeof signal?.aborted !== "boolean"
      || typeof signal.addEventListener !== "function" || typeof signal.removeEventListener !== "function"))) {
    fail("client_error", "invalid_options");
  }
  let chunks;
  let first;
  let end = 0;
  let pages = 0;
  let cursor;
  try {
    for (;;) {
      checkAbort(signal);
      const request = { record_id: recordId, page_bytes: pageBytes };
      if (first) Object.assign(request, { revision: first.revision, cursor });
      if (encoder.encode(JSON.stringify(request)).length > 4096) fail("client_error", "request_budget");
      const response = await fetchPage(readPage, request, signal);
      checkAbort(signal);
      let checked;
      try { checked = checkPage(response, recordId, pageBytes); }
      catch (error) {
        if (ownFailures.has(error)) throw error;
        protocol("invalid_page");
      }
      const { page, bytes } = checked;
      if (page.start_byte !== end) protocol("noncontiguous_page");
      if (first && (page.revision !== first.revision || page.body_digest !== first.body_digest
        || page.body_present !== first.body_present || page.total_bytes !== first.total_bytes
        || JSON.stringify(page.limits) !== JSON.stringify(first.limits))) protocol("assembly_changed");
      if (page.total_bytes > maxBodyBytes) fail("client_limit", "body_memory_limit");
      if (!first) {
        // Retain only fixed assembly metadata, never the first page's text.
        first = { revision: page.revision, body_digest: page.body_digest,
          body_present: page.body_present, total_bytes: page.total_bytes, limits: page.limits };
        chunks = new ByteChunks(page.total_bytes);
      }
      if (page.end_byte === end && !(pages === 0 && page.complete && page.total_bytes === 0)) {
        protocol("nonprogress");
      }
      chunks.append(bytes);
      end = page.end_byte;
      pages += 1;
      if (onProgress) {
        try {
          const pending = onProgress(Object.freeze({ receivedBytes: end, totalBytes: first.total_bytes, pages }));
          if (pending && typeof pending.then === "function") {
            Promise.resolve(pending).catch(() => {});
            fail("client_error", "progress_failed");
          }
        } catch { fail("client_error", "progress_failed"); }
      }
      checkAbort(signal);
      if (page.complete) {
        const body = first.body_present ? chunks.text() : null;
        checkAbort(signal);
        return { record_id: recordId, body, body_present: first.body_present,
          body_digest: first.body_digest, revision: first.revision, total_bytes: first.total_bytes };
      }
      cursor = page.next_cursor;
    }
  } finally {
    chunks?.clear();
  }
}
