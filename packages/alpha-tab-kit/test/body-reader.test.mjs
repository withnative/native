import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { BodyReadError, readBody } from "@withnative/alpha-tab-kit/body-reader";

const contract = "records.body.read.v1";
const id = "document-a";
const hash = (text) => createHash("sha256").update(text ?? "").digest("hex");
const failure = (code, reason) => ({ contract, error: { code, reason } });
const refusalGoldens = JSON.parse(await readFile(new URL("../fixtures/body-read-v1.json", import.meta.url), "utf8"));
const options = (readPage, rest = {}) => ({ recordId: id, readPage, ...rest });
const rejects = (promise, code, reason) => assert.rejects(promise, (error) => {
  assert.ok(error instanceof BodyReadError);
  assert.equal(error.code, code);
  if (reason) assert.equal(error.reason, reason);
  return true;
});

function fixture(text, { size = 32768, revision = "opaque-r-A", limits = {}, alter } = {}) {
  const body = Buffer.from(text ?? "");
  const guard = hash(text);
  let calls = 0;
  let offset = 0;
  const requests = [];
  const readPage = async (request, transport) => {
    requests.push({ ...request });
    assert.deepEqual(Object.keys(request).sort(), calls === 0 ? ["page_bytes", "record_id"]
      : ["cursor", "page_bytes", "record_id", "revision"]);
    assert.equal(request.record_id, id);
    if (calls) {
      assert.equal(request.revision, revision);
      assert.equal(request.cursor, `opaque-c-${offset}`);
    }
    let end = Math.min(offset + Math.min(request.page_bytes, size), body.length);
    while (end < body.length && (body[end] & 0xc0) === 0x80) end -= 1;
    const page = {
      contract, record_id: id, revision, body_digest: guard, body_present: text !== null,
      encoding: "utf-8", start_byte: offset, end_byte: end, total_bytes: body.length,
      text: body.subarray(offset, end).toString("utf8"), complete: end === body.length,
      next_cursor: end === body.length ? null : `opaque-c-${end}`,
      limits: { max_page_bytes: 32768, max_response_bytes: 262144, ...limits },
    };
    offset = end;
    const index = calls++;
    return alter ? alter(page, index, transport) : page;
  };
  return { readPage, requests, get calls() { return calls; } };
}

test("browser subpath is standalone, without Node/index dependencies", async () => {
  const source = await readFile(new URL("../src/body-reader.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /^\s*(?:import|export .* from)\b/m);
  assert.doesNotMatch(source, /node:|Buffer\.|process\.|require\(/);
});

test("large Unicode/control/whitespace body reconstructs exactly with engine guard and counts only", async () => {
  const text = "\ufeff\r\n  " + "🙂e\u0301\t\u0000\n字 \r\n".repeat(20000) + " trailing \t\n";
  assert.ok(Buffer.byteLength(text) > 262144 && [...text].length > 120000);
  const f = fixture(text, { limits: { max_body_bytes: 16777216, max_source_bytes: 16777216,
    max_provenance_payload_bytes: 33554432, max_provenance_events: 128, request_timeout_ms: 5000 } });
  const progress = [];
  const result = await readBody(options(f.readPage, { onProgress: (counts) => {
    assert.deepEqual(Object.keys(counts).sort(), ["pages", "receivedBytes", "totalBytes"]);
    assert.ok(Object.isFrozen(counts));
    progress.push(counts);
  } }));
  assert.deepEqual(result, { record_id: id, body: text, body_present: true,
    body_digest: hash(text), revision: "opaque-r-A", total_bytes: Buffer.byteLength(text) });
  assert.equal(progress.length, f.calls);
  assert.ok(progress.every((p, i) => i === 0 || p.receivedBytes > progress[i - 1].receivedBytes));
  assert.equal(progress.at(-1).receivedBytes, result.total_bytes);
});

test("minimum pages and internal 64KiB byte chunks preserve every scalar, including BOM", async () => {
  const text = "ab🙂".repeat(11500) + "\ufeffe\u0301\r\n\u0000";
  for (const pageBytes of [4, 5, 7, 32768]) {
    const f = fixture(text);
    assert.equal((await readBody(options(f.readPage, { pageBytes }))).body, text);
  }
});

test("null and empty remain distinct with exact empty engine guard", async () => {
  for (const body of [null, ""]) {
    const f = fixture(body);
    const result = await readBody(options(f.readPage, { maxBodyBytes: 0 }));
    assert.equal(result.body, body);
    assert.equal(result.body_present, body !== null);
    assert.equal(result.total_bytes, 0);
    assert.equal(result.body_digest, hash(""));
    assert.equal(f.calls, 1);
  }
  const f = fixture(null, { alter: (p) => ({ ...p, body_digest: "a".repeat(64) }) });
  await rejects(readBody(options(f.readPage)), "protocol_error", "invalid_presence");
});

test("engine digest is never replaced by a client-created CAS", async () => {
  const opaqueGuard = "b".repeat(64);
  const f = fixture("abcdef", { alter: (p) => ({ ...p, body_digest: opaqueGuard }) });
  const result = await readBody(options(f.readPage));
  assert.equal(result.body_digest, opaqueGuard);
  assert.notEqual(result.body_digest, hash(result.body));
});

test("wrong contract/record/encoding, raw broker wrappers and unsafe shape refuse", async () => {
  for (const alter of [
    (p) => ({ ...p, contract: "sql.snapshot.v1" }), (p) => ({ ...p, record_id: "other" }),
    (p) => ({ ...p, encoding: "utf-16" }), (p) => ({ result: p }),
    (p) => ({ ...p, extra: true }), (p) => ({ ...p, revision: "é" }),
    (p) => ({ ...p, revision: "x".repeat(1025) }), (p) => ({ ...p, body_digest: "A".repeat(64) }),
    (p) => ({ ...p, body_present: 1 }), (p) => ({ ...p, text: "\ud800" }),
    (p) => ({ ...p, text: "\udc00" }), (p) => ({ ...p, start_byte: -1 }),
    (p) => ({ ...p, total_bytes: Number.MAX_SAFE_INTEGER + 1 }),
    (p) => ({ ...p, end_byte: 1.5 }), (p) => ({ ...p, complete: "yes" }),
    (p) => ({ ...p, get text() { throw new Error("must not invoke getter"); } }),
  ]) {
    const f = fixture("x", { alter });
    await rejects(readBody(options(f.readPage)), "protocol_error");
  }
});

test("fixed revision/guard/presence/total/limits prevent mixed incarnations and A-B-A", async () => {
  for (const patch of [{ revision: "opaque-r-B" }, { body_digest: "c".repeat(64) },
    { body_present: false }, { total_bytes: 11 }, { limits: { max_page_bytes: 16, max_response_bytes: 262144 } }]) {
    const f = fixture("abcdefghij", { alter: (p, i) => i === 1 ? { ...p, ...patch } : p });
    await rejects(readBody(options(f.readPage, { pageBytes: 4 })), "protocol_error");
    assert.equal(f.calls, 2); // Never fetch the third A page after B.
  }
});

test("first offset, gaps, overlap, duplicate pages and no progress refuse", async () => {
  for (const alter of [
    (p) => ({ ...p, start_byte: 1, end_byte: 5 }),
    (p, i) => i === 1 ? { ...p, start_byte: 5, end_byte: 9 } : p,
    (p, i) => i === 1 ? { ...p, start_byte: 3, end_byte: 7 } : p,
    (p, i) => i === 1 ? { ...p, start_byte: 0, end_byte: 4 } : p,
    (p) => ({ ...p, text: "", end_byte: p.start_byte }),
  ]) {
    const f = fixture("abcdefghijkl", { alter });
    await rejects(readBody(options(f.readPage, { pageBytes: 4 })), "protocol_error");
  }
});

test("UTF8 byte offsets and requested/published page bounds are real", async () => {
  for (const alter of [
    (p) => ({ ...p, end_byte: p.end_byte - 1 }),
    (p) => ({ ...p, limits: { ...p.limits, max_page_bytes: 4 } }),
    (p) => ({ ...p, text: "x".repeat(32769), end_byte: 32769, total_bytes: 32769 }),
  ]) {
    const f = fixture("🙂🙂", { alter });
    await rejects(readBody(options(f.readPage)), "protocol_error");
  }
  const f = fixture("abcdefgh", { size: 8 });
  const ignoringRequested = async (req, opts) => f.readPage({ ...req, page_bytes: 8 }, opts);
  await rejects(readBody(options(ignoringRequested, { pageBytes: 4 })), "protocol_error", "invalid_offsets");
});

test("completion must be explicit, terminal exact and null-cursor consistent", async () => {
  for (const alter of [
    (p) => ({ ...p, complete: false }), (p) => ({ ...p, next_cursor: "more" }),
    (p) => ({ ...p, total_bytes: p.total_bytes + 1 }),
    (p) => ({ ...p, body_present: false }),
  ]) {
    const f = fixture("abcd", { alter });
    await rejects(readBody(options(f.readPage)), "protocol_error");
  }
  for (const next_cursor of [null, "", "é", "x".repeat(1025)]) {
    const f = fixture("abcdefgh", { alter: (p) => ({ ...p, next_cursor }) });
    await rejects(readBody(options(f.readPage, { pageBytes: 4 })), "protocol_error", "invalid_completion");
  }
});

test("whole-object serialized response budget includes limits and escaped text", async () => {
  let canonical;
  const f = fixture("\u0000".repeat(32768), { alter: (p) => { canonical = p; return p; } });
  assert.equal((await readBody(options(f.readPage))).body.length, 32768);
  const bytes = Buffer.byteLength(JSON.stringify(canonical));
  assert.ok(bytes > 65536 && bytes <= 262144);
  assert.equal(canonical.limits.max_response_bytes, 262144);
  // The budget number's digit count is unchanged between these two boundaries.
  for (const adjustment of [0, -1]) {
    const bounded = fixture("\u0000".repeat(32768), { limits: { max_response_bytes: bytes + adjustment } });
    if (adjustment === 0) await readBody(options(bounded.readPage));
    else await rejects(readBody(options(bounded.readPage)), "protocol_error", "response_budget");
  }
});

test("known published limits and client UTF8 buffering cap refuse without truncation", async () => {
  const client = fixture("abcdef");
  await rejects(readBody(options(client.readPage, { maxBodyBytes: 5 })), "client_limit", "body_memory_limit");
  assert.equal(client.calls, 1);
  const exact = fixture("abcdef");
  assert.equal((await readBody(options(exact.readPage, { maxBodyBytes: 6 }))).body, "abcdef");
  const published = fixture("abcdef", { limits: { max_body_bytes: 5 } });
  await rejects(readBody(options(published.readPage)), "protocol_error", "published_body_limit");
  for (const limits of [{ max_page_bytes: 3 }, { max_response_bytes: 262145 },
    { request_timeout_ms: 0 }, { max_source_bytes: "big" }, { unknown_budget: 1 }]) {
    const f = fixture("x", { limits });
    await rejects(readBody(options(f.readPage)), "protocol_error", "invalid_limits");
  }
  const overDefault = fixture("x", { alter: (p) => ({ ...p, total_bytes: 16777217, complete: false, next_cursor: "c" }) });
  await rejects(readBody(options(overDefault.readPage)), "client_limit", "body_memory_limit");
});

test("default 16MiB UTF8 boundary completes without a per-page chunk metadata explosion", async () => {
  const text = "x".repeat(16777216);
  const f = fixture(text);
  const result = await readBody(options(f.readPage));
  assert.equal(f.calls, 512);
  assert.equal(result.total_bytes, 16777216);
  assert.equal(result.body, text);
  assert.equal(result.body_digest, hash(text));
});

test("shared golden contains exactly twenty distinct canonical engine refusal pairs", () => {
  assert.equal(refusalGoldens.length, 20);
  assert.equal(new Set(refusalGoldens.map(({ error }) => `${error.code}/${error.reason}`)).size, 20);
  for (const response of refusalGoldens) {
    assert.deepEqual(Object.keys(response).sort(), ["contract", "error"]);
    assert.equal(response.contract, contract);
    assert.deepEqual(Object.keys(response.error).sort(), ["code", "reason"]);
  }
});

for (const response of refusalGoldens) {
  const { code, reason } = response.error;
  test(`engine refusal ${code}/${reason} survives first and continuation pages without retry`, async () => {
    let calls = 0;
    await rejects(readBody(options(async () => { calls++; return response; })), code, reason);
    assert.equal(calls, 1);
    let progress = 0;
    const f = fixture("abcdefgh", { alter: (p, i) => i === 1 ? response : p });
    await rejects(readBody(options(f.readPage, { pageBytes: 4, onProgress: () => { progress++; } })), code, reason);
    assert.equal(f.calls, 2);
    assert.equal(progress, 1); // Counts only; no completed body/guard escapes.
  });
}

test("unknown pairs and removed legacy vocabulary stay static", async () => {
  for (const response of [
    ...refusalGoldens.map(({ error: { code } }) => failure(code, code)),
    ...["removed", "disabled", "adoption_unverified", "missing", "archived", "wrong_record_type",
      "unauthorized", "not_renderable", "source_revision_unresolved", "digest_mismatch"]
      .map((code) => failure(code, code)),
    failure("resource_exhausted", "token_budget"),
    failure("revision_changed", "cursor"), failure("access_lost", "source"),
  ]) {
    await rejects(readBody(options(async () => response)), "remote_refusal", "unknown_refusal");
  }
  for (const response of [failure("unknown", "SQLite secret".repeat(100000)),
    failure("engine", "SQLite secret"), failure("__proto__", "prototype")]) {
    await rejects(readBody(options(async () => response)), "remote_refusal", "unknown_refusal");
  }
  await rejects(readBody(options(async () => failure("too_large", "body_read_work_limit"))), "too_large");
  await rejects(readBody(options(async () => ({ contract, error: { code: "engine", reason: 5 } }))), "protocol_error", "invalid_error");
});

test("refusal envelope requires exact contract and error fields", async () => {
  const response = failure("engine", "integrity_or_execution");
  for (const malformed of [
    { error: response.error }, { ...response, contract: "other" }, { ...response, extra: true },
    { ...response, error: { ...response.error, message: "private" } },
    { ...response, error: { code: "engine" } },
    { ...response, error: { reason: "integrity_or_execution" } },
  ]) {
    await rejects(readBody(options(async () => malformed)), "protocol_error", "invalid_error");
  }
});

test("missing completion and transport failure stay distinct from protocol and refusal", async () => {
  const f = fixture("abcdefgh", { alter: (p, i) => i === 1 ? undefined : p });
  await rejects(readBody(options(f.readPage, { pageBytes: 4 })), "incomplete", "missing_completion");
  await rejects(readBody(options(async () => { throw new Error("SQLite private text"); })), "transport_error", "read_page_failed");
  await rejects(readBody(options(async () => { throw new BodyReadError("engine", "private"); })), "transport_error");
  const hostile = new Proxy({}, { getOwnPropertyDescriptor() { throw new Error("private diagnostic"); } });
  await rejects(readBody(options(async () => hostile)), "protocol_error", "invalid_page");
});

test("opaque ASCII token escaping cannot produce an oversized continuation request", async () => {
  const f = fixture("abcdefgh", { alter: (p) => ({ ...p, revision: "\u0000".repeat(1024), next_cursor: "\u0000".repeat(1024) }) });
  await rejects(readBody(options(f.readPage, { pageBytes: 4 })), "client_error", "request_budget");
  assert.equal(f.calls, 1);
});

test("injected accessor, lookalike and proxy exceptions are never inspected", async () => {
  let inspections = 0;
  const get = () => { inspections++; throw new Error("PRIVATE_CALLBACK_DIAGNOSTIC"); };
  const branded = new BodyReadError("cancelled", "aborted");
  Object.defineProperty(branded, "code", { get });
  const lookalike = { get code() { return get(); }, get reason() { return get(); } };
  const proxy = new Proxy({}, { getPrototypeOf: get, get });
  for (const error of [branded, lookalike, proxy]) {
    await rejects(readBody(options(() => { throw error; })), "transport_error", "read_page_failed");
    await rejects(readBody(options(() => Promise.reject(error))), "transport_error", "read_page_failed");
    const controller = new AbortController();
    await rejects(readBody(options(() => { controller.abort(); throw error; },
      { signal: controller.signal })), "cancelled", "aborted");
  }
  assert.equal(inspections, 0);
});

test("late hostile rejection stays observed after native cancellation", async () => {
  const controller = new AbortController();
  let reject;
  let entered;
  let inspections = 0;
  const started = new Promise((resolve) => { entered = resolve; });
  const hostile = new Proxy({}, { getPrototypeOf() { inspections++; throw new Error("PRIVATE"); } });
  const pending = readBody(options(() => {
    entered();
    return new Promise((_, rejectPromise) => { reject = rejectPromise; });
  }, { signal: controller.signal }));
  await started;
  controller.abort();
  await rejects(pending, "cancelled", "aborted");
  reject(hostile);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(inspections, 0);
});

test("abort before invocation and during ignored inflight fetch returns no late completion", async () => {
  const before = new AbortController();
  before.abort("private reason");
  let calls = 0;
  await rejects(readBody(options(async () => { calls++; }, { signal: before.signal })), "cancelled", "aborted");
  assert.equal(calls, 0);
  const controller = new AbortController();
  let resolve;
  let entered;
  const started = new Promise((r) => { entered = r; });
  let progress = 0;
  const pending = readBody(options((request, { signal }) => {
    assert.equal(signal, controller.signal);
    calls++;
    entered();
    return new Promise((r) => { resolve = r; }); // Intentionally ignores abort.
  }, { signal: controller.signal, onProgress: () => { progress++; } }));
  await started;
  controller.abort();
  await rejects(pending, "cancelled", "aborted");
  resolve(await fixture("late completion").readPage({ record_id: id, page_bytes: 32768 }, {}));
  await new Promise((r) => setImmediate(r));
  assert.equal(progress, 0);
  assert.equal(calls, 1);
});

test("abort in progress, late rejection and callback failure cannot publish partial bases", async () => {
  const controller = new AbortController();
  const f = fixture("complete");
  await rejects(readBody(options(f.readPage, { signal: controller.signal,
    onProgress: () => controller.abort() })), "cancelled");
  const between = new AbortController();
  const partial = fixture("abcdefgh");
  await rejects(readBody(options(partial.readPage, { pageBytes: 4, signal: between.signal,
    onProgress: () => between.abort() })), "cancelled");
  assert.equal(partial.calls, 1); // Abort at first progress prevents continuation.
  let reject;
  let entered;
  const started = new Promise((r) => { entered = r; });
  const c = new AbortController();
  const promise = readBody(options(() => { entered(); return new Promise((_, r) => { reject = r; }); }, { signal: c.signal }));
  await started;
  c.abort();
  await rejects(promise, "cancelled");
  reject(new Error("late private failure"));
  await new Promise((r) => setImmediate(r)); // No unhandled late rejection.
  const failed = fixture("abcdef");
  await rejects(readBody(options(failed.readPage, { onProgress: () => { throw new Error("private"); } })), "client_error", "progress_failed");
});

test("each invocation starts fresh; invalid options never reach transport", async () => {
  const requests = [];
  for (const text of ["A", "B", "A"]) {
    const f = fixture(text);
    await readBody(options(f.readPage));
    requests.push(f.requests[0]);
  }
  assert.ok(requests.every((r) => !Object.hasOwn(r, "revision") && !Object.hasOwn(r, "cursor")));
  let calls = 0;
  for (const patch of [{ recordId: "bad id" }, { pageBytes: 3 }, { pageBytes: 32769 },
    { maxBodyBytes: -1 }, { maxBodyBytes: 16777217 }, { signal: {} }]) {
    await rejects(readBody(options(async () => { calls++; }, patch)), "client_error", "invalid_options");
  }
  await rejects(readBody(null), "client_error", "invalid_options");
  assert.equal(calls, 0);
});
