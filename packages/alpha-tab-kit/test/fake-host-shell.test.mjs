// Lifecycle tests for the fake host's parent page (src/fake-host/shell.js),
// without a browser. Each test loads a fresh copy of the real module with a
// stub window, a recording MessageChannel and fetches this file settles by
// hand, so terminal paths the real bridge cannot easily reach are driven
// directly: handshake timeout, message error, read timeout, a reload with a
// read on the wire, and a superseded document's handler. They mirror the
// shell's own lifecycle (experiments/demo-shell/check-tab-read-queue-headless.mjs):
// every accepted read is answered exactly once, on its own port, before
// that port closes, and nothing reaches a retired frame or a successor.
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { LIMITS } from "../src/limits.mjs";

const source = readFileSync(new URL("../src/fake-host/shell.js", import.meta.url), "utf8")
  .replace('from "/__kit/rules.mjs"', `from ${JSON.stringify(new URL("../src/fake-host/rules.mjs", import.meta.url).href)}`);
const dir = mkdtempSync(join(tmpdir(), "alpha-tab-kit-shell-"));
const shellFile = join(dir, "shell.mjs");
writeFileSync(shellFile, source);
process.on("exit", () => rmSync(dir, { recursive: true, force: true }));

const VERSION = LIMITS.bridge.version;
const flush = async () => { for (let i = 0; i < 4; i += 1) await new Promise((resolve) => setImmediate(resolve)); };
let loads = 0;
const open = [];

/** Load a fresh shell.js; returns a driver over its stubs. */
async function loadShell({ mode = "live", handshakeTimeoutMs = 60_000, readTimeoutMs = 60_000 } = {}) {
  const listeners = [];
  const channels = [];
  const fetches = [];
  const events = [];
  const iframe = { contentWindow: null };
  globalThis.window = {
    __ALPHA_TAB_HOST_CONFIG__: {
      mode, title: "probe",
      plan: { onRequestHost: [], onRequestSql: [{ key: "probe.body", params: [{ name: "id", type: "text", max_len: 64 }] }] },
      init: { input: { version: "native.artifact-input.v1", mode: "live", sample_preview: false, records: [], inputs: {} }, needs: ["probe.body"] },
      limits: { ...LIMITS, shell: { ...LIMITS.shell, handshake_timeout_ms: handshakeTimeoutMs } },
      readTimeoutMs,
    },
    addEventListener: (type, fn) => { if (type === "message") listeners.push(fn); },
  };
  globalThis.document = { createElement: () => iframe, getElementById: (id) => (id === "holder" ? { append() {} } : null) };
  globalThis.MessageChannel = class {
    constructor() {
      const record = { posted: [], closed: false, postedAfterClose: [] };
      channels.push(record);
      this.port1 = {
        onmessage: null, onmessageerror: null, start() {},
        close() { record.closed = true; },
        postMessage(message) { (record.closed ? record.postedAfterClose : record.posted).push(message); },
      };
      this.port2 = {};
      record.port1 = this.port1;
    }
  };
  globalThis.fetch = (url, opts) => {
    if (String(url) === "/__host/event") return Promise.resolve({ ok: true });
    return new Promise((resolve, reject) => {
      const body = JSON.parse(opts.body);
      const call = { body, settled: false, aborted: false };
      call.resolve = (value) => { call.settled = true; resolve({ json: async () => value }); };
      opts.signal?.addEventListener("abort", () => { call.aborted = true; reject(new Error("aborted")); });
      fetches.push(call);
    });
  };
  loads += 1;
  await import(`${pathToFileURL(shellFile).href}?load=${loads}`);
  const host = window.__alphaTabHost;
  const driver = {
    channels, fetches, host,
    events: () => host.events(),
    async bootstrap(id) {
      iframe.contentWindow = { id, postMessage() {} };
      for (const fn of [...listeners]) fn({ source: iframe.contentWindow, data: { type: "native-html-bootstrap", version: VERSION } });
      return channels[channels.length - 1];
    },
    send(channel, message) { channel.port1.onmessage?.({ data: { version: VERSION, ...message } }); },
    read(channel, requestId, id) { driver.send(channel, { type: "read", request_id: requestId, need: "probe.body", params: { id } }); },
    replies(channel) { return channel.posted.filter((message) => message.type === "read-result").map((m) => `${m.request_id}:${m.status}/${m.code ?? ""}`); },
    // Leave nothing pending for the next test. Resolving a read can make the
    // shell dispatch a queued one, so settle in passes until the queue drains.
    async settleAll() {
      for (let pass = 0; pass < 16; pass += 1) {
        const pending = fetches.filter((call) => !call.settled && !call.aborted);
        if (pending.length === 0) break;
        for (const call of pending) call.resolve({ result: { rows: [] } });
        await flush();
      }
    },
  };
  open.push(driver);
  return driver;
}

afterEach(async () => { for (const driver of open.splice(0)) await driver.settleAll(); });

for (const [mode, code] of [["live", "unsupported_host"], ["sample", "preview_sample_only"]]) {
  test(`fake host: ${mode} proposal refusal uses the bridge's terminal result envelope`, async () => {
    const shell = await loadShell({ mode });
    const channel = await shell.bootstrap("doc-1");
    shell.send(channel, { type: "ready" });
    shell.send(channel, { type: "intent", intent: { request_id: "comment-1", entry_id: "docs.add-comment", slots: {}, values: { text: "Keep my draft" } } });
    assert.deepEqual(channel.posted.filter((message) => message.type === "intent-result"), [
      { type: "intent-result", version: VERSION, request_id: "comment-1", result: { status: "rejected", code } },
    ]);
    assert.equal(shell.fetches.length, 0, "refused proposals never reach the write handler");
  });
}

test("fake host: a handshake timeout answers every accepted read once, then closes; the late answer changes nothing", async () => {
  const shell = await loadShell({ handshakeTimeoutMs: 30 });
  const channel = await shell.bootstrap("doc-1");
  shell.read(channel, "read-1", "r1");
  shell.read(channel, "read-2", "r2");
  await flush();
  assert.equal(shell.fetches.length, 2, "both accepted reads are in flight");
  // The one bounded timer wait: the shrunk handshake deadline.
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.deepEqual(shell.replies(channel), ["read-1:unavailable/tab_closed", "read-2:unavailable/tab_closed"]);
  assert.ok(channel.closed);
  shell.fetches[0].resolve({ result: { rows: [{ id: "r1" }] } });
  await flush();
  assert.equal(shell.replies(channel).length, 2, "no second answer");
  assert.equal(channel.postedAfterClose.length, 0);
  assert.equal(shell.fetches.length, 2, "nothing more is dispatched after close");
});

test("fake host: a message error drains once, closes and dispatches nothing more", async () => {
  const shell = await loadShell();
  const channel = await shell.bootstrap("doc-1");
  shell.send(channel, { type: "ready" });
  shell.read(channel, "read-1", "r1");
  shell.read(channel, "read-2", "r2");
  await flush();
  channel.port1.onmessageerror();
  assert.deepEqual(shell.replies(channel), ["read-1:unavailable/tab_closed", "read-2:unavailable/tab_closed"]);
  assert.ok(channel.closed);
  shell.fetches[0].resolve({ result: { rows: [{ id: "r1" }] } });
  await flush();
  assert.equal(shell.replies(channel).length, 2);
  assert.equal(shell.fetches.length, 2, "nothing more is dispatched after close");
  shell.read(channel, "read-3", "r3");
  await flush();
  assert.equal(shell.fetches.length, 2);
  assert.ok(!shell.events().some((event) => event.type === "read-queued" && event.request_id === "read-3"));
});

test("fake host: several reads are in flight at once, up to the in-flight cap", async () => {
  const shell = await loadShell();
  const channel = await shell.bootstrap("doc-1");
  shell.send(channel, { type: "ready" });
  const cap = LIMITS.shell.reads_in_flight;
  for (let i = 0; i < cap; i += 1) shell.read(channel, `read-${i}`, `r${i}`);
  await flush();
  assert.equal(shell.fetches.length, cap, `${cap} reads are on the wire together`);
  assert.equal(shell.events().filter((event) => event.type === "read-start").length, cap);
  // The next read waits in the queue rather than dispatching a (cap + 1)th.
  shell.read(channel, "read-over", "r-over");
  await flush();
  assert.equal(shell.fetches.length, cap, "the queued read does not exceed the in-flight cap");
  // Settling one frees a slot; the queued read dispatches then.
  shell.fetches[0].resolve({ result: { rows: [{ id: "r0" }] } });
  await flush();
  assert.equal(shell.fetches.length, cap + 1, "a freed slot admits the queued read");
  assert.deepEqual(shell.fetches.map((call) => call.body.params.id),
    ["r0", "r1", "r2", "r3", "r-over"]);
});

test("fake host: a timed-out read retires only its ticket; the frame's other reads keep going", async () => {
  const shell = await loadShell({ readTimeoutMs: 30 });
  const channel = await shell.bootstrap("doc-1");
  shell.send(channel, { type: "ready" });
  shell.read(channel, "read-1", "hang");
  shell.read(channel, "read-2", "r2");
  await flush();
  assert.equal(shell.fetches.length, 2, "both accepted reads are in flight");
  // The second settles before the first's deadline.
  shell.fetches[1].resolve({ result: { rows: [{ id: "r2" }] } });
  await flush();
  assert.deepEqual(shell.replies(channel), ["read-2:ok/"]);
  // The one bounded timer wait: past the hung read's deadline.
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.deepEqual(shell.replies(channel), ["read-2:ok/", "read-1:unavailable/unavailable"]);
  assert.ok(!channel.closed, "one read's timeout does not close the frame");
  assert.ok(!shell.events().some((event) => event.type === "frame-closed"), "no terminal teardown for one timeout");
  // A later read is still admitted and dispatched, not ignored.
  shell.read(channel, "read-3", "r3");
  await flush();
  assert.equal(shell.fetches.length, 3);
  shell.fetches[2].resolve({ result: { rows: [{ id: "r3" }] } });
  await flush();
  assert.equal(shell.replies(channel).at(-1), "read-3:ok/");
});

test("fake host: the per-tab admission cap still answers extra reads busy without queueing them", async () => {
  const shell = await loadShell();
  const channel = await shell.bootstrap("doc-1");
  shell.send(channel, { type: "ready" });
  const cap = LIMITS.shell.read_queue_max;
  for (let i = 0; i < cap + 1; i += 1) shell.read(channel, `read-${i}`, `r${i}`);
  await flush();
  assert.equal(shell.replies(channel).filter((reply) => reply === `read-${cap}:busy/busy`).length, 1,
    "the read past the cap is answered busy at once");
  assert.equal(shell.replies(channel).length, 1, "only the over-cap read is answered before any settles");
  assert.equal(shell.fetches.length, LIMITS.shell.reads_in_flight, "the over-cap read is not dispatched");
  assert.ok(!shell.events().some((event) => event.type === "read-queued" && event.request_id === `read-${cap}`));
});

test("fake host: a reload with a read on the wire drains the old port once and retires; nothing reaches the new document", async () => {
  const shell = await loadShell({ readTimeoutMs: 40 });
  const oldChannel = await shell.bootstrap("doc-1");
  shell.send(oldChannel, { type: "ready" });
  shell.read(oldChannel, "read-1", "r1");
  shell.read(oldChannel, "read-2", "r2");
  await flush();
  const before = shell.channels.length;
  await shell.bootstrap("doc-2");
  assert.equal(shell.channels.length, before, "no channel is opened for the new document");
  assert.deepEqual(shell.replies(oldChannel), ["read-1:unavailable/tab_reloaded", "read-2:unavailable/tab_reloaded"]);
  assert.ok(oldChannel.closed);
  // Past the old reads' deadline: both were disarmed by the drain.
  await new Promise((resolve) => setTimeout(resolve, 90));
  assert.ok(!shell.events().some((event) => event.type === "read-timeout"));
  shell.fetches[0].resolve({ result: { rows: [{ id: "r1" }] } });
  await flush();
  assert.equal(shell.replies(oldChannel).length, 2);
  assert.equal(oldChannel.postedAfterClose.length, 0);
  assert.equal(shell.fetches.length, 2, "nothing more is dispatched");
});

test("fake host: an idle reload re-handshakes; the old document's handler is ignored and a reused read-1 is answered on the new port only", async () => {
  const shell = await loadShell();
  const oldChannel = await shell.bootstrap("doc-1");
  shell.send(oldChannel, { type: "ready" });
  shell.read(oldChannel, "read-1", "r-old");
  await flush();
  shell.fetches[0].resolve({ result: { rows: [{ id: "r-old" }] } });
  await flush();
  const newChannel = await shell.bootstrap("doc-2");
  assert.notEqual(newChannel, oldChannel);
  assert.ok(oldChannel.closed);
  shell.send(newChannel, { type: "ready" });
  // The superseded document's handler, retained, is not heard.
  shell.read(oldChannel, "read-1", "r-stale");
  shell.read(newChannel, "read-1", "r-new");
  await flush();
  assert.deepEqual(shell.fetches.map((call) => call.body.params.id), ["r-old", "r-new"]);
  shell.fetches[1].resolve({ result: { rows: [{ id: "r-new" }] } });
  await flush();
  assert.deepEqual(shell.replies(newChannel), ["read-1:ok/"]);
  assert.deepEqual(shell.replies(oldChannel), ["read-1:ok/"]);
  assert.equal(oldChannel.postedAfterClose.length, 0);
});
