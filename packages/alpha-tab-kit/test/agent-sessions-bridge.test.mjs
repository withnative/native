// Browser behavior tests for the generated agent-sessions bridge
// (app.agent-sessions.v2) in crates/artifact-html/src/html.rs, mirrored as
// packages/alpha-tab-kit/src/fake-host/bridge-bootstrap.js.
//
// The fake host's shell has no agent-sessions channel, so each test serves a
// minimal parent page that performs the bridge handshake itself and speaks the
// exact wire protocol from packages/native-launcher/src/appAgentSessions.mjs:
// it offers the feature, answers list/follow/send/read/watch results, pushes events, and
// closes the port. Every assertion executes the real generated JS in Chromium.
// Playwright is an optional peer, as in fake-host-agents.test.mjs.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { loadChromium } from "../src/fake-host/playwright.mjs";
import { injectBridge } from "../src/fake-host/server.mjs";
import { LIMITS } from "../src/limits.mjs";
import { followupBoundaryCases } from "./vectors/followup-boundaries.mjs";

const VERSION = LIMITS.bridge.version;
const probeHtml = readFileSync(new URL("fixtures/probe-agent-sessions.html", import.meta.url), "utf8");

const parentHtml = (version) => `<!doctype html><html><head><meta charset="utf-8"></head><body>
<iframe id="f" src="/frame"></iframe>
<script>
const received = [];
let port = null;
window.addEventListener("message", (event) => {
  if (!event.data || event.data.type !== "native-html-bootstrap") return;
  const channel = new MessageChannel();
  port = channel.port1;
  port.onmessage = (e) => received.push(e.data);
  port.start();
  const features = (new URLSearchParams(location.search).get("features") || "").split(",").filter(Boolean);
  const init = { type: "native-html-init", version: ${JSON.stringify(version)}, input: {} };
  if (features.length) init.host_features = features;
  document.getElementById("f").contentWindow.postMessage(init, "*", [channel.port2]);
});
window.__host = {
  received: () => received.slice(),
  clear: () => { received.length = 0; },
  send: (message) => port.postMessage({ version: ${JSON.stringify(version)}, ...message }),
  close: () => { try { port.close(); } catch {} port = null; },
};
</script>
</body></html>`;

let server, base, browser;
const chromium = await loadChromium();
before(async () => {
  server = createServer((request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");
    if (url.pathname === "/frame") {
      const origin = `http://${request.headers.host}`;
      const body = injectBridge(probeHtml, origin);
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end(body);
      return;
    }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(parentHtml(VERSION));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  if (chromium) browser = await chromium.launch();
});
after(async () => { await browser?.close(); server.close(); });
const skip = !chromium && "Playwright is not installed";

async function open(features, fastSessionDeadline = false) {
  const page = await browser.newPage();
  if (fastSessionDeadline) await page.addInitScript(manual => {
    if (window === window.top) return;
    const original = window.setTimeout, clear = window.clearTimeout;
    const deadlines = new Map(); let next = 0;
    window.setTimeout = (callback, delay, ...args) => {
      if (![30000, 60000, 90000, 145000, 205000, 50000].includes(delay)) return original(callback, delay, ...args);
      if (!manual) return original(callback, 100, ...args);
      const id = --next; deadlines.set(id, () => callback(...args)); return id;
    };
    window.clearTimeout = id => { if (!deadlines.delete(id)) clear(id); };
    window.__expireSessionDeadlines = () => {
      for (const [id, callback] of [...deadlines]) { deadlines.delete(id); callback(); }
    };
  }, fastSessionDeadline === "manual");
  const query = features.length ? `?features=${features.join(",")}` : "";
  await page.goto(`${base}/${query}`);
  const frame = page.frameLocator("#f");
  await frame.locator("#surface").filter({ hasText: /^sessions:/ }).waitFor({ timeout: 5000 });
  const probe = (expression, arg) => frame.locator("body").evaluate(expression, arg);
  const host = (expression, arg) => page.evaluate(expression, arg);
  const wire = async (type) => (await host(() => window.__host.received())).filter((m) => m.type === type);
  return { page, frame, probe, host, wire, done: async () => page.close() };
}

const summary = (id) => ({
  id, hostId: 'local', hostLabel: 'Local', hostEpoch: 'epoch-1', title: `Session ${id}`, provider: "codex", model: "gpt-5.4", status: "working",
  lastActivity: "2026-09-28T05:12:30.000Z", workspace: { id: "w1", name: "Demo shell" }, dropped: "junk",
});
const snapshot = () => ([
  { id: "m1", kind: "message", role: "user", text: "hello" },
  { id: "t1", kind: "tool", title: "read", status: "done" },
  { id: "s1", kind: "status", status: "working" },
]);
const answer = ({ type, request_id, result }) => window.__host.send({ type, request_id, result });
const pushEvent = ({ subscription_id, session_id, event, host_id = 'local', host_epoch = 'epoch-1' }) => window.__host.send({ type: "agent-sessions-event", subscription_id, host_id, host_epoch, session_id, event });

test("absent without the host feature; offered it is one frozen sessions surface", { skip }, async () => {
  for (const features of [[], ["app.call.v2"], ["app.agent-sessions.v1"]]) {
    const tab = await open(features);
    try {
      const surface = await tab.probe(() => window.probe.surface());
      assert.equal(surface.artifactSessions, "undefined", JSON.stringify(features));
      assert.equal(surface.nativeSessions, "undefined", JSON.stringify(features));
      if (features.includes("app.call.v2")) assert.equal(surface.native, "object");
    } finally { await tab.done(); }
  }
  const tab = await open(["app.agent-sessions.v2"]);
  try {
    const surface = await tab.probe(() => window.probe.surface());
    assert.deepEqual(surface.methods, ["follow", "getPermissionForm", "list", "markRead", "openInPaseo", "protocolVersion", "respondToPermission", "send", "watchList"]);
    assert.equal(surface.same, true);
    assert.equal(surface.frozen, true);
    assert.equal(surface.protocolVersion, 2);
    assert.equal(surface.artifactSessions, "object");
  } finally { await tab.done(); }
});

test("scoped permission bridge keeps the original target, projects forms and never retries an uncertain response", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2"], "manual");
  try {
    const target = { hostId: 'local', hostEpoch: 'epoch-1', sessionId: 's1' };
    const ask = tab.probe((_, input) => window.probe.getPermissionForm(input), { ...target, permissionRequestId: 'opaque id:1', requestId: 'form-1' });
    await tab.page.waitForFunction(() => window.__host.received().some(m => m.type === 'agent-sessions-get-permission-form'));
    const [wire] = await tab.wire('agent-sessions-get-permission-form');
    assert.deepEqual([wire.host_id, wire.host_epoch, wire.session_id, wire.permission_request_id, wire.form_request_id], ['local', 'epoch-1', 's1', 'opaque id:1', 'form-1']);
    const form = { kind: 'tool', requestId: 'opaque id:1', provider: 'codex', name: 'Inspect file', preview: { filePath: '/tmp/a' } };
    await tab.host(answer, { type: 'agent-sessions-get-permission-form-result', request_id: wire.request_id,
      result: { ok: true, value: { outcome: { status: 'supported', form } } } });
    assert.deepEqual(await ask, { ok: true, value: { outcome: { status: 'supported', form } } });
    await tab.host(() => window.__host.clear());
    const action = { kind: 'tool_decision', behavior: 'deny' };
    const reply = tab.probe((_, input) => window.probe.respondToPermission(input), { ...target, permissionRequestId: 'opaque id:1', operationKey: 'operation-1', requestId: 'response-1', action });
    await tab.page.waitForFunction(() => window.__host.received().some(m => m.type === 'agent-sessions-respond-to-permission'));
    const [responseWire] = await tab.wire('agent-sessions-respond-to-permission');
    assert.deepEqual([responseWire.permission_request_id, responseWire.operation_key, responseWire.response_request_id, responseWire.action], ['opaque id:1', 'operation-1', 'response-1', action]);
    await tab.probe(() => window.__expireSessionDeadlines());
    assert.deepEqual(await reply, { ok: true, value: { outcome: { status: 'unknown' } } });
    await tab.host(answer, { type: 'agent-sessions-respond-to-permission-result', request_id: responseWire.request_id, result: { ok: true, value: { outcome: { status: 'acknowledged' } } } });
    assert.equal((await tab.wire('agent-sessions-respond-to-permission')).length, 1);
    await tab.host(() => window.__host.clear());
    const openRequest = tab.probe((_, input) => window.probe.openInPaseo(input), target);
    await tab.page.waitForFunction(() => window.__host.received().some(m => m.type === 'agent-sessions-open-in-paseo'));
    const [openWire] = await tab.wire('agent-sessions-open-in-paseo');
    assert.deepEqual([openWire.host_id, openWire.host_epoch, openWire.session_id], ['local', 'epoch-1', 's1']);
    await tab.host(answer, { type: 'agent-sessions-open-in-paseo-result', request_id: openWire.request_id, result: { ok: true, value: {} } });
    assert.deepEqual(await openRequest, { ok: true, value: {} });
  } finally { await tab.done(); }
});

test("openConversation appears only with its host feature and posts a strict depth", { skip }, async () => {
  const target = { hostId: 'local', hostEpoch: 'epoch-1', sessionId: 's1' };
  const plain = await open(["app.agent-sessions.v2"]);
  try {
    const surface = await plain.probe(() => window.probe.surface());
    assert.ok(!surface.methods.includes("openConversation"), "no openConversation without the feature");
  } finally { await plain.done(); }
  const tab = await open(["app.agent-sessions.v2", "app.agent-sessions.open-conversation.v1"], true);
  try {
    const surface = await tab.probe(() => window.probe.surface());
    assert.ok(surface.methods.includes("openConversation"));
    assert.equal(surface.frozen, true);
    const full = tab.probe((_, input) => window.probe.openConversation(input, { depth: "full" }), target);
    await tab.page.waitForFunction(() => window.__host.received().some(m => m.type === 'agent-sessions-open-conversation'));
    const [fullWire] = await tab.wire('agent-sessions-open-conversation');
    assert.deepEqual([fullWire.host_id, fullWire.host_epoch, fullWire.session_id, fullWire.depth], ['local', 'epoch-1', 's1', 'full']);
    await tab.host(answer, { type: 'agent-sessions-open-conversation-result', request_id: fullWire.request_id, result: { ok: true, value: {} } });
    assert.deepEqual(await full, { ok: true, value: {} });
    await tab.host(() => window.__host.clear());
    const quick = tab.probe((_, input) => window.probe.openConversation(input), target);
    await tab.page.waitForFunction(() => window.__host.received().some(m => m.type === 'agent-sessions-open-conversation'));
    const [quickWire] = await tab.wire('agent-sessions-open-conversation');
    assert.equal(quickWire.depth, undefined, "an absent depth posts no depth key");
    // Answer before the rejected-depth probes: the test shortens the request
    // deadline to 100 ms, and those round trips can outlast it on a slow runner.
    await tab.host(answer, { type: 'agent-sessions-open-conversation-result', request_id: quickWire.request_id, result: { ok: false, code: 'gone' } });
    assert.deepEqual(await quick, { ok: false, code: 'gone' });
    assert.deepEqual(await tab.probe((_, input) => window.probe.openConversation({ ...input, depth: "side" }), target), { ok: false, code: "invalid" });
    assert.deepEqual(await tab.probe(() => window.probe.openConversation({ hostId: "local", hostEpoch: "epoch-1", sessionId: "s1", depth: ["quick"] })), { ok: false, code: "invalid" });
    assert.deepEqual(await tab.probe(() => window.probe.openConversation({ hostId: "local", hostEpoch: "epoch-1", sessionId: "s1", depth: { toString() { throw new Error("evil"); } } })), { ok: false, code: "invalid" });
    assert.equal((await tab.wire('agent-sessions-open-conversation')).length, 1, "rejected depths never post");
  } finally { await tab.done(); }
});

const followupStatus = (overrides = {}) => ({
  state: "paused", reason: "15 follow-ups started in 10 minutes.", limit: "burst", launchesToday: 15, dailyCeiling: 100, burst: { launches: 15, limit: 15, windowMs: 600000 },
  running: 0, maxConcurrent: 2, queued: 3, queuedAt: 1760000000000, worker: { provider: "codex", model: "gpt-6.1", modeId: "auto", workspaceId: "w-1" },
  executesOn: "this Desktop", updatedAt: 1760000000000, ...overrides,
});
const followupView = { configured: true, enabled: true, provider: "codex", model: "gpt-6.1", modeId: "auto", optionsReason: null,
  options: [{ provider: "codex", label: "Codex", modeId: "auto", models: [{ id: "gpt-6.1", label: "GPT 6.1" }] }] };

test("followup appears only with its host feature, posts the four requests and checks every answer strictly", { skip }, async () => {
  const plain = await open(["app.agent-sessions.v2"]);
  try {
    assert.equal(await plain.probe(() => window.probe.followupSurface()), null, "no followup without the feature");
  } finally { await plain.done(); }
  const tab = await open(["app.agent-sessions.v2", "app.agent-sessions.followup.v1"], true);
  const wait = (type) => tab.page.waitForFunction((t) => window.__host.received().some(m => m.type === t), type);
  try {
    assert.deepEqual(await tab.probe(() => window.probe.followupSurface()), { methods: ["continue", "getSettings", "setSettings", "status"], frozen: true });
    // status: strict value; a message of another kind never settles it.
    const status = tab.probe(() => window.probe.followup("status"));
    await wait("agent-sessions-followup-status");
    const [statusWire] = await tab.wire("agent-sessions-followup-status");
    assert.deepEqual(Object.keys(statusWire).sort(), ["request_id", "type", "version"]);
    await tab.host(answer, { type: "agent-sessions-followup-continue-result", request_id: statusWire.request_id, result: { ok: true, value: followupStatus() } });
    await tab.host(answer, { type: "agent-sessions-followup-status-result", request_id: statusWire.request_id, result: { ok: true, value: followupStatus() } });
    assert.deepEqual(await status, { ok: true, value: followupStatus() });
    await tab.host(() => window.__host.clear());
    // A malformed or oversize-shaped answer is unavailable, never repaired.
    const bad = tab.probe(() => window.probe.followup("status"));
    await wait("agent-sessions-followup-status");
    const [badWire] = await tab.wire("agent-sessions-followup-status");
    await tab.host(answer, { type: "agent-sessions-followup-status-result", request_id: badWire.request_id, result: { ok: true, value: followupStatus({ state: "sleeping" }) } });
    assert.deepEqual(await bad, { ok: false, code: "unavailable" });
    await tab.host(() => window.__host.clear());
    // settings change: at least one of enabled/provider/model and nothing else, checked before posting.
    for (const input of [undefined, {}, { enabled: "yes" }, { provider: "" }, { model: "m".repeat(257) }, { enabled: true, modeId: "auto" }, { enabled: true, workspaceId: "w" }, []])
      assert.deepEqual(await tab.probe((_, i) => window.probe.followup("setSettings", i), input), { ok: false, code: "invalid" }, JSON.stringify(input));
    assert.equal((await tab.wire("agent-sessions-followup-settings-set")).length, 0, "invalid changes never post");
    const change = tab.probe(() => window.probe.followup("setSettings", { enabled: false, provider: "codex", model: "gpt-6.1" }));
    await wait("agent-sessions-followup-settings-set");
    const [setWire] = await tab.wire("agent-sessions-followup-settings-set");
    assert.deepEqual([setWire.enabled, setWire.provider, setWire.model], [false, "codex", "gpt-6.1"]);
    assert.deepEqual(Object.keys(setWire).sort(), ["enabled", "model", "provider", "request_id", "type", "version"]);
    // `saved` (written, not yet applied) carries its settings; a refusal carries none.
    const saved = { result: "saved", message: "Saved. It applies on the next pass.", settings: { ...followupView, enabled: false }, status: followupStatus({ state: "disabled", reason: null, limit: null }) };
    await tab.host(answer, { type: "agent-sessions-followup-settings-set-result", request_id: setWire.request_id, result: { ok: true, value: saved } });
    assert.deepEqual(await change, { ok: true, value: saved });
    await tab.host(() => window.__host.clear());
    const refusal = tab.probe(() => window.probe.followup("setSettings", { provider: "claude", model: "x" }));
    await wait("agent-sessions-followup-settings-set");
    const [refusalWire] = await tab.wire("agent-sessions-followup-settings-set");
    const refused = { result: "refused", message: "claude is not available on this Mac right now.", status: followupStatus() };
    await tab.host(answer, { type: "agent-sessions-followup-settings-set-result", request_id: refusalWire.request_id, result: { ok: true, value: { ...refused, settings: followupView } } });
    assert.deepEqual(await refusal, { ok: false, code: "unavailable" }, "a refusal that carries settings is malformed");
  } finally { await tab.done(); }
});

test("followup answers: the frame accepts exactly what the launcher accepts (shared boundary cases)", { skip }, async () => {
  // The same cases run against the launcher's projection in packages/native-launcher/test/appAgentSessionsFollowup.test.mjs.
  const tab = await open(["app.agent-sessions.v2", "app.agent-sessions.followup.v1"]);
  const call = { status: ["status"], getSettings: ["getSettings"], continue: ["continue"], setSettings: ["setSettings", { enabled: true }] };
  const wire = { status: "status", getSettings: "settings-get", continue: "continue", setSettings: "settings-set" };
  const methodOf = { status: "status", settingsGet: "getSettings", continue: "continue", settingsSet: "setSettings" };
  try {
    assert.ok(followupBoundaryCases.length > 50);
    const wrong = [];
    for (const { name, kind, value, valid } of followupBoundaryCases) {
      const method = methodOf[kind];
      const type = `agent-sessions-followup-${wire[method]}`;
      await tab.host(() => window.__host.clear());
      const [, input] = call[method];
      const asked = tab.probe((_, args) => window.probe.followup(args.method, args.input), { method, input });
      await tab.page.waitForFunction((t) => window.__host.received().some(m => m.type === t), type);
      const [request] = await tab.wire(type);
      await tab.host(answer, { type: `${type}-result`, request_id: request.request_id, result: { ok: true, value } });
      const result = await asked;
      if (result.ok !== valid) wrong.push(`${name}: expected ${valid ? "accepted" : "refused"}, got ${JSON.stringify(result).slice(0, 80)}`);
    }
    assert.deepEqual(wrong, []);
  } finally { await tab.done(); }
});

test("followup answers unavailable on a deadline, and a closed port resolves what is pending", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2", "app.agent-sessions.followup.v1"], true);
  try {
    // The test harness shortens the 30 s deadline to 100 ms.
    assert.deepEqual(await tab.probe(() => window.probe.followup("continue")), { ok: false, code: "unavailable" });
    const pending = tab.probe(() => window.probe.followup("getSettings"));
    await tab.page.waitForFunction(() => window.__host.received().some(m => m.type === "agent-sessions-followup-settings-get"));
    await tab.host(() => window.__host.close());
    assert.deepEqual(await pending, { ok: false, code: "unavailable" });
    assert.deepEqual(await tab.probe(() => window.probe.followup("status")), { ok: false, code: "unavailable" }, "after close nothing is posted");
  } finally { await tab.done(); }
});

test("read receipts correlate the original id; watch hints arrive before acknowledgement and unwatch once", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2"]);
  try {
    const read = tab.probe(() => window.probe.markRead({ hostId: "local", hostEpoch: "epoch-1", sessionId: "s1", requestId: "read-1" }));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-mark-read"));
    const [wire] = await tab.wire("agent-sessions-mark-read");
    assert.equal(wire.read_request_id, "read-1");
    assert.deepEqual([wire.host_id, wire.host_epoch, wire.session_id], ["local", "epoch-1", "s1"]);
    await tab.host(answer, { type: "agent-sessions-mark-read-result", request_id: wire.request_id, result: { ok: true, value: { requestId: "wrong", delivery: "acknowledged" } } });
    assert.deepEqual(await read, { ok: true, value: { requestId: "read-1", delivery: "unknown" } });
    await tab.probe(() => window.probe.startWatch("live"));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-watch-list"));
    const [watch] = await tab.wire("agent-sessions-watch-list");
    await tab.host((id) => window.__host.send({ type: "agent-sessions-list-changed", subscription_id: id, revision: 1 }), watch.subscription_id);
    await tab.probe(() => new Promise((resolve) => { const check = () => window.probe.heard("live").length ? resolve() : setTimeout(check, 10); check(); }));
    assert.deepEqual(await tab.probe(() => window.probe.heard("live")), [{ revision: 1 }]);
    await tab.host(answer, { type: "agent-sessions-watch-list-result", request_id: watch.request_id, result: { ok: true, value: {} } });
    assert.deepEqual(await tab.probe(() => window.probe.watchResult("live")), { ok: true, code: undefined, hasDispose: true });
    await tab.probe(() => window.probe.dispose("live"));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-unwatch-list"));
    assert.equal((await tab.wire("agent-sessions-unwatch-list")).length, 1);
    await tab.host((id) => window.__host.send({ type: "agent-sessions-list-changed", subscription_id: id, revision: 2 }), watch.subscription_id);
    assert.deepEqual(await tab.probe(() => window.probe.heard("live")), [{ revision: 1 }]);
  } finally { await tab.done(); }
});

test("a watch-ended message reaches the watch callback once, only for its own subscription and never after dispose", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2"]);
  try {
    await tab.probe(() => window.probe.startWatch("live"));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-watch-list"));
    const [watch] = await tab.wire("agent-sessions-watch-list");
    await tab.host(answer, { type: "agent-sessions-watch-list-result", request_id: watch.request_id, result: { ok: true, value: {} } });
    assert.deepEqual(await tab.probe(() => window.probe.watchResult("live")), { ok: true, code: undefined, hasDispose: true });
    await tab.host(() => window.__host.send({ type: "agent-sessions-list-watch-ended", subscription_id: "someone-else" }));
    await tab.host((id) => window.__host.send({ type: "agent-sessions-list-watch-ended", subscription_id: id, extra: "x".repeat(1100) }), watch.subscription_id);
    await tab.host((id) => window.__host.send({ type: "agent-sessions-list-watch-ended", subscription_id: id }), watch.subscription_id);
    await tab.probe(() => new Promise((resolve) => { const check = () => window.probe.heard("live").length ? resolve() : setTimeout(check, 10); check(); }));
    assert.deepEqual(await tab.probe(() => window.probe.heard("live")), [{ ended: true }]);
    await tab.probe(() => window.probe.dispose("live"));
    await tab.host((id) => window.__host.send({ type: "agent-sessions-list-watch-ended", subscription_id: id }), watch.subscription_id);
    assert.deepEqual(await tab.probe(() => window.probe.heard("live")), [{ ended: true }]);
  } finally { await tab.done(); }
});

test("read and watch deadlines settle once, free their slots, and never retry", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2"], true);
  try {
    const read = tab.probe(() => window.probe.markRead({ hostId: "local", hostEpoch: "epoch-1", sessionId: "s1", requestId: "read-timeout" }));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-mark-read"));
    const [readWire] = await tab.wire("agent-sessions-mark-read");
    assert.deepEqual(await read, { ok: true, value: { requestId: "read-timeout", delivery: "unknown" } });
    await tab.host(answer, { type: "agent-sessions-mark-read-result", request_id: readWire.request_id, result: { ok: true, value: { requestId: "read-timeout", delivery: "acknowledged" } } });
    assert.equal((await tab.wire("agent-sessions-mark-read")).length, 1);
    await tab.probe(() => window.probe.startWatch("timed"));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-watch-list"));
    const [watchWire] = await tab.wire("agent-sessions-watch-list");
    assert.deepEqual(await tab.probe(() => window.probe.watchResult("timed")), { ok: false, code: "unavailable", hasDispose: false });
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-unwatch-list"));
    assert.deepEqual((await tab.wire("agent-sessions-unwatch-list")).map((wire) => wire.subscription_id), [watchWire.subscription_id]);
    await tab.host((id) => window.__host.send({ type: "agent-sessions-list-changed", subscription_id: id, revision: 1 }), watchWire.subscription_id);
    assert.deepEqual(await tab.probe(() => window.probe.heard("timed")), []);
    await tab.host(answer, { type: "agent-sessions-watch-list-result", request_id: watchWire.request_id, result: { ok: true, value: {} } });
    assert.equal((await tab.wire("agent-sessions-unwatch-list")).length, 1);
  } finally { await tab.done(); }
});

test("list posts only cursor beside the fresh correlation id and resolves the projected page", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2"]);
  try {
    const asked = tab.probe(() => window.probe.list({ cursor: "c1" }));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-list"));
    const [message] = await tab.wire("agent-sessions-list");
    assert.deepEqual(Object.keys(message).sort(), ["cursor", "request_id", "type", "version"]);
    assert.match(message.request_id, /^agent-sessions-\d+$/);
    await tab.host(answer, { type: "agent-sessions-list-result", request_id: message.request_id, result: { ok: true, value: { hosts: [{ id: 'local', label: 'Local', status: 'reachable', epoch: 'epoch-1' }], sessions: [summary("s1")], nextCursor: "c2" } } });
    const { result, frozen } = await asked;
    assert.equal(frozen, true);
    assert.deepEqual(result, { ok: true, value: { hosts: [{ id: 'local', label: 'Local', status: 'reachable', epoch: 'epoch-1' }], sessions: [{ id: "s1", hostId: "local", hostLabel: "Local", hostEpoch: "epoch-1", title: "Session s1", provider: "codex", model: "gpt-5.4", status: "working", lastActivity: "2026-09-28T05:12:30.000Z", workspace: { id: "w1", name: "Demo shell" } }], nextCursor: "c2" } });
    const bare = tab.probe(() => window.probe.list());
    await tab.page.waitForFunction(() => window.__host.received().filter((m) => m.type === "agent-sessions-list").length === 2);
    const [, second] = await tab.wire("agent-sessions-list");
    assert.ok(!("cursor" in second), "list() must not send a cursor key");
    assert.notEqual(second.request_id, message.request_id, "correlation ids must be fresh");
    await tab.host(answer, { type: "agent-sessions-list-result", request_id: second.request_id, result: { ok: true, value: { hosts: [{ id: 'local', label: 'Local', status: 'reachable', epoch: 'epoch-1' }], sessions: [] } } });
    assert.deepEqual((await bare).result, { ok: true, value: { hosts: [{ id: 'local', label: 'Local', status: 'reachable', epoch: 'epoch-1' }], sessions: [] } });
  } finally { await tab.done(); }
});

test("malformed lists resolve invalid without a message; malformed pages resolve unavailable", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2"]);
  try {
    await tab.probe(() => window.probe.surface());
    const wiresBefore = (await tab.wire("agent-sessions-list")).length;
    const bad = await tab.probe(() => window.probe.badLists());
    assert.ok(bad.every((result) => result.ok === false && result.code === "invalid"), JSON.stringify(bad));
    assert.equal((await tab.wire("agent-sessions-list")).length, wiresBefore, "invalid lists reached the host");
    const asked = tab.probe(() => window.probe.list());
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-list"));
    const [message] = (await tab.wire("agent-sessions-list")).slice(-1);
    const oversized = { ok: true, value: { hosts: [{ id: 'local', label: 'Local', status: 'reachable', epoch: 'epoch-1' }], sessions: Array.from({ length: 101 }, (_, i) => summary(`s${i}`)) } };
    await tab.host(answer, { type: "agent-sessions-list-result", request_id: message.request_id, result: oversized });
    assert.deepEqual(await asked, { result: { ok: false, code: "unavailable" }, frozen: true });
    const refused = tab.probe(() => window.probe.list());
    await tab.page.waitForFunction(() => window.__host.received().filter((m) => m.type === "agent-sessions-list").length === 2);
    const [, second] = await tab.wire("agent-sessions-list");
    await tab.host(answer, { type: "agent-sessions-list-result", request_id: second.request_id, result: { ok: false, code: "gone" } });
    assert.deepEqual((await refused).result, { ok: false, code: "gone" });
  } finally { await tab.done(); }
});

test("follow reserves its slot before posting, so a synchronous snapshot is heard; dispose unsubscribes", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2"]);
  try {
    await tab.probe(() => window.probe.surface());
    await tab.probe(() => window.probe.follow("a", { hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s1" }));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-follow"));
    const [message] = await tab.wire("agent-sessions-follow");
    assert.deepEqual(Object.keys(message).sort(), ["host_epoch", "host_id", "request_id", "session_id", "subscription_id", "type", "version"]);
    assert.equal(message.session_id, "s1");
    assert.match(message.subscription_id, /^agent-session-follow-\d+$/);
    // A live subscription cannot receive another session's events. The next
    // valid snapshot is an ordered-port barrier for both rejected events.
    await tab.host(pushEvent, { subscription_id: message.subscription_id, host_id: 'local', host_epoch: 'epoch-1', session_id: "s2", event: { kind: "snapshot", items: snapshot() } });
    await tab.host(pushEvent, { subscription_id: "foreign-follow", host_id: 'local', host_epoch: 'epoch-1', session_id: "s1", event: { kind: "snapshot", items: snapshot() } });
    // The initial snapshot lands while the follow promise is still unsettled.
    await tab.host(pushEvent, { subscription_id: message.subscription_id, host_id: 'local', host_epoch: 'epoch-1', session_id: "s1", event: { kind: "snapshot", items: snapshot() } });
    await tab.host(answer, { type: "agent-sessions-follow-result", request_id: message.request_id, result: { ok: true, value: {} } });
    assert.deepEqual(await tab.probe(() => window.probe.followResult("a")), { ok: true, code: undefined, hasDispose: true });
    const heard = await tab.probe(() => window.probe.heard("a"));
    assert.equal(heard.length, 1, "wrong-session or foreign-subscription events reached the follow, or its synchronous snapshot was dropped");
    assert.deepEqual(heard[0].event, { hostId: "local", hostEpoch: "epoch-1", sessionId: "s1", kind: "snapshot", items: snapshot() });
    assert.equal(heard[0].frozen, true);
    await tab.probe(() => window.probe.rememberDisposer("a"));
    await tab.probe(() => window.probe.dispose("a"));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-unsubscribe"));
    const [unsub] = await tab.wire("agent-sessions-unsubscribe");
    assert.deepEqual(Object.keys(unsub).sort(), ["subscription_id", "type", "version"]);
    assert.equal(unsub.subscription_id, message.subscription_id);
    await tab.host(pushEvent, { subscription_id: message.subscription_id, host_id: 'local', host_epoch: 'epoch-1', session_id: "s1", event: { kind: "update", items: [] } });
    await tab.page.waitForTimeout(150);
    assert.equal((await tab.probe(() => window.probe.heard("a"))).length, 1, "event after dispose was delivered");
    assert.equal(await tab.probe(() => window.probe.throwsOnFollow()), "TypeError");
  } finally { await tab.done(); }
});

test("a terminal event before the result unsubscribes the late handle and never resurrects", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2"]);
  try {
    await tab.probe(() => window.probe.surface());
    await tab.probe(() => window.probe.follow("b", { hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s2" }));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-follow"));
    const [message] = await tab.wire("agent-sessions-follow");
    await tab.host(pushEvent, { subscription_id: message.subscription_id, host_id: 'local', host_epoch: 'epoch-1', session_id: "s2", event: { kind: "ended", code: "gone" } });
    await tab.host(answer, { type: "agent-sessions-follow-result", request_id: message.request_id, result: { ok: true, value: {} } });
    assert.deepEqual(await tab.probe(() => window.probe.followResult("b")), { ok: true, code: undefined, hasDispose: true });
    assert.deepEqual((await tab.probe(() => window.probe.heard("b"))).map((h) => h.event), [{ hostId: "local", hostEpoch: "epoch-1", sessionId: "s2", kind: "ended", code: "gone" }]);
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-unsubscribe"));
    assert.equal((await tab.wire("agent-sessions-unsubscribe")).length, 1, "late handle was not unsubscribed");
    await tab.host(pushEvent, { subscription_id: message.subscription_id, host_id: 'local', host_epoch: 'epoch-1', session_id: "s2", event: { kind: "update", items: snapshot() } });
    await tab.page.waitForTimeout(150);
    assert.equal((await tab.probe(() => window.probe.heard("b"))).length, 1, "dead slot resurrected");
    await tab.probe(() => window.probe.rememberDisposer("b"));
    const unsubsBefore = (await tab.wire("agent-sessions-unsubscribe")).length;
    await tab.probe(() => window.probe.dispose("b"));
    assert.equal((await tab.wire("agent-sessions-unsubscribe")).length, unsubsBefore, "late dispose posted again");
  } finally { await tab.done(); }
});

test("a refused follow drops its reservation; malformed follows never post", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2"]);
  try {
    await tab.probe(() => window.probe.surface());
    const wiresBefore = (await tab.wire("agent-sessions-follow")).length;
    const bad = await tab.probe(() => window.probe.badFollows());
    assert.ok(bad.every((result) => result.ok === false && result.code === "invalid"), JSON.stringify(bad));
    assert.equal((await tab.wire("agent-sessions-follow")).length, wiresBefore, "invalid follows reached the host");
    await tab.probe(() => window.probe.follow("c", { hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s3" }));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-follow"));
    const [message] = (await tab.wire("agent-sessions-follow")).slice(-1);
    await tab.host(answer, { type: "agent-sessions-follow-result", request_id: message.request_id, result: { ok: false, code: "gone" } });
    assert.deepEqual(await tab.probe(() => window.probe.followResult("c")), { ok: false, code: "gone", hasDispose: false });
    await tab.host(pushEvent, { subscription_id: message.subscription_id, host_id: 'local', host_epoch: 'epoch-1', session_id: "s3", event: { kind: "update", items: [] } });
    await tab.page.waitForTimeout(150);
    assert.deepEqual(await tab.probe(() => window.probe.heard("c")), [], "refused follow kept its slot");
  } finally { await tab.done(); }
});

test("send posts the public requestId with the complete target and text, and settles every outcome once", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2"]);
  try {
    await tab.probe(() => window.probe.surface());
    const wiresBefore = (await tab.wire("agent-sessions-send")).length;
    const bad = await tab.probe(() => window.probe.badSends());
    assert.ok(bad.every((result) => result.ok === false && result.code === "invalid"), JSON.stringify(bad).slice(0, 200));
    assert.equal((await tab.wire("agent-sessions-send")).length, wiresBefore, "invalid sends reached the host");
    const asked = tab.probe(() => window.probe.send({ hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s1", text: "hello", requestId: "r-1" }));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-send"));
    const [message] = (await tab.wire("agent-sessions-send")).slice(-1);
    assert.deepEqual(Object.keys(message).sort(), ["host_epoch", "host_id", "request_id", "session_id", "text", "type", "version"]);
    assert.equal(message.request_id, "r-1", "the wire must carry the public requestId for Desktop dedupe");
    await tab.host(answer, { type: "agent-sessions-send-result", request_id: "r-1", result: { ok: true, value: { requestId: "r-1", delivery: "acknowledged" } } });
    assert.deepEqual((await asked).result, { ok: true, value: { requestId: "r-1", delivery: "acknowledged" } });
    assert.equal((await asked).frozen, true);
    const unknown = tab.probe(() => window.probe.send({ hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s1", text: "hello", requestId: "r-2" }));
    await tab.page.waitForFunction(() => window.__host.received().filter((m) => m.type === "agent-sessions-send").length === 2);
    await tab.host(answer, { type: "agent-sessions-send-result", request_id: "r-2", result: { ok: true, value: { requestId: "r-2", delivery: "unknown" } } });
    assert.deepEqual((await unknown).result, { ok: true, value: { requestId: "r-2", delivery: "unknown" } });
    const refused = tab.probe(() => window.probe.send({ hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s1", text: "hello", requestId: "r-3" }));
    await tab.page.waitForFunction(() => window.__host.received().filter((m) => m.type === "agent-sessions-send").length === 3);
    await tab.host(answer, { type: "agent-sessions-send-result", request_id: "r-3", result: { ok: false, code: "busy" } });
    assert.deepEqual((await refused).result, { ok: false, code: "busy" });
    // Malformed answers and receipts naming another request stay uncertain, never definite.
    const uncertainCases = [
      ["r-4", { ok: true, value: {} }],
      ["r-5", { ok: true, value: { requestId: "r-other", delivery: "acknowledged" } }],
      ["r-6", { ok: true }],
      ["r-7", { ok: false, code: "nope" }],
    ];
    for (const [requestId, result] of uncertainCases) {
      const pending = tab.probe((_, id) => window.probe.send({ hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s1", text: "hello", requestId: id }), requestId);
      await tab.page.waitForFunction((id) => window.__host.received().some((m) => m.type === "agent-sessions-send" && m.request_id === id), requestId);
      await tab.host(answer, { type: "agent-sessions-send-result", request_id: requestId, result });
      const expected = { ok: true, value: { requestId, delivery: "unknown" } };
      assert.deepEqual((await pending).result, expected, `uncertain case ${requestId}`);
    }
    // A duplicate requestId while its send is unresolved is refused, never overwritten.
    await tab.probe(() => window.probe.startSend("dup", { hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s1", text: "hello", requestId: "r-dup" }));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-send" && m.request_id === "r-dup"));
    assert.deepEqual(await tab.probe(() => window.probe.send({ hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s1", text: "hello", requestId: "r-dup" })), { result: { ok: false, code: "refused" }, frozen: true });
    assert.equal((await tab.wire("agent-sessions-send")).filter((m) => m.request_id === "r-dup").length, 1, "duplicate overwrote the unresolved send");
    await tab.host(answer, { type: "agent-sessions-send-result", request_id: "r-dup", result: { ok: true, value: { requestId: "r-dup", delivery: "acknowledged" } } });
    assert.deepEqual((await tab.probe(() => window.probe.finish("dup"))).result, { ok: true, value: { requestId: "r-dup", delivery: "acknowledged" } });
  } finally { await tab.done(); }
});

test("bounds: generated ids skip occupied keys, a fifth follow and a seventeenth result resolve busy", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2"]);
  try {
    await tab.probe(() => window.probe.surface());
    // A caller-chosen send id occupying the next sequence slot is never overwritten.
    await tab.probe(() => window.probe.startSend("held", { hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s1", text: "hello", requestId: "agent-sessions-1" }));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-send"));
    const listed = tab.probe(() => window.probe.startList("first"));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-list"));
    const [listWire] = await tab.wire("agent-sessions-list");
    assert.notEqual(listWire.request_id, "agent-sessions-1", "generated id overwrote the unresolved send");
    await tab.host(answer, { type: "agent-sessions-send-result", request_id: "agent-sessions-1", result: { ok: true, value: { requestId: "agent-sessions-1", delivery: "acknowledged" } } });
    assert.deepEqual((await tab.probe(() => window.probe.finish("held"))).result, { ok: true, value: { requestId: "agent-sessions-1", delivery: "acknowledged" } });
    await tab.host(answer, { type: "agent-sessions-list-result", request_id: listWire.request_id, result: { ok: true, value: { hosts: [{ id: 'local', label: 'Local', status: 'reachable', epoch: 'epoch-1' }], sessions: [] } } });
    assert.deepEqual((await tab.probe(() => window.probe.finish("first"))).result, { ok: true, value: { hosts: [{ id: 'local', label: 'Local', status: 'reachable', epoch: 'epoch-1' }], sessions: [] } });
    // Four follows may pend; the fifth resolves busy without posting.
    for (const name of ["w", "x", "y", "z"]) await tab.probe((_, n) => window.probe.follow(n, { hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s9" }), name);
    await tab.page.waitForFunction(() => window.__host.received().filter((m) => m.type === "agent-sessions-follow").length === 4);
    await tab.probe(() => window.probe.follow("over", { hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s9" }));
    assert.deepEqual(await tab.probe(() => window.probe.followResult("over")), { ok: false, code: "busy", hasDispose: false });
    assert.equal((await tab.wire("agent-sessions-follow")).length, 4, "busy follow posted");
    // Twelve more lists fill all sixteen in-flight slots; the seventeenth is busy.
    for (let i = 0; i < 12; i += 1) await tab.probe((_, i) => window.probe.startList(`fill${i}`), i);
    await tab.page.waitForFunction(() => window.__host.received().filter((m) => m.type === "agent-sessions-list").length === 13);
    const listsBefore = (await tab.wire("agent-sessions-list")).length;
    assert.deepEqual((await tab.probe(() => window.probe.list())).result, { ok: false, code: "busy" });
    assert.equal((await tab.wire("agent-sessions-list")).length, listsBefore, "busy list posted");
    // Drain: every pending slot settles exactly once.
    for (const m of await tab.wire("agent-sessions-list")) {
      if (m.request_id === listWire.request_id) continue;
      await tab.host(answer, { type: "agent-sessions-list-result", request_id: m.request_id, result: { ok: false, code: "unavailable" } });
    }
    for (const m of await tab.wire("agent-sessions-follow")) {
      await tab.host(answer, { type: "agent-sessions-follow-result", request_id: m.request_id, result: { ok: true, value: {} } });
    }
    for (let i = 0; i < 12; i += 1) assert.deepEqual((await tab.probe((_, i) => window.probe.finish(`fill${i}`), i)).result, { ok: false, code: "unavailable" });
    for (const name of ["w", "x", "y", "z"]) {
      assert.deepEqual(await tab.probe((_, n) => window.probe.followResult(n), name), { ok: true, code: undefined, hasDispose: true });
      await tab.probe((_, n) => window.probe.rememberDisposer(n), name);
      await tab.probe((_, n) => window.probe.dispose(n), name);
    }
    assert.equal((await tab.wire("agent-sessions-unsubscribe")).length, 4, "each follow unsubscribed once");
  } finally { await tab.done(); }
});

test("teardown settles pendings once and drops every callback; calls after teardown are unavailable", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2"]);
  try {
    await tab.probe(() => window.probe.surface());
    await tab.probe(() => window.probe.startList("gl"));
    await tab.probe(() => window.probe.follow("gf", { hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s1" }));
    await tab.probe(() => window.probe.startSend("gs", { hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s1", text: "hello", requestId: "r-gone" }));
    await tab.page.waitForFunction(() => window.__host.received().filter((m) => ["agent-sessions-list", "agent-sessions-follow", "agent-sessions-send"].includes(m.type)).length === 3);
    // A parent-side port.close() need not deliver a timely close event, so drive the
    // same closeAgentSessions path the channel listeners share via pagehide.
    await tab.probe(() => window.probe.pagehide());
    assert.deepEqual((await tab.probe(() => window.probe.finish("gl"))).result, { ok: false, code: "unavailable" });
    assert.deepEqual(await tab.probe(() => window.probe.followResult("gf")), { ok: false, code: "unavailable", hasDispose: false });
    assert.deepEqual((await tab.probe(() => window.probe.finish("gs"))).result, { ok: true, value: { requestId: "r-gone", delivery: "unknown" } });
    assert.deepEqual((await tab.probe(() => window.probe.list())).result, { ok: false, code: "unavailable" });
    assert.deepEqual((await tab.probe(() => window.probe.send({ hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s1", text: "hello", requestId: "r-after" }))).result, { ok: false, code: "unavailable" });
    await tab.probe(() => window.probe.follow("late", { hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s1" }));
    assert.deepEqual(await tab.probe(() => window.probe.followResult("late")), { ok: false, code: "unavailable", hasDispose: false });
  } finally { await tab.done(); }
});

test("pagehide settles a pending send unknown; an over-size event never reaches its follower", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2"]);
  try {
    await tab.probe(() => window.probe.surface());
    await tab.probe(() => window.probe.startSend("ph", { hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s1", text: "hello", requestId: "r-ph" }));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-send"));
    await tab.probe(() => window.probe.pagehide());
    assert.deepEqual((await tab.probe(() => window.probe.finish("ph"))).result, { ok: true, value: { requestId: "r-ph", delivery: "unknown" } });
  } finally { await tab.done(); }
  const sized = await open(["app.agent-sessions.v2"]);
  try {
    await sized.probe(() => window.probe.surface());
    await sized.probe(() => window.probe.follow("big", { hostId: 'local', hostEpoch: 'epoch-1', sessionId: "s7" }));
    await sized.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-follow"));
    const [message] = await sized.wire("agent-sessions-follow");
    const big = Array.from({ length: 20 }, (_, i) => ({ id: `b${i}`, kind: "message", role: "assistant", text: "x".repeat(16 * 1024) }));
    await sized.host(pushEvent, { subscription_id: message.subscription_id, host_id: 'local', host_epoch: 'epoch-1', session_id: "s7", event: { kind: "update", items: big } });
    await sized.page.waitForTimeout(200);
    assert.deepEqual(await sized.probe(() => window.probe.heard("big")), [], "over-256KiB event was delivered");
    await sized.host(pushEvent, { subscription_id: message.subscription_id, host_id: 'local', host_epoch: 'epoch-1', session_id: "s7", event: { kind: "update", items: [{ id: "ok1", kind: "message", role: "assistant", text: "still here" }] } });
    await sized.host(answer, { type: "agent-sessions-follow-result", request_id: message.request_id, result: { ok: true, value: {} } });
    assert.deepEqual((await sized.probe(() => window.probe.heard("big"))).map((h) => h.event), [{ hostId: "local", hostEpoch: "epoch-1", sessionId: "s7", kind: "update", items: [{ id: "ok1", kind: "message", role: "assistant", text: "still here" }] }]);
    assert.deepEqual(await sized.probe(() => window.probe.followResult("big")), { ok: true, code: undefined, hasDispose: true });
  } finally { await sized.done(); }
});

test("same sessionId on two hosts routes independently and stale epochs cannot deliver", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2"]);
  try {
    for (const host of ['local','remote']) await tab.probe((_, host) => window.probe.follow(host, { hostId: host, hostEpoch: `${host}-1`, sessionId: 'shared' }), host);
    await tab.page.waitForFunction(() => window.__host.received().filter(m => m.type === 'agent-sessions-follow').length === 2);
    const messages = await tab.wire('agent-sessions-follow');
    const local = messages[0], remote = messages[1];
    for (const host of ['remote','local']) await tab.host(pushEvent, { subscription_id: local.subscription_id, session_id: 'shared', host_id: host, host_epoch: `${host}-2`, event: {kind:'snapshot', items: snapshot()} });
    await tab.page.waitForTimeout(50);
    assert.deepEqual(await tab.probe(() => window.probe.heard('local')), []);
    for (const message of messages) {
      await tab.host(answer, {type:'agent-sessions-follow-result', request_id:message.request_id, result:{ok:true,value:{}}});
      await tab.host(pushEvent, {...message, event:{kind:'snapshot',items:snapshot()}});
    }
    for (const host of ['local','remote']) {
      const heard = await tab.probe((_, host) => window.probe.heard(host), host);
      assert.equal(heard.length, 1);
      assert.equal(heard[0].event.hostId, host);
      assert.equal(heard[0].event.hostEpoch, `${host}-1`);
    }
    await tab.host(pushEvent, {...remote, event:{kind:'ended',code:'gone'}});
    await tab.host(pushEvent, {...remote, host_epoch:'remote-2', event:{kind:'update',items:snapshot()}});
    await tab.page.waitForTimeout(50);
    assert.equal((await tab.probe(() => window.probe.heard('remote'))).length, 2);
    assert.equal((await tab.probe(() => window.probe.heard('local'))).length, 1);
  } finally { await tab.done(); }
});

test('session pages reject absent, unreachable and stale host references', { skip }, async () => {
  const tab = await open(['app.agent-sessions.v2']);
  try {
    for (const hosts of [[], [{id:'local',label:'Local',status:'unreachable',epoch:'epoch-1'}],
      [{id:'local',label:'Local',status:'reachable',epoch:'epoch-2'}]]) {
      const asked = tab.probe(() => window.probe.list());
      await tab.page.waitForFunction(() => window.__host.received().some(m => m.type === 'agent-sessions-list'));
      const [wire] = await tab.wire('agent-sessions-list');
      await tab.host(answer, {type:'agent-sessions-list-result',request_id:wire.request_id,result:{ok:true,value:{hosts,sessions:[summary('s1')]}}});
      assert.deepEqual((await asked).result, {ok:false,code:'unavailable'});
      await tab.host(() => window.__host.clear());
    }
  } finally { await tab.done(); }
});

test('canonical list result accepts exact UTF-8 envelope budget and refuses one extra byte', { skip }, async () => {
  const tab = await open(['app.agent-sessions.v2']);
  try {
    const page = {hosts:[{id:'local',label:'Local',status:'reachable',epoch:'epoch-1'}],
      sessions:Array.from({length:100}, (_,i) => {
        const {dropped,...row} = summary(`s-${i}`);
        return {...row,title:'x'.repeat(512),provider:'ࠀ'.repeat(128),model:'ࠀ'.repeat(128),
          status:'x'.repeat(64),lastActivity:'x'.repeat(128),workspace:{id:null,name:'ࠀ'.repeat(128)}};
      }),nextCursor:'a'};
    let remaining = 262144 - Buffer.byteLength(JSON.stringify({ok:true,value:page}));
    assert.ok(remaining > 0 && remaining < 100*512*2);
    for (const row of page.sessions) {
      const count = Math.min(512,Math.floor(remaining/2));
      row.title='ࠀ'.repeat(count)+'x'.repeat(512-count); remaining-=count*2;
    }
    page.nextCursor+='a'.repeat(remaining);
    for (const extra of [false,true]) {
      if (extra) page.nextCursor+='a';
      const asked=tab.probe(() => window.probe.list());
      await tab.page.waitForFunction(() => window.__host.received().some(m => m.type === 'agent-sessions-list'));
      const [wire]=await tab.wire('agent-sessions-list');
      await tab.host(answer,{type:'agent-sessions-list-result',request_id:wire.request_id,result:{ok:true,value:page}});
      const {result}=await asked;
      if (extra) assert.deepEqual(result,{ok:false,code:'unavailable'});
      else assert.equal(result.value.sessions.length,100);
      await tab.host(() => window.__host.clear());
    }
  } finally { await tab.done(); }
});

// ---- Starting sessions: app.agent-sessions.create.v1 ----

const BOTH = ["app.agent-sessions.v2", "app.agent-sessions.create.v1"];
const catalogValue = () => ({ hosts: [{
  hostId: "local", hostLabel: "Local", hostEpoch: "epoch-1", status: "reachable",
  providers: [{ id: "claude", label: "Claude", available: true, defaultModeId: "default",
    models: [{ id: "claude-fable-5-1", label: "Fable 5.1", featured: true, isDefault: true, thinkingOptions: [{ id: "high", label: "High" }], defaultThinkingOptionId: "high" }],
    modes: [{ id: "default", label: "Default" }] }],
  workspaces: [{ id: "ws-1", name: "repo", path: "/repo", projectName: "repo", isGitRepo: true }],
}] });
const created = () => ({ id: "s-new", hostId: "local", hostLabel: "Local", hostEpoch: "epoch-1", title: null, provider: "claude", model: "claude-fable-5-1",
  status: "running", lastActivity: "2026-10-14T00:00:00.000Z", workspace: { id: "ws-1", name: "repo" } });
const startInput = (over = {}) => ({ requestId: "My_Req:42", hostId: "local", hostEpoch: "epoch-1", provider: "claude", model: "claude-fable-5-1", workspaceId: "ws-1", initialPrompt: "hello", ...over });
const unknownCreate = { ok: false, error: { code: "outcome_unknown", message: "The session may have started. Retry with the same requestId to find out; it cannot start a second one." } };
async function startOnWire(tab, input = startInput()) {
  tab.probe((_, value) => { window.probe.startCreate("c", value); }, input);
  await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-create"));
  return (await tab.wire("agent-sessions-create"))[0];
}

test("catalog and create exist only when the host offers the create feature beside sessions", { skip }, async () => {
  for (const features of [["app.agent-sessions.create.v1"], ["app.agent-sessions.v2"]]) {
    const tab = await open(features);
    try {
      const surface = await tab.probe(() => window.probe.surface());
      if (features.length === 1 && features[0] === "app.agent-sessions.create.v1") assert.equal(surface.nativeSessions, "undefined", "the create feature alone offers no sessions");
      else assert.ok(!surface.methods.includes("catalog") && !surface.methods.includes("create"), JSON.stringify(surface.methods));
    } finally { await tab.done(); }
  }
  const tab = await open(BOTH);
  try {
    const surface = await tab.probe(() => window.probe.surface());
    assert.deepEqual(surface.methods, ["catalog", "chooseFolder", "create", "follow", "getPermissionForm", "list", "markRead", "openInPaseo", "protocolVersion", "respondToPermission", "send", "watchList"]);
    assert.equal(surface.same, true);
    assert.equal(surface.frozen, true);
  } finally { await tab.done(); }
});

test("capabilities.create reaches the app's host rows, as true only and only on reachable hosts", { skip }, async () => {
  const tab = await open(BOTH);
  try {
    const asked = tab.probe(() => window.probe.list());
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-list"));
    const [message] = await tab.wire("agent-sessions-list");
    await tab.host(answer, { type: "agent-sessions-list-result", request_id: message.request_id, result: { ok: true, value: { sessions: [], hosts: [
      { id: "a", label: "A", status: "reachable", epoch: "e1", capabilities: { create: true, listChanged: true } },
      { id: "b", label: "B", status: "reachable", epoch: "e1", capabilities: { create: "yes" } },
      { id: "c", label: "C", status: "unreachable", epoch: null, capabilities: { create: true } },
    ] } } });
    const { result } = await asked;
    assert.deepEqual(result.value.hosts.map((host) => host.capabilities), [{ listChanged: true, create: true }, undefined, undefined]);
  } finally { await tab.done(); }
});

test("catalog posts one bare request, projects the reply and refuses what is malformed", { skip }, async () => {
  const tab = await open(BOTH);
  try {
    const asked = tab.probe(() => window.probe.catalog());
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-catalog"));
    const [message] = await tab.wire("agent-sessions-catalog");
    assert.deepEqual(Object.keys(message).sort(), ["request_id", "type", "version"]);
    await tab.host(answer, { type: "agent-sessions-catalog-result", request_id: message.request_id, result: { ok: true, value: { hosts: [{ ...catalogValue().hosts[0], junk: 1 }] } } });
    assert.deepEqual(await asked, { result: { ok: true, value: catalogValue() }, frozen: true });
    for (const [reply, expected] of [
      [{ ok: true, value: { hosts: [{ hostId: "x" }] } }, { ok: false, code: "unavailable" }],
      [{ ok: true, value: { hosts: Array.from({ length: 33 }, (_, i) => ({ ...catalogValue().hosts[0], hostId: `h${i}` })) } }, { ok: false, code: "unavailable" }],
      [{ ok: false, code: "busy" }, { ok: false, code: "busy" }],
      [{ ok: false, code: "invented" }, { ok: false, code: "unavailable" }],
    ]) {
      await tab.host(() => window.__host.clear());
      const next = tab.probe(() => window.probe.catalog());
      await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-catalog"));
      const [wire] = await tab.wire("agent-sessions-catalog");
      await tab.host(answer, { type: "agent-sessions-catalog-result", request_id: wire.request_id, result: reply });
      assert.deepEqual((await next).result, expected, JSON.stringify(reply));
    }
  } finally { await tab.done(); }
});

test("create posts the public requestId as request_id with the Desktop fields and resolves the new session", { skip }, async () => {
  const tab = await open(BOTH);
  try {
    const wire = await startOnWire(tab, startInput({ modeId: "default", thinkingOptionId: "high", newWorktree: { baseBranch: "main" } }));
    assert.deepEqual({ ...wire, version: undefined }, { version: undefined, type: "agent-sessions-create", request_id: "My_Req:42", host_id: "local", host_epoch: "epoch-1",
      provider: "claude", model: "claude-fable-5-1", mode_id: "default", thinking_option_id: "high", workspace_id: "ws-1", new_worktree: { base_branch: "main" }, initial_prompt: "hello" });
    await tab.host(answer, { type: "agent-sessions-create-result", request_id: "My_Req:42", result: { ok: true, value: { ...created(), junk: 1 } } });
    assert.deepEqual(await tab.probe(() => window.probe.createResult("c")), { ok: true, value: created() });
    // A bare request carries no optional keys.
    await tab.host(() => window.__host.clear());
    const bare = await startOnWire(tab, startInput({ requestId: "bare-1" }));
    assert.deepEqual(Object.keys(bare).sort(), ["host_epoch", "host_id", "initial_prompt", "model", "provider", "request_id", "type", "version", "workspace_id"]);
  } finally { await tab.done(); }
});

test("create refuses a malformed request before anything is posted", { skip }, async () => {
  const tab = await open(BOTH);
  try {
    await tab.probe(() => window.probe.surface());
    const bad = [
      undefined, null, "x", {}, startInput({ extra: 1 }), startInput({ idempotencyKey: "k" }), startInput({ requestId: "bad id" }), startInput({ requestId: "" }),
      startInput({ initialPrompt: "   " }), startInput({ initialPrompt: "x".repeat(16385) }), startInput({ provider: "" }), startInput({ provider: "a\nb" }),
      startInput({ model: "m".repeat(257) }), startInput({ workspaceId: "w".repeat(513) }), startInput({ hostId: "bad id" }), startInput({ modeId: null }),
      startInput({ thinkingOptionId: "" }), startInput({ newWorktree: {} }), startInput({ newWorktree: { baseBranch: "main", extra: 1 } }), startInput({ newWorktree: "main" }),
    ];
    for (const input of bad) {
      const { result } = await tab.probe((_, value) => window.probe.create(value), input);
      assert.equal(result.ok, false, JSON.stringify(input));
      assert.equal(result.error.code, "invalid_request", JSON.stringify(input));
    }
    assert.equal((await tab.wire("agent-sessions-create")).length, 0, "an invalid start reached the host");
  } finally { await tab.done(); }
});

test("create passes a typed Desktop refusal as definite and everything else as outcome_unknown", { skip }, async () => {
  const tab = await open(BOTH);
  try {
    const cases = [
      [{ ok: false, error: { code: "model_unavailable", message: "no such model" } }, { ok: false, error: { code: "model_unavailable", message: "no such model" } }],
      [{ ok: false, error: { code: "create_failed", message: "x".repeat(500), future: 1 } }, { ok: false, error: { code: "create_failed", message: "x".repeat(500) } }],
      [{ ok: false, error: { code: "create_failed", message: "x".repeat(501) } }, unknownCreate],
      [{ ok: true, value: { ...created(), workspace: { id: 5, name: "repo" } } }, unknownCreate],
      [{ ok: true, value: { ...created(), workspace: { id: "w".repeat(129), name: "repo" } } }, unknownCreate],
      [{ ok: true, value: { ...created(), title: "t".repeat(501) } }, unknownCreate],
      [{ ok: true, value: { ...created(), createdAt: 5 } }, unknownCreate],
      [{ ok: true, value: { ...created(), parentId: "bad id" } }, unknownCreate],
      [{ ok: true, value: { ...created(), unread: "yes" } }, unknownCreate],
      [{ ok: true, value: { ...created(), pendingPermission: { requestId: "r", kind: "weird" } } }, unknownCreate],
      [{ ok: true, value: { ...created(), attentionRequest: { kind: "done", message: "m".repeat(501) } } }, unknownCreate],
      [{ ok: true, value: { ...created(), createdAt: "2026-10-14T00:00:00Z", parentId: "p-1", quoted: [{ from: "a", text: "b" }], futureField: 1, attentionRequest: { kind: "done", message: "ok", future: 1 } } },
        { ok: true, value: { ...created(), createdAt: "2026-10-14T00:00:00Z", parentId: "p-1", attentionRequest: { kind: "done", message: "ok" } } }],
      [{ ok: false, error: { code: "outcome_unknown", message: "maybe" } }, { ok: false, error: { code: "outcome_unknown", message: "maybe" } }],
      [{ ok: false, code: "unavailable" }, unknownCreate],
      [{ ok: false, code: "busy" }, unknownCreate],
      [{ ok: false, error: { code: "invented", message: "x" } }, unknownCreate],
      [{ ok: false, error: { code: "create_failed" } }, unknownCreate],
      [{ ok: false }, unknownCreate],
      [{ ok: true }, unknownCreate],
      [{ ok: true, value: {} }, unknownCreate],
      [{ ok: true, value: { ...created(), hostId: "elsewhere" } }, unknownCreate],
      [{ ok: true, value: { ...created(), status: 7 } }, unknownCreate],
      [undefined, unknownCreate],
      [null, unknownCreate],
      ["ok", unknownCreate],
    ];
    for (const [index, [reply, expected]] of cases.entries()) {
      await tab.host(() => window.__host.clear());
      const requestId = `try-${index}`;
      await startOnWire(tab, startInput({ requestId }));
      await tab.host(answer, { type: "agent-sessions-create-result", request_id: requestId, result: reply });
      assert.deepEqual(await tab.probe(() => window.probe.createResult("c")), expected, JSON.stringify(reply));
    }
  } finally { await tab.done(); }
});

test("a create that gets no answer resolves outcome_unknown and is never re-sent; a closed port does the same", { skip }, async () => {
  const tab = await open(BOTH, true);
  try {
    await startOnWire(tab, startInput({ requestId: "slow-1" }));
    assert.deepEqual(await tab.probe(() => window.probe.createResult("c")), unknownCreate);
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal((await tab.wire("agent-sessions-create")).length, 1, "the bridge must not retry");
    // A late answer after the deadline changes nothing and starts nothing.
    await tab.host(answer, { type: "agent-sessions-create-result", request_id: "slow-1", result: { ok: true, value: created() } });
    assert.equal((await tab.wire("agent-sessions-create")).length, 1);
  } finally { await tab.done(); }
  const closing = await open(BOTH);
  try {
    await startOnWire(closing, startInput({ requestId: "closing-1" }));
    await closing.probe(() => window.probe.pagehide());
    assert.deepEqual(await closing.probe(() => window.probe.createResult("c")), unknownCreate);
    const { result } = await closing.probe((_, value) => window.probe.create(value), startInput({ requestId: "after-close" }));
    assert.equal(result.error.code, "create_unsupported", "after close nothing is posted, and that is definite");
  } finally { await closing.done(); }
});

test("a repeat of a requestId already in flight is outcome_unknown locally, without touching the first", { skip }, async () => {
  const tab = await open(BOTH);
  try {
    await startOnWire(tab, startInput({ requestId: "dup-1" }));
    const { result } = await tab.probe((_, value) => window.probe.create(value), startInput({ requestId: "dup-1" }));
    assert.equal(result.error.code, "outcome_unknown", "the first may still start a session, so the repeat is never a definite refusal");
    assert.equal((await tab.wire("agent-sessions-create")).length, 1);
    await tab.host(answer, { type: "agent-sessions-create-result", request_id: "dup-1", result: { ok: true, value: created() } });
    assert.equal((await tab.probe(() => window.probe.createResult("c"))).ok, true, "the first request still gets its own verdict");
  } finally { await tab.done(); }
});

test("a repeat of a pending requestId is outcome_unknown even when the bridge is at capacity", { skip }, async () => {
  const tab = await open(BOTH);
  try {
    await tab.probe(() => window.probe.surface());
    // Sixteen starts in flight fill the bridge.
    for (let i = 0; i < 16; i += 1) {
      await tab.probe((_, value) => { window.probe.startCreate(`full-${value.requestId}`, value); }, startInput({ requestId: `cap-${i}` }));
    }
    await tab.page.waitForFunction(() => window.__host.received().filter((m) => m.type === "agent-sessions-create").length === 16);
    // The same id again is the first one's repeat: never a definite busy.
    const repeat = await tab.probe((_, value) => window.probe.create(value), startInput({ requestId: "cap-0" }));
    assert.deepEqual(repeat.result, unknownCreate);
    // A new id at capacity is still a definite, retryable busy.
    const fresh = await tab.probe((_, value) => window.probe.create(value), startInput({ requestId: "cap-new" }));
    assert.equal(fresh.result.error.code, "busy");
    assert.equal((await tab.wire("agent-sessions-create")).length, 16, "neither extra call reached the host");
    // The first request still gets its own verdict.
    await tab.host(answer, { type: "agent-sessions-create-result", request_id: "cap-0", result: { ok: true, value: created() } });
    assert.equal((await tab.probe(() => window.probe.createResult("full-cap-0"))).ok, true);
  } finally { await tab.done(); }
});

// ---- Slices C1/C2: createStatus, cancel and quoted, behind the adopted feature ------------------------

const ADOPTED = ["app.agent-sessions.v2", "app.agent-sessions.create.v1", "app.agent-sessions.adopted.v1"];
const adoptedStart = (extra = {}) => ({ hostId: "local", hostEpoch: "epoch-1", requestId: "c-1", provider: "claude", model: "m-1", workspaceId: "w-1", initialPrompt: "Do the thing", ...extra });
const waitFor = (tab, type, count = 1) => tab.page.waitForFunction(([t, n]) => window.__host.received().filter((m) => m.type === t).length >= n, [type, count]);

test("createStatus and cancel exist only with the adopted feature beside the create feature, on the same frozen surface", { skip }, async () => {
  const plain = await open(["app.agent-sessions.v2", "app.agent-sessions.create.v1"]);
  try {
    const surface = await plain.probe(() => window.probe.surface());
    assert.deepEqual(surface.methods.filter((m) => ["catalog", "create", "createStatus", "cancel"].includes(m)), ["catalog", "create"]);
  } finally { await plain.done(); }
  const alone = await open(["app.agent-sessions.v2", "app.agent-sessions.adopted.v1"]);
  try {
    const surface = await alone.probe(() => window.probe.surface());
    assert.deepEqual(surface.methods.filter((m) => ["catalog", "create", "createStatus", "cancel"].includes(m)), [], "adopted alone offers no start operations");
  } finally { await alone.done(); }
  const tab = await open(ADOPTED);
  try {
    const surface = await tab.probe(() => window.probe.surface());
    assert.deepEqual(surface.methods.filter((m) => ["catalog", "create", "createStatus", "cancel"].includes(m)), ["cancel", "catalog", "create", "createStatus"]);
    assert.equal(surface.same, true);
    assert.equal(surface.frozen, true);
  } finally { await tab.done(); }
});

test("createStatus and cancel post a fresh id beside the create's requestId and resolve the projected state", { skip }, async () => {
  const tab = await open(ADOPTED);
  try {
    const status = tab.probe(() => window.probe.createStatus("c-1"));
    await waitFor(tab, "agent-sessions-create-status");
    const [wire] = await tab.wire("agent-sessions-create-status");
    assert.deepEqual([wire.create_request_id, wire.request_id === "c-1"], ["c-1", false]);
    assert.deepEqual(Object.keys(wire).sort(), ["create_request_id", "request_id", "type", "version"]);
    await tab.host(answer, { type: "agent-sessions-create-status-result", request_id: wire.request_id, result: { ok: true, value: { state: "confirming", leaked: 1 } } });
    assert.deepEqual(await status, { ok: true, value: { state: "confirming" } });
    const stored = { ok: false, error: { code: "refused", message: "Cancelled." } };
    const cancel = tab.probe(() => window.probe.cancel("c-1"));
    await waitFor(tab, "agent-sessions-cancel");
    const [cw] = await tab.wire("agent-sessions-cancel");
    assert.equal(cw.create_request_id, "c-1");
    await tab.host(answer, { type: "agent-sessions-cancel-result", request_id: cw.request_id, result: { ok: true, value: { state: "cancelled", acknowledged: true, result: stored } } });
    assert.deepEqual(await cancel, { ok: true, value: { state: "cancelled", acknowledged: true, result: stored } });
    const noAck = tab.probe(() => window.probe.cancel("c-1"));
    await waitFor(tab, "agent-sessions-cancel", 2);
    const second = (await tab.wire("agent-sessions-cancel"))[1];
    await tab.host(answer, { type: "agent-sessions-cancel-result", request_id: second.request_id, result: { ok: true, value: { state: "cancelled" } } });
    assert.deepEqual(await noAck, { ok: false, code: "unavailable" });
    const bad = await tab.probe(() => Promise.all([window.native.agentSessions.cancel({}), window.native.agentSessions.createStatus({ requestId: "a b" }), window.native.agentSessions.cancel(null)]));
    assert.deepEqual(bad, [{ ok: false, code: "invalid" }, { ok: false, code: "invalid" }, { ok: false, code: "invalid" }]);
  } finally { await tab.done(); }
});

test("a control that gets no answer resolves unavailable at its deadline and frees its slot", { skip }, async () => {
  const tab = await open(ADOPTED, true);
  try {
    assert.deepEqual(await tab.probe(() => window.probe.createStatus("c-1")), { ok: false, code: "unavailable" });
    const [wire] = await tab.wire("agent-sessions-create-status");
    await tab.host(answer, { type: "agent-sessions-create-status-result", request_id: wire.request_id, result: { ok: true, value: { state: "settled" } } });
    assert.equal((await tab.wire("agent-sessions-create-status")).length, 1);
  } finally { await tab.done(); }
});

test("quoted rides a start and a send only under the adopted feature, validated, and absent stays absent", { skip }, async () => {
  const quoted = [{ from: "Sam", text: "ship it" }];
  const tab = await open(ADOPTED);
  try {
    void tab.probe((_, input) => window.probe.startCreate("p", input), adoptedStart({ quoted }));
    await waitFor(tab, "agent-sessions-create");
    const [wire] = await tab.wire("agent-sessions-create");
    assert.deepEqual(wire.quoted, quoted);
    await tab.host(() => window.__host.clear());
    void tab.probe((_, input) => window.probe.sendWith(input), { hostId: "local", hostEpoch: "epoch-1", sessionId: "s1", text: "hi", requestId: "r2", quoted }).catch(() => {});
    await waitFor(tab, "agent-sessions-send");
    assert.deepEqual((await tab.wire("agent-sessions-send"))[0].quoted, quoted);
    const bad = await tab.probe(() => Promise.all([
      window.native.agentSessions.send({ hostId: "local", hostEpoch: "epoch-1", sessionId: "s1", text: "hi", requestId: "r3", quoted: [{ from: "", text: "x" }] }),
      window.native.agentSessions.create({ hostId: "local", hostEpoch: "epoch-1", requestId: "c-9", provider: "claude", model: "m-1", workspaceId: "w-1", initialPrompt: "go", quoted: [{ from: "a", text: "b", more: 1 }] }),
    ]));
    assert.deepEqual(bad[0], { ok: false, code: "invalid" });
    assert.equal(bad[1].error.code, "invalid_request");
  } finally { await tab.done(); }
  // Without the adopted feature a quoted send is unavailable and a quoted start create_unsupported; nothing is posted.
  const plain = await open(["app.agent-sessions.v2", "app.agent-sessions.create.v1"]);
  try {
    const out = await plain.probe(() => Promise.all([
      window.native.agentSessions.send({ hostId: "local", hostEpoch: "epoch-1", sessionId: "s1", text: "hi", requestId: "r4", quoted: [{ from: "Sam", text: "ship it" }] }),
      window.native.agentSessions.create({ hostId: "local", hostEpoch: "epoch-1", requestId: "c-8", provider: "claude", model: "m-1", workspaceId: "w-1", initialPrompt: "go", quoted: [{ from: "Sam", text: "ship it" }] }),
    ]));
    assert.deepEqual(out[0], { ok: false, code: "unavailable" });
    assert.equal(out[1].error.code, "create_unsupported");
    assert.equal((await plain.wire("agent-sessions-send")).length + (await plain.wire("agent-sessions-create")).length, 0);
  } finally { await plain.done(); }
});

test("a send without quoted posts exactly its old keys, and waits its own deadline", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2"]);
  try {
    void tab.probe(() => window.probe.startSend("a", { hostId: "local", hostEpoch: "epoch-1", sessionId: "s1", text: "hi", requestId: "r1" }));
    await waitFor(tab, "agent-sessions-send");
    const [plain] = await tab.wire("agent-sessions-send");
    assert.deepEqual(plain, { version: VERSION, type: "agent-sessions-send", request_id: "r1", host_id: "local", host_epoch: "epoch-1", session_id: "s1", text: "hi" });
  } finally { await tab.done(); }
});

test("saved feature exposes target-only owner commands, preserves paused/private results and stays absent on old hosts", { skip }, async () => {
  const old = await open(["app.agent-sessions.v2"]);
  try { assert.equal(await old.probe(() => typeof window.native.agentSessions.save), 'undefined'); }
  finally { await old.done(); }
  const tab = await open(["app.agent-sessions.v2", "app.agent-sessions.saved.v1"]);
  const target = { hostId: 'local', hostEpoch: 'epoch-1', sessionId: 's1' };
  try {
    for (const [kind, wire, value] of [
      ['save', 'save', { requestId: 'main-1', delivery: 'acknowledged' }],
      ['stopSaving', 'stop-saving', { requestId: 'main-2', delivery: 'unknown' }],
      ['saveStatus', 'save-status', { label: 'paused', confirmedSeq: 123 }],
      ['previewSaved', 'preview-saved', { text: 'Private', excludedCounts: { reasoning: 3, toolInput: 2, images: 0 } }],
    ]) {
      assert.deepEqual(await tab.probe((_, { kind, input }) => window.native.agentSessions[kind](input), { kind, input: { ...target, accountId: 'injected' } }), { ok: false, code: 'invalid' });
      const promise = tab.probe((_, { kind, input }) => window.native.agentSessions[kind](input), { kind, input: target });
      await tab.page.waitForFunction(type => window.__host.received().some(m => m.type === type), 'agent-sessions-' + wire);
      const [message] = await tab.wire('agent-sessions-' + wire);
      assert.deepEqual(Object.keys(message).sort(), ['host_epoch', 'host_id', 'request_id', 'session_id', 'type', 'version']);
      await tab.host(answer, { type: 'agent-sessions-' + wire + '-result', request_id: message.request_id, result: { ok: true, value } });
      assert.deepEqual(await promise, { ok: true, value });
    }
    assert.equal((await tab.wire('agent-sessions-send')).length + (await tab.wire('agent-sessions-create')).length, 0);
    const malformed = tab.probe((_, input) => window.native.agentSessions.saveStatus(input), target);
    await tab.page.waitForFunction(() => window.__host.received().filter(m => m.type === 'agent-sessions-save-status').length === 2);
    const message = (await tab.wire('agent-sessions-save-status')).at(-1);
    await tab.host(answer, { type: 'agent-sessions-save-status-result', request_id: message.request_id, result: { ok: true, value: { label: 'paused', raw: 'leak' } } });
    assert.deepEqual(await malformed, { ok: false, code: 'unavailable' });
  } finally { await tab.done(); }
});


test("folder chooser carries only host identity and preserves cancel/choice through the real bridge", { skip }, async () => {
  const tab = await open(["app.agent-sessions.v2", "app.agent-sessions.create.v1"]);
  try {
    const waiting = tab.probe(() => window.native.agentSessions.chooseFolder({ hostId: "local", hostEpoch: "epoch-1" }));
    await tab.page.waitForFunction(() => window.__host.received().some((m) => m.type === "agent-sessions-choose-folder"));
    const [wire] = await tab.wire("agent-sessions-choose-folder");
    assert.deepEqual(Object.keys(wire).sort(), ["host_epoch", "host_id", "request_id", "type", "version"]);
    await tab.host(answer, { type: "agent-sessions-choose-folder-result", request_id: wire.request_id, result: { ok: true, value: null } });
    assert.deepEqual(await waiting, { ok: true, value: null });
    const invalid = await tab.probe(() => window.native.agentSessions.chooseFolder({ hostId: "local", hostEpoch: "epoch-1", path: "/private" }));
    assert.deepEqual(invalid, { ok: false, code: "invalid" });
  } finally { await tab.done(); }
});
