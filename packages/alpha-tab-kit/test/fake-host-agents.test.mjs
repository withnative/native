// Browser tests for native.agents (app contract v2, ask an agent; Shapes
// bf7cfa5) in the fake host: the real bridge, a host that lists agents,
// answers asks and pushes statuses. The alpha host's own checks (activation,
// the viewer's own recent comment, the allowlist) are proved against the real
// pending.js in experiments/demo-shell/check-app-agents-headless.mjs.
// Playwright is an optional peer, as in fake-host.test.mjs.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadChromium, openFakeHost } from "../src/fake-host/playwright.mjs";

const fixture = (name) => readFileSync(new URL(`fixtures/${name}`, import.meta.url), "utf8");
const descriptor = { ...JSON.parse(fixture("probe-descriptor.json")), declaration: { contract: "native.app.v2", needs: [], effects: [] } };

const chromium = await loadChromium();
let browser;
before(async () => { if (chromium) browser = await chromium.launch(); });
after(async () => { await browser?.close(); });
const skip = !chromium && "Playwright is not installed";

async function open(options = {}) {
  const page = await browser.newPage();
  const tab = await openFakeHost(page, { descriptor, html: fixture("probe-agents.html"), fixtures: { sql: { "probe.list": [] } }, latencyMs: 0, ...options });
  await tab.frame.locator("#surface").filter({ hasText: /agents:/ }).waitFor({ timeout: 3000 });
  const probe = (method, ...args) => tab.frame.locator("body").evaluate((_, [name, rest]) => window.probe[name](...rest), [method, args]);
  const events = async (type) => (await tab.events()).filter((event) => event.type === type);
  const settled = () => tab.page.waitForTimeout(150);
  return { page, tab, probe, events, settled, done: async () => { await tab.close(); await page.close(); } };
}

const status = (comment_id, state = "working") => ({ ask_id: `fake-ask-${comment_id}`, comment_id, state, at_ms: 1700000000000 });

test("a host offering app.agents.v2 gives the frame frozen list, ask and onStatus; list resolves frozen summaries", { skip }, async () => {
  const { tab, probe, events, done } = await open({ agents: { list: () => [
    { id: "claude", label: "Claude", ready: true }, { id: "codex", label: "Codex", ready: false, reason: "not_installed" },
    { id: "bad id", label: "x", ready: true }, { id: "nolabel", ready: true }, "junk",
  ] } });
  try {
    assert.deepEqual(await probe("surface"), { artifactAgents: "object", native: "object", nativeAgents: "object", methods: ["ask", "list", "onStatus"], same: true, frozen: true });
    // Malformed entries are dropped, not frozen in.
    assert.deepEqual(await probe("list"), { agents: [{ id: "claude", label: "Claude", ready: true }, { id: "codex", label: "Codex", ready: false, reason: "not_installed" }], frozen: true });
    const twice = await probe("listTwice");
    assert.equal(twice.same, true);
    assert.equal((await events("agents-list")).length, 2, "the two concurrent lists made one request");
    await tab.expectHealthy();
  } finally { await done(); }
});

test("on a host that does not offer app.agents.v2, neither nativeArtifact.agents nor native.agents exists", { skip }, async () => {
  for (const options of [{}, { calls: true }, { agents: true, mode: "sample" }]) {
    const { probe, done } = await open(options);
    try {
      const surface = await probe("surface");
      assert.equal(surface.artifactAgents, "undefined", JSON.stringify(options));
      assert.equal(surface.nativeAgents, "undefined", JSON.stringify(options));
    } finally { await done(); }
  }
});

test("ask sends only the agent and comment ids and resolves the host's AskResult; malformed asks resolve invalid without a message", { skip }, async () => {
  const { tab, probe, events, done } = await open({ agents: { ask: ({ to, comment_id }) => (comment_id === "c-dup"
    ? { ok: false, code: "duplicate", message: "Already asked." }
    : comment_id === "c-weird" ? { ok: false, code: "nonsense", message: "?" } : { ok: true, ask_id: `agent-${to}-${comment_id}` }) } });
  try {
    assert.deepEqual(await probe("ask", { to: "claude", comment_id: "c-1" }), { result: { ok: true, ask_id: "agent-claude-c-1" }, frozen: true });
    assert.deepEqual((await events("agents-ask")).map((event) => [event.request_id, event.to, event.comment_id]), [["agents-1", "claude", "c-1"]]);
    assert.deepEqual((await probe("ask", { to: "claude", comment_id: "c-dup" })).result, { ok: false, code: "duplicate", message: "Already asked." });
    // An AskResult outside the shared codes is not passed through.
    assert.deepEqual((await probe("ask", { to: "claude", comment_id: "c-weird" })).result,
      { ok: false, code: "unavailable", message: "the host's answer to the ask could not be read" });
    const bad = await probe("badAsks");
    assert.equal(bad.length, 13);
    for (const result of bad) assert.equal(result.code, "invalid", JSON.stringify(result));
    assert.equal((await events("agents-ask")).length, 3, "no malformed ask reached the host");
    assert.equal(await probe("throwsOnStatus"), "TypeError: status subscriber must be a function");
  } finally { await done(); }
});

test("a fifth ask in flight resolves busy in the bridge; the four answer when the host does", { skip }, async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const { probe, events, settled, done } = await open({ agents: { ask: async ({ comment_id }) => { await gate; return { ok: true, ask_id: `a-${comment_id}` }; } } });
  try {
    for (const n of [1, 2, 3, 4, 5]) await probe("start", `ask-${n}`, { to: "claude", comment_id: `c-${n}` });
    assert.deepEqual(await probe("finish", "ask-5"), { ok: false, code: "busy", message: "too many asks in flight" });
    await settled();
    assert.equal((await events("agents-ask")).length, 4, "the fifth never reached the host");
    release();
    for (const n of [1, 2, 3, 4]) assert.deepEqual(await probe("finish", `ask-${n}`), { ok: true, ask_id: `a-c-${n}` });
    // A slot is free again.
    assert.deepEqual((await probe("ask", { to: "claude", comment_id: "c-6" })).result, { ok: true, ask_id: "a-c-6" });
  } finally { await done(); }
});

test("statuses reach the frame only for the ask_ids its asks started, frozen, to every subscriber until it unsubscribes", { skip }, async () => {
  const { tab, probe, done } = await open({ agents: true });
  try {
    await probe("onStatus", "a");
    await probe("onStatus", "b");
    assert.equal(await tab.pushAgentStatus(status("c-1")), false, "nothing asked yet: the host does not post it");
    await probe("ask", { to: "claude", comment_id: "c-1" });
    assert.equal(await tab.pushAgentStatus(status("c-1", "starting")), true);
    assert.equal(await tab.pushAgentStatus(status("c-other")), false, "another comment's status is not this frame's");
    assert.equal(await tab.pushAgentStatus({ ...status("c-1"), ask_id: "foreign" }), false, "another run on the same comment is not this frame's");
    await tab.page.waitForTimeout(100);
    const expected = [{ ...status("c-1", "starting"), frozen: true }];
    assert.deepEqual(await probe("heard", "a"), expected);
    assert.deepEqual(await probe("heard", "b"), expected);
    await probe("unsubscribe", "a");
    await tab.pushAgentStatus({ ...status("c-1", "done"), message: "Replied.", extra: "dropped" });
    await tab.page.waitForTimeout(100);
    assert.equal((await probe("heard", "a")).length, 1);
    assert.deepEqual((await probe("heard", "b"))[1], { ...status("c-1", "done"), message: "Replied.", frozen: true });
    // A malformed status is dropped by the bridge.
    await tab.pushAgentStatus({ ...status("c-1"), state: "exploded" });
    await tab.page.waitForTimeout(100);
    assert.equal((await probe("heard", "b")).length, 2);
  } finally { await done(); }
});

test("closing the port resolves pending asks unavailable and the pending list empty; a reload forgets what was asked", { skip }, async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const { tab, probe, done } = await open({ agents: { ask: async () => { await gate; return { ok: true, ask_id: "late" }; } } });
  try {
    await probe("start", "pending", { to: "claude", comment_id: "c-1" });
    await tab.page.waitForTimeout(100);
    await probe("pagehide");
    assert.deepEqual(await probe("finish", "pending"), { ok: false, code: "unavailable",
      message: "the host port closed before the ask was answered; the agent may already have started" });
    assert.deepEqual((await probe("ask", { to: "claude", comment_id: "c-2" })).result, { ok: false, code: "unavailable", message: "the host port is closed" });
    assert.deepEqual((await probe("list")).agents, []);
    release();
    // The fake host remembered c-1 for that document; a new document starts clean.
    await tab.reload();
    await tab.frame.locator("#surface").filter({ hasText: /agents:object/ }).waitFor({ timeout: 3000 });
    assert.equal(await tab.pushAgentStatus(status("c-1")), false);
  } finally { await done(); }
});
