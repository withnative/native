// Browser tests for native.session (app contract v2, live co-editing) in the
// fake host: the real bridge, a host that transfers a MessagePort per session.
// Playwright is an optional peer, as in fake-host.test.mjs.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadChromium, openFakeHost } from "../src/fake-host/playwright.mjs";

const fixture = (name) => readFileSync(new URL(`fixtures/${name}`, import.meta.url), "utf8");
const descriptor = { ...JSON.parse(fixture("probe-descriptor.json")), declaration: { contract: "native.app.v2", needs: [], effects: [] } };

const rows = Array.from({ length: 3 }, (_, i) => ({ id: `r${i}`, name: `Task ${i}` }));
const chromium = await loadChromium();
let browser;
before(async () => { if (chromium) browser = await chromium.launch(); });
after(async () => { await browser?.close(); });
const skip = !chromium && "Playwright is not installed";

async function open(options = {}) {
  const page = await browser.newPage();
  const tab = await openFakeHost(page, { descriptor, html: fixture("probe-session.html"), fixtures: { sql: { "probe.list": rows } }, latencyMs: 0, ...options });
  await tab.frame.locator("#surface").filter({ hasText: /open:/ }).waitFor({ timeout: 3000 });
  const probe = (method, ...args) => tab.frame.locator("body").evaluate((_, [name, rest]) => window.probe[name](...rest), [method, args]);
  const events = async (type) => (await tab.events()).filter((event) => event.type === type);
  const heard = (name) => probe("heard", name);
  const until = (name, count) => tab.frame.locator("body").evaluate((_, [n, c]) => new Promise((resolve, reject) => {
    const deadline = Date.now() + 3000;
    const poll = () => (window.probe.heard(n).length >= c ? resolve(window.probe.heard(n)) : Date.now() > deadline ? reject(new Error(`only ${window.probe.heard(n).length} of ${c} frames on ${n}`)) : setTimeout(poll, 10));
    poll();
  }), [name, count]);
  return { page, tab, probe, events, heard, until, done: async () => { await tab.close(); await page.close(); } };
}

// A host that holds its answer to each listed record's session-open until the test releases it,
// so "before the port arrives" holds however slowly the test's own calls get through (a fixed
// latency would race them on a loaded machine). Records not listed are answered at once.
function holdAnswers(...recordIds) {
  const gates = new Map(recordIds.map((id) => {
    const gate = {};
    gate.opened = new Promise((resolve) => { gate.release = resolve; });
    return [id, gate];
  }));
  return {
    sessions: async ({ recordId }) => { await gates.get(recordId)?.opened; return null; },
    release: (id) => gates.get(id).release(),
    releaseAll: () => { for (const gate of gates.values()) gate.release(); },
  };
}

test("a frame on a host offering app.session.v2 opens a session and gets its frames echoed back, unchanged", { skip }, async () => {
  const { tab, probe, events, until, done } = await open({ sessions: true });
  try {
    assert.deepEqual(await probe("surface"), { artifactOpen: "function", native: "object", nativeOpen: "function", nativeCall: "undefined", same: true, nativeFrozen: true, artifactFrozen: true });
    // The channel comes back synchronously, frozen, with exactly the agreed members.
    assert.deepEqual(await probe("open", "a", "rec-1", { mode: "view" }), { keys: ["close", "onMessage", "send"], frozen: true });
    await probe("send", "a", { op: "session.presence", cursor: { at: 3 } });
    assert.deepEqual(await until("a", 1), [{ op: "session.presence", cursor: { at: 3 } }]);
    const opens = await events("session-open");
    assert.deepEqual(opens.map((event) => [event.request_id, event.record_id, event.mode]), [["session-1", "rec-1", "view"]]);
    await tab.expectHealthy();
  } finally { await done(); }
});

test("the mode defaults to edit, and a bad record id, mode, option or frame throws at the call site without reaching the host", { skip }, async () => {
  const { probe, events, done } = await open({ sessions: true });
  try {
    await probe("open", "default", "rec-1");
    assert.equal((await events("session-open"))[0].mode, "edit");
    for (const [recordId, options] of [["", undefined], ["has space", undefined], ["a".repeat(129), undefined], [5, undefined], ["rec", { mode: "write" }], ["rec", { mode: "edit", extra: 1 }], ["rec", []]]) {
      assert.match(await probe("throws", recordId, options), /^TypeError: /, JSON.stringify([recordId, options]));
    }
    assert.equal((await events("session-open")).length, 1);
    for (const outcome of await probe("badFrames", "default")) assert.match(outcome ?? "", /^TypeError: /);
  } finally { await done(); }
});

test("frames sent before the port arrives are flushed to the host in order", { skip }, async () => {
  const held = holdAnswers("rec-1");
  const { tab, probe, events, until, done } = await open({ sessions: held.sessions });
  try {
    await probe("open", "a", "rec-1");
    for (let index = 0; index < 5; index += 1) await probe("send", "a", { op: "session.update", index });
    // The host has the open and is holding its answer.
    await tab.page.waitForFunction(() => window.__alphaTabHost.events().some((event) => event.type === "session-open"), null, { timeout: 3000 });
    assert.equal((await events("session-frame")).length, 0, "nothing reaches the host before it answers");
    held.release("rec-1");
    const echoed = await until("a", 5);
    assert.deepEqual(echoed.map((frame) => frame.index), [0, 1, 2, 3, 4]);
    assert.deepEqual((await events("session-frame")).map((event) => event.frame.index), [0, 1, 2, 3, 4]);
  } finally { held.releaseAll(); await done(); }
});

test("a refused session delivers session.error once and then closes", { skip }, async () => {
  const { probe, events, heard, tab, until, done } = await open({ sessions: ({ recordId }) => (recordId === "locked" ? { code: "forbidden", message: "no access to locked" } : null) });
  try {
    await probe("open", "locked", "locked");
    await tab.page.waitForFunction(() => window.__alphaTabHost.events().some((event) => event.type === "session-refused"), null, { timeout: 3000 });
    assert.deepEqual(await until("locked", 1), [{ op: "session.error", code: "forbidden", message: "no access to locked" }]);
    // Closed: a later send is dropped, not thrown, and nothing reaches the host.
    assert.equal(await probe("throwsOnSend", "locked", { op: "session.update" }), null);
    await probe("close", "locked");
    await probe("close", "locked");
    assert.equal((await events("session-frame")).length, 0);
    assert.deepEqual(await heard("locked"), [{ op: "session.error", code: "forbidden", message: "no access to locked" }]);
    // The refusal released its slot: an accepted session still opens.
    await probe("open", "fine", "other");
    await probe("send", "fine", { op: "session.presence" });
    await until("fine", 1);
    assert.equal((await events("session-frame")).length, 1);
  } finally { await done(); }
});

test("a session answer for an unknown request is ignored, and an answer without exactly one port errors the session", { skip }, async () => {
  const { probe, tab, until, heard, done } = await open({ sessions: true, latencyMs: 400 });
  try {
    await probe("open", "none", "rec-1");
    await probe("open", "two", "rec-2");
    await tab.page.evaluate(() => {
      window.__alphaTabHost.sendRaw({ type: "session-refused", request_id: "session-99", code: "forbidden", message: "x" });
      window.__alphaTabHost.sendRaw({ type: "session-opened", request_id: "session-99" }, 1);
      window.__alphaTabHost.sendRaw({ type: "session-opened", request_id: "session-1" }, 0);
      window.__alphaTabHost.sendRaw({ type: "session-opened", request_id: "session-2" }, 2);
    });
    const protocol = { op: "session.error", code: "protocol", message: "the host did not transfer exactly one session port" };
    assert.deepEqual(await until("none", 1), [protocol]);
    assert.deepEqual(await until("two", 1), [protocol]);
    // The real answers that follow are for sessions already ended: ignored.
    await tab.page.waitForTimeout(600);
    assert.deepEqual(await heard("none"), [protocol]);
    assert.deepEqual(await heard("two"), [protocol]);
  } finally { await done(); }
});

test("at most 16 sessions are open per frame; the 17th gets busy, and closing one frees a slot", { skip }, async () => {
  const { probe, events, heard, until, done } = await open({ sessions: true });
  try {
    for (let index = 0; index < 16; index += 1) await probe("open", `s${index}`, `rec-${index}`);
    await probe("open", "extra", "rec-extra");
    await until("extra", 1);
    assert.deepEqual(await heard("extra"), [{ op: "session.error", code: "busy", message: "too many open sessions" }]);
    assert.equal((await events("session-open")).length, 16, "the host never hears of the 17th");
    await probe("close", "s0");
    await probe("open", "again", "rec-again");
    await probe("send", "again", { op: "session.presence" });
    await until("again", 1);
    assert.equal((await events("session-open")).length, 17);
  } finally { await done(); }
});

// Chromium does not fire `close` on a MessagePort, so the bridge's `close`
// listener is dormant there; pagehide, which it also listens for, is the
// observable way for the host port to go away (as for the call drain).
test("when the host port goes away every open session hears session.error once, and later opens fail port_closed", { skip }, async () => {
  const { tab, probe, events, heard, until, done } = await open({ sessions: true, latencyMs: 300 });
  try {
    await probe("open", "live", "rec-1");
    await probe("send", "live", { op: "session.presence" });
    await until("live", 1);
    await probe("open", "waiting", "rec-2");
    await probe("open", "closed-early", "rec-3");
    await probe("close", "closed-early");
    await probe("pagehide");
    await until("waiting", 1);
    await until("live", 2);
    const expected = { op: "session.error", code: "port_closed", message: "the host port closed" };
    assert.deepEqual(await heard("waiting"), [expected]);
    assert.deepEqual((await heard("live")).slice(1), [expected]);
    assert.deepEqual(await heard("closed-early"), [], "a session the app closed hears nothing");
    await probe("open", "late", "rec-4");
    await until("late", 1);
    assert.deepEqual(await heard("late"), [expected]);
    // The host's answers to the sessions that already ended change nothing.
    await tab.page.waitForTimeout(600);
    // The bridge failing the open session says goodbye on its port, and the sessions still waiting
    // (or closed early) are told session-close on their late ports.
    assert.deepEqual((await events("session-closed")).map((event) => [event.request_id, event.by]).sort(), [["session-1", "frame"], ["session-2", "frame"], ["session-3", "frame"]]);
    for (const name of ["waiting", "live", "late"]) assert.equal((await heard(name)).filter((frame) => frame.op === "session.error").length, 1, name);
  } finally { await done(); }
});

test("close() is idempotent, stops delivery both ways, and a session closed before the port arrives sends and hears nothing", { skip }, async () => {
  const held = holdAnswers("rec-2");
  const { tab, probe, events, heard, until, done } = await open({ sessions: held.sessions });
  try {
    await probe("open", "a", "rec-1");
    await until("a", 0);
    await probe("send", "a", { op: "session.presence", n: 1 });
    await until("a", 1);
    await probe("close", "a");
    await probe("close", "a");
    assert.equal(await probe("throwsOnSend", "a", { op: "session.presence", after: true }), null, "a send after close is dropped, not thrown");
    // The host hears the end in-band, once, before the port closes.
    await tab.page.waitForFunction(() => window.__alphaTabHost.events().some((event) => event.type === "session-closed"), null, { timeout: 3000 });
    assert.deepEqual((await events("session-closed")).map((event) => [event.request_id, event.by]), [["session-1", "frame"]]);
    // Closed before the host answered: nothing it sends or answers reaches either side.
    await probe("open", "early", "rec-2");
    await probe("send", "early", { op: "session.presence", early: true });
    await probe("close", "early");
    held.release("rec-2");
    // The late port is told session-close too, so the host frees the session it opened. That is the
    // last thing the bridge does with it, so once the host has heard it nothing more can follow.
    await tab.page.waitForFunction(() => window.__alphaTabHost.events().filter((event) => event.type === "session-closed").length === 2, null, { timeout: 3000 });
    assert.deepEqual((await events("session-frame")).map((event) => event.frame.n ?? event.frame.early), [1]);
    assert.deepEqual((await events("session-closed")).map((event) => [event.request_id, event.by]), [["session-1", "frame"], ["session-2", "frame"]]);
    assert.deepEqual(await heard("a"), [{ op: "session.presence", n: 1 }], "no session.error: the app closed it");
    assert.deepEqual(await heard("early"), []);
  } finally { held.releaseAll(); await done(); }
});

test("a late session-opened for a session the app already closed is told session-close and gets nothing else", { skip }, async () => {
  const held = holdAnswers("rec-1");
  const { tab, probe, events, done } = await open({ sessions: held.sessions });
  try {
    await probe("open", "early", "rec-1");
    await probe("send", "early", { op: "session.presence" });
    await probe("close", "early");
    held.release("rec-1");
    await tab.page.waitForFunction(() => window.__alphaTabHost.events().some((event) => event.type === "session-closed"), null, { timeout: 3000 });
    assert.deepEqual((await events("session-closed")).map((event) => [event.request_id, event.by]), [["session-1", "frame"]]);
    assert.equal((await events("session-frame")).length, 0, "the queued frame is dropped, not flushed onto the late port");
    // An answer for a session this frame never opened is treated the same way.
    await tab.page.evaluate(() => window.__alphaTabHost.sendRaw({ type: "session-opened", request_id: "session-77" }, 1));
    await tab.page.waitForTimeout(100);
  } finally { held.releaseAll(); await done(); }
});

test("a session the host ends frees its slot: the 17th open succeeds, and a later send is refused", { skip }, async () => {
  const { tab, probe, events, heard, until, done } = await open({ sessions: true });
  try {
    for (let index = 0; index < 16; index += 1) await probe("open", `s${index}`, `rec-${index}`);
    await probe("send", "s15", { op: "session.presence" });
    await until("s15", 1);
    await probe("open", "full", "rec-full");
    await until("full", 1);
    assert.equal((await heard("full"))[0].code, "busy");
    // Non-terminal refusals (a resync, refused updates) leave the session open.
    await tab.sessionPost("session-1", { op: "session.refused", session: "x", code: "resync", refused: [] });
    await until("s0", 1);
    assert.equal(await probe("throwsOnSend", "s0", { op: "session.presence" }), null);
    // Terminal: session.closed, or a refusal naming a key (a refused open).
    await tab.sessionPost("session-1", { op: "session.closed", session: "x", reason: "access_lost" });
    await tab.sessionPost("session-2", { op: "session.refused", key: "k", code: "forbidden" });
    await until("s1", 1);
    assert.deepEqual((await heard("s0")).slice(-1), [{ op: "session.closed", session: "x", reason: "access_lost" }]);
    assert.deepEqual(await heard("s1"), [{ op: "session.refused", key: "k", code: "forbidden" }]);
    assert.match(await probe("throwsOnSend", "s0", { op: "session.presence" }) ?? "", /^TypeError: /);
    assert.match(await probe("throwsOnSend", "s1", { op: "session.presence" }) ?? "", /^TypeError: /);
    await probe("open", "again", "rec-again");
    await probe("open", "again2", "rec-again2");
    await probe("send", "again", { op: "session.presence" });
    await probe("send", "again2", { op: "session.presence" });
    await until("again", 1);
    assert.deepEqual(await heard("again"), [{ op: "session.presence" }]);
    await until("again2", 1);
    assert.deepEqual(await heard("again2"), [{ op: "session.presence" }]);
    // Two slots were freed and both are taken again: the next open is busy.
    await probe("open", "third", "rec-third");
    await until("third", 1);
    assert.equal((await heard("third"))[0].code, "busy");
    // The host ended those sessions itself: the bridge does not say goodbye back.
    assert.deepEqual((await events("session-closed")).filter((event) => event.by === "frame"), []);
  } finally { await done(); }
});

test("frames queued before the port arrives are bounded in total bytes across sessions", { skip }, async () => {
  const held = holdAnswers("rec-a", "rec-b", "rec-c");
  const { tab, probe, heard, until, done } = await open({ sessions: held.sessions });
  try {
    await probe("open", "a", "rec-a");
    await probe("open", "b", "rec-b");
    for (let index = 0; index < 3; index += 1) assert.equal(await probe("sendBlob", "a", 1000000), null);
    assert.equal(await probe("sendBlob", "b", 1000000), null, "3 MB + 1 MB fits in the 4 MiB budget");
    assert.equal(await probe("sendBlob", "b", 1000000), null, "the send itself does not throw; the session errors");
    await until("b", 1);
    assert.equal((await heard("b"))[0].code, "too_large");
    assert.deepEqual((await heard("a")).filter((frame) => frame.op === "session.error"), []);
    // Session a's frames still go out in order once its port arrives.
    held.release("rec-a");
    await until("a", 3);
    assert.equal((await heard("a")).length, 3);
    // The budget is released: a fresh session can queue again, while its own port is still to come.
    await probe("open", "c", "rec-c");
    for (let index = 0; index < 4; index += 1) assert.equal(await probe("sendBlob", "c", 1000000), null);
    held.release("rec-c");
    await until("c", 4);
    assert.deepEqual((await heard("c")).filter((frame) => frame.op === "session.error"), []);
    await tab.expectHealthy();
  } finally { held.releaseAll(); await done(); }
});

test("on a host that does not offer app.session.v2, neither nativeArtifact.session nor native.session exists", { skip }, async () => {
  const { probe, events, done } = await open();
  try {
    assert.deepEqual(await probe("surface"), { artifactOpen: "undefined", native: "undefined", nativeOpen: "undefined", nativeCall: "undefined", same: null, nativeFrozen: null, artifactFrozen: true });
    assert.equal((await events("session-open")).length, 0);
  } finally { await done(); }
});

test("with calls but no sessions, window.native has call and no session; with sessions but no calls, the reverse", { skip }, async () => {
  const callsOnly = await open({ calls: true });
  try {
    assert.deepEqual(await callsOnly.probe("surface"), { artifactOpen: "undefined", native: "object", nativeOpen: "undefined", nativeCall: "function", same: null, nativeFrozen: true, artifactFrozen: true });
  } finally { await callsOnly.done(); }
  const both = await open({ calls: true, sessions: true });
  try {
    const surface = await both.probe("surface");
    assert.equal(surface.nativeCall, "function");
    assert.equal(surface.nativeOpen, "function");
  } finally { await both.done(); }
});
