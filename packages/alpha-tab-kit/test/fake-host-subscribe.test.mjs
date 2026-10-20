// Browser tests for native.query and native.subscribe (app contract v2, instant
// reads) in the fake host: the real bridge, a host that answers a query and
// pushes subscription deliveries. Playwright is an optional peer, as in
// fake-host.test.mjs.
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

const result = (...cells) => ({ columns: ["n"], rows: cells.map((cell) => [cell]), truncated: false });

async function open(options = {}) {
  const page = await browser.newPage();
  const tab = await openFakeHost(page, { descriptor, html: fixture("probe-subscribe.html"), fixtures: { sql: { "probe.list": rows } }, latencyMs: 0, ...options });
  await tab.frame.locator("#surface").filter({ hasText: /query:/ }).waitFor({ timeout: 3000 });
  const probe = (method, ...args) => tab.frame.locator("body").evaluate((_, [name, rest]) => window.probe[name](...rest), [method, args]);
  const events = async (type) => (await tab.events()).filter((event) => event.type === type);
  const heard = (name) => probe("heard", name);
  const until = (name, count) => tab.frame.locator("body").evaluate((_, [n, c]) => new Promise((resolve, reject) => {
    const deadline = Date.now() + 3000;
    const poll = () => (window.probe.heard(n).length >= c ? resolve(window.probe.heard(n)) : Date.now() > deadline ? reject(new Error(`only ${window.probe.heard(n).length} of ${c} frames on ${n}`)) : setTimeout(poll, 10));
    poll();
  }), [name, count]);
  const settled = () => tab.page.waitForTimeout(150);
  return { page, tab, probe, events, heard, until, settled, done: async () => { await tab.close(); await page.close(); } };
}

const ready = (rowsOut, extra = {}) => ({ status: "ready", rows: rowsOut, columns: ["n"], truncated: false, cached: false, frozen: true, ...extra });

test("a v1 install receives no v2 methods even when host test options enable them", { skip }, async () => {
  const v1 = JSON.parse(fixture("probe-descriptor.json"));
  const { tab, probe, events, done } = await open({ descriptor: v1, queries: true, calls: true, sessions: true });
  try {
    const surface = await probe("surface");
    for (const name of ["artifactQuery", "artifactSubscribe", "nativeQuery", "nativeSubscribe", "nativeCall", "nativeSession"]) assert.equal(surface[name], "undefined", name);
    assert.deepEqual(await tab.page.evaluate(() => { const c = window.__ALPHA_TAB_HOST_CONFIG__; return [c.queries, c.calls, c.sessions]; }), [false, false, false]);
    for (const endpoint of ["query", "call"]) {
      const answer = await tab.page.evaluate(async path => (await fetch(`/__host/${path}`, { method: "POST", body: "{}" })).json(), endpoint);
      assert.equal(answer.code, "unsupported_host");
    }
    await tab.expectHealthy();
  } finally { await done(); }
});

test("a host offering app.subscribe.v2 gives the frame frozen query and subscribe, and query resolves rows, columns and truncated", { skip }, async () => {
  const { tab, probe, events, done } = await open({ queries: true });
  try {
    assert.deepEqual(await probe("surface"), { artifactQuery: "function", artifactSubscribe: "function", native: "object", nativeQuery: "function", nativeSubscribe: "function", nativeCall: "undefined", nativeSession: "undefined", same: true, nativeFrozen: true });
    const answer = await probe("query", { sql: "select ?1, ?2", params: [1, "a"] });
    assert.deepEqual(answer, { ok: { columns: ["sql", "parameters"], rows: [["select ?1, ?2", [1, "a"]]], truncated: false }, frozen: true });
    // `params` travel as the engine's positional `parameters`; with none the host still sees an array.
    await probe("query", { sql: "select 1" });
    assert.deepEqual((await events("query")).map((event) => [event.request_id, event.query]), [["query-1", { sql: "select ?1, ?2", parameters: [1, "a"] }], ["query-2", { sql: "select 1", parameters: [] }]]);
    await tab.expectHealthy();
  } finally { await done(); }
});

test("a structured query travels as query_record's own steps, order, limit and offset, and the two forms never mix", { skip }, async () => {
  const { tab, probe, events, done } = await open({ queries: true });
  try {
    const steps = [{ step: "filter", types: ["Document"], home_id: "folder-1" }];
    assert.deepEqual(await probe("query", { steps, order: "name_asc", limit: 20 }), { ok: { columns: ["steps"], rows: [[steps]], truncated: false }, frozen: true });
    assert.deepEqual((await events("query")).map((event) => event.query), [{ steps, order: "name_asc", limit: 20 }]);
    for (const bad of [{ steps: [] }, { steps: "x" }, { steps, sql: "select 1" }, { steps, params: [] }, { sql: "select 1", order: "name_asc" }, { sql: "select 1", offset: 5 }]) {
      const outcome = await probe("query", bad);
      assert.deepEqual([outcome.error?.status, outcome.error?.code], ["refused", "malformed"], JSON.stringify(bad));
    }
    assert.equal((await events("query")).length, 1);
    await tab.expectHealthy();
  } finally { await done(); }
});

test("a query the host refuses or fails rejects with status and code; a malformed host answer rejects malformed", { skip }, async () => {
  const { tab, probe, done } = await open({ queries: ({ sql }) => { if (sql === "refuse") throw Object.assign(new Error("not yours"), { status: "refused", code: "forbidden" }); if (sql === "boom") throw new Error("kaboom"); return { rows: "nope", columns: [] }; } });
  try {
    assert.deepEqual((await probe("query", { sql: "refuse" })).error, { name: "Error", status: "refused", code: "forbidden", message: "not yours" });
    assert.deepEqual((await probe("query", { sql: "boom" })).error, { name: "Error", status: "error", code: "handler_error", message: "kaboom" });
    assert.deepEqual((await probe("query", { sql: "bad shape" })).error, { name: "Error", status: "error", code: "malformed", message: "the query result could not be delivered" });
    await tab.expectHealthy();
  } finally { await done(); }
});

test("subscribe delivers the first result, then a pushed update, then nothing after unsubscribe", { skip }, async () => {
  let version = 0;
  const { tab, probe, events, heard, until, settled, done } = await open({ queries: () => result(`v${++version}`) });
  try {
    // The unsubscribe function comes back synchronously and nothing is delivered inline.
    assert.deepEqual(await probe("subscribe", "list", { sql: "select n", params: [7] }), { type: "function", frozen: false, delivered: 0 });
    assert.deepEqual(await until("list", 1), [ready([["v1"]])]);
    // Push 1: the host re-runs its handler. Push 2: an explicit cached result.
    await tab.pushSubscription("subscription-1");
    assert.deepEqual((await until("list", 2))[1], ready([["v2"]]));
    await tab.pushSubscription("subscription-1", result("cached"), { cached: true });
    assert.deepEqual((await until("list", 3))[2], ready([["cached"]], { cached: true }));
    assert.deepEqual((await events("subscribe")).map((event) => [event.subscription_id, event.query]), [["subscription-1", { sql: "select n", parameters: [7] }]]);

    await probe("unsubscribe", "list");
    await probe("unsubscribe", "list"); // idempotent: the host hears it once
    await settled();
    assert.equal((await events("unsubscribe")).length, 1);
    assert.deepEqual(await tab.subscriptions(), []);
    assert.equal((await heard("list")).length, 3);
    await tab.expectHealthy();
  } finally { await done(); }
});

test("a delivery that is not newer than the last or not a whole non-negative number is dropped", { skip }, async () => {
  const { tab, probe, heard, until, settled, done } = await open({ queries: true });
  try {
    await probe("subscribe", "a", { sql: "select 1" });
    await until("a", 1); // delivery 1
    await tab.pushSubscription("subscription-1", result("two")); // delivery 2
    await tab.pushSubscription("subscription-1", result("stale"), { delivery: 2 });
    await tab.pushSubscription("subscription-1", result("older"), { delivery: 1 });
    await tab.pushSubscription("subscription-1", result("skip ahead"), { delivery: 9 });
    await tab.pushSubscription("subscription-1", result("fractional"), { delivery: 9.5 });
    await tab.pushSubscription("subscription-1", result("negative"), { delivery: -1 });
    await until("a", 3);
    await settled();
    assert.deepEqual((await heard("a")).map((frame) => frame.rows[0][0]), ["select 1", "two", "skip ahead"]);
    assert.deepEqual(await tab.subscriptions(), ["subscription-1"]);
    await tab.expectHealthy();
  } finally { await done(); }
});

test("a host error is delivered; non-terminal leaves the subscription open, terminal ends it and frees the slot", { skip }, async () => {
  const { tab, probe, until, settled, events, done } = await open({ queries: true });
  try {
    await probe("subscribe", "a", { sql: "select 1" });
    await until("a", 1);
    await tab.failSubscription("subscription-1", "stale_authority", "re-checking", false);
    assert.deepEqual((await until("a", 2))[1], { status: "error", code: "stale_authority", message: "re-checking", terminal: false, frozen: true });
    await tab.pushSubscription("subscription-1", result("again"));
    assert.equal((await until("a", 3))[2].status, "ready");
    await tab.failSubscription("subscription-1", "forbidden", "access lost", true);
    assert.deepEqual((await until("a", 4))[3], { status: "error", code: "forbidden", message: "access lost", terminal: true, frozen: true });
    // Ended by the host: the frame does not say goodbye, and unsubscribe afterwards is a no-op.
    await probe("unsubscribe", "a");
    await settled();
    assert.equal((await events("unsubscribe")).length, 0);
    assert.deepEqual(await tab.subscriptions(), []);
    await tab.expectHealthy();
  } finally { await done(); }
});

test("a host that refuses the subscribe ends it with a terminal error", { skip }, async () => {
  const { tab, probe, until, done } = await open({ queries: () => { throw Object.assign(new Error("no hub"), { status: "refused", code: "unsupported_host" }); } });
  try {
    await probe("subscribe", "a", { sql: "select 1" });
    assert.deepEqual(await until("a", 1), [{ status: "error", code: "unsupported_host", message: "no hub", terminal: true, frozen: true }]);
    assert.deepEqual(await tab.subscriptions(), []);
  } finally { await done(); }
});

test("the feature is absent unless the host offers it", { skip }, async () => {
  const none = await open();
  try {
    assert.deepEqual(await none.probe("surface"), { artifactQuery: "undefined", artifactSubscribe: "undefined", native: "undefined", nativeQuery: "undefined", nativeSubscribe: "undefined", nativeCall: "undefined", nativeSession: "undefined", same: null, nativeFrozen: null });
    assert.deepEqual((await none.tab.events()).filter((event) => ["query", "subscribe"].includes(event.type)), []);
  } finally { await none.done(); }
  // Other v2 features do not offer it, and offering it does not offer them.
  const callsOnly = await open({ calls: true });
  try {
    const surface = await callsOnly.probe("surface");
    assert.deepEqual([surface.native, surface.nativeCall, surface.nativeQuery, surface.nativeSubscribe, surface.artifactQuery], ["object", "function", "undefined", "undefined", "undefined"]);
  } finally { await callsOnly.done(); }
  const queriesOnly = await open({ queries: true });
  try {
    const surface = await queriesOnly.probe("surface");
    assert.deepEqual([surface.nativeCall, surface.nativeSession, surface.nativeQuery, surface.nativeSubscribe], ["undefined", "undefined", "function", "function"]);
  } finally { await queriesOnly.done(); }
  const both = await open({ calls: true, sessions: true, queries: true });
  try {
    const surface = await both.probe("surface");
    assert.deepEqual([surface.nativeCall, surface.nativeSession, surface.nativeQuery, surface.nativeSubscribe, surface.nativeFrozen], ["function", "object", "function", "function", true]);
  } finally { await both.done(); }
});

test("a malformed or oversized query is refused in the frame and never reaches the host", { skip }, async () => {
  const { tab, probe, events, until, done } = await open({ queries: true });
  try {
    for (const outcome of await probe("badQueries")) {
      assert.equal(outcome.error.status, "refused");
      assert.equal(outcome.error.code, "malformed");
    }
    // 262144 characters of serialized query is the cap: one over is too_large, the exact cap passes.
    const over = await probe("bigQuery", 262144);
    assert.deepEqual([over.error.status, over.error.code], ["refused", "too_large"]);
    const overhead = JSON.stringify({ sql: "select ''", parameters: [] }).length;
    assert.ok((await probe("bigQuery", 262144 - overhead)).ok, "the query exactly at the cap is accepted");
    assert.equal((await events("query")).length, 1);
    // A subscribe is never thrown at: it is answered once with a terminal error, after the call returns.
    for (const name of await probe("badSubscribes")) assert.deepEqual((await until(name, 1)).map((frame) => [frame.status, frame.code, frame.terminal]), [["error", "malformed", true]], name);
    assert.deepEqual(await probe("subscribe", "big", { sql: `select '${"x".repeat(262144)}'` }), { type: "function", frozen: false, delivered: 0 });
    assert.deepEqual((await until("big", 1)).map((frame) => [frame.code, frame.terminal]), [["too_large", true]]);
    assert.equal((await events("subscribe")).length, 0);
    assert.match(await probe("throwsOnSubscribe", undefined), /^TypeError: /);
    await tab.expectHealthy();
  } finally { await done(); }
});

test("a query whose shape throws when probed is a refusal, not a synchronous throw", { skip }, async () => {
  const { tab, probe, until, events, done } = await open({ queries: true });
  try {
    // Nothing threw at the call site: a throwing ownKeys trap and a revoked proxy, for query and subscribe alike.
    assert.deepEqual(await probe("hostileQueries"), [null, null, null, null]);
    for (const name of ["hostile-0", "hostile-1"]) assert.deepEqual((await until(name, 1)).map((frame) => [frame.status, frame.code, frame.terminal]), [["error", "malformed", true]], name);
    assert.equal((await events("query")).length + (await events("subscribe")).length, 0);
    await tab.expectHealthy();
  } finally { await done(); }
});

test("a refused subscribe is delivered even if the app unsubscribes at once; a live one unsubscribed at once hears nothing", { skip }, async () => {
  const { tab, probe, heard, until, settled, events, done } = await open({ queries: true });
  try {
    assert.equal(await probe("subscribeRefusedThenUnsubscribe", "refused"), 0); // never inline
    assert.deepEqual((await until("refused", 1)).map((frame) => [frame.status, frame.code, frame.terminal]), [["error", "malformed", true]]);
    await probe("subscribeThenUnsubscribe", "live");
    await settled();
    assert.deepEqual(await heard("live"), []);
    assert.deepEqual(await tab.subscriptions(), []);
    assert.equal((await events("unsubscribe")).length, 1);
    await tab.expectHealthy();
  } finally { await done(); }
});

test("sample mode does not offer app.subscribe.v2, as it answers neither query nor subscribe", { skip }, async () => {
  const { probe, events, done } = await open({ queries: true, mode: "sample" });
  try {
    const surface = await probe("surface");
    assert.deepEqual([surface.native, surface.nativeQuery, surface.nativeSubscribe, surface.artifactQuery, surface.artifactSubscribe], ["undefined", "undefined", "undefined", "undefined", "undefined"]);
    assert.deepEqual((await events("init")).length, 1);
  } finally { await done(); }
});

test("at most 8 queries are in flight; the 9th is refused busy and a finished one frees a slot", { skip }, async () => {
  // The host holds every answer until the test releases it, so the 8 stay in flight however
  // slowly the test's own calls arrive (a fixed latency would race them on a loaded machine).
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const { tab, probe, events, done } = await open({ queries: async ({ sql, parameters }) => { await gate; return { columns: ["sql", "parameters"], rows: [[sql, parameters]], truncated: false }; } });
  try {
    for (let i = 0; i < 8; i += 1) await probe("start", `q${i}`, { sql: `select ${i}` });
    // All 8 have reached the host, which is holding them: the frame's cap is what refuses the 9th.
    await tab.page.waitForFunction(() => window.__alphaTabHost.events().filter((event) => event.type === "query").length === 8, null, { timeout: 3000 });
    assert.deepEqual([(await probe("query", { sql: "select 9" })).error.code], ["busy"]);
    release();
    for (let i = 0; i < 8; i += 1) assert.equal((await probe("finish", `q${i}`)).ok.rows[0][0], `select ${i}`);
    assert.ok((await probe("query", { sql: "select again" })).ok);
    assert.equal((await events("query")).length, 9);
    await tab.expectHealthy();
  } finally { release(); await done(); }
});

test("at most 32 subscriptions are open; the 33rd gets subscription_limit, and closing one frees a slot", { skip }, async () => {
  const { tab, probe, events, until, settled, done } = await open({ queries: true });
  try {
    for (let i = 0; i < 32; i += 1) await probe("subscribe", `s${i}`, { sql: `select ${i}` });
    await probe("subscribe", "extra", { sql: "select extra" });
    assert.deepEqual((await until("extra", 1)).map((frame) => [frame.status, frame.code, frame.terminal]), [["error", "subscription_limit", true]]);
    assert.equal((await events("subscribe")).length, 32);
    await probe("unsubscribe", "s0");
    await probe("subscribe", "again", { sql: "select again" });
    assert.equal((await until("again", 1))[0].status, "ready");
    await settled();
    assert.equal((await events("subscribe")).length, 33);
    assert.equal((await tab.subscriptions()).length, 32);
    await tab.expectHealthy();
  } finally { await done(); }
});

test("a result over 1 MiB rejects a query and is a non-terminal error on a subscription, which then carries on", { skip }, async () => {
  const big = "x".repeat(1048576);
  const { tab, probe, until, done } = await open({ queries: ({ sql }) => (sql === "select big" ? result(big) : result("small")) });
  try {
    // The subscription's first answer is too large: an error, not terminal.
    await probe("subscribe", "a", { sql: "select big" });
    assert.deepEqual((await until("a", 1)).map((frame) => [frame.status, frame.code, frame.terminal]), [["error", "too_large", false]]);
    // It is still open: a smaller delivery arrives, a larger one errors again.
    await tab.pushSubscription("subscription-1", result("small"));
    assert.deepEqual((await until("a", 2))[1], ready([["small"]]));
    await tab.pushSubscription("subscription-1", result(big));
    assert.deepEqual((await until("a", 3))[2].code, "too_large");
    assert.deepEqual(await tab.subscriptions(), ["subscription-1"]);
    // A query with a too-large answer rejects; one with a small answer is unaffected.
    const tooBig = await probe("query", { sql: "select big" });
    assert.deepEqual([tooBig.error.status, tooBig.error.code], ["error", "too_large"]);
    assert.ok((await probe("query", { sql: "select small" })).ok);
    await tab.expectHealthy();
  } finally { await done(); }
});

test("a subscription callback may unsubscribe from inside its own delivery, and a throwing callback does not stop later ones", { skip }, async () => {
  const { tab, probe, events, until, settled, done } = await open({ queries: true });
  try {
    await probe("subscribeThrowing", "throws", { sql: "select 1" });
    await until("throws", 1);
    await tab.pushSubscription("subscription-1", result("again"));
    assert.deepEqual(await until("throws", 2), ["ready", "ready"]);
    assert.equal((await events("diagnostic")).filter((event) => event.code === "html_subscription_failed").length, 2);
    await probe("unsubscribe", "throws");
    await probe("subscribeOnce", "once", { sql: "select 1" });
    await until("once", 1);
    await settled();
    assert.equal((await events("unsubscribe")).length, 2); // the throwing one, then this one
    assert.deepEqual(await tab.subscriptions(), []);
    assert.equal((await probe("heard", "once")).length, 1);
    await tab.expectHealthy();
  } finally { await done(); }
});

test("the host port closing rejects every pending query and ends every subscription with a terminal port_closed", { skip }, async () => {
  // The host holds every answer until the test releases it, so the frame is retired before the host
  // answered any of them however slowly the test's own calls get through.
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const { tab, probe, until, settled, events, done } = await open({ queries: async ({ sql, parameters }) => { await gate; return { columns: ["sql", "parameters"], rows: [[sql, parameters]], truncated: false }; } });
  try {
    await probe("subscribe", "a", { sql: "select a" });
    await probe("subscribe", "b", { sql: "select b" });
    await probe("start", "pending", { sql: "select slow" });
    // All three have reached the host, which is holding them.
    await tab.page.waitForFunction(() => window.__alphaTabHost.events().filter((event) => event.type === "subscribe" || event.type === "query").length === 3, null, { timeout: 3000 });
    // The frame is retired before the host answered any of them.
    await probe("pagehide");
    assert.deepEqual((await probe("finish", "pending")).error, { name: "Error", status: "error", code: "port_closed", message: "the host port closed before the query was answered" });
    for (const name of ["a", "b"]) assert.deepEqual((await until(name, 1)).map((frame) => [frame.status, frame.code, frame.terminal]), [["error", "port_closed", true]], name);
    // The late host answers change nothing.
    release();
    await settled();
    await tab.page.waitForTimeout(600);
    for (const name of ["a", "b"]) assert.equal((await probe("heard", name)).length, 1, name);
    // The frame does not say goodbye on a closed port, and nothing new gets through.
    assert.equal((await events("unsubscribe")).length, 0);
    const query = await probe("query", { sql: "select after" });
    // Same status as the queries that were in flight at the close: it was not dispatched.
    assert.deepEqual([query.error.status, query.error.code], ["error", "port_closed"]);
    await probe("subscribe", "late", { sql: "select late" });
    assert.deepEqual((await until("late", 1)).map((frame) => [frame.code, frame.terminal]), [["port_closed", true]]);
    assert.equal((await events("query")).length, 1);
    assert.equal((await events("subscribe")).length, 2);
  } finally { release(); await done(); }
});

test("a host that reloads the frame drops its subscriptions and answers its pending queries", { skip }, async () => {
  const { tab, probe, events, done } = await open({ queries: true, latencyMs: 300 });
  try {
    await probe("subscribe", "a", { sql: "select a" });
    await tab.page.waitForTimeout(500);
    assert.deepEqual(await tab.subscriptions(), ["subscription-1"]);
    await tab.reload();
    await tab.frame.locator("#surface").filter({ hasText: /query:/ }).waitFor({ timeout: 3000 });
    await tab.page.waitForTimeout(100);
    assert.deepEqual(await tab.subscriptions(), []);
    assert.equal((await events("subscription-closed")).length, 1);
    // The new document starts from nothing: its first subscription is subscription-1 again.
    await probe("subscribe", "a", { sql: "select a" });
    await tab.page.waitForTimeout(500);
    assert.deepEqual(await tab.subscriptions(), ["subscription-1"]);
  } finally { await done(); }
});
