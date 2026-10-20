// Browser tests for the fake host. Playwright is an optional peer: these
// skip when it is not installed, except in CI (see README "Running the tests").
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadChromium, openFakeHost } from "../src/fake-host/playwright.mjs";
import { LIMITS } from "../src/limits.mjs";

const fixture = (name) => readFileSync(new URL(`fixtures/${name}`, import.meta.url), "utf8");
const descriptor = JSON.parse(fixture("probe-descriptor.json"));
const rows = (n) => Array.from({ length: n }, (_, i) => ({ id: `r${i}`, name: `Task ${i}` }));
const fixtures = (extra = {}) => ({
  sql: {
    "probe.list": rows(3),
    "probe.body": ({ id }) => [{ id, body: `Body of ${id}` }],
    "probe.links": () => [{ target_id: "t", relationship: "part_of" }],
    ...extra,
  },
});

const chromium = await loadChromium();
let browser;
before(async () => { if (chromium) browser = await chromium.launch(); });
after(async () => { await browser?.close(); });
// Locally, a missing Playwright skips the browser tests. In CI (GitHub
// Actions sets CI) or with ALPHA_TAB_KIT_REQUIRE_BROWSER, it fails instead,
// so the fidelity tests cannot go green by not running.
const required = Boolean(process.env.CI || process.env.ALPHA_TAB_KIT_REQUIRE_BROWSER);
const skip = !chromium && "Playwright is not installed";
test("Playwright is resolvable where the browser tests are required", { skip: !required && "not required here" }, () => {
  assert.ok(chromium, "Playwright could not be resolved (ALPHA_TAB_KIT_PLAYWRIGHT, the current directory, web/workbench, or import('playwright')): the fake-host browser tests would silently skip");
});

async function open(html, options = {}) {
  const page = await browser.newPage();
  const selected = options.calls ? { ...descriptor, declaration: { contract: "native.app.v2", needs: [], effects: [] } } : descriptor;
  const tab = await openFakeHost(page, { descriptor: selected, html, fixtures: fixtures(), latencyMs: 30, ...options });
  return { page, tab, done: async () => { await tab.close(); await page.close(); } };
}

test("a tab that sends two reads at once gets both, in order, as in the alpha shell", { skip }, async () => {
  const { tab, done } = await open(fixture("probe-concurrent.html"));
  try {
    await tab.frame.locator("button").first().click();
    await tab.frame.locator("#links").filter({ hasText: "1 links" }).waitFor({ timeout: 3000 });
    assert.equal(await tab.frame.locator("#body").textContent(), "Body of r0");
    const summary = await tab.expectHealthy();
    assert.equal(summary.busy, 0);
    assert.equal(summary.reads, 2);
    const started = (await tab.events()).filter((event) => event.type === "read-start")
      .flatMap((event) => event.requests.map((read) => read.need));
    assert.deepEqual(started, ["probe.body", "probe.links"]);
  } finally { await done(); }
});

test("a tab that queues reads and retries busy loads everything", { skip }, async () => {
  const { tab, done } = await open(fixture("probe-queued.html"));
  try {
    await tab.frame.locator("button").first().click();
    await tab.frame.locator("#links").filter({ hasText: "1 links" }).waitFor({ timeout: 3000 });
    assert.equal(await tab.frame.locator("#body").textContent(), "Body of r0");
    const summary = await tab.expectHealthy();
    assert.equal(summary.reads, 2);
    const events = await tab.events();
    assert.deepEqual(events.find((event) => event.type === "view-state").view_state, { value: { open: "r0" } });
  } finally { await done(); }
});

test("snapshots deliver at most 200 rows with the full count and truncated: true", { skip }, async () => {
  const { tab, done } = await open(fixture("probe-queued.html"), { fixtures: fixtures({ "probe.list": rows(250) }) });
  try {
    assert.equal(await tab.frame.locator("#list").getAttribute("data-count"), "250 truncated");
    assert.equal(await tab.frame.locator("#list button").count(), 200);
  } finally { await done(); }
});

test("the real bridge's own caps apply: 8 pending reads, 1 MiB answers", { skip }, async () => {
  const big = [{ id: "x", body: "x".repeat(1_100_000) }];
  const { tab, done } = await open(fixture("probe-queued.html"), { fixtures: fixtures({ "probe.body": () => big }), latencyMs: 20 });
  try {
    const frame = tab.page.frames().find((candidate) => { try { return new URL(candidate.url()).pathname === "/frame"; } catch { return false; } });
    const outcome = await frame.evaluate(async () => {
      const replies = [];
      let threw = null;
      for (let i = 0; i < 9; i += 1) {
        try { replies.push(window.nativeArtifact.read("probe.body", { id: `r${i}` })); } catch (error) { threw = `${i}: ${error.message}`; }
      }
      const settled = await Promise.all(replies);
      return { threw, statuses: settled.map((reply) => `${reply.status}/${reply.code ?? ""}`) };
    });
    assert.equal(outcome.threw, "8: too many reads in flight");
    // The shell queues all eight; each >1 MiB answer is replaced by the bridge.
    assert.deepEqual(outcome.statuses, Array(8).fill("unavailable/too_large"));
    assert.equal((await tab.audit()).busy, 0);
  } finally { await done(); }
});

test("undeclared needs and bad params are refused", { skip }, async () => {
  const { tab, done } = await open(fixture("probe-queued.html"));
  try {
    const frame = tab.page.frames().find((candidate) => { try { return new URL(candidate.url()).pathname === "/frame"; } catch { return false; } });
    const outcome = await frame.evaluate(async () => {
      let undeclared = null;
      try { window.nativeArtifact.read("probe.nope", {}); } catch (error) { undeclared = error.message; }
      const missing = await window.nativeArtifact.read("probe.body", {});
      const long = await window.nativeArtifact.read("probe.body", { id: "x".repeat(65) });
      return { undeclared, missing: missing.code, long: long.code };
    });
    assert.deepEqual(outcome, { undeclared: "this host offers no such read", missing: "missing_sql_param", long: "invalid_sql_param" });
  } finally { await done(); }
});

test("sample mode delivers the host's sample input and offers no reads", { skip }, async () => {
  const { tab, done } = await open(fixture("probe-queued.html"), { mode: "sample" });
  try {
    assert.equal(await tab.frame.locator("#list").getAttribute("data-count"), "sample");
    const frame = tab.page.frames().find((candidate) => { try { return new URL(candidate.url()).pathname === "/frame"; } catch { return false; } });
    const outcome = await frame.evaluate(() => {
      try { window.nativeArtifact.read("probe.body", { id: "r0" }); return "no throw"; } catch (error) { return error.message; }
    });
    assert.equal(outcome, "this host offers no such read");
    assert.equal(await frame.evaluate(() => window.nativeArtifact.input.mode), "sample");
  } finally { await done(); }
});

test("pushInput delivers a new snapshot through the bridge", { skip }, async () => {
  let generation = 0;
  const { tab, done } = await open(fixture("probe-queued.html"), { fixtures: fixtures({ "probe.list": () => rows(3 + generation++) }) });
  try {
    await tab.pushInput();
    await tab.frame.locator("#list").and(tab.frame.locator('[data-count="4"]')).waitFor({ timeout: 3000 });
    assert.ok((await tab.events()).some((event) => event.type === "input-applied"));
  } finally { await done(); }
});

// Issue `n` reads at once from inside the frame and time them to the last
// answer. Runs in the frame, through the real bridge.
async function burst(tab, n) {
  const frame = tab.page.frames().find((candidate) => { try { return new URL(candidate.url()).pathname === "/frame"; } catch { return false; } });
  return frame.evaluate(async (count) => {
    const started = performance.now();
    const order = [];
    const replies = await Promise.all(Array.from({ length: count }, (_, i) =>
      window.nativeArtifact.read("probe.body", { id: `r${i}` }).then((reply) => { order.push(i); return reply; })));
    return { ms: Math.round(performance.now() - started), order, statuses: replies.map((reply) => reply.status) };
  }, n);
}

// The host's scheduling, read off its timeline in logged order (the shell logs
// from one thread, so the order is causal) rather than off timestamps. A tool
// call is in flight from its `read-start` until its last read answers; a read
// is queued from `read-queued` until a `read-start` carries it. Returns the
// peak number of calls in flight, how many `read-queued` events it saw (the
// "slot free and work queued" rule below is only meaningful if they are there)
// and every way the order broke the contract:
//   - more than `cap` calls in flight after a dispatch;
//   - an answer logged while a slot was free and a read was still queued, i.e.
//     the next round did not start as soon as a slot freed. The pump runs in a
//     microtask after a `read-queued` and synchronously when a call settles, so
//     in a correct host nothing else is logged between a slot freeing (or a read
//     queueing) and the dispatch it owes.
function schedule(events, cap) {
  const violations = [];
  const queued = new Set(), callOf = new Map();
  let inFlight = 0, peak = 0, queuedSeen = 0;
  const answered = (id) => {
    const call = callOf.get(id);
    if (!call || !call.pending.delete(id)) return;
    if (call.pending.size === 0) inFlight -= 1;
  };
  events.forEach((event, index) => {
    if (event.type === "read-queued") { queued.add(event.request_id); queuedSeen += 1; return; }
    if (event.type === "read-start") {
      const call = { pending: new Set(event.requests.map((read) => read.request_id)) };
      for (const id of call.pending) { queued.delete(id); callOf.set(id, call); }
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      if (inFlight > cap) violations.push(`event ${index}: ${inFlight} calls in flight, cap ${cap}`);
      return;
    }
    const ending = event.request_id && ["read-ok", "read-error", "read-drained"].includes(event.type) ? [event.request_id]
      : event.type === "read-timeout" ? event.requests : null;
    if (!ending) return;
    if (inFlight < cap && queued.size > 0)
      violations.push(`event ${index} (${event.type}): a slot was free with ${queued.size} read(s) queued and no dispatch`);
    for (const id of ending) answered(id);
  });
  return { peak, violations, queuedSeen };
}

test("reads dispatch several at a time, in FIFO order, never above the in-flight cap (scheduling evidence, not engine throughput)", { skip }, async () => {
  const cap = LIMITS.shell.reads_in_flight;
  const evidence = [];
  for (const latencyMs of [40, 250]) {
    for (const n of [1, 4, 8]) {
      const { tab, done } = await open(fixture("probe-queued.html"), { latencyMs });
      try {
        const outcome = await burst(tab, n);
        const events = await tab.events();
        const starts = events.filter((event) => event.type === "read-start");
        const summary = await tab.expectHealthy();
        const { peak: maxConcurrent, violations, queuedSeen } = schedule(events, cap);
        // Every accepted read is logged queued, so the causal check below has
        // its input: without these events it would pass vacuously.
        assert.equal(queuedSeen, n, `${n} reads: expected a read-queued event for each, saw ${queuedSeen}`);
        const row = { latencyMs, n, calls: starts.length, maxConcurrent, busy: summary.busy, dropped: summary.dropped.length,
          order: outcome.order.join(","), completionMs: outcome.ms };
        evidence.push(row);
        assert.deepEqual(outcome.statuses, Array(n).fill("ok"));
        assert.ok(starts.length >= 1 && starts.length <= n, "at least one call, never more than one per read");
        assert.deepEqual(starts.flatMap((event) => event.requests.map((read) => read.params.id)),
          Array.from({ length: n }, (_, i) => `r${i}`), "dispatched FIFO");
        assert.equal(summary.busy, 0);
        assert.equal(summary.dropped.length, 0);
        // Several reads overlap, and the FIFO queue keeps real concurrency
        // at or below the shell's named in-flight cap.
        assert.ok(maxConcurrent >= Math.min(n, cap), `${n} reads: expected at least ${Math.min(n, cap)} together, saw ${maxConcurrent}`);
        assert.ok(maxConcurrent <= cap, `${n} reads: expected no more than ${cap} together, saw ${maxConcurrent}`);
        // Rounds, not n: whenever a slot is free and a read is queued, the
        // next call is dispatched before anything else is answered, so the
        // last answer lands in ceil(n / cap) rounds however long a round takes.
        // (Read off the host's event order; a wall-clock bound on the last
        // answer measured the machine's load as much as the scheduling.)
        assert.deepEqual(violations, [], `${n} reads at ${latencyMs} ms: scheduling broke the contract`);
      } finally { await done(); }
    }
  }
  for (const row of evidence) console.log(`# fake-host S2 ${JSON.stringify(row)}`);
});

test("a timed-out read retires only its own ticket; the frame's other reads keep going", { skip }, async () => {
  const { tab, done } = await open(fixture("probe-queued.html"), {
    readTimeoutMs: 200, latencyMs: (need, params) => (params?.id === "r0" ? 1000 : 20),
  });
  try {
    const outcome = await burst(tab, 3);
    assert.deepEqual(outcome.statuses, ["unavailable", "ok", "ok"]);
    const events = await tab.events();
    assert.equal(events.filter((event) => event.type === "read-start").length, 3, "the other reads still dispatched");
    const slow = events.find((event) => event.type === "read-start" && event.requests.some((read) => read.params?.id === "r0"));
    const slowId = slow.requests.find((read) => read.params?.id === "r0").request_id;
    assert.ok(events.some((event) => event.type === "read-timeout" && event.requests.includes(slowId)));
    assert.ok(!events.some((event) => event.type === "frame-closed"), "one read's timeout does not retire the frame");
    assert.ok(!events.some((event) => event.type === "read-drained"), "no accepted read is drained by one timeout");
    // The frame is still live: a later read is admitted and answered.
    const frame = tab.page.frames().find((candidate) => { try { return new URL(candidate.url()).pathname === "/frame"; } catch { return false; } });
    const late = await frame.evaluate(async () => {
      const reply = await window.nativeArtifact.read("probe.body", { id: "r-after" });
      return `${reply.status}/${reply.code ?? ""}`;
    });
    assert.equal(late, "ok/");
  } finally { await done(); }
});

test("a reload with reads on the wire drains once and retires the frame; the old reads' timers and answers reach nothing", { skip }, async () => {
  const { tab, done } = await open(fixture("probe-queued.html"), { latencyMs: 300, readTimeoutMs: 400 });
  try {
    const frame = tab.page.frames().find((candidate) => { try { return new URL(candidate.url()).pathname === "/frame"; } catch { return false; } });
    await frame.evaluate(() => { for (let i = 0; i < 3; i += 1) window.nativeArtifact.read("probe.body", { id: `r${i}` }); });
    // All three dispatch together (the in-flight cap is above three), then reload.
    await tab.page.waitForFunction(() => window.__alphaTabHost.events().filter((event) => event.type === "read-start").length >= 3);
    await tab.reload();
    await tab.page.waitForFunction(() => window.__alphaTabHost.events().some((event) => event.type === "reload-retired"));
    // The one bounded timer wait: past the old reads' latency and timeout.
    await tab.page.waitForTimeout(700);
    const events = await tab.events();
    assert.deepEqual(events.filter((event) => event.type === "read-drained").map((event) => [event.params.id, event.code, event.active]),
      [["r0", "tab_reloaded", true], ["r1", "tab_reloaded", true], ["r2", "tab_reloaded", true]]);
    assert.equal(events.filter((event) => event.type === "init").length, 1, "the new document is not re-handshaken on the retired frame");
    assert.equal(events.filter((event) => event.type === "read-start").length, 3, "nothing more is dispatched");
    assert.ok(!events.some((event) => ["read-timeout", "read-ok", "read-error"].includes(event.type)), "the old reads' timers and late answers do nothing");
  } finally { await done(); }
});

test("a reload with no read on the wire re-handshakes the new document, which reads at once", { skip }, async () => {
  const { tab, done } = await open(fixture("probe-queued.html"), { latencyMs: 20 });
  try {
    assert.deepEqual((await burst(tab, 1)).statuses, ["ok"]);
    await tab.reload();
    await tab.page.waitForFunction(() => window.__alphaTabHost.events().filter((event) => event.type === "ready").length >= 2);
    const next = await burst(tab, 2);
    assert.deepEqual(next.statuses, ["ok", "ok"]);
    const events = await tab.events();
    assert.ok(!events.some((event) => event.type === "reload-retired" || event.type === "read-drained"));
  } finally { await done(); }
});

// App contract v2: `call` exists only on a host that offers app.call.v2.
test("a frame on a host offering app.call.v2 calls and gets the canned result; the alias is the same frozen function", { skip }, async () => {
  const { tab, done } = await open(fixture("probe-call.html"), { calls: true });
  try {
    await tab.frame.locator("#surface").filter({ hasText: "call:function native:object" }).waitFor({ timeout: 3000 });
    await tab.frame.locator("#call").click();
    await tab.frame.locator("#result").filter({ hasText: "canned" }).waitFor({ timeout: 3000 });
    const answer = JSON.parse(await tab.frame.locator("#result").textContent());
    assert.deepEqual(answer, { request_id: "call-1", result: { canned: true, operation: "probe_echo", args: { hello: "world" } } });
    const surface = await tab.frame.locator("body").evaluate(() => window.probe.surface());
    assert.deepEqual(surface, { call: "function", native: "object", nativeCall: "function", nativeFrozen: true, same: true, artifactFrozen: true });
    assert.deepEqual((await tab.events()).filter((event) => event.type === "call").map((event) => event.operation), ["probe_echo"]);
    await tab.expectHealthy();
  } finally {
    await done();
  }
});

test("a call rejects with {status, code, message} when the host's handler fails", { skip }, async () => {
  const { tab, done } = await open(fixture("probe-call.html"), { calls: (operation) => { throw new Error(`no such operation ${operation}`); } });
  try {
    await tab.frame.locator("#surface").filter({ hasText: "call:function" }).waitFor({ timeout: 3000 });
    const answer = await tab.frame.locator("body").evaluate(() => window.probe.call("probe_echo", {}));
    assert.equal(answer.rejected, true);
    assert.equal(answer.status, "error");
    assert.equal(answer.code, "handler_error");
    assert.match(answer.message, /no such operation probe_echo/);
  } finally {
    await done();
  }
});

test("a handler can answer a call refused or uncertain by throwing an error that carries the status", { skip }, async () => {
  const calls = (operation) => { throw Object.assign(new Error(`${operation} said so`), operation === "probe_refuse" ? { status: "refused", code: "not_allowed" } : operation === "probe_5xx" ? { status: "error", code: "engine_error" } : { status: "uncertain" }); };
  const { tab, done } = await open(fixture("probe-call.html"), { calls });
  try {
    await tab.frame.locator("#surface").filter({ hasText: "call:function" }).waitFor({ timeout: 3000 });
    const refused = await tab.frame.locator("body").evaluate(() => window.probe.call("probe_refuse", {}));
    assert.deepEqual([refused.status, refused.code], ["refused", "not_allowed"]);
    const uncertain = await tab.frame.locator("body").evaluate(() => window.probe.call("probe_unsure", {}));
    assert.deepEqual([uncertain.status, uncertain.code], ["uncertain", "uncertain"]);
    assert.match(uncertain.message, /probe_unsure said so/);
    const serverError = await tab.frame.locator("body").evaluate(() => window.probe.call("probe_5xx", {}));
    assert.deepEqual([serverError.status, serverError.code], ["error", "engine_error"]);
  } finally {
    await done();
  }
});

test("call refuses oversize args and a ninth in-flight call at the bridge, before the host hears of them", { skip }, async () => {
  const { tab, done } = await open(fixture("probe-call.html"), { calls: true, latencyMs: 150 });
  try {
    await tab.frame.locator("#surface").filter({ hasText: "call:function" }).waitFor({ timeout: 3000 });
    const big = await tab.frame.locator("body").evaluate(() => window.probe.call("probe_echo", { blob: "x".repeat(262144) }));
    assert.equal(big.status, "refused");
    assert.equal(big.code, "too_large");
    const outcomes = await tab.frame.locator("body").evaluate(() => window.probe.burst(9));
    assert.deepEqual(outcomes.filter((outcome) => outcome === "ok").length, 8);
    assert.deepEqual(outcomes.filter((outcome) => outcome === "busy").length, 1);
    assert.equal((await tab.events()).filter((event) => event.type === "call").length, 8);
  } finally {
    await done();
  }
});

test("on a host that does not offer app.call.v2, neither nativeArtifact.call nor window.native exists", { skip }, async () => {
  const { tab, done } = await open(fixture("probe-call.html"));
  try {
    await tab.frame.locator("#surface").filter({ hasText: "call:undefined native:undefined" }).waitFor({ timeout: 3000 });
    const surface = await tab.frame.locator("body").evaluate(() => window.probe.surface());
    assert.equal(surface.call, "undefined");
    assert.equal(surface.native, "undefined");
    assert.equal(surface.artifactFrozen, true);
    assert.equal((await tab.events()).filter((event) => event.type === "call").length, 0);
  } finally {
    await done();
  }
});

test("args that serialize to a scalar or an array are refused malformed, whatever the object says", { skip }, async () => {
  const { tab, done } = await open(fixture("probe-call.html"), { calls: true });
  try {
    await tab.frame.locator("#surface").filter({ hasText: "call:function" }).waitFor({ timeout: 3000 });
    const outcomes = await tab.frame.locator("body").evaluate(async () => [
      await window.probe.call("probe_echo", { toJSON: () => 5 }),
      await window.probe.call("probe_echo", { toJSON: () => [1] }),
      await window.probe.call("probe_echo", { toJSON: () => null }),
      await window.probe.call("probe_echo", [1]),
    ]);
    for (const outcome of outcomes) assert.deepEqual([outcome.status, outcome.code], ["refused", "malformed"]);
    assert.equal((await tab.events()).filter((event) => event.type === "call").length, 0);
  } finally {
    await done();
  }
});

test("when the port goes away every pending call rejects once, uncertain, and later calls are not stuck on busy", { skip }, async () => {
  const { tab, done } = await open(fixture("probe-call.html"), { calls: true, latencyMs: 400 });
  try {
    await tab.frame.locator("#surface").filter({ hasText: "call:function" }).waitFor({ timeout: 3000 });
    const outcomes = await tab.frame.locator("body").evaluate(async () => {
      const pending = Array.from({ length: 8 }, (_, index) => window.probe.call("probe_echo", { index }));
      window.dispatchEvent(new Event("pagehide"));
      const settled = await Promise.all(pending);
      const after = await window.probe.call("probe_echo", {});
      return { settled: settled.map((item) => [item.status, item.code]), after: [after.status, after.code] };
    });
    assert.deepEqual(outcomes.settled, Array(8).fill(["uncertain", "port_closed"]));
    assert.deepEqual(outcomes.after, ["refused", "port_closed"]);
  } finally {
    await done();
  }
});

test("a reload with a call on the wire answers it uncertain on the old port, once", { skip }, async () => {
  const { tab, done } = await open(fixture("probe-call.html"), { calls: true, latencyMs: 600 });
  try {
    await tab.frame.locator("#surface").filter({ hasText: "call:function" }).waitFor({ timeout: 3000 });
    await tab.frame.locator("body").evaluate(() => { window.probe.call("probe_echo", { slow: true }); });
    await tab.frame.locator("body").evaluate(() => new Promise((resolve) => setTimeout(resolve, 100)));
    await tab.reload();
    await tab.page.waitForFunction(() => window.__alphaTabHost.events().some((event) => event.type === "call-drained"), null, { timeout: 3000 });
    await tab.page.waitForTimeout(800);
    const drained = (await tab.events()).filter((event) => event.type === "call-drained");
    assert.deepEqual(drained.map((event) => event.code), ["tab_reloaded"]);
  } finally {
    await done();
  }
});
