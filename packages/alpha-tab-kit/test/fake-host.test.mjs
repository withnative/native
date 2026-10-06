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
  const tab = await openFakeHost(page, { descriptor, html, fixtures: fixtures(), latencyMs: 30, ...options });
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
    const started = (await tab.events()).filter((event) => event.type === "read-start").map((event) => event.need);
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
    const frame = tab.page.frames().find((candidate) => candidate.url().endsWith("/frame"));
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
    const frame = tab.page.frames().find((candidate) => candidate.url().endsWith("/frame"));
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
    const frame = tab.page.frames().find((candidate) => candidate.url().endsWith("/frame"));
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

// Peak overlapping reads from the host's own event timeline: +1 at each
// dispatched read, -1 at each answer. Ends sort before starts at the same
// rounded millisecond so the count never overstates the real overlap.
function peakConcurrency(events) {
  const deltas = [];
  for (const event of events) {
    if (event.type === "read-start") deltas.push([event.at, 1]);
    else if (event.type === "read-ok" || event.type === "read-error") deltas.push([event.at, -1]);
  }
  deltas.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  let current = 0, peak = 0;
  for (const [, delta] of deltas) { current += delta; peak = Math.max(peak, current); }
  return peak;
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
        const maxConcurrent = peakConcurrency(events);
        const row = { latencyMs, n, calls: starts.length, maxConcurrent, busy: summary.busy, dropped: summary.dropped.length,
          order: outcome.order.join(","), completionMs: outcome.ms };
        evidence.push(row);
        assert.deepEqual(outcome.statuses, Array(n).fill("ok"));
        assert.equal(starts.length, n, "one host call per read");
        assert.deepEqual(starts.map((event) => event.params.id), Array.from({ length: n }, (_, i) => `r${i}`), "dispatched FIFO");
        assert.equal(summary.busy, 0);
        assert.equal(summary.dropped.length, 0);
        // Several reads overlap, and the FIFO queue keeps real concurrency
        // at or below the shell's named in-flight cap.
        assert.ok(maxConcurrent >= Math.min(n, cap), `${n} reads: expected at least ${Math.min(n, cap)} together, saw ${maxConcurrent}`);
        assert.ok(maxConcurrent <= cap, `${n} reads: expected no more than ${cap} together, saw ${maxConcurrent}`);
        // Discrete windows: with one per-read latency, the last answer lands
        // in ceil(n / cap) rounds, not n.
        assert.ok(outcome.ms <= Math.ceil(n / cap) * latencyMs + 200, `${n} reads at ${latencyMs} ms finished in ${outcome.ms} ms`);
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
    assert.ok(events.some((event) => event.type === "read-timeout" && event.params.id === "r0"));
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
