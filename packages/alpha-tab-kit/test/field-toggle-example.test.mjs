// The source-only field-toggle example (examples/field-toggle.html) running
// against core kit 1.7.0 in Chromium, through the fake host's real bridge
// (app.subscribe.v2 + app.call.v2). It proves the three things the example is
// for: it reads one task through two subscribers, a refused toggle keeps the
// editable draft with Retry, and an uncertain toggle retries under its
// original key. Playwright is an optional peer, as in
// agent-sessions-example.test.mjs.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadChromium, openFakeHost } from "../src/fake-host/playwright.mjs";
import { validateHtml } from "../src/html.mjs";
import { startFakeHost } from "../src/fake-host/server.mjs";

const example = readFileSync(new URL("../examples/field-toggle.html", import.meta.url), "utf8");
const declaration = JSON.parse(readFileSync(new URL("../examples/field-toggle.declaration.json", import.meta.url), "utf8"));
const descriptor = { package: "field-toggle-example", version: "0.1.0", declaration };

const chromium = await loadChromium();
let browser;
before(async () => { if (chromium) browser = await chromium.launch(); });
after(async () => { await browser?.close(); });
const skip = !chromium && "Playwright is not installed";

// Polls Node-side fake-host state (calls, subscriptions) that the frame fills
// in over the bridge after the click returns.
async function until(description, fn, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await fn();
    if (value) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${description}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

const row = (id, lifecycle, kind = "task") => ({
  id, name: `Task ${id}`, type: "WorkItem", kind, lifecycle, summary: null,
  home_id: "folder-1", created_at: "2026-11-01T00:00:00.000Z", updated_at: "2026-11-01T00:00:00.000Z",
  updated_at_ms: 1, is_current: 1, body: "", body_length: 0,
});

// `plan` answers each `update_record` call in order: `{ throw: { status, code,
// message } }` refuses or loses the reply, `{ hold: true }` keeps the call
// open until `releaseHeld` runs, anything else resolves with that result.
// `shapes` overrides the row per id as `{ lifecycle, kind }`; the default is
// a task sitting on open.
async function open(plan, shapes = {}) {
  const page = await browser.newPage();
  const calls = [];
  const held = new Set();
  const tab = await openFakeHost(page, {
    descriptor, html: example, latencyMs: 0,
    queries: (query) => {
      // Parameters travel as `{ type, value }` objects (see recordQuery).
      const first = query.parameters?.[0];
      const id = (typeof first === "string" ? first : first?.value) || "task-1";
      const shape = row(id, shapes[id]?.lifecycle ?? "open", shapes[id]?.kind ?? "task");
      return { columns: Object.keys(shape), rows: [shape], truncated: false };
    },
    calls: (operation, args) => {
      calls.push({ operation, args });
      const step = plan[calls.length - 1] ?? { return: { id: args.id } };
      if (step.throw) throw Object.assign(new Error(step.throw.message ?? step.throw.code), step.throw);
      if (step.hold) return new Promise((resolve) => { held.add(() => resolve({ id: args.id })); });
      return step.return;
    },
  });
  const frame = tab.frame;
  const openTask = async (id) => {
    await frame.locator("#record").fill(id);
    await frame.locator("#open").click();
    await frame.getByText(`Task ${id}`).waitFor({ timeout: 10_000 });
    // Both subscribers (useRecord + the one-row useRecordList) arrive over
    // the bridge just after the first paint.
    await until("both subscriptions", async () => (await tab.subscriptions()).length === 2);
  };
  const untilCalls = (count) => until(`${count} call(s)`, () => calls.length >= count && calls.slice());
  return {
    page, tab, frame, calls, openTask, untilCalls,
    listSubscription: async () => {
      // The one-row useRecordList query filters `id IN (...)`; the record
      // query binds a single `id = ?1`.
      const events = await tab.events();
      const found = events.find((event) => event.type === "subscribe" && /\bid IN \(/.test(String(event.query?.sql ?? "")));
      assert.ok(found, `list subscription not found in ${JSON.stringify(events.map((event) => event.type))}`);
      return found.subscription_id;
    },
    releaseHeld: () => { for (const release of held) release(); held.clear(); },
    done: async () => { await tab.close(); await page.close(); },
  };
}

test("the example is a complete package: no validator errors and it passes admission on its exact bytes", async () => {
  assert.deepEqual(validateHtml(example).filter((item) => item.severity === "error"), []);
  assert.equal((example.match(/<script type="module">/g) || []).length, 1);
  assert.doesNotMatch(example, /\bimport\s|<script[^>]+src=/);
  const fake = await startFakeHost({ html: example, descriptor });
  await fake.close();
});

test("reads one task through two subscribers; a refused toggle keeps the editable draft and Retry sends again", { skip }, async () => {
  const tab = await open([{ throw: { status: "refused", code: "conflict", message: "Changed" } }, { return: { id: "task-1" } }]);
  try {
    await tab.openTask("task-1");
    await tab.frame.locator("#summary").fill("needs review");
    await tab.frame.locator("#toggle").click();
    const [first] = await tab.untilCalls(1);
    assert.equal(first.operation, "update_record");
    const { idempotency_key, ...rest } = first.args;
    assert.deepEqual(rest, { id: "task-1", reason: "Toggled in field-toggle example.", lifecycle: "completed", summary: "needs review" });
    assert.match(idempotency_key, /^[A-Za-z0-9._:-]+$/);
    // Refusal is normal admission: the draft is untouched, the reason is shown,
    // and Retry/Discard stand by the entry.
    // (Substring match: the status element also holds the Retry/Discard buttons.)
    await tab.frame.getByText("Not sent").first().waitFor({ timeout: 10_000 });
    assert.equal(await tab.frame.locator("#summary").inputValue(), "needs review");
    assert.match(await tab.frame.locator("#app").textContent(), /Reason: Changed/);
    await tab.frame.getByRole("button", { name: "Retry" }).click();
    const [, second] = await tab.untilCalls(2);
    assert.notEqual(second.args.idempotency_key, idempotency_key);
    await tab.frame.getByText("Sent").first().waitFor({ timeout: 10_000 });
    await tab.tab.expectHealthy();
  } finally { await tab.done(); }
});

test("record navigation keeps each record's draft and the refused entry's target", { skip }, async () => {
  const tab = await open([
    { throw: { status: "refused", code: "conflict", message: "Changed" } },
    { return: { id: "task-2" } },
  ]);
  try {
    await tab.openTask("task-1");
    await tab.frame.locator("#summary").fill("t1 note");
    await tab.frame.locator("#toggle").click();
    await tab.untilCalls(1);
    await tab.frame.getByText("Not sent").first().waitFor({ timeout: 10_000 });
    // Switching records keeps the refused entry with its target but starts a
    // fresh draft: task-1's summary must not leak into task-2's toggle.
    await tab.openTask("task-2");
    assert.equal(await tab.frame.locator("#summary").inputValue(), "");
    assert.match(await tab.frame.locator("#app").textContent(), /for task-1/);
    await tab.frame.locator("#toggle").click();
    const [, task2] = await tab.untilCalls(2);
    const { idempotency_key: _ignored, ...sent } = task2.args;
    assert.deepEqual(sent, { id: "task-2", reason: "Toggled in field-toggle example.", lifecycle: "completed" });
    await tab.frame.getByText("Sent").first().waitFor({ timeout: 10_000 });
    // Back on task-1, its draft and its refused entry are intact.
    await tab.openTask("task-1");
    assert.equal(await tab.frame.locator("#summary").inputValue(), "t1 note");
    assert.match(await tab.frame.locator("#app").textContent(), /for task-1/);
    await tab.tab.expectHealthy();
  } finally { await tab.done(); }
});

test("unsupported tokens never send: a blocked task and a non-task show their state with the toggle off", { skip }, async () => {
  const tab = await open([], { "task-blocked": { lifecycle: "blocked" }, "note-1": { kind: "note", lifecycle: "open" } });
  try {
    await tab.openTask("task-blocked");
    assert.match(await tab.frame.locator("#app").textContent(), /task\/blocked/);
    assert.equal(await tab.frame.locator("#toggle").isDisabled(), true);
    await tab.openTask("note-1");
    assert.match(await tab.frame.locator("#app").textContent(), /note\/open/);
    assert.equal(await tab.frame.locator("#toggle").isDisabled(), true);
    assert.equal(tab.calls.length, 0);
    await tab.tab.expectHealthy();
  } finally { await tab.done(); }
});

test("timing: the new status shows at once while Sending, and stays through the host's fresh rows until the write is confirmed", { skip }, async () => {
  // Controlled fixture timing, not production latency: the held call proves
  // the kit lays the person's own status change over the record at once (an
  // update_record sent through useWrite is a pending edit, kit 1.7.9) and that
  // the safe write feedback still says Sending until the host confirms. The
  // fixture, standing in for the host, then delivers fresh subscription rows
  // with the write applied while its call is still open: nothing moves.
  const tab = await open([{ hold: true }]);
  try {
    await tab.openTask("task-1");
    const lifecycle = () => tab.frame.locator("article strong").first().textContent();
    // Status counts off the rendered WriteStatus elements (body text would
    // also match the inline script source, which names these statuses).
    const feedback = () => tab.frame.locator("body").evaluate(() => ({
      pending: document.querySelectorAll('p[data-write-status="pending"]').length,
      sent: document.querySelectorAll('p[data-write-status="sent"]').length,
    }));
    const snapshot = async () => {
      const counts = await feedback();
      return `lifecycle=${await lifecycle()} pending=${counts.pending} sent=${counts.sent}`;
    };
    const observed = [];
    observed.push(await snapshot());
    await tab.frame.locator("#toggle").click();
    await tab.untilCalls(1);
    await until("Sending feedback", async () => (await feedback()).pending === 1);
    observed.push(await snapshot());
    // Host fresh deliveries (fixture-driven): both subscribers get rows with
    // the write applied while its call is still open.
    const applied = row("task-1", "completed");
    for (const id of await tab.tab.subscriptions()) {
      await tab.tab.pushSubscription(id, { columns: Object.keys(applied), rows: [applied], truncated: false });
    }
    await until("fresh rows delivered", async () => (await lifecycle()) === "completed");
    observed.push(await snapshot());
    tab.releaseHeld();
    await tab.frame.getByText("Sent").first().waitFor({ timeout: 10_000 });
    observed.push(await snapshot());
    assert.deepEqual(observed, [
      "lifecycle=open pending=0 sent=0",
      "lifecycle=completed pending=1 sent=0",
      "lifecycle=completed pending=1 sent=0",
      "lifecycle=completed pending=0 sent=1",
    ]);
    await tab.tab.expectHealthy();
  } finally { await tab.done(); }
});

test("an uncertain toggle retries under its original key; a scope fence drops it and the late answer changes nothing", { skip }, async () => {
  const tab = await open([
    { throw: { status: "uncertain", code: "call_timeout", message: "No answer" } },
    { hold: true },
  ]);
  try {
    await tab.openTask("task-1");
    await tab.frame.locator("#summary").fill("fence note");
    await tab.frame.locator("#toggle").click();
    await tab.frame.getByText("May not have sent").waitFor({ timeout: 10_000 });
    // Uncertain entries offer Retry but never Discard.
    assert.equal(await tab.frame.getByRole("button", { name: "Retry" }).count(), 1);
    assert.equal(await tab.frame.getByRole("button", { name: "Discard" }).count(), 0);
    const [uncertain] = await tab.untilCalls(1);
    const key = uncertain.args.idempotency_key;
    await tab.frame.getByRole("button", { name: "Retry" }).click();
    const [, retried] = await tab.untilCalls(2);
    assert.equal(retried.args.idempotency_key, key);
    // The fence on the list reader only: the record still looks ready, yet the
    // entry and the draft are dropped and submission locks until a reload.
    await tab.tab.failSubscription(await tab.listSubscription(), "scope_changed", "Moved", false);
    await tab.frame.locator("body").evaluate(() => new Promise((resolve, reject) => {
      const deadline = Date.now() + 10_000;
      const poll = () => {
        const done = !document.body.textContent.includes("May not have sent")
          && document.querySelector("#summary")?.value === "";
        if (done) resolve(true);
        else if (Date.now() > deadline) reject(new Error("list-only fence did not drop the entry and draft"));
        else setTimeout(poll, 50);
      };
      poll();
    }));
    assert.equal(await tab.frame.locator("#toggle").isDisabled(), true);
    assert.match(await tab.frame.locator("#app").textContent(), /Reload the page to continue/);
    tab.releaseHeld();
    await tab.page.waitForTimeout(300);
    assert.equal(tab.calls.length, 2);
    assert.doesNotMatch(await tab.frame.locator("#app").textContent(), /May not have sent|Sent/);
    await tab.tab.expectHealthy();
  } finally { await tab.done(); }
});
