// The source-only subscription-budget example (examples/subscription-budget.html)
// running against core kit 1.7.0 in Chromium through the fake host's real bridge.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadChromium, openFakeHost } from "../src/fake-host/playwright.mjs";
import { validateHtml } from "../src/html.mjs";
import { validatePackage } from "../src/validate.mjs";
import { startFakeHost } from "../src/fake-host/server.mjs";
import { createKitDelivery, readKitAssets } from "../src/fake-host/kit-assets.mjs";

// This is the pre-sharing reproduction, independent of the host's current
// default. Kit 1.7.1 duplicate sharing is exercised in shared-records-browser.
const kitDelivery = createKitDelivery(await readKitAssets(), {
  schema: "native.app-kit.selector.v1", selections: [{ major: 1, version: "1.7.0" }],
});

const example = readFileSync(new URL("../examples/subscription-budget.html", import.meta.url), "utf8");
const declaration = JSON.parse(readFileSync(new URL("../examples/subscription-budget.declaration.json", import.meta.url), "utf8"));
const descriptor = { package: "agent.subscription-budget", version: "0.1.0", runtime: "native.html.v1", declaration };

const chromium = await loadChromium();
let browser;
before(async () => { if (chromium) browser = await chromium.launch(); });
after(async () => { await browser?.close(); });
const skip = !chromium && "Playwright is not installed";

const metaColumns = ["id", "name", "type", "kind", "lifecycle", "summary", "home_id", "created_at", "updated_at", "updated_at_ms", "is_current"];

function makeFixtures() {
  const mainSlides = Array.from({ length: 19 }, (_, index) => {
    const num = String(index + 1).padStart(2, "0");
    const id = `slide-${num}`;
    const embeds = index === 12 ? " [[embed:fig-1]] [[embed:fig-2]] [[embed:fig-3]]" : "";
    return {
      id,
      name: `Slide ${num}: Topic ${index + 1}`,
      type: "Document",
      kind: "note",
      lifecycle: "open",
      summary: null,
      home_id: "deck-main",
      created_at: "2026-11-10T00:00:00.000Z",
      updated_at: "2026-11-10T00:00:00.000Z",
      updated_at_ms: 1000 + index,
      is_current: 1,
      body: `Body for slide ${num}.${embeds}`,
    };
  });
  const altSlides = [1, 2].map((n) => ({
    id: `alt-0${n}`,
    name: `Alt 0${n}: Short deck ${n}`,
    type: "Document",
    kind: "note",
    lifecycle: "open",
    summary: null,
    home_id: "deck-alt",
    created_at: "2026-11-10T00:00:00.000Z",
    updated_at: "2026-11-10T00:00:00.000Z",
    updated_at_ms: 3000 + n,
    is_current: 1,
    body: `Alt slide ${n} body.`,
  }));
  const embedHeavyFigures = Array.from({ length: 30 }, (_, idx) => {
    const id = `heavy-fig-${String(idx + 1).padStart(2, "0")}`;
    return {
      id,
      name: `Heavy Figure ${idx + 1}`,
      type: "Document",
      kind: "note",
      lifecycle: "open",
      summary: null,
      home_id: "figures",
      created_at: "2026-11-10T00:00:00.000Z",
      updated_at: "2026-11-10T00:00:00.000Z",
      updated_at_ms: 4000 + idx,
      is_current: 1,
      body: `Heavy figure ${idx + 1} diagram.`,
    };
  });
  const embedHeavySlides = Array.from({ length: 5 }, (_, idx) => {
    const num = String(idx + 1).padStart(2, "0");
    const tokens = embedHeavyFigures
      .slice(idx * 6, (idx + 1) * 6)
      .map((fig) => `[[embed:${fig.id}]]`)
      .join(" ");
    return {
      id: `embed-slide-${num}`,
      name: `Embed Slide ${num}`,
      type: "Document",
      kind: "note",
      lifecycle: "open",
      summary: null,
      home_id: "deck-embeds",
      created_at: "2026-11-10T00:00:00.000Z",
      updated_at: "2026-11-10T00:00:00.000Z",
      updated_at_ms: 5000 + idx,
      is_current: 1,
      body: `Embed-heavy body ${num}: ${tokens}`,
    };
  });
  const figures = [1, 2, 3].map((n) => ({
    id: `fig-${n}`,
    name: `Figure ${n}`,
    type: "Document",
    kind: "note",
    lifecycle: "open",
    summary: null,
    home_id: "figures",
    created_at: "2026-11-10T00:00:00.000Z",
    updated_at: "2026-11-10T00:00:00.000Z",
    updated_at_ms: 2000 + n,
    is_current: 1,
    body: `Diagram ${n} content`,
  }));
  const folders = {
    "deck-main": mainSlides,
    "deck-alt": altSlides,
    "deck-embeds": embedHeavySlides,
  };
  const allRecords = new Map(
    [...mainSlides, ...altSlides, ...embedHeavySlides, ...figures, ...embedHeavyFigures].map((r) => [r.id, r]),
  );
  const failures = new Map();
  const queryDispatches = [];

  function answerSql(query) {
    const param0 = query.parameters?.[0]?.value ?? query.parameters?.[0];
    const hasBody = /substr\(body/.test(query.sql);
    const kind = /WHERE home_id = \?1/.test(query.sql) ? "list" : hasBody ? "record-body" : "record-meta";
    queryDispatches.push({ kind, target: param0, sql: query.sql });

    const injected = failures.get(param0);
    if (injected && (!injected.onlyBody || hasBody)) {
      throw Object.assign(new Error(injected.message ?? injected.code), {
        status: injected.status ?? "error",
        code: injected.code,
        terminal: injected.terminal ?? false,
      });
    }

    if (kind === "list") {
      const rows = folders[param0] ?? [];
      return {
        columns: metaColumns,
        rows: rows.map((r) => Object.fromEntries(metaColumns.map((k) => [k, r[k]]))),
        truncated: false,
      };
    }
    const rec = allRecords.get(param0);
    const cols = hasBody ? [...metaColumns, "body", "body_length"] : metaColumns;
    if (!rec) return { columns: cols, rows: [], truncated: false };
    const row = Object.fromEntries(metaColumns.map((k) => [k, rec[k]]));
    if (hasBody) {
      row.body = rec.body;
      row.body_length = rec.body.length;
    }
    return { columns: cols, rows: [row], truncated: false };
  }

  return { folders, allRecords, failures, queryDispatches, answerSql };
}

test("subscription-budget example passes HTML and package validation on its exact bytes", async () => {
  assert.deepEqual(validateHtml(example).filter((item) => item.severity === "error"), []);
  assert.deepEqual(validatePackage({ descriptor, html: example, strict: true }).findings, []);
  assert.equal((example.match(/<script type="module">/g) || []).length, 1);
  assert.doesNotMatch(example, /\bimport\s|<script[^>]+src=/);
  const fake = await startFakeHost({ html: example, descriptor, kitDelivery });
  await fake.close();
});

test("bounded navigation, lazy picker, deck switch, and teardown stay within budget; leaking mode hits 32-slot cap at slide 14", { skip }, async () => {
  const world = makeFixtures();
  const page = await browser.newPage();
  const tab = await openFakeHost(page, {
    descriptor,
    html: example,
    kitDelivery,
    latencyMs: 0,
    queries: (query) => world.answerSql(query),
  });
  try {
    const frame = tab.frame;
    assert.equal(await frame.locator("body").evaluate(() => window.native.kit.release.version), "1.7.0");
    await frame.getByTestId("slide-title").filter({ hasText: "Slide 01: Topic 1" }).waitFor({ timeout: 5000 });
    for (let i = 1; i < 19; i += 1) {
      const num = String(i + 1).padStart(2, "0");
      await frame.locator("#next").click();
      await frame.getByTestId("slide-title").filter({ hasText: `Slide ${num}: Topic ${i + 1}` }).waitFor({ timeout: 5000 });
    }
    // Walk back and revisit slide 14, then settle on slide 5 (all 19 slides retained, 0 embeds in 5±2 -> 1 deck + 5 window = 6 slots).
    await frame.getByTestId("jump-14").click();
    await frame.getByTestId("slide-title").filter({ hasText: "Slide 14: Topic 14" }).waitFor({ timeout: 5000 });
    await frame.getByTestId("jump-5").click();
    await frame.getByTestId("slide-title").filter({ hasText: "Slide 05: Topic 5" }).waitFor({ timeout: 5000 });
    await page.waitForFunction(() => window.__alphaTabHost.subscriptionDiagnostics().activeCount === 6, null, { timeout: 5000 });

    const boundedPass = await tab.subscriptionDiagnostics();
    assert.equal(boundedPass.observedLimitRefusals, 0);
    assert.ok(boundedPass.peakOpen <= 11, `expected bounded pass peak <= 11, got ${boundedPass.peakOpen}`);
    assert.equal(boundedPass.duplicateQueries.length, 0);

    // Lazy picker adds 1 subscription while open (6 -> 7) and releases it on close (7 -> 6).
    const beforePicker = boundedPass.activeCount;
    assert.equal(beforePicker, 6);
    await frame.getByTestId("toggle-picker").click();
    await frame.getByTestId("lazy-picker").waitFor({ timeout: 5000 });
    await frame.getByTestId("pick-slide-06").waitFor({ timeout: 5000 });
    await page.waitForFunction((expected) => window.__alphaTabHost.subscriptionDiagnostics().activeCount === expected, beforePicker + 1, { timeout: 5000 });
    await frame.getByTestId("pick-slide-06").click();
    await frame.getByTestId("slide-title").filter({ hasText: "Slide 06: Topic 6" }).waitFor({ timeout: 5000 });
    await page.waitForFunction((expected) => window.__alphaTabHost.subscriptionDiagnostics().activeCount === expected, beforePicker, { timeout: 5000 });

    // Deck switch releases old deck's window slots and clears retained snapshots.
    await frame.getByTestId("deck-select").selectOption("deck-alt");
    await frame.getByTestId("slide-title").filter({ hasText: "Alt 01: Short deck 1" }).waitFor({ timeout: 5000 });
    await page.waitForFunction(() => window.__alphaTabHost.subscriptionDiagnostics().activeCount <= 4, null, { timeout: 5000 });
    await frame.getByTestId("deck-select").selectOption("deck-main");
    await frame.getByTestId("slide-title").filter({ hasText: "Slide 01: Topic 1" }).waitFor({ timeout: 5000 });

    // Switch to leaking mode from slide 1 and walk to slide 14: 6 list slots + 2*13 slide slots = 32 at slide 13, cap refusal at slide 14.
    await frame.getByTestId("toggle-mode").click();
    for (let i = 1; i < 13; i += 1) {
      const num = String(i + 1).padStart(2, "0");
      await frame.locator("#next").click();
      await frame.getByTestId("slide-title").filter({ hasText: `Slide ${num}: Topic ${i + 1}` }).waitFor({ timeout: 5000 });
    }
    // Cached slide titles can paint before the new readers are subscribed.
    await page.waitForFunction(() => {
      const diagnostics = window.__alphaTabHost.subscriptionDiagnostics();
      return diagnostics.activeCount === 32 && diagnostics.duplicateQueries.length >= 13;
    }, null, { timeout: 5000 });
    const atSlide13 = await tab.subscriptionDiagnostics();
    assert.equal(atSlide13.activeCount, 32);
    assert.ok(atSlide13.duplicateQueries.length >= 13);

    await frame.locator("#next").click();
    await frame.locator('[data-testid="active-slide"][data-slide-id="slide-14"][data-slide-status="error"]').waitFor({ timeout: 5000 });
    const atSlide14 = await tab.subscriptionDiagnostics();
    assert.equal(atSlide14.activeCount, 32);
    assert.ok(atSlide14.observedLimitRefusals >= 1);
    assert.match(atSlide14.hint ?? "", /32-subscription cap/);

    // Switching back to bounded mode unmounts leaked offscreen readers and recovers slide 14.
    await frame.getByTestId("toggle-mode").click();
    await frame.getByTestId("slide-title").filter({ hasText: "Slide 14: Topic 14" }).waitFor({ timeout: 5000 });
    await page.waitForFunction(() => window.__alphaTabHost.subscriptionDiagnostics().activeCount <= 10, null, { timeout: 5000 });
    const recoveredDiag = await tab.subscriptionDiagnostics();
    assert.ok(recoveredDiag.activeCount <= 10, `expected recovered activeCount <= 10, got ${recoveredDiag.activeCount}`);

    // Teardown via pagehide releases all open frame subscriptions.
    await frame.locator("body").evaluate(() => window.dispatchEvent(new Event("pagehide")));
    await page.waitForFunction(() => window.__alphaTabHost.subscriptionDiagnostics().activeCount === 0, null, { timeout: 5000 });
    await tab.expectHealthy();
  } finally {
    await tab.close();
    await page.close();
  }
});

test("Retry dispatches a real backend query; warm transient errors preserve content while definite errors clear it; embed-heavy window can exceed 32", { skip }, async () => {
  const world = makeFixtures();
  // Cold failure on slide 19 (definite refusal so Try again appears immediately).
  world.failures.set("slide-19", { status: "refused", code: "query_refused", message: "Simulated slide 19 failure", terminal: true, onlyBody: true });

  const page = await browser.newPage();
  const tab = await openFakeHost(page, {
    descriptor,
    html: example,
    kitDelivery,
    latencyMs: 0,
    queries: (query) => world.answerSql(query),
  });
  try {
    const frame = tab.frame;
    assert.equal(await frame.locator("body").evaluate(() => window.native.kit.release.version), "1.7.0");
    await frame.getByTestId("slide-title").filter({ hasText: "Slide 01: Topic 1" }).waitFor({ timeout: 5000 });

    // Jump to slide 19: fails cold, shows Try again.
    await frame.locator("#last").click();
    await frame.locator('[data-testid="active-slide"][data-slide-id="slide-19"][data-slide-status="error"]').waitFor({ timeout: 5000 });
    const retryButton = frame.locator(".kit-error").getByRole("button", { name: "Try again" }).first();
    await retryButton.waitFor({ timeout: 5000 });

    // First Try again dispatches a real backend query for slide-19 (still armed -> fails).
    const dispatchesBeforeFirstRetry = world.queryDispatches.filter((d) => d.target === "slide-19" && d.kind === "record-body").length;
    await retryButton.click();
    await page.waitForFunction(
      () => true,
    );
    const deadline1 = Date.now() + 5000;
    while (world.queryDispatches.filter((d) => d.target === "slide-19" && d.kind === "record-body").length <= dispatchesBeforeFirstRetry && Date.now() < deadline1) {
      await new Promise((r) => setTimeout(r, 20));
    }
    const dispatchesAfterFirstRetry = world.queryDispatches.filter((d) => d.target === "slide-19" && d.kind === "record-body").length;
    assert.ok(dispatchesAfterFirstRetry > dispatchesBeforeFirstRetry, "first Try again must dispatch a real backend query");

    // Disarm failure; second Try again dispatches and recovers slide 19.
    world.failures.delete("slide-19");
    await retryButton.click();
    await frame.getByTestId("slide-title").filter({ hasText: "Slide 19: Topic 19" }).waitFor({ timeout: 5000 });
    const dispatchesAfterSecondRetry = world.queryDispatches.filter((d) => d.target === "slide-19" && d.kind === "record-body").length;
    assert.ok(dispatchesAfterSecondRetry > dispatchesAfterFirstRetry, "second Try again must dispatch and recover");

    // A warm live read keeps its kit-owned last rows through a transient
    // failure. Off-window snapshots never rewrite a new episode as ready.
    const currentSub = (await tab.subscriptionDiagnostics()).active.find((reader) =>
      reader.query.parameters?.[0]?.value === "slide-19" && /substr\(body/.test(reader.query.sql));
    assert.ok(currentSub);
    await tab.failSubscription(currentSub.id, "unavailable", "Temporary blip", false);
    assert.match(await frame.getByTestId("slide-body").textContent(), /Body for slide 19/);
    await tab.pushSubscription(currentSub.id);

    // Definite denial (access_denied) on slide 1 after unmount/remount clears retained snapshot and shows error instead of stale body.
    world.failures.set("slide-01", { status: "refused", code: "access_denied", message: "Access revoked", terminal: true, onlyBody: true });
    await frame.locator("#first").click();
    await frame.locator('[data-testid="active-slide"][data-slide-id="slide-01"][data-slide-status="error"]').waitFor({ timeout: 5000 });
    assert.equal(await frame.getByTestId("slide-title").count(), 0, "definite denial must clear retained snapshot on remount");
    // The child paints its error before its effect updates the parent outline.
    await frame.locator('[data-testid="outline-item-1"][data-retained="false"]').waitFor({ timeout: 5000 });
    assert.equal(await frame.getByTestId("outline-item-1").getAttribute("data-retained"), "false");
    world.failures.delete("slide-01");

    // Embed-heavy deck: 5 slides in the ±2 window with 6 embeds each (1 deck + 5 slides + 30 embeds = 36 > 32) exceeds the 32-slot cap.
    await frame.getByTestId("deck-select").selectOption("deck-embeds");
    await frame.getByTestId("jump-3").click();
    await page.waitForFunction(() => window.__alphaTabHost.subscriptionDiagnostics().observedLimitRefusals >= 1, null, { timeout: 5000 });
    const embedDiag = await tab.subscriptionDiagnostics();
    assert.equal(embedDiag.peakOpen, 32);
    assert.ok(embedDiag.observedLimitRefusals >= 1, "unbounded embeds inside the active window still hit the 32-slot cap");
    await tab.expectHealthy();
  } finally {
    await tab.close();
    await page.close();
  }
});
