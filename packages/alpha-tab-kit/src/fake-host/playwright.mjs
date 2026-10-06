// Playwright glue for the fake host. Playwright is an optional peer: pass
// your own `page`, or call `loadChromium()` to resolve it.
import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { startFakeHost } from "./server.mjs";

/**
 * Resolve Playwright's chromium: `ALPHA_TAB_KIT_PLAYWRIGHT` (a directory
 * whose node_modules holds playwright), the caller's own install, or —
 * inside native-ce — web/workbench's pinned copy.
 */
export async function loadChromium() {
  const candidates = [process.env.ALPHA_TAB_KIT_PLAYWRIGHT, process.cwd(), resolve(new URL("../../../../web/workbench", import.meta.url).pathname)].filter(Boolean);
  for (const base of candidates) {
    const manifest = resolve(base, "package.json");
    if (!existsSync(manifest)) continue;
    try {
      return createRequire(manifest)("playwright").chromium;
    } catch { /* try the next */ }
  }
  try {
    return (await import("playwright")).chromium;
  } catch {
    return null;
  }
}

const keyOf = (need, params) => `${need} ${JSON.stringify(params ?? null)}`;

/**
 * Summarise one session's host events. A read answered `busy` whose exact
 * (need, params) was never answered afterwards is a dropped read: the real
 * shell would have lost it too.
 */
export function audit(events) {
  const busy = events.filter((event) => event.type === "read-busy");
  const answered = events.filter((event) => ["read-ok", "read-error", "read-refused"].includes(event.type));
  const dropped = busy.filter((event) => !answered.some((later) => later.at >= event.at && keyOf(later.need, later.params) === keyOf(event.need, event.params)));
  const diagnostics = events.filter((event) => event.type === "diagnostic");
  return {
    reads: answered.length,
    busy: busy.length,
    dropped: dropped.map((event) => ({ need: event.need, params: event.params })),
    bridgeRefusals: diagnostics.filter((event) => event.code === "html_read_refused").map((event) => event.detail),
    runtimeErrors: diagnostics.filter((event) => event.code === "html_runtime_error").map((event) => event.detail),
    refused: events.filter((event) => event.type === "read-refused").map((event) => ({ need: event.need, code: event.code })),
  };
}

/**
 * Start a fake host for one package and open it in `page`.
 * Returns `{ host, frame, events(), pushInput(), audit(), expectHealthy(), close() }`.
 */
export async function openFakeHost(page, options) {
  const host = await startFakeHost(options);
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(host.url);
  const frame = page.frameLocator("#alpha-tab-frame");
  const events = () => page.evaluate(() => window.__alphaTabHost.events());
  const deadline = Date.now() + (options.readyTimeoutMs ?? 5000);
  while (!(await events()).some((event) => event.type === "ready")) {
    if (Date.now() > deadline) throw new Error(`tab never sent ready; host events: ${JSON.stringify(await events())}`);
    await page.waitForTimeout(25);
  }
  return {
    host,
    frame,
    page,
    events,
    pushInput: () => page.evaluate(() => window.__alphaTabHost.pushInput()),
    reload: () => page.evaluate(() => window.__alphaTabHost.reload()),
    async audit() { return audit(await events()); },
    async expectHealthy() {
      const summary = audit(await events());
      const problems = [];
      if (summary.dropped.length) problems.push(`${summary.dropped.length} read(s) answered busy and never retried: ${summary.dropped.map((read) => keyOf(read.need, read.params)).join("; ")}`);
      if (summary.runtimeErrors.length) problems.push(`runtime errors in the frame: ${JSON.stringify(summary.runtimeErrors)}`);
      if (errors.length) problems.push(`host page errors: ${errors.join("; ")}`);
      if (problems.length) throw new Error(`fake host found problems the real shell would show:\n- ${problems.join("\n- ")}`);
      return summary;
    },
    close: () => host.close(),
  };
}
