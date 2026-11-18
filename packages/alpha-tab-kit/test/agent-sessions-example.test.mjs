// The source-only agent sessions example (examples/agent-sessions.html) running against core kit 1.3.0 in Chromium, with a
// minimal parent page that speaks the real bridge wire protocol (see agent-sessions-bridge.test.mjs). It proves the three
// things the example is for: it lists sessions, it survives a transient list failure quietly, and it opens the folder
// chooser and starts a session in the chosen folder. A host still on kit 1.2.0 shows the feature-detect message instead.
// Playwright is an optional peer, as in agent-sessions-bridge.test.mjs.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { loadChromium } from "../src/fake-host/playwright.mjs";
import { injectBridge } from "../src/fake-host/server.mjs";
import { createKitDelivery, readKitAssets } from "../src/fake-host/kit-assets.mjs";
import { validateHtml } from "../src/html.mjs";
import { startFakeHost } from "../src/fake-host/server.mjs";
import { LIMITS } from "../src/limits.mjs";

const VERSION = LIMITS.bridge.version;
const example = readFileSync(new URL("../examples/agent-sessions.html", import.meta.url), "utf8");
const declaration = JSON.parse(readFileSync(new URL("../examples/agent-sessions.declaration.json", import.meta.url), "utf8"));

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
  send: (message) => port.postMessage({ version: ${JSON.stringify(version)}, ...message }),
};
</script>
</body></html>`;

let server, base, browser, rolledBack;
const chromium = await loadChromium();
before(async () => {
  rolledBack = createKitDelivery(await readKitAssets(), { schema: "native.app-kit.selector.v1", selections: [{ major: 1, version: "1.2.0" }] });
  server = createServer((request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    if (url.pathname === "/frame") {
      const origin = `http://${request.headers.host}`;
      response.end(url.searchParams.get("kit") === "1.2.0" ? injectBridge(example, origin, rolledBack) : injectBridge(example, origin));
      return;
    }
    response.end(parentHtml(VERSION));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  if (chromium) browser = await chromium.launch(process.env.ALPHA_TAB_KIT_CHROMIUM ? { executablePath: process.env.ALPHA_TAB_KIT_CHROMIUM } : {});
});
after(async () => { await browser?.close(); server.close(); });
const skip = !chromium && "Playwright is not installed";

const host = { id: "mac", label: "Studio Mac", status: "reachable", epoch: "e1", capabilities: { create: true, chooseFolder: true } };
const summary = (id, title) => ({ id, hostId: "mac", hostLabel: "Studio Mac", hostEpoch: "e1", title, provider: "claude", model: "fable", status: "idle", lastActivity: "2026-10-31T10:00:00.000Z", workspace: { id: "ordinary", name: "Chat" } });
const catalog = { hosts: [{ hostId: "mac", hostLabel: "Studio Mac", hostEpoch: "e1", status: "reachable",
  providers: [{ id: "claude", label: "Claude", available: true, defaultModeId: "default", models: [{ id: "fable", label: "Fable", isDefault: true, thinkingOptions: [] }], modes: [{ id: "default", label: "Default" }] }],
  workspaces: [{ id: "ordinary", name: "Ordinary chat", path: "/chat", kind: "ordinary" }] }] };
const answer = ({ type, request_id, result }) => window.__host.send({ type, request_id, result });

async function open(query) {
  const page = await browser.newPage();
  await page.goto(`${base}/?${query}`);
  const frame = page.frameLocator("#f");
  const wire = async (type) => (await page.evaluate(() => window.__host.received())).filter((m) => m.type === type);
  const next = async (type, count = 1) => {
    await page.waitForFunction(([t, n]) => window.__host.received().filter((m) => m.type === t).length >= n, [type, count], { timeout: 10_000 });
    return (await wire(type))[count - 1];
  };
  const reply = (type, message, result) => page.evaluate(answer, { type, request_id: message.request_id, result });
  return { page, frame, wire, next, reply };
}

test("the example is a complete package: it passes admission and loads in the fake host", async () => {
  validateHtml(example);
  assert.equal((example.match(/<script type="module">/g) || []).length, 1);
  assert.doesNotMatch(example, /\bimport\s|<script[^>]+src=/);
  const fake = await startFakeHost({ html: example, descriptor: { package: "agent-sessions-example", version: "0.1.0", declaration } });
  await fake.close();
});

test("lists sessions, survives a transient list failure quietly, opens the folder chooser and starts in the chosen folder", { skip }, async () => {
  const tab = await open("features=app.agent-sessions.v2,app.agent-sessions.create.v1");
  try {
    // The first list fails transiently: nothing is said, and the kit reads again by itself.
    const first = await tab.next("agent-sessions-list");
    await tab.reply("agent-sessions-list-result", first, { ok: false, code: "unavailable" });
    await tab.frame.locator("h1, #app").first().waitFor();
    const quiet = await tab.frame.locator("#app").textContent();
    assert.doesNotMatch(quiet, /Reconnecting|Couldn.t refresh|unavailable/);
    const second = await tab.next("agent-sessions-list", 2);
    assert.notEqual(second.request_id, first.request_id);
    await tab.reply("agent-sessions-list-result", second, { ok: true, value: { hosts: [host], sessions: [summary("s1", "Plan the launch"), summary("s2", "Fix the tests")] } });
    await tab.frame.getByText("Plan the launch").waitFor();
    await tab.frame.getByText("Fix the tests").waitFor();
    assert.doesNotMatch(await tab.frame.locator("#app").textContent(), /Reconnecting|Couldn.t refresh/);

    // The catalog is read before any click, because a start must reach the host inside its click.
    const cat = await tab.next("agent-sessions-catalog");
    await tab.reply("agent-sessions-catalog-result", cat, { ok: true, value: catalog });
    await tab.frame.getByText("in Ordinary chat").waitFor();

    // The folder chooser: one wire request naming the machine and epoch; the chosen folder becomes the start's folder.
    await tab.frame.locator("#choose-folder").click();
    const choose = await tab.next("agent-sessions-choose-folder");
    assert.equal(choose.host_id, "mac");
    assert.equal(choose.host_epoch, "e1");
    await tab.reply("agent-sessions-choose-folder-result", choose, { ok: true, value: { id: "chosen-docs", name: "Documents", path: "/Users/me/Documents", kind: "folder", isGitRepo: false } });
    await tab.frame.getByText("in Documents").waitFor();

    await tab.frame.locator("#prompt").fill("Summarise this folder");
    await tab.frame.locator("#start").click();
    const create = await tab.next("agent-sessions-create");
    assert.equal(create.workspace_id, "chosen-docs");
    assert.equal(create.initial_prompt, "Summarise this folder");
    assert.match(create.request_id, /^[A-Za-z0-9:_-]+$/);
    await tab.frame.getByText("Sending…").waitFor();
    await tab.reply("agent-sessions-create-result", create, { ok: true, value: { ...summary("s3", null), workspace: { id: "chosen-docs", name: "Documents" } } });
    await tab.frame.getByText("Sent", { exact: true }).waitFor();
  } finally { await tab.page.close(); }
});

test("a cancelled chooser changes nothing", { skip }, async () => {
  const tab = await open("features=app.agent-sessions.v2,app.agent-sessions.create.v1");
  try {
    const first = await tab.next("agent-sessions-list");
    await tab.reply("agent-sessions-list-result", first, { ok: true, value: { hosts: [host], sessions: [summary("s1", "Plan the launch")] } });
    await tab.frame.getByText("Plan the launch").waitFor();
    const cat = await tab.next("agent-sessions-catalog");
    await tab.reply("agent-sessions-catalog-result", cat, { ok: true, value: catalog });
    await tab.frame.getByText("in Ordinary chat").waitFor();
    await tab.frame.locator("#choose-folder").click();
    const choose = await tab.next("agent-sessions-choose-folder");
    await tab.reply("agent-sessions-choose-folder-result", choose, { ok: true, value: null });
    await tab.page.waitForTimeout(100);
    assert.match(await tab.frame.locator("#app").textContent(), /in Ordinary chat/);
    await tab.frame.locator("#prompt").fill("x");
    await tab.frame.locator("#start").waitFor();
  } finally { await tab.page.close(); }
});

test("reports Native Desktop only when the host offers no agent sessions", { skip }, async () => {
  const tab = await open("features=app.call.v2");
  try {
    await tab.frame.getByText("Agent sessions are available in Native Desktop only.").waitFor();
    assert.equal((await tab.wire("agent-sessions-list")).length, 0);
  } finally { await tab.page.close(); }
});

test("a host rolled back to kit 1.2.0 shows the feature-detect message, not a broken page", { skip }, async () => {
  const page = await browser.newPage();
  try {
    await page.goto(`${base}/?features=app.agent-sessions.v2`);
    await page.evaluate(() => { document.getElementById("f").src = "/frame?kit=1.2.0"; });
    await page.frameLocator("#f").getByText("Open in Native with core kit 1.3.0.").waitFor();
  } finally { await page.close(); }
});
