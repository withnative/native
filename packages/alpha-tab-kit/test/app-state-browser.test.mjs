import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadChromium, openFakeHost } from '../src/fake-host/playwright.mjs';
const chromium = await loadChromium();
const required = !!(process.env.CI || process.env.ALPHA_TAB_KIT_REQUIRE_BROWSER);
const descriptor = JSON.parse(readFileSync(new URL('fixtures/probe-descriptor.json', import.meta.url), 'utf8'));
descriptor.declaration = { contract: 'native.app.v2', needs: [], effects: [] };
const html = '<!doctype html><html><head><title>App state probe</title></head><body><p>App state probe</p></body></html>';
test('device state is feature gated, acknowledged, and restored after the parent host reloads without sending', { skip: !chromium && !required ? 'Playwright unavailable' : false }, async () => {
  assert.ok(chromium);
  const browser = await chromium.launch(), page = await browser.newPage();
  let tab;
  try {
    tab = await openFakeHost(page, { descriptor, html, appState: true });
    const body = () => page.frameLocator('#alpha-tab-frame').locator('body');
    assert.equal(await body().evaluate(() => window.native.appState === window.nativeArtifact.appState), true);
    const saved = await body().evaluate(() => window.native.appState.set({ outbox: [{ key: 'permanent', text: 'held' }], drafts: ['draft'] }, { schema: 'outbox.v1', expectedRevision: 0 }));
    assert.equal(saved.status, 'ok'); assert.equal(saved.revision, 1);
    assert.equal((await body().evaluate(() => window.native.appState.set(['wrong revision'], { expectedRevision: 0 }))).code, 'stale_revision');
    await page.reload();
    await body().evaluate(() => window.nativeArtifact.ready);
    const restored = await body().evaluate(() => window.native.appState.get({ schema: 'outbox.v2' }));
    assert.equal(restored.status, 'ok');
    assert.equal(restored.recovered.length, 1);
    assert.equal(restored.recovered[0].value.outbox[0].text, 'held');
    assert.equal(restored.recovered[0].schemaChanged, true);
    const events = await tab.events();
    assert.equal(events.filter(event => ['call', 'intent', 'read-start'].includes(event.type)).length, 0);
    assert.equal((await body().evaluate(() => window.native.appState.clear({ expectedRevision: 0 }))).status, 'ok');
    assert.equal((await body().evaluate(() => window.native.appState.get())).recovered.length, 0);
    await tab.close(); tab = null;
    tab = await openFakeHost(page, { descriptor, html });
    assert.equal(await body().evaluate(() => typeof window.nativeArtifact.appState), 'undefined');
  } finally { await tab?.close(); await browser.close(); }
});

test('supplied kit checkpoints a Slack-like outbox before send, survives reload, and retries once under its permanent key', { skip: !chromium && !required ? 'Playwright unavailable' : false }, async () => {
  assert.ok(chromium);
  const browser = await chromium.launch(), page = await browser.newPage();
  let tab;
  try {
    const source = html.replace('</head>', '<script type="application/json" id="native-app-kit">{"schema":"native.app-kit.v1","major":1}</script></head>');
    tab = await openFakeHost(page, { descriptor: { ...descriptor, kit: { major: 1 } }, html: source, appState: true });
    const body = () => page.frameLocator('#alpha-tab-frame').locator('body');
    const key = await body().evaluate(async () => {
      await native.kit.ready;
      window.state = native.kit.createAppState({ schema: 'slack-like.v1' });
      await state.load(); window.sentKeys = [];
      window.helper = native.kit.createWriteHelper({ checkpoint: entries => state.save({ entries }), dispatch: async (request, ctx) => {
        const saved = await native.appState.get();
        if (!saved.snapshot.value.entries.some(e => e.key === ctx.key && e.request.body === request.body)) throw new Error('not checkpointed');
        sentKeys.push(ctx.key); throw { code: 'timeout' };
      } });
      const ticket = helper.submit({ body: 'A message awaiting confirmation', channel: 'general' });
      const entry = await ticket.done;
      return entry.key;
    });
    assert.equal(await body().evaluate(() => sentKeys.length), 1);
    await page.reload(); await body().evaluate(() => native.kit.ready);
    const restored = await body().evaluate(async () => {
      window.state = native.kit.createAppState({ schema: 'slack-like.v1' });
      const value = await state.load(); window.sentKeys = [];
      window.helper = native.kit.createWriteHelper({ checkpoint: entries => state.save({ entries }), dispatch: async (_request, ctx) => { sentKeys.push(ctx.key); return { replayed: true }; } });
      for (const entry of value.entries) helper.restore(entry);
      return { count: helper.entries().length, key: helper.entries()[0]?.key, sent: sentKeys.length };
    });
    assert.deepEqual(restored, { count: 1, key, sent: 0 });
    const retried = await body().evaluate(async () => {
      const entry = helper.entries()[0]; await helper.retry(entry.id).done;
      helper.retry(entry.id); // already sent: cannot dispatch again
      return { keys: sentKeys, status: helper.get(entry.id).status };
    });
    assert.deepEqual(retried, { keys: [key], status: 'sent' });
  } finally { await tab?.close(); await browser.close(); }
});
