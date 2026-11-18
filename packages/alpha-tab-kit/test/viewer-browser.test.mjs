import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadChromium, openFakeHost } from '../src/fake-host/playwright.mjs';
const chromium = await loadChromium();
const required = !!(process.env.CI || process.env.ALPHA_TAB_KIT_REQUIRE_BROWSER);
const descriptor = JSON.parse(readFileSync(new URL('fixtures/probe-descriptor.json', import.meta.url), 'utf8'));
descriptor.declaration = { contract: 'native.app.v2', needs: [], effects: [] };
const html = '<!doctype html><html><head><title>Viewer probe</title></head><body><p>Viewer probe</p></body></html>';
const wire = (personId, name) => ({ version: 'native.viewer.v1', person_id: personId, name });

test('viewer is feature gated, live through updates, and released on pagehide', { skip: !chromium && !required ? 'Playwright unavailable' : false }, async () => {
  assert.ok(chromium);
  const browser = await chromium.launch(), page = await browser.newPage();
  let tab;
  try {
    tab = await openFakeHost(page, { descriptor, html, viewer: wire('p1', 'Ada Lovelace') });
    const body = () => page.frameLocator('#alpha-tab-frame').locator('body');
    // Init value, mapped by the bridge to the port shape.
    assert.deepEqual(await body().evaluate(() => window.native.viewer), { personId: 'p1', name: 'Ada Lovelace' });
    // Subscribe: updates arrive, the getter stays live, malformed and null updates keep state.
    await body().evaluate(() => {
      window.seen = [];
      window.offViewer = window.native.onViewer((viewer) => window.seen.push(viewer));
    });
    await tab.pushViewer(wire('p1', 'Grace Hopper'));
    await page.waitForTimeout(50);
    assert.deepEqual(await body().evaluate(() => window.native.viewer), { personId: 'p1', name: 'Grace Hopper' });
    assert.deepEqual(await body().evaluate(() => window.seen), [{ personId: 'p1', name: 'Grace Hopper' }]);
    await tab.pushViewer({ version: 'native.viewer.v9', person_id: 'p9', name: 'Wrong Version' });
    await tab.pushViewer({ version: 'native.viewer.v1', person_id: 'p9' });
    await tab.pushViewer(null);
    await page.waitForTimeout(50);
    assert.deepEqual(await body().evaluate(() => window.native.viewer), { personId: 'p1', name: 'Grace Hopper' });
    assert.equal(await body().evaluate(() => window.seen.length), 1);
    // Unsubscribe stops callbacks; the getter still follows.
    await body().evaluate(() => window.offViewer());
    await tab.pushViewer(wire('p2', 'Third Person'));
    await page.waitForTimeout(50);
    assert.deepEqual(await body().evaluate(() => window.native.viewer), { personId: 'p2', name: 'Third Person' });
    assert.equal(await body().evaluate(() => window.seen.length), 1);
    // After pagehide the bridge has released subscribers: no further callbacks.
    await body().evaluate(() => {
      window.late = 0;
      window.native.onViewer(() => { window.late += 1; });
      window.dispatchEvent(new Event('pagehide'));
    });
    await tab.pushViewer(wire('p3', 'After Close'));
    await page.waitForTimeout(50);
    assert.equal(await body().evaluate(() => window.late), 0);
    await tab.close(); tab = null;

    // No feature offered: no viewer surface at all.
    tab = await openFakeHost(page, { descriptor, html });
    assert.equal(await body().evaluate(() => window.native?.viewer ?? undefined), undefined);
    assert.equal(await body().evaluate(() => window.native?.onViewer ?? undefined), undefined);
    await tab.close(); tab = null;

    // Offered but not known yet: null at init, filled in by a later update.
    tab = await openFakeHost(page, { descriptor, html, viewer: null });
    assert.equal(await body().evaluate(() => window.native.viewer), null);
    await tab.pushViewer(wire(null, null));
    await page.waitForTimeout(50);
    assert.deepEqual(await body().evaluate(() => window.native.viewer), { personId: null, name: null });
  } finally { await tab?.close(); await browser.close(); }
});
