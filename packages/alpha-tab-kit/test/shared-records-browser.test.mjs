// Shipped kit in the opaque frame, using the ordinary bridge's 32-slot limit.
// This proves identical record reads share a slot; distinct records are a later slice.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadChromium, openFakeHost } from '../src/fake-host/playwright.mjs';
import { createKitDelivery, readKitAssets } from '../src/fake-host/kit-assets.mjs';

const chromium = await loadChromium();
const fixture = readFileSync(new URL('./fixtures/probe-shared-records.html', import.meta.url), 'utf8');
const descriptor = {
  package: 'agent.shared-records-probe', version: '0.1.0', bundle: 'probe-shared-records.html', runtime: 'native.html.v1',
  declaration: { contract: 'native.app.v2', needs: [], effects: [] },
};
const result = name => ({ columns: ['id', 'name'], rows: [{ id: 'record-1', name }], truncated: false });

test('kit 1.7.1 shares one bridge subscription across forty record readers and releases it on last unmount', {
  skip: !chromium && 'Playwright is not installed',
}, async () => {
  const browser = await chromium.launch();
  let tab;
  try {
    const page = await browser.newPage();
    tab = await openFakeHost(page, {
      descriptor, html: fixture, latencyMs: 0, queries: () => result('Accepted'),
      kitDelivery: createKitDelivery(await readKitAssets(), {
        schema: 'native.app-kit.selector.v1', selections: [{ major: 1, version: '1.7.1' }],
      }),
    });
    const count = async (selector, wanted) => {
      await tab.frame.locator('body').evaluate((_, [query, expected]) => new Promise((resolve, reject) => {
        const deadline = Date.now() + 5000;
        const check = () => document.querySelectorAll(query).length === expected ? resolve()
          : Date.now() > deadline ? reject(new Error(`${query}: expected ${expected}, got ${document.querySelectorAll(query).length}`)) : setTimeout(check, 10);
        check();
      }), [selector, wanted]);
    };
    const subscriptions = async () => (await tab.events()).filter(event => event.type === 'subscribe');
    assert.equal(await tab.frame.locator('#release').textContent(), '1.7.1');
    await count('.reader[data-status="ready"]', 40);
    assert.equal((await subscriptions()).length, 1);
    const [wire] = await tab.subscriptions();
    assert.ok(wire);
    assert.equal((await tab.subscriptions()).length, 1);

    await tab.frame.locator('#add').click();
    await count('.reader[data-status="ready"]', 41);
    assert.equal((await subscriptions()).length, 1, 'joining a warm active query does not subscribe again');
    await tab.pushSubscription(wire, result('Updated'));
    await count('.reader[data-status="ready"]', 41);
    await tab.frame.locator('.reader').first().filter({ hasText: 'Updated' }).waitFor();
    assert.deepEqual(new Set(await tab.frame.locator('.reader').allTextContents()), new Set(['Updated']));

    await tab.frame.locator('#remove').click();
    await count('.reader', 40);
    assert.deepEqual(await tab.subscriptions(), [wire], 'removing one consumer leaves the others subscribed');
    await tab.failSubscription(wire, 'unavailable', 'Temporarily unavailable', false);
    await count('.reader[data-error="unavailable"]', 40);
    assert.deepEqual(new Set(await tab.frame.locator('.reader').allTextContents()), new Set(['Updated']));
    await tab.pushSubscription(wire, result('Recovered'));
    await count('.reader[data-error=""]', 40);
    await tab.failSubscription(wire, 'access_denied', 'Access removed', true);
    await count('.reader[data-status="error"]', 40);
    assert.deepEqual(new Set(await tab.frame.locator('.reader').allTextContents()), new Set(['']));
    assert.deepEqual(await tab.subscriptions(), []);

    await tab.frame.locator('#clear').click();
    await count('.reader', 0);
    await tab.frame.locator('#mount').click();
    await count('.reader[data-status="ready"]', 40);
    assert.equal((await subscriptions()).length, 2);
    await tab.frame.locator('#clear').click();
    await count('.reader', 0);
    await page.waitForFunction(() => window.__alphaTabHost.subscriptions().length === 0);
    const diagnostics = (await tab.events()).filter(event => event.type === 'diagnostic');
    assert.ok(!diagnostics.some(event => JSON.stringify(event).includes('subscription_limit')));
    await tab.expectHealthy();
  } finally {
    await tab?.close();
    await browser.close();
  }
});


test('kit 1.7.1 still refuses distinct record 33 and releases all 32 slots on unmount', {
  skip: !chromium && 'Playwright is not installed',
}, async () => {
  const browser = await chromium.launch();
  let tab;
  try {
    const page = await browser.newPage();
    tab = await openFakeHost(page, {
      descriptor, html: fixture, latencyMs: 0,
      queries: query => {
        const id = query.params?.[0]?.value ?? query.parameters?.[0]?.value;
        return { columns: ['id', 'name'], rows: [{ id, name: id }], truncated: false };
      },
      kitDelivery: createKitDelivery(await readKitAssets(), {
        schema: 'native.app-kit.selector.v1', selections: [{ major: 1, version: '1.7.1' }],
      }),
    });
    assert.equal(await tab.frame.locator('#release').textContent(), '1.7.1');
    await tab.frame.locator('.reader[data-status="ready"]').first().waitFor();
    assert.equal((await tab.subscriptions()).length, 1);
    await tab.frame.locator('#distinct').click();
    await tab.frame.locator('body').evaluate(() => new Promise((resolve, reject) => {
      const deadline = Date.now() + 5000;
      const check = () => document.querySelectorAll('.reader[data-status="ready"]').length === 32
        && document.querySelectorAll('.reader[data-error="subscription_limit"]').length === 8 ? resolve()
        : Date.now() > deadline ? reject(new Error('distinct readers did not settle at the 32-slot cap')) : setTimeout(check, 10);
      check();
    }));
    const live = await tab.subscriptionDiagnostics();
    assert.equal(live.activeCount, 32);
    assert.equal(live.duplicateQueries.length, 0);
    // The bridge rejects the extra eight before a host subscription opens;
    // their explicit subscription_limit states above are the refusal proof.
    assert.equal((await tab.subscriptions()).length, 32);
    await tab.frame.locator('#clear').click();
    await page.waitForFunction(() => window.__alphaTabHost.subscriptionDiagnostics().activeCount === 0);
    await tab.expectHealthy();
  } finally {
    await tab?.close();
    await browser.close();
  }
});
