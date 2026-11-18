// The canonical starter through the released supplied kit and bridge, with controlled receipt/list orderings.
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { loadChromium, openFakeHost } from '../src/fake-host/playwright.mjs';
import { readKitAssets, createKitDelivery } from '../src/fake-host/kit-assets.mjs';
import { starters } from './helpers/source-starters.mjs';
const row = (id, name, folder = 'native:unfiled', kind = 'note') => ({ id, name, kind, home_id: folder, type: 'Document' });
const result = rows => ({ columns: Object.keys(rows[0] || { id: '' }), rows, truncated: false });
const deferred = () => { let resolve; const promise = new Promise(r => resolve = r); return { promise, resolve }; };
const painted = frame => frame.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
const actions = frame => frame.getByRole('region', { name: 'Note actions', exact: true });
const recovery = frame => frame.getByRole('region', { name: 'Changes', exact: true });
const links = frame => frame.locator('ul [data-native-record-id]');
export async function checkMeetingNotes(browser, inbox) {
  async function open(options) {
    const page = await browser.newPage();
    const tab = await openFakeHost(page, { ...inbox, ...options });
    const frame = page.frames().find(f => f.url().includes('/frame'));
    await frame.locator('input[name="title"]').waitFor();
    const close = async () => { await tab.expectHealthy(); await tab.close(); await page.close(); };
    return { page, tab, frame, close };
  }
  async function submit(frame, name = 'First note', enter = false) {
    await frame.locator('input[name="title"]').fill(name);
    await frame.locator('textarea[name="body"]').fill('Original body');
    if (enter) await frame.locator('input[name="title"]').press('Enter');
    else await frame.getByRole('button', { name: 'Create note', exact: true }).click();
    assert.equal(await frame.locator('input[name="title"]').evaluate(input => input === document.activeElement), true, 'submission returns focus to the next title');
  }
  async function captured(frame) {
    await recovery(frame).locator('summary').first().click();
    await recovery(frame).getByText('Captured content', { exact: true }).click();
    assert.equal(await recovery(frame).getByRole('textbox', { name: 'Name', exact: true }).inputValue(), 'First note');
    assert.equal(await recovery(frame).getByRole('textbox', { name: 'Body', exact: true }).inputValue(), 'Original body');
  }
  // A pending create is an action, never a made-up record. Either arrival order settles to one real link.
  for (const listFirst of [false, true]) {
    const ack = deferred(), calls = [], records = [];
    const t = await open({ queries: () => result(records), calls: async (operation, args) => {
      assert.equal(operation, 'create_record'); calls.push(structuredClone(args)); await ack.promise; return { id: 'final-1' };
    } });
    try {
      await t.frame.locator('textarea[name="body"]').fill('Draft without title');
      await t.frame.getByRole('button', { name: 'Create note', exact: true }).click();
      assert.equal(await t.frame.locator('input[name="title"]').evaluate(input => input.validity.valueMissing), true);
      assert.equal(await t.frame.locator('textarea[name="body"]').inputValue(), 'Draft without title');
      assert.equal(calls.length, 0, 'required title validation prevents capture and dispatch');
      assert.equal(await actions(t.frame).locator('article').count(), 0);
      await t.frame.locator('input[name="title"]').press('Enter');
      assert.equal(await t.frame.locator('textarea[name="body"]').inputValue(), 'Draft without title');
      assert.equal(calls.length, 0, 'empty-title Enter also prevents capture and dispatch');
      assert.equal(await actions(t.frame).locator('article').count(), 0);
      await submit(t.frame, 'First note', listFirst);
      await actions(t.frame).locator('[data-edit-status="saving"]').waitFor();
      assert.equal(await actions(t.frame).locator('[data-native-record-id]').count(), 0, 'render handles are never domain IDs');
      assert.equal(await links(t.frame).count(), 0);
      await captured(t.frame);
      assert.equal(await t.frame.locator('input[name="title"]').inputValue(), '', 'capture permits immediate form reset');
      await t.frame.locator('input[name="title"]').fill('Next draft');
      await t.frame.locator('textarea[name="body"]').fill('Next body');
      assert.equal(await t.frame.getByRole('button', { name: 'Create note', exact: true }).isDisabled(), false);
      records.push(row('final-1', 'First note'));
      const sub = (await t.tab.subscriptions())[0];
      if (listFirst) await t.tab.pushSubscription(sub, result(records));
      ack.resolve();
      await t.frame.locator('ul [data-native-record-id="final-1"]').waitFor();
      await actions(t.frame).locator('article').waitFor({ state: 'hidden' });
      if (!listFirst) await t.tab.pushSubscription(sub, result(records));
      await painted(t.frame);
      assert.equal(await links(t.frame).count(), 1, 'receipt row and list row reconcile in either order');
      assert.equal(await links(t.frame).textContent(), 'First note');
      assert.equal(calls.length, 1);
      assert.equal(calls[0].type, 'Document'); assert.equal(calls[0].kind, 'note'); assert.equal(calls[0].home_id, 'native:unfiled');
      assert.equal(calls[0].body, 'Original body');
      assert.equal(await t.frame.locator('input[name="title"]').inputValue(), 'Next draft');
      assert.equal(await t.frame.locator('textarea[name="body"]').inputValue(), 'Next body');
    } finally { ack.resolve(); await t.close(); }
  }
  // Lost replies retry the identical frozen payload/key, including after a refused retry.
  {
    const calls = []; let mode = 'uncertain'; const ack = deferred();
    const t = await open({ queries: () => result([]), calls: async (_op, args) => {
      calls.push(structuredClone(args)); await ack.promise;
      if (mode === 'uncertain') throw { status: 'uncertain', message: 'Receipt lost' };
      if (mode === 'refused') throw { status: 'refused', code: 'forbidden', message: 'Not allowed' };
      return { id: 'recovered' };
    } });
    try {
      await submit(t.frame); await actions(t.frame).locator('[data-edit-status="saving"]').waitFor();
      await t.frame.locator('input[name="title"]').fill('Later draft');
      await t.frame.locator('textarea[name="body"]').fill('Later body'); ack.resolve();
      await actions(t.frame).locator('[data-edit-status="unsure"]').waitFor();
      await captured(t.frame);
      mode = 'refused'; await recovery(t.frame).getByRole('button', { name: 'Retry', exact: true }).click();
      await recovery(t.frame).getByText(/An earlier attempt may have applied/).waitFor();
      assert.equal(await actions(t.frame).locator('[data-edit-status="unsure"]').count(), 1);
      mode = 'confirmed'; await recovery(t.frame).getByRole('button', { name: 'Retry', exact: true }).click();
      await t.frame.locator('ul [data-native-record-id="recovered"]').waitFor();
      assert.equal(await links(t.frame).count(), 1);
      assert.deepEqual(calls[1], calls[0]); assert.deepEqual(calls[2], calls[0]);
      assert.ok(calls[0].idempotency_key, 'retry has a host deduplication key');
      assert.equal(await t.frame.locator('input[name="title"]').inputValue(), 'Later draft');
      assert.equal(await t.frame.locator('textarea[name="body"]').inputValue(), 'Later body');
    } finally { ack.resolve(); await t.close(); }
  }
  // Definite refusal remains recoverable in the default Changes panel without overwriting later composition.
  {
    const calls = [];
    const t = await open({ queries: () => result([]), calls: async (_op, args) => { calls.push(args); throw { status: 'refused', code: 'forbidden', message: 'Refused note' }; } });
    try {
      await submit(t.frame); await actions(t.frame).locator('[data-edit-status="refused"]').waitFor();
      await t.frame.locator('input[name="title"]').fill('Later draft');
      await t.frame.locator('textarea[name="body"]').fill('Later body');
      await captured(t.frame);
      assert.equal(await recovery(t.frame).getByRole('textbox', { name: 'Body', exact: true }).getAttribute('readonly'), '');
      await recovery(t.frame).getByRole('button', { name: 'Discard', exact: true }).click();
      await actions(t.frame).locator('article').waitFor({ state: 'hidden' });
      assert.equal(await recovery(t.frame).isVisible(), false);
      assert.equal(calls.length, 1, 'copying or discarding recovery never sends a new create');
      assert.equal(await t.frame.locator('input[name="title"]').inputValue(), 'Later draft');
      assert.equal(await t.frame.locator('textarea[name="body"]').inputValue(), 'Later body');
    } finally { await t.close(); }
  }
  // Kind is filtered in SQL before paging; list reads contain bounded metadata and never fetch bodies.
  {
    const docs = Array.from({ length: 60 }, (_, i) => row('plan-' + i, 'Plan ' + i, 'native:unfiled', 'plan'));
    docs.push(...Array.from({ length: 55 }, (_, i) => row('note-' + i, 'Note ' + i)));
    const queries = [];
    const t = await open({ queries: q => {
      queries.push(q);
      assert.match(q.sql, /kind = \?3/); assert.equal(q.parameters[2].value, 'note');
      assert.equal(q.parameters[0].value, 'native:unfiled'); assert.equal(q.parameters[1].value, 'Document');
      assert.doesNotMatch(q.sql, /\bbody\b|body_length|SELECT \*/);
      const limit = Number(q.sql.match(/LIMIT (\d+)$/)[1]);
      return result(docs.filter(r => r.kind === q.parameters[2].value).slice(0, limit));
    } });
    try {
      await t.frame.locator('ul [data-native-record-id="note-0"]').waitFor();
      assert.equal(await links(t.frame).count(), 50);
      assert.match(queries[0].sql, /LIMIT 51$/);
      assert.equal(await t.frame.locator('ul').getByText('Plan 0', { exact: true }).count(), 0);
      await t.frame.getByRole('button', { name: 'More notes', exact: true }).click();
      await t.frame.locator('ul [data-native-record-id="note-54"]').waitFor();
      assert.equal(await links(t.frame).count(), 55); assert.match(queries.at(-1).sql, /LIMIT 101$/);
      assert.equal(await t.frame.getByRole('button', { name: 'More notes', exact: true }).count(), 0);
      for (const sub of await t.tab.subscriptions()) await t.tab.failSubscription(sub, 'network_lost', 'Connection lost', false);
      assert.equal(await links(t.frame).count(), 55, 'transient read failure preserves known metadata');
      for (const sub of await t.tab.subscriptions()) await t.tab.failSubscription(sub, 'access_denied', 'Not allowed', true);
      await links(t.frame).first().waitFor({ state: 'hidden' });
    } finally { await t.close(); }
  }
  // Both terminal and live scope errors remove private work and require reload.
  for (const terminal of [true, false]) {
    const ack = deferred(); const calls = [];
    const t = await open({ queries: () => result([]), calls: async (_op, args) => { calls.push(args); await ack.promise; return { id: 'old-workspace-note' }; } });
    try {
      await submit(t.frame); await actions(t.frame).locator('[data-edit-status="saving"]').waitFor();
      await t.frame.locator('input[name="title"]').fill('Private next title');
      await t.frame.locator('textarea[name="body"]').fill('Private next body');
      const subscription = (await t.tab.subscriptions())[0];
      await t.tab.failSubscription(subscription, 'scope_changed', 'Workspace changed', terminal);
      await t.frame.getByRole('alert').getByText('Your workspace changed. Reload to continue.', { exact: true }).waitFor();
      assert.equal(await t.frame.locator('form, input[name="title"], textarea[name="body"]').count(), 0);
      assert.equal(await t.frame.getByRole('button', { name: 'Create note', exact: true }).count(), 0);
      assert.doesNotMatch(await t.frame.locator('#app').textContent(), /Private next|First note|Original body/);
      await actions(t.frame).locator('article').waitFor({ state: 'hidden' });
      assert.equal(await recovery(t.frame).isVisible(), false);
      if (terminal) {
        assert.deepEqual(await t.tab.subscriptions(), [], 'terminal scope error closes the reader; no fresh delivery is eligible');
      } else {
        assert.deepEqual(await t.tab.subscriptions(), [subscription], 'nonterminal scope error keeps the same reader eligible');
        await t.tab.pushSubscription(subscription, result([row('fresh-scope-note', 'Fresh workspace note')]));
        await painted(t.frame);
        await t.frame.getByText('Your workspace changed. Reload to continue.', { exact: true }).waitFor();
        assert.equal(await t.frame.locator('form, input[name="title"], textarea[name="body"]').count(), 0, 'fresh delivery cannot reopen the blocked form');
        assert.equal(await t.frame.getByRole('button', { name: 'Create note', exact: true }).count(), 0);
        assert.equal(await links(t.frame).count(), 0, 'sticky reload boundary also hides newly delivered records');
      }
      ack.resolve();
      await t.page.waitForTimeout(100);
      assert.equal(await links(t.frame).count(), 0);
      assert.equal(await actions(t.frame).locator('article').count(), 0);
      assert.equal(calls.length, 1);
    } finally { ack.resolve(); await t.close(); }
  }
  // Older hosts show the capability message without attempting unsupported reads or writes.
  {
    const delivery = createKitDelivery(await readKitAssets(), { schema: 'native.app-kit.selector.v1', selections: [{ major: 1, version: '1.1.0' }] });
    const page = await browser.newPage(); let attempted = 0;
    const tab = await openFakeHost(page, { ...inbox, kitDelivery: delivery, queries: () => { attempted++; return result([]); }, calls: () => { attempted++; } });
    try {
      await tab.frame.getByText('Open with Native core kit 1.7.13 or later.').waitFor();
      assert.equal(attempted, 0); await tab.expectHealthy();
    } finally { await tab.close(); await page.close(); }
  }
  console.log('Meeting notes: receipt/list ordering, click/Enter focus, frozen capture, continued composition, default recovery, same-key retry, kind paging, scope fence and old-host fallback passed.');
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const chromium = await loadChromium(); assert.ok(chromium, 'Playwright required');
  const browser = await chromium.launch({ ...(process.env.ALPHA_TAB_KIT_CHROMIUM ? { executablePath: process.env.ALPHA_TAB_KIT_CHROMIUM } : {}) });
  try { await checkMeetingNotes(browser, starters[1]); } finally { await browser.close(); }
}
