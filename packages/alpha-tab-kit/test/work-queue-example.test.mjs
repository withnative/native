import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadChromium } from '../src/fake-host/playwright.mjs';
import { validateHtml } from '../src/html.mjs';
import { startFakeHost } from '../src/fake-host/server.mjs';
import { startWorkQueueFixture, taskId } from '../examples/work-queue-fixture.mjs';

const chromium = await loadChromium();
let browser;
before(async () => { if (chromium) browser = await chromium.launch(); });
after(async () => { await browser?.close(); });
const skip = !chromium && 'Playwright is not installed';
async function open(options = {}, query = '') {
  const fixture = await startWorkQueueFixture(options);
  const page = await browser.newPage();
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  await page.goto(fixture.url + query);
  const frame = page.frameLocator('#app-frame');
  await frame.locator('#brief').waitFor();
  return { fixture, page, frame, errors, close: async () => { await page.close(); await fixture.close(); } };
}
async function approve(tab, brief = 'Compare the handoff glue. Recommend one small improvement.') {
  await tab.frame.locator('#brief').fill(brief);
  await tab.frame.locator('#prepare').click();
  await tab.frame.locator('#start').waitFor();
}

test('the exact source is a valid installable app using the supplied kit', async () => {
  const html = readFileSync(new URL('../examples/work-queue.html', import.meta.url), 'utf8');
  assert.deepEqual(validateHtml(html).filter(x => x.severity === 'error'), []);
  const declaration = JSON.parse(readFileSync(new URL('../examples/work-queue.declaration.json', import.meta.url)));
  const host = await startFakeHost({ html, descriptor: { package: 'agent.work-queue', version: '0.1.0', declaration } });
  await host.close();
});

test('approves exact wording, starts once, returns a linked result and sends feedback to that session', { skip }, async () => {
  const tab = await open();
  try {
    const brief = 'Find one useful kit improvement. Keep the recommendation under 150 words.';
    await approve(tab, brief);
    assert.equal(tab.fixture.launches.length, 0, 'saving approval must never start an agent');
    const record = tab.fixture.records[0], approved = JSON.parse(record.body);
    assert.equal(approved.brief, brief);
    assert.equal(approved.taskId, taskId);
    assert.ok(tab.fixture.links.some(l => l.source_id === record.id && l.target_id === taskId));
    await tab.frame.locator('#brief').fill('This new wording is not approved yet.');
    await tab.frame.locator('#start').click();
    await tab.frame.locator('#open-session').waitFor();
    const launch = tab.fixture.launches[0];
    assert.equal(launch.request_id, approved.requestKey);
    assert.ok(launch.initial_prompt.startsWith(brief));
    assert.ok(!launch.initial_prompt.includes('This new wording'));
    assert.ok(launch.initial_prompt.includes(record.id));
    assert.equal(launch.quoted[0].text, approved.evidence);
    await tab.frame.locator('.result').waitFor();
    assert.equal(tab.fixture.sessions.size, 1);
    assert.equal(await tab.frame.locator('#start').isDisabled(), true);
    await tab.frame.locator('#followup').fill('Please include a concrete example.');
    await tab.frame.locator('#send-feedback:not([disabled])').waitFor();
    await tab.frame.locator('#send-feedback').click();
    await tab.page.waitForFunction(() => window.fixture.received().some(m => m.type === 'agent-sessions-send'));
    assert.equal(tab.fixture.sends[0].session_id, [...tab.fixture.sessions.values()][0].id);
    assert.match(tab.fixture.sends[0].text, /Please include a concrete example/);
    assert.deepEqual(tab.errors, []);
  } finally { await tab.close(); }
});

test('a lost launch answer is recovered under its canonical key after reload, without another session', { skip }, async () => {
  const tab = await open({ loseFirstLaunch: true });
  try {
    await approve(tab);
    await tab.frame.locator('#start').click();
    await tab.frame.locator('[data-write-status="uncertain"]').waitFor();
    const original = tab.fixture.launches[0].request_id;
    await tab.page.reload();
    await tab.frame.locator('#recover').waitFor();
    assert.equal(tab.fixture.launches.length, 1, 'reload must not auto launch');
    await tab.frame.locator('#recover').click();
    await tab.frame.locator('#open-session').waitFor();
    assert.equal(await tab.frame.locator('[data-write-status="uncertain"]').count(), 0);
    assert.equal(tab.fixture.sessions.size, 1);
    assert.equal(tab.fixture.launches[0].request_id, original);
    assert.deepEqual(tab.errors, []);
  } finally { await tab.close(); }
});

test('a second approved brief binds its own session rather than the first completed launch', { skip }, async () => {
  const tab = await open();
  try {
    await approve(tab, 'First research question');
    await tab.frame.locator('#start').click();
    await tab.frame.locator('#open-session').waitFor();
    await approve(tab, 'Second research question');
    await tab.frame.locator('#start:not([disabled])').waitFor();
    await tab.frame.locator('#start').click();
    await tab.frame.locator('#open-session').waitFor();
    await tab.frame.locator('#followup').fill('Feedback on the second brief');
    await tab.frame.locator('#send-feedback:not([disabled])').waitFor();
    await tab.frame.locator('#send-feedback').click();
    await tab.page.waitForFunction(() => window.fixture.received().some(m => m.type === 'agent-sessions-send'));
    assert.equal(tab.fixture.sessions.size, 2);
    assert.equal(tab.fixture.sends[0].session_id, [...tab.fixture.sessions.values()][1].id);
    assert.deepEqual(tab.errors, []);
  } finally { await tab.close(); }
});

test('draft survives source updates and a device-backed reload; a scope change disables the app', { skip }, async () => {
  const tab = await open();
  try {
    // The form mounts before the initial suggestion effect fills and saves it.
    // Let that settle before Playwright selects the value for replacement.
    await tab.frame.getByText('Your place and brief are saved on this device.', { exact: false }).waitFor();
    await tab.frame.locator('#brief').fill('My unsaved wording');
    await tab.frame.getByText('Your place and brief are saved on this device.', { exact: false }).waitFor();
    tab.fixture.tasks[0].summary = 'Another agent changed the suggestion';
    await tab.page.evaluate(() => window.fixture.push());
    assert.equal(await tab.frame.locator('#brief').inputValue(), 'My unsaved wording');
    await tab.page.reload();
    await tab.frame.locator('#brief').waitFor();
    assert.equal(await tab.frame.locator('#brief').inputValue(), 'My unsaved wording');
    await tab.page.evaluate(() => window.fixture.failScope());
    await tab.frame.getByText('Your workspace access changed. Reload to continue.').waitFor();
    assert.equal(await tab.frame.locator('#start').count(), 0);
    assert.equal(tab.fixture.launches.length, 0);
  } finally { await tab.close(); }
});

test('reopens the suggested brief before held list and task reads return, keeping edits during refresh', { skip }, async () => {
  const tab = await open();
  try {
    const suggestion = tab.fixture.tasks[0].summary;
    await tab.frame.getByText('Your place and brief are saved on this device.', { exact: false }).waitFor();
    assert.equal(await tab.frame.locator('#brief').inputValue(), suggestion);
    // Neither read has a kit fixture cache. Device form state must restore the
    // selected id and its suggested text without waiting for either response.
    tab.fixture.holdReads({ lists: true, task: true });
    await tab.page.reload();
    await tab.frame.locator('#brief').waitFor();
    assert.equal(await tab.frame.locator('#brief').inputValue(), suggestion);
    assert.equal(await tab.frame.locator('#brief').isDisabled(), false);
    assert.equal(await tab.frame.locator('#prepare').isDisabled(), true, 'a saved draft alone cannot approve a missing source');
    await tab.frame.getByText('Showing your saved brief while the task refreshes.').waitFor();
    await tab.frame.locator('#brief').fill('My wording during the refresh');
    tab.fixture.releaseReads();
    await tab.frame.getByRole('heading', { name: 'Find the most useful next kit improvement', exact: true }).waitFor();
    assert.equal(await tab.frame.locator('#brief').inputValue(), 'My wording during the refresh');
    assert.deepEqual(tab.errors, []);
  } finally { await tab.close(); }
});

test('cold startup reports loading rather than asking for an unavailable selection or claiming a restored brief', { skip }, async () => {
  const fixture = await startWorkQueueFixture();
  fixture.holdReads();
  const page = await browser.newPage();
  try {
    await page.goto(fixture.url);
    const frame = page.frameLocator('#app-frame');
    await frame.getByText('No saved brief on this device yet.', { exact: false }).waitFor();
    await frame.locator('section.panel > p.empty').getByText('Loading proposals…', { exact: true }).waitFor();
    assert.equal(await frame.getByText('Select a proposal to get started.', { exact: true }).count(), 0);
    assert.equal(await frame.getByText('Drafts restored from this device.', { exact: false }).count(), 0);
    fixture.releaseReads();
    await frame.locator('#brief').waitFor();
  } finally { await page.close(); await fixture.close(); }
});

test('host capability gaps stay usable and approval refusal preserves the draft without launching', { skip }, async () => {
  const noAgents = await open({}, '?agents=off&state=off');
  try {
    await noAgents.frame.getByText('Open this app in Native Desktop with agent access', { exact: false }).waitFor();
    assert.equal(await noAgents.frame.locator('#prepare').isDisabled(), true);
    await noAgents.frame.locator('#brief').fill('Keep this in the page');
    await noAgents.frame.getByText('Drafts stay in this page; device saving is unavailable.', { exact: false }).waitFor();
    assert.equal(noAgents.fixture.launches.length, 0);
  } finally { await noAgents.close(); }
  const tab = await open({ refuseApproval: true });
  try {
    await tab.frame.locator('#brief').fill('My approved words');
    await tab.frame.locator('#prepare').click();
    await tab.frame.locator('[data-write-status="failed"]').waitFor();
    assert.equal(await tab.frame.locator('#brief').inputValue(), 'My approved words');
    assert.equal(await tab.frame.locator('#start').count(), 0);
    assert.equal(tab.fixture.launches.length, 0);
  } finally { await tab.close(); }
});

test('retrying an uncertain launch sends the same frozen request; UTF-8 overflow cannot be approved', { skip }, async () => {
  const tab = await open({ loseFirstLaunch: true });
  try {
    await approve(tab);
    await tab.frame.locator('#start').click();
    await tab.frame.locator('[data-write-status="uncertain"]').waitFor();
    await tab.frame.locator('[data-write-status="uncertain"]').getByRole('button', { name: 'Retry', exact: true }).click();
    await tab.frame.locator('#open-session').waitFor();
    assert.equal(tab.fixture.launches.length, 2);
    assert.deepEqual(tab.fixture.launches[1], tab.fixture.launches[0]);
    assert.equal(tab.fixture.sessions.size, 1);
    await tab.frame.locator('#brief').fill('界'.repeat(5000));
    await tab.frame.getByText('The brief and evidence are too long for this agent launch.', { exact: false }).waitFor();
    assert.equal(await tab.frame.locator('#prepare').isDisabled(), true);
    assert.deepEqual(tab.errors, []);
  } finally { await tab.close(); }
});

test('launch choices work independently of unavailable or empty conversation lists', { skip }, async () => {
  for (const options of [{ listUnavailable: true }, { emptyListHosts: true }]) {
    const tab = await open(options);
    try {
      await tab.frame.locator('#host:not([disabled])').waitFor();
      assert.equal(await tab.frame.locator('#host').inputValue(), 'fixture');
      assert.equal(await tab.frame.locator('#provider').isDisabled(), false);
      assert.equal(await tab.frame.locator('#model').isDisabled(), false);
      assert.equal(await tab.frame.locator('#workspace').isDisabled(), false);
      await tab.frame.locator('#model').selectOption('demo-model');
      await tab.frame.locator('#workspace').selectOption('ordinary');
      await approve(tab);
      await tab.frame.locator('#start').click();
      await tab.frame.locator('#open-session').waitFor();
      assert.equal(tab.fixture.sessions.size, 1);
      assert.deepEqual(tab.errors, []);
    } finally { await tab.close(); }
  }
});

test('failed catalog is explained and a deliberate reload restores the dropdowns without losing the brief', { skip }, async () => {
  const tab = await open({ catalogFailures: 3 });
  try {
    await tab.frame.locator('#brief').fill('Keep my wording while choices reconnect.');
    await tab.frame.getByText('Native Desktop could not load agent choices.', { exact: false }).waitFor();
    // Three bounded reads fail; the app then offers a real reload action.
    await tab.page.waitForFunction(() => window.fixture.received().filter(m => m.type === 'agent-sessions-catalog').length >= 3);
    await tab.frame.locator('#refresh-choices').click();
    await tab.frame.locator('#host:not([disabled])').waitFor();
    assert.equal(await tab.frame.locator('#brief').inputValue(), 'Keep my wording while choices reconnect.');
    assert.equal(await tab.frame.locator('#model').isDisabled(), false);
    assert.equal(await tab.frame.locator('#workspace').isDisabled(), false);
    assert.deepEqual(tab.errors, []);
  } finally { await tab.close(); }
});


test('an independent saved-brief read failure keeps the acknowledged approval and names one retry', { skip }, async () => {
  const tab = await open();
  try {
    tab.fixture.failReads({ approvals: true });
    await approve(tab, 'Frozen approved research');
    await tab.frame.getByText(/Saved-brief list could not load. Your new brief is saved in Native./).waitFor();
    assert.equal(tab.fixture.calls.length, 1);
    assert.equal(tab.fixture.launches.length, 0);
    assert.equal(await tab.frame.locator('#start').isDisabled(), false);
    await tab.frame.locator('#brief').fill('Later unapproved edits');
    await tab.frame.locator('#start').click();
    await tab.frame.locator('#open-session').waitFor();
    assert.ok(tab.fixture.launches[0].initial_prompt.startsWith('Frozen approved research'));
    const warning = tab.frame.getByRole('alert').filter({ hasText: 'Saved-brief list' });
    assert.equal(await warning.getByRole('button', { name: 'Try again', exact: true }).count(), 1);
    tab.fixture.failReads(); await warning.getByRole('button', { name: 'Try again' }).click();
    await warning.waitFor({ state: 'hidden' });
    assert.equal(tab.fixture.calls.length, 1, 'repairing the read must not repeat the write');
    assert.equal(await tab.frame.locator('#brief').inputValue(), 'Later unapproved edits');
    assert.deepEqual(tab.errors, []);
  } finally { await tab.close(); }
});

test('a cold task failure has one recovery action and leaves the saved draft editable', { skip }, async () => {
  const tab = await open();
  try {
    await tab.frame.locator('#brief').fill('Keep my draft');
    tab.fixture.failReads({ task: true }); await tab.page.evaluate(() => window.fixture.push());
    await tab.frame.getByText('Source task could not load.', { exact: true }).waitFor();
    assert.equal(await tab.frame.getByRole('button', { name: 'Try again', exact: true }).count(), 1);
    assert.equal(await tab.frame.getByRole('button', { name: 'Reload task' }).count(), 0);
    assert.equal(await tab.frame.locator('#brief').inputValue(), 'Keep my draft');
    assert.equal(await tab.frame.locator('#brief').isDisabled(), false);
    tab.fixture.failReads(); await tab.frame.getByRole('button', { name: 'Try again' }).click();
    await tab.frame.locator('.evidence').waitFor();
    assert.equal(await tab.frame.locator('#brief').inputValue(), 'Keep my draft');
  } finally { await tab.close(); }
});


test('a persistent transient approvals refresh failure retains the saved brief through quiet recovery', { skip }, async () => {
  const tab = await open();
  try {
    tab.fixture.failReads({ approvals: true, transient: true });
    await approve(tab, 'Keep the acknowledged approval');
    await tab.frame.getByText(/Saved-brief list could not (load|refresh). Your new brief is saved in Native./).waitFor({ timeout: 25000 });
    assert.equal(await tab.frame.locator('#start').isDisabled(), false);
    const warning = tab.frame.getByRole('alert').filter({ hasText: 'Saved-brief list' });
    assert.equal(await warning.getByRole('button', { name: 'Try again', exact: true }).count(), 1);
    assert.equal(tab.fixture.calls.length, 1);
    tab.fixture.failReads(); await warning.getByRole('button', { name: 'Try again' }).click();
    await warning.waitFor({ state: 'hidden' });
    assert.equal(tab.fixture.calls.length, 1);
  } finally { await tab.close(); }
});
