// Explicit acceptance: fail (never skip) without Chromium or freshly emitted Rust custody.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadChromium, openFakeHost } from '../src/fake-host/playwright.mjs';
import { injectBridge } from '../src/fake-host/server.mjs';
import { checkMeetingNotes } from './meeting-notes-browser.mjs';
import { starters } from './helpers/source-starters.mjs';
import { readKitAssets, createKitDelivery } from '../src/fake-host/kit-assets.mjs';
const chromium = await loadChromium();
assert.ok(chromium, 'Playwright required');
const browser = await chromium.launch({headless: true});
const [reader, inbox, records] = starters;
const snapshot = rows => ({ sql: { 'records.recent': { rows, columns: ['id','name','type'], row_count: rows.length, row_count_complete: true, truncated: false } } });
const notes = { columns: ['id','name','body'], rows: [['note-1','Planning','**Hello** <img src=x onerror=alert(1)> &amp; safe\n\n' + 'Large '.repeat(6000) + '\nBODY_END'], ['note-2','Review','Second']], truncated: false };
// The hosted read hub passes `query_sql` rows through, and those are objects keyed by column name.
const sqlAnswer = (columns, cells, truncated = false) => ({ columns, rows: cells.map(row => Object.fromEntries(columns.map((key, i) => [key, row[i]]))), truncated });
const until = async (page, predicate) => page.waitForFunction(predicate);
try {
  // v1 uses the exact guide bytes and gets no v2 methods, even with host options enabled.
  {
    let rows = [{id:'r1',name:'Alpha',type:'Document'},{id:'r2',name:'Beta',type:'Document'}];
    const page = await browser.newPage();
    const tab = await openFakeHost(page, { ...reader, calls:true, queries:true, fixtures:{sql:{'records.recent': () => rows}} });
    const frame = page.frames().find(f => f.url().includes('/frame'));
    await frame.getByText('Alpha', {exact:true}).waitFor();
    assert.deepEqual(await frame.evaluate(() => ['query','subscribe','call'].map(k => typeof native[k])), ['undefined','undefined','undefined']);
    await frame.locator('#filter').fill('beta');
    await frame.getByText('Alpha',{exact:true}).waitFor({state:'hidden'});
    assert.equal(await frame.locator('[data-native-record-id="r2"]').count(),1);
    rows=[]; await tab.pushInput();
    await frame.getByText('No matching records.').waitFor();
    await frame.evaluate(() => dispatchEvent(new Event('pagehide')));
    assert.equal(await frame.locator('#app').textContent(),'');
    await tab.expectHealthy(); await tab.close(); await page.close();
  }
  await checkMeetingNotes(browser, inbox);
  // record-reader (kit 1.7.0 record helpers): folder and id-list browsing, load-more, prev/next, truncation, unavailable ids, recovery.
  {
    const body = id => id === 'big' ? 'B'.repeat(130000) : `Body of ${id}`;
    const meta = id => ({ id, name: `Record ${id}`, type: 'Document', kind: 'note', lifecycle: 'open', summary: null, home_id: 'f', created_at: null, updated_at: null, updated_at_ms: 1, is_current: 1 });
    const folders = { 'native:root': Array.from({ length: 25 }, (_, i) => `r${i}`), 'native:unfiled': ['u0', 'u1'] };
    const known = new Set([...folders['native:root'], ...folders['native:unfiled'], 'big', 'a', 'b']);
    const asked = [];
    const answer = query => {
      asked.push(query);
      const value = i => query.parameters[i].value;
      if (/WHERE home_id = \?1/.test(query.sql)) {
        const limit = Number(query.sql.match(/LIMIT (\d+)$/)[1]);
        return sqlAnswer(Object.keys(meta('x')), (folders[value(0)] || []).slice(0, limit).map(id => Object.values(meta(id))), (folders[value(0)] || []).length > 200);
      }
      if (/WHERE id IN/.test(query.sql)) {
        const ids = query.parameters.map(p => p.value).filter(id => known.has(id));
        return sqlAnswer(Object.keys(meta('x')), ids.map(id => Object.values(meta(id))));
      }
      const id = value(0), n = Number(query.sql.match(/substr\(body, 1, (\d+)\)/)[1]);
      return sqlAnswer([...Object.keys(meta('x')), 'body', 'body_length'], known.has(id) ? [[...Object.values(meta(id)), body(id).slice(0, n), body(id).length]] : []);
    };
    const page = await browser.newPage();
    const tab = await openFakeHost(page, { ...records, queries: answer });
    const frame = page.frames().find(f => f.url().includes('/frame'));
    await frame.getByRole('button', { name: 'Record r0', exact: true }).waitFor();
    assert.equal(await frame.locator('nav li').count(), 20);
    assert.match(asked[0].sql, /WHERE home_id = \?1 AND deleted_at IS NULL AND archived = 0 .* ORDER BY updated_at_ms DESC, id ASC LIMIT 21$/);
    await frame.locator('#more').click();
    await frame.locator('nav li').nth(24).waitFor();
    assert.equal(await frame.locator('nav li').count(), 25);
    assert.equal(await frame.locator('#more').count(), 0);
    // Reader with previous/next; the previous record never shows under the next one.
    await frame.getByRole('button', { name: 'Record r0', exact: true }).click();
    await frame.getByText('Body of r0').waitFor();
    assert.equal(await frame.locator('#previous').isDisabled(), true);
    await frame.locator('#next').click();
    await frame.getByText('Body of r1').waitFor();
    assert.equal(await frame.getByText('Body of r0').count(), 0);
    await frame.locator('#previous').click();
    await frame.getByText('Body of r0').waitFor();
    // A large body says it is a prefix.
    await frame.locator('#mode-ids').click();
    await frame.locator('#ids').fill('b\nnope\nbig\na');
    await frame.locator('#open').click();
    await frame.getByText('1 listed record is unavailable to this account: nope').waitFor();
    assert.deepEqual(await frame.locator('nav li button').allTextContents(), ['Record b', 'Record big', 'Record a']);
    await frame.getByRole('button', { name: 'Record big', exact: true }).click();
    await frame.getByText('Showing the first 120,000 of 130,000 characters.').waitFor();
    // Folder to folder shows nothing of the old one.
    await frame.locator('#mode-folder').click();
    await frame.locator('#folder').fill('native:unfiled');
    await frame.locator('#open').click();
    await frame.getByRole('button', { name: 'Record u0', exact: true }).waitFor();
    assert.deepEqual(await frame.locator('nav li button').allTextContents(), ['Record u0', 'Record u1']);
    // A transient failure keeps the record and rows on screen; a definite answer clears them.
    await frame.getByRole('button', { name: 'Record u1', exact: true }).click();
    await frame.getByText('Body of u1').waitFor();
    const subs = await tab.subscriptions();
    for (const sub of subs) await tab.failSubscription(sub, 'network_lost', 'Connection lost', false);
    await frame.getByText('Body of u1').waitFor();
    assert.equal(await frame.getByRole('button', { name: 'Record u0', exact: true }).count(), 1);
    for (const sub of await tab.subscriptions()) await tab.failSubscription(sub, 'access_denied', 'Not allowed', false);
    await frame.locator('.kit-error').first().getByRole('button', { name: 'Try again' }).waitFor();
    assert.equal(await frame.getByText('Body of u1').count(), 0);
    assert.equal(await frame.getByRole('button', { name: 'Record u0', exact: true }).count(), 0);
    await tab.expectHealthy(); await tab.close(); await page.close();
  }
  {
    const page = await browser.newPage();
    const tab = await openFakeHost(page, records);
    const frame = page.frames().find(f => f.url().includes('/frame'));
    await frame.getByText('This host does not offer app-v2 query subscriptions.').waitFor();
    await tab.expectHealthy(); await tab.close(); await page.close();
  }
  // Exact read-only starter through Rust legacy ticket custody and real MessagePort bootstrap.
  const real=readFileSync(process.env.NATIVE_STARTER_REAL_HTML,'utf8');
  assert.equal(real,injectBridge(reader.html,'https://parent.test'));
  const page=await browser.newPage();
  await page.route('https://artifact.test/**',route=>route.fulfill({contentType:'text/html',body:real}));
  await page.route('https://parent.test/**',route=>route.fulfill({contentType:'text/html',body:`<!doctype html><iframe sandbox="allow-scripts" src="https://artifact.test/frame"></iframe><script>addEventListener('message',event=>{if(event.data.type!=='native-html-bootstrap')return;const channel=new MessageChannel();window.port=channel.port1;channel.port1.start();event.source.postMessage({type:'native-html-init',version:'native.html.bridge.v1',input:${JSON.stringify(snapshot([{id:'real-1',name:'Rust custody',type:'Document'}]))},input_digest:'initial',revision:{content_event_seq:1},host_features:[]},'*',[channel.port2]);});</script>`}));
  await page.goto('https://parent.test/');
  const frame=page.frames().find(f=>f.url().startsWith('https://artifact.test/'));
  await frame.getByText('Rust custody',{exact:true}).waitFor();
  assert.equal(await frame.locator('[data-native-record-id="real-1"]').count(),1);
  await page.evaluate(()=>window.port.postMessage({version:'native.html.bridge.v1',type:'input',input:{sql:{'records.recent':{bad:true}}},input_digest:'bad',revision:{content_event_seq:2}}));
  await frame.getByText('Last good rows; may be out of date.').waitFor();
  assert.equal(await frame.locator('[data-native-record-id="real-1"]').count(),1);
  await page.evaluate(input=>window.port.postMessage({version:'native.html.bridge.v1',type:'input',input,input_digest:'empty',revision:{content_event_seq:3}}),snapshot([]));
  await frame.getByText('No matching records.').waitFor();
  await frame.evaluate(()=>dispatchEvent(new Event('pagehide')));
  assert.equal(await frame.locator('#app').textContent(),'');
  await page.close();
  console.log('Source starters: fake-host journey and Rust-custody inline-module browser proof passed.');
} finally { await browser.close(); }
