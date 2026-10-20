// Explicit acceptance: fail (never skip) without Chromium or freshly emitted Rust custody.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadChromium, openFakeHost } from '../src/fake-host/playwright.mjs';
import { injectBridge } from '../src/fake-host/server.mjs';
import { starters } from './helpers/source-starters.mjs';
const chromium = await loadChromium();
assert.ok(chromium, 'Playwright required');
const browser = await chromium.launch({headless: true});
const [reader, inbox] = starters;
const snapshot = rows => ({ sql: { 'records.recent': { rows, columns: ['id','name','type'], row_count: rows.length, row_count_complete: true, truncated: false } } });
const notes = { columns: ['id','name','body'], rows: [['note-1','Planning','**Hello** <img src=x onerror=alert(1)> &amp; safe\n\n' + 'Large '.repeat(6000) + '\nBODY_END'], ['note-2','Review','Second']], truncated: false };
// The hosted read hub passes `query_sql` rows through, and those are objects keyed by column name.
const sqlAnswer = (columns, cells, truncated = false) => ({ columns, rows: cells.map(row => Object.fromEntries(columns.map((key, i) => [key, row[i]]))), truncated });
// The decoder run set 3 copied from the starter (c904228): it reads positional cells and blanks named rows.
const ARRAY_DECODER = "  const objects = result => (result?.rows || []).map(cells => Object.fromEntries(result.columns.map((key, i) => [key, cells[i]])));\n";
function withArrayDecoder(html) {
  let out = html;
  for (const [from, to] of [
    ['  // SQL query rows arrive as objects keyed by column name: use row.id, never row[0].\n', ARRAY_DECODER],
    ['const note = result?.rows[0];', 'const note = objects(result)[0];'],
    ['const rows = result?.rows || [];', 'const rows = objects(result);'],
  ]) { assert.equal(out.split(from).length, 2, `starter no longer contains ${from}`); out = out.replace(from, to); }
  return out;
}
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
  // Queries, errors, retries, filtering, safe Markdown and confirmed-only writes.
  {
    let releaseQuery;
    const gate = new Promise(resolve => releaseQuery=resolve);
    const created = new Map(); const attempts=[]; let mode='confirmed'; let callNumber=0;
    const page = await browser.newPage();
    page.on('pageerror', e => console.error('inbox browser error',e.message));
    const tab = await openFakeHost(page, {...inbox, latencyMs:500,
      queries:async query => {
        await gate;
        const rows=[...notes.rows, ...[...created.values()].filter(row=>row.home_id===query.parameters.at(-1).value).map(row=>[row.id,row.name,row.body])];
        if(query.parameters.length===2) {
          assert.match(query.sql,/id = \?1 AND home_id = \?2/);
          assert.match(query.sql,/substr\(body, 1, 120000\).*LIMIT 1/);
          return sqlAnswer(notes.columns, rows.filter(row=>row[0]===query.parameters[0].value).map(row=>[row[0],row[1].slice(0,160),row[2].slice(0,120000)]));
        }
        assert.match(query.sql,/substr\(body, 1, 160\).*LIMIT 50/);
        return sqlAnswer(['id','name','excerpt'], rows.slice(0,50).map(row=>[row[0],row[1].slice(0,160),row[2].slice(0,160)]));
      },
      calls:async (op,args) => {
        assert.equal(op,'create_record'); attempts.push(structuredClone(args)); callNumber++;
        if(mode==='refused') throw Object.assign(new Error('Write refused'),{status:'refused',code:'forbidden'});
        if(!created.has(args.idempotency_key)) created.set(args.idempotency_key,{id:`saved-${created.size}`, ...args});
        if(mode==='commit-error' && callNumber===1) throw new Error('500 after commit');
        if(mode==='uncertain' && callNumber===1) throw Object.assign(new Error('Receipt lost'),{status:'uncertain'});
        return created.get(args.idempotency_key);
      }});
    const frame = page.frames().find(f => f.url().includes('/frame'));
    await frame.getByText('Loading notes…').waitFor(); releaseQuery();
    await frame.getByRole('button',{name:'Planning',exact:true}).waitFor();
    assert.match(await frame.locator('nav').textContent(),/\*\*Hello\*\* <img/);
    await frame.locator('#filter').fill('review');
    await frame.getByRole('button',{name:'Planning',exact:true}).waitFor({state:'hidden'});
    await frame.getByRole('button',{name:'Review',exact:true}).waitFor();
    await frame.locator('#filter').fill('no such title');
    await frame.getByText('No matching notes.').waitFor();
    await frame.locator('#filter').fill('');
    await frame.getByRole('button',{name:'Planning',exact:true}).click();
    await frame.locator('article strong').waitFor();
    assert.equal(await frame.locator('article strong').textContent(),'Hello');
    assert.match(await frame.locator('article').textContent(),/BODY_END/);
    assert.equal(await frame.locator('article img').count(),0);
    assert.match(await frame.locator('article').textContent(),/<img src=x onerror=alert\(1\)> & safe/);
    assert.equal(await frame.locator('article [data-native-record-id="note-1"]').count(),1);
    let subs=await tab.subscriptions();
    const list=sqlAnswer(['id','name','excerpt'],notes.rows.map(row=>[row[0],row[1],row[2].slice(0,160)]));
    await tab.pushSubscription(subs[0], {...list, rows:[]});
    await frame.getByText('No matching notes.').waitFor();
    await tab.pushSubscription(subs[0], list);
    await frame.getByRole('button',{name:'Planning',exact:true}).waitFor();
    // Last-good named rows survive an error, in the list and the selected note.
    const noteSub=subs.find(sub=>sub!==subs[0]);
    assert.ok(noteSub,'the selected note has its own subscription');
    await tab.failSubscription(noteSub,'forbidden','Body refused',false);
    await frame.getByText('Last good body; may be out of date.').waitFor();
    assert.equal(await frame.locator('article strong').textContent(),'Hello');
    assert.equal(await frame.locator('article [data-native-record-id="note-1"]').count(),1);
    await tab.failSubscription(subs[0],'forbidden','Read refused',true);
    await frame.getByText('Last good rows; may be out of date.').waitFor();
    await frame.getByRole('button',{name:'Planning',exact:true}).waitFor();
    assert.match(await frame.locator('nav').textContent(),/Second/);
    await frame.locator('.kit-error').first().getByRole('button',{name:'Try again'}).click();
    await frame.getByText('Last good rows; may be out of date.').waitFor({state:'hidden'});
    await frame.locator('#folder').selectOption('native:root');
    await until(page,()=>window.__alphaTabHost.events().some(e=>e.type==='subscribe' && e.query.parameters?.[0]?.value==='native:root'));
    assert.ok((await tab.events()).some(e=>e.type==='unsubscribe'));
    assert.equal(await frame.locator('article').textContent(),'Select a note to read its preview.');
    async function fillAndCreate(title) {
      await frame.locator('#title').fill(title); await frame.locator('#body').fill('Meeting body'); await frame.locator('#create').click();
      await frame.getByText('Saving… waiting for confirmation.').waitFor();
    }
    await fillAndCreate('First');
    await frame.getByText('Saved.',{exact:true}).waitFor();
    assert.equal(await frame.locator('#title').inputValue(),''); assert.equal(created.size,1);
    await frame.getByRole('button',{name:'First',exact:true}).waitFor();
    mode='refused'; await fillAndCreate('Refused');
    await frame.getByText('Write refused',{exact:true}).waitFor();
    assert.equal(created.size,1); assert.equal(await frame.locator('#title').inputValue(),'Refused');
    mode='uncertain'; callNumber=0; await frame.locator('#title').fill('Retry me');
    await frame.locator('#create').click();
    await frame.getByText(/Outcome uncertain/).waitFor();
    assert.equal(await frame.locator('#title').isDisabled(),true);
    const size=created.size; const first=attempts.at(-1);
    mode='refused';
    await frame.getByRole('button',{name:'Try again'}).click();
    await frame.getByText('Write refused',{exact:true}).waitFor();
    assert.equal(await frame.locator('#title').isDisabled(),true);
    assert.deepEqual(attempts.at(-1),first);
    mode='confirmed';
    await frame.getByRole('button',{name:'Try again'}).click();
    await frame.getByText('Saved.',{exact:true}).waitFor();
    assert.deepEqual(attempts.at(-1),first); assert.equal(created.size,size);
    await frame.getByRole('button',{name:'Retry me',exact:true}).waitFor();
    // A plain error can follow commit; fields and the key must remain locked.
    mode='commit-error'; callNumber=0;
    await fillAndCreate('Committed before error');
    await frame.getByText(/Outcome uncertain/).waitFor();
    assert.equal(await frame.locator('#title').isDisabled(),true);
    const committed=created.size; const committedAttempt=attempts.at(-1);
    await frame.getByRole('button',{name:'Try again'}).click();
    await frame.getByText('Saved.',{exact:true}).waitFor();
    assert.deepEqual(attempts.at(-1),committedAttempt);
    assert.equal(created.size,committed);
    await frame.getByRole('button',{name:'Committed before error',exact:true}).waitFor();
    // Key generation failure is visible and never dispatches a call.
    mode='confirmed'; const count=attempts.length;
    await frame.evaluate(()=>{window.originalUUID=crypto.randomUUID;crypto.randomUUID=undefined;});
    await frame.locator('#title').fill('Missing random key');
    await frame.locator('#create').click();
    await frame.getByText(/Secure random key unavailable/).waitFor();
    assert.equal(attempts.length,count);
    assert.equal(await frame.locator('#title').isDisabled(),false);
    await frame.evaluate(()=>{crypto.randomUUID=window.originalUUID;});
    await frame.evaluate(()=>native.kit.preact.render(null,document.getElementById('app')));
    await until(page,()=>window.__alphaTabHost.subscriptions().length===0);
    assert.equal(await frame.locator('#app').textContent(),'');
    await tab.expectHealthy(); await tab.close(); await page.close();
  }
  // Regression for run set 3: the array-only decoder must fail on the same live-shaped rows.
  {
    const page=await browser.newPage();
    const tab=await openFakeHost(page,{...inbox,html:withArrayDecoder(inbox.html),queries:()=>sqlAnswer(['id','name','excerpt'],[['note-1','Planning','Agenda']])});
    const frame=page.frames().find(f=>f.url().includes('/frame'));
    await frame.locator('nav button').first().waitFor();
    assert.equal(await frame.getByRole('button',{name:'Planning',exact:true}).count(),0);
    assert.equal((await frame.locator('nav button').first().textContent()).trim(),'');
    await frame.locator('#filter').fill('plan');
    await frame.getByText('No matching notes.').waitFor();
    await tab.expectHealthy(); await tab.close(); await page.close();
  }
  {
    const page=await browser.newPage();
    const tab=await openFakeHost(page,inbox);
    const frame=page.frames().find(f=>f.url().includes('/frame'));
    await frame.getByText('This host does not offer app-v2 query subscriptions.').waitFor();
    await frame.getByText('This host does not offer app-v2 writes.').waitFor();
    assert.equal(await frame.locator('#create').isDisabled(),true);
    await tab.expectHealthy(); await tab.close(); await page.close();
  }
  // Fifty worst-case escaped excerpts and one long selected body fit the answer cap.
  {
    const longBody='\u0001'.repeat(60000)+'BODY_AFTER_EXCERPT'+'\u0001'.repeat(70000);
    const rows=Array.from({length:100},(_,i)=>[`long-${i}`, '\u0001'.repeat(160),longBody]);
    const delivered=[];
    const page=await browser.newPage();
    const tab=await openFakeHost(page,{...inbox,queries:query=>{
      const selected=query.parameters.length===2;
      const bodyLimit=Number(query.sql.match(/substr\(body,\s*1,\s*(\d+)\)/i)[1]);
      const rowLimit=Number(query.sql.match(/\bLIMIT\s+(\d+)/i)[1]);
      const result=sqlAnswer(['id','name',selected?'body':'excerpt'],
        (selected?rows.filter(row=>row[0]===query.parameters[0].value):rows.slice(0,rowLimit))
          .map(row=>[row[0],row[1],row[2].slice(0,bodyLimit)]),!selected);
      const bytes=Buffer.byteLength(JSON.stringify(result));
      assert.ok(bytes<1048576);
      if (!selected) assert.ok(bytes<100000, "list only fetches the displayed excerpts");
      delivered.push(result); return result;
    }});
    const frame=page.frames().find(f=>f.url().includes('/frame'));
    await frame.locator('nav button').first().waitFor();
    assert.equal(await frame.locator('nav button').count(),50);
    await frame.locator('nav button').first().click();
    await frame.getByText('Body preview, up to 120,000 characters.').waitFor();
    assert.match(await frame.locator('.kit-markdown').textContent(),/BODY_AFTER_EXCERPT/);
    assert.equal(delivered[0].rows[0].excerpt.length,160);
    assert.equal(delivered.at(-1).rows[0].body.length,120000);
    assert.equal(await frame.locator('.kit-error').count(),0);
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
