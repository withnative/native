import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { loadChromium } from '../src/fake-host/playwright.mjs';
import { injectBridge } from '../src/fake-host/server.mjs';
import { createKitDelivery, readKitAssets } from '../src/fake-host/kit-assets.mjs';

const chromium = await loadChromium();
const delivery = createKitDelivery(await readKitAssets(), { schema: 'native.app-kit.selector.v1', selections: [{ major: 1, version: '1.7.14' }] });
let server, browser, base;
const app = `<!doctype html><html><head><script type="application/json" id="native-app-kit">{"schema":"native.app-kit.v1","major":1}</script></head><body><main id="app"></main><script>
(async()=>{const kit=window.native.kit;await kit.ready;const ui=kit.preact;
function Screen(){const read=ui.useRecord('record-a');return ui.h('article',{'data-error':read.error?.code||''},ui.h('p',{id:'body'},read.body||''),ui.h('input',{id:'draft'}),ui.h(ui.FeedNotice,{feed:read}))}
ui.render(ui.h(Screen,{}),document.getElementById('app'))})();
</script></body></html>`;
const parent = `<!doctype html><html><body><iframe id="f" sandbox="allow-scripts"></iframe><script type="module">
import {createRecordObservationPort} from '/launcher/recordObservationPort.mjs';
const frame=document.getElementById('f'),generation='same-launch';let owner,wire,current=true,held=false,resumes=0,reads=0,refused=false,ignoreReconnect=false;
const value=body=>({status:'ready',result:{columns:['id','name','type','kind','body','body_length'],rows:[['record-a','Title','Document','note',body,body.length]],truncated:false}});
const deferred=[];const posted=[];
function physical(){const pair=new MessageChannel();wire=pair.port1;const original=wire.postMessage.bind(wire);wire.postMessage=v=>{posted.push(v);original(v)};return pair}
window.host={
 drop(){wire.close()},
 hold(){held=true},
 release(){held=false;for(const done of deferred.splice(0))done(refused?{status:'error',code:'access_denied',message:'Access removed',terminal:true,clear:true}:value('Refreshed body'))},
 revoke(){refused=true},
 ignore(value){ignoreReconnect=value},
 end(){current=false;owner.dispose('scope_changed')},
 stats(){return {...owner.diagnostics(),resumes,reads,posted:posted.map(v=>({type:v.type,delivery_id:v.delivery_id,control_id:v.control_id}))}}
};
addEventListener('message',event=>{if(event.source!==frame.contentWindow||event.data?.type!=='native-html-bootstrap')return;
 const main=new MessageChannel(),lane=physical();
 owner=createRecordObservationPort({port:lane.port1,generation,protocolVersion:2,resumable:true,isCurrent:()=>current,hasScopeChanged:()=>!current,
 subscribeInvalidation:()=>()=>{},read:()=>{reads++;return held?new Promise(done=>deferred.push(done)):Promise.resolve(value('Loaded body'))}});
 main.port1.onmessage=event=>{const m=event.data;if(m.type!=='records-reconnect')return;resumes++;if(ignoreReconnect===true||(typeof ignoreReconnect==='number'&&resumes<ignoreReconnect))return;const next=physical();
 if(current&&owner.replacePort(next.port1)){main.port1.postMessage({version:'native.html.bridge.v1',type:'records-reconnected',generation,request_id:m.request_id},[next.port2]);owner.refresh(undefined,{restart:true})}
 else{next.port1.close();next.port2.close();main.port1.postMessage({version:'native.html.bridge.v1',type:'records-reconnected',generation,request_id:m.request_id,code:'scope_changed'})}};
 main.port1.start();frame.contentWindow.postMessage({type:'native-html-init',version:'native.html.bridge.v1',input:{},host_features:['app.records.observe.v2','app.records.reconnect.v1'],record_observation:{generation}},'*',[main.port2,lane.port2]);
});frame.src='/frame';
</script></body></html>`;
before(async () => {
  server = createServer((req, res) => {
    if (/^\/launcher\/[A-Za-z]+\.mjs$/.test(req.url)) {
      res.writeHead(200, { 'content-type': 'text/javascript' });
      res.end(readFileSync(new URL(`../../native-launcher/src/${req.url.split('/').at(-1)}`, import.meta.url)));
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(req.url === '/frame' ? injectBridge(app, `http://${req.headers.host}`, delivery) : parent);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  if (chromium) browser = await chromium.launch();
});
after(async () => { await browser?.close(); await new Promise(resolve => server.close(resolve)); });
const skip = !chromium && 'Playwright is not installed';

test('generated kit keeps body and draft across a real lost port and network resume, then refreshes within the original budget', { skip }, async () => {
  const page = await browser.newPage();
  page.setDefaultTimeout(10000);
  page.on("pageerror", error => process.stderr.write(`BROWSER ${error.message}\n`));
  try {
    await page.goto(base);
    const frame = page.frameLocator('#f');
    await frame.locator('#body', { hasText: 'Loaded body' }).waitFor();
    await frame.locator('#draft').fill('My unsaved draft');
    await page.waitForFunction(() => window.host.stats().frameBodyBytes > 0);
    const before = await page.evaluate(() => window.host.stats());
    await page.evaluate(() => { window.host.hold(); window.host.drop(); });
    await page.context().setOffline(true);
    await page.context().setOffline(false);
    await page.waitForFunction(() => window.host.stats().resumes === 1);
    assert.equal(await frame.locator('#body').textContent(), 'Loaded body');
    assert.equal(await frame.locator('#draft').inputValue(), 'My unsaved draft');
    const during = await page.evaluate(() => window.host.stats());
    assert.equal(during.watches, 1);
    assert.equal(during.frameBodyBytes, before.frameBodyBytes);
    await page.evaluate(() => window.host.release());
    await frame.locator('#body', { hasText: 'Refreshed body' }).waitFor();
    assert.equal(await frame.locator('#draft').inputValue(), 'My unsaved draft');
    assert.deepEqual((await frame.locator('article [role="status"]').allTextContents()).filter(text => text.trim()), []);
    assert.equal((await page.evaluate(() => window.host.stats())).resumes, 1);
  } catch (error) { process.stderr.write(JSON.stringify(await page.evaluate(() => ({stats:window.host?.stats(),html:document.querySelector("iframe")?.outerHTML})))+"\n"); throw error; } finally { await page.close(); }
});

test('a confirmed access refusal after reconnect clears the held body', { skip }, async () => {
  const page = await browser.newPage();
  page.setDefaultTimeout(10000);
  page.on("pageerror", error => process.stderr.write(`BROWSER ${error.message}\n`));
  try {
    await page.goto(base);
    const frame = page.frameLocator('#f');
    await frame.locator('#body', { hasText: 'Loaded body' }).waitFor();
    await page.evaluate(() => { window.host.hold(); window.host.revoke(); window.host.drop(); });
    await page.context().setOffline(true);
    await page.context().setOffline(false);
    await page.waitForFunction(() => window.host.stats().resumes === 1);
    await page.evaluate(() => window.host.release());
    await frame.locator('article[data-error="access_denied"]').waitFor();
    assert.equal(await frame.locator('#body').textContent(), '');
  } catch (error) { process.stderr.write(JSON.stringify(await page.evaluate(() => ({stats:window.host?.stats(),html:document.querySelector("iframe")?.outerHTML})))+"\n"); throw error; } finally { await page.close(); }
});

test('reconnect attempts are bounded, one retry works, and content stays through exhaustion', { skip }, async () => {
  const page = await browser.newPage(); page.setDefaultTimeout(10000);
  try {
    await page.clock.install();
    await page.goto(base);
    const frame = page.frameLocator('#f');
    await frame.locator('#body', { hasText: 'Loaded body' }).waitFor();
    await frame.locator('#draft').fill('Keep this draft');
    await page.evaluate(() => { window.host.ignore(true); window.host.drop(); });
    await page.context().setOffline(true); await page.context().setOffline(false);
    await page.clock.runFor(3000); // A missed liveness reply proves the transport was lost.
    // Drain each actual request before advancing the browser's retry clock.
    for (let attempt = 1; attempt <= 4; attempt++) {
      await page.waitForFunction(n => window.host.stats().resumes === n, attempt);
      await page.clock.runFor(3000 + (attempt < 4 ? 1000 * (2 ** (attempt - 1)) : 0));
    }
    await page.clock.runFor(10000);
    assert.equal((await page.evaluate(() => window.host.stats())).resumes, 4);
    assert.equal(await frame.locator('#body').textContent(), 'Loaded body');
    assert.equal(await frame.locator('#draft').inputValue(), 'Keep this draft');
    assert.equal(await frame.locator('article button').count(), 1);
    await page.evaluate(() => window.host.ignore(false));
    await frame.getByRole('button', { name: 'Try again' }).click();
    await page.waitForFunction(() => window.host.stats().resumes === 5);
    await page.waitForFunction(() => window.host.stats().reads >= 2);
    await frame.locator('article [role="alert"]').waitFor({state:'detached'});
    assert.equal(await frame.locator('#draft').inputValue(), 'Keep this draft');
  } finally { await page.close(); }
});

test('online and refocus probe a healthy port without restarting any reads', { skip }, async () => {
  const page = await browser.newPage(); page.setDefaultTimeout(5000);
  try {
    await page.clock.install(); await page.goto(base);
    const frame = page.frameLocator('#f');
    await frame.locator('#body', { hasText: 'Loaded body' }).waitFor();
    await page.context().setOffline(true); await page.context().setOffline(false);
    await page.waitForFunction(() => window.host.stats().posted.some(v => v.type === 'records-pong'));
    await page.clock.runFor(16000);
    await frame.locator('body').evaluate(() => dispatchEvent(new PageTransitionEvent('pageshow')));
    await page.waitForFunction(() => window.host.stats().posted.filter(v => v.type === 'records-pong').length === 2);
    const stats = await page.evaluate(() => window.host.stats());
    assert.equal(stats.resumes, 0); assert.equal(stats.reads, 1); assert.equal(stats.watches, 1);
  } finally { await page.close(); }
});

test('a late automatic success clears the failure cue without a click', { skip }, async () => {
  const page = await browser.newPage(); page.setDefaultTimeout(5000);
  try {
    await page.clock.install(); await page.goto(base);
    const frame = page.frameLocator('#f');
    await frame.locator('#body', { hasText: 'Loaded body' }).waitFor();
    await page.evaluate(() => { window.host.ignore(4); window.host.drop(); });
    await page.context().setOffline(true); await page.context().setOffline(false);
    await page.clock.runFor(3000);
    for (let attempt = 1; attempt <= 2; attempt++) {
      await page.waitForFunction(n => window.host.stats().resumes === n, attempt);
      await page.clock.runFor(3000 + 1000 * (2 ** (attempt - 1)));
    }
    await page.waitForFunction(() => window.host.stats().resumes === 3);
    await page.clock.runFor(6000);
    await frame.getByRole('button', { name: 'Try again' }).waitFor();
    await page.clock.runFor(1000);
    await page.waitForFunction(() => window.host.stats().resumes === 4);
    await frame.locator('article [role="alert"]').waitFor({ state: 'detached' });
    assert.equal(await frame.locator('#body').textContent(), 'Loaded body');
  } finally { await page.close(); }
});
