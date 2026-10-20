// Explicit browser acceptance, using cached Chromium and Rust-emitted custody HTML.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadChromium,openFakeHost} from '../src/fake-host/playwright.mjs';
import {injectBridge} from '../src/fake-host/server.mjs';
import {DEFAULT_KIT_DELIVERY} from '../src/fake-host/kit-assets.mjs';
import {fixtureDelivery} from './helpers/fixture-kit-delivery.mjs';
const source=readFileSync(new URL('./fixtures/core-source.html',import.meta.url),'utf8');
const real=readFileSync(process.env.NATIVE_KIT_DELIVERY_REAL_HTML,'utf8');
assert.equal(real,injectBridge(source,'https://parent.test'),'Rust custody and fake composition must be byte-identical');
const declaration=JSON.parse(readFileSync(new URL('../../../web/apps/src/apps/template/declaration.json',import.meta.url),'utf8'));
const descriptor={package:'core-source-fixture',version:'0.0.0',declaration,kit:{major:1}};
const release=DEFAULT_KIT_DELIVERY.resolve(1).release;
const chromium=await loadChromium();assert.ok(chromium,'cached Playwright required');
const browser=await chromium.launch({headless:true, ...(process.env.ALPHA_TAB_KIT_CHROMIUM ? {executablePath:process.env.ALPHA_TAB_KIT_CHROMIUM} : {})});
const rows=[{id:'record-1',name:'First'}];
const input=rows=>({sql:{'records.recent':{label:'Recent',rows,columns:['id','name'],row_count:rows.length,row_count_complete:true,truncated:false}}});
const reload=async page=>{
  const [frame]=await Promise.all([page.waitForEvent('framenavigated',{predicate:f=>f.url().includes('/frame?session=')}),page.evaluate(()=>window.__alphaTabHost.reload())]);
  await frame.waitForFunction(()=>window.native?.kit);return frame;
};
const check=async frame=>{
  await frame.waitForFunction(()=>window.states?.some(s=>s.status==='ready'));
  await frame.waitForFunction(()=>document.querySelector('#preact-feed')?.textContent==='ready');
  assert.equal(await frame.locator('#preact-app strong').textContent(),'Inline module works');
  assert.equal(await frame.locator('#preact-app .kit-avatar').textContent(),'AL');
  assert.equal(await frame.locator('#preact-app img').count(),0);
  assert.match(await frame.locator('#preact-app').textContent(),/& safe <img onerror=x>/);
  assert.equal(await frame.evaluate(()=>Object.isFrozen(native.kit.preact)),true);
  assert.deepEqual(await frame.evaluate(async()=>({first:window.firstKit,gated:window.preNegotiation,frozen:Object.isFrozen(native)&&Object.isFrozen(native.kit)&&Object.isFrozen(native.kit.release),descriptor:Object.getOwnPropertyDescriptor(window,'native').writable===false&&Object.getOwnPropertyDescriptor(window,'native').configurable===false,kitDescriptor:Object.getOwnPropertyDescriptor(native,'kit').writable===false,private:typeof window.kitFactory==='undefined'&&typeof window.disposeKit==='undefined',missing:await window.missing,keys:Object.keys(native.kit.release).sort()})),{first:true,gated:true,frozen:true,descriptor:true,kitDescriptor:true,private:true,missing:await frame.evaluate(()=>window.missing),keys:Object.keys(release).sort()});
  assert.equal(await frame.evaluate(()=>window.missing),'undeclared');
  assert.deepEqual(await frame.evaluate(()=>native.kit.release),release);
  assert.equal(await frame.evaluate(()=>{try{Object.defineProperty(window,'native',{value:{}});return false}catch{return true}}),true);
};
try {
  // Real Rust legacy custody output, sandboxed cross-origin document and actual MessagePort init.
  const page=await browser.newPage();
  await page.route('https://artifact.test/**',route=>route.fulfill({contentType:'text/html',body:real}));
  await page.route('https://parent.test/**',route=>route.fulfill({contentType:'text/html',body:`<!doctype html><iframe sandbox="allow-scripts" src="https://artifact.test/frame"></iframe><script>
  let port;window.commands=[];addEventListener('message',event=>{if(event.data.type!=='native-html-bootstrap')return;const channel=new MessageChannel();port=channel.port1;port.onmessage=e=>commands.push(e.data);port.start();event.source.postMessage({type:'native-html-init',version:'native.html.bridge.v1',input:${JSON.stringify(input(rows))},input_digest:'initial',revision:{content_event_seq:1},host_features:['app.call.v2','app.session.v2','app.subscribe.v2','app.agents.v2','app.agent-sessions.v2','app.presentation.v1']},'*',[channel.port2]);});
  window.push=value=>port.postMessage({version:'native.html.bridge.v1',type:'input',input:value,input_digest:JSON.stringify(value),revision:{content_event_seq:++window.seq}});window.seq=1;
  </script>`}));
  await page.goto('https://parent.test/');const frame=page.frames().find(f=>f.url().startsWith('https://artifact.test/'));assert.ok(frame);
  await check(frame);
  assert.deepEqual(await frame.evaluate(()=>['call','session','query','subscribe','agents','agentSessions','presentation'].map(k=>typeof native[k])),['function','object','function','function','object','object','object']);
  assert.equal(await frame.evaluate(()=>['call','session','query','subscribe','agents','agentSessions','presentation'].every(key=>native[key]===nativeArtifact[key])),true);
  await page.evaluate(value=>window.push(value),input([{id:'record-2',name:'Second'}]));
  await frame.waitForFunction(()=>states.at(-1)?.result?.rows[0]?.id==='record-2');
  await page.evaluate(()=>window.push({sql:{'records.recent':{bad:true}}}));
  await frame.waitForFunction(()=>states.at(-1)?.status==='error');
  assert.equal(await frame.evaluate(()=>states.at(-1).error.code),'malformed');
  assert.equal(await frame.evaluate(()=>states.at(-1).last.rows[0].id),'record-2');
  assert.match(await frame.locator('#state').textContent(),/Last good:/);
  assert.equal(await frame.locator('#records a').getAttribute('data-native-record-id'),'record-2');
  await frame.evaluate(()=>stopRecent());const count=await frame.evaluate(()=>states.length);
  await page.evaluate(value=>window.push(value),input(rows));await page.waitForTimeout(50);assert.equal(await frame.evaluate(()=>states.length),count);
  // Disposal is private, driven by the document lifecycle, and suppresses later input.
  await frame.evaluate(()=>{window.afterClose=[];native.kit.subscribe('records.recent',s=>afterClose.push(s));dispatchEvent(new Event('pagehide'));});
  const closedCount=await frame.evaluate(()=>afterClose.length);
  await page.evaluate(value=>window.push(value),input([]));await page.waitForTimeout(50);
  assert.equal(await frame.evaluate(()=>afterClose.length),closedCount);
  assert.equal(await frame.evaluate(()=>native.kit.read('records.recent').catch(e=>e.code)),'closed');
  assert.equal(await page.evaluate(()=>commands.filter(c=>['read','call','query','subscribe'].includes(c.type)).length),0);
  await page.close();

  for(const mode of ['live','sample']){
    const page=await browser.newPage();
    const tab=await openFakeHost(page,{descriptor,html:source,mode,calls:true,sessions:true,queries:true,agents:true,presentation:true,fixtures:{sql:{'records.recent':(_,ctx)=>[{id:'record-'+ctx.generation,name:'Record'}]}}});
    const frame=page.frames().find(f=>f.url().includes('/frame'));
    if(mode==='live'){
      await check(frame);
      assert.equal(await frame.evaluate(()=>native.agentSessions),undefined);
      assert.deepEqual(await frame.evaluate(()=>['call','session','query','subscribe','agents','presentation'].map(k=>typeof native[k])),['undefined','undefined','undefined','undefined','undefined','undefined']);
      await tab.pushInput();await frame.waitForFunction(()=>states.at(-1)?.result?.rows[0]?.id==='record-1');
    }else{
      await frame.waitForFunction(()=>window.states?.some(s=>s.status==='error'));
      assert.equal(await frame.evaluate(()=>states.at(-1).error.code),'undeclared');
      assert.deepEqual(await frame.evaluate(()=>['query','subscribe','agents','presentation'].map(k=>typeof native[k])),['undefined','undefined','undefined','undefined']);
    }
    await reload(page);
    await page.waitForFunction(()=>document.querySelector('iframe').src.includes('session=2'));
    await page.waitForTimeout(100);
    if(mode==='live') assert.equal(await page.frames().find(f=>f.url().includes('/frame')).evaluate(()=>states.at(-1)?.result?.rows[0]?.id),'record-1');
    assert.ok((await tab.events()).some(e=>e.type==='kit-session'&&e.kit_release.version==='1.1.0'));
    await tab.expectHealthy();await tab.close();await page.close();
  }
  // V2 methods require the v2 install declaration, independently of core major 1.
  {
    const page=await browser.newPage();
    const v2={...descriptor,declaration:{contract:'native.app.v2',needs:[],effects:[]}};
    const tab=await openFakeHost(page,{descriptor:v2,html:source,calls:true,sessions:true,queries:true,agents:true,presentation:true});
    const frame=page.frames().find(f=>f.url().includes('/frame'));
    await frame.evaluate(()=>native.kit.ready);
    await frame.waitForFunction(()=>document.querySelector('#preact-app strong')?.textContent==='Inline module works');
    assert.deepEqual(await frame.evaluate(()=>['call','session','query','subscribe','agents','presentation'].map(k=>typeof native[k])),['function','object','function','function','object','object']);
    assert.equal(await frame.evaluate(()=>native.presentation.setFloatingChat({suppress:true})),true);
    assert.equal(await frame.evaluate(()=>native.kit.release.version),'1.1.0');
    await tab.expectHealthy();await tab.close();await page.close();
  }
  // Explicit test-only A/B host ownership; prepared and running A never reselects.
  {
  const a=await fixtureDelivery('1.0.0'),b=await fixtureDelivery('1.0.1');
  const page=await browser.newPage();const tab=await openFakeHost(page,{descriptor,html:source,kitDelivery:a,fixtures:{sql:{'records.recent':rows}}});
  const oldUrl=page.frames().find(f=>f.url().includes('/frame')).url();tab.host.selectKitDeliveryForNextSession(b);
  assert.equal(await page.frames().find(f=>f.url().includes('/frame')).evaluate(()=>native.kit.release.version),'1.0.0');
  await reload(page);await page.waitForTimeout(150);
  assert.equal(await page.frames().find(f=>f.url().includes('/frame')).evaluate(()=>native.kit.release.version),'1.0.1');
  assert.ok((await(await fetch(oldUrl)).text()).includes('"version":"1.0.0"'));
  tab.host.selectKitDeliveryForNextSession(a);await reload(page);await page.waitForTimeout(150);
  assert.equal(await page.frames().find(f=>f.url().includes('/frame')).evaluate(()=>native.kit.release.version),'1.0.0');
  await tab.expectHealthy();await tab.close();await page.close();
  }
  console.log('PASS real custody/fake inline-module Preact/htm, safe Markdown and canonical kit before author script; frozen descriptors, negotiated parity, declared snapshots, ready/push/error/last-good/unsubscribe/disposal; A/B pinning and rollback');
} finally {await browser.close();}
