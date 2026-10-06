// Authentic PRIVATE Held HTTP/opaque-frame runner. No fake host or seeded grants.
// Configuration (including session cookie) arrives on stdin, never argv/logs.
import assert from 'node:assert/strict';
import { createInterface } from 'node:readline';
import { loadChromium } from '../src/fake-host/playwright.mjs';
import { createBodyWire } from '../src/body-wire.mjs';
const lines=createInterface({input:process.stdin})[Symbol.asyncIterator]();
const config=JSON.parse((await lines.next()).value);
const bodyWire=createBodyWire();
function assertNoResolvedError(response,stage,elapsed) {
 const checked=bodyWire.validateBody(response);
 const timing=`${stage} elapsed_ms=${Math.round(elapsed)}`;
 assert.ok(checked.kind==='body',timing);
 const error=checked.response.error;
 // Only the pinned wire's closed error pair may enter diagnostics, never a reply.
 assert.ok(!error,error?`${timing} code=${error.code} reason=${error.reason}`:timing);
}
const chromium=await loadChromium();assert.ok(chromium,'required Chromium unavailable');
const browser=await chromium.launch();
try {
 const context=await browser.newContext();
 const split=config.cookie.indexOf('=');assert.ok(split>0);
 await context.addCookies([{name:config.cookie.slice(0,split),value:config.cookie.slice(split+1),domain:new URL(config.parent).hostname,path:'/',secure:true,httpOnly:true,sameSite:'Lax'}]);
 const cookies=await context.cookies();const session=cookies.find(c=>c.name===config.cookie.slice(0,split));
 assert.ok(session);assert.equal(session.domain,new URL(config.parent).hostname);assert.equal(session.path,'/');assert.equal(session.secure,true);assert.equal(session.httpOnly,true);
 const page=await context.newPage();let pageErrors=0;
 page.on('pageerror',()=>{pageErrors++;});
 await page.goto(config.parent,{waitUntil:'domcontentloaded'});
 const frame=()=>page.frames().find(f=>f.url().startsWith(config.artifact));
 await page.waitForFunction(()=>document.getElementById('app').src!=='');
 for(let n=0;n<200&&!frame();n++)await page.waitForTimeout(25);
 const app=frame();assert.ok(app,'real artifact frame absent');
 try {await app.waitForFunction(()=>!!window.p1);} catch {
  const stage=await app.evaluate(async()=>({bootstrap:typeof nativeArtifact==='object',author:typeof p1Ready!=='undefined',api:typeof p1!=='undefined',ready:typeof nativeArtifact==='object'?await Promise.race([nativeArtifact.ready.then(()=>true,()=>false),new Promise(r=>setTimeout(()=>r(null),250))]):null}));
  console.error('P1 startup finite flags '+JSON.stringify({...stage,pageErrors}));throw new Error('private authored startup incomplete');
 }
 assert.equal(await app.evaluate(()=>globalThis.origin),'null');
 assert.equal(await app.evaluate(()=>p1.input()),null);
 assert.equal(await app.evaluate(()=>p1.offering().max_inflight),1);
 const assembled=await app.evaluate(()=>p1.all());
 assert.equal(assembled.body,'\uFEFFé😀正文 \0\n'.repeat(24000));
 assert.ok(assembled.body.length>120000);assert.ok(assembled.total_bytes>262144);
 assert.ok(/^[0-9a-f]{64}$/.test(assembled.body_digest));
 // Guard comes from the actual engine page, not a client recomputation.
 const escaped=await app.evaluate(id=>p1.page({record_id:id,page_bytes:32768}),config.escaped);
 assert.equal(escaped.text,'\0'.repeat(32768));assert.ok(new TextEncoder().encode(JSON.stringify(escaped)).length>65536);
 const emptyStarted=performance.now();
 const empty=await app.evaluate(id=>p1.page({record_id:id,page_bytes:32768}),config.empty);
 const emptyElapsed=performance.now()-emptyStarted;
 const absentStarted=performance.now();
 const absent=await app.evaluate(id=>p1.page({record_id:id,page_bytes:32768}),config.absent);
 const absentElapsed=performance.now()-absentStarted;
 assertNoResolvedError(empty,'empty',emptyElapsed);assertNoResolvedError(absent,'absent',absentElapsed);
 assert.equal(empty.body_present,true);assert.equal(absent.body_present,false);assert.equal(empty.text,'');assert.equal(absent.text,'');
 await page.evaluate(()=>p1OpenSibling());
 for(let n=0;n<200&&page.frames().filter(f=>f.url().startsWith(config.artifact)).length<2;n++)await page.waitForTimeout(25);
 const sibling=page.frames().find(f=>f!==app&&f.url().startsWith(config.artifact));assert.ok(sibling);
 await sibling.waitForFunction(()=>!!window.p1);
 assert.equal((await sibling.evaluate(id=>p1.page({record_id:id,page_bytes:32768}),config.target)).text.length>0,true);
 await page.evaluate(()=>p1Close(1));
 const siblingClosed=await sibling.evaluate(async id=>{try{await p1.page({record_id:id,page_bytes:32768});return false;}catch{return true;}},config.target);assert.equal(siblingClosed,true);
 assert.equal((await app.evaluate(id=>p1.page({record_id:id,page_bytes:4}),config.target)).text,'\uFEFF');
 const first=await app.evaluate(id=>p1.page({record_id:id,page_bytes:32768}),config.target);
 assert.equal(assembled.body_digest,first.body_digest);assert.equal(assembled.revision,first.revision);
 for(const raw of ['{}','[]','\uFEFF{}','{"record_id":"a","record_id":"b"}','{"record_id":"\\ud800"}']){
  const refused=await app.evaluate(s=>p1.raw(s),raw);assert.deepEqual(refused.error,{code:'invalid_params',reason:'request'});
 }
 const concurrent=await app.evaluate(async id=>{const first=p1.page({record_id:id,page_bytes:4});const second=p1.page({record_id:id,page_bytes:4});const reason=await second.then(()=>null,e=>e.reason);await first;return reason;},config.target);
 assert.equal(concurrent,'busy');
 assert.equal(await app.evaluate(()=>p1.cancel()),true);
 await app.evaluate(()=>{window.saved=p1.page;});
 // The token is never transferred to authored frame input/namespace/DOM/URLs.
 assert.equal(await app.evaluate(()=>/abm1\.[0-9a-f]+/.test(document.documentElement.outerHTML+JSON.stringify(nativeArtifact.input)+JSON.stringify(nativeArtifact.body)+location.href)),false);
 assert.equal(await page.evaluate(()=>/abm1\.[0-9a-f]+/.test(document.documentElement.outerHTML)),false);
 await app.evaluate(id=>{window.oldPage=p1.page({record_id:id,page_bytes:4});},config.target);
 await app.evaluate(async()=>{window.oldPage=await oldPage;});
 process.stdout.write('target-ready\n');assert.equal((await lines.next()).value,'target-changed');
 const drift=await app.evaluate(id=>p1.page({record_id:id,page_bytes:4,revision:oldPage.revision,cursor:oldPage.next_cursor}),config.target);
 assert.equal(drift.error.code,'revision_changed');
 const current=await app.evaluate(id=>p1.page({record_id:id,page_bytes:32768}),config.target);assert.equal(current.text,'new current target');
 process.stdout.write('source-ready\n');assert.equal((await lines.next()).value,'source-changed');
 const lost=await app.evaluate(id=>p1.page({record_id:id,page_bytes:32768}),config.target);
 assert.equal(lost.error.code,'source_integrity');
 await page.evaluate(()=>p1Close());
 const closed=await app.evaluate(async id=>{try{await p1.page({record_id:id,page_bytes:32768});return false;}catch{return true;}},config.target);
 assert.equal(closed,true);
 assert.equal(pageErrors,0);
 process.stdout.write('private body browser: genuine assembly, raw, abort, secrecy and holder teardown passed\n');
} finally {await browser.close();lines.return?.();}
