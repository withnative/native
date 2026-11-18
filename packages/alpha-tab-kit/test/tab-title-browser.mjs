/** Explicit Chromium title bridge proof; no live Native account. */
import assert from 'node:assert/strict';
import { loadChromium, openFakeHost } from '../src/fake-host/playwright.mjs';
const chromium=await loadChromium();
if (!chromium) throw Error('Set ALPHA_TAB_KIT_PLAYWRIGHT to a directory with Playwright installed');const browser=await chromium.launch({headless:true});
try {const page=await browser.newPage();const descriptor={package:'title-fixture',version:'0.0.0',declaration:{contract:'native.app.v2',needs:[],effects:[]}};const tab=await openFakeHost(page,{descriptor,html:'<!doctype html><html><head><meta charset="utf-8"></head><body><p>Title test</p></body></html>',tabTitles:true});const frame=page.frames().find(f=>f.url().includes('/frame'));
assert.equal(await frame.evaluate(()=>typeof native.presentation.setFloatingChat),'undefined');
assert.equal(await frame.evaluate(()=>native.presentation.setTabTitle({title:'  Browser   title  '})),true);
assert.equal((await tab.events()).filter(e=>e.type==='tab-title').at(-1).title,'Browser title');
assert.equal(await frame.evaluate(()=>native.presentation.setTabTitle({title:null})),true);
assert.equal((await tab.events()).filter(e=>e.type==='tab-title').at(-1).title,null);
assert.equal(await frame.evaluate(()=>{try{native.presentation.setTabTitle({title:'\u202eevil'});return false}catch{return true}}),true);
await tab.expectHealthy();await tab.close();console.log('PASS real Chromium negotiated title setter, host acknowledgement, whitespace normalization, clear, bidi refusal; floating-chat absent without negotiation');}finally{await browser.close()}
