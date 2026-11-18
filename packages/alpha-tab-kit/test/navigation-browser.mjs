/** Trusted-click acceptance of current production-mirrored bootstrap bytes.
 * node packages/alpha-tab-kit/test/navigation-browser.mjs
 * No backend/engine image is substituted for the current vendored bridge.
 */
import assert from 'node:assert/strict';
import { loadChromium } from '../src/fake-host/playwright.mjs';
import { injectBridge } from '../src/fake-host/server.mjs';
const chromium = await loadChromium(); assert.ok(chromium, 'Cached Playwright Chromium is required');
const browser = await chromium.launch({headless:true});
try {
  const page = await browser.newPage();
  const source = '<!doctype html><html><head><meta charset="utf-8"><title>Navigation bridge</title></head><body>'
    + '<button id="plain" data-native-record-id="record-id">Plain record</button>'
    + '<button id="app" data-native-record-id="record-id" data-native-app="agent.tracker">Tracker</button>'
    + '<button id="native" data-native-record-id="record-id" data-native-app="native">Native</button></body></html>';
  await page.route('https://artifact.test/**', route => route.fulfill({contentType:'text/html',body:injectBridge(source,'https://parent.test')}));
  await page.route('https://parent.test/**', route => route.fulfill({contentType:'text/html',body:`<!doctype html><iframe sandbox="allow-scripts" src="https://artifact.test/frame"></iframe><script>
    window.commands=[];addEventListener('message',event=>{if(event.source!==document.querySelector('iframe').contentWindow||event.data?.type!=='native-html-bootstrap')return;
      const channel=new MessageChannel();channel.port1.onmessage=event=>commands.push(event.data);channel.port1.start();
      event.source.postMessage({type:'native-html-init',version:'native.html.bridge.v1',input:{},input_digest:'initial',revision:{content_event_seq:1}},'*',[channel.port2]);});
    </script>`}));
  await page.goto('https://parent.test/');
  await page.waitForFunction(()=>commands.some(packet=>packet.type==='ready'));
  const frame = page.frames().find(frame=>frame.url().startsWith('https://artifact.test/')); assert.ok(frame);
  await frame.locator('#app').evaluate(node=>node.click());
  assert.equal(await page.evaluate(()=>commands.filter(packet=>packet.type==='navigation').length),0,'Authored synthetic clicks cannot navigate');
  await frame.locator('#plain').click();
  await frame.locator('#app').click({modifiers:['Control']});
  await frame.locator('#native').press('Enter');
  await page.waitForFunction(()=>commands.filter(packet=>packet.type==='navigation').length===3);
  const messages=await page.evaluate(()=>commands.filter(packet=>packet.type==='navigation'));
  assert.equal(messages[0].recordId,'record-id'); assert.equal(Object.hasOwn(messages[0],'app'),false);
  assert.equal(messages[1].recordId,'record-id'); assert.equal(messages[1].app,'agent.tracker'); assert.equal(messages[1].newTab,true);
  assert.equal(messages[2].recordId,'record-id'); assert.equal(messages[2].app,'native');
  console.log('Trusted plain click, explicit app, explicit Native keyboard click and synthetic-click refusal passed.');
} finally { await browser.close(); }
