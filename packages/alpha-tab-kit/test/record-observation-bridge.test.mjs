import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { loadChromium } from '../src/fake-host/playwright.mjs';
import { injectBridge } from '../src/fake-host/server.mjs';
import { LIMITS } from '../src/limits.mjs';

const version = LIMITS.bridge.version;
const feature = 'app.records.observe.v1';
const chromium = await loadChromium();
let server, browser, base;
const frameHtml = `<!doctype html><html><head><title>Record transport</title></head><body><script>
window.probe = { ready: false, values: [] };
// Authored code runs after the bridge captures these primitives.
MessagePort.prototype.postMessage = () => { throw Error('patched post'); };
MessagePort.prototype.start = () => { throw Error('patched start'); };
MessagePort.prototype.close = () => { throw Error('patched close'); };
Object.defineProperty(MessageEvent.prototype, 'data', { get() { throw Error('patched data'); } });
window.nativeArtifact.ready.then(() => {
  const lane = window.native?.recordObservation;
  window.probe.ready = true;
  window.probe.offered = !!lane;
  if (!lane) return;
  window.probe.generation = lane.generation;
  window.probe.protocolVersion = lane.protocolVersion;
  window.probe.frozen = Object.isFrozen(lane) && Object.isFrozen(lane.port);
  const listener = e => { window.probe.values.push(e.data); document.body.dataset.received = 'true'; };
  const attach=()=>{lane.port.addEventListener('message',listener);lane.port.start()};
  if(window.nativeArtifact.input?.delay_records)setTimeout(attach,100);else attach();
  window.probe.send = value => lane.port.postMessage(value);
  window.probe.remove = () => lane.port.removeEventListener('message', listener);
});
</script></body></html>`;
const parentHtml = `<!doctype html><html><body><iframe id="f" sandbox="allow-scripts" src="/frame"></iframe><script>
const messages = [], records = []; let recordPort;
window.host = {
  booted: false,
  init(mode) {
    const control = new MessageChannel(), lane = new MessageChannel();
    control.port1.onmessage = e => messages.push(e.data); control.port1.start();
    recordPort = lane.port1; recordPort.onmessage = e => records.push(e.data); recordPort.start();
    const data = { type: 'native-html-init', version: ${JSON.stringify(version)}, input: {delay_records:mode==='early'} };
    if (mode !== 'legacy' && mode !== 'extra') data.host_features = mode === 'v2' ? ['app.records.observe.v2'] : mode === 'both' ? [${JSON.stringify(feature)}, 'app.records.observe.v2'] : [${JSON.stringify(feature)}];
    if (mode !== 'legacy' && mode !== 'missing') data.record_observation = { generation: mode === 'bad' ? '' : 'launch-1' };
    const ports = mode === 'legacy' || mode === 'missing' ? [control.port2] : [control.port2, lane.port2];
    document.getElementById('f').contentWindow.postMessage(data, '*', ports);
    if(mode==='early')recordPort.postMessage({type:'records-end',generation:'launch-1',code:'scope_changed'});
  },
  send: value => recordPort.postMessage(value),
  messages: () => messages.slice(), records: () => records.slice(),
};
addEventListener('message', event => {
  if (event.source !== document.getElementById('f').contentWindow || event.data?.type !== 'native-html-bootstrap') return;
  window.host.booted = true; window.host.init(new URLSearchParams(location.search).get('mode') || 'valid');
});
</script></body></html>`;
before(async () => {
  server = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(req.url === '/frame' ? injectBridge(frameHtml, `http://${req.headers.host}`) : parentHtml);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  if (chromium) browser = await chromium.launch();
});
after(async () => { await browser?.close(); await new Promise(resolve => server.close(resolve)); });
const skip = !chromium && 'Playwright is not installed';
const ready = page => page.frameLocator('#f').locator('body').evaluate(() => window.probe.ready);
async function opened(mode) {
  const page = await browser.newPage(); await page.goto(`${base}/?mode=${mode}`);
  await page.waitForFunction(() => window.host.booted);
  return page;
}
async function waitReady(page) {
  await page.waitForFunction(() => window.host.messages().some(x => x.type === 'ready'));
  assert.equal(await ready(page), true);
}

test('authenticated second INIT port is frozen and uses captured transport without receipt ACKs', { skip }, async () => {
  const page = await opened('valid');
  try {
    await waitReady(page);
    const frame = page.frameLocator('#f').locator('body');
    assert.deepEqual(await frame.evaluate(() => ({ offered: window.probe.offered, frozen: window.probe.frozen, generation: window.probe.generation })), { offered: true, frozen: true, generation: 'launch-1' });
    await page.evaluate(() => window.host.send({ type: 'records-delivery', generation: 'launch-1', delivery_id: 1 }));
    await page.frameLocator('#f').locator('body[data-received="true"]').waitFor({ state: 'attached', timeout: 5000 });
    assert.deepEqual(await frame.evaluate(() => window.probe.values), [{ type: 'records-delivery', generation: 'launch-1', delivery_id: 1 }]);
    assert.deepEqual(await page.evaluate(() => window.host.records()), []);
    await frame.evaluate(() => window.probe.send({ type: 'records-ack', generation: 'launch-1', delivery_id: 1, retain: true }));
    await page.waitForFunction(() => window.host.records().length === 1);
    assert.deepEqual(await page.evaluate(() => window.host.records()[0]), { type: 'records-ack', generation: 'launch-1', delivery_id: 1, retain: true });
    await frame.evaluate(() => { dispatchEvent(new Event('pagehide')); window.probe.send({ type: 'after-close' }); });
    assert.equal(await page.evaluate(() => window.host.records().length), 1);
  } finally { await page.close(); }
});

test('one-port legacy INIT keeps the record transport absent', { skip }, async () => {
  const page = await opened('legacy');
  try { await waitReady(page); assert.equal(await page.frameLocator('#f').locator('body').evaluate(() => window.probe.offered), false); }
  finally { await page.close(); }
});

test('an early legacy records-end stays buffered until the client listens and starts', { skip }, async () => {
  const page = await opened('early');
  try {
    await waitReady(page);
    const frame = page.frameLocator('#f').locator('body');
    await page.frameLocator('#f').locator('body[data-received="true"]').waitFor({ state: 'attached' });
    assert.deepEqual(await frame.evaluate(() => window.probe.values), [{ type: 'records-end', generation: 'launch-1', code: 'scope_changed' }]);
  } finally { await page.close(); }
});

test('extra ports, mixed protocol versions, missing ports and malformed generations do not consume INIT', { skip }, async () => {
  for (const mode of ['extra', 'missing', 'bad', 'both']) {
    const page = await opened(mode);
    try {
      // A correct legacy INIT must still establish the original bridge. The
      // malformed offer cannot install a lane or consume that one-time INIT.
      await page.evaluate(() => window.host.init('legacy'));
      await waitReady(page);
      assert.equal(await page.frameLocator('#f').locator('body').evaluate(() => window.probe.offered), false, mode);
    } finally { await page.close(); }
  }
});

test('v2 is explicitly negotiated without changing the one-key INIT descriptor', { skip }, async () => {
  const page = await opened('v2');
  try {
    await waitReady(page);
    assert.equal(await page.frameLocator('#f').locator('body').evaluate(() => window.probe.protocolVersion), 2);
    assert.equal(await page.frameLocator('#f').locator('body').evaluate(() => window.probe.frozen), true);
  } finally { await page.close(); }
});
