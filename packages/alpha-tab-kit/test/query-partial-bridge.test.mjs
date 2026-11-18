// Frame tests for the read side of the bridge (design note b08bdf78): `behind` on pushed results, and the one-off
// query that may ask for last-known first (`last_known` / `query-partial`). Loads the real vendored bridge in node:vm.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const VERSION = "native.html.bridge.v1";
const HOST = "https://workbench.example";
const bootstrap = readFileSync(new URL("../src/fake-host/bridge-bootstrap.js", import.meta.url), "utf8");

const STUBS = `
class Event {
  constructor(type, init = {}) {
    this._type = type;
    this._trusted = init.trusted === true;
    this._target = init.target ?? null;
    this._defaultPrevented = false;
  }
  get type() { return this._type; }
  get isTrusted() { return this._trusted; }
  get target() { return this._target; }
  get defaultPrevented() { return this._defaultPrevented; }
  preventDefault() { this._defaultPrevented = true; }
  stopImmediatePropagation() {}
}
class MessageEvent extends Event {
  constructor(type, init = {}) {
    super(type, init);
    this._data = init.data ?? null;
    this._source = init.source ?? null;
    this._origin = init.origin ?? "";
    this._ports = init.ports ?? [];
  }
  get data() { return this._data; }
  get source() { return this._source; }
  get origin() { return this._origin; }
  get ports() { return this._ports; }
}
class KeyboardEvent extends Event {
  constructor(type, init = {}) {
    super(type, init);
    this._key = init.key ?? "";
    this._repeat = init.repeat === true;
    this._shiftKey = init.shiftKey === true;
  }
  get key() { return this._key; }
  get repeat() { return this._repeat; }
  get shiftKey() { return this._shiftKey; }
}
class MouseEvent extends Event {
  constructor(type, init = {}) {
    super(type, init);
    this._ctrlKey = init.ctrlKey === true;
    this._metaKey = init.metaKey === true;
    this._button = init.button ?? 0;
  }
  get ctrlKey() { return this._ctrlKey; }
  get metaKey() { return this._metaKey; }
  get button() { return this._button; }
}
class PageTransitionEvent extends Event {
  constructor(type, init = {}) {
    super(type, init);
    this._persisted = init.persisted === true;
  }
  get persisted() { return this._persisted; }
}
class Node {
  get nodeType() { return this._nodeType ?? 1; }
}
class Element extends Node {
  closest() { return null; }
  getAttribute() { return null; }
}
class EventTarget {
  constructor() { this._listeners = {}; }
  addEventListener(type, fn) { (this._listeners[type] ??= []).push(fn); }
  removeEventListener(type, fn) {
    const list = this._listeners[type];
    if (list) { const i = list.indexOf(fn); if (i >= 0) list.splice(i, 1); }
  }
  _emit(type, event) { for (const fn of [...(this._listeners[type] || [])]) fn(event); }
}
class MessagePort extends EventTarget {
  constructor() { super(); this._posted = []; }
  postMessage(value) { this._posted.push(value); }
  start() {}
}
class Window extends EventTarget {
  dispatchEvent() { return true; }
}
class CustomEvent extends Event {
  constructor(type, init = {}) { super(type, init); this._detail = init.detail; }
  get detail() { return this._detail; }
}
`;

function loadFrame(kit = false, nativeConflict = false) {
  const sandbox = { __NATIVE_WORKBENCH_ORIGIN__: HOST, __NATIVE_KIT_FACTORY__: null, __NATIVE_KIT_RELEASE__: null, setTimeout, clearTimeout, AbortController, TextEncoder, TextDecoder, performance, requestAnimationFrame: undefined, console };
  sandbox.window = null; sandbox.parent = { postMessage() {} }; sandbox.document = { querySelector: () => null };
  vm.createContext(sandbox); vm.runInContext(`${STUBS}\nwindow=new Window();`, sandbox);
  const grab = (n) => vm.runInContext(n, sandbox);
  const refs = { MessageEvent: grab("MessageEvent"), MessagePort: grab("MessagePort") };
  if (kit) {
    sandbox.__NATIVE_KIT_FACTORY__ = vm.runInContext(readFileSync(new URL('../supplied-kit/1.0.0/core.js', import.meta.url), 'utf8'), sandbox);
    const m = JSON.parse(readFileSync(new URL('../supplied-kit/1.0.0/manifest.json', import.meta.url), 'utf8'));
    sandbox.__NATIVE_KIT_RELEASE__ = {version:m.version,major:m.major,layer:m.layer,factory:m.factory,bridge:m.bridge,js_sha256:m.js.sha256,types_sha256:m.types.sha256};
  }
  if (nativeConflict) {
    const canonicalFactory=sandbox.__NATIVE_KIT_FACTORY__;
    sandbox.__NATIVE_KIT_FACTORY__=(bridge,release)=>{sandbox.testOwned=canonicalFactory(bridge,release);return sandbox.testOwned;};
    Object.defineProperty(sandbox.window,'native',{value:{},configurable:false});
  }
  let error;
  try { vm.runInContext(bootstrap, sandbox); } catch (failure) { if (!nativeConflict) throw failure; error=failure; }
  return { sandbox, refs, error };
}
function initFrame(frame, hostFeatures = [], fail = false) {
  const port = new frame.refs.MessagePort();
  const init = vm.runInContext(`({type:"native-html-init",version:${JSON.stringify(VERSION)},needs:[],host_features:${JSON.stringify(hostFeatures)},input:{}})`, frame.sandbox);
  if (fail) Object.defineProperty(init,"input",{get(){throw new Error("test init failure")}});
  frame.sandbox.window._emit("message", new frame.refs.MessageEvent("message", { data: init, ports: [port], source: frame.sandbox.parent, origin: HOST }));
  return port;
}
function posts(port) { return port._posted; }
function emit(frame, port, data) {
  frame.sandbox.window._emit("unused", null);
  port._emit("message", new frame.refs.MessageEvent("message", { data }));
}

const tick = () => new Promise(resolve => setImmediate(resolve));
const table = (rows) => ({ columns: ['id'], rows: rows.map(id => [id]), truncated: false });

test('a pushed subscription result carries the host\'s behind flag beside cached, and an unflagged one says false', async () => {
  const f = loadFrame(), port = initFrame(f, ['app.subscribe.v2']);
  vm.runInContext(`var seen=[];window.native.subscribe({sql:'select 1'},function(d){seen.push(d)});`, f.sandbox);
  const sub = posts(port).find(m => m.type === 'subscribe');
  emit(f, port, { version: VERSION, type: 'subscription-result', subscription_id: sub.subscription_id, delivery: 1, result: table(['a']), cached: true, behind: true });
  emit(f, port, { version: VERSION, type: 'subscription-result', subscription_id: sub.subscription_id, delivery: 2, result: table(['a']) });
  assert.equal(JSON.stringify(f.sandbox.seen.map(d => [d.cached, d.behind])), '[[true,true],[false,false]]');
});

test('a query that asks for last-known sends last_known, hears one frozen partial, and still resolves only with the final answer', async () => {
  const f = loadFrame(), port = initFrame(f, ['app.subscribe.v2']);
  vm.runInContext(`var held=[], final=null;
    window.native.query({sql:'select 1'}, {lastKnown:true, onPartial:function(p){held.push(p)}}).then(function(r){final=r});`, f.sandbox);
  const sent = posts(port).find(m => m.type === 'query');
  assert.equal(sent.last_known, true);
  emit(f, port, { version: VERSION, type: 'query-partial', request_id: sent.request_id, result: table(['saved']), cached: true, behind: true });
  emit(f, port, { version: VERSION, type: 'query-partial', request_id: sent.request_id, result: table(['again']), cached: true });
  await tick();
  assert.equal(f.sandbox.held.length, 1, 'at most one partial');
  assert.equal(Object.isFrozen(f.sandbox.held[0]), true);
  assert.deepEqual([f.sandbox.held[0].cached, f.sandbox.held[0].behind, f.sandbox.held[0].rows[0][0]], [true, true, 'saved']);
  assert.equal(f.sandbox.final, null, 'a partial never settles the promise');
  emit(f, port, { version: VERSION, type: 'query-result', request_id: sent.request_id, status: 'ok', result: table(['current']) });
  await tick();
  assert.equal(f.sandbox.final.rows[0][0], 'current');
  emit(f, port, { version: VERSION, type: 'query-partial', request_id: sent.request_id, result: table(['late']), cached: true });
  assert.equal(f.sandbox.held.length, 1, 'nothing follows the final');
});

test('a plain query sends no last_known, ignores a partial, and a throwing callback or malformed partial cannot break the answer', async () => {
  const f = loadFrame(), port = initFrame(f, ['app.subscribe.v2']);
  vm.runInContext(`var plain=window.native.query({sql:'select 1'});
    var odd=window.native.query({sql:'select 2'}, {lastKnown:true, onPartial:function(){throw Error('paint failed')}});
    var bad=window.native.query({sql:'select 3'}, {lastKnown:true, onPartial:function(){ globalThis.badHeard=true }});`, f.sandbox);
  const [a, b, c] = posts(port).filter(m => m.type === 'query');
  assert.equal(a.last_known, undefined);
  emit(f, port, { version: VERSION, type: 'query-partial', request_id: a.request_id, result: table(['x']), cached: true });
  emit(f, port, { version: VERSION, type: 'query-partial', request_id: b.request_id, result: table(['x']), cached: true });
  emit(f, port, { version: VERSION, type: 'query-partial', request_id: c.request_id, result: { rows: 'nope' }, cached: true });
  emit(f, port, { version: VERSION, type: 'query-result', request_id: a.request_id, status: 'ok', result: table(['a']) });
  emit(f, port, { version: VERSION, type: 'query-result', request_id: b.request_id, status: 'ok', result: table(['b']) });
  emit(f, port, { version: VERSION, type: 'query-result', request_id: c.request_id, status: 'ok', result: table(['c']) });
  assert.equal((await f.sandbox.plain).rows[0][0], 'a');
  assert.equal((await f.sandbox.odd).rows[0][0], 'b');
  assert.equal((await f.sandbox.bad).rows[0][0], 'c');
  assert.equal(f.sandbox.badHeard, undefined, 'a malformed partial is dropped, not delivered');
});

test('the port closing rejects a pending last-known query and delivers no partial afterwards', async () => {
  const f = loadFrame(), port = initFrame(f, ['app.subscribe.v2']);
  vm.runInContext(`var held=[], failure=null;
    window.native.query({sql:'select 1'}, {lastKnown:true, onPartial:function(p){held.push(p)}}).catch(function(e){failure=e});`, f.sandbox);
  const sent = posts(port).find(m => m.type === 'query');
  port._emit('close', new f.refs.MessageEvent('close', {}));
  await tick();
  emit(f, port, { version: VERSION, type: 'query-partial', request_id: sent.request_id, result: table(['late']), cached: true });
  assert.equal(f.sandbox.held.length, 0);
  assert.equal(f.sandbox.failure.code, 'port_closed');
});
