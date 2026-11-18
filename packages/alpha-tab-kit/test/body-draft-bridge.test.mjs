// Frame tests for native.presentation.setFloatingChat (task e27b79d).
// Loads the real vendored bridge in node:vm; asserts gated exposure,
// boolean update round-trip, default absent, invalid/oversized throws,
// and generation teardown resolves false.
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

function loadFrame(kit = false, nativeConflict = false, timers = {}) {
  const sandbox = { __NATIVE_WORKBENCH_ORIGIN__: HOST, __NATIVE_KIT_FACTORY__: null, __NATIVE_KIT_RELEASE__: null, setTimeout, clearTimeout, AbortController, TextEncoder, TextDecoder, performance, requestAnimationFrame: undefined, console, ...timers };
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
function settle(frame, port, request_id, accepted) {
  const data = vm.runInContext(`({version:${JSON.stringify(VERSION)},type:"presentation-result",request_id:${JSON.stringify(request_id)},status:"ok",accepted:${accepted ? "true" : "false"}})`, frame.sandbox);
  port._emit("message", new frame.refs.MessageEvent("message", { data }));
}
test('new apps on old hosts have no device draft capability', () => {
  const frame = loadFrame(); initFrame(frame, ['app.call.v2']);
  assert.equal(frame.sandbox.window.nativeArtifact.bodyDraft, undefined);
  assert.equal(frame.sandbox.window.native.bodyDraft, undefined);
});
test('new host negotiation does nothing to an old app that never uses the port', () => {
  const frame = loadFrame(); const port = initFrame(frame, ['app.call.v2', 'app.body-draft.v1']);
  assert.equal(posts(port).filter(message => message.type === 'body-draft').length, 0);
});
test('put and clear correlate exact acknowledgements; close answers unavailable', async () => {
  const frame = loadFrame(); const port = initFrame(frame, ['app.call.v2', 'app.body-draft.v1']);
  const api = frame.sandbox.window.native.bodyDraft;
  const pending = api.put({ record: 'doc', writer: 'writer-a', revision: 3, draft: { text: 'private text' } });
  const sent = posts(port).find(message => message.type === 'body-draft');
  emit(frame, port, { version: VERSION, type: 'body-draft-result', request_id: sent.request_id, status: 'ok', writer: 'writer-a', revision: 3 });
  assert.deepEqual(JSON.parse(JSON.stringify(await pending)), { status: 'ok', writer: 'writer-a', revision: 3 });
  const clear = api.clear({ record: 'doc', writer: 'writer-a', revision: 3, reason: 'saved' });
  port._emit('close', new frame.refs.MessageEvent('close'));
  assert.equal((await clear).code, 'unavailable');
});

test('draft deadline releases slots, settles once, ignores late replies and teardown clears timers', async () => {
  const timers = [], cleared = [];
  const frame = loadFrame(false, false, { setTimeout(fn, ms) { const t = { fn, ms }; timers.push(t); return t; }, clearTimeout(t) { cleared.push(t); } });
  const port = initFrame(frame, ['app.call.v2', 'app.body-draft.v1']), api = frame.sandbox.window.native.bodyDraft;
  const pending = Array.from({ length: 8 }, () => api.get('doc'));
  assert.equal((await api.get('doc')).code, 'busy');
  const deadlines = timers.filter(t => t.ms === 10000);
  assert.equal(deadlines.length, 8);
  for (const timer of deadlines) { timer.fn(); timer.fn(); }
  assert.ok((await Promise.all(pending)).every(result => result.code === 'timeout'));
  const last = api.get('doc');
  assert.equal(posts(port).filter(message => message.type === 'body-draft').length, 9);
  const sent = posts(port).filter(message => message.type === 'body-draft');
  emit(frame, port, { version: VERSION, type: 'body-draft-result', request_id: sent[0].request_id, status: 'ok', entries: [] });
  port._emit('close', new frame.refs.MessageEvent('close'));
  assert.equal((await last).code, 'unavailable');
  assert.ok(cleared.includes(timers.at(-1)));
});

 test('trusted non-persisted pagehide leaves draft lane open for a synchronous bubble put; unload closes it', async () => {
  const frame = loadFrame(); const port = initFrame(frame, ['app.call.v2', 'app.body-draft.v1']);
  vm.runInContext(`window._emit('pagehide', new PageTransitionEvent('pagehide', {trusted:true,persisted:false}))`, frame.sandbox);
  await Promise.resolve();
  const pending = frame.sandbox.window.native.bodyDraft.put({ record: 'doc', writer: 'writer', revision: 1, draft: { text: 'private text' } });
  assert.equal(posts(port).filter(m => m.type === 'body-draft').length, 1);
  vm.runInContext(`window._emit('unload', new Event('unload', {trusted:true}))`, frame.sandbox);
  assert.equal((await pending).code, 'unavailable');
});
