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
function settle(frame, port, request_id, accepted) {
  const data = vm.runInContext(`({version:${JSON.stringify(VERSION)},type:"presentation-result",request_id:${JSON.stringify(request_id)},status:"ok",accepted:${accepted ? "true" : "false"}})`, frame.sandbox);
  port._emit("message", new frame.refs.MessageEvent("message", { data }));
}
test('saved call presentation is opt-in, frozen and cannot settle the confirmed read', async () => {
  const f = loadFrame(), port = initFrame(f, ['app.call.v2']);
  vm.runInContext(`var snapshots=[], confirmed=false; var ticket=window.native.call('manage_messages',
    {action:'list_inbox'}, {onSnapshot:function(result,meta){snapshots.push({result,meta});}});
    ticket.confirmed.then(function(){confirmed=true;});`, f.sandbox);
  const id = posts(port).find(message => message.type === 'call').request_id;
  assert.equal(posts(port).find(message => message.type === 'call').read_snapshot, true);
  emit(f, port, { version: VERSION, type: 'call-snapshot', request_id: id, result: { items: ['old'] }, stored_at: 123 });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.sandbox.snapshots.length, 1);
  assert.equal(Object.isFrozen(f.sandbox.snapshots[0].result), true);
  assert.equal(f.sandbox.snapshots[0].meta.storedAt, 123);
  assert.equal(f.sandbox.confirmed, false);
  emit(f, port, { version: VERSION, type: 'call-result', request_id: id, status: 'ok', result: { items: ['new'] } });
  assert.equal((await f.sandbox.ticket.confirmed).items[0], 'new');
  emit(f, port, { version: VERSION, type: 'call-snapshot', request_id: id, result: { items: ['late'] } });
  assert.equal(f.sandbox.snapshots.length, 1);
});
test('a snapshot callback failure cannot break confirmation and normal calls request no snapshot', async () => {
  const f = loadFrame(), port = initFrame(f, ['app.call.v2']);
  vm.runInContext(`var normal=window.native.call('get_record',{});
    var ticket=window.native.call('manage_messages',{}, {onSnapshot:function(){throw Error('paint failed');}});`, f.sandbox);
  const calls = posts(port).filter(message => message.type === 'call');
  assert.equal(calls[0].read_snapshot, undefined);
  emit(f, port, { version: VERSION, type: 'call-snapshot', request_id: calls[1].request_id, result: {} });
  emit(f, port, { version: VERSION, type: 'call-result', request_id: calls[1].request_id, status: 'ok', result: 'confirmed' });
  assert.equal(await f.sandbox.ticket.confirmed, 'confirmed');
  emit(f, port, { version: VERSION, type: 'call-result', request_id: calls[0].request_id, status: 'ok', result: {} });
  await f.sandbox.normal.confirmed;
});
test("absent without host feature; present with app.presentation.v1", () => {
  const off = loadFrame(); initFrame(off, []);
  assert.equal(off.sandbox.window.nativeArtifact.presentation, undefined);
  assert.equal(off.sandbox.window.native, undefined);
  const on = loadFrame(); initFrame(on, ["app.presentation.v1"]);
  assert.equal(typeof on.sandbox.window.nativeArtifact.presentation.setFloatingChat, "function");
  assert.equal(typeof on.sandbox.window.native.presentation.setFloatingChat, "function");
});
test("boolean update round-trips; host accept resolves true", async () => {
  const f = loadFrame(); const port = initFrame(f, ["app.presentation.v1"]);
  const api = f.sandbox.window.nativeArtifact.presentation;
  const p = api.setFloatingChat(vm.runInContext("({suppress:true})", f.sandbox));
  const sent = posts(port).find((m) => m && m.type === "presentation");
  assert.ok(sent); assert.equal(sent.suppress, true);
  settle(f, port, sent.request_id, true);
  assert.equal(await p, true);
});
test("invalid and oversized inputs throw synchronously", () => {
  const f = loadFrame(); initFrame(f, ["app.presentation.v1"]);
  const api = f.sandbox.window.nativeArtifact.presentation;
  for (const bad of ["x", 1, null, [], {}, { suppress: 1 }, { suppress: true, extra: 1 }]) {
    const v = typeof bad === "object" && bad !== null ? vm.runInContext(`(${JSON.stringify(bad)})`, f.sandbox) : bad;
    assert.throws(() => api.setFloatingChat(v));
  }
  const getter = vm.runInContext(`(()=>{const o={};Object.defineProperty(o,"suppress",{enumerable:true,configurable:true,get(){return true}});return o})()`, f.sandbox);
  assert.throws(() => api.setFloatingChat(getter));
  const hidden = vm.runInContext(`(()=>{const o={};Object.defineProperty(o,"suppress",{enumerable:false,value:true});return o})()`, f.sandbox);
  assert.throws(() => api.setFloatingChat(hidden));
  const sym = vm.runInContext(`(()=>{const o={suppress:true};o[Symbol("s")]=1;return o})()`, f.sandbox);
  assert.throws(() => api.setFloatingChat(sym));
});
test("generation teardown resolves pending false", async () => {
  const f = loadFrame(); const port = initFrame(f, ["app.presentation.v1"]);
  const api = f.sandbox.window.nativeArtifact.presentation;
  const p = api.setFloatingChat(vm.runInContext("({suppress:true})", f.sandbox));
  port._emit("close", new f.refs.MessageEvent("close", {}));
  assert.equal(await p, false);
});

test("supplied canonical kit disposes on initialization failure before rejected readiness callbacks", async () => {
  const f=loadFrame(true);const kit=f.sandbox.window.native.kit;const states=[];
  kit.subscribe('records.recent',value=>states.push(value.status));
  initFrame(f,[],true);
  await assert.rejects(kit.ready,/test init failure/);
  await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(states,['loading']);
  await assert.rejects(kit.read('records.recent'),error=>error.code==='closed');
});
test("supplied canonical kit suppresses pending and pushed callbacks after every lifecycle closure", async () => {
  for (const event of ['pagehide','unload','messageerror','close']) {
    const f=loadFrame(true),kit=f.sandbox.window.native.kit,states=[];
    kit.subscribe('records.recent',value=>states.push(value.status));
    if(event==='pagehide'||event==='unload') f.sandbox.window._emit(event,new f.refs.MessageEvent(event));
    const port=initFrame(f,['app.presentation.v1']);
    if(event==='messageerror'||event==='close')port._emit(event,new f.refs.MessageEvent(event));
    await kit.ready;await new Promise(resolve=>setImmediate(resolve));
    emit(f,port,{version:VERSION,type:'input',input:{sql:{'records.recent':{rows:[]}}},input_digest:'new',revision:{content_event_seq:1}});
    await new Promise(resolve=>setImmediate(resolve));
    assert.deepEqual(states,['loading'],event);
    await assert.rejects(kit.read('records.recent'),error=>error.code==='closed');
  }
});

test("supplied canonical kit disposes if native slot initialization fails", async () => {
  const frame=loadFrame(true,true);
  assert.match(String(frame.error),/Cannot redefine property/);
  await assert.rejects(frame.sandbox.testOwned.kit.read('records.recent'),error=>error.code==='closed');
});

test('title feature negotiates independently, normalizes, acknowledges and closes pending work', async () => {
  const f=loadFrame(); const port=initFrame(f,['app.tab-title.v1']);
  const api=f.sandbox.window.native.presentation;
  assert.equal(api,f.sandbox.window.nativeArtifact.presentation);
  assert.equal(api.setFloatingChat,undefined);assert.equal(typeof api.setTabTitle,'function');
  const pending=api.setTabTitle(vm.runInContext('({title:"  My   document  "})',f.sandbox));
  const sent=posts(port).find(m=>m.type==='tab-title');assert.equal(sent.title,'My document');
  emit(f,port,{version:VERSION,type:'tab-title-result',request_id:sent.request_id,status:'ok',accepted:true});
  assert.equal(await pending,true);
  for(const expression of ['({title:""})','({title:"bad\\nname"})','({title:"\\u202ename"})','({title:"x".repeat(257)})','({get title(){throw Error("getter")}})','({title:"ok",extra:1})']) assert.throws(()=>api.setTabTitle(vm.runInContext(expression,f.sandbox)));
  const clear=api.setTabTitle(vm.runInContext('({title:null})',f.sandbox));
  port._emit('close',new f.refs.MessageEvent('close'));assert.equal(await clear,false);
  const old=loadFrame();initFrame(old,['app.presentation.v1']);assert.equal(old.sandbox.window.native.presentation.setTabTitle,undefined);
});
