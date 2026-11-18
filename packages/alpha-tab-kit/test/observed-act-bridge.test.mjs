// Frame tests for observed_act on the bridge (design note b08bdf78, slice 4): a pushed result carries the host's `act` beside
// cached and behind, and `call` may carry the frame's `observed: {act, basis}` claim on the envelope, never inside the args.
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


test('a pushed subscription result carries the act the host says, beside the rows; a missing or unusable one is simply absent', () => {
  const f = loadFrame(), port = initFrame(f, ['app.subscribe.v2']);
  vm.runInContext(`var seen=[];window.native.subscribe({sql:'select 1'},function(d){seen.push(d)});`, f.sandbox);
  const sub = posts(port).find(m => m.type === 'subscribe');
  const send = (delivery, extra) => emit(f, port, { version: VERSION, type: 'subscription-result', subscription_id: sub.subscription_id, delivery, result: table(['a']), ...extra });
  send(1, { act: 55 });
  send(2, {});
  send(3, { act: -1 }); send(4, { act: 1.5 }); send(5, { act: '9' }); send(6, { act: null });
  send(7, { act: 0 });
  const seen = f.sandbox.seen;
  assert.equal(seen.length, 7);
  assert.equal(seen[0].act, 55);
  assert.equal(Object.isFrozen(seen[0]), true);
  for (const index of [1, 2, 3, 4, 5]) assert.equal('act' in seen[index], false, `delivery ${index + 1}`);
  assert.equal(seen[6].act, 0);
});

test('a call carries the frame\'s observed claim on the envelope, beside operation and args, and not inside the args', () => {
  const f = loadFrame(), port = initFrame(f, ['app.call.v2']);
  vm.runInContext(`window.native.call('update_record', {id:'a', name:'N'}, {observed:{act:41, basis:'rendered'}});
    window.native.call('update_record', {id:'b'}, {observed:{act:null, basis:'none'}});
    window.native.call('update_record', {id:'c'});`, f.sandbox);
  const calls = posts(port).filter(m => m.type === 'call');
  assert.equal(calls.length, 3);
  assert.deepEqual(JSON.parse(JSON.stringify(calls[0].observed)), { act: 41, basis: 'rendered' });
  assert.deepEqual(JSON.parse(JSON.stringify(calls[0].args)), { id: 'a', name: 'N' });
  assert.deepEqual(JSON.parse(JSON.stringify(calls[1].observed)), { act: null, basis: 'none' });
  assert.equal('observed' in calls[2], false, 'a call without a claim sends none (the host fills in what the frame was given)');
});

test('an unusable observed claim is dropped, never sent and never refused', () => {
  const f = loadFrame(), port = initFrame(f, ['app.call.v2']);
  vm.runInContext(`var results=[];
    [{act:-1,basis:'rendered'},{act:1.5,basis:'rendered'},{act:'3',basis:'rendered'},{act:3,basis:'seen'},{act:3},{basis:'rendered'},{act:9007199254740993,basis:'rendered'}]
      .forEach(function(o){results.push(window.native.call('update_record', {id:'a'}, {observed:o}))});`, f.sandbox);
  const calls = posts(port).filter(m => m.type === 'call');
  assert.equal(calls.length, 7, 'every call still went');
  for (const call of calls) assert.equal('observed' in call, false);
});
