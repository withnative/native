// Headless frame-behavior tests for the inbound reveal surface (task
// fb8564c). Each test executes the ACTUAL vendored bridge
// (src/fake-host/bridge-bootstrap.js, pinned by SHA in limits.json and
// byte-identical to the engine BOOTSTRAP by the drift guard) inside
// node:vm with stub browser intrinsics, drives it as the host would —
// init handshake, channel posts, subscriber registration — and asserts
// what the frame does: latest-one retention, replay-once, unsubscribe,
// deep-frozen minimal delivery, bad-payload bounds, clear paths, throw
// diagnostics, and the ready features advertisement next to unchanged
// fields and neighbor APIs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import vm from "node:vm";

const VERSION = "native.html.bridge.v1";
const HOST = "https://workbench.example";
const bootstrap = readFileSync(
  new URL("../src/fake-host/bridge-bootstrap.js", import.meta.url),
  "utf8",
);

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

/** Boot one frame. Returns the driver: window, parent posts, channel. */
function loadFrame(source = bootstrap) {
  const parentPosts = [];
  const sandbox = {
    __NATIVE_WORKBENCH_ORIGIN__: HOST,
    setTimeout,
    clearTimeout,
    AbortController,
    TextEncoder, TextDecoder,
    performance,
    requestAnimationFrame: undefined,
    console,
  };
  sandbox.window = null;
  sandbox.parent = { postMessage(value) { parentPosts.push(value); } };
  sandbox.document = { querySelector: () => null };
  vm.createContext(sandbox);
  vm.runInContext(`${STUBS}\nwindow = new Window();`, sandbox);
  // Expose the stub classes to the Node-side driver.
  const grab = (name) => vm.runInContext(name, sandbox);
  const refs = {
    EventTarget: grab("EventTarget"),
    MessageEvent: grab("MessageEvent"),
    MessagePort: grab("MessagePort"),
    PageTransitionEvent: grab("PageTransitionEvent"),
    Event: grab("Event"),
  };
  vm.runInContext(source, sandbox);
  return { sandbox, refs, parentPosts, window: sandbox.window };
}

/** Complete the init handshake; returns the frame-side channel port. */
function initFrame(frame, { needs = [], hostFeatures = [], input = {}, bodyAttempt = null } = {}) {
  const { sandbox, refs } = frame;
  const port = new refs.MessagePort();
  const init = vm.runInContext(
    `({ type: "native-html-init", version: ${JSON.stringify(VERSION)}, needs: ${JSON.stringify(needs)}, host_features: ${JSON.stringify(hostFeatures)}, input: ${JSON.stringify(input)}, body_attempt: ${JSON.stringify(bodyAttempt)} })`,
    sandbox,
  );
  const event = new refs.MessageEvent("message", {
    data: init,
    ports: [port],
    source: sandbox.parent,
    origin: HOST,
  });
  sandbox.window._emit("message", event);
  return port;
}

function channelPosts(port) {
  return port._posted;
}

function diagnostics(port) {
  return port._posted.filter((m) => m && m.type === "diagnostic");
}

function postReveal(frame, port, payload) {
  const { sandbox, refs } = frame;
  const data =
    payload !== null && typeof payload === "object"
      ? vm.runInContext(`(${JSON.stringify(payload)})`, sandbox)
      : payload;
  if (data !== null && (typeof data === "object" || typeof data === "function")) {
    data.version = VERSION;
  }
  port._emit("message", new refs.MessageEvent("message", { data }));
}

test("ready advertises the reveal feature beside unchanged fields", () => {
  const frame = loadFrame();
  const port = initFrame(frame);
  const ready = channelPosts(port).find((m) => m && m.type === "ready");
  assert.ok(ready, "ready is sent");
  assert.equal(ready.version, VERSION);
  assert.equal(ready.profile, "document");
  assert.equal(ready.slides, 0);
  assert.equal(ready.features.length, 1, "one advertised feature");
  assert.equal(ready.features[0], "surface.reveal.v1");
  const api = frame.window.nativeArtifact;
  assert.equal(typeof api.onReveal, "function");
  // Neighbors unchanged: input subscription, on-request reads, ARM.
  assert.equal(typeof api.onInput, "function");
  assert.equal(typeof api.read, "function");
  assert.equal(typeof api.arm, "function");
  assert.equal(typeof api.publishLocation, "function");
  api.publishLocation("unnegotiated-record");
  assert.equal(channelPosts(port).filter((m) => m.type === "location").length, 0,
    "a current API does not imply negotiated location capability");

  const locationFrame = loadFrame();
  const locationPort = initFrame(locationFrame, { hostFeatures: ["surface.location.v1"] });
  const locationReady = channelPosts(locationPort).find((m) => m.type === "ready");
  assert.deepEqual(Array.from(locationReady.features), ["surface.reveal.v1", "surface.location.v1"]);
  locationFrame.window.nativeArtifact.publishLocation("selected-record");
  locationFrame.window.nativeArtifact.publishLocation(null);
  assert.deepEqual(Array.from(channelPosts(locationPort).filter((m) => m.type === "location"), (m) => m.record_id),
    ["selected-record", null]);
  assert.throws(() => locationFrame.window.nativeArtifact.publishLocation("bad\nrecord"));
  assert.equal(channelPosts(locationPort).filter((m) => m.type === "location").length, 2,
    "invalid scalar publication is refused without sending");
  locationPort._emit("close", {});
  assert.throws(() => locationFrame.window.nativeArtifact.publishLocation("after-close"),
    /location observation unavailable/);
  assert.equal(channelPosts(locationPort).filter((m) => m.type === "location").length, 2,
    "closed channel cannot publish another location");

  const historical = new URL("../../../experiments/alpha-tab-proof-packages/bridge-bootstrap-c851-historical.js", import.meta.url);
  if (existsSync(historical)) {
    const oldFrame = loadFrame(readFileSync(historical, "utf8"));
    const oldPort = initFrame(oldFrame, { hostFeatures: ["surface.reveal.v1", "surface.location.v1"] });
    const oldReady = channelPosts(oldPort).find((m) => m.type === "ready");
    assert.ok(oldReady, "historical bridge still becomes ready");
    assert.equal(oldReady.features, undefined, "offered capabilities cannot upgrade historical bytes");
    assert.equal(oldFrame.window.nativeArtifact.onReveal, undefined);
    assert.equal(oldFrame.window.nativeArtifact.publishLocation, undefined);
    assert.equal(typeof oldFrame.window.nativeArtifact.read, "function", "legacy read API survives");
  }
});

test("a reveal before registration is retained latest-one and replayed once", () => {
  const frame = loadFrame();
  const port = initFrame(frame);
  postReveal(frame, port, { type: "reveal", record_id: "first-target" });
  postReveal(frame, port, { type: "reveal", record_id: "second-target" });
  assert.equal(diagnostics(port).length, 0, "retention sends no diagnostics");
  const seen = [];
  const api = frame.window.nativeArtifact;
  api.onReveal((target) => seen.push(target));
  assert.equal(seen.length, 1, "replayed exactly once");
  assert.deepEqual(Object.keys(seen[0]).sort(), ["record_id"]);
  assert.equal(seen[0].record_id, "second-target", "latest supersedes");
  assert.ok(Object.isFrozen(seen[0]), "delivery is deep-frozen");
  // A later subscriber cannot re-deliver the retained command.
  api.onReveal(() => seen.push("late"));
  assert.equal(seen.length, 1, "no re-delivery to later subscribers");
});

test("current subscribers receive fresh reveals; unsubscribe works", () => {
  const frame = loadFrame();
  const port = initFrame(frame);
  const api = frame.window.nativeArtifact;
  const first = [];
  const second = [];
  const off = api.onReveal((t) => first.push(t.record_id));
  api.onReveal((t) => second.push(t.record_id));
  postReveal(frame, port, { type: "reveal", record_id: "live-one" });
  assert.deepEqual(first, ["live-one"]);
  assert.deepEqual(second, ["live-one"]);
  off();
  postReveal(frame, port, { type: "reveal", record_id: "live-two" });
  assert.deepEqual(first, ["live-one"], "unsubscribed callback stays silent");
  assert.deepEqual(second, ["live-one", "live-two"]);
});

test("unsupported payload fields are dropped, never frozen in", () => {
  const frame = loadFrame();
  const port = initFrame(frame);
  const seen = [];
  frame.window.nativeArtifact.onReveal((t) => seen.push(t));
  // Built inside the frame realm: a cyclic, field-heavy command the JSON
  // transport could never carry, proving delivery copies only the id.
  const { sandbox, refs } = frame;
  const cyclic = vm.runInContext(
    `(() => { const o = { type: "reveal", record_id: "kept-id", body: "leak", ancestors: ["a"], version: ${JSON.stringify(VERSION)} }; o.self = o; return o; })()`,
    sandbox,
  );
  port._emit("message", new refs.MessageEvent("message", { data: cyclic }));
  assert.equal(seen.length, 1);
  assert.deepEqual({ ...seen[0] }, { record_id: "kept-id" });
});

test("malformed reveals are bounded-dropped with a diagnostic and no ack", () => {
  const frame = loadFrame();
  const port = initFrame(frame);
  const seen = [];
  frame.window.nativeArtifact.onReveal((t) => seen.push(t));
  const bad = [
    { type: "reveal" },
    { type: "reveal", record_id: "" },
    { type: "reveal", record_id: "x".repeat(129) },
    { type: "reveal", record_id: 42 },
    { type: "reveal", record_id: "caf\u00e9" },
    { type: "reveal", record_id: "has\nnewline" },
    // Outside the exact backend alphabet: spaces and punctuation never
    // reach the callback, even though they fit a loose ASCII shape.
    { type: "reveal", record_id: "has space" },
    { type: "reveal", record_id: "bang!id" },
    { type: "reveal", record_id: "slash/id" },
    { type: "reveal", record_id: "at@sign" },
    // Trailing line terminators are refused too: the flagless `$` anchors
    // at end of input only (executed verification, not assumption).
    { type: "reveal", record_id: "native:root\n" },
    { type: "reveal", record_id: "native:root\r" },
    { type: "reveal", record_id: "native:root\r\n" },
    { type: "reveal", record_id: "native:root " },
    { type: "reveal", record_id: "native:root " },
    { type: "reveal", record_id: "native:root\t" },
  ];
  for (const payload of bad) postReveal(frame, port, payload);
  // Versionless shapes never enter reveal handling at all, like every
  // other channel dispatch: silent, no diagnostic.
  postReveal(frame, port, null);
  postReveal(frame, port, "reveal");
  assert.equal(seen.length, 0, "nothing reaches subscribers");
  const dropped = diagnostics(port).filter((d) => d.code === "html_reveal_dropped");
  assert.equal(dropped.length, bad.length, "one bounded diagnostic each");
  assert.ok(
    channelPosts(port).every((m) => m.type !== "reveal-applied" && m.type !== "reveal-unhandled"),
    "reveal never acks",
  );
});

test("a version-mismatched reveal is ignored silently", () => {
  const frame = loadFrame();
  const port = initFrame(frame);
  const { sandbox, refs } = frame;
  const seen = [];
  frame.window.nativeArtifact.onReveal((t) => seen.push(t));
  const data = vm.runInContext(`({ type: "reveal", record_id: "abc", version: "other" })`, sandbox);
  port._emit("message", new refs.MessageEvent("message", { data }));
  assert.equal(seen.length, 0);
  assert.equal(diagnostics(port).length, 0);
});

test("a throwing callback yields a bounded diagnostic, not authority", () => {
  const frame = loadFrame();
  const port = initFrame(frame);
  const api = frame.window.nativeArtifact;
  const after = [];
  api.onReveal(() => {
    throw new Error("package blew up");
  });
  api.onReveal((t) => after.push(t.record_id));
  postReveal(frame, port, { type: "reveal", record_id: "shaky" });
  assert.deepEqual(after, ["shaky"], "remaining subscribers still run");
  const failed = diagnostics(port).filter((d) => d.code === "html_reveal_failed");
  assert.equal(failed.length, 1);
  assert.match(failed[0].detail.message, /package blew up/);
});

test("reveal-clear drops the retained target with no callbacks and no ack", () => {
  const frame = loadFrame();
  const port = initFrame(frame);
  postReveal(frame, port, { type: "reveal", record_id: "doomed" });
  const before = channelPosts(port).length;
  const seen = [];
  postReveal(frame, port, { type: "reveal-clear" });
  frame.window.nativeArtifact.onReveal((t) => seen.push(t));
  assert.equal(seen.length, 0, "cleared target never replays");
  assert.equal(channelPosts(port).length, before, "clear sends nothing");
});

test("retained target clears on pagehide, messageerror and close", () => {
  for (const how of ["pagehide", "messageerror", "close"]) {
    const frame = loadFrame();
    const port = initFrame(frame);
    postReveal(frame, port, { type: "reveal", record_id: "doomed" });
    if (how === "pagehide") {
      frame.window._emit(
        "pagehide",
        new frame.refs.PageTransitionEvent("pagehide", { trusted: true, persisted: false }),
      );
    } else {
      port._emit(how, new frame.refs.Event(how));
    }
    const seen = [];
    frame.window.nativeArtifact.onReveal((t) => seen.push(t));
    assert.equal(seen.length, 0, `cleared on ${how}`);
  }
});

test("a pre-init reveal never reaches a later subscriber", () => {
  const frame = loadFrame();
  const { sandbox, refs } = frame;
  // No channel exists before init; a reveal-shaped window message is not
  // an init handshake, so it is ignored and retains nothing.
  const data = vm.runInContext(
    `({ type: "reveal", record_id: "early", version: ${JSON.stringify(VERSION)} })`,
    sandbox,
  );
  sandbox.window._emit(
    "message",
    new refs.MessageEvent("message", { data, ports: [], source: sandbox.parent, origin: HOST }),
  );
  initFrame(frame);
  const seen = [];
  frame.window.nativeArtifact.onReveal((t) => seen.push(t));
  assert.equal(seen.length, 0, "only post-init commands are retained");
});

test("exact alphabet shapes are accepted: UUID, reserved, historical", () => {
  const frame = loadFrame();
  const port = initFrame(frame);
  const seen = [];
  frame.window.nativeArtifact.onReveal((t) => seen.push(t.record_id));
  for (const id of [
    "e1d00000-0000-4000-8000-0000000000a1",
    "native:root",
    "native:unfiled",
    "order-one",
    "a",
    "A-Z_9.:-x",
    "y".repeat(128),
  ]) {
    postReveal(frame, port, { type: "reveal", record_id: id });
  }
  assert.deepEqual(seen, [
    "e1d00000-0000-4000-8000-0000000000a1",
    "native:root",
    "native:unfiled",
    "order-one",
    "a",
    "A-Z_9.:-x",
    "y".repeat(128),
  ]);
});

test("author prototype tampering cannot change the shape verdict", () => {
  const frame = loadFrame();
  const port = initFrame(frame);
  const { sandbox } = frame;
  // Tamper AFTER bootstrap load: the validator must keep working because
  // it captured the pristine exec and never consults prototype methods,
  // the RegExp global, or string helpers.
  vm.runInContext(
    `RegExp.prototype.test = () => false;
     RegExp.prototype.exec = () => null;
     RegExp.prototype[Symbol.replace] = () => { throw new Error("tampered"); };
     String.prototype.replace = () => { throw new Error("tampered"); };
     String.prototype.match = () => { throw new Error("tampered"); };
     String.prototype.search = () => { throw new Error("tampered"); };
     RegExp = function () { throw new Error("tampered"); };`,
    sandbox,
  );
  const seen = [];
  frame.window.nativeArtifact.onReveal((t) => seen.push(t.record_id));
  postReveal(frame, port, { type: "reveal", record_id: "e1d00000-0000-4000-8000-0000000000a1" });
  postReveal(frame, port, { type: "reveal", record_id: "native:root" });
  postReveal(frame, port, { type: "reveal", record_id: "has space" });
  postReveal(frame, port, { type: "reveal", record_id: "z".repeat(129) });
  assert.deepEqual(seen, ["e1d00000-0000-4000-8000-0000000000a1", "native:root"]);
  const dropped = diagnostics(port).filter((d) => d.code === "html_reveal_dropped");
  assert.equal(dropped.length, 2, "malformed still refused under tampering");
});

test("registering a non-function still throws synchronously", () => {
  const frame = loadFrame();
  initFrame(frame);
  assert.throws(
    () => frame.window.nativeArtifact.onReveal("nope"),
    /reveal subscriber must be a function/,
  );
});


test("actual Body bootstrap accepts full escaped capacity and rejects raw excess beyond its old early-count cutoff", async () => {
  const frame = loadFrame();
  const port = initFrame(frame, { hostFeatures: ["native.html.body-attempt.v1"], bodyAttempt: { generation: "channel" } });
  const api = frame.window.nativeArtifact.bodyAttempt;
  const candidate = { entry_id: "save_body", target_id: "doc", expected_body_digest: "a".repeat(64), body: "" };
  const pending = [];
  for (const body of ["\u0001".repeat(524288), "😀".repeat(131072)]) {
    pending.push(api.prepare({ ...candidate, body }));
    const sent = channelPosts(port).at(-1);
    assert.equal(sent.type, "body-attempt-prepare");
    assert.equal(sent.candidate.body, body);
    assert.ok(Buffer.byteLength(JSON.stringify(sent)) <= 3211264);
  }
  const count = channelPosts(port).length;
  for (const body of ["x".repeat(524289), "😀".repeat(131073)]) {
    assert.throws(() => api.prepare({ ...candidate, body }), /Body source exceeds byte limit/);
  }
  assert.equal(channelPosts(port).length, count, "oversize sends no request");
  port._emit("close", new frame.refs.Event("close"));
  for (const work of pending) assert.equal((await work).code, "closed");
});
