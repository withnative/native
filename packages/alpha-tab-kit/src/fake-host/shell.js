// The fake host's parent page: a browser-side mirror of the alpha shell's
// live-frame holder (experiments/demo-shell/public/views/pending.js,
// `liveFrame`, `handleRead` and `dispatchRead`). Served as a module by
// server.mjs, which also injects `window.__ALPHA_TAB_HOST_CONFIG__`.
//
// Semantics kept from the real shell:
// - on-request reads queue FIFO per frame, at most `read_queue_max` (8)
//   accepted at once counting those in flight; up to `reads_in_flight` (4)
//   are dispatched together, and a read beyond the cap is answered
//   `{status:"busy", code:"busy"}` immediately and is NOT queued;
// - admission bounds mirror the bridge (need and request id 1-128 chars,
//   params a JSON object of at most 4096 chars); a queued read keeps only a
//   copy of those three values;
// - undeclared needs and out-of-schema params are refused before any
//   network call, at admission and again when the read reaches the front
//   (pendingTabs.js declaredReadRefusalFor);
// - backend errors map `[code]` to refused/unavailable;
// - a dispatched read that outlives the host timeout retires only its own
//   ticket: it is answered unavailable and the frame's other reads keep
//   going. The real shell cannot cancel its tool call, so it holds the
//   timed-out slot until that call settles or a bounded grace passes; this
//   host aborts its fetch, so the call settles at once and the slot frees
//   immediately, with the same grace as a backstop (only the answers and
//   slot accounting are mirrored);
// - a new document in the same holder answers the old document's reads
//   `tab_reloaded` on the old port. With no read on the wire it is then
//   re-handshaken as before; with one still on the wire the frame's reads
//   are retired instead (the shell closes that holder with a notice, and
//   Retry opens a fresh one), so the old read's timer, answer and cleanup
//   can never reach the new document;
// - navigation is honoured only with host user activation and a bounded,
//   printable record id (pending.js handleNavigation);
// - view-state messages are accepted and dropped (the alpha shell has no
//   handler); `holdViewState` re-delivers the latest one on reload, as the
//   Workbench host does (web/workbench/src/htmlArtifactHost/mount.ts:1056).
// The frame side is the real bridge (crates/artifact-html BOOTSTRAP),
// injected by server.mjs, so its own caps (8 pending reads, 4 KiB params,
// 1 MiB answers, 64 KiB view state) apply unmodified.
import { declaredReadRefusal } from "/__kit/rules.mjs";

const config = window.__ALPHA_TAB_HOST_CONFIG__;
const limits = config.limits;
const version = limits.bridge.version;
const events = [];
const log = (type, detail = {}) => {
  const event = { type, at: Math.round(performance.now()), ...detail };
  events.push(event);
  const status = document.getElementById("host-log");
  if (status) status.textContent = `${events.length} host events; last: ${type}`;
  navigator.sendBeacon?.("/__host/event", JSON.stringify(event));
};

let port = null;
// Reads accepted but not yet dispatched, oldest first, and those dispatched
// and not yet settled. A ticket is `{ id, port, requestId, need, params,
// settled, timer, releaseTimer }`.
const readQueue = [];
const readInFlight = new Set();
let readTicketSeq = 0;
const readTimeoutMs = config.readTimeoutMs ?? limits.shell.read_timeout_ms;
const readsInFlightMax = limits.shell.reads_in_flight ?? 1;
const readSlotGraceMs = limits.shell.read_timeout_slot_grace_ms ?? 15_000;
let heldViewState = null;
let inputSeq = 0;
let handshakeTimer = null;
let failed = false;

const iframe = document.createElement("iframe");
iframe.id = "alpha-tab-frame";
iframe.title = config.title;
iframe.sandbox = "allow-scripts";
iframe.referrerPolicy = "no-referrer";
iframe.allow = "";
iframe.src = "/frame";
document.getElementById("holder").append(iframe);

function reply(type, requestId, body) {
  port?.postMessage({ type, version, request_id: requestId, ...body });
}

const boundedId = (value) => typeof value === "string" && value.length > 0 && value.length <= 128 && value.trim() === value && !/[\u0000-\u001f\u007f]/.test(value);

// Answer one ticket exactly once, on the port it arrived on.
function settleRead(ticket, body) {
  if (ticket.settled) return false;
  ticket.settled = true;
  try { ticket.port.postMessage({ type: "read-result", version, request_id: ticket.requestId, ...body }); } catch { /* closed */ }
  return true;
}

// Answer every accepted read that has not been answered: each in-flight
// ticket (whose dispatch still holds its slot until it finishes) and the
// queue.
function drainReads(code) {
  // Disarm each dispatched read's timeout and grace: an abandoned read never
  // times out into anything later. Its fetch is left to finish, as the
  // shell's call is.
  for (const ticket of readInFlight) {
    clearTimeout(ticket.timer);
    if (ticket.releaseTimer) { clearTimeout(ticket.releaseTimer); ticket.releaseTimer = null; }
    if (settleRead(ticket, { status: "unavailable", code })) {
      log("read-drained", { request_id: ticket.requestId, need: ticket.need, params: ticket.params, code, active: true });
    }
  }
  for (const ticket of readQueue.splice(0)) {
    if (settleRead(ticket, { status: "unavailable", code })) log("read-drained", { request_id: ticket.requestId, need: ticket.need, params: ticket.params, code, active: false });
  }
}

function handleRead(message) {
  const requestId = message.request_id;
  if (!boundedId(requestId)) { log("read-ignored", { reason: "request_id" }); return; }
  if (!boundedId(message.need)) {
    log("read-refused", { request_id: requestId, need: null, params: null, code: "undeclared_need" });
    reply("read-result", requestId, { status: "refused", code: "undeclared_need" });
    return;
  }
  let params;
  if (message.params !== undefined) {
    let encoded = null;
    try { encoded = message.params && typeof message.params === "object" && !Array.isArray(message.params) ? JSON.stringify(message.params) : null; } catch { encoded = null; }
    if (typeof encoded !== "string" || encoded.length > limits.bridge.read_params_max_chars) {
      log("read-refused", { request_id: requestId, need: message.need, params: null, code: "invalid_params" });
      reply("read-result", requestId, { status: "refused", code: "invalid_params" });
      return;
    }
    params = JSON.parse(encoded);
  }
  if (config.mode === "sample") {
    // The sample frame is offered no needs, so the bridge refuses reads
    // before they reach here; anything that does is undeclared.
    reply("read-result", requestId, { status: "refused", code: "undeclared_need" });
    return;
  }
  const refusal = declaredReadRefusal(config.plan, message.need, params, limits);
  if (refusal) {
    log("read-refused", { request_id: requestId, need: message.need, params, code: refusal });
    reply("read-result", requestId, { status: "refused", code: refusal });
    return;
  }
  if (readInFlight.size + readQueue.length >= limits.shell.read_queue_max) {
    log("read-busy", { request_id: requestId, need: message.need, params, inflight: [...readInFlight].map((ticket) => ticket.requestId), queued: readQueue.length });
    reply("read-result", requestId, { status: "busy", code: "busy" });
    return;
  }
  readTicketSeq += 1;
  const ticket = { id: readTicketSeq, port, requestId, need: message.need, params, settled: false };
  readQueue.push(ticket);
  log("read-queued", { request_id: requestId, need: ticket.need, params, ticket: ticket.id, position: readInFlight.size + readQueue.length });
  pumpReads();
}

function pumpReads() {
  while (!failed && readInFlight.size < readsInFlightMax && readQueue.length > 0) {
    const ticket = readQueue.shift();
    if (ticket.settled) continue;
    // Consent and params again at dispatch, as the shell does.
    const refusal = declaredReadRefusal(config.plan, ticket.need, ticket.params, limits);
    if (refusal) {
      log("read-refused", { request_id: ticket.requestId, need: ticket.need, params: ticket.params, code: refusal });
      settleRead(ticket, { status: "refused", code: refusal });
      continue;
    }
    readInFlight.add(ticket);
    void dispatchRead(ticket);
  }
}

// Release a ticket's slot if it still holds one, clearing any pending
// post-timeout grace; pump when this is still the live frame. Idempotent.
function releaseReadSlot(ticket) {
  if (ticket.releaseTimer) { clearTimeout(ticket.releaseTimer); ticket.releaseTimer = null; }
  if (!readInFlight.has(ticket)) return;
  readInFlight.delete(ticket);
  if (ticket.port === port) pumpReads();
}

async function dispatchRead(ticket) {
  const { requestId, need, params } = ticket;
  log("read-start", { request_id: requestId, need, params, ticket: ticket.id });
  const controller = new AbortController();
  let timedOut = false;
  const timeout = setTimeout(() => { timedOut = true; controller.abort(); }, readTimeoutMs);
  ticket.timer = timeout;
  const live = () => !failed && !ticket.settled && ticket.port === port;
  try {
    const response = await fetch("/__host/read", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ need, params }),
      signal: controller.signal,
    });
    const answer = await response.json();
    if (!live()) return;
    if (answer.error) {
      const code = String(answer.error);
      const status = code === "unavailable" ? "unavailable" : "refused";
      log("read-error", { request_id: requestId, need, params, code });
      settleRead(ticket, { status, code });
      return;
    }
    log("read-ok", { request_id: requestId, need, params, rows: answer.result?.rows?.length ?? null, truncated: answer.result?.truncated ?? null });
    settleRead(ticket, { status: "ok", need, result: answer.result });
  } catch (error) {
    if (timedOut) {
      // Retire only this ticket; the frame's other reads keep going. This
      // host aborts its fetch, so the slot frees in `finally` (the real
      // shell, which cannot cancel, holds the slot until its abandoned call
      // settles or a bounded grace passes).
      if (!live()) return;
      if (settleRead(ticket, { status: "unavailable", code: "unavailable" })) log("read-error", { request_id: requestId, need, params, code: "unavailable", detail: "timeout" });
      log("read-timeout", { request_id: requestId, need, params });
      return;
    }
    if (!live()) return;
    log("read-error", { request_id: requestId, need, params, code: "unavailable", detail: String(error?.message ?? error) });
    settleRead(ticket, { status: "unavailable", code: "unavailable" });
  } finally {
    clearTimeout(timeout);
    if (timedOut) {
      // Mirror the shell's bounded post-timeout release: the shell cannot
      // cancel its call, so it holds the slot until the call settles or the
      // grace passes. This host aborts its fetch, which settles the call at
      // once, so `releaseReadSlot` below is the "settles first" path and
      // clears this timer; the grace is the same backstop if a fetch hangs.
      ticket.releaseTimer = setTimeout(() => releaseReadSlot(ticket), readSlotGraceMs);
    }
    releaseReadSlot(ticket);
  }
}

// The one terminal path, as the shell's `fail`/`close`: stop dispatching,
// disarm the handshake and read timers, answer every accepted read once on
// its own port, then close the port. Later messages cannot arrive (the port
// is closed) and a retained handler ignores them (see `onPortMessage`).
function terminate(code, reason) {
  if (failed) return;
  failed = true;
  clearTimeout(handshakeTimer);
  drainReads(code);
  try { port?.close(); } catch { /* closed */ }
  log("frame-closed", { reason });
}

async function answerIntent(intent) {
  const response = await fetch("/__host/intent", { method: "POST", body: JSON.stringify(intent) });
  return response.json();
}

function handleNavigation(message) {
  const hostActive = navigator.userActivation?.isActive === true;
  const id = message.recordId;
  const valid = typeof id === "string" && id.length > 0 && id.length <= limits.shell.navigation_id_max_chars && !/[\u0000-\u001f\u007f\s]/.test(id);
  log(hostActive && valid ? "navigation" : "navigation-ignored", { recordId: id, href: message.href, newTab: message.newTab === true, hostActive, valid });
}

function onPortMessage(event, receivingPort) {
  // Only the current, live port is heard: nothing reaches a retired frame
  // or a superseded document's handler.
  if (failed || receivingPort !== port) return;
  const message = event.data;
  if (message?.version !== version) return;
  switch (message.type) {
    case "ready":
      clearTimeout(handshakeTimer);
      log("ready", { profile: message.profile });
      break;
    case "read":
      if (config.mode === "sample") { log("read-ignored-sample", { need: message.need }); break; }
      handleRead(message);
      break;
    case "view-state":
      heldViewState = message.view_state;
      log("view-state", { view_state: message.view_state, bytes: JSON.stringify(message.view_state ?? null).length });
      break;
    case "navigation":
      if (config.mode === "sample") { log("navigation-ignored", { recordId: message.recordId, reason: "sample" }); break; }
      handleNavigation(message);
      break;
    case "intent":
      log("intent", { intent: message.intent });
      if (config.writes && config.mode !== "sample") {
        const replyPort = port;
        answerIntent(message.intent).then((result) => {
          if (replyPort === port) port.postMessage({ type: "intent-result", version, request_id: message.intent?.request_id, result });
        });
        break;
      }
      port.postMessage({ type: "intent-result", version, request_id: message.intent?.request_id, result: { status: "rejected", code: config.mode === "sample" ? "preview_sample_only" : "unsupported_host" } });
      break;
    case "intent-arm": {
      // Only when the package's host was given `intents`: the confirmation
      // prompt is simulated, and the handler's answer stands for the person
      // pressing Apply (or Cancel) in the host.
      log("intent-arm", { intent: message.intent });
      const armPort = port;
      const requestId = message.intent?.request_id;
      armPort.postMessage({ type: "intent-arm-ack", version, request_id: requestId, status: "armed" });
      answerIntent(message.intent).then((result) => {
        if (armPort === port) armPort.postMessage({ type: "intent-arm-result", version, request_id: requestId, result });
      });
      break;
    }
    case "intent-arm-ready":
    case "intent-arm-cancel":
      log(message.type, { request_id: message.request_id });
      break;
    case "input-applied":
    case "input-unhandled":
      log(message.type, { input_digest: message.input_digest, reason: message.reason });
      break;
    case "diagnostic":
      log("diagnostic", { code: message.code, detail: message.detail });
      break;
    default:
      log("message", { message_type: message.type });
  }
}

window.addEventListener("message", (event) => {
  if (event.source !== iframe.contentWindow || event.data?.type !== "native-html-bootstrap" || event.data?.version !== version) return;
  if (failed) return;
  if (port) {
    // A new document in the same holder: answer its accepted reads on the
    // old port, as the shell does (pending.js `tab_reloaded`).
    drainReads("tab_reloaded");
    if (readInFlight.size > 0) {
      // The shell retires this holder rather than re-handshake it while a
      // read it cannot cancel is on the wire (notice `reloaded_during_read`).
      log("reload-retired", { reason: "reloaded_during_read" });
      terminate("tab_reloaded", "reloaded_during_read");
      return;
    }
    port.close();
  }
  const channel = new MessageChannel();
  port = channel.port1;
  const receivingPort = port;
  port.onmessage = (event) => onPortMessage(event, receivingPort);
  port.onmessageerror = () => {
    if (receivingPort !== port) return;
    log("message-error");
    terminate("tab_closed", "message-error");
  };
  port.start();
  const init = { type: "native-html-init", version, input: config.init.input };
  if (config.init.input_digest) init.input_digest = config.init.input_digest;
  if (config.init.needs?.length) init.needs = config.init.needs;
  if (config.writes) init.host_features = ["intent-arm-confirm.v1"];
  if (config.holdViewState && heldViewState) init.view_state = heldViewState;
  log("init", { mode: config.mode, needs: init.needs ?? [] });
  iframe.contentWindow.postMessage(init, "*", [channel.port2]);
  clearTimeout(handshakeTimer);
  handshakeTimer = setTimeout(() => {
    if (receivingPort !== port) return;
    log("handshake-timeout");
    terminate("tab_closed", "handshake-timeout");
  }, limits.shell.handshake_timeout_ms);
});

// Test hooks: the Node side drives these through page.evaluate.
window.__alphaTabHost = Object.freeze({
  events: () => events.slice(),
  // Test-only delivery after simulated host admission. This proves the real
  // bridge/app subscription, not production admission or committed-focus ACK.
  reveal(record_id) {
    if (failed || !port || typeof record_id !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(record_id)) throw Error("Invalid reveal target or closed tab");
    port.postMessage({ type: "reveal", version, record_id });
    log("reveal-sent", { record_id });
  },
  async pushInput() {
    const response = await fetch("/__host/snapshot", { method: "POST" });
    const fresh = await response.json();
    inputSeq += 1;
    port?.postMessage({ type: "input", version, input: fresh.input, input_digest: fresh.input_digest, revision: { content_event_seq: inputSeq } });
    log("input-sent", { seq: inputSeq, input_digest: fresh.input_digest });
    return fresh.input_digest;
  },
  reload() { iframe.src = `/frame?reload=${Date.now()}`; },
});
