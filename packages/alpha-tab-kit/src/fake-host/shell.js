// The fake host's parent page: a browser-side mirror of the alpha shell's
// live-frame holder (experiments/demo-shell/public/views/pending.js,
// `liveFrame`, `handleRead` and `dispatchRead`). Served as a module by
// server.mjs, which also injects `window.__ALPHA_TAB_HOST_CONFIG__`.
//
// Semantics kept from the real shell:
// - on-request reads queue FIFO per frame, at most `read_queue_max` (8)
//   accepted at once counting those in flight; up to `reads_in_flight` (4)
//   calls are dispatched together, and two or more queued declared reads of
//   one generation coalesce into one batched call (up to `read_batch_max`,
//   16) charging one slot; a read beyond the cap is answered
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
// - with `calls` configured the host offers `app.call.v2` and answers a
//   frame's `call` with `call-result`, with no need check (the v2 contract);
// - with `sessions` configured the host offers `app.session.v2` and answers a
//   frame's `session-open` with `session-opened` and one transferred
//   MessagePort that echoes frames (or `session-refused`), as the v2 host will
//   once it bridges each port to the session broker;
// - with `queries` configured (and not in sample mode, which answers neither)
//   the host offers `app.subscribe.v2` and answers a
//   frame's `query` with `query-result`, and a `subscribe` with a first
//   `subscription-result` (then pushes when the test asks), as the v2 read hub
//   will;
// - with `agents` configured (and not in sample mode) the host offers
//   `app.agents.v2`, answers `agents-list` and `agents-ask` (at most 4 asks in
//   flight, a fifth `busy`), and pushes `agents-status` only to a frame whose
//   ask was answered with that `ask_id`, as the alpha host does. The alpha
//   host's activation, gesture budget and own-comment checks are not mirrored
//   here;
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
// Reads accepted but not yet dispatched, oldest first, and the tool calls
// dispatched and not yet settled. A queued ticket is `{ id, port, requestId,
// need, params, settled }`; a dispatched call is a group `{ tickets, port,
// timer, releaseTimer }` — one ticket for a single read, several when the
// queued declared reads coalesce into one batched `live_read` (as the shell's
// `pumpReads` now does, charging one slot per call).
const readQueue = [];
const readInFlight = new Set();
let readTicketSeq = 0;
const readTimeoutMs = config.readTimeoutMs ?? limits.shell.read_timeout_ms;
const readsInFlightMax = limits.shell.reads_in_flight ?? 1;
const readBatchMax = limits.shell.read_batch_max ?? 16;
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
iframe.src = config.frameUrl ?? "/frame";
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
  for (const group of readInFlight) {
    clearTimeout(group.timer);
    if (group.releaseTimer) { clearTimeout(group.releaseTimer); group.releaseTimer = null; }
    for (const ticket of group.tickets) {
      if (settleRead(ticket, { status: "unavailable", code })) {
        log("read-drained", { request_id: ticket.requestId, need: ticket.need, params: ticket.params, code, active: true });
      }
    }
  }
  for (const ticket of readQueue.splice(0)) {
    if (settleRead(ticket, { status: "unavailable", code })) log("read-drained", { request_id: ticket.requestId, need: ticket.need, params: ticket.params, code, active: false });
  }
}

// Reads accepted but not yet answered, in flight or queued. One group may
// hold several tickets, so this is the admission bound `read_queue_max`
// counts against, not `readInFlight.size` (which counts tool calls).
function inFlightReadCount() {
  let count = 0;
  for (const group of readInFlight) count += group.tickets.length;
  return count;
}

// Defer the dispatch pump to a microtask so a burst of reads issued in one
// task coalesces into one batched call instead of dispatching its first
// `reads_in_flight` individually, mirroring the shell's `scheduleReadPump`.
// One microtask per frame; settle-time pumps stay synchronous.
let pumpScheduled = false;
function schedulePump() {
  if (pumpScheduled) return;
  pumpScheduled = true;
  queueMicrotask(() => {
    pumpScheduled = false;
    pumpReads();
  });
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
  if (inFlightReadCount() + readQueue.length >= limits.shell.read_queue_max) {
    log("read-busy", { request_id: requestId, need: message.need, params, inflight: [...readInFlight].flatMap((group) => group.tickets.map((ticket) => ticket.requestId)), queued: readQueue.length });
    reply("read-result", requestId, { status: "busy", code: "busy" });
    return;
  }
  readTicketSeq += 1;
  const ticket = { id: readTicketSeq, port, requestId, need: message.need, params, settled: false };
  readQueue.push(ticket);
  log("read-queued", { request_id: requestId, need: ticket.need, params, ticket: ticket.id, position: inFlightReadCount() + readQueue.length });
  schedulePump();
}

// Whether one queued ticket may join a batched call: still current and its
// consent/params still pass. This host has no `watch`, so nothing else
// excludes a ticket.
function readBatchEligible(ticket) {
  if (ticket.settled) return false;
  if (ticket.port !== port) return false;
  return !declaredReadRefusal(config.plan, ticket.need, ticket.params, limits);
}

function pumpReads() {
  while (!failed && readInFlight.size < readsInFlightMax && readQueue.length > 0) {
    const batch = [];
    for (let i = 0; i < readQueue.length && batch.length < readBatchMax; i += 1) {
      if (!readBatchEligible(readQueue[i])) break;
      batch.push(readQueue[i]);
    }
    if (batch.length >= 2) {
      for (const ticket of batch) readQueue.shift();
      const group = { tickets: batch, port, reads: batch.map((ticket) => ({ need: ticket.need, params: ticket.params })) };
      readInFlight.add(group);
      void dispatchReads(group);
      continue;
    }
    const ticket = readQueue.shift();
    if (ticket.settled) continue;
    // Consent and params again at dispatch, as the shell does.
    const refusal = declaredReadRefusal(config.plan, ticket.need, ticket.params, limits);
    if (refusal) {
      log("read-refused", { request_id: ticket.requestId, need: ticket.need, params: ticket.params, code: refusal });
      settleRead(ticket, { status: "refused", code: refusal });
      continue;
    }
    const group = { tickets: [ticket], port };
    readInFlight.add(group);
    void dispatchReads(group);
  }
}

// Release one group's slot if it still holds one, clearing any pending
// post-timeout grace; pump when this is still the live frame. Idempotent.
function releaseReadSlot(group) {
  if (group.releaseTimer) { clearTimeout(group.releaseTimer); group.releaseTimer = null; }
  if (!readInFlight.has(group)) return;
  readInFlight.delete(group);
  if (group.port === port) pumpReads();
}

async function dispatchReads(group) {
  const isBatch = group.tickets.length > 1;
  log("read-start", { requests: group.tickets.map((ticket) => ({ request_id: ticket.requestId, need: ticket.need, params: ticket.params })),
    ticket: group.tickets[0].id, batch: isBatch });
  const controller = new AbortController();
  let timedOut = false;
  const timeout = setTimeout(() => { timedOut = true; controller.abort(); }, readTimeoutMs);
  group.timer = timeout;
  const live = (ticket) => !failed && !ticket.settled && ticket.port === port;
  const settleRefusal = (ticket, code) => {
    const status = code === "unavailable" ? "unavailable" : "refused";
    log("read-error", { request_id: ticket.requestId, need: ticket.need, params: ticket.params, code });
    settleRead(ticket, { status, code });
  };
  try {
    const response = await fetch("/__host/read", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(isBatch ? { reads: group.reads } : { need: group.tickets[0].need, params: group.tickets[0].params }),
      signal: controller.signal,
    });
    const answer = await response.json();
    if (isBatch) {
      const items = Array.isArray(answer?.results) ? answer.results : null;
      if (!items || items.length !== group.tickets.length) {
        // An answer that does not describe every ticket cannot be split; the
        // whole call failed for all of them, as the shell treats a mismatch.
        for (const ticket of group.tickets) if (live(ticket)) settleRefusal(ticket, "unavailable");
        return;
      }
      for (let index = 0; index < group.tickets.length; index += 1) {
        const ticket = group.tickets[index], item = items[index];
        if (!live(ticket)) continue;
        if (item?.error) settleRefusal(ticket, String(item.error?.code ?? item.error));
        else {
          log("read-ok", { request_id: ticket.requestId, need: ticket.need, params: ticket.params, rows: item?.result?.rows?.length ?? null, truncated: item?.result?.truncated ?? null });
          settleRead(ticket, { status: "ok", need: ticket.need, result: item?.result });
        }
      }
      return;
    }
    const ticket = group.tickets[0];
    if (!live(ticket)) return;
    if (answer.error) { settleRefusal(ticket, String(answer.error)); return; }
    log("read-ok", { request_id: ticket.requestId, need: ticket.need, params: ticket.params, rows: answer.result?.rows?.length ?? null, truncated: answer.result?.truncated ?? null });
    settleRead(ticket, { status: "ok", need: ticket.need, result: answer.result });
  } catch (error) {
    if (timedOut) {
      // Retire every ticket in this call; the frame's other reads keep going.
      // This host aborts its fetch, so the slot frees in `finally` (the real
      // shell, which cannot cancel, holds the slot until its abandoned call
      // settles or a bounded grace passes).
      for (const ticket of group.tickets) if (live(ticket) && settleRead(ticket, { status: "unavailable", code: "unavailable" })) {
        log("read-error", { request_id: ticket.requestId, need: ticket.need, params: ticket.params, code: "unavailable", detail: "timeout" });
      }
      log("read-timeout", { requests: group.tickets.map((ticket) => ticket.requestId) });
      return;
    }
    for (const ticket of group.tickets) if (live(ticket)) settleRefusal(ticket, "unavailable");
  } finally {
    clearTimeout(timeout);
    if (timedOut) {
      // Mirror the shell's bounded post-timeout release: the shell cannot
      // cancel its call, so it holds the slot until the call settles or the
      // grace passes. This host aborts its fetch, which settles the call at
      // once, so `releaseReadSlot` below is the "settles first" path and
      // clears this timer; the grace is the same backstop if a fetch hangs.
      group.releaseTimer = setTimeout(() => releaseReadSlot(group), readSlotGraceMs);
    }
    releaseReadSlot(group);
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
  drainCalls(code);
  drainQueries(code);
  dropSubscriptions();
  closeSessionPorts();
  drainAgents();
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

// App contract v2 `call` (app.call.v2): answered from the Node side's canned
// or supplied result. Each accepted call is a ticket answered exactly once on
// the port it arrived on: by the host's answer, or `uncertain` when the frame
// is retired or reloaded first (drainCalls), as a read is.
const callInFlight = new Set();

function settleCall(ticket, body) {
  if (ticket.settled) return false;
  ticket.settled = true;
  callInFlight.delete(ticket);
  try { ticket.port.postMessage({ type: "call-result", version, request_id: ticket.requestId, ...body }); } catch { /* closed */ }
  return true;
}

function drainCalls(code) {
  for (const ticket of [...callInFlight]) {
    if (settleCall(ticket, { status: "uncertain", code, message: "the host closed before the call was answered" })) {
      log("call-drained", { request_id: ticket.requestId, operation: ticket.operation, code });
    }
  }
}

async function handleCall(message, receivingPort) {
  if (!config.calls || config.mode === "sample") { log("call-ignored", { operation: message.operation }); return; }
  const { request_id: requestId, operation, args } = message;
  log("call", { operation, args });
  const ticket = { requestId, operation, port: receivingPort, settled: false };
  if (!boundedId(requestId) || !boundedId(operation) || !args || typeof args !== "object" || Array.isArray(args)) {
    settleCall(ticket, { status: "refused", code: "malformed", message: "call needs an id, an operation and object args" });
    return;
  }
  callInFlight.add(ticket);
  try {
    const response = await fetch("/__host/call", { method: "POST", body: JSON.stringify({ operation, args }) });
    settleCall(ticket, await response.json());
  } catch (error) {
    settleCall(ticket, { status: "error", code: "host_unavailable", message: String(error?.message ?? error).slice(0, 200) });
  }
}

// App contract v2 `query` / `subscribe` / `unsubscribe` (app.subscribe.v2). A
// query is a ticket answered exactly once on the port it arrived on, by the
// host's answer or `error` when the frame is retired or reloaded first. A
// subscription lives until the frame unsubscribes, the host ends it with a
// terminal error, or the frame retires or reloads; its deliveries are numbered
// from 1 and strictly increasing.
const queryInFlight = new Set();
const subscriptionsOpen = new Map();

// `{sql, parameters}`, or a structured query (R4): `query_record`'s own `{steps, order?, limit?, offset?}`.
const validQuery = (query) => !!query && typeof query === "object" && !Array.isArray(query)
  && (Array.isArray(query.steps)
    ? query.steps.length > 0 && query.sql === undefined && query.parameters === undefined
    : typeof query.sql === "string" && query.sql.length > 0 && Array.isArray(query.parameters));

function settleQuery(ticket, body) {
  if (ticket.settled) return false;
  ticket.settled = true;
  queryInFlight.delete(ticket);
  try { ticket.port.postMessage({ type: "query-result", version, request_id: ticket.requestId, ...body }); } catch { /* closed */ }
  return true;
}

function drainQueries(code) {
  for (const ticket of [...queryInFlight]) {
    if (settleQuery(ticket, { status: "error", code, message: "the host closed before the query was answered" })) log("query-drained", { request_id: ticket.requestId, code });
  }
}

function dropSubscriptions() {
  for (const [id] of [...subscriptionsOpen]) {
    subscriptionsOpen.delete(id);
    log("subscription-closed", { subscription_id: id, by: "host" });
  }
}

async function askQuery(query) {
  try {
    return await (await fetch("/__host/query", { method: "POST", body: JSON.stringify({ query }) })).json();
  } catch (error) {
    return { status: "error", code: "host_unavailable", message: String(error?.message ?? error).slice(0, 200) };
  }
}

async function handleQuery(message, receivingPort) {
  if (!config.queries || config.mode === "sample") { log("query-ignored", { request_id: message.request_id }); return; }
  const { request_id: requestId, query } = message;
  log("query", { request_id: requestId, query });
  const ticket = { requestId, port: receivingPort, settled: false };
  if (!boundedId(requestId) || !validQuery(query)) {
    settleQuery(ticket, { status: "refused", code: "malformed", message: "query needs an id and either a sql string with a parameters array or a steps array" });
    return;
  }
  queryInFlight.add(ticket);
  const answer = await askQuery(query);
  settleQuery(ticket, answer.status === "ok" ? { status: "ok", result: answer.result } : { status: answer.status, code: answer.code, message: answer.message });
}

function postSubscription(subscription, body) {
  if (subscriptionsOpen.get(subscription.id) !== subscription) return false;
  try { subscription.port.postMessage({ version, subscription_id: subscription.id, ...body }); } catch { return false; }
  return true;
}

function deliverSubscription(subscription, answer, options = {}) {
  if (answer.status === "ok") {
    subscription.delivery = options.delivery ?? subscription.delivery + 1;
    postSubscription(subscription, { type: "subscription-result", delivery: subscription.delivery, result: answer.result, cached: options.cached === true });
    return;
  }
  const terminal = answer.terminal === true || answer.status === "refused";
  if (postSubscription(subscription, { type: "subscription-error", code: answer.code, message: answer.message, terminal }) && terminal) subscriptionsOpen.delete(subscription.id);
}

async function handleSubscribe(message, receivingPort) {
  if (!config.queries || config.mode === "sample") { log("subscribe-ignored", { subscription_id: message.subscription_id }); return; }
  const { subscription_id: id, query } = message;
  log("subscribe", { subscription_id: id, query });
  if (!boundedId(id) || !validQuery(query) || subscriptionsOpen.has(id)) {
    try { receivingPort.postMessage({ type: "subscription-error", version, subscription_id: id, code: "malformed", message: "subscribe needs a fresh id and either a sql string with a parameters array or a steps array", terminal: true }); } catch { /* closed */ }
    return;
  }
  const subscription = { id, query, port: receivingPort, delivery: 0 };
  subscriptionsOpen.set(id, subscription);
  deliverSubscription(subscription, await askQuery(query));
}

function handleUnsubscribe(message) {
  if (subscriptionsOpen.delete(message.subscription_id)) log("unsubscribe", { subscription_id: message.subscription_id });
  else log("unsubscribe-ignored", { subscription_id: message.subscription_id });
}

// App contract v2 `session-open` (app.session.v2). Each accepted open gets its
// own MessageChannel: port2 is transferred with `session-opened`, port1 echoes
// every frame back unchanged. The host closes its end when the frame retires or
// reloads. It learns the frame closed its end from the in-band
// `{type:"session-close"}` the frame posts first: Chromium does not fire
// `close` on a MessagePort.
const sessionPorts = new Map();

function closeSessionPorts() {
  for (const [requestId, sessionPort] of [...sessionPorts]) {
    sessionPorts.delete(requestId);
    try { sessionPort.close(); } catch { /* closed */ }
    log("session-closed", { request_id: requestId, by: "host" });
  }
}

async function handleSessionOpen(message, receivingPort) {
  if (!config.sessions || config.mode === "sample") { log("session-ignored", { record_id: message.record_id }); return; }
  const { request_id: requestId, record_id: recordId, mode } = message;
  log("session-open", { request_id: requestId, record_id: recordId, mode });
  const refuse = (code, text) => {
    log("session-refused", { request_id: requestId, code });
    if (receivingPort === port) receivingPort.postMessage({ type: "session-refused", version, request_id: requestId, code, message: text });
  };
  if (!boundedId(requestId) || !boundedId(recordId) || (mode !== "edit" && mode !== "view")) { refuse("malformed", "session-open needs an id, a record id and a mode"); return; }
  let answer;
  try {
    answer = await (await fetch("/__host/session", { method: "POST", body: JSON.stringify({ recordId, mode }) })).json();
  } catch (error) {
    answer = { status: "refused", code: "host_unavailable", message: String(error?.message ?? error).slice(0, 200) };
  }
  if (answer.status !== "ok") { refuse(answer.code ?? "refused", answer.message ?? ""); return; }
  if (failed || receivingPort !== port) return;
  const channel = new MessageChannel();
  const sessionPort = channel.port1;
  sessionPorts.set(requestId, sessionPort);
  sessionPort.onmessage = (frameEvent) => {
    if (frameEvent.data?.type === "session-close") {
      // The frame's in-band goodbye, sent before it closes its end.
      if (sessionPorts.delete(requestId)) log("session-closed", { request_id: requestId, by: "frame" });
      sessionPort.close();
      return;
    }
    log("session-frame", { request_id: requestId, frame: frameEvent.data });
    sessionPort.postMessage(frameEvent.data);
  };
  sessionPort.start();
  receivingPort.postMessage({ type: "session-opened", version, request_id: requestId }, [channel.port2]);
}

// App contract v2 `agents-list` / `agents-ask` (app.agents.v2). Each ask is a
// ticket answered exactly once on the port it arrived on: by the Node side's
// answer, or `unavailable` when the frame is retired or reloaded first. A frame
// hears `agents-status` only for the `ask_id`s its asks were answered with, and
// none after it reloads or retires (the alpha host scopes statuses the same way).
const AGENTS_MAX_IN_FLIGHT = 4;
const askInFlight = new Set();
const listInFlight = new Set();
let askIds = new Set();

function settleAsk(ticket, result) {
  if (ticket.settled) return false;
  ticket.settled = true;
  askInFlight.delete(ticket);
  log("agents-ask-result", { request_id: ticket.requestId, result });
  try { ticket.port.postMessage({ type: "agents-ask-result", version, request_id: ticket.requestId, result }); } catch { /* closed */ }
  return true;
}

function settleList(ticket, agents) {
  if (ticket.settled) return;
  ticket.settled = true;
  listInFlight.delete(ticket);
  try { ticket.port.postMessage({ type: "agents-list-result", version, request_id: ticket.requestId, agents }); } catch { /* closed */ }
}

function drainAgents() {
  // Every list is answered once too: `[]` when the frame goes first.
  for (const ticket of [...listInFlight]) settleList(ticket, []);
  for (const ticket of [...askInFlight]) {
    settleAsk(ticket, { ok: false, code: "unavailable", message: "The app was closed before the ask was answered; the agent may already have started." });
  }
  askIds = new Set();
}

async function askAgentsHost(body) {
  try {
    return await (await fetch("/__host/agents", { method: "POST", body: JSON.stringify(body) })).json();
  } catch {
    return null;
  }
}

async function handleAgentsList(message, receivingPort) {
  if (!config.agents || config.mode === "sample") { log("agents-ignored", { type: message.type }); return; }
  log("agents-list", { request_id: message.request_id });
  const ticket = { requestId: message.request_id, port: receivingPort, settled: false };
  listInFlight.add(ticket);
  const answer = await askAgentsHost({ action: "list" });
  settleList(ticket, Array.isArray(answer?.agents) ? answer.agents : []);
}

async function handleAgentsAsk(message, receivingPort) {
  if (!config.agents || config.mode === "sample") { log("agents-ignored", { type: message.type }); return; }
  const { request_id: requestId, to, comment_id: commentId } = message;
  log("agents-ask", { request_id: requestId, to, comment_id: commentId });
  const ticket = { requestId, port: receivingPort, settled: false };
  if (!boundedId(requestId) || !boundedId(to) || !boundedId(commentId)) {
    settleAsk(ticket, { ok: false, code: "invalid", message: "agents-ask needs a request id, an agent id and a comment id." });
    return;
  }
  if (askInFlight.size >= AGENTS_MAX_IN_FLIGHT) {
    settleAsk(ticket, { ok: false, code: "busy", message: `At most ${AGENTS_MAX_IN_FLIGHT} asks may be in flight.` });
    return;
  }
  askInFlight.add(ticket);
  const started = askIds;
  const answer = await askAgentsHost({ action: "ask", ask: { to, comment_id: commentId } });
  const result = answer?.result ?? { ok: false, code: "unavailable", message: "The host did not answer." };
  if (result.ok === true && typeof result.ask_id === "string" && !ticket.settled) started.add(result.ask_id);
  settleAsk(ticket, result);
}

// Floating-chat presentation (task e27b79d, scoped test support only).
// Offers app.presentation.v1 when config.presentation is set; answers the
// frame's exact presentation envelope with presentation-result. Modes:
// "accept"/true answers accepted true, "refuse" answers accepted false,
// "reject" answers host error (status error; bridge resolves false, never
// a Promise rejection or sync throw). Without the option the feature is absent.
function handlePresentation(message, receivingPort) {
  if (!config.presentation || config.mode === "sample") { log("presentation-ignored", { type: message.type }); return; }
  const { request_id: requestId, presentation_version: feature, suppress } = message;
  const valid = boundedId(requestId) && feature === "app.presentation.v1" && typeof suppress === "boolean";
  const mode = config.presentation === true ? "accept" : config.presentation;
  let accepted = false;
  let status = "ok";
  if (valid && mode === "accept") accepted = true;
  else if (!valid) accepted = false;
  else if (mode === "refuse") accepted = false;
  else if (mode === "reject") { status = "error"; accepted = false; }
  log("presentation", { request_id: requestId, suppress, accepted, status });
  try {
    if (status === "ok") receivingPort.postMessage({ type: "presentation-result", version, request_id: requestId, status: "ok", accepted });
    else receivingPort.postMessage({ type: "presentation-result", version, request_id: requestId, status: "error", code: "rejected", accepted: false });
  } catch { /* closed */ }
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
    case "call":
      handleCall(message, receivingPort);
      break;
    case "session-open":
      handleSessionOpen(message, receivingPort);
      break;
    case "query":
      handleQuery(message, receivingPort);
      break;
    case "subscribe":
      handleSubscribe(message, receivingPort);
      break;
    case "unsubscribe":
      handleUnsubscribe(message);
      break;
    case "agents-list":
      handleAgentsList(message, receivingPort);
      break;
    case "agents-ask":
      handleAgentsAsk(message, receivingPort);
      break;
    case "presentation":
      handlePresentation(message, receivingPort);
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
    drainCalls("tab_reloaded");
    drainQueries("tab_reloaded");
    dropSubscriptions();
    closeSessionPorts();
    drainAgents();
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
  const features = [...(config.writes ? ["intent-arm-confirm.v1"] : []), ...(config.calls ? ["app.call.v2"] : []), ...(config.sessions ? ["app.session.v2"] : []), ...(config.queries && config.mode !== "sample" ? ["app.subscribe.v2"] : []), ...(config.agents && config.mode !== "sample" ? ["app.agents.v2"] : []), ...(config.presentation && config.mode !== "sample" ? ["app.presentation.v1"] : [])];
  if (features.length) init.host_features = features;
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
  // Test-only: post a raw message on the main port, transferring `ports` fresh ports,
  // to exercise how the frame treats a host that misbehaves.
  sendRaw(message, ports = 0) {
    const transfer = Array.from({ length: ports }, () => new MessageChannel().port2);
    port?.postMessage({ version, ...message }, transfer);
  },
  // Test-only: send a frame to the frame on one open session's port, as the broker bridge would
  // (a terminal `session.closed`, a `session.refused`, a plain server frame).
  sessionPost(requestId, frame) {
    const sessionPort = sessionPorts.get(requestId);
    if (!sessionPort) throw Error(`no open session ${requestId}`);
    sessionPort.postMessage(frame);
  },
  // Test-only: the open subscription ids, in subscribe order.
  subscriptions: () => [...subscriptionsOpen.keys()],
  // Test-only: push a delivery on one open subscription. With no `result` the host re-runs its
  // handler (so a handler that changes its answer pushes the change); `options.delivery` forces
  // the number (to replay a stale one) and `options.cached` sets the flag.
  async pushSubscription(id, result, options = {}) {
    const subscription = subscriptionsOpen.get(id);
    if (!subscription) throw Error(`no open subscription ${id}`);
    deliverSubscription(subscription, result === undefined ? await askQuery(subscription.query) : { status: "ok", result }, options);
  },
  // Test-only: a subscription-error on one open subscription; terminal ends it.
  failSubscription(id, code, message, terminal = true) {
    const subscription = subscriptionsOpen.get(id);
    if (!subscription) throw Error(`no open subscription ${id}`);
    postSubscription(subscription, { type: "subscription-error", code, message, terminal });
    if (terminal) subscriptionsOpen.delete(id);
  },
  // Test-only: push an AskStatus as the shell relay would. It reaches the frame only when the
  // current frame's ask was answered with `status.ask_id`; returns whether it was posted.
  pushAgentStatus(status) {
    if (failed || !port || !askIds.has(status?.ask_id)) {
      log("agents-status-dropped", { ask_id: status?.ask_id ?? null });
      return false;
    }
    port.postMessage({ type: "agents-status", version, status });
    log("agents-status", { status });
    return true;
  },
  async reload() {
    const response = await fetch('/__host/frame-session', {method: 'POST'});
    if (!response.ok) throw new Error('fake host could not prepare a new session');
    const session = await response.json();
    config.init = session.init;
    log('kit-session', {kit_release: session.kit_release});
    iframe.src = session.url;
  },
});
