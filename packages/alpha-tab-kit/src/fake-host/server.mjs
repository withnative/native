// A zero-dependency local host for one alpha-tab package: the shell page
// (shell.js), the tab document with the real bridge injected exactly as
// `native_artifact_html::html::inject` does (html.rs:1897), served under the
// real CSP, and a read endpoint answered from package-supplied fixtures.
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { LIMITS } from "../limits.mjs";
import { parseDeclaration, splitNeeds, isAppV2Declaration } from "../declaration.mjs";
import { bootstrapInsertionOffset, requireAvailableKit, descriptorKitPolicyFindings } from "../html.mjs";
import { DEFAULT_KIT_DELIVERY, assertKitDelivery } from "./kit-assets.mjs";
import { hostNeedRefusal, shapeSqlResult } from "./rules.mjs";

// Same bound as artifact-html kit_delivery::ORIGIN_MAX: full DNS + scheme/port.
const ORIGIN_MAX = 512;
const ORIGIN_JSON_MAX = ORIGIN_MAX * 6 + 2;
const here = new URL("./", import.meta.url);
const BOOTSTRAP = readFileSync(new URL("bridge-bootstrap.js", here), "utf8");
const SHELL = readFileSync(new URL("shell.js", here), "utf8");
const RULES = readFileSync(new URL("rules.mjs", here), "utf8");
const BOOTSTRAP_SHA256 = createHash("sha256").update(BOOTSTRAP).digest("hex");
if (BOOTSTRAP_SHA256 !== LIMITS.bridge.bootstrap_sha256) {
  throw new Error(`vendored bridge bootstrap ${BOOTSTRAP_SHA256} does not match limits.json ${LIMITS.bridge.bootstrap_sha256}`);
}
// crates/artifact-html/src/html.rs:76 PERMISSIONS_POLICY
const PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), display-capture=(), payment=(), usb=(), serial=(), hid=(), bluetooth=(), midi=(), clipboard-read=(), clipboard-write=(), web-share=(), local-fonts=(), idle-detection=(), screen-wake-lock=(), gamepad=(), accelerometer=(), gyroscope=(), magnetometer=(), ambient-light-sensor=(), publickey-credentials-get=(), screen-orientation=(), pointer-lock=(), presentation=(), fullscreen=()";

/** Insert the bridge the way the host does; throws on a bad preamble. */
export function injectBridge(html, hostOrigin, delivery = DEFAULT_KIT_DELIVERY) {
  return prepareFrame(html, hostOrigin, delivery).html;
}
function prepareFrame(html, hostOrigin, delivery) {
  return composeFrame(html, hostOrigin, requireAvailableKit(html, assertKitDelivery(delivery)));
}
function composeFrame(html, hostOrigin, resolved) {
  const { offset, error } = bootstrapInsertionOffset(html);
  if (error) throw new Error(`${error.message} [${error.rule}]`);
  if (typeof hostOrigin !== 'string' || Buffer.byteLength(hostOrigin) > ORIGIN_MAX) throw new Error('host origin bounds exceeded');
  const origin = new URL(hostOrigin);
  if (!['http:', 'https:'].includes(origin.protocol) || origin.origin !== hostOrigin) throw new Error('invalid host origin');
  const replacements = {__NATIVE_WORKBENCH_ORIGIN__: JSON.stringify(hostOrigin), __NATIVE_KIT_FACTORY__: resolved?.js ?? 'null', __NATIVE_KIT_RELEASE__: JSON.stringify(resolved?.release ?? null)};
  const bootstrap = BOOTSTRAP.replace(/__NATIVE_(?:WORKBENCH_ORIGIN|KIT_FACTORY|KIT_RELEASE)__/g, token => replacements[token]);
  const bytes = Buffer.byteLength(html) + Buffer.byteLength(bootstrap) + 17;
  const overhead = Buffer.byteLength(BOOTSTRAP) + 65536 + 1024 + ORIGIN_JSON_MAX + 17;
  if (Buffer.byteLength(html) > 1048576 || bytes > 1048576 + overhead) throw new Error('delivered bounds exceeded');
  return Object.freeze({html: `${html.slice(0, offset)}<script>${bootstrap}</script>${html.slice(offset)}`, kit_release: resolved?.release ?? null});
}

const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * @param {object} options
 * @param {object} options.descriptor  package descriptor ({package, version, declaration, ...})
 * @param {string} options.html        exact bundle bytes
 * @param {object} [options.fixtures]  { sql: {key: rows | (params, ctx) => rows}, records, search, resolve, scene, changes }
 * @param {"live"|"sample"} [options.mode]
 * @param {number|((need, params) => number)} [options.latencyMs]  per-read backend latency (default 40)
 * @param {boolean} [options.holdViewState]  re-deliver the latest view state on reload (Workbench host)
 * @param {number} [options.readTimeoutMs]  host read timeout (default limits.shell.read_timeout_ms)
 * @param {(intent: object, ctx: object) => object | Promise<object>} [options.intents]
 *   Turns writes on: the host advertises `intent-arm-confirm.v1`, answers an arm
 *   (or a propose) by calling this with the intent `{request_id, entry_id, slots, values}`
 *   and returns its result (`{status: "committed" | "cancelled" | "rejected" | "conflict" |
 *   "uncertain" | ...}`) as the host's terminal answer. Without it every write is refused
 *   `unsupported_host`, as before. Call `ctx.bump()` inside a handler to make the next
 *   `pushInput` a new generation. Writes are logged as `intent` / `intent-arm` events.
 * @param {boolean | ((operation: string, args: object, ctx: object) => unknown)} [options.calls]
 *   Offers `app.call.v2` (app contract v2): the frame gets `nativeArtifact.call` and
 *   `window.native.call`. `true` answers every call `ok` with a canned result
 *   `{canned: true, operation, args}`; a function supplies the result. A throw answers
 *   `error` (code `handler_error`), unless the thrown error carries a `status` of `refused`,
 *   `uncertain` or `error` (and optionally a `code`), which answers with that status and code.
 *   The real appHost classifies a failure by its HTTP status: 4xx `refused`, 408/502/504 and a lost
 *   connection `uncertain`, other 5xx `error` (which can follow a committed write), and `error` with
 *   code `tool_not_dispatched` or `effect_not_dispatched` only when nothing was sent. A handler that
 *   wants to behave like that says so explicitly; a plain throw is not one of them.
 *   Without it the feature is not offered and neither exists. Logged as `call`.
 * @param {boolean | ((open: {recordId: string, mode: string}, ctx: object) => unknown)} [options.sessions]
 *   Offers `app.session.v2` (live co-editing): the frame gets `native.session.open`. The host
 *   answers `session-open` with `session-opened` and a transferred MessagePort that echoes every
 *   frame back unchanged. `true` accepts every open; a function may return `{code, message}` to
 *   answer `session-refused` instead (a throw refuses `host_error`). Without it the feature is
 *   not offered. Logged as `session-open`, `session-refused`, `session-frame`, `session-closed` (`by` "frame" once the frame posts `session-close`, "host" when the host ends it).
 * @param {boolean | ((query: {sql: string, parameters: unknown[]} | {steps: unknown[], order?: string, limit?: number, offset?: number}, ctx: object) => {rows: unknown[], columns: unknown[], truncated?: boolean} | Promise<object>)} [options.queries]
 *   Offers `app.subscribe.v2` (app contract v2, instant reads): the frame gets `native.query` and
 *   `native.subscribe`. The host answers `query` with `query-result` and `subscribe` with a first
 *   `subscription-result` (delivery 1, `cached` false), then pushes more when the test calls
 *   `tab.pushSubscription(id)` (re-runs the handler) or `tab.pushSubscription(id, result)`.
 *   `true` answers every query with `{columns: ["sql", "parameters"], rows: [[sql, parameters]],
 *   truncated: false}` (a structured `{steps}` query: `{columns: ["steps"], rows: [[steps]]}`);
 *   a function supplies the result. A throw answers `error` (code
 *   `handler_error`) for a query, or `subscription-error` for a subscribe, unless the thrown error
 *   carries a `status` of `refused` and/or a `code`; `terminal: true` on it ends the subscription.
 *   Without it the feature is not offered and neither method exists. Logged as `query`, `subscribe`,
 *   `unsubscribe`, `subscription-closed` (the host dropped it because the frame went away).
 * @param {boolean | {list?: (ctx: object) => unknown, ask?: (ask: {to: string, comment_id: string}, ctx: object) => unknown}} [options.agents]
 *   Offers `app.agents.v2` (ask an agent, Shapes bf7cfa5): the frame gets `native.agents`. The
 *   host answers `agents-list` with the handler's AgentSummary[] (`true`: one ready Claude) and
 *   `agents-ask` with its AskResult (`true`: `{ok: true, ask_id: "fake-ask-<comment_id>"}`), at
 *   most 4 asks in flight per frame (a fifth is answered `busy`). It does none of the real host's
 *   checks (activation, own recent comment): that is the alpha host's job, proved by
 *   `experiments/demo-shell/check-app-agents-headless.mjs`. `tab.pushAgentStatus(status)` posts
 *   `agents-status` only when the current frame's ask was answered with `status.ask_id`, as the real host
 *   scopes them. Not offered in sample mode. Logged as `agents-list`, `agents-ask`,
 *   `agents-ask-result`, `agents-status` and `agents-status-dropped`.
 * @param {boolean | "refuse" | "reject"} [options.presentation]
 *   Offers `app.presentation.v1` (task e27b79d): the frame gets
 *   `native.presentation.setFloatingChat`. `true` answers accepted true;
 *   `"refuse"` answers accepted false; `"reject"` answers host error
 *   (status error, bridge resolves false, not a Promise rejection).
 *   Without it the feature is not offered. Logged as `presentation`.
 *   Scoped test support only.
 * @param {number} [options.port]  default: an ephemeral port on 127.0.0.1
 */
export async function startFakeHost(options) {
  const { descriptor, html, fixtures = {}, mode = "live", holdViewState = false } = options;
  const kitFindings = descriptorKitPolicyFindings(descriptor, html);
  if (kitFindings.length) throw new Error(`${kitFindings[0].message} [${kitFindings[0].rule}]`);
  let kitDelivery = assertKitDelivery(options.kitDelivery ?? DEFAULT_KIT_DELIVERY);
  const initialKit = requireAvailableKit(html, kitDelivery);
  const latency = options.latencyMs ?? 40;
  const parsed = parseDeclaration(descriptor.declaration);
  if (parsed.findings.some((item) => item.severity === "error")) {
    throw new Error(`declaration is invalid: ${parsed.findings.map((item) => item.message).join("; ")}`);
  }
  const appV2 = isAppV2Declaration(descriptor.declaration);
  const split = splitNeeds(parsed);
  const plan = {
    onRequestHost: split.onRequestHost,
    onRequestSql: split.onRequestSql.map((need) => ({ key: need.key, params: need.params })),
  };
  const offered = [...split.onRequestHost, ...split.onRequestSql.map((need) => need.key)];
  const attention = parsed.needs.includes("attention.query.v1");
  const events = [];
  const ctx = { generation: 0, events };

  async function resolveFixture(value, params) {
    return typeof value === "function" ? await value(params ?? {}, ctx) : value;
  }

  async function liveInput() {
    const records = attention ? (await resolveFixture(fixtures.records, {})) ?? [] : [];
    const input = {
      version: "native.artifact-input.v1",
      mode: "live",
      sample_preview: false,
      records,
      records_sha256: sha256(JSON.stringify(records)),
      inputs: {},
    };
    if (split.snapshot.length) {
      input.sql = {};
      for (const need of split.snapshot) {
        const rows = await resolveFixture(fixtures.sql?.[need.key], {});
        if (rows === undefined) throw new Error(`fixtures.sql['${need.key}'] is missing: a snapshot need must have rows`);
        input.sql[need.key] = shapeSqlResult(need.label, rows, LIMITS);
      }
    }
    return { input, input_digest: sha256(JSON.stringify(input)) };
  }

  async function initFor() {
    if (mode === "sample") {
      const input = LIMITS.sample_input;
      return { input, input_digest: sha256(JSON.stringify(input)) };
    }
    if (split.snapshot.length || attention) return { ...(await liveInput()), needs: offered };
    // On-request only: no rows at open (pending.js:2745).
    return { input: { version: "native.artifact-input.v1", mode: "live", sample_preview: false, records: [], inputs: {} }, needs: offered };
  }

  async function answerNeed(need, params) {
    const wait = typeof latency === "function" ? latency(need, params) : latency;
    if (wait > 0) await delay(wait);
    try {
      if (plan.onRequestHost.includes(need)) {
        const refusal = hostNeedRefusal(need, params, LIMITS);
        if (refusal) return { error: refusal };
        const fixture = {
          "records.search.v1": fixtures.search,
          "records.resolve_reference.v1": fixtures.resolve,
          "canvas.scene.v1": fixtures.scene,
          "records.changes.v1": fixtures.changes,
          "artifact.render.v1": fixtures.render,
          "records.body.current.v1": fixtures.bodyCurrent,
        }[need];
        if (fixture === undefined) return { error: "unavailable" };
        return { result: await resolveFixture(fixture, params) };
      }
      const sqlNeed = split.onRequestSql.find((candidate) => candidate.key === need);
      if (!sqlNeed) return { error: "undeclared_need" };
      const rows = await resolveFixture(fixtures.sql?.[need], params);
      if (rows === undefined) return { error: "sql_need_failed" };
      if (rows && !Array.isArray(rows) && rows.error) return { error: rows.error };
      return { result: shapeSqlResult(sqlNeed.label, rows, LIMITS) };
    } catch (error) {
      const code = /\[([a-z_]+)\]/.exec(String(error?.message ?? ""))?.[1] ?? "sql_need_failed";
      return { error: code };
    }
  }

  // One read (`{need, params}`) or several coalesced into one call
  // (`{reads:[...]}`), matching the shell's batched `live_read`. A batch
  // answers `{results:[{need, result}|{need, error:{code,message}}]}` in
  // request order, the engine's per-item error shape.
  async function answerRead(body) {
    if (Array.isArray(body?.reads)) {
      const results = await Promise.all(body.reads.map(async (item) => {
        const answer = await answerNeed(item.need, item.params);
        return answer.error
          ? { need: item.need, error: { code: answer.error, message: `manage_alpha_tabs: live read refused [${answer.error}]` } }
          : { need: item.need, result: answer.result };
      }));
      return { results };
    }
    return answerNeed(body?.need, body?.params);
  }

  const readBody = (request) => new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });

  let hostOrigin = null;
  let preparedFrame = null;
  const sessions = new Map();
  let sessionSeq = 0;
  const retainSession = frame => {
    if (sessions.size >= 32) throw new Error("fake session inventory full");
    sessionSeq += 1; sessions.set(String(sessionSeq), frame);
    return Object.freeze({url: `/frame?session=${sessionSeq}`, kit_release: frame.kit_release});
  };
  let initialSession;
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, hostOrigin);
    const send = (status, type, body, headers = {}) => {
      response.writeHead(status, { "content-type": type, "cache-control": "no-store", ...headers });
      response.end(body);
    };
    try {
      if (url.pathname === "/") {
        const presentation = options.presentation === true ? "accept" : typeof options.presentation === "string" ? options.presentation : undefined;
        const config = { mode, writes: typeof options.intents === "function", calls: appV2 && (options.calls === true || typeof options.calls === "function"), sessions: appV2 && (options.sessions === true || typeof options.sessions === "function"), queries: appV2 && (options.queries === true || typeof options.queries === "function"), agents: appV2 && !!options.agents, presentation: appV2 ? presentation : undefined, title: `${descriptor.package} ${descriptor.version}`, plan, init: await initFor(), holdViewState, limits: LIMITS, readTimeoutMs: options.readTimeoutMs, kitRelease: preparedFrame.kit_release, frameUrl: initialSession.url };
        return send(200, "text/html; charset=utf-8", `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>alpha-tab-kit fake host — ${descriptor.package}</title><style>html,body{margin:0;height:100%}body{display:flex;flex-direction:column;font:12px system-ui}#holder{flex:1;display:flex}#holder iframe{flex:1;border:0}#host-log{padding:2px 8px;background:#eee}</style></head><body><div id="host-log">fake host (${mode})</div><div id="holder"></div><script>window.__ALPHA_TAB_HOST_CONFIG__=${JSON.stringify(config).replace(/</g, "\\u003c")};</script><script type="module" src="/__kit/shell.js"></script></body></html>`);
      }
      if (url.pathname === "/__host/frame-session" && request.method === "POST") {
        const init = await initFor();
        const session = retainSession(prepareFrame(html, hostOrigin, kitDelivery));
        return send(200, "application/json", JSON.stringify({...session, init}));
      }
      if (url.pathname === "/frame") {
        const frame = sessions.get(url.searchParams.get("session") ?? String(1));
        if (!frame) return send(404, "text/plain", "session unavailable");
        return send(200, "text/html; charset=utf-8", frame.html, {
          "content-security-policy": LIMITS.bridge.csp.replace("{origin}", hostOrigin),
          "permissions-policy": PERMISSIONS_POLICY,
          "referrer-policy": "no-referrer",
          "x-content-type-options": "nosniff",
        });
      }
      if (url.pathname === "/__kit/shell.js") return send(200, "text/javascript", SHELL);
      if (url.pathname === "/__kit/rules.mjs") return send(200, "text/javascript", RULES);
      if (url.pathname === "/__host/read" && request.method === "POST") {
        const body = JSON.parse(await readBody(request));
        return send(200, "application/json", JSON.stringify(await answerRead(body)));
      }
      if (url.pathname === "/__host/intent" && request.method === "POST") {
        const intent = JSON.parse(await readBody(request));
        if (typeof options.intents !== "function") return send(200, "application/json", JSON.stringify({ status: "rejected", code: "unsupported_host" }));
        if (latency > 0) await delay(typeof latency === "function" ? latency("intent", intent) : latency);
        const result = await options.intents(intent, ctx);
        return send(200, "application/json", JSON.stringify(result ?? { status: "rejected", code: "no_answer" }));
      }
      if (url.pathname === "/__host/call" && request.method === "POST") {
        const { operation, args } = JSON.parse(await readBody(request));
        if (!appV2 || !options.calls) return send(200, "application/json", JSON.stringify({ status: "refused", code: "unsupported_host" }));
        if (latency > 0) await delay(typeof latency === "function" ? latency("call", { operation, args }) : latency);
        try {
          const result = typeof options.calls === "function" ? await options.calls(operation, args, ctx) : { canned: true, operation, args };
          return send(200, "application/json", JSON.stringify({ status: "ok", result: result ?? null }));
        } catch (error) {
          const status = error?.status === "refused" || error?.status === "uncertain" ? error.status : "error";
          const code = typeof error?.code === "string" ? error.code : status === "error" ? "handler_error" : status;
          return send(200, "application/json", JSON.stringify({ status, code, message: String(error?.message ?? error).slice(0, 200) }));
        }
      }
      if (url.pathname === "/__host/query" && request.method === "POST") {
        const { query } = JSON.parse(await readBody(request));
        if (!appV2 || !options.queries) return send(200, "application/json", JSON.stringify({ status: "refused", code: "unsupported_host" }));
        if (latency > 0) await delay(typeof latency === "function" ? latency("query", query) : latency);
        try {
          const result = typeof options.queries === "function" ? await options.queries(query, ctx)
            : Array.isArray(query.steps) ? { columns: ["steps"], rows: [[query.steps]], truncated: false }
            : { columns: ["sql", "parameters"], rows: [[query.sql, query.parameters]], truncated: false };
          return send(200, "application/json", JSON.stringify({ status: "ok", result }));
        } catch (error) {
          const status = error?.status === "refused" ? "refused" : "error";
          const code = typeof error?.code === "string" ? error.code : status === "error" ? "handler_error" : status;
          return send(200, "application/json", JSON.stringify({ status, code, message: String(error?.message ?? error).slice(0, 200), terminal: error?.terminal === true }));
        }
      }
      if (url.pathname === "/__host/agents" && request.method === "POST") {
        const { action, ask } = JSON.parse(await readBody(request));
        const handlers = typeof options.agents === "object" && options.agents ? options.agents : {};
        if (!appV2 || !options.agents) return send(200, "application/json", JSON.stringify(action === "list" ? { agents: [] } : { result: { ok: false, code: "unavailable", message: "this host offers no agents" } }));
        if (latency > 0) await delay(typeof latency === "function" ? latency(`agents-${action}`, ask ?? {}) : latency);
        try {
          if (action === "list") {
            const agents = handlers.list ? await handlers.list(ctx) : [{ id: "claude", label: "Claude", ready: true }];
            return send(200, "application/json", JSON.stringify({ agents: agents ?? [] }));
          }
          const result = handlers.ask ? await handlers.ask(ask, ctx) : { ok: true, ask_id: `fake-ask-${ask.comment_id}` };
          return send(200, "application/json", JSON.stringify({ result: result ?? { ok: false, code: "unavailable", message: "no answer" } }));
        } catch (error) {
          return send(200, "application/json", JSON.stringify(action === "list" ? { agents: [] } : { result: { ok: false, code: "unavailable", message: String(error?.message ?? error).slice(0, 200) } }));
        }
      }
      if (url.pathname === "/__host/session" && request.method === "POST") {
        const { recordId, mode } = JSON.parse(await readBody(request));
        if (!appV2 || !options.sessions) return send(200, "application/json", JSON.stringify({ status: "refused", code: "unsupported_host", message: "this host offers no sessions" }));
        if (latency > 0) await delay(typeof latency === "function" ? latency("session", { recordId, mode }) : latency);
        try {
          const refusal = typeof options.sessions === "function" ? await options.sessions({ recordId, mode }, ctx) : null;
          if (refusal) return send(200, "application/json", JSON.stringify({ status: "refused", code: String(refusal.code ?? "refused"), message: String(refusal.message ?? "") }));
          return send(200, "application/json", JSON.stringify({ status: "ok" }));
        } catch (error) {
          return send(200, "application/json", JSON.stringify({ status: "refused", code: "host_error", message: String(error?.message ?? error).slice(0, 200) }));
        }
      }
      if (url.pathname === "/__host/snapshot" && request.method === "POST") {
        ctx.generation += 1;
        return send(200, "application/json", JSON.stringify(await liveInput()));
      }
      if (url.pathname === "/__host/event" && request.method === "POST") {
        const event = JSON.parse(await readBody(request));
        events.push(event);
        options.onEvent?.(event);
        return send(204, "text/plain", "");
      }
      return send(404, "text/plain", "not found");
    } catch (error) {
      return send(500, "text/plain", String(error?.stack ?? error));
    }
  });
  await new Promise((resolve) => server.listen(options.port ?? 0, "127.0.0.1", resolve));
  hostOrigin = `http://127.0.0.1:${server.address().port}`;
  try { preparedFrame = composeFrame(html, hostOrigin, initialKit); initialSession = retainSession(preparedFrame); }
  catch (error) { await new Promise(resolve => server.close(resolve)); throw error; }
  return {
    url: `${hostOrigin}/`,
    origin: hostOrigin,
    events,
    plan,
    kit_release: preparedFrame.kit_release,
    // Node host configuration only. Existing session URLs and frames remain pinned.
    selectKitDeliveryForNextSession(delivery) { kitDelivery = assertKitDelivery(delivery); },
    close: () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }),
  };
}
