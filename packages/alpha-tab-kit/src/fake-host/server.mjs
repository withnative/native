// A zero-dependency local host for one alpha-tab package: the shell page
// (shell.js), the tab document with the real bridge injected exactly as
// `native_artifact_html::html::inject` does (html.rs:1897), served under the
// real CSP, and a read endpoint answered from package-supplied fixtures.
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { LIMITS } from "../limits.mjs";
import { parseDeclaration, splitNeeds } from "../declaration.mjs";
import { bootstrapInsertionOffset } from "../html.mjs";
import { hostNeedRefusal, shapeSqlResult } from "./rules.mjs";

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
export function injectBridge(html, hostOrigin) {
  const { offset, error } = bootstrapInsertionOffset(html);
  if (error) throw new Error(`${error.message} [${error.rule}]`);
  const bootstrap = BOOTSTRAP.replace("__NATIVE_WORKBENCH_ORIGIN__", JSON.stringify(hostOrigin));
  return `${html.slice(0, offset)}<script>${bootstrap}</script>${html.slice(offset)}`;
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
 * @param {number} [options.port]  default: an ephemeral port on 127.0.0.1
 */
export async function startFakeHost(options) {
  const { descriptor, html, fixtures = {}, mode = "live", holdViewState = false } = options;
  const latency = options.latencyMs ?? 40;
  const parsed = parseDeclaration(descriptor.declaration);
  if (parsed.findings.some((item) => item.severity === "error")) {
    throw new Error(`declaration is invalid: ${parsed.findings.map((item) => item.message).join("; ")}`);
  }
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

  async function answerRead({ need, params }) {
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

  const readBody = (request) => new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });

  let hostOrigin = null;
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, hostOrigin);
    const send = (status, type, body, headers = {}) => {
      response.writeHead(status, { "content-type": type, "cache-control": "no-store", ...headers });
      response.end(body);
    };
    try {
      if (url.pathname === "/") {
        const config = { mode, writes: typeof options.intents === "function", title: `${descriptor.package} ${descriptor.version}`, plan, init: await initFor(), holdViewState, limits: LIMITS, readTimeoutMs: options.readTimeoutMs };
        return send(200, "text/html; charset=utf-8", `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>alpha-tab-kit fake host — ${descriptor.package}</title><style>html,body{margin:0;height:100%}body{display:flex;flex-direction:column;font:12px system-ui}#holder{flex:1;display:flex}#holder iframe{flex:1;border:0}#host-log{padding:2px 8px;background:#eee}</style></head><body><div id="host-log">fake host (${mode})</div><div id="holder"></div><script>window.__ALPHA_TAB_HOST_CONFIG__=${JSON.stringify(config).replace(/</g, "\\u003c")};</script><script type="module" src="/__kit/shell.js"></script></body></html>`);
      }
      if (url.pathname === "/frame") {
        return send(200, "text/html; charset=utf-8", injectBridge(html, hostOrigin), {
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
  return {
    url: `${hostOrigin}/`,
    origin: hostOrigin,
    events,
    plan,
    close: () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }),
  };
}
