// Run an install plan against a hosted Native without routing its bytes
// through an agent's own tool calls (task 1619b59).
//
// `login` exchanges an emailed code for the person's own session bearer
// (POST /auth/request-otp, /auth/verify-otp) and writes it to a 0600 file;
// the token is never printed. `createMcpClient` is the `client` that
// `runInstall` takes: stateless MCP `tools/call` over HTTP, the same shape as
// scripts/release/production-engine-info-read-transport.mjs. Every write is
// attributed to the person whose bearer it is, so use your own.
// writeSecret calls through the default export so a test can make a write fail.
import fs, { mkdirSync, readFileSync, statSync, lstatSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { randomBytes } from "node:crypto";
import { findField } from "./install.mjs";

export const DEFAULT_ORIGIN = "https://app.withnative.ai";
export const PROTOCOL_VERSION = "2026-07-28";
export const DEFAULT_BEARER_FILE = join(homedir(), ".config", "native-principal", "production-bearer");

const TOKEN = /^[\x21-\x7e]{1,4096}$/;

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** The origin a credential may be sent to: https, or http on loopback only. */
export function credentialOrigin(raw) {
  let url;
  try { url = new URL(raw); } catch { throw new Error(`not a URL: ${raw}`); }
  const ok = url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK.has(url.hostname));
  if (!ok) throw new Error(`refusing to send credentials to ${url.origin}: use https (http only on localhost)`);
  return url.origin;
}

// Redirects are refused: a 307/308 would forward the code or the bearer to
// another host (as scripts/release/production-engine-info-read-transport.mjs).
async function postJson(fetchImpl, url, body, headers = {}, timeoutMs = 120000) {
  const signal = AbortSignal.timeout(timeoutMs);
  try {
    const response = await fetchImpl(url, {
      method: "POST",
      redirect: "error",
      signal,
      headers: { "content-type": "application/json", accept: "application/json", ...headers },
      body: JSON.stringify(body),
    });
    const text = await response.text();
    let value = null;
    try { value = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
    return { status: response.status, value, text };
  } catch (error) {
    // Fetch implementations may report AbortError rather than TimeoutError.
    if (signal.aborted) throw signal.reason;
    throw error;
  }
}

/** Ask the origin to email a sign-in code. */
export async function requestCode({ origin = DEFAULT_ORIGIN, email, fetchImpl = globalThis.fetch }) {
  origin = credentialOrigin(origin);
  const { status, value } = await postJson(fetchImpl, `${origin}/auth/request-otp`, { email });
  if (status < 200 || status >= 300) throw new Error(`request-otp refused (${status}): ${value?.error ?? "no detail"}`);
}

/** Exchange the code for a session bearer and store it at `bearerFile` (0600). Returns nothing secret. */
export async function verifyCode({ origin = DEFAULT_ORIGIN, email, code, bearerFile = DEFAULT_BEARER_FILE, fetchImpl = globalThis.fetch }) {
  origin = credentialOrigin(origin);
  checkSecretDir(dirname(bearerFile));
  const { status, value } = await postJson(fetchImpl, `${origin}/auth/verify-otp`, { email, code });
  if (status < 200 || status >= 300) throw new Error(`verify-otp refused (${status}): ${value?.error ?? "no detail"}`);
  const token = value?.token;
  if (typeof token !== "string" || !TOKEN.test(token)) throw new Error("verify-otp returned no usable token");
  writeSecret(bearerFile, token);
  return { bearerFile, origin };
}

// A missing directory is created 0700; an existing one is never re-permissioned,
// only refused if others can write to it (e.g. /tmp).
function checkSecretDir(dir) {
  let stat;
  try { stat = statSync(dir); } catch { return; }
  if (!stat.isDirectory()) throw new Error(`${dir} is not a directory`);
  if (stat.mode & 0o022) throw new Error(`refusing to store a credential in ${dir}: it is writable by others`);
}

// Write a fresh 0600 file beside the target, then rename over it: the old
// bearer survives a failed write, and a symlink at the target is replaced
// rather than followed.
function writeSecret(path, value) {
  const dir = dirname(path);
  checkSecretDir(dir);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try { if (lstatSync(path).isDirectory()) throw new Error(`${path} is a directory`); } catch (error) { if (error.code !== "ENOENT") throw error; }
  const temp = `${path}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    fs.writeFileSync(temp, `${value}\n`, { mode: 0o600, flag: "wx" });
    fs.renameSync(temp, path);
  } catch (error) {
    fs.rmSync(temp, { force: true });
    throw error;
  }
}

export function readBearer(path = DEFAULT_BEARER_FILE) {
  const token = readFileSync(path, "utf8").trim();
  if (!TOKEN.test(token)) throw new Error(`${path} does not hold a bearer token`);
  return token;
}

/**
 * A `runInstall` client over hosted MCP. `open(intent)` bootstraps a run and
 * declares the intent, so the install is inspectable as one run in Native;
 * every later call carries that run key.
 */
export function createMcpClient({ origin = DEFAULT_ORIGIN, bearer, fetchImpl = globalThis.fetch, clientName = "alpha-tab-kit", timeoutMs = 120000 }) {
  if (!TOKEN.test(bearer ?? "")) throw new Error("createMcpClient needs a bearer");
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2147483647) {
    throw new Error("timeoutMs must be a positive integer no greater than 2147483647");
  }
  origin = credentialOrigin(origin);
  // Nothing the server or a proxy echoes back may carry the bearer to stderr.
  // Redact the whole text before truncating it: a token cut at the boundary
  // would no longer match, and its prefix would survive.
  const redact = (text, max = 600) => String(text).split(bearer).join("[redacted]").slice(0, max);
  let id = 0;
  let runKey = null;

  async function tool(name, envelope) {
    id += 1;
    const { status, value, text } = await postJson(fetchImpl, `${origin}/mcp`, {
      jsonrpc: "2.0",
      id,
      method: "tools/call",
      params: {
        name,
        arguments: envelope,
        _meta: {
          "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
          "io.modelcontextprotocol/clientInfo": { name: clientName, version: "0.1.0" },
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    }, {
      authorization: `Bearer ${bearer}`,
      accept: "application/json, text/event-stream",
      "mcp-protocol-version": PROTOCOL_VERSION,
      "mcp-method": "tools/call",
      "mcp-name": name,
    }, timeoutMs).catch((error) => {
      if (error.name === "TimeoutError") {
        const readOnly = name === "bootstrap" || name.endsWith("_read");
        const warning = readOnly ? "" : " — a write may or may not have committed; inspect before retrying";
        throw new Error(redact(`${name}: no response after ${timeoutMs / 1000}s${warning}`));
      }
      throw error;
    });
    if (status === 401 || status === 403) throw new Error(`${name}: unauthorized (${status}); run \`alpha-tab-kit login\` again`);
    if (status < 200 || status >= 300 || !value) throw new Error(`${name}: HTTP ${status}: ${redact(text, 300)}`);
    if (value.error) throw new Error(`${name}: ${redact(value.error.message ?? JSON.stringify(value.error))}`);
    const result = value.result ?? {};
    const detail = result.structuredContent ?? parseContent(result.content);
    if (result.isError) throw new Error(`${name}.${envelope.operation ?? ""}: ${redact(typeof detail === "string" ? detail : JSON.stringify(detail))}`);
    return detail;
  }

  return {
    get runKey() { return runKey; },
    async open(intent) {
      const boot = await tool("bootstrap", { format: "json" });
      runKey = findField(boot, "run_key");
      if (!runKey) throw new Error("bootstrap returned no run_key");
      await tool("coordination_write", { operation: "set_intent", run_key: runKey, arguments: { intent } });
      return runKey;
    },
    async call(executor, operation, args) {
      return tool(executor, { operation, ...(runKey ? { run_key: runKey } : {}), format: "json", arguments: args });
    },
    /** Execute a plan-required operation from its preparation's plan_id, target and effect_summary. */
    async execute(executor, operation, { plan_id, target, effect_summary }) {
      return tool(executor, { operation, ...(runKey ? { run_key: runKey } : {}), format: "json", plan_id, target, effect_summary });
    },
  };
}

function parseContent(content) {
  const text = Array.isArray(content) ? content.map((part) => part?.text ?? "").join("") : "";
  try { return JSON.parse(text); } catch { return text; }
}
