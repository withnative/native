/** Test-only framing/transport. All session state and admission live in Rust. */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { TextDecoder } from "node:util";

import type { CoeditTransport } from "../src/client.js";
import type { ClientMsg, ServerMsg } from "../src/protocol.js";

const MAX_FRAME = 1024 * 1024;
const MAX_QUEUE = 32;
const MAX_QUEUE_BYTES = 2 * MAX_FRAME;
const MAX_HISTORY = 128;
const REQUEST_TIMEOUT_MS = 5000;
const LIFETIME_MS = 30000;
const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const SOURCE_PATHS = ["src/coedit/registry.rs", "src/coedit/refusal.rs"] as const;

type ObjectValue = Record<string, unknown>;
type Control =
  | { op: "handshake" }
  | { op: "attach"; database: string; link: string }
  | { op: "message"; link: string; message: unknown }
  | { op: "inspect"; link: string }
  | { op: "shutdown" };
type Pending = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
  bytes: number;
};

function object(value: unknown): ObjectValue {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("expected fixture object");
  return value as ObjectValue;
}
function keys(value: ObjectValue, expected: string[]): void {
  if (Object.keys(value).sort().join(",") !== [...expected].sort().join(",")) throw new Error("unexpected fixture fields");
}
function string(value: unknown): string {
  if (typeof value !== "string") throw new Error("expected fixture string");
  return value;
}
function integer(value: unknown, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > max) throw new Error("invalid fixture integer");
  return value;
}
function bytes(value: unknown): Uint8Array {
  if (!Array.isArray(value) || value.length > MAX_FRAME) throw new Error("invalid fixture byte array");
  return Uint8Array.from(value.map((b) => integer(b, 255)));
}
function strings(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > MAX_QUEUE) throw new Error("invalid fixture string array");
  return value.map(string);
}
function wire(msg: ClientMsg): unknown {
  return msg.op === "session.update" ? { ...msg, update: Array.from(msg.update) } : msg;
}
function serverMessage(value: unknown): ServerMsg {
  const m = object(value);
  const session = string(m.session);
  switch (m.op) {
    case "session.opened": {
      keys(m, ["op", "session", "peer", "doc_client_ids", "sync", "base", "limits", "presence"]);
      if (!Array.isArray(m.doc_client_ids) || m.doc_client_ids.length !== 3) throw new Error("expected real three-ID core pool");
      const ids = m.doc_client_ids.map((id) => integer(id, 0xffffffff));
      if (new Set(ids).size !== 3) throw new Error("duplicate fixture lease");
      const base = object(m.base), limits = object(m.limits), presence = object(m.presence);
      keys(base, ["version", "body_sha256"]); keys(limits, ["max_update_bytes"]); keys(presence, ["sharing"]);
      if (!/^[a-f0-9]{64}$/.test(string(base.body_sha256)) || typeof presence.sharing !== "boolean") throw new Error("invalid opened metadata");
      return {
        op: m.op, session, peer: string(m.peer), doc_client_ids: ids, sync: bytes(m.sync),
        base: { version: integer(base.version), body_sha256: string(base.body_sha256) },
        limits: { max_update_bytes: integer(limits.max_update_bytes) }, presence: { sharing: presence.sharing },
      };
    }
    case "session.ack":
      keys(m, ["op", "session", "update_id", "clock"]);
      return { op: m.op, session, update_id: string(m.update_id), clock: integer(m.clock) };
    case "session.refused":
      keys(m, ["op", "session", "code", "refused", "sync"]);
      return { op: m.op, session, code: string(m.code), refused: strings(m.refused), sync: bytes(m.sync) };
    case "session.remote": {
      keys(m, ["op", "session", "update", "from"]);
      const from = object(m.from);
      keys(from, ["person_ref", "kind"]);
      if (from.person_ref !== null) throw new Error("fixture cannot mint a person");
      return { op: m.op, session, update: bytes(m.update), from: { person_ref: null, kind: string(from.kind) } };
    }
    case "session.closed":
      keys(m, ["op", "session", "reason"]);
      return { op: m.op, session, reason: string(m.reason) };
    default: throw new Error(`unexpected fixture session op ${String(m.op)}`);
  }
}

/** Independently gated frames are test-owned delivery controls, not refusals. */
export class FixtureLink {
  readonly sent: ClientMsg[] = [];
  readonly received: ServerMsg[] = [];
  readonly transport: CoeditTransport;
  private callback: ((msg: ServerMsg) => void) | undefined;
  private out: ClientMsg[] = [];
  private incoming: ServerMsg[] = [];
  private holdOutbound = false;
  private holdInbound = false;
  private historyBytes = 0;

  constructor(readonly id: string, readonly database: string, private readonly fixture: CoreFixture) {
    this.transport = {
      send: (msg) => {
        this.remember(this.sent, msg);
        if (this.holdOutbound) this.enqueue(this.out, msg);
        else this.fixture.schedule(this.id, msg);
      },
      onMessage: (callback) => {
        if (this.callback) throw new Error("fixture transport observer already installed");
        this.callback = callback;
      },
    };
  }
  get opened(): Extract<ServerMsg, { op: "session.opened" }> {
    const opened = this.received.find((m) => m.op === "session.opened");
    if (opened?.op !== "session.opened") throw new Error("fixture link has not opened");
    return opened;
  }
  holdOut(): void { this.holdOutbound = true; }
  holdIn(): void { this.holdInbound = true; }
  releaseOut(predicate: (msg: ClientMsg) => boolean): void {
    const selected = this.out.filter(predicate);
    this.out = this.out.filter((msg) => !selected.includes(msg));
    for (const msg of selected) this.fixture.schedule(this.id, msg);
  }
  releaseIn(predicate: (msg: ServerMsg) => boolean): ServerMsg[] {
    const selected = this.incoming.filter(predicate);
    this.incoming = this.incoming.filter((msg) => !selected.includes(msg));
    for (const msg of selected) this.deliverIn(msg);
    return selected;
  }
  /** Repeat an actual received frame; never manufacture a policy refusal. */
  deliverIn(msg: ServerMsg): void {
    if (!this.received.includes(msg)) throw new Error("only an actual received core frame may be delivered/repeated");
    if (!this.callback) throw new Error("fixture link has no SDK consumer");
    this.callback(msg);
  }
  receive(msg: ServerMsg): void {
    this.remember(this.received, msg);
    if (this.holdInbound) this.enqueue(this.incoming, msg);
    else this.deliverIn(msg);
  }
  private encodedSize(msg: ClientMsg | ServerMsg): number {
    return Buffer.byteLength(JSON.stringify(msg, (_key, v: unknown) => v instanceof Uint8Array ? Array.from(v) : v));
  }
  private enqueue<T extends ClientMsg | ServerMsg>(queue: T[], msg: T): void {
    if (queue.length >= MAX_QUEUE || queue.reduce((n, m) => n + this.encodedSize(m), this.encodedSize(msg)) > MAX_QUEUE_BYTES) {
      throw new Error("fixture delivery queue bound exceeded");
    }
    queue.push(msg);
  }
  private remember<T extends ClientMsg | ServerMsg>(history: T[], msg: T): void {
    const size = this.encodedSize(msg);
    if (history.length >= MAX_HISTORY || this.historyBytes + size > MAX_QUEUE_BYTES) throw new Error("fixture history bound exceeded");
    this.historyBytes += size;
    history.push(msg);
  }
}

export class CoreFixture {
  readonly links = new Map<string, FixtureLink>();
  readonly sourceHashes: Record<string, string> = {};
  seed = "";
  recordId = "";
  private readonly child: ChildProcessWithoutNullStreams;
  private readonly pending = new Map<number, Pending>();
  private readonly flights = new Set<Promise<void>>();
  private readonly closed: Promise<void>;
  private readonly lifetime: ReturnType<typeof setTimeout>;
  private buffer: Buffer = Buffer.alloc(0);
  private stderr = "";
  private seq = 0;
  private nextLink = 0;
  private pendingBytes = 0;
  private failure: Error | undefined;
  private closing = false;
  private exited = false;

  private constructor(binary: string) {
    this.child = spawn(binary, [], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"] });
    this.closed = new Promise((resolve) => {
      this.child.once("close", (code, signal) => {
        this.exited = true;
        if (!this.closing || code !== 0 || signal !== null || this.pending.size !== 0 || this.buffer.length !== 0) {
          this.fail(new Error(`fixture child closed: code=${code} signal=${signal}; ${this.stderr}`));
        }
        resolve();
      });
    });
    this.child.on("error", (error) => this.fail(error));
    this.child.stdin.on("error", (error) => this.fail(error));
    this.child.stdout.on("error", (error) => this.fail(error));
    this.child.stderr.on("error", (error) => this.fail(error));
    this.child.stderr.on("data", (chunk: Buffer) => { this.stderr = (this.stderr + chunk.toString("utf8")).slice(-8192); });
    this.child.stdout.on("data", (chunk: Buffer) => {
      try { this.read(chunk); } catch (error) { this.fail(error instanceof Error ? error : new Error(String(error))); }
    });
    this.lifetime = setTimeout(() => this.fail(new Error("fixture process lifetime exceeded")), LIFETIME_MS);
  }

  static async start(): Promise<CoreFixture> {
    const binary = process.env.COEDIT_CORE_FIXTURE_BIN;
    if (!binary || !isAbsolute(binary) || !(await stat(binary)).isFile()) {
      throw new Error("COEDIT_CORE_FIXTURE_BIN must name an existing absolute executable; core interop never skips");
    }
    const fixture = new CoreFixture(binary);
    try {
      const hello = object(await fixture.request({ op: "handshake" }));
      keys(hello, ["fixture_version", "source_sha256", "seed", "record_id", "max_frame_bytes", "max_links"]);
      if (hello.fixture_version !== 1 || hello.max_frame_bytes !== MAX_FRAME || hello.max_links !== 16) throw new Error("incompatible core fixture handshake");
      const hashes = object(hello.source_sha256);
      keys(hashes, [...SOURCE_PATHS]);
      for (const path of SOURCE_PATHS) {
        const current = createHash("sha256").update(await readFile(new URL(`../../../${path}`, import.meta.url))).digest("hex");
        if (hashes[path] !== current) throw new Error(`stale core fixture: ${path} compiled=${String(hashes[path])} current=${current}`);
        fixture.sourceHashes[path] = current;
      }
      fixture.seed = string(hello.seed);
      fixture.recordId = string(hello.record_id);
      return fixture;
    } catch (error) {
      fixture.fail(error instanceof Error ? error : new Error(String(error)));
      await fixture.closed;
      clearTimeout(fixture.lifetime);
      throw error;
    }
  }

  async attach(database = "db-a"): Promise<FixtureLink> {
    const id = `link-${++this.nextLink}`;
    const result = object(await this.request({ op: "attach", database, link: id }));
    keys(result, ["attached"]);
    if (result.attached !== true) throw new Error("fixture attach not confirmed");
    const link = new FixtureLink(id, database, this);
    this.links.set(id, link);
    return link;
  }
  async inspect(link: FixtureLink): Promise<{ body: string; body_sha256: string; sync: Uint8Array }> {
    const result = object(await this.request({ op: "inspect", link: link.id }));
    keys(result, ["body", "body_sha256", "sync"]);
    const body = string(result.body), sha = string(result.body_sha256);
    if (sha !== createHash("sha256").update(body, "utf8").digest("hex")) throw new Error("core inspection body/digest mismatch");
    return { body, body_sha256: sha, sync: bytes(result.sync) };
  }
  /** Negative guard tests only; errors reject without becoming policy refusals. */
  async rawMessage(link: FixtureLink, message: unknown): Promise<unknown> {
    return this.request({ op: "message", link: link.id, message });
  }
  schedule(link: string, msg: ClientMsg): void {
    let flight: Promise<void>;
    flight = this.request({ op: "message", link, message: wire(msg) }).then((value) => {
      const result = object(value);
      keys(result, ["dispatched"]);
      if (result.dispatched !== true) throw new Error("fixture message not dispatched");
    }).catch((error: unknown) => {
      this.fail(error instanceof Error ? error : new Error(String(error)));
    }).finally(() => { this.flights.delete(flight); });
    this.flights.add(flight);
  }
  /** Await actual frame receipts and any SDK replay they synchronously schedule. */
  async idle(): Promise<void> {
    this.check();
    while (this.flights.size !== 0) { await Promise.all([...this.flights]); this.check(); }
    this.check();
  }
  async stop(): Promise<void> {
    const deadline = setTimeout(() => this.fail(new Error("fixture shutdown timed out")), REQUEST_TIMEOUT_MS);
    try {
      await this.idle();
      this.closing = true;
      const result = object(await this.request({ op: "shutdown" }));
      keys(result, ["shutdown"]);
      if (result.shutdown !== true) throw new Error("fixture shutdown not confirmed");
      await this.closed;
      this.check();
    } finally {
      clearTimeout(deadline); clearTimeout(this.lifetime);
      if (!this.exited) this.child.kill("SIGKILL");
    }
  }
  private check(): void { if (this.failure) throw this.failure; }
  private fail(error: Error): void {
    if (this.failure) return;
    this.failure = error;
    for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(error); }
    this.pending.clear(); this.pendingBytes = 0;
    if (!this.exited) this.child.kill("SIGKILL");
  }
  private request(control: Control): Promise<unknown> {
    try {
      this.check();
      if (this.exited) throw new Error("fixture already exited");
      if (this.seq >= 0xffffffff) throw new Error("fixture request ID exhausted");
      const id = ++this.seq;
      const encoded = JSON.stringify({ request_id: id, control }) + "\n";
      const size = Buffer.byteLength(encoded);
      if (size > MAX_FRAME || this.pending.size >= MAX_QUEUE || this.pendingBytes + size > MAX_QUEUE_BYTES) throw new Error("fixture request queue/frame bound exceeded");
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => this.fail(new Error(`fixture request ${id} timed out; ${this.stderr}`)), REQUEST_TIMEOUT_MS);
        this.pending.set(id, { resolve, reject, timer, bytes: size });
        this.pendingBytes += size;
        this.child.stdin.write(encoded, (error) => { if (error) this.fail(error); });
      });
    } catch (error) { return Promise.reject(error); }
  }
  private read(chunk: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    for (let end = this.buffer.indexOf(10); end !== -1; end = this.buffer.indexOf(10)) {
      if (end + 1 > MAX_FRAME) throw new Error("oversized fixture output line");
      const line = new TextDecoder("utf-8", { fatal: true }).decode(this.buffer.subarray(0, end));
      this.buffer = this.buffer.subarray(end + 1);
      const response = object(JSON.parse(line) as unknown);
      const failed = "error" in response;
      keys(response, ["request_id", failed ? "error" : "result", "events"]);
      const id = integer(response.request_id, 0xffffffff);
      const pending = this.pending.get(id);
      if (!pending) throw new Error(`unknown/duplicate fixture response ${id}`);
      if (!Array.isArray(response.events) || response.events.length > 16) throw new Error("invalid fixture events");
      if (failed && response.events.length !== 0) throw new Error("fixture error cannot carry events");
      for (const value of response.events) {
        const e = object(value);
        keys(e, ["link", "message"]);
        const link = this.links.get(string(e.link));
        if (!link) throw new Error("fixture delivered to an unattached link");
        link.receive(serverMessage(e.message));
      }
      const error = failed ? new Error(string(response.error)) : undefined;
      this.pending.delete(id); this.pendingBytes -= pending.bytes; clearTimeout(pending.timer);
      if (error) pending.reject(error);
      else pending.resolve(response.result);
    }
    if (this.buffer.length >= MAX_FRAME) throw new Error("oversized/unterminated fixture output");
  }
}
