import { test, mock } from "node:test";
import fs from "node:fs";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, chmodSync, readFileSync, statSync, writeFileSync, symlinkSync, lstatSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { planInstall, runInstall } from "../src/install.mjs";
import { requestCode, verifyCode, readBearer, createMcpClient, credentialOrigin } from "../src/remote.mjs";

const origin = "https://native.test";
const reply = (status, value) => new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });

test("login stores the bearer 0600 and returns nothing secret", async () => {
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push([url, JSON.parse(init.body)]);
    return url.endsWith("/auth/request-otp") ? reply(200, { challenge_id: "c" }) : reply(200, { token: "a".repeat(64), user: {} });
  };
  const dir = mkdtempSync(join(tmpdir(), "kit-login-"));
  const bearerFile = join(dir, "nested", "production-bearer");
  await requestCode({ origin, email: "p@example.test", fetchImpl });
  const result = await verifyCode({ origin, email: "p@example.test", code: "123456", bearerFile, fetchImpl });
  assert.deepEqual(seen.map(([url]) => url), [`${origin}/auth/request-otp`, `${origin}/auth/verify-otp`]);
  assert.deepEqual(seen[1][1], { email: "p@example.test", code: "123456" });
  assert.ok(!JSON.stringify(result).includes("aaaa"));
  assert.equal(statSync(bearerFile).mode & 0o777, 0o600);
  assert.equal(statSync(join(dir, "nested")).mode & 0o777, 0o700);
  assert.equal(readBearer(bearerFile), "a".repeat(64));
  // A second login replaces the file rather than refusing.
  await verifyCode({ origin, email: "p@example.test", code: "654321", bearerFile, fetchImpl });
});

test("a refused code surfaces the server's reason and writes nothing", async () => {
  const dir = mkdtempSync(join(tmpdir(), "kit-login-"));
  const bearerFile = join(dir, "production-bearer");
  await assert.rejects(
    verifyCode({ origin, email: "p@example.test", code: "000000", bearerFile, fetchImpl: async () => reply(401, { error: "invalid code" }) }),
    /verify-otp refused \(401\): invalid code/,
  );
  assert.throws(() => readFileSync(bearerFile));
});

test("readBearer refuses a file that holds no token", () => {
  const dir = mkdtempSync(join(tmpdir(), "kit-login-"));
  writeFileSync(join(dir, "b"), "\n");
  assert.throws(() => readBearer(join(dir, "b")), /does not hold a bearer token/);
});

test("the MCP client bootstraps a run, then carries its key on every call", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ url, auth: init.headers.authorization, name: body.params.name, args: body.params.arguments });
    if (body.params.name === "bootstrap") return reply(200, { jsonrpc: "2.0", id: body.id, result: { structuredContent: { run: { run_key: "run-1" } } } });
    if (body.params.name === "coordination_write") return reply(200, { jsonrpc: "2.0", id: body.id, result: { structuredContent: { accepted_intent: "x" } } });
    return reply(200, { jsonrpc: "2.0", id: body.id, result: { content: [{ type: "text", text: JSON.stringify({ write_receipt: { body_digest: "d" } }) }] } });
  };
  const client = createMcpClient({ origin, bearer: "b".repeat(64), fetchImpl });
  assert.equal(await client.open("Install a tab"), "run-1");
  const result = await client.call("records_write", "update_record", { id: "r", body_append: "x" });
  assert.equal(result.write_receipt.body_digest, "d");
  assert.ok(calls.every((call) => call.url === `${origin}/mcp` && call.auth === `Bearer ${"b".repeat(64)}`));
  assert.deepEqual(calls[1].args, { operation: "set_intent", run_key: "run-1", arguments: { intent: "Install a tab" } });
  assert.deepEqual(calls[2].args, { operation: "update_record", run_key: "run-1", format: "json", arguments: { id: "r", body_append: "x" } });
});

test("tool errors and auth failures throw instead of passing as receipts", async () => {
  const toolError = createMcpClient({ origin, bearer: "b".repeat(64), fetchImpl: async (url, init) =>
    reply(200, { jsonrpc: "2.0", id: JSON.parse(init.body).id, result: { isError: true, content: [{ type: "text", text: "digest mismatch" }] } }) });
  await assert.rejects(toolError.call("records_write", "update_record", {}), /records_write\.update_record: digest mismatch/);
  const unauthorized = createMcpClient({ origin, bearer: "b".repeat(64), fetchImpl: async () => reply(401, { error: "missing bearer token" }) });
  await assert.rejects(unauthorized.call("records_read", "get_record", {}), /unauthorized \(401\)/);
});

test("credentials go only to https, or http on loopback, and never follow a redirect", async () => {
  assert.equal(credentialOrigin("https://app.withnative.ai/x"), "https://app.withnative.ai");
  assert.equal(credentialOrigin("http://127.0.0.1:4174"), "http://127.0.0.1:4174");
  assert.throws(() => credentialOrigin("http://app.withnative.ai"), /refusing to send credentials/);
  assert.throws(() => createMcpClient({ origin: "http://evil.test", bearer: "b".repeat(64) }), /refusing to send credentials/);
  let fetched = false;
  await assert.rejects(requestCode({ origin: "http://evil.test", email: "p@example.test", fetchImpl: async () => { fetched = true; } }), /refusing/);
  assert.equal(fetched, false);
  const seen = [];
  await verifyCode({ origin, email: "p@example.test", code: "1", bearerFile: join(mkdtempSync(join(tmpdir(), "kit-login-")), "b"),
    fetchImpl: async (url, init) => { seen.push(init.redirect); return reply(200, { token: "t".repeat(64) }); } });
  const client = createMcpClient({ origin, bearer: "b".repeat(64), fetchImpl: async (url, init) => { seen.push(init.redirect); return reply(200, { jsonrpc: "2.0", id: 1, result: { structuredContent: {} } }); } });
  await client.call("records_read", "get_record", {});
  assert.deepEqual(seen, ["error", "error"]);
});

test("an existing directory is never re-permissioned; one others can write to is refused", async () => {
  const shared = mkdtempSync(join(tmpdir(), "kit-shared-"));
  chmodSync(shared, 0o777);
  const fetchImpl = async () => reply(200, { token: "t".repeat(64) });
  await assert.rejects(verifyCode({ origin, email: "p@example.test", code: "1", bearerFile: join(shared, "b"), fetchImpl }), /writable by others/);
  assert.equal(statSync(shared).mode & 0o777, 0o777);
  const project = mkdtempSync(join(tmpdir(), "kit-project-"));
  chmodSync(project, 0o755);
  await verifyCode({ origin, email: "p@example.test", code: "1", bearerFile: join(project, "b"), fetchImpl });
  assert.equal(statSync(project).mode & 0o777, 0o755);
  assert.equal(statSync(join(project, "b")).mode & 0o777, 0o600);
});

test("replacing a bearer is atomic and replaces a symlink instead of following it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "kit-login-"));
  const decoy = join(dir, "decoy");
  writeFileSync(decoy, "untouched\n");
  const bearerFile = join(dir, "b");
  symlinkSync(decoy, bearerFile);
  await verifyCode({ origin, email: "p@example.test", code: "1", bearerFile, fetchImpl: async () => reply(200, { token: "n".repeat(64) }) });
  assert.equal(readFileSync(decoy, "utf8"), "untouched\n");
  assert.ok(!lstatSync(bearerFile).isSymbolicLink());
  assert.equal(readBearer(bearerFile), "n".repeat(64));
});

test("a write that fails after a successful verification keeps the previous bearer", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "kit-login-"));
  const bearerFile = join(dir, "b");
  await verifyCode({ origin, email: "p@example.test", code: "1", bearerFile, fetchImpl: async () => reply(200, { token: "o".repeat(64) }) });
  t.mock.method(fs, "writeFileSync", () => { throw Object.assign(new Error("ENOSPC: no space left on device"), { code: "ENOSPC" }); });
  await assert.rejects(
    verifyCode({ origin, email: "p@example.test", code: "2", bearerFile, fetchImpl: async () => reply(200, { token: "n".repeat(64) }) }),
    /ENOSPC/,
  );
  t.mock.restoreAll();
  assert.equal(readBearer(bearerFile), "o".repeat(64));
  assert.deepEqual(fs.readdirSync(dir), ["b"]);
});

test("a bearer reflected by the server or a proxy is redacted from every error", async () => {
  const bearer = "s".repeat(64);
  const echo = (status, value) => createMcpClient({ origin, bearer, fetchImpl: async () => reply(status, value) });
  for (const client of [
    echo(502, { proxy: `Authorization: Bearer ${bearer}` }),
    echo(200, { jsonrpc: "2.0", id: 1, error: { message: `bad header Bearer ${bearer}` } }),
    echo(200, { jsonrpc: "2.0", id: 1, result: { isError: true, content: [{ type: "text", text: `token ${bearer}` }] } }),
  ]) {
    const error = await client.call("records_read", "get_record", {}).then(() => null, (caught) => caught);
    assert.ok(error, "expected a failure");
    assert.ok(!error.message.includes(bearer), error.message);
    assert.match(error.message, /\[redacted\]/);
  }
});

test("a bearer straddling the truncation boundary leaks no prefix", async () => {
  const bearer = "0123456789abcdef".repeat(4);
  for (const response of [
    () => new Response("x".repeat(237) + bearer, { status: 502 }),
    () => reply(200, { jsonrpc: "2.0", id: 1, result: { isError: true, structuredContent: { message: "x".repeat(525) + bearer } } }),
    () => reply(200, { jsonrpc: "2.0", id: 1, error: { message: "x".repeat(590) + bearer } }),
  ]) {
    const client = createMcpClient({ origin, bearer, fetchImpl: async () => response() });
    const error = await client.call("records_read", "get_record", {}).then(() => null, (caught) => caught);
    assert.ok(error, "expected a failure");
    for (let n = 8; n <= bearer.length; n += 1) assert.ok(!error.message.includes(bearer.slice(0, n)), `leaked ${n} characters`);
  }
});

test("without a terminal, login's completion command keeps --origin and --bearer-file", async () => {
  const { createServer } = await import("node:http");
  const server = createServer((req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const local = `http://127.0.0.1:${server.address().port}`;
  const bearerFile = join(mkdtempSync(join(tmpdir(), "kit-login-")), "it's here");
  const cli = fileURLToPath(new URL("../bin/alpha-tab-kit.mjs", import.meta.url));
  const run = await new Promise((done) => {
    import("node:child_process").then(({ execFile }) => execFile(process.execPath, [cli, "login", "--email", "p@example.test", "--origin", local, "--bearer-file", bearerFile], (error, stdout) => done({ error, stdout })));
  });
  server.close();
  assert.equal(run.error, null);
  assert.match(run.stdout, new RegExp(`--origin '${local}'`));
  assert.ok(run.stdout.includes(`--bearer-file '${bearerFile.replace("'", "'\\''")}'`), run.stdout);
});


test("whole-body create survives MCP encoding and retries stage a fresh source", async () => {
  const descriptor = JSON.parse(readFileSync(new URL("fixtures/probe-descriptor.json", import.meta.url), "utf8"));
  const html = readFileSync(new URL("fixtures/probe-queued.html", import.meta.url), "utf8") + "\n<!-- \\n \" € 😀 -->";
  const input = { descriptor, html, homeId: "home", name: "Whole body", reason: "Transport test", sources: [{ record_id: "design", reason: "Accepted design" }] };
  const plan = planInstall(input);
  const calls = [];
  const creates = [];
  const fetchImpl = async (url, init) => {
    assert.equal(url, `${origin}/mcp`);
    assert.equal(init.redirect, "error");
    const request = JSON.parse(init.body);
    const envelope = request.params.arguments;
    calls.push(envelope);
    let result;
    if (envelope.operation === "create_record") {
      const args = envelope.arguments;
      assert.equal(args.body_encoding, "gzip+base64");
      assert.equal(gunzipSync(Buffer.from(args.body, "base64")).toString("utf8"), html);
      assert.deepEqual(args.sources, input.sources);
      assert.deepEqual(args.facets, { runtime: "native.html.v1" });
      assert.equal(Object.hasOwn(args, "idempotency_key"), false);
      const receipt = { id: `artifact-${creates.length}`, body_digest: plan.digests.bundle_sha256, source_event_id: `body-created-${creates.length}` };
      creates.push(receipt);
      result = { write_receipt: receipt };
    } else {
      assert.ok(["manage_alpha_tabs.install", "manage_alpha_tabs.inspect"].includes(envelope.operation));
      if (envelope.operation === "manage_alpha_tabs.install") {
        assert.equal(envelope.arguments.artifact_id, creates.at(-1).id);
        assert.equal(envelope.arguments.source_revision, creates.at(-1).source_event_id);
      }
      result = { install: { digest: plan.digests.digest, declaration_digest: plan.digests.declaration_digest, version: descriptor.version } };
    }
    // Exercise text-mode JSON unwrapping as well as nested receipt fields.
    return reply(200, { jsonrpc: "2.0", id: request.id, result: { content: [{ type: "text", text: JSON.stringify(result) }] } });
  };
  const client = createMcpClient({ origin, bearer: "b".repeat(64), fetchImpl });
  const first = await runInstall(plan, client);
  const retry = await runInstall(planInstall(input), client);
  assert.notEqual(first.record_id, retry.record_id);
  assert.notEqual(first.source_revision, retry.source_revision);
  assert.equal(creates.length, 2);
  assert.equal(calls.length, 6);
});


test("MCP timeout aborts the request and reports uncertain write outcome without secrets", async () => {
  const bearer = "timeout-secret".repeat(5);
  let aborted = false;
  const client = createMcpClient({ origin, bearer, timeoutMs: 20, fetchImpl: async (url, init) => {
    assert.ok(init.signal instanceof AbortSignal);
    return new Promise((resolve, reject) => {
      // AbortSignal.timeout uses an unref'd timer; keep this simulated fetch alive.
      const pending = setTimeout(() => reject(new Error("timeout did not abort fetch")), 1000);
      init.signal.addEventListener("abort", () => {
        aborted = true;
        clearTimeout(pending);
        reject(new Error(`Authorization: Bearer ${bearer}`));
      }, { once: true });
    });
  } });
  const error = await client.call("records_write", "create_record", {}).then(() => null, error => error);
  assert.equal(aborted, true);
  assert.equal(error.message, "records_write: no response after 0.02s — a write may or may not have committed; inspect before retrying");
  assert.ok(!error.message.includes(bearer));
});

test("MCP requests default to 120 seconds and reject invalid timeout settings", async (t) => {
  const timeout = AbortSignal.timeout.bind(AbortSignal);
  const durations = [];
  t.mock.method(AbortSignal, "timeout", ms => { durations.push(ms); return timeout(ms); });
  const client = createMcpClient({ origin, bearer: "b".repeat(64), fetchImpl: async () => reply(200, { result: { structuredContent: {} } }) });
  await client.call("records_read", "get_record", {});
  assert.deepEqual(durations, [120000]);
  for (const timeoutMs of [0, -1, 1.5, NaN, Infinity, 2147483648]) {
    assert.throws(() => createMcpClient({ origin, bearer: "b".repeat(64), timeoutMs }), /timeoutMs must be a positive integer/);
  }
});

test("install-run passes --timeout-ms and reports a stalled fake server clearly", async () => {
  const { createServer } = await import("node:http");
  const { execFile } = await import("node:child_process");
  const server = createServer(() => {});
  await new Promise(done => server.listen(0, "127.0.0.1", done));
  const dir = mkdtempSync(join(tmpdir(), "kit-timeout-"));
  const bearerFile = join(dir, "fake-bearer");
  writeFileSync(bearerFile, "b".repeat(64));
  const planFile = join(dir, "plan.json");
  writeFileSync(planFile, JSON.stringify({ package: "agent.timeout", version: "0.1.0", steps: [] }));
  const cli = fileURLToPath(new URL("../bin/alpha-tab-kit.mjs", import.meta.url));
  try {
    const run = await new Promise(done => execFile(process.execPath,
      [cli, "install-run", planFile, "--origin", `http://127.0.0.1:${server.address().port}`, "--bearer-file", bearerFile, "--timeout-ms", "20"],
      { timeout: 5000 }, (error, stdout, stderr) => done({ error, stdout, stderr })));
    assert.equal(run.error?.code, 1);
    assert.equal(run.stderr, "bootstrap: no response after 0.02s\n");
  } finally {
    server.closeAllConnections();
    await new Promise(done => server.close(done));
  }
});


test("read-only MCP timeouts omit write outcome warnings", async () => {
  for (const executor of ["bootstrap", "records_read", "artifacts_read", "sql_read"]) {
    const client = createMcpClient({ origin, bearer: "b".repeat(64), timeoutMs: 10, fetchImpl: async (url, init) => new Promise((resolve, reject) => {
      const pending = setTimeout(() => reject(new Error("fetch did not abort")), 1000);
      init.signal.addEventListener("abort", () => { clearTimeout(pending); reject(init.signal.reason); }, { once: true });
    }) });
    await assert.rejects(client.call(executor, "read", {}), { message: `${executor}: no response after 0.01s` });
  }
});

test("install-run rejects invalid timeout flags with usage before reading credentials", async () => {
  const { spawnSync } = await import("node:child_process");
  const cli = fileURLToPath(new URL("../bin/alpha-tab-kit.mjs", import.meta.url));
  for (const values of [[], ["nope"], ["1.5"], ["0"], ["-1"], ["2147483648"], ["--origin", origin]]) {
    const run = spawnSync(process.execPath, [cli, "install-run", "unused-plan.json", "--timeout-ms", ...values], { encoding: "utf8" });
    assert.equal(run.status, 2);
    assert.match(run.stderr, /^--timeout-ms needs a positive integer no greater than 2147483647\n/);
    assert.match(run.stderr, /install-run <plan dir/);
    assert.ok(!run.stderr.includes("Error:"));
    assert.equal(run.stdout, "");
  }
});

// The CLI plans locally, then executes over real HTTP against a fake MCP server.
// No browser adoption is simulated: these are server-reported update outcomes.
test("CLI update plans report carried or required adoption and refuse old servers", async () => {
  const { createServer } = await import("node:http");
  const { execFile } = await import("node:child_process");
  const cli = fileURLToPath(new URL("../bin/alpha-tab-kit.mjs", import.meta.url));
  const fixture = fileURLToPath(new URL("fixtures/probe-descriptor.json", import.meta.url));
  const execute = args => new Promise(done => execFile(process.execPath, [cli, ...args],
    { timeout: 10000 }, (error, stdout, stderr) => done({ error, stdout, stderr })));
  const dir = mkdtempSync(join(tmpdir(), "kit-update-"));
  const bearerFile = join(dir, "fake-bearer");
  writeFileSync(bearerFile, "b".repeat(64));
  for (const other of ["--replace", "--after-removal"]) {
    const refused = await execute(["install-plan", fixture, "--home", "home", "--reason", "Update", "--update", "current", other, "previous"]);
    assert.equal(refused.error?.code, 1);
    assert.match(refused.stderr, /mutually exclusive/);
    assert.equal(refused.stdout, "");
  }
  const bareReplace = await execute(["install-plan", fixture, "--home", "home", "--reason", "Update", "--update", "current", "--replace"]);
  assert.equal(bareReplace.error?.code, 1);
  assert.match(bareReplace.stderr, /mutually exclusive/);
  const missingReplace = await execute(["install-plan", fixture, "--home", "home", "--reason", "Replace", "--replace"]);
  assert.ok(missingReplace.error?.code);
  assert.match(missingReplace.stderr, /--replace needs/);
  for (const id of ["", " "]) {
    const refused = await execute(["install-plan", fixture, "--home", "home", "--reason", "Update", "--update", id]);
    assert.ok(refused.error?.code);
    assert.match(refused.stderr, /--update needs/);
  }
  for (const outcome of ["carried", "required", "disabled", "retry", "unsupported"]) {
    const planFile = join(dir, `${outcome}.json`);
    const planned = await execute(["install-plan", fixture, "--home", "home", "--reason", "Update", "--update", "current"]);
    assert.equal(planned.error, null, planned.stderr);
    writeFileSync(planFile, planned.stdout);
    const plan = JSON.parse(planned.stdout);
    assert.deepEqual(plan.steps.map(s => s.step), ["create-artifact", "update", "inspect"]);
    const calls = [];
    const install = { digest: plan.digests.digest, declaration_digest: plan.digests.declaration_digest, version: plan.version, status: outcome === "disabled" ? "disabled" : "installed" };
    const server = createServer(async (req, res) => {
      let body = "";
      for await (const chunk of req) body += chunk;
      const request = JSON.parse(body);
      const envelope = request.params.arguments;
      let result;
      if (request.params.name === "bootstrap") result = { run: { run_key: "fake-run" } };
      else if (request.params.name === "coordination_write") result = {};
      else {
        calls.push(envelope);
        if (envelope.operation === "create_record") result = { write_receipt: { id: "new-source", source_event_id: "new-body", body_digest: plan.digests.bundle_sha256 } };
        else if (envelope.operation === "manage_alpha_tabs.update") {
          assert.equal(envelope.arguments.expected_install_event_id, "current");
          assert.equal(envelope.arguments.artifact_id, "new-source");
          assert.equal(envelope.arguments.source_revision, "new-body");
          assert.equal(envelope.arguments.digest, plan.digests.digest);
          if (outcome === "unsupported") {
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({ jsonrpc: "2.0", id: request.id, result: { isError: true, content: [{ type: "text", text: "unknown operation 'manage_alpha_tabs.update' for artifacts_write" }] } }));
            return;
          }
          result = { changed: outcome !== "retry", idempotent_retry: outcome === "retry", update_event_id: "updated", adoption_carried: outcome !== "required", adoption_required: outcome === "required", install,
            decoy: { update_event_id: "fake", adoption_carried: outcome !== "carried", adoption_required: outcome !== "required" } };
        } else {
          assert.equal(envelope.operation, "manage_alpha_tabs.inspect");
          result = { install };
        }
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: request.id, result: { structuredContent: result } }));
    });
    await new Promise(done => server.listen(0, "127.0.0.1", done));
    try {
      const run = await execute(["install-run", planFile, "--origin", `http://127.0.0.1:${server.address().port}`, "--bearer-file", bearerFile]);
      if (outcome === "unsupported") {
        assert.equal(run.error?.code, 1);
        assert.match(run.stderr, /Server predates manage_alpha_tabs.update; use --replace explicitly/);
        assert.match(run.stderr, /Staged source record new-source can be archived/);
        assert.deepEqual(calls.map(c => c.operation), ["create_record", "manage_alpha_tabs.update"]);
      } else {
        assert.equal(run.error, null, run.stderr);
        assert.match(run.stdout, /"update_event_id": "updated"/);
        assert.ok(run.stdout.includes(`"adoption_carried": ${outcome !== "required"}`));
        assert.ok(run.stdout.includes(`"adoption_required": ${outcome === "required"}`));
        assert.ok(run.stdout.includes(outcome === "retry"
          ? "No change: this update was already applied"
          : outcome !== "required"
            ? "Updated; adoption carried over (no re-adoption needed)"
            : "Updated; Preview and Adopt it at /alpha/ before launching"));
        assert.ok(run.stdout.includes(`"changed": ${outcome !== "retry"}`));
        assert.ok(run.stdout.includes(`"idempotent_retry": ${outcome === "retry"}`));
        if (outcome === "retry") assert.ok(!run.stdout.includes("Updated;"));
        assert.equal(run.stdout.includes("(tab is disabled; restore it to launch — restore requires fresh Preview → Adopt)"), outcome === "disabled");
        assert.deepEqual(calls.map(c => c.operation), ["create_record", "manage_alpha_tabs.update", "manage_alpha_tabs.inspect"]);
      }
    } finally {
      await new Promise(done => server.close(done));
    }
  }
});
