import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  createHash,
  createPrivateKey,
  randomBytes,
  randomUUID,
  sign,
} from "node:crypto";
import {
  b64u,
  canonical,
  digestBytes,
  parseIJsonBytes,
  validateEnvelope,
  validateIJson,
  validateReceipt,
} from "../protocol/federation/experimental-jose-hpke-1/interop/clean-room-core.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const profileRoot = join(repoRoot, "protocol/federation/experimental-jose-hpke-1");
const runner = join(repoRoot, "scripts/federation-conformance.mjs");
const client = join(profileRoot, "interop/clean-room-client.mjs");
const services = join(profileRoot, "interop/replacement-services.mjs");
const core = join(profileRoot, "interop/clean-room-core.mjs");
const clock = "2026-08-02T09:10:00Z";
const proofFixture = JSON.parse(readFileSync(join(profileRoot, "fixtures/request-proof-signing.json"), "utf8"));
const load = (relative) => JSON.parse(readFileSync(join(profileRoot, relative), "utf8"));

function invoke(script, args, options = {}) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    timeout: 20_000,
    ...options,
  });
}

async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const stopped = Promise.race([
    once(child, "exit"),
    new Promise((resolveStop) => setTimeout(() => resolveStop(null), 1_000)),
  ]);
  if (await stopped === null && child.exitCode === null) {
    child.kill("SIGKILL");
    await once(child, "exit");
  }
}

async function startReplacementServices({ program = services, args = [], timeoutMs = 5_000, onSpawn, env = {} } = {}) {
  const child = spawn(process.execPath, [program, ...args], {
    cwd: repoRoot,
    env: { ...process.env, NATIVE_FEDERATION_FIXTURE_ROOT: profileRoot, NATIVE_FEDERATION_CLOCK: clock, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  onSpawn?.(child);
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  let ready;
  try {
    ready = await new Promise((resolveReady, reject) => {
      const timer = setTimeout(() => reject(new Error(`replacement service startup timed out: ${stderr}`)), timeoutMs);
      child.once("error", reject);
      child.once("exit", (code, signal) => reject(new Error(`replacement service exited before ready (${code ?? signal}): ${stderr}`)));
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
        const newline = stdout.indexOf("\n");
        if (newline === -1) return;
        clearTimeout(timer);
        try { resolveReady(JSON.parse(stdout.slice(0, newline))); } catch (error) { reject(error); }
      });
    });
    assert.equal(ready.status, "ready");
    assert.notEqual(ready.directory_url, ready.relay_url, "replacement roles must use distinct configured origins");
  } catch (error) {
    await stopChild(child);
    throw error;
  }
  return {
    child,
    ready,
    async close() {
      await stopChild(child);
    },
  };
}

function clientEnvironment(ready) {
  return {
    ...process.env,
    NATIVE_FEDERATION_PROFILE: "native-fed/experimental-jose-hpke-1",
    NATIVE_FEDERATION_CLOCK: clock,
    NATIVE_FEDERATION_DIRECTORY_URL: ready.directory_url,
    NATIVE_FEDERATION_RELAY_URL: ready.relay_url,
    NATIVE_FEDERATION_FIXTURE_ROOT: profileRoot,
    NATIVE_FEDERATION_MANIFEST: join(profileRoot, "fixtures/manifest.json"),
    NATIVE_FEDERATION_REQUEST_PROOF_SIGNING: join(profileRoot, "fixtures/request-proof-signing.json"),
    NATIVE_FEDERATION_NETWORK_DESCRIPTOR_URL: ready.network_descriptor_url,
    NATIVE_FEDERATION_DIRECTORY_AUDIENCE: ready.directory_url,
    NATIVE_FEDERATION_RELAY_AUDIENCE: ready.relay_url,
  };
}

function detachedJws(payload, privateJwk, typ) {
  const first = b64u(Buffer.from(canonical({ alg: "EdDSA", kid: privateJwk.kid, typ })));
  const second = b64u(Buffer.from(canonical(payload)));
  const signature = sign(null, Buffer.from(`${first}.${second}`), createPrivateKey({ key: privateJwk, format: "jwk" }));
  return `${first}..${b64u(signature)}`;
}

function compactJws(payload, privateJwk) {
  const first = b64u(Buffer.from(canonical({ alg: "EdDSA", kid: privateJwk.kid, typ: "native-request-proof+jws" })));
  const second = b64u(Buffer.from(canonical(payload)));
  const signature = sign(null, Buffer.from(`${first}.${second}`), createPrivateKey({ key: privateJwk, format: "jwk" }));
  return `${first}.${second}.${b64u(signature)}`;
}

function signedEnvelope(source = "fixtures/positive/envelope-one-recipient.json", mutate = () => {}) {
  const envelope = structuredClone(load(source).envelope);
  envelope.envelope_id = randomUUID();
  mutate(envelope);
  const context = Object.fromEntries(Object.entries(envelope).filter(([key]) => key !== "jwe" && key !== "ciphertext_digest"));
  envelope.jwe.aad = b64u(Buffer.from(canonical(context)));
  return { envelope, signature: detachedJws(envelope, proofFixture.signers.alice_signing.jwk, "native-envelope+jws") };
}

async function signedRequest(baseUrl, path, { signerName, operation, body, principal, installationId, requestId = randomUUID(), nonce = b64u(randomBytes(16)), proofMutate = () => {}, headers = {} }) {
  const signer = proofFixture.signers[signerName];
  const raw = Buffer.from(JSON.stringify(body));
  const proof = {
    protocol_version: "1.0",
    operation,
    aud: baseUrl,
    principal: principal ?? signer.principal,
    installation_id: installationId === undefined ? signer.installation_id : installationId,
    request_id: requestId,
    body_digest: digestBytes(raw),
    created_at: clock,
    expires_at: "2026-08-02T09:15:00Z",
    nonce,
  };
  proofMutate(proof);
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/vnd.native.federation+json", Authorization: `NativeJWS ${compactJws(proof, signer.jwk)}`, ...headers },
    body: raw,
    redirect: "error",
    signal: AbortSignal.timeout(2_000),
  });
  return { status: response.status, body: await response.json() };
}

async function signedRawRequest(baseUrl, path, { signerName, operation, raw, principal, installationId }) {
  const signer = proofFixture.signers[signerName];
  const proof = {
    protocol_version: "1.0",
    operation,
    aud: baseUrl,
    principal: principal ?? signer.principal,
    installation_id: installationId === undefined ? signer.installation_id : installationId,
    request_id: randomUUID(),
    body_digest: digestBytes(raw),
    created_at: clock,
    expires_at: "2026-08-02T09:15:00Z",
    nonce: b64u(randomBytes(16)),
  };
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/vnd.native.federation+json", Authorization: `NativeJWS ${compactJws(proof, signer.jwk)}` },
    body: raw,
    redirect: "error",
    signal: AbortSignal.timeout(2_000),
  });
  return { status: response.status, body: await response.json() };
}

function fixturePrivateKey(label) {
  const chunks = [];
  for (let counter = 0; Buffer.concat(chunks).length < 32; counter += 1) chunks.push(createHash("sha256").update(`native-fed-fixture:${label}:${counter}`).digest());
  return createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.concat(chunks).subarray(0, 32)]), format: "der", type: "pkcs8" });
}

function resignReceipt(wrapper) {
  const copy = structuredClone(wrapper);
  const relay = load("fixtures/verification-keys.json").relay;
  const first = b64u(Buffer.from(canonical({ alg: "EdDSA", kid: relay.kid, typ: "native-relay-receipt+jws" })));
  const second = b64u(Buffer.from(canonical(copy.receipt)));
  copy.signature = `${first}..${b64u(sign(null, Buffer.from(`${first}.${second}`), fixturePrivateKey("native-relay")))}`;
  return copy;
}

test("clean-room sources import only the local public core and Node standard library", () => {
  for (const source of [client, services, core]) {
    const text = readFileSync(source, "utf8");
    const imports = [...text.matchAll(/from\s+["']([^"']+)["']/g)].map((match) => match[1]);
    assert.ok(imports.length > 0, `${source} has no auditable imports`);
    assert.ok(imports.every((specifier) => specifier.startsWith("node:") || specifier === "./clean-room-core.mjs"), `${source} crossed the clean-room import boundary: ${imports.join(", ")}`);
    assert.doesNotMatch(text, /(?:@withnative|\.\.\/\.\.\/\.\.\/\.\.\/src|scripts\/federation-conformance)/);
  }
});

test("clean-room I-JSON traversal enforces every global boundary", () => {
  assert.doesNotThrow(() => validateIJson({ text: "x".repeat(4096), array: Array.from({ length: 256 }, () => null), number: Number.MAX_SAFE_INTEGER }));
  for (const value of [
    { text: "x".repeat(4097) },
    Array.from({ length: 257 }, () => null),
    Object.fromEntries(Array.from({ length: 257 }, (_, index) => [`key${index}`, null])),
    { number: Number.MAX_SAFE_INTEGER + 1 },
    { text: "\ud800" },
    Array.from({ length: 256 }, () => "x".repeat(4096)),
  ]) assert.throws(() => validateIJson(value), (error) => error.code === "invalid_request" && error.layer === "schema");
  const nested = (wrappers) => {
    let value = "leaf";
    for (let index = 0; index < wrappers; index += 1) value = { next: value };
    return value;
  };
  assert.doesNotThrow(() => validateIJson(nested(31)));
  assert.throws(() => validateIJson(nested(32)), (error) => error.code === "invalid_request" && error.layer === "schema");
});

test("duplicate-aware JSON parsing compares decoded names at the correct object scope", () => {
  assert.throws(() => parseIJsonBytes('{"same":1,"same":2}'), (error) => error.code === "invalid_request" && /duplicate JSON member/.test(error.message));
  assert.throws(() => parseIJsonBytes('{"same":1,"\\u0073ame":2}'), (error) => error.code === "invalid_request" && /duplicate JSON member/.test(error.message));
  assert.throws(() => parseIJsonBytes('{"outer":{"same":1,"same":2}}'), (error) => error.code === "invalid_request" && /duplicate JSON member/.test(error.message));
  assert.deepEqual(parseIJsonBytes(JSON.stringify({ left: { repeated: 1 }, right: { repeated: 2 }, text: '\"repeated\":3' })), {
    left: { repeated: 1 }, right: { repeated: 2 }, text: '\"repeated\":3',
  });
});

test("raw JSON parsing rejects decimal and exponent number lexemes before normalization", () => {
  for (const source of ["1.0", "1e0", "1e3", "9007199254740991.0", "-2E+0"]) {
    assert.throws(() => parseIJsonBytes(`{"value":${source}}`), (error) => error.code === "invalid_request" && /integer lexemes/.test(error.message), source);
  }
  for (const value of [0, -1, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]) {
    assert.deepEqual(parseIJsonBytes(`{"value":${value}}`), { value });
  }
});

test("clean-room client passes the public core profile against Native-compatible defaults", () => {
  const result = invoke(runner, ["run", "--adapter", process.execPath, "--adapter-arg", client]);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report.summary.status, "pass");
  assert.ok(report.summary.total > 1, "the public core fixture profile was not run");
  const adapter = report.cases.find((entry) => entry.id.startsWith("adapter:"));
  assert.equal(adapter.observed.report.implementation, "native-federation-clean-room-node-1");
  assert.equal(adapter.observed.report.credentials, "deterministic-public-fixture-keys-only");
  assert.deepEqual(adapter.observed.report.checks, ["manifest-corpus", "descriptor", "endpoint-binding", "alias", "sender-principal", "recipient-principal", "principal-jws", "negotiation", "outer-envelope-signing", "submit", "receipt-jws", "collect", "acknowledge"]);
});

test("Native reference probe exchanges through replacement directory and relay origins", async () => {
  const replacement = await startReplacementServices();
  try {
    const result = invoke(runner, [
      "probe",
      "--clock", clock,
      "--directory-url", replacement.ready.directory_url,
      "--relay-url", replacement.ready.relay_url,
      "--network-descriptor-url", replacement.ready.network_descriptor_url,
    ]);
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const report = JSON.parse(result.stdout);
    assert.equal(report.summary.status, "pass");
    assert.deepEqual(report.cases.map((entry) => entry.id), ["external-directory-configuration", "external-relay-exchange"]);
  } finally {
    await replacement.close();
  }
});

test("clean-room client exchanges through replacements and rejects Native-specific URL repair", async () => {
  const replacement = await startReplacementServices();
  try {
    const valid = invoke(client, [], { env: clientEnvironment(replacement.ready) });
    assert.equal(valid.status, 0, valid.stderr || valid.stdout);
    const validReport = JSON.parse(valid.stdout);
    assert.equal(validReport.status, "pass");
    assert.deepEqual(validReport.configured_origins, { directory: replacement.ready.directory_url, relay: replacement.ready.relay_url });

    const invalidEnvironment = clientEnvironment(replacement.ready);
    invalidEnvironment.NATIVE_FEDERATION_RELAY_URL = replacement.ready.directory_url;
    invalidEnvironment.NATIVE_FEDERATION_RELAY_AUDIENCE = replacement.ready.directory_url;
    const invalid = invoke(client, [], { env: invalidEnvironment });
    assert.equal(invalid.status, 1, invalid.stderr || invalid.stdout);
    const invalidReport = JSON.parse(invalid.stdout);
    assert.equal(invalidReport.status, "fail");
    assert.match(invalidReport.error, /descriptor relay URL differs from explicit configuration/);
  } finally {
    await replacement.close();
  }
});

test("wire clients reject duplicate response members without rejecting scoped repeats or escaped content", async () => {
  for (const fault of ["duplicate_response_root", "duplicate_response_nested"]) {
    const replacement = await startReplacementServices({ env: { NATIVE_FEDERATION_INTEROP_FAULT: fault } });
    try {
      const result = invoke(client, [], { env: clientEnvironment(replacement.ready) });
      assert.equal(result.status, 1, `${fault}: ${result.stderr || result.stdout}`);
      assert.match(JSON.parse(result.stdout).error, /duplicate JSON member/, fault);
    } finally {
      await replacement.close();
    }
  }
  const compatible = await startReplacementServices({ env: { NATIVE_FEDERATION_INTEROP_FAULT: "compatible_response_names" } });
  try {
    const result = invoke(client, [], { env: clientEnvironment(compatible.ready) });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout).status, "pass");
  } finally {
    await compatible.close();
  }
});

test("wire clients reject non-integer response lexemes before signed-object validation", async () => {
  for (const fault of ["decimal_response", "exponent_response"]) {
    const replacement = await startReplacementServices({ env: { NATIVE_FEDERATION_INTEROP_FAULT: fault } });
    try {
      const result = invoke(client, [], { env: clientEnvironment(replacement.ready) });
      assert.equal(result.status, 1, `${fault}: ${result.stderr || result.stdout}`);
      assert.match(JSON.parse(result.stdout).error, /integer lexemes/, fault);
    } finally {
      await replacement.close();
    }
  }
  const compatible = await startReplacementServices({ env: { NATIVE_FEDERATION_INTEROP_FAULT: "integer_response" } });
  try {
    const result = invoke(client, [], { env: clientEnvironment(compatible.ready) });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    await compatible.close();
  }
});

test("clean-room client rejects signed stale descriptors and stale or revoked recipient state", async () => {
  for (const [fault, pattern] of [
    ["stale_network", /stale_document/],
    ["stale_recipient", /stale_document/],
    ["revoked_recipient_key", /no active encryption key/],
    ["recipient_relay_mismatch", /authority-bind the configured relay endpoint/],
  ]) {
    const replacement = await startReplacementServices({ env: { NATIVE_FEDERATION_INTEROP_FAULT: fault } });
    try {
      const result = invoke(client, [], { env: clientEnvironment(replacement.ready) });
      assert.equal(result.status, 1, `${fault}: ${result.stderr || result.stdout}`);
      assert.match(JSON.parse(result.stdout).error, pattern, fault);
    } finally {
      await replacement.close();
    }
  }
});

test("clean-room corpus is closed and rejects schema and receipt tampering independently", () => {
  const result = invoke(runner, ["run", "--filter", "adapter-only", "--adapter", process.execPath, "--adapter-arg", client]);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const adapter = JSON.parse(result.stdout).cases[0].observed.report;
  const manifest = load("fixtures/manifest.json");
  assert.equal(adapter.corpus.results.length, manifest.cases.length);
  assert.deepEqual(adapter.corpus.results.map((entry) => entry.id).sort(), manifest.cases.map((entry) => entry.id).sort());
  assert.equal(new Set(adapter.corpus.results.map((entry) => entry.fixture_digest)).size, manifest.cases.length);

  const schemaTamper = load("fixtures/positive/envelope-one-recipient.json");
  schemaTamper.unpublished_repair = true;
  assert.throws(() => validateEnvelope(schemaTamper, clock, load), (error) => error.code === "invalid_request" && error.layer === "schema");

  const baseline = load("fixtures/positive/receipt-queued.json");
  const expected = {
    relay_key_id: baseline.receipt.relay_key_id,
    recipient: baseline.receipt.recipient,
    state: baseline.receipt.state,
    delivery_id: baseline.receipt.delivery_id,
    envelope_id: baseline.receipt.envelope_id,
    envelope_digest: baseline.receipt.envelope_digest,
  };
  for (const [field, value] of [
    ["recipient", { network_id: "native", principal_id: "carol001" }],
    ["delivery_id", "00000000-0000-4000-8000-000000000999"],
    ["envelope_id", "00000000-0000-4000-8000-000000000998"],
    ["envelope_digest", "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
  ]) {
    const tampered = structuredClone(baseline);
    tampered.receipt[field] = value;
    assert.throws(() => validateReceipt(resignReceipt(tampered), load, expected), (error) => error.code === "conflict" && error.layer === "receipt-binding", field);
  }
  const badTransition = structuredClone(baseline);
  badTransition.receipt.previous_state = "collected";
  assert.throws(() => validateReceipt(resignReceipt(badTransition), load, expected), (error) => error.code === "invalid_request" && error.layer === "receipt-state");

  const wrongRelayKey = structuredClone(baseline);
  wrongRelayKey.receipt.relay_key_id = "n1.relay.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  assert.throws(() => validateReceipt(resignReceipt(wrongRelayKey), load, expected), (error) => error.code === "signature_invalid" && error.layer === "relay-key-binding");

  const collected = structuredClone(baseline);
  collected.receipt.state = "collected";
  collected.receipt.previous_state = "queued";
  collected.receipt.collector_installation_id = "00000000-0000-4000-8000-000000000999";
  assert.throws(() => validateReceipt(resignReceipt(collected), load, {
    ...expected,
    state: "collected",
    previous_state: "queued",
    collector_installation_id: "00000000-0000-4000-8000-000000000201",
  }), (error) => error.code === "conflict" && error.layer === "receipt-binding");

  for (const mutate of [
    (receipt) => { delete receipt.receipt_id; },
    (receipt) => { receipt.protocol_version = "2.0"; },
    (receipt) => { receipt.observed_at = "2026-02-31T09:05:01Z"; },
    (receipt) => { receipt.delivery_id = "not-a-uuid"; },
  ]) {
    const malformed = structuredClone(baseline);
    mutate(malformed.receipt);
    assert.throws(() => validateReceipt(resignReceipt(malformed), load, expected), (error) => error.code === "invalid_request" && error.layer === "schema");
  }
  const compatible = structuredClone(baseline);
  compatible.receipt.future_relay_hint = { version: 1, opaque: true };
  assert.doesNotThrow(() => validateReceipt(resignReceipt(compatible), load, expected));
});

test("clean-room client rejects correctly signed malformed or inactive-key live receipts", async () => {
  for (const fault of ["receipt_missing_id", "receipt_bad_version", "receipt_bad_timestamp", "receipt_bad_delivery_id", "retired_receipt_key"]) {
    const replacement = await startReplacementServices({ env: { NATIVE_FEDERATION_INTEROP_FAULT: fault } });
    try {
      const result = invoke(client, [], { env: clientEnvironment(replacement.ready) });
      assert.equal(result.status, 1, `${fault}: ${result.stderr || result.stdout}`);
      assert.match(JSON.parse(result.stdout).error, /receipt|relay|timestamp|UUID|version/i, fault);
    } finally {
      await replacement.close();
    }
  }
  const compatible = await startReplacementServices({ env: { NATIVE_FEDERATION_INTEROP_FAULT: "receipt_optional_field" } });
  try {
    const result = invoke(client, [], { env: clientEnvironment(compatible.ready) });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout).status, "pass");
  } finally {
    await compatible.close();
  }
});

test("replacement relay validates envelope keys against fresh live directory documents", async () => {
  for (const [fault, expectedCode] of [
    ["revoked_recipient_key", "recipient_mismatch"],
    ["stale_recipient", "stale_document"],
    ["revoked_sender_key", "key_revoked"],
    ["stale_sender", "stale_document"],
  ]) {
    const replacement = await startReplacementServices({ env: { NATIVE_FEDERATION_INTEROP_FAULT: fault } });
    try {
      const envelope = signedEnvelope();
      const result = await signedRequest(replacement.ready.relay_url, "/v1/envelopes", {
        signerName: "alice_signing", operation: "relay.submit", body: { operation: "relay.submit", envelope },
      });
      assert.notEqual(result.status, 200, `${fault} was accepted using static fixture trust`);
      assert.equal(result.body.code, expectedCode, fault);
    } finally {
      await replacement.close();
    }
  }
});

test("replacement services reject duplicate request members before proof or envelope use", async () => {
  const replacement = await startReplacementServices();
  try {
    const bob = proofFixture.signers.bob_installation;
    const rootDuplicate = Buffer.from('{"operation":"relay.collect","operation":"relay.collect","limit":1,"wait_seconds":0}');
    const rootResult = await signedRawRequest(replacement.ready.relay_url, `/v1/mailboxes/${bob.installation_id}:collect`, {
      signerName: "bob_installation", operation: "relay.collect", raw: rootDuplicate,
    });
    assert.equal(rootResult.status, 400);
    assert.equal(rootResult.body.code, "invalid_request");

    const duplicateEnvelope = signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { envelope.extensions["wire.duplicate"] = 2; });
    const canonicalBody = JSON.stringify({ operation: "relay.submit", envelope: duplicateEnvelope });
    const nestedBody = Buffer.from(canonicalBody.replace('"wire.duplicate":2', '"wire.duplicate":1,"wire.duplicate":2'));
    assert.notEqual(nestedBody.toString(), canonicalBody, "failed to construct nested duplicate request");
    const nestedResult = await signedRawRequest(replacement.ready.relay_url, "/v1/envelopes", {
      signerName: "alice_signing", operation: "relay.submit", raw: nestedBody,
    });
    assert.equal(nestedResult.status, 400);
    assert.equal(nestedResult.body.code, "invalid_request");

    const compatibleEnvelope = signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => {
      envelope.future_siblings = [{ repeated: 1 }, { repeated: 2 }];
      envelope.future_text = '\"repeated\":3';
    });
    const compatible = await signedRequest(replacement.ready.relay_url, "/v1/envelopes", {
      signerName: "alice_signing", operation: "relay.submit", body: { operation: "relay.submit", envelope: compatibleEnvelope },
    });
    assert.equal(compatible.status, 200, JSON.stringify(compatible.body));
  } finally {
    await replacement.close();
  }
});

test("replacement services reject signed request number lexemes before JSON normalization", async () => {
  const replacement = await startReplacementServices();
  try {
    const bob = proofFixture.signers.bob_installation;
    for (const raw of [
      Buffer.from('{"operation":"relay.collect","limit":1.0,"wait_seconds":0}'),
      Buffer.from('{"operation":"relay.collect","limit":1e0,"wait_seconds":0}'),
    ]) {
      const result = await signedRawRequest(replacement.ready.relay_url, `/v1/mailboxes/${bob.installation_id}:collect`, {
        signerName: "bob_installation", operation: "relay.collect", raw,
      });
      assert.equal(result.status, 400, raw.toString());
      assert.equal(result.body.code, "invalid_request");
    }
    const valid = await signedRequest(replacement.ready.relay_url, `/v1/mailboxes/${bob.installation_id}:collect`, {
      signerName: "bob_installation", operation: "relay.collect", body: { operation: "relay.collect", limit: 1, wait_seconds: 0 },
    });
    assert.equal(valid.status, 200);
  } finally {
    await replacement.close();
  }
});

test("replacement relay rejects impersonation and invalid envelopes without partial fan-out", async () => {
  const replacement = await startReplacementServices({ env: { NATIVE_FEDERATION_INTEROP_DISABLE_CAROL_MAILBOX: "1" } });
  try {
    const bob = proofFixture.signers.bob_installation;
    const impersonation = await signedRequest(replacement.ready.relay_url, `/v1/mailboxes/${bob.installation_id}:collect`, {
      signerName: "alice_root",
      operation: "relay.collect",
      principal: bob.principal,
      installationId: bob.installation_id,
      body: { operation: "relay.collect", limit: 100, wait_seconds: 0 },
    });
    assert.equal(impersonation.status, 403);
    assert.equal(impersonation.body.code, "forbidden");

    const expired = signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => {
      envelope.created_at = "2026-08-02T08:00:00Z";
      envelope.expires_at = "2026-08-02T09:05:00Z";
    });
    const expiredResult = await signedRequest(replacement.ready.relay_url, "/v1/envelopes", { signerName: "alice_signing", operation: "relay.submit", body: { operation: "relay.submit", envelope: expired } });
    assert.notEqual(expiredResult.status, 200);

    const partial = signedEnvelope("fixtures/positive/envelope-many-recipients.json");
    const partialResult = await signedRequest(replacement.ready.relay_url, "/v1/envelopes", { signerName: "alice_signing", operation: "relay.submit", body: { operation: "relay.submit", envelope: partial } });
    assert.equal(partialResult.status, 400);
    const collected = await signedRequest(replacement.ready.relay_url, `/v1/mailboxes/${bob.installation_id}:collect`, {
      signerName: "bob_installation", operation: "relay.collect", body: { operation: "relay.collect", limit: 100, wait_seconds: 0 },
    });
    assert.equal(collected.status, 200);
    assert.deepEqual(collected.body.deliveries, [], "a later invalid recipient partially committed the earlier delivery");
  } finally {
    await replacement.close();
  }
});

test("replacement relay rejects signed envelopes outside every public structural bound", async () => {
  const replacement = await startReplacementServices();
  try {
    const invalidEnvelopes = [
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { envelope.expires_at = "2026-09-02T09:05:01Z"; }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { delete envelope.jwe.recipients[0].header.ek; }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { delete envelope.jwe.recipients[0].encrypted_key; }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { envelope.jwe.iv = "too-short"; }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { envelope.jwe.tag = "also-too-short"; }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { envelope.jwe.recipients[0].extra = true; }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { envelope.content_version = "65536.0"; }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { envelope.envelope_type = "native.federation.other"; }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { envelope.envelope_id = "not-a-uuid"; }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { envelope.content_type = "Application/JSON"; }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { envelope.extensions["future.large"] = "x".repeat(4097); }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { envelope.ciphertext_digest = `sha-256:${"A".repeat(42)}B`; }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { envelope.jwe.tag = `${"A".repeat(21)}B`; }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { envelope.jwe.recipients[0].header.ek = `${"A".repeat(42)}B`; }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => {
        let nested = "leaf";
        for (let depth = 0; depth < 32; depth += 1) nested = { next: nested };
        envelope.extensions["future.deep"] = nested;
      }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { envelope.future_array = Array.from({ length: 257 }, () => null); }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => { envelope.future_wide = Object.fromEntries(Array.from({ length: 257 }, (_, index) => [`key${index}`, null])); }),
      signedEnvelope("fixtures/positive/envelope-one-recipient.json", (envelope) => {
        while (envelope.recipients.length < 129) {
          envelope.recipients.push(structuredClone(envelope.recipients[0]));
          envelope.jwe.recipients.push(structuredClone(envelope.jwe.recipients[0]));
        }
      }),
    ];
    for (const envelope of invalidEnvelopes) {
      const result = await signedRequest(replacement.ready.relay_url, "/v1/envelopes", { signerName: "alice_signing", operation: "relay.submit", body: { operation: "relay.submit", envelope } });
      assert.equal(result.status, 400, JSON.stringify(result.body));
      assert.equal(result.body.code, "invalid_request");
    }
  } finally {
    await replacement.close();
  }
});

test("replacement request proofs enforce exact shape, syntax, scope, and request-id/body reuse", async () => {
  const replacement = await startReplacementServices();
  try {
    const bob = proofFixture.signers.bob_installation;
    const target = `/v1/mailboxes/${bob.installation_id}:collect`;
    const body = { operation: "relay.collect", limit: 1, wait_seconds: 0 };
    for (const options of [
      { proofMutate: (proof) => { proof.created_at = "2026-08-02T09:10:00.000Z"; } },
      { proofMutate: (proof) => { proof.request_id = "not-a-uuid"; } },
      { nonce: b64u(randomBytes(15)) },
      { proofMutate: (proof) => { proof.extra = true; } },
    ]) {
      const result = await signedRequest(replacement.ready.relay_url, target, { signerName: "bob_installation", operation: "relay.collect", body, ...options });
      assert.equal(result.status, 401, JSON.stringify(result.body));
      assert.equal(result.body.code, "unauthorized");
    }
    const outOfScope = await signedRequest(replacement.ready.relay_url, "/v1/envelopes", {
      signerName: "alice_root", operation: "relay.submit", body: { operation: "relay.submit", envelope: signedEnvelope() },
    });
    assert.equal(outOfScope.status, 403);
    assert.equal(outOfScope.body.code, "forbidden");

    const reusedId = randomUUID();
    const first = await signedRequest(replacement.ready.relay_url, target, { signerName: "bob_installation", operation: "relay.collect", body, requestId: reusedId });
    assert.equal(first.status, 200);
    const conflict = await signedRequest(replacement.ready.relay_url, target, { signerName: "bob_installation", operation: "relay.collect", body: { ...body, limit: 2 }, requestId: reusedId });
    assert.equal(conflict.status, 409);
    assert.equal(conflict.body.code, "idempotency_conflict");
  } finally {
    await replacement.close();
  }
});

test("replacement relay redelivers an expired lease without minting another transition receipt", async () => {
  const replacement = await startReplacementServices();
  try {
    const envelope = signedEnvelope();
    const submitted = await signedRequest(replacement.ready.relay_url, "/v1/envelopes", { signerName: "alice_signing", operation: "relay.submit", body: { operation: "relay.submit", envelope } });
    assert.equal(submitted.status, 200);
    const bob = proofFixture.signers.bob_installation;
    const target = `/v1/mailboxes/${bob.installation_id}:collect`;
    const body = { operation: "relay.collect", limit: 1, wait_seconds: 0 };
    const first = await signedRequest(replacement.ready.relay_url, target, { signerName: "bob_installation", operation: "relay.collect", body });
    assert.equal(first.status, 200);
    assert.equal(first.body.deliveries[0].attempt, 1);
    assert.ok(first.body.deliveries[0].collected_receipt);
    const redelivered = await signedRequest(replacement.ready.relay_url, target, {
      signerName: "bob_installation", operation: "relay.collect", body, headers: { "Native-Conformance-Advance-Seconds": "301" },
    });
    assert.equal(redelivered.status, 200);
    assert.equal(redelivered.body.deliveries[0].attempt, 2);
    assert.notEqual(redelivered.body.deliveries[0].lease_token, first.body.deliveries[0].lease_token);
    assert.equal(redelivered.body.deliveries[0].collected_receipt, undefined);
    assert.deepEqual(redelivered.body.deliveries[0].queued_receipt, first.body.deliveries[0].queued_receipt);
  } finally {
    await replacement.close();
  }
});

test("clean-room URL parsing fails closed instead of repairing service endpoints", () => {
  const baseReady = { directory_url: "http://127.0.0.1:1", relay_url: "http://127.0.0.1:2", network_descriptor_url: "http://127.0.0.1:1/v1/network" };
  for (const invalidUrl of [
    "http://directory.example",
    "http://user:pass@127.0.0.1:1",
    "http://127.0.0.1:1/prefix",
    "http://127.0.0.1:1/?query=1",
    "http://127.0.0.1:1/#fragment",
  ]) {
    const env = clientEnvironment(baseReady);
    env.NATIVE_FEDERATION_DIRECTORY_URL = invalidUrl;
    env.NATIVE_FEDERATION_DIRECTORY_AUDIENCE = invalidUrl;
    const result = invoke(client, [], { env });
    assert.equal(result.status, 1, invalidUrl);
    assert.match(JSON.parse(result.stdout).error, /URL|HTTPS|forbidden|path/i);
  }
});

test("probe deadlines are bounded and reported as named interoperability failures", async () => {
  const code = "const h=require('http');const a=h.createServer(()=>{});const b=h.createServer(()=>{});a.listen(0,'127.0.0.1',()=>b.listen(0,'127.0.0.1',()=>{const d='http://127.0.0.1:'+a.address().port;const r='http://127.0.0.1:'+b.address().port;console.log(JSON.stringify({status:'ready',directory_url:d,relay_url:r,network_descriptor_url:d+'/v1/network'}));}));process.on('SIGTERM',()=>{a.close();b.close();});";
  const hanging = await startReplacementServices({ program: "-e", args: [code] });
  try {
    const started = Date.now();
    const result = invoke(runner, ["probe", "--directory-url", hanging.ready.directory_url, "--relay-url", hanging.ready.relay_url, "--network-descriptor-url", hanging.ready.network_descriptor_url, "--request-timeout-ms", "100"]);
    assert.equal(result.status, 1, result.stderr || result.stdout);
    const report = JSON.parse(result.stdout);
    assert.equal(report.cases[0].id, "external-directory-configuration");
    assert.equal(report.cases[0].status, "fail");
    assert.ok(Date.now() - started < 3_000, "probe ignored the configured request deadline");
  } finally {
    await hanging.close();
  }
});

test("replacement startup failures terminate malformed and silent children", async () => {
  for (const [code, timeoutMs] of [
    ["console.log('{malformed');setInterval(()=>{},1000)", 1_000],
    ["setInterval(()=>{},1000)", 50],
  ]) {
    let child;
    await assert.rejects(startReplacementServices({ program: "-e", args: [code], timeoutMs, onSpawn: (spawned) => { child = spawned; } }));
    assert.ok(child.exitCode !== null || child.signalCode !== null, "failed startup leaked its child process");
  }
});
