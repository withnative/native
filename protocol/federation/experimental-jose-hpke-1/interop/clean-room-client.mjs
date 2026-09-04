#!/usr/bin/env node

// Deliberately standalone clean-room client. It imports Node's standard
// library only and consumes the public profile, fixtures, and process-adapter
// environment. Do not import the Native runner or application packages here.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  randomUUID,
  sign,
  verify,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve, sep } from "node:path";
import {
  evaluateManifest,
  parseIJsonBytes,
  strictServiceUrl,
  validateNetwork,
  validatePrincipal,
  validateReceipt as validateReceiptSemantics,
} from "./clean-room-core.mjs";

const requiredEnvironment = [
  "NATIVE_FEDERATION_PROFILE",
  "NATIVE_FEDERATION_CLOCK",
  "NATIVE_FEDERATION_DIRECTORY_URL",
  "NATIVE_FEDERATION_RELAY_URL",
  "NATIVE_FEDERATION_FIXTURE_ROOT",
  "NATIVE_FEDERATION_MANIFEST",
  "NATIVE_FEDERATION_REQUEST_PROOF_SIGNING",
  "NATIVE_FEDERATION_NETWORK_DESCRIPTOR_URL",
  "NATIVE_FEDERATION_DIRECTORY_AUDIENCE",
  "NATIVE_FEDERATION_RELAY_AUDIENCE",
];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    assert(Number.isSafeInteger(value), "clean-room JCS rejects non-integer or unsafe numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  throw new Error(`clean-room JCS rejects ${typeof value}`);
}

const b64u = (value) => Buffer.from(value).toString("base64url");
const digestBytes = (value) => `sha-256:${b64u(createHash("sha256").update(value).digest())}`;
const digestValue = (value) => digestBytes(Buffer.from(canonical(value)));

function strictB64u(value) {
  assert(typeof value === "string" && /^[A-Za-z0-9_-]+$/.test(value), "non-canonical base64url");
  const decoded = Buffer.from(value, "base64url");
  assert(b64u(decoded) === value, "non-canonical base64url");
  return decoded;
}

function verifyDetached(payload, compact, jwk, typ) {
  assert(jwk && typeof compact === "string", `missing ${typ} verification material`);
  const parts = compact.split(".");
  assert(parts.length === 3 && parts[1] === "", `${typ} is not detached compact JWS`);
  const header = JSON.parse(strictB64u(parts[0]));
  assert(canonical(header) === canonical({ alg: "EdDSA", kid: jwk.kid, typ }), `${typ} protected header mismatch`);
  assert(parts[0] === b64u(Buffer.from(canonical(header))), `${typ} protected header is not canonical`);
  const input = Buffer.from(`${parts[0]}.${b64u(Buffer.from(canonical(payload)))}`);
  assert(verify(null, input, createPublicKey({ key: jwk, format: "jwk" }), strictB64u(parts[2])), `${typ} signature invalid`);
}

function compactJws(payload, privateJwk) {
  const header = { alg: "EdDSA", kid: privateJwk.kid, typ: "native-request-proof+jws" };
  const first = b64u(Buffer.from(canonical(header)));
  const second = b64u(Buffer.from(canonical(payload)));
  const signature = sign(null, Buffer.from(`${first}.${second}`), createPrivateKey({ key: privateJwk, format: "jwk" }));
  return `${first}.${second}.${b64u(signature)}`;
}

function detachedJws(payload, privateJwk, typ) {
  const header = { alg: "EdDSA", kid: privateJwk.kid, typ };
  const first = b64u(Buffer.from(canonical(header)));
  const payloadPart = b64u(Buffer.from(canonical(payload)));
  const signature = sign(null, Buffer.from(`${first}.${payloadPart}`), createPrivateKey({ key: privateJwk, format: "jwk" }));
  return `${first}..${b64u(signature)}`;
}

function fixtureReader(root) {
  const boundary = `${resolve(root)}${sep}`;
  return (relative) => {
    const target = resolve(root, relative);
    assert(target.startsWith(boundary), `fixture path escaped the published profile: ${relative}`);
    return JSON.parse(readFileSync(target, "utf8"));
  };
}

function rawFixtureReader(root) {
  const boundary = `${resolve(root)}${sep}`;
  return (relative) => {
    const target = resolve(root, relative);
    assert(target.startsWith(boundary), `fixture path escaped the published profile: ${relative}`);
    return readFileSync(target);
  };
}

function publicJwk(jwk) {
  const { d: _private, ...publicMembers } = jwk;
  return publicMembers;
}

async function main() {
  for (const name of requiredEnvironment) assert(process.env[name], `missing ${name}`);
  const profile = process.env.NATIVE_FEDERATION_PROFILE;
  assert(profile === "native-fed/experimental-jose-hpke-1", `unsupported profile ${profile}`);
  const clock = process.env.NATIVE_FEDERATION_CLOCK;
  const now = new Date(clock);
  assert(Number.isFinite(now.getTime()), "invalid conformance clock");
  const fixtureRoot = resolve(process.env.NATIVE_FEDERATION_FIXTURE_ROOT);
  const manifestPath = resolve(process.env.NATIVE_FEDERATION_MANIFEST);
  const signingPath = resolve(process.env.NATIVE_FEDERATION_REQUEST_PROOF_SIGNING);
  assert(manifestPath === resolve(fixtureRoot, "fixtures/manifest.json"), "manifest is outside the published profile contract");
  assert(signingPath.startsWith(`${fixtureRoot}${sep}`), "request-proof fixture is outside the published profile");
  const load = fixtureReader(fixtureRoot);
  const raw = rawFixtureReader(fixtureRoot);
  const proofFixture = JSON.parse(readFileSync(signingPath, "utf8"));
  assert(/^FIXTURE PRIVATE KEYS ONLY/.test(proofFixture.warning), "refusing non-fixture request-proof material");
  const verificationKeys = load("fixtures/verification-keys.json");
  const directoryUrl = strictServiceUrl(process.env.NATIVE_FEDERATION_DIRECTORY_URL);
  const relayUrl = strictServiceUrl(process.env.NATIVE_FEDERATION_RELAY_URL);
  const descriptorUrl = strictServiceUrl(process.env.NATIVE_FEDERATION_NETWORK_DESCRIPTOR_URL, true);
  const directoryAudience = process.env.NATIVE_FEDERATION_DIRECTORY_AUDIENCE;
  const relayAudience = process.env.NATIVE_FEDERATION_RELAY_AUDIENCE;
  assert(directoryAudience === directoryUrl && relayAudience === relayUrl, "configured audiences do not match service origins");
  const corpus = evaluateManifest(JSON.parse(readFileSync(manifestPath, "utf8")), clock, load, raw);

  let requests = 0;
  async function call(baseUrl, path, { method = "GET", body, signerName, operation, headers = {} } = {}) {
    requests += 1;
    const rawBody = body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body));
    const requestHeaders = { ...(body === undefined ? {} : { "content-type": "application/vnd.native.federation+json" }), ...headers };
    if (signerName) {
      const signer = proofFixture.signers[signerName];
      assert(signer, `unknown public fixture signer ${signerName}`);
      const createdAt = now.toISOString().replace(".000Z", "Z");
      const proof = {
        protocol_version: "1.0",
        operation,
        aud: baseUrl === directoryUrl ? directoryAudience : relayAudience,
        principal: signer.principal,
        installation_id: signer.installation_id,
        request_id: randomUUID(),
        body_digest: digestBytes(rawBody),
        created_at: createdAt,
        expires_at: new Date(now.getTime() + 300_000).toISOString().replace(".000Z", "Z"),
        nonce: b64u(randomBytes(16)),
      };
      requestHeaders.Authorization = `NativeJWS ${compactJws(proof, signer.jwk)}`;
    }
    const response = await fetch(`${baseUrl}${path}`, {
      method,
      headers: requestHeaders,
      redirect: "error",
      signal: AbortSignal.timeout(5_000),
      ...(body === undefined ? {} : { body: rawBody }),
    });
    const responseBytes = Buffer.from(await response.arrayBuffer());
    return { status: response.status, headers: response.headers, body: responseBytes.length ? parseIJsonBytes(responseBytes) : null };
  }

  const descriptorResponse = await fetch(descriptorUrl, { redirect: "error", signal: AbortSignal.timeout(5_000) });
  assert(descriptorResponse.status === 200, `descriptor returned HTTP ${descriptorResponse.status}`);
  const network = parseIJsonBytes(Buffer.from(await descriptorResponse.arrayBuffer()));
  validateNetwork(network, clock, load);
  assert(network.descriptor.profile_preference.includes(profile), "descriptor does not prefer the requested profile");
  assert(network.descriptor.directory_base_url === directoryUrl, "descriptor directory URL differs from explicit configuration");
  assert(network.descriptor.relay_base_urls.includes(relayUrl), "descriptor relay URL differs from explicit configuration");
  assert(canonical(network.descriptor.authority_keys[0].jwk) === canonical(verificationKeys.authority), "descriptor authority is not the fixture trust anchor");
  verifyDetached(network.descriptor, network.signature, verificationKeys.authority, "native-network-descriptor+jws");
  const relayVerification = network.descriptor.relay_keys.find((entry) => entry.status === "active" && new Date(entry.not_before) <= now && (!entry.not_after || now < new Date(entry.not_after)));
  assert(relayVerification, "descriptor has no active relay verification key");

  const aliasBody = { operation: "directory.alias.resolve", protocol_version: "1.0", system: "email", normalization: "native.email-ascii-v1", value: "Alice@example.com" };
  const alias = await call(directoryUrl, "/v1/aliases:resolve", { method: "POST", body: aliasBody });
  assert(alias.status === 200 && alias.headers.get("cache-control") === "no-store", "alias resolution failed or was cacheable");
  const principal = alias.body.principal_document;
  validatePrincipal(principal, clock, load, network);
  assert(principal.document.network_id === "native" && principal.document.principal_id === "alice0001", "alias resolved to the wrong principal");
  const relayEndpoints = principal.document.delivery_endpoints.filter((entry) => entry.kind === "relay").sort((a, b) => a.priority - b.priority);
  assert(relayEndpoints[0]?.url === `${relayUrl}/v1`, "resolved principal did not bind the configured relay endpoint");
  const signingKey = principal.document.operational_keys.find((entry) => entry.purpose === "signing" && entry.status === "active")?.jwk;
  verifyDetached(principal.document, principal.principal_signature, signingKey, "native-principal+jws");
  assert(principal.authority_attestation.statement.document_digest === digestValue(principal.document), "principal authority digest mismatch");
  assert(principal.authority_attestation.statement.directory_base_url === directoryUrl, "principal attestation did not bind the configured directory");
  verifyDetached(principal.authority_attestation.statement, principal.authority_attestation.signature, verificationKeys.authority, "native-principal-attestation+jws");

  const recipientResponse = await call(directoryUrl, "/v1/principals/bob00001");
  assert(recipientResponse.status === 200, `recipient principal returned HTTP ${recipientResponse.status}`);
  const recipient = recipientResponse.body;
  validatePrincipal(recipient, clock, load, network);
  const recipientAddress = { network_id: recipient.document.network_id, principal_id: recipient.document.principal_id };
  assert(canonical(recipientAddress) === canonical({ network_id: "native", principal_id: "bob00001" }), "directory returned the wrong recipient principal");
  const recipientEncryption = recipient.document.operational_keys.filter((entry) => entry.purpose === "encryption" && entry.status === "active"
    && new Date(entry.not_before) <= now && (!entry.not_after || now < new Date(entry.not_after))
    && (!entry.revocation || now < new Date(entry.revocation.effective_at)))
    .sort((left, right) => Date.parse(right.not_before) - Date.parse(left.not_before) || left.jwk.kid.localeCompare(right.jwk.kid))[0];
  assert(recipientEncryption, "recipient has no active encryption key at the send time");
  const recipientRelays = recipient.document.delivery_endpoints.filter((entry) => entry.kind === "relay").sort((a, b) => a.priority - b.priority);
  const recipientRelayEndpoint = strictServiceUrl(recipientRelays[0]?.url, true);
  const parsedRecipientRelay = new URL(recipientRelayEndpoint);
  assert(parsedRecipientRelay.pathname === "/v1" && parsedRecipientRelay.origin === relayUrl, "recipient principal did not authority-bind the configured relay endpoint");
  const recipientRelayUrl = parsedRecipientRelay.origin;

  const negotiationBody = { operation: "directory.negotiate", protocol_version: "1.0", profiles: [profile], capabilities: [], required_capabilities: [] };
  const negotiation = await call(directoryUrl, "/v1/profiles:negotiate", { method: "POST", body: negotiationBody });
  assert(negotiation.status === 200 && negotiation.body.result.selected_profile === profile, "profile negotiation failed");
  verifyDetached(negotiation.body.result, negotiation.body.signature, verificationKeys.authority, "native-profile-negotiation+jws");

  const structuralEnvelope = load("fixtures/positive/envelope-one-recipient.json").envelope;
  assert(canonical(structuralEnvelope.recipients[0].principal) === canonical(recipientAddress)
    && structuralEnvelope.recipients[0].encryption_key_id === recipientEncryption.jwk.kid,
  "the provisional structural HPKE fixture does not cover the resolved recipient key");
  const envelopeValue = structuredClone(structuralEnvelope);
  envelopeValue.envelope_id = randomUUID();
  envelopeValue.recipients = [{ principal: recipientAddress, encryption_key_id: recipientEncryption.jwk.kid }];
  envelopeValue.jwe.recipients[0].header.kid = recipientEncryption.jwk.kid;
  const encryptionContext = Object.fromEntries(Object.entries(envelopeValue).filter(([key]) => key !== "jwe" && key !== "ciphertext_digest"));
  envelopeValue.jwe.aad = b64u(Buffer.from(canonical(encryptionContext)));
  const envelope = {
    envelope: envelopeValue,
    signature: detachedJws(envelopeValue, proofFixture.signers.alice_signing.jwk, "native-envelope+jws"),
  };
  const submitBody = { operation: "relay.submit", envelope };
  const submitted = await call(recipientRelayUrl, "/v1/envelopes", { method: "POST", signerName: "alice_signing", operation: "relay.submit", body: submitBody });
  assert(submitted.status === 200 && submitted.body.results?.length === 1, `relay submit failed with HTTP ${submitted.status}`);
  assert(submitted.body.envelope_digest === digestValue(envelope), "relay returned the wrong envelope digest");
  const queuedExpected = {
    relay_key_id: submitted.body.results[0].receipt.receipt.relay_key_id,
    recipient: submitted.body.results[0].recipient,
    state: "queued",
    delivery_id: submitted.body.results[0].delivery_id,
    envelope_id: envelope.envelope.envelope_id,
    envelope_digest: submitted.body.envelope_digest,
  };
  validateReceiptSemantics(submitted.body.results[0].receipt, load, queuedExpected, network, clock);

  const mailbox = proofFixture.signers.bob_installation.installation_id;
  const collectBody = { operation: "relay.collect", limit: 100, wait_seconds: 0 };
  const collected = await call(relayUrl, `/v1/mailboxes/${mailbox}:collect`, { method: "POST", signerName: "bob_installation", operation: "relay.collect", body: collectBody });
  assert(collected.status === 200 && collected.body.deliveries?.length === 1, "relay collection did not return one delivery");
  const delivery = collected.body.deliveries[0];
  assert(delivery.envelope_digest === submitted.body.envelope_digest, "collected delivery digest mismatch");
  validateReceiptSemantics(delivery.queued_receipt, load, queuedExpected, network, clock);
  if (delivery.collected_receipt) validateReceiptSemantics(delivery.collected_receipt, load, {
    ...queuedExpected,
    state: "collected",
    previous_state: "queued",
    collector_installation_id: mailbox,
  }, network, clock);
  const ackBody = {
    operation: "relay.acknowledge",
    acknowledgements: [{
      delivery_id: delivery.delivery_id,
      envelope_id: delivery.envelope.envelope.envelope_id,
      envelope_digest: delivery.envelope_digest,
      lease_token: delivery.lease_token,
      disposition: "received",
    }],
  };
  const acked = await call(relayUrl, `/v1/mailboxes/${mailbox}/acknowledgements`, { method: "POST", signerName: "bob_installation", operation: "relay.acknowledge", body: ackBody });
  assert(acked.status === 200 && acked.body.receipts?.length === 1, "relay acknowledgement failed");
  validateReceiptSemantics(acked.body.receipts[0], load, {
    ...queuedExpected,
    state: "acknowledged",
    previous_state: "collected",
    collector_installation_id: mailbox,
  }, network, clock);

  return {
    status: "pass",
    implementation: "native-federation-clean-room-node-1",
    profile,
    isolation: "node-standard-library+published-profile-only",
    configured_origins: { directory: directoryUrl, relay: relayUrl },
    checks: ["manifest-corpus", "descriptor", "endpoint-binding", "alias", "sender-principal", "recipient-principal", "principal-jws", "negotiation", "outer-envelope-signing", "submit", "receipt-jws", "collect", "acknowledge"],
    requests,
    credentials: "deterministic-public-fixture-keys-only",
    corpus,
  };
}

try {
  process.stdout.write(`${JSON.stringify(await main())}\n`);
} catch (error) {
  process.stdout.write(`${JSON.stringify({ status: "fail", implementation: "native-federation-clean-room-node-1", error: error.message })}\n`);
  process.exitCode = 1;
}
