#!/usr/bin/env node

// Independently replaceable directory and relay built from the published wire
// contract. This is intentionally not an import of the Native conformance
// runner: interoperability must cross an HTTP/process boundary.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseIJsonBytes, validateEnvelope as validatePublicEnvelope, validateIJson } from "./clean-room-core.mjs";

const profile = "native-fed/experimental-jose-hpke-1";
const defaultClock = "2026-08-02T09:10:00Z";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function failure(code, message) {
  return Object.assign(new Error(message ?? code), { code });
}

function proofAssert(condition, code, message) {
  if (!condition) throw failure(code, message);
}

function assertClosed(value, allowed, required, path) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${path} must be an object`);
  assert(Object.keys(value).every((key) => allowed.includes(key)), `${path} has an unknown member`);
  assert(required.every((key) => Object.hasOwn(value, key)), `${path} is missing a required member`);
}

function jcs(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    assert(Number.isSafeInteger(value), "JCS only accepts safe integers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(",")}}`;
  throw new Error(`unsupported JCS value ${typeof value}`);
}

const b64u = (value) => Buffer.from(value).toString("base64url");
const sha = (value) => createHash("sha256").update(value).digest();
const digestBytes = (value) => `sha-256:${b64u(sha(value))}`;
const digestValue = (value) => digestBytes(Buffer.from(jcs(value)));

function deterministic(label, length) {
  const chunks = [];
  for (let counter = 0; Buffer.concat(chunks).length < length; counter += 1) chunks.push(sha(Buffer.from(`${label}:${counter}`)));
  return Buffer.concat(chunks).subarray(0, length);
}

function privateKey(label) {
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({ key: Buffer.concat([prefix, deterministic(`native-fed-fixture:${label}`, 32)]), format: "der", type: "pkcs8" });
}

function detached(payload, key, kid, typ) {
  const headerPart = b64u(Buffer.from(jcs({ alg: "EdDSA", kid, typ })));
  const payloadPart = b64u(Buffer.from(jcs(payload)));
  return `${headerPart}..${b64u(sign(null, Buffer.from(`${headerPart}.${payloadPart}`), key))}`;
}

function strictB64u(value) {
  assert(typeof value === "string" && /^[A-Za-z0-9_-]+$/.test(value), "invalid base64url");
  const bytes = Buffer.from(value, "base64url");
  assert(b64u(bytes) === value, "non-canonical base64url");
  return bytes;
}

function verifyDetached(payload, compact, jwk, typ) {
  const parts = compact?.split(".") ?? [];
  assert(parts.length === 3 && parts[1] === "", "invalid detached JWS");
  const header = JSON.parse(strictB64u(parts[0]));
  assert(jcs(header) === jcs({ alg: "EdDSA", kid: jwk.kid, typ }), "detached JWS header mismatch");
  const input = Buffer.from(`${parts[0]}.${b64u(Buffer.from(jcs(payload)))}`);
  assert(verify(null, input, createPublicKey({ key: jwk, format: "jwk" }), strictB64u(parts[2])), "detached JWS signature invalid");
}

function stableUuid(label) {
  const bytes = Buffer.from(sha(Buffer.from(label)).subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function withoutPrivate(jwk) {
  const { d: _private, ...publicJwk } = jwk;
  return publicJwk;
}

function servicePublicJwk(label, purpose) {
  const exported = createPublicKey(privateKey(label)).export({ format: "jwk" });
  const jwk = { ...exported, alg: "EdDSA", use: "sig" };
  jwk.kid = `n1.${purpose}.${b64u(sha(Buffer.from(jcs({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }))))}`;
  return jwk;
}

function fixtureLoader(root) {
  const boundary = `${resolve(root)}${sep}`;
  return (relative) => {
    const target = resolve(root, relative);
    assert(target.startsWith(boundary), `fixture path escaped profile: ${relative}`);
    return JSON.parse(readFileSync(target, "utf8"));
  };
}

async function readBody(req) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    assert(bytes <= 1_048_576, "payload_too_large");
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks);
  return { raw, body: raw.length ? parseIJsonBytes(raw) : null };
}

function response(res, status, body, requestId, headers = {}) {
  res.writeHead(status, {
    "content-type": status >= 400 ? "application/problem+json" : "application/vnd.native.federation+json",
    "Native-Request-Id": requestId,
    ...headers,
  });
  res.end(body === null ? "" : `${JSON.stringify(body)}\n`);
}

function rawResponse(res, status, body, requestId, headers = {}) {
  res.writeHead(status, {
    "content-type": "application/vnd.native.federation+json",
    "Native-Request-Id": requestId,
    ...headers,
  });
  res.end(`${body}\n`);
}

function problem(code, requestId, status) {
  return { type: `urn:native:federation:error:${code}`, title: code.replaceAll("_", " "), status, code, request_id: requestId, retryable: false };
}

function listen(server) {
  return new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolveListen(`http://127.0.0.1:${server.address().port}`));
  });
}

async function main() {
  const scriptRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
  const fixtureRoot = resolve(process.env.NATIVE_FEDERATION_FIXTURE_ROOT ?? scriptRoot);
  const clock = process.env.NATIVE_FEDERATION_CLOCK ?? defaultClock;
  let currentNowMs = new Date(clock).getTime();
  assert(Number.isFinite(currentNowMs), "invalid conformance clock");
  const fault = process.env.NATIVE_FEDERATION_INTEROP_FAULT ?? "";
  const load = fixtureLoader(fixtureRoot);
  const keys = load("fixtures/verification-keys.json");
  const principals = load("fixtures/request-proof-signing.json");
  assert(/^FIXTURE PRIVATE KEYS ONLY/.test(principals.warning), "replacement services require published fixture keys");
  const alice = load("fixtures/positive/principal-document.json");
  let servedAlice = alice;
  const bob = principals.principals.bob;
  let servedBob = bob;
  const carol = principals.principals.carol;
  let servedCarol = carol;
  const authorityPrivate = privateKey("native-authority");
  const relayPrivate = privateKey("native-relay");
  const callers = new Map(Object.values(principals.signers).map((entry) => [entry.jwk.kid, { ...entry, jwk: withoutPrivate(entry.jwk) }]));
  const authorizations = new Map();
  for (const principalWrapper of Object.values(principals.principals)) {
    const document = principalWrapper.document;
    const principal = { network_id: document.network_id, principal_id: document.principal_id };
    for (const record of document.operational_keys.filter((entry) => entry.purpose === "signing")) {
      authorizations.set(record.jwk.kid, { principal, installation_id: null, status: record.status, not_before: record.not_before, not_after: record.not_after, scopes: ["relay.submit"] });
    }
    for (const installation of document.installations) {
      authorizations.set(installation.jwk.kid, { principal, installation_id: installation.installation_id, status: installation.status, not_before: document.issued_at, not_after: document.hard_expires_at, scopes: installation.scopes });
    }
  }
  const seenNonces = new Set();
  const seenRequestBodies = new Map();
  let sequence = 0;
  let directoryUrl;
  let relayUrl;
  let descriptor;

  function verifyProof(req, rawBody, operation, audience, expectedPrincipal, expectedInstallation) {
    const authorization = /^NativeJWS ([A-Za-z0-9._-]+)$/.exec(req.headers.authorization ?? "");
    proofAssert(authorization, "unauthorized", "missing request proof");
    const parts = authorization[1].split(".");
    proofAssert(parts.length === 3 && parts.every(Boolean), "unauthorized", "invalid request proof framing");
    let header;
    let payload;
    try {
      header = JSON.parse(strictB64u(parts[0]));
      payload = JSON.parse(strictB64u(parts[1]));
    } catch { throw failure("unauthorized", "invalid request proof encoding"); }
    try {
      validateIJson(header);
      validateIJson(payload);
    } catch { throw failure("unauthorized", "request proof exceeds I-JSON bounds"); }
    proofAssert(jcs(header) === jcs({ alg: "EdDSA", kid: header.kid, typ: "native-request-proof+jws" }), "unauthorized", "invalid request proof header");
    proofAssert(parts[0] === b64u(Buffer.from(jcs(header))) && parts[1] === b64u(Buffer.from(jcs(payload))), "unauthorized", "request proof is not canonical");
    const caller = callers.get(header.kid);
    proofAssert(caller, "unauthorized", "unknown request proof key");
    let signatureValid = false;
    try { signatureValid = verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), createPublicKey({ key: caller.jwk, format: "jwk" }), strictB64u(parts[2])); } catch {}
    proofAssert(signatureValid, "unauthorized", "request proof signature invalid");
    const exactPayload = {
      protocol_version: "1.0", operation, aud: audience, principal: expectedPrincipal, installation_id: expectedInstallation,
      request_id: payload.request_id, body_digest: digestBytes(rawBody), created_at: payload.created_at,
      expires_at: payload.expires_at, nonce: payload.nonce,
    };
    proofAssert(jcs(payload) === jcs(exactPayload), "unauthorized", "request proof binding or member closure mismatch");
    proofAssert(jcs(caller.principal) === jcs(payload.principal) && caller.installation_id === payload.installation_id, "forbidden", "request proof signer identity is outside the requested principal or installation");
    const authority = authorizations.get(header.kid);
    const authorityNotBefore = Date.parse(authority?.not_before);
    const authorityNotAfter = authority?.not_after === undefined ? Infinity : Date.parse(authority.not_after);
    proofAssert(authority && jcs(authority.principal) === jcs(payload.principal) && authority.installation_id === payload.installation_id
      && authority.status === "active" && authority.scopes.includes(operation)
      && authorityNotBefore <= currentNowMs && currentNowMs < authorityNotAfter,
    "forbidden", "request proof key is outside the operation scope");
    proofAssert(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(payload.request_id), "unauthorized", "invalid request id");
    const canonicalTimestamp = (value) => {
      if (typeof value !== "string" || !/^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/.test(value)) return NaN;
      const milliseconds = Date.parse(value);
      return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString().replace(".000Z", "Z") === value ? milliseconds : NaN;
    };
    const created = canonicalTimestamp(payload.created_at);
    const expires = canonicalTimestamp(payload.expires_at);
    proofAssert(Number.isFinite(created) && Number.isFinite(expires) && created <= currentNowMs && currentNowMs < expires && expires - created <= 300_000, "unauthorized", "request proof expired or invalid");
    let nonceBytes;
    try { nonceBytes = strictB64u(payload.nonce); } catch { throw failure("unauthorized", "invalid request proof nonce"); }
    proofAssert(payload.nonce.length === 22 && nonceBytes.length === 16, "unauthorized", "request proof nonce must encode 16 octets");
    const requestKey = `${header.kid}:${payload.request_id}`;
    const priorBody = seenRequestBodies.get(requestKey);
    proofAssert(priorBody === undefined || priorBody === payload.body_digest, "idempotency_conflict", "request id reused with another body");
    proofAssert(!seenNonces.has(`${header.kid}:${payload.nonce}`), "idempotency_conflict", "request proof nonce replay");
    seenRequestBodies.set(requestKey, payload.body_digest);
    seenNonces.add(`${header.kid}:${payload.nonce}`);
    return payload.request_id;
  }

  const directoryServer = createServer(async (req, res) => {
    sequence += 1;
    let requestId = stableUuid(`replacement-directory-request:${sequence}`);
    try {
      const url = new URL(req.url, directoryUrl);
      const { body } = await readBody(req);
      if (body !== null) validateIJson(body);
      if (req.method === "GET" && url.pathname === "/v1/network") {
        const encoded = JSON.stringify(descriptor);
        if (fault === "duplicate_response_root") return rawResponse(res, 200, `{"wire_hint":1,"wire_hint":2,${encoded.slice(1)}`, requestId);
        if (fault === "duplicate_response_nested") {
          const duplicate = encoded.replace('"extensions":{}', '"extensions":{"wire.hint":1,"wire.hint":2}');
          assert(duplicate !== encoded, "failed to construct nested duplicate response");
          return rawResponse(res, 200, duplicate, requestId);
        }
        if (fault === "decimal_response" || fault === "exponent_response") {
          const replacement = fault === "decimal_response" ? '"future_integer":1.0' : '"future_integer":1e0';
          const nonInteger = encoded.replace('"future_integer":1', replacement);
          assert(nonInteger !== encoded, "failed to construct non-integer response lexeme");
          return rawResponse(res, 200, nonInteger, requestId);
        }
        return response(res, 200, descriptor, requestId);
      }
      const principalMatch = url.pathname.match(/^\/v1\/principals\/([^/]+)$/);
      if (req.method === "GET" && principalMatch) {
        const principal = principalMatch[1] === "alice0001" ? servedAlice : principalMatch[1] === "bob00001" ? servedBob : principalMatch[1] === "carol001" ? servedCarol : null;
        if (!principal) return response(res, 404, problem("unknown_principal", requestId, 404), requestId);
        const etag = `\"pd-${digestValue(principal.document).slice(8)}\"`;
        const headers = { ETag: etag, "Cache-Control": "public, max-age=300, must-revalidate" };
        return response(res, req.headers["if-none-match"] === etag ? 304 : 200, req.headers["if-none-match"] === etag ? null : principal, requestId, headers);
      }
      if (req.method === "POST" && url.pathname === "/v1/aliases:resolve") {
        if (body?.operation !== "directory.alias.resolve" || body.protocol_version !== "1.0") return response(res, 400, problem("invalid_request", requestId, 400), requestId, { "Cache-Control": "no-store" });
        if (body.system !== "email" || body.normalization !== "native.email-ascii-v1" || body.value !== "Alice@example.com") return response(res, 404, problem("unknown_alias", requestId, 404), requestId, { "Cache-Control": "no-store" });
        return response(res, 200, { operation: "directory.alias.resolve.result", principal_document: servedAlice, matched_alias: servedAlice.document.verified_aliases[0] }, requestId, { "Cache-Control": "no-store" });
      }
      if (req.method === "POST" && url.pathname === "/v1/profiles:negotiate") {
        if (body?.operation !== "directory.negotiate" || !body.profiles?.includes(profile)) return response(res, 406, problem("unsupported_profile", requestId, 406), requestId);
        const result = { operation: "directory.negotiate.result", protocol_version: "1.0", selected_profile: profile, capabilities: ["native.relay.receipts"], unsupported_required_capabilities: [], fresh_until: "2026-08-02T09:15:00Z" };
        return response(res, 200, { result, signature: detached(result, authorityPrivate, keys.authority.kid, "native-profile-negotiation+jws") }, requestId);
      }
      return response(res, 404, problem("invalid_request", requestId, 404), requestId);
    } catch (error) {
      const code = error.message === "payload_too_large" ? "payload_too_large" : "invalid_request";
      const status = code === "payload_too_large" ? 413 : 400;
      return response(res, status, problem(code, requestId, status), requestId);
    }
  });

  const mailboxByPrincipal = new Map([
    ["native/bob00001", "00000000-0000-4000-8000-000000000201"],
    ...(process.env.NATIVE_FEDERATION_INTEROP_DISABLE_CAROL_MAILBOX === "1" ? [] : [["native/carol001", "00000000-0000-4000-8000-000000000202"]]),
  ]);
  const deliveries = new Map();
  function signedReceipt(delivery, state, previousState) {
    const receipt = {
      receipt_type: "native.relay.delivery-receipt",
      protocol_version: "1.0",
      profile,
      receipt_id: stableUuid(`replacement-receipt:${delivery.delivery_id}:${state}`),
      relay_id: "clean-room-replacement-relay",
      relay_key_id: keys.relay.kid,
      delivery_id: delivery.delivery_id,
      envelope_id: delivery.envelope.envelope.envelope_id,
      envelope_digest: delivery.envelope_digest,
      recipient: delivery.recipient,
      ...(previousState ? { previous_state: previousState } : {}),
      state,
      observed_at: new Date(currentNowMs).toISOString().replace(".000Z", "Z"),
      ...(["collected", "acknowledged"].includes(state) ? { collector_installation_id: delivery.mailbox } : {}),
    };
    if (fault === "receipt_missing_id") delete receipt.receipt_id;
    if (fault === "receipt_bad_version") receipt.protocol_version = "2.0";
    if (fault === "receipt_bad_timestamp") receipt.observed_at = "2026-02-31T09:10:00Z";
    if (fault === "receipt_bad_delivery_id") receipt.delivery_id = "not-a-uuid";
    if (fault === "receipt_optional_field") receipt.future_relay_hint = { version: 1, opaque: true };
    return { receipt, signature: detached(receipt, relayPrivate, keys.relay.kid, "native-relay-receipt+jws") };
  }

  const relayServer = createServer(async (req, res) => {
    sequence += 1;
    let requestId = stableUuid(`replacement-relay-request:${sequence}`);
    try {
      const url = new URL(req.url, relayUrl);
      const { raw, body } = await readBody(req);
      if (body !== null) validateIJson(body);
      if (req.method === "POST" && url.pathname === "/v1/envelopes") {
        assertClosed(body, ["operation", "envelope"], ["operation", "envelope"], "relay submission");
        assert(body.operation === "relay.submit", "invalid relay submission");
        requestId = verifyProof(req, raw, "relay.submit", relayUrl, body.envelope.envelope.sender_principal, null);
        const envelope = body.envelope;
        validatePublicEnvelope(envelope, new Date(currentNowMs).toISOString().replace(".000Z", "Z"), load, {
          network: descriptor,
          principals: [servedAlice, servedBob, servedCarol],
        });
        const envelopeDigest = digestValue(envelope);
        const plan = envelope.envelope.recipients.map((recipient) => {
          const binding = `${recipient.principal.network_id}/${recipient.principal.principal_id}`;
          const mailbox = mailboxByPrincipal.get(binding);
          assert(mailbox, `unknown recipient ${binding}`);
          const deliveryId = stableUuid(`replacement-delivery:${envelope.envelope.envelope_id}:${binding}`);
          const existing = deliveries.get(deliveryId);
          if (existing) assert(existing.envelope_digest === envelopeDigest, "idempotency conflict");
          return { recipient, binding, mailbox, deliveryId, existing };
        });
        const results = plan.map(({ recipient, mailbox, deliveryId, existing }) => {
          let delivery = existing;
          if (!delivery) {
            delivery = { delivery_id: deliveryId, envelope, envelope_digest: envelopeDigest, recipient: recipient.principal, mailbox, state: "queued", attempt: 0 };
            delivery.queued_receipt = signedReceipt(delivery, "queued");
            deliveries.set(deliveryId, delivery);
          }
          return { recipient: recipient.principal, outcome: "queued", delivery_id: deliveryId, receipt: delivery.queued_receipt };
        });
        return response(res, 200, { operation: "relay.submit.result", envelope_id: envelope.envelope.envelope_id, envelope_digest: envelopeDigest, results }, requestId);
      }
      const collect = url.pathname.match(/^\/v1\/mailboxes\/([^/]+):collect$/);
      if (req.method === "POST" && collect) {
        assertClosed(body, ["operation", "cursor", "limit", "wait_seconds"], ["operation", "limit", "wait_seconds"], "relay collection");
        assert(body.operation === "relay.collect" && Number.isInteger(body.limit) && body.limit >= 1 && body.limit <= 100
          && Number.isInteger(body.wait_seconds) && body.wait_seconds >= 0 && body.wait_seconds <= 30
          && (body.cursor === undefined || (typeof body.cursor === "string" && body.cursor.length <= 512)), "invalid collect operation");
        const authority = [...authorizations.values()].find((entry) => entry.installation_id === collect[1]);
        assert(authority, "unknown mailbox");
        requestId = verifyProof(req, raw, "relay.collect", relayUrl, authority.principal, collect[1]);
        const advance = req.headers["native-conformance-advance-seconds"];
        if (advance !== undefined) {
          assert(typeof advance === "string" && /^[1-9][0-9]{0,3}$/.test(advance) && Number(advance) <= 3600, "invalid clock advance");
          currentNowMs += Number(advance) * 1000;
        }
        const selected = [...deliveries.values()].filter((delivery) => delivery.mailbox === collect[1]
          && (delivery.state === "queued" || (delivery.state === "collected" && delivery.lease_expires_at <= currentNowMs))).slice(0, body.limit);
        const returned = selected.map((delivery) => {
          const firstCollection = delivery.state === "queued";
          delivery.state = "collected";
          delivery.attempt += 1;
          delivery.lease_token = b64u(deterministic(`replacement-lease:${delivery.delivery_id}:${delivery.attempt}`, 24));
          delivery.lease_expires_at = currentNowMs + 300_000;
          if (firstCollection) delivery.collected_receipt = signedReceipt(delivery, "collected", "queued");
          return { delivery_id: delivery.delivery_id, envelope_digest: delivery.envelope_digest, envelope: delivery.envelope, state: "collected", attempt: delivery.attempt, lease_token: delivery.lease_token, lease_expires_at: new Date(delivery.lease_expires_at).toISOString().replace(".000Z", "Z"), queued_receipt: delivery.queued_receipt, ...(firstCollection ? { collected_receipt: delivery.collected_receipt } : {}) };
        });
        return response(res, 200, { operation: "relay.collect.result", cursor: b64u(Buffer.from(`replacement-cursor:${sequence}`)), deliveries: returned }, requestId);
      }
      const acknowledge = url.pathname.match(/^\/v1\/mailboxes\/([^/]+)\/acknowledgements$/);
      if (req.method === "POST" && acknowledge) {
        assertClosed(body, ["operation", "acknowledgements"], ["operation", "acknowledgements"], "relay acknowledgement");
        assert(body.operation === "relay.acknowledge" && Array.isArray(body.acknowledgements)
          && body.acknowledgements.length >= 1 && body.acknowledgements.length <= 100, "invalid acknowledge operation");
        for (const entry of body.acknowledgements) {
          assertClosed(entry, ["delivery_id", "envelope_id", "envelope_digest", "lease_token", "disposition"], ["delivery_id", "envelope_id", "envelope_digest", "lease_token", "disposition"], "acknowledgement entry");
          assert(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(entry.delivery_id)
            && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(entry.envelope_id)
            && /^sha-256:[A-Za-z0-9_-]{43}$/.test(entry.envelope_digest)
            && typeof entry.lease_token === "string" && entry.lease_token.length >= 22 && entry.lease_token.length <= 256 && /^[A-Za-z0-9_-]+$/.test(entry.lease_token)
            && entry.disposition === "received", "invalid acknowledgement entry");
        }
        const authority = [...authorizations.values()].find((entry) => entry.installation_id === acknowledge[1]);
        assert(authority, "unknown mailbox");
        requestId = verifyProof(req, raw, "relay.acknowledge", relayUrl, authority.principal, acknowledge[1]);
        const plan = body.acknowledgements.map((entry) => {
          const delivery = deliveries.get(entry.delivery_id);
          assert(delivery && delivery.mailbox === acknowledge[1], "delivery is not collectable by this mailbox");
          assert(entry.envelope_id === delivery.envelope.envelope.envelope_id && entry.envelope_digest === delivery.envelope_digest && entry.lease_token === delivery.lease_token && entry.disposition === "received", "acknowledgement tuple mismatch");
          assert(delivery.state === "acknowledged" || delivery.state === "collected", "delivery is not in a collected state");
          return delivery;
        });
        const receipts = plan.map((delivery) => {
          if (delivery.state === "acknowledged") return delivery.acknowledged_receipt;
          delivery.state = "acknowledged";
          delivery.acknowledged_receipt = signedReceipt(delivery, "acknowledged", "collected");
          return delivery.acknowledged_receipt;
        });
        return response(res, 200, { operation: "relay.acknowledge.result", receipts }, requestId);
      }
      return response(res, 404, problem("invalid_request", requestId, 404), requestId);
    } catch (error) {
      const protocolStatuses = { expired: 410, unsupported_profile: 406, required_capability_unsupported: 422, recipient_mismatch: 400, malformed_envelope: 400, signature_invalid: 400 };
      const status = error.message === "payload_too_large" ? 413 : error.code === "unauthorized" ? 401 : error.code === "forbidden" ? 403 : error.code === "idempotency_conflict" ? 409 : (protocolStatuses[error.code] ?? 400);
      const code = status === 413 ? "payload_too_large" : (error.code ?? "invalid_request");
      return response(res, status, problem(code, requestId, status), requestId);
    }
  });

  directoryUrl = await listen(directoryServer);
  relayUrl = await listen(relayServer);
  const baseline = load("fixtures/positive/network-descriptor.json");
  descriptor = structuredClone(baseline);
  descriptor.descriptor.directory_base_url = directoryUrl;
  descriptor.descriptor.relay_base_urls = [relayUrl];
  descriptor.descriptor.issued_at = new Date(currentNowMs - 60_000).toISOString().replace(".000Z", "Z");
  descriptor.descriptor.fresh_until = new Date(currentNowMs + 840_000).toISOString().replace(".000Z", "Z");
  descriptor.descriptor.hard_expires_at = new Date(currentNowMs + 86_340_000).toISOString().replace(".000Z", "Z");
  if (fault === "stale_network") {
    descriptor.descriptor.issued_at = new Date(currentNowMs - 1_800_000).toISOString().replace(".000Z", "Z");
    descriptor.descriptor.fresh_until = new Date(currentNowMs - 900_000).toISOString().replace(".000Z", "Z");
    descriptor.descriptor.hard_expires_at = new Date(currentNowMs + 1_200_000).toISOString().replace(".000Z", "Z");
  }
  if (fault === "retired_receipt_key") {
    descriptor.descriptor.relay_keys[0].status = "retired";
    descriptor.descriptor.relay_keys[0].not_after = new Date(currentNowMs - 1_000).toISOString().replace(".000Z", "Z");
    descriptor.descriptor.relay_keys.push({
      jwk: servicePublicJwk("replacement-next-relay", "relay"),
      status: "active",
      not_before: new Date(currentNowMs - 60_000).toISOString().replace(".000Z", "Z"),
      not_after: new Date(currentNowMs + 31_536_000_000).toISOString().replace(".000Z", "Z"),
    });
  }
  if (fault === "compatible_response_names") {
    descriptor.descriptor.future_siblings = [{ repeated: 1 }, { repeated: 2 }];
    descriptor.descriptor.future_text = '\"repeated\":3';
  }
  if (["decimal_response", "exponent_response", "integer_response"].includes(fault)) descriptor.descriptor.future_integer = 1;
  descriptor.signature = detached(descriptor.descriptor, authorityPrivate, keys.authority.kid, "native-network-descriptor+jws");
  const bindRuntimePrincipal = (source, signingLabel, endpointBase = relayUrl) => {
    const wrapper = structuredClone(source);
    wrapper.document.delivery_endpoints = [{ kind: "relay", url: `${endpointBase}/v1`, priority: 0 }];
    wrapper.principal_signature = detached(wrapper.document, privateKey(signingLabel), wrapper.document.operational_keys.find((entry) => entry.purpose === "signing").jwk.kid, "native-principal+jws");
    wrapper.authority_attestation.statement.document_digest = digestValue(wrapper.document);
    wrapper.authority_attestation.statement.directory_base_url = directoryUrl;
    wrapper.authority_attestation.signature = detached(wrapper.authority_attestation.statement, authorityPrivate, keys.authority.kid, "native-principal-attestation+jws");
    return wrapper;
  };
  servedAlice = structuredClone(alice);
  if (fault === "stale_sender") {
    servedAlice.document.issued_at = "2026-08-02T08:40:00Z";
    servedAlice.document.fresh_until = "2026-08-02T08:55:00Z";
    servedAlice.document.hard_expires_at = "2026-08-02T09:30:00Z";
  }
  if (fault === "revoked_sender_key") {
    const signing = servedAlice.document.operational_keys.find((entry) => entry.purpose === "signing" && entry.status === "active");
    signing.status = "revoked";
    signing.revocation = { revoked_at: "2026-08-02T09:01:00Z", effective_at: "2026-08-02T09:02:00Z", reason: "compromised" };
  }
  servedAlice = bindRuntimePrincipal(servedAlice, "alice-signing");
  servedBob = structuredClone(bob);
  if (fault === "stale_recipient") {
    servedBob.document.issued_at = "2026-08-02T08:40:00Z";
    servedBob.document.fresh_until = "2026-08-02T08:55:00Z";
    servedBob.document.hard_expires_at = "2026-08-02T09:30:00Z";
  }
  if (fault === "revoked_recipient_key") {
    const encryption = servedBob.document.operational_keys.find((entry) => entry.purpose === "encryption");
    encryption.status = "revoked";
    encryption.revocation = { revoked_at: "2026-08-02T09:01:00Z", effective_at: "2026-08-02T09:02:00Z", reason: "compromised" };
  }
  servedBob = bindRuntimePrincipal(servedBob, "bob-signing", fault === "recipient_relay_mismatch" ? directoryUrl : relayUrl);
  servedCarol = bindRuntimePrincipal(carol, "carol-signing");

  process.stdout.write(`${JSON.stringify({ status: "ready", implementation: "clean-room-replacement-services-1", profile, directory_url: directoryUrl, relay_url: relayUrl, network_descriptor_url: `${directoryUrl}/v1/network`, isolation: "node-standard-library+published-profile-only", credentials: "deterministic-public-fixture-keys-only" })}\n`);

  await new Promise((resolveStop) => {
    process.once("SIGINT", resolveStop);
    process.once("SIGTERM", resolveStop);
  });
  await Promise.all([
    new Promise((resolveClose) => directoryServer.close(resolveClose)),
    new Promise((resolveClose) => relayServer.close(resolveClose)),
  ]);
}

main().catch((error) => {
  process.stderr.write(`replacement services failed: ${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
