#!/usr/bin/env node

// Credential-free black-box runner for the public experimental federation
// profile. This deliberately verifies only the published structural/JWS
// contract. It never treats FINAL-RFC JOSE-HPKE placeholders as cryptographic
// known-answer vectors.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join, resolve, sep } from "node:path";
import { domainToASCII, fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const profileName = "native-fed/experimental-jose-hpke-1";
const defaultProfileRoot = join(repoRoot, "protocol/federation/experimental-jose-hpke-1");
const profileRoot = process.env.NATIVE_FEDERATION_PROFILE_ROOT
  ? resolve(process.env.NATIVE_FEDERATION_PROFILE_ROOT)
  : defaultProfileRoot;
const defaultClock = "2026-08-02T09:10:00Z";
const schemaBase = "https://spec.withnative.ai/federation/experimental-jose-hpke-1/schemas/";
const conformanceRequire = createRequire(join(defaultProfileRoot, "conformance/package.json"));
let schemaRegistry;
let errorReportClock = defaultClock;

class HarnessFailure extends Error {
  constructor(code, message, cause) {
    super(message, { cause });
    this.name = "HarnessFailure";
    this.code = code;
  }
}

const harnessFailure = (code, message, cause) => new HarnessFailure(code, message, cause);

const help = `Native experimental federation conformance runner

Usage:
  node scripts/federation-conformance.mjs run [options]
  node scripts/federation-conformance.mjs list [options]
  node scripts/federation-conformance.mjs serve [options]
  node scripts/federation-conformance.mjs probe [options]

Options:
  --profile <id>         Exact profile (default: ${profileName})
  --clock <rfc3339>      Deterministic clock (default: ${defaultClock})
  --filter <text,...>    Match fixture ids or validation layers
  --format json|jsonl    Machine-readable output (default: json)
  --adapter <executable> Run an implementation adapter against fake services
  --adapter-arg <value>  Repeatable adapter argument (no shell expansion)
  --adapter-timeout-ms <number> Total adapter startup/run timeout (default: 30000)
  --adapter-output-bytes <number> Maximum bytes per output stream (default: 1048576)
  --adapter-shutdown-timeout-ms <number> Grace before forced termination (default: 2000)
  --host <address>       Fake service bind host (serve only)
  --port <number>        Fake service bind port, 0 selects a free port
  --directory-url <url>  Configured directory base URL (probe only)
  --relay-url <url>      Configured relay base URL (probe; optional serve override)
  --network-descriptor-url <url> Trusted descriptor URL (probe only)
  --request-timeout-ms <number> External request deadline (probe; default: 5000)

The adapter receives NATIVE_FEDERATION_PROFILE, NATIVE_FEDERATION_CLOCK,
NATIVE_FEDERATION_DIRECTORY_URL, NATIVE_FEDERATION_RELAY_URL and
NATIVE_FEDERATION_FIXTURE_ROOT, NATIVE_FEDERATION_MANIFEST,
NATIVE_FEDERATION_REQUEST_PROOF_SIGNING,
NATIVE_FEDERATION_DIRECTORY_AUDIENCE and NATIVE_FEDERATION_RELAY_AUDIENCE.
Authenticated fake operations require Authorization: NativeJWS <compact-JWS>.
The adapter must emit one JSON report with status=pass, the exact manifest
digest, and one independently observed result per manifest case. The runner
checks case-id closure, fixture digests, results and expected error codes.
FINAL-RFC JOSE-HPKE values remain structural placeholders.
`;

function load(relative) {
  const target = resolve(profileRoot, relative);
  if (!target.startsWith(`${resolve(profileRoot)}${sep}`)) throw new Error(`fixture path escapes profile: ${relative}`);
  return JSON.parse(readFileSync(target, "utf8"));
}

function schemas() {
  if (schemaRegistry) return schemaRegistry;
  let Ajv2020;
  let addFormats;
  try {
    Ajv2020 = conformanceRequire("ajv/dist/2020").default;
    addFormats = conformanceRequire("ajv-formats").default;
  } catch (error) {
    throw harnessFailure("dependency_missing", "conformance dependencies are not installed; run npm ci in protocol/federation/experimental-jose-hpke-1/conformance", error);
  }
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, allowUnionTypes: true, validateFormats: true });
  addFormats(ajv);
  const schemaDirectory = join(profileRoot, "schemas");
  const documents = readdirSync(schemaDirectory)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => [name, JSON.parse(readFileSync(join(schemaDirectory, name), "utf8"))]);
  for (const [, document] of documents) ajv.addSchema(document);
  // Compiling every root eagerly proves transitive local $ref files and JSON
  // Pointer fragments are resolvable, even if no current case selects one.
  for (const [name, document] of documents) {
    if (!ajv.getSchema(document.$id)) throw harnessFailure("schema_compile_failed", `could not compile schema ${name}`);
  }
  schemaRegistry = { ajv, documents: new Map(documents) };
  return schemaRegistry;
}

function schemaUrl(reference) {
  if (!reference.startsWith("schemas/")) throw failure("schema", "invalid_request", `non-file schema reference: ${reference}`);
  return new URL(reference.slice("schemas/".length), schemaBase).href;
}

function validateSchema(reference, value) {
  const validate = schemas().ajv.getSchema(schemaUrl(reference));
  if (!validate) throw failure("schema", "invalid_request", `unresolved schema: ${reference}`);
  if (!validate(value)) throw failure("schema", "invalid_request", schemas().ajv.errorsText(validate.errors, { separator: "; " }));
}

function validateManifestAndTree(manifest) {
  validateSchema("schemas/fixture-manifest.schema.json", manifest);
  const ids = new Set();
  const paths = new Set();
  for (const entry of manifest.cases) {
    if (ids.has(entry.id)) throw failure("manifest", "invalid_request", `duplicate case id: ${entry.id}`);
    if (paths.has(entry.path)) throw failure("manifest", "invalid_request", `duplicate fixture path: ${entry.path}`);
    ids.add(entry.id);
    paths.add(entry.path);
    load(entry.path);
    if (!schemas().ajv.getSchema(schemaUrl(entry.schema))) throw failure("schema", "invalid_request", `unresolved schema: ${entry.schema}`);
  }
  const fixtureFiles = (directory, prefix) => readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const relative = `${prefix}/${entry.name}`;
    return entry.isDirectory()
      ? fixtureFiles(join(directory, entry.name), relative)
      : entry.isFile() && entry.name.endsWith(".json") ? [relative] : [];
  });
  const treePaths = ["positive", "negative"].flatMap((directory) =>
    fixtureFiles(join(profileRoot, "fixtures", directory), `fixtures/${directory}`));
  const orphans = treePaths.filter((path) => !paths.has(path));
  const missing = [...paths].filter((path) => !treePaths.includes(path));
  if (orphans.length || missing.length || treePaths.length !== paths.size) {
    throw failure("manifest", "invalid_request", `fixture tree is not closed; orphan=${orphans.join(",") || "none"}; missing=${missing.join(",") || "none"}`);
  }
}

function jcs(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("fixture JCS only accepts safe integers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(",")}}`;
  }
  throw new Error(`unsupported JCS value: ${typeof value}`);
}

const b64u = (value) => Buffer.from(value).toString("base64url");
const sha = (value) => createHash("sha256").update(value).digest();
const digestBytes = (value) => `sha-256:${b64u(sha(value))}`;
const digestValue = (value) => digestBytes(Buffer.from(jcs(value)));

function deterministic(label, length) {
  const chunks = [];
  for (let counter = 0; Buffer.concat(chunks).length < length; counter += 1) {
    chunks.push(sha(Buffer.from(`${label}:${counter}`)));
  }
  return Buffer.concat(chunks).subarray(0, length);
}

function privateKey(label, curve = "Ed25519") {
  const oid = curve === "Ed25519" ? "70" : "6e";
  const prefix = Buffer.from(`302e020100300506032b65${oid}04220420`, "hex");
  return createPrivateKey({
    key: Buffer.concat([prefix, deterministic(`native-fed-fixture:${label}`, 32)]),
    format: "der",
    type: "pkcs8",
  });
}

function detached(payload, key, kid, typ) {
  const protectedHeader = { alg: "EdDSA", kid, typ };
  const protectedPart = b64u(Buffer.from(jcs(protectedHeader)));
  const payloadPart = b64u(Buffer.from(jcs(payload)));
  const signature = edSign(null, Buffer.from(`${protectedPart}.${payloadPart}`), key);
  return `${protectedPart}..${b64u(signature)}`;
}

function compactJws(payload, jwk, typ = "native-request-proof+jws") {
  const key = createPrivateKey({ key: jwk, format: "jwk" });
  const protectedHeader = { alg: "EdDSA", kid: jwk.kid, typ };
  const protectedPart = b64u(Buffer.from(jcs(protectedHeader)));
  const payloadPart = b64u(Buffer.from(jcs(payload)));
  const signature = edSign(null, Buffer.from(`${protectedPart}.${payloadPart}`), key);
  return `${protectedPart}.${payloadPart}.${b64u(signature)}`;
}

function requestProof({ operation, audience, signer, requestId, rawBody, clock, nonce, overrides = {} }) {
  const created = new Date(clock);
  const payload = {
    protocol_version: "1.0",
    operation,
    aud: audience,
    principal: signer.principal,
    installation_id: signer.installation_id,
    request_id: requestId,
    body_digest: digestBytes(rawBody),
    created_at: created.toISOString().replace(".000Z", "Z"),
    expires_at: new Date(created.getTime() + 300_000).toISOString().replace(".000Z", "Z"),
    nonce,
    ...overrides,
  };
  return compactJws(payload, signer.jwk);
}

function decodeB64uStrict(value, layer = "jws") {
  const code = layer === "request-proof" ? "unauthorized" : "signature_invalid";
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw failure(layer, code, "non-canonical base64url");
  const decoded = Buffer.from(value, "base64url");
  if (b64u(decoded) !== value) throw failure(layer, code, "non-canonical base64url");
  return decoded;
}

function protectedHeader(compact) {
  const parts = compact.split(".");
  if (parts.length !== 3 || parts[1] !== "") throw failure("jws", "signature_invalid");
  decodeB64uStrict(parts[2]);
  try {
    const decoded = decodeB64uStrict(parts[0]);
    const header = JSON.parse(decoded);
    if (parts[0] !== b64u(Buffer.from(jcs(header)))) throw failure("jws", "signature_invalid", "protected header is not canonical");
    return header;
  } catch (error) {
    if (error.code) throw error;
    throw failure("jws", "signature_invalid", "invalid protected header");
  }
}

function verifyDetached(payload, compact, jwk, typ) {
  const parts = compact.split(".");
  const header = protectedHeader(compact);
  const expectedHeader = { alg: "EdDSA", kid: jwk.kid, typ };
  if (jcs(header) !== jcs(expectedHeader)) {
    throw failure("jws", "signature_invalid");
  }
  const publicKey = createPublicKey({ key: jwk, format: "jwk" });
  const input = Buffer.from(`${parts[0]}.${b64u(Buffer.from(jcs(payload)))}`);
  if (!edVerify(null, input, publicKey, decodeB64uStrict(parts[2]))) {
    throw failure("jws", "signature_invalid");
  }
}

function parseRequestProof(compact, callers) {
  if (typeof compact !== "string") throw failure("request-proof", "unauthorized", "missing NativeJWS proof");
  const parts = compact.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) throw failure("request-proof", "unauthorized", "request proof must be normal compact JWS");
  let header;
  let payload;
  try {
    header = JSON.parse(decodeB64uStrict(parts[0], "request-proof"));
    payload = JSON.parse(decodeB64uStrict(parts[1], "request-proof"));
  } catch (error) {
    if (error.code) throw error;
    throw failure("request-proof", "unauthorized", "invalid request proof JSON");
  }
  const expectedHeader = { alg: "EdDSA", kid: header.kid, typ: "native-request-proof+jws" };
  if (jcs(header) !== jcs(expectedHeader)
      || parts[0] !== b64u(Buffer.from(jcs(header)))
      || parts[1] !== b64u(Buffer.from(jcs(payload)))) {
    throw failure("request-proof", "unauthorized", "non-canonical request proof");
  }
  const caller = callers.get(header.kid);
  if (!caller) throw failure("request-proof", "unauthorized", "unknown request proof key");
  const publicKey = createPublicKey({ key: caller.jwk, format: "jwk" });
  if (!edVerify(null, Buffer.from(`${parts[0]}.${parts[1]}`), publicKey, decodeB64uStrict(parts[2], "request-proof"))) {
    throw failure("request-proof", "unauthorized", "invalid request proof signature");
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(payload.request_id)) {
    throw failure("request-proof", "unauthorized", "invalid request id");
  }
  return { caller, payload };
}

function verifyRequestProof(compact, { callers, operation, audience, principal, installationId, rawBody, nowMs, replay, parsedProof }) {
  const { caller, payload } = parsedProof ?? parseRequestProof(compact, callers);
  const allowedInstallationIds = Array.isArray(installationId) ? installationId : null;
  const boundInstallationId = allowedInstallationIds ? payload.installation_id : installationId;
  const requestId = payload.request_id;
  const exactPayload = {
    protocol_version: "1.0",
    operation,
    aud: audience,
    principal,
    installation_id: boundInstallationId,
    request_id: requestId,
    body_digest: digestBytes(rawBody),
    created_at: payload.created_at,
    expires_at: payload.expires_at,
    nonce: payload.nonce,
  };
  if (jcs(payload) !== jcs(exactPayload)) throw failure("request-proof", "unauthorized", "request proof binding mismatch");
  if (allowedInstallationIds && !allowedInstallationIds.includes(boundInstallationId)) {
    throw failure("request-proof", "forbidden", "installation endpoint scope mismatch");
  }
  const created = Date.parse(payload.created_at);
  const expires = Date.parse(payload.expires_at);
  const canonicalTime = (value, milliseconds) => typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)
    && new Date(milliseconds).toISOString().replace(".000Z", "Z") === value;
  if (!Number.isFinite(created) || !Number.isFinite(expires)
      || !canonicalTime(payload.created_at, created) || !canonicalTime(payload.expires_at, expires)
      || created > nowMs || expires <= nowMs || expires - created > 300_000) {
    throw failure("request-proof", "unauthorized", "request proof outside validity window");
  }
  const nonceBytes = decodeB64uStrict(payload.nonce, "request-proof");
  if (payload.nonce.length !== 22 || nonceBytes.length !== 16) throw failure("request-proof", "unauthorized", "invalid nonce");
  if (jcs(caller.principal) !== jcs(principal) || caller.installation_id !== boundInstallationId) throw failure("request-proof", "forbidden", "caller scope mismatch");
  if (!caller.operations.includes(operation)) throw failure("request-proof", "forbidden", "operation scope missing");
  const replayKey = `${caller.jwk.kid}:${payload.nonce}`;
  if (replay.has(replayKey)) throw failure("request-proof", "idempotency_conflict", "nonce replay");
  replay.add(replayKey);
  return { caller, requestId };
}

function failure(layer, code, detail) {
  return Object.assign(new Error(detail ?? code), { layer, code });
}

function binding(principal) {
  return `${principal.network_id}/${principal.principal_id}`;
}

function verifiedProofCallers(proofFixture, clock) {
  const principalDocuments = Object.values(proofFixture.principals ?? {});
  const byAddress = new Map();
  for (const wrapper of principalDocuments) {
    validatePrincipal(wrapper, clock);
    byAddress.set(binding(wrapper.document), wrapper.document);
  }
  const rootOperations = ["directory.key.retire", "directory.key.revoke", "directory.root.rotate"];
  const signingOperations = ["directory.key.publish", "relay.delivery.get", "relay.submit"];
  const installationScopeOperations = {
    "directory.endpoint.update": ["directory.installation.put"],
    "relay.acknowledge": ["relay.acknowledge"],
    "relay.collect": ["relay.collect", "relay.delivery.get"],
  };
  const callers = new Map();
  for (const signer of Object.values(proofFixture.signers ?? {})) {
    const document = byAddress.get(binding(signer.principal));
    if (!document) throw harnessFailure("proof_fixture_invalid", `no verified principal for ${binding(signer.principal)}`);
    const publicJwk = { ...signer.jwk };
    delete publicJwk.d;
    let authorizedRecord;
    let operations;
    let installationKey = false;
    if (signer.installation_id === null) {
      authorizedRecord = document.root_keys.find((record) => record.jwk.kid === signer.jwk.kid);
      if (authorizedRecord) operations = rootOperations;
      else {
        authorizedRecord = document.operational_keys.find((record) => record.purpose === "signing" && record.jwk.kid === signer.jwk.kid);
        operations = signingOperations;
      }
    } else {
      installationKey = true;
      authorizedRecord = document.installations.find((record) => record.installation_id === signer.installation_id && record.jwk.kid === signer.jwk.kid);
      operations = authorizedRecord?.scopes.flatMap((scope) => installationScopeOperations[scope] ?? []);
    }
    const authorizedNow = installationKey ? authorizedRecord?.status === "active" : keyUsable(authorizedRecord, clock);
    if (!authorizedRecord || !authorizedNow || jcs(authorizedRecord.jwk) !== jcs(publicJwk)) {
      throw harnessFailure("proof_fixture_invalid", `request proof key is not actively authorized: ${signer.jwk.kid}`);
    }
    callers.set(signer.jwk.kid, { ...signer, operations: [...new Set(operations)] });
  }
  return callers;
}

function normalizeEmailAscii(value) {
  if (typeof value !== "string") return null;
  if (value.length > 254 || value.indexOf("@") !== value.lastIndexOf("@")) return null;
  const separator = value.indexOf("@");
  if (separator < 1 || separator > 64 || separator === value.length - 1) return null;
  const local = value.slice(0, separator);
  const domain = value.slice(separator + 1);
  const lowerDomain = domain.toLowerCase();
  const dotAtom = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
  const domainValid = domain.length <= 253 && domain.split(".").every((label) =>
    /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)$/.test(label))
    && domainToASCII(lowerDomain) === lowerDomain;
  if (!dotAtom.test(local) || !domainValid) return null;
  return `${local}@${lowerDomain}`;
}

function keyUsable(record, at) {
  const instant = new Date(at);
  return record?.status === "active"
    && new Date(record.not_before) <= instant
    && (!record.not_after || instant < new Date(record.not_after));
}

function addressValid(principal) {
  if (!principal || typeof principal !== "object") return false;
  const network = principal.network_id;
  const id = principal.principal_id;
  if (typeof network !== "string" || typeof id !== "string") return false;
  const dns = network.startsWith("dns:") ? network.slice(4) : null;
  const networkValid = network === "native"
    || (dns !== null && dns.length <= 253 && dns.split(".").every((part) => /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$/.test(part)))
    || /^key:[A-Za-z0-9_-]{43}$/.test(network);
  return networkValid && /^[A-Za-z0-9](?:[A-Za-z0-9._~-]{0,62}[A-Za-z0-9])?$/.test(id);
}

function expectedKid(jwk, purpose) {
  return `n1.${purpose}.${b64u(sha(Buffer.from(jcs({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }))))}`;
}

function validateKey(jwk, purpose) {
  const encryption = purpose === "encryption";
  if (!jwk || jwk.kty !== "OKP"
      || jwk.crv !== (encryption ? "X25519" : "Ed25519")
      || jwk.alg !== (encryption ? "HPKE-3-KE" : "EdDSA")
      || jwk.use !== (encryption ? "enc" : "sig")) {
    throw failure("key-purpose", "invalid_request");
  }
  if (jwk.kid !== expectedKid(jwk, purpose)) throw failure("kid", "invalid_request");
}

function validateNetwork(wrapper, now = defaultClock) {
  const descriptor = wrapper.descriptor;
  const pinned = load("fixtures/verification-keys.json");
  if (!descriptor || !wrapper.signature) throw failure("schema", "invalid_request");
  const instant = new Date(now);
  const issued = new Date(descriptor.issued_at);
  const fresh = new Date(descriptor.fresh_until);
  const hardExpiry = new Date(descriptor.hard_expires_at);
  if (!Number.isFinite(instant.getTime()) || !Number.isFinite(issued.getTime())
      || !Number.isFinite(fresh.getTime()) || !Number.isFinite(hardExpiry.getTime())
      || issued >= fresh || fresh > hardExpiry
      || fresh.getTime() - issued.getTime() > 900_000
      || hardExpiry.getTime() - issued.getTime() > 86_400_000
      || instant < issued) throw failure("freshness", "invalid_request");
  if (instant >= hardExpiry) throw failure("freshness", "expired");
  if (instant >= fresh) throw failure("freshness", "stale_document");
  if (descriptor.protocol_version !== "1.0" || descriptor.network_id !== "native"
      || !descriptor.supported_profiles.includes(profileName) || !descriptor.profile_preference.includes(profileName)) {
    throw failure("version", "unsupported_profile");
  }
  for (const record of descriptor.authority_keys) validateKey(record.jwk, "authority");
  for (const record of descriptor.relay_keys) validateKey(record.jwk, "relay");
  const signatureKid = protectedHeader(wrapper.signature).kid;
  const authority = descriptor.authority_keys.find((record) => keyUsable(record, now) && record.jwk.kid === signatureKid);
  if (!authority || jcs(authority.jwk) !== jcs(pinned.authority)) throw failure("trust-binding", "signature_invalid");
  const relay = descriptor.relay_keys.find((record) => keyUsable(record, now) && record.jwk.kid === pinned.relay.kid);
  if (!relay || jcs(relay.jwk) !== jcs(pinned.relay)) throw failure("trust-binding", "signature_invalid");
  verifyDetached(descriptor, wrapper.signature, pinned.authority, "native-network-descriptor+jws");
}

function validatePrincipal(wrapper, now, trustedNetwork) {
  const document = wrapper.document;
  if (!document || !wrapper.principal_signature || !wrapper.authority_attestation) {
    throw failure("schema", "invalid_request");
  }
  if (!addressValid({ network_id: document.network_id, principal_id: document.principal_id })) {
    throw failure("address", "invalid_principal_address");
  }
  const network = trustedNetwork ?? load("fixtures/positive/network-descriptor.json");
  validateNetwork(network, now);
  for (const key of document.root_keys ?? []) validateKey(key.jwk, "root");
  const principalAddress = { network_id: document.network_id, principal_id: document.principal_id };
  for (const key of document.operational_keys ?? []) {
    validateKey(key.jwk, key.purpose);
    const { authorization } = key;
    const authorizedKey = authorization.statement.key;
    if (authorizedKey.purpose !== key.purpose
        || jcs(authorizedKey.jwk) !== jcs(key.jwk)
        || authorizedKey.status !== "active") {
      throw failure("authorization-binding", "signature_invalid");
    }
    const expected = {
      statement_type: "native.operational-key-authorization",
      protocol_version: "1.0",
      principal: principalAddress,
      key: authorizedKey,
      issued_at: authorization.statement.issued_at,
    };
    if (jcs(authorization.statement) !== jcs(expected)) throw failure("authorization-binding", "signature_invalid");
    const rootKid = protectedHeader(authorization.signature).kid;
    const root = document.root_keys.find((record) => keyUsable(record, expected.issued_at) && record.jwk.kid === rootKid);
    if (!root) throw failure("authorization-binding", "signature_invalid");
    verifyDetached(authorization.statement, authorization.signature, root.jwk, "native-key-authorization+jws");
  }
  for (const installation of document.installations ?? []) {
    validateKey(installation.jwk, "installation");
    const { authorization, ...installationRecord } = installation;
    const expected = {
      statement_type: "native.installation-key-authorization",
      protocol_version: "1.0",
      principal: principalAddress,
      installation: installationRecord,
      issued_at: authorization.statement.issued_at,
    };
    if (jcs(authorization.statement) !== jcs(expected)) throw failure("authorization-binding", "signature_invalid");
    const signingKid = protectedHeader(authorization.signature).kid;
    const signingAtIssue = document.operational_keys.find((record) => record.purpose === "signing"
      && record.jwk.kid === signingKid
      && new Date(record.not_before) <= new Date(expected.issued_at)
      && (!record.not_after || new Date(expected.issued_at) < new Date(record.not_after))
      && (!record.revocation || new Date(expected.issued_at) < new Date(record.revocation.effective_at)));
    if (!signingAtIssue) throw failure("authorization-binding", "signature_invalid");
    verifyDetached(authorization.statement, authorization.signature, signingAtIssue.jwk, "native-key-authorization+jws");
  }
  const instant = new Date(now);
  const issued = new Date(document.issued_at);
  const fresh = new Date(document.fresh_until);
  const hardExpiry = new Date(document.hard_expires_at);
  if (!Number.isFinite(instant.getTime()) || !Number.isFinite(issued.getTime())
      || !Number.isFinite(fresh.getTime()) || !Number.isFinite(hardExpiry.getTime())
      || issued >= fresh || fresh > hardExpiry
      || fresh.getTime() - issued.getTime() > 900_000
      || hardExpiry.getTime() - issued.getTime() > 86_400_000
      || instant < issued) throw failure("freshness", "invalid_request");
  if (instant >= hardExpiry) throw failure("freshness", "expired");
  if (instant >= fresh) throw failure("freshness", "stale_document");
  const signatureKid = protectedHeader(wrapper.principal_signature).kid;
  const signing = document.operational_keys.find((key) => key.purpose === "signing" && key.jwk.kid === signatureKid);
  if (!signing) throw failure("jws", "signature_invalid");
  if (signing.status === "revoked") throw failure("key-state", "key_revoked");
  if (!keyUsable(signing, now)) throw failure("key-state", "signature_invalid");
  verifyDetached(document, wrapper.principal_signature, signing.jwk, "native-principal+jws");
  const attestation = wrapper.authority_attestation;
  const expectedAttestation = {
    statement_type: "native.authority.principal-attestation",
    protocol_version: "1.0",
    network_id: document.network_id,
    principal: principalAddress,
    document_version: document.document_version,
    document_digest: digestValue(document),
    root_kids: document.root_keys.map((record) => record.jwk.kid),
    issued_at: document.issued_at,
    fresh_until: document.fresh_until,
    hard_expires_at: document.hard_expires_at,
    directory_base_url: network.descriptor.directory_base_url,
  };
  if (jcs(attestation.statement) !== jcs(expectedAttestation)) {
    throw failure("authority-digest", "conflict");
  }
  const authorityKid = protectedHeader(attestation.signature).kid;
  const authority = network.descriptor.authority_keys.find((record) => keyUsable(record, attestation.statement.issued_at) && record.jwk.kid === authorityKid);
  const pinnedAuthority = load("fixtures/verification-keys.json").authority;
  if (!authority || jcs(authority.jwk) !== jcs(pinnedAuthority)) throw failure("trust-binding", "signature_invalid");
  verifyDetached(attestation.statement, attestation.signature, pinnedAuthority, "native-principal-attestation+jws");
}

function validateEnvelope(wrapper, now) {
  const envelope = wrapper.envelope;
  if (!envelope || !wrapper.signature) throw failure("schema", "invalid_request");
  if (envelope.protocol_version !== "1.0") throw failure("version", "unsupported_profile");
  if (envelope.profile !== profileName) throw failure("profile", "unsupported_profile");
  if (envelope.expires_at && new Date(now) >= new Date(envelope.expires_at)) {
    throw failure("expiry", "expired");
  }
  if (protectedHeader(wrapper.signature).kid !== envelope.sender_key_id) {
    throw failure("sender-key-binding", "signature_invalid");
  }
  const recipients = envelope.recipients ?? [];
  if (recipients.length === 0 || recipients.some((entry) => !addressValid(entry.principal))) {
    throw failure("schema", "invalid_request");
  }
  if (recipients.some((entry, index) => index > 0 && binding(recipients[index - 1].principal) >= binding(entry.principal))) {
    throw failure("recipient-order", "invalid_request");
  }
  const inner = envelope.jwe?.recipients ?? [];
  if (inner.length !== recipients.length || inner.some((entry, index) => entry.header?.kid !== recipients[index].encryption_key_id)) {
    throw failure("recipient-mapping", "recipient_mismatch");
  }
  const context = Object.fromEntries(Object.entries(envelope).filter(([key]) => key !== "jwe" && key !== "ciphertext_digest"));
  if (envelope.jwe.aad !== b64u(Buffer.from(jcs(context)))) throw failure("context", "malformed_envelope");
  let header;
  try { header = JSON.parse(Buffer.from(envelope.jwe.protected, "base64url")); } catch { throw failure("protected-header", "malformed_envelope"); }
  const expected = { alg: "HPKE-3-KE", enc: "A256GCM", typ: "native-federation+jwe", cty: envelope.content_type, native_profile: profileName, crit: ["native_profile"] };
  if (jcs(header) !== jcs(expected) || envelope.jwe.protected !== b64u(Buffer.from(jcs(expected)))) {
    throw failure("protected-header", "malformed_envelope");
  }
  if (envelope.ciphertext_digest !== digestBytes(Buffer.from(envelope.jwe.ciphertext, "base64url"))) {
    throw failure("encryption", "malformed_envelope");
  }
  if ((envelope.required_capabilities ?? []).some((item) => item !== "native.relay.receipts")) {
    throw failure("capability", "required_capability_unsupported");
  }
  const principal = load("fixtures/positive/principal-document.json");
  validatePrincipal(principal, now);
  const signing = principal.document.operational_keys.find((record) => record.purpose === "signing" && keyUsable(record, now) && record.jwk.kid === envelope.sender_key_id);
  if (!signing || binding(envelope.sender_principal) !== `${principal.document.network_id}/${principal.document.principal_id}`) throw failure("sender-key-binding", "signature_invalid");
  verifyDetached(envelope, wrapper.signature, signing.jwk, "native-envelope+jws");
}

function validateReceipt(wrapper) {
  const receipt = wrapper.receipt;
  if (!receipt || !wrapper.signature) throw failure("schema", "invalid_request");
  if (protectedHeader(wrapper.signature).kid !== receipt.relay_key_id) throw failure("relay-key-binding", "signature_invalid");
  const has = (field) => Object.hasOwn(receipt, field);
  const valid = receipt.state === "queued"
    ? !has("previous_state") && !has("collector_installation_id") && !has("reason_code")
    : receipt.state === "collected"
      ? receipt.previous_state === "queued" && has("collector_installation_id") && !has("reason_code")
      : receipt.state === "acknowledged"
        ? receipt.previous_state === "collected" && has("collector_installation_id") && !has("reason_code")
        : receipt.state === "rejected" && has("reason_code") && !has("collector_installation_id");
  if (!valid) throw failure("receipt-state", "invalid_request");
  const network = load("fixtures/positive/network-descriptor.json");
  validateNetwork(network, receipt.observed_at);
  const pinnedRelay = load("fixtures/verification-keys.json").relay;
  const relay = network.descriptor.relay_keys.find((record) => keyUsable(record, receipt.observed_at) && record.jwk.kid === receipt.relay_key_id);
  if (!relay || jcs(relay.jwk) !== jcs(pinnedRelay)) throw failure("trust-binding", "signature_invalid");
  verifyDetached(receipt, wrapper.signature, pinnedRelay, "native-relay-receipt+jws");
}

function assertSubset(actual, expected, path = "expect") {
  if (expected === null || typeof expected !== "object") {
    if (actual !== expected) throw failure("scenario-assertion", "invalid_request", `${path}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
    return;
  }
  for (const [key, value] of Object.entries(expected)) assertSubset(actual?.[key], value, `${path}.${key}`);
}

function validateScenario(value, id) {
  if (value.scenario_id !== id || !Array.isArray(value.steps) || value.steps.length === 0) {
    throw failure("schema", "invalid_request");
  }
  const steps = value.steps;
  switch (id) {
    case "directory-etag-revalidation": {
      const first = { status: 200, etag: "strong", cache_control: "must-revalidate" };
      const second = { status: steps[1].if_none_match === "previous" ? 304 : 200, cache_control: "must-revalidate" };
      assertSubset(first, steps[0].expect);
      assertSubset(second, steps[1].expect);
      return;
    }
    case "directory-alias-resolve": {
      const normalized = normalizeEmailAscii(steps[0].value);
      const actual = normalized === "Alice@example.com"
        ? { status: 200, principal: "native/alice0001", cache_control: "no-store" }
        : { status: 404, code: "unknown_alias" };
      assertSubset(actual, steps[0].expect);
      return;
    }
    case "directory-profile-negotiate": {
      const selected = steps[0].profiles.includes(profileName) ? profileName : null;
      assertSubset(selected ? { status: 200, selected_profile: selected, signed: true } : { status: 406 }, steps[0].expect);
      return;
    }
    case "envelope-replay-identical": {
      const stable = steps[0].digest === steps[1].digest;
      assertSubset({ state: "queued" }, steps[0].expect);
      assertSubset(stable ? { state: "queued", same_delivery_id: true, same_receipt_bytes: true } : { code: "idempotency_conflict" }, steps[1].expect);
      return;
    }
    case "relay-fanout-lifecycle": {
      let state = "none";
      const outputs = [];
      const deliveryId = fixtureUuid("scenario:relay-fanout-lifecycle:delivery");
      const receiptBytes = (nextState, previousState) => jcs({
        delivery_id: deliveryId,
        previous_state: previousState,
        receipt_id: fixtureUuid(`scenario:relay-fanout-lifecycle:${nextState}`),
        state: nextState,
        observed_at: value.clock,
      });
      state = "queued";
      receiptBytes(state, null);
      outputs.push({ state, independent_results: steps[0].recipients });
      if (state !== "queued") throw failure("protocol-state", "invalid_request");
      state = "collected";
      receiptBytes(state, "queued");
      outputs.push({ state, attempt: 1, lease_seconds: 300 });
      if (steps[2].disposition !== "received" || state !== "collected") throw failure("acknowledgement", "conflict");
      state = "acknowledged";
      const acknowledged = receiptBytes(state, "collected");
      const retried = receiptBytes(state, "collected");
      outputs.push({ state, stable_receipt: acknowledged === retried });
      outputs.forEach((output, index) => assertSubset(output, steps[index].expect, `steps[${index}].expect`));
      return;
    }
    case "relay-ack-retry": {
      const acknowledgements = new Map();
      const acknowledge = (tuple) => {
        const key = jcs(tuple);
        if (!acknowledgements.has(key)) {
          acknowledgements.set(key, jcs({
            receipt_id: fixtureUuid(`scenario:relay-ack-retry:${key}`),
            state: "acknowledged",
            observed_at: value.clock,
          }));
        }
        return acknowledgements.get(key);
      };
      const tuple = { delivery_id: fixtureUuid("scenario:relay-ack-retry:delivery"), disposition: "received" };
      const firstBytes = acknowledge(tuple);
      const retryBytes = steps[1].retry === true ? acknowledge(tuple) : acknowledge({ ...tuple, retry: false });
      const firstReceipt = JSON.parse(firstBytes);
      assertSubset({ state: firstReceipt.state, receipt_id: firstReceipt.receipt_id === JSON.parse(retryBytes).receipt_id ? "stable" : "changed" }, steps[0].expect);
      assertSubset({ state: firstReceipt.state, same_receipt_bytes: firstBytes === retryBytes }, steps[1].expect);
      return;
    }
    case "relay-lease-redelivery": {
      let now = new Date(value.clock).getTime();
      const leaseUntil = now + 300_000;
      assertSubset({ state: "collected", attempt: 1 }, steps[0].expect);
      now += steps[1].advance_seconds * 1000;
      const redelivered = now > leaseUntil;
      assertSubset({ state: "collected", attempt: redelivered ? 2 : 1, new_lease: redelivered, no_new_transition_receipt: true }, steps[2].expect);
      return;
    }
    case "principal-document-rollback":
      if (steps[0].received_version < steps[0].cached_version) throw failure("rollback", "conflict");
      return;
    case "alias-unverified":
      if (steps[0].verified !== true) throw failure("alias", "alias_unverified");
      return;
    case "alias-collision":
      if (new Set(steps[0].active_principals).size > 1) throw failure("alias", "conflict");
      return;
    case "alias-reassignment-stale":
      if (steps[1].version > steps[0].version && steps[1].principal !== steps[0].principal) throw failure("freshness", "stale_document");
      return;
    case "alias-local-part-case-mismatch":
      if (normalizeEmailAscii(steps[0].query) !== normalizeEmailAscii(steps[0].stored)) throw failure("alias", "unknown_alias");
      return;
    case "directory-mutation-unauthorized":
      if (!steps[0].request_proof) throw failure("authorization", "unauthorized");
      return;
    case "directory-precondition-failed":
      if (steps[0].if_match === "stale") throw failure("etag", "precondition_failed");
      return;
    case "directory-unsupported-profile":
      if (!steps[0].profiles.includes(profileName)) throw failure("negotiation", "unsupported_profile");
      return;
    case "directory-required-capability":
      if (steps[0].required_capabilities.some((item) => item !== "native.relay.receipts")) throw failure("capability", "required_capability_unsupported");
      return;
    case "relay-concurrent-lease":
      if (steps[0].live_lease_holders > 1) throw failure("lease", "conflict");
      return;
    case "relay-ack-digest-mismatch":
      if (steps[0].acknowledgement_digest !== steps[0].envelope_digest) throw failure("acknowledgement", "conflict");
      return;
    case "relay-ack-wrong-lease":
      if (steps[0].lease_token !== steps[0].expected_lease_token) throw failure("lease", "conflict");
      return;
    case "relay-quota-exceeded":
      if (steps[0].mailbox_quota_remaining < 1) throw failure("quota", "quota_exceeded");
      return;
    case "relay-terminal-transition":
      if (["acknowledged", "rejected"].includes(steps[0].from)) throw failure("protocol-state", "delivery_terminal");
      return;
    default:
      throw failure("scenario", "invalid_request", `no semantic executor for scenario ${id}`);
  }
}

function validateCase(entry, value, clock) {
  validateSchema(entry.schema, value);
  try {
    if (entry.id === "profile-negotiation-response") {
      const network = load("fixtures/positive/network-descriptor.json");
      validateNetwork(network, clock);
      verifyDetached(value.result, value.signature, load("fixtures/verification-keys.json").authority, "native-profile-negotiation+jws");
      if (value.result.selected_profile !== profileName || new Date(clock) >= new Date(value.result.fresh_until)) {
        throw failure("negotiation", "unsupported_profile");
      }
    } else if (entry.id === "idempotency-conflict") {
      if (digestValue(value.first) !== digestValue(value.retry)) throw failure("idempotency", "idempotency_conflict");
    } else if (entry.schema.includes("scenario.schema.json")) {
      validateScenario(value, entry.id);
    } else if (entry.id.startsWith("principal-address-")) {
      if (!addressValid(value)) throw failure("address", "invalid_principal_address");
    } else if (entry.schema.includes("network-descriptor")) {
      validateNetwork(value, clock);
    } else if (entry.schema.includes("principal-document")) {
      validatePrincipal(value, clock);
    } else if (entry.schema.includes("transport-envelope")) {
      validateEnvelope(value, clock);
    } else if (entry.schema.includes("relay-receipt")) {
      validateReceipt(value);
      if (entry.id === "receipt-envelope-digest"
          && value.receipt.envelope_digest !== digestValue(load("fixtures/positive/envelope-one-recipient.json"))) {
        throw failure("envelope-digest", "conflict");
      }
    } else if (entry.id === "error-rate-limited") {
      if (value.code !== "rate_limited" || value.status !== 429 || value.retryable !== true) throw failure("error-registry", "invalid_request");
    }
  } catch (semanticError) {
    throw semanticError;
  }
}

function resultFor(entry, clock) {
  const started = performance.now();
  let observed = "valid";
  let error = null;
  let layer = null;
  try {
    validateCase(entry, load(entry.path), clock);
  } catch (cause) {
    observed = "invalid";
    error = cause.code ?? "internal";
    layer = cause.layer ?? "runner";
  }
  const passed = observed === entry.expect && (entry.expect === "valid" || error === entry.error)
    && (entry.expect === "valid" || entry.validation_layers.includes(layer));
  return {
    id: entry.id,
    status: passed ? "pass" : "fail",
    expected: { result: entry.expect, ...(entry.error ? { error: entry.error } : {}), layers: entry.validation_layers },
    observed: { result: observed, ...(error ? { error } : {}), ...(layer ? { layer } : {}) },
    duration_ms: Math.round((performance.now() - started) * 1000) / 1000,
    crypto_status: entry.crypto_status,
  };
}

function fixtureUuid(label) {
  const bytes = Buffer.from(sha(Buffer.from(label)).subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function problem(code, requestId, status, retryable = false, retryAfter) {
  return {
    type: `urn:native:federation:error:${code}`,
    title: code.replaceAll("_", " "),
    status,
    code,
    request_id: requestId,
    retryable,
    ...(retryAfter === undefined ? {} : { retry_after: retryAfter }),
  };
}

function makeFakeServices(clock = defaultClock) {
  let principal = load("fixtures/positive/principal-document.json");
  const envelopeFixture = load("fixtures/positive/envelope-one-recipient.json");
  const relayJwk = load("fixtures/verification-keys.json").relay;
  const relayPrivate = privateKey("native-relay");
  const deliveries = new Map();
  const idempotency = new Map();
  const proofFixture = load("fixtures/request-proof-signing.json");
  let recipientPrincipal = structuredClone(proofFixture.principals.bob);
  const callers = verifiedProofCallers(proofFixture, clock);
  const proofReplay = new Set();
  const mailboxByPrincipal = new Map([
    ["native/bob00001", "00000000-0000-4000-8000-000000000201"],
    ["native/carol001", "00000000-0000-4000-8000-000000000202"],
  ]);
  let nowMs = new Date(clock).getTime();
  let requestCounter = 0;
  let runtimeNetwork;

  function receipt(delivery, state, previousState) {
    const body = {
      receipt_type: "native.relay.delivery-receipt",
      protocol_version: "1.0",
      profile: profileName,
      receipt_id: fixtureUuid(`receipt:${delivery.id}:${state}`),
      relay_id: "native-conformance-relay",
      relay_key_id: relayJwk.kid,
      delivery_id: delivery.id,
      envelope_id: delivery.envelope.envelope.envelope_id,
      envelope_digest: delivery.digest,
      recipient: delivery.recipient,
      ...(previousState ? { previous_state: previousState } : {}),
      state,
      observed_at: new Date(nowMs).toISOString().replace(".000Z", "Z"),
      ...(["collected", "acknowledged"].includes(state) ? { collector_installation_id: delivery.installation } : {}),
    };
    return { receipt: body, signature: detached(body, relayPrivate, relayJwk.kid, "native-relay-receipt+jws") };
  }

  async function handler(req, res) {
    requestCounter += 1;
    let requestId = fixtureUuid(`request:${requestCounter}`);
    const authorization = /^NativeJWS ([A-Za-z0-9._-]+)$/.exec(req.headers.authorization ?? "");
    let parsedProof;
    try {
      parsedProof = parseRequestProof(authorization?.[1], callers);
      requestId = parsedProof.payload.request_id;
    } catch {}
    const url = new URL(req.url, "http://fake.invalid");
    const parsed = await new Promise((resolve, reject) => {
      const chunks = [];
      let bytes = 0;
      let tooLarge = false;
      const maximum = runtimeNetwork?.descriptor.limits.max_envelope_bytes ?? 1048576;
      const declaredLength = req.headers["content-length"];
      if (typeof declaredLength === "string" && /^[0-9]+$/.test(declaredLength) && Number(declaredLength) > maximum) {
        tooLarge = true;
        resolve({ tooLarge: true });
        req.resume();
      }
      req.on("data", (chunk) => {
        if (tooLarge) return;
        bytes += chunk.length;
        if (bytes > maximum) {
          tooLarge = true;
          resolve({ tooLarge: true });
          req.resume();
        } else chunks.push(chunk);
      });
      req.on("end", () => {
        if (tooLarge) return resolve({ tooLarge: true });
        const raw = Buffer.concat(chunks);
        if (chunks.length === 0) return resolve({ raw, body: null });
        try { resolve({ raw, body: JSON.parse(raw) }); } catch (error) { reject(error); }
      });
      req.on("error", reject);
    }).catch(() => undefined);
    const send = (status, value, headers = {}) => {
      res.writeHead(status, { "content-type": "application/json", "Native-Request-Id": requestId, ...headers });
      res.end(value === null ? "" : `${JSON.stringify(value)}\n`);
    };
    if (parsed === undefined) return send(400, problem("invalid_request", requestId, 400));
    if (parsed.tooLarge) return send(413, problem("payload_too_large", requestId, 413));
    const { raw: rawBody, body } = parsed;
    const authorize = (operation, expectedPrincipal, installationId) => {
      try {
        validateNetwork(runtimeNetwork, new Date(nowMs).toISOString());
        const audience = operation.startsWith("directory.")
          ? runtimeNetwork.descriptor.directory_base_url
          : runtimeNetwork.descriptor.relay_base_urls[0];
        const verified = verifyRequestProof(authorization?.[1], {
          callers,
          operation,
          audience,
          principal: expectedPrincipal,
          installationId,
          rawBody,
          nowMs,
          replay: proofReplay,
          parsedProof,
        });
        requestId = verified.requestId;
        return true;
      } catch (error) {
        const status = error.code === "forbidden" ? 403 : error.code === "idempotency_conflict" ? 409 : 401;
        send(status, problem(error.code ?? "unauthorized", requestId, status));
        return false;
      }
    };
    const applyClockAdvance = () => {
      const raw = req.headers["native-conformance-advance-seconds"];
      if (raw === undefined) return true;
      if (typeof raw !== "string" || !/^[1-9][0-9]{0,3}$/.test(raw) || Number(raw) > 3600) {
        send(400, problem("invalid_request", requestId, 400));
        return false;
      }
      nowMs += Number(raw) * 1000;
      return true;
    };

    if (req.method === "GET" && url.pathname === "/v1/network") return send(200, runtimeNetwork);

    const principalMatch = url.pathname.match(/^\/v1\/principals\/([^/]+)$/);
    if (req.method === "GET" && principalMatch) {
      const resolvedPrincipal = principalMatch[1] === "alice0001" ? principal : principalMatch[1] === "bob00001" ? recipientPrincipal : null;
      if (!resolvedPrincipal) return send(404, problem("unknown_principal", requestId, 404));
      const etag = `\"pd-${digestValue(resolvedPrincipal.document).slice(8)}\"`;
      const headers = { ETag: etag, "Cache-Control": "public, max-age=300, must-revalidate" };
      if (req.headers["if-none-match"] === etag) return send(304, null, headers);
      return send(200, resolvedPrincipal, headers);
    }
    if (req.method === "POST" && url.pathname === "/v1/aliases:resolve") {
      res.setHeader("Cache-Control", "no-store");
      if (body?.operation !== "directory.alias.resolve") return send(400, problem("invalid_request", requestId, 400));
      const normalized = normalizeEmailAscii(body.value);
      if (normalized === null) return send(400, problem("invalid_request", requestId, 400));
      if (normalized === "unverified@example.com") return send(409, problem("alias_unverified", requestId, 409));
      if (normalized !== "Alice@example.com") return send(404, problem("unknown_alias", requestId, 404));
      return send(200, { operation: "directory.alias.resolve.result", principal_document: principal, matched_alias: principal.document.verified_aliases[0] });
    }
    if (req.method === "POST" && url.pathname === "/v1/profiles:negotiate") {
      if (body?.operation !== "directory.negotiate") return send(400, problem("invalid_request", requestId, 400));
      if (!body.profiles?.includes(profileName)) return send(406, problem("unsupported_profile", requestId, 406));
      const unsupported = (body.required_capabilities ?? []).filter((item) => item !== "native.relay.receipts");
      if (unsupported.length) return send(422, problem("required_capability_unsupported", requestId, 422));
      const result = { operation: "directory.negotiate.result", protocol_version: "1.0", selected_profile: profileName, capabilities: ["native.relay.receipts"], unsupported_required_capabilities: [], fresh_until: "2026-08-02T09:15:00Z" };
      const authorityKey = privateKey("native-authority");
      const authorityJwk = load("fixtures/verification-keys.json").authority;
      return send(200, { result, signature: detached(result, authorityKey, authorityJwk.kid, "native-profile-negotiation+jws") });
    }
    const mutationShapes = [
      ["PUT", /^\/v1\/principals\/([^/]+)\/installations\/([^/]+)$/, "directory.installation.put"],
      ["POST", /^\/v1\/principals\/([^/]+)\/keys$/, "directory.key.publish"],
      ["POST", /^\/v1\/principals\/([^/]+)\/keys\/[^/]+:retire$/, "directory.key.retire"],
      ["POST", /^\/v1\/principals\/([^/]+)\/keys\/[^/]+:revoke$/, "directory.key.revoke"],
      ["POST", /^\/v1\/principals\/([^/]+)\/roots:rotate$/, "directory.root.rotate"],
    ];
    const mutation = mutationShapes.map(([method, pattern, operation]) => [method, url.pathname.match(pattern), operation]).find(([method, match]) => req.method === method && match);
    if (mutation) {
      res.setHeader("Cache-Control", "no-store");
      if (body?.operation !== mutation[2] || body.principal?.principal_id !== mutation[1][1]) return send(400, problem("invalid_request", requestId, 400));
      const callerInstallation = mutation[2] === "directory.installation.put" ? [null, mutation[1][2]] : null;
      if (!authorize(mutation[2], body.principal, callerInstallation)) return;
      if (req.headers["if-match"] === "\"stale\"") return send(412, problem("precondition_failed", requestId, 412, true));
      return send(200, principal);
    }
    if (req.method === "POST" && url.pathname === "/v1/envelopes") {
      if (body?.operation !== "relay.submit" || !body.envelope) return send(400, problem("invalid_request", requestId, 400));
      if (!authorize("relay.submit", body.envelope.envelope.sender_principal, null)) return;
      if (req.headers["native-conformance-scenario"] === "quota") return send(429, problem("quota_exceeded", requestId, 429, true, 30), { "Retry-After": "30" });
      try {
        validateEnvelope(body.envelope, new Date(nowMs).toISOString());
        const signatureKid = protectedHeader(body.envelope.signature).kid;
        const signing = principal.document.operational_keys.find((key) => key.purpose === "signing" && key.status === "active" && key.jwk.kid === signatureKid);
        if (!signing) throw failure("sender-key-binding", "signature_invalid");
        verifyDetached(body.envelope.envelope, body.envelope.signature, signing.jwk, "native-envelope+jws");
      } catch (error) {
        const statuses = { expired: 410, unsupported_profile: 406, required_capability_unsupported: 422 };
        const status = statuses[error.code] ?? 400;
        return send(status, problem(error.code, requestId, status));
      }
      const wrapperDigest = digestValue(body.envelope);
      const sender = binding(body.envelope.envelope.sender_principal);
      const keys = body.envelope.envelope.recipients.map((item) => `${sender}:${body.envelope.envelope.envelope_id}:${binding(item.principal)}`);
      if (keys.some((key) => idempotency.has(key) && idempotency.get(key) !== wrapperDigest)) {
        return send(409, problem("idempotency_conflict", requestId, 409));
      }
      const results = body.envelope.envelope.recipients.map((recipient, index) => {
        const key = keys[index];
        const id = fixtureUuid(`delivery:${key}`);
        let delivery = deliveries.get(id);
        if (!delivery) {
          delivery = { id, digest: wrapperDigest, envelope: structuredClone(body.envelope), recipient: recipient.principal, state: "queued", attempt: 0, installation: mailboxByPrincipal.get(binding(recipient.principal)), leaseToken: null, leaseUntil: 0 };
          delivery.receipts = { queued: receipt(delivery, "queued") };
          deliveries.set(id, delivery);
          idempotency.set(key, wrapperDigest);
        }
        return { recipient: recipient.principal, outcome: "queued", delivery_id: id, receipt: delivery.receipts.queued };
      });
      return send(200, { operation: "relay.submit.result", envelope_id: body.envelope.envelope.envelope_id, envelope_digest: wrapperDigest, results });
    }
    const collect = url.pathname.match(/^\/v1\/mailboxes\/([^/]+):collect$/);
    if (req.method === "POST" && collect) {
      if (body?.operation !== "relay.collect") return send(400, problem("invalid_request", requestId, 400));
      const expectedCaller = Object.values(proofFixture.signers).find((caller) => caller.installation_id === collect[1]);
      if (!expectedCaller || !authorize("relay.collect", expectedCaller.principal, collect[1])) return;
      if (!applyClockAdvance()) return;
      const selected = [...deliveries.values()].filter((item) => item.installation === collect[1] && item.state !== "acknowledged" && item.leaseUntil <= nowMs).slice(0, body.limit);
      const responseDeliveries = selected.map((delivery) => {
        const previousState = delivery.state;
        delivery.state = "collected";
        delivery.attempt += 1;
        delivery.leaseToken = b64u(deterministic(`lease:${delivery.id}:${delivery.attempt}`, 24));
        delivery.leaseUntil = nowMs + 300_000;
        if (!delivery.receipts.collected) delivery.receipts.collected = receipt(delivery, "collected", "queued");
        return { delivery_id: delivery.id, envelope_digest: delivery.digest, envelope: delivery.envelope, state: "collected", attempt: delivery.attempt, lease_token: delivery.leaseToken, lease_expires_at: new Date(delivery.leaseUntil).toISOString().replace(".000Z", "Z"), queued_receipt: delivery.receipts.queued, ...(previousState === "queued" ? { collected_receipt: delivery.receipts.collected } : {}) };
      });
      return send(200, { operation: "relay.collect.result", cursor: b64u(Buffer.from(`cursor:${requestCounter}`)), deliveries: responseDeliveries });
    }
    const ack = url.pathname.match(/^\/v1\/mailboxes\/([^/]+)\/acknowledgements$/);
    if (req.method === "POST" && ack) {
      if (body?.operation !== "relay.acknowledge") return send(400, problem("invalid_request", requestId, 400));
      const expectedCaller = Object.values(proofFixture.signers).find((caller) => caller.installation_id === ack[1]);
      if (!expectedCaller || !authorize("relay.acknowledge", expectedCaller.principal, ack[1])) return;
      const receipts = [];
      for (const entry of body.acknowledgements ?? []) {
        const delivery = deliveries.get(entry.delivery_id);
        if (!delivery) return send(404, problem("delivery_unknown", requestId, 404));
        const tupleValid = delivery.installation === ack[1]
          && entry.disposition === "received"
          && entry.lease_token === delivery.leaseToken
          && entry.envelope_digest === delivery.digest
          && entry.envelope_id === delivery.envelope.envelope.envelope_id;
        if (!tupleValid) {
          return send(409, problem("conflict", requestId, 409));
        }
        if (delivery.state === "acknowledged") { receipts.push(delivery.receipts.acknowledged); continue; }
        if (delivery.state !== "collected") return send(409, problem("conflict", requestId, 409));
        delivery.state = "acknowledged";
        delivery.receipts.acknowledged = receipt(delivery, "acknowledged", "collected");
        receipts.push(delivery.receipts.acknowledged);
      }
      return send(200, { operation: "relay.acknowledge.result", receipts });
    }
    const deliveryGet = url.pathname.match(/^\/v1\/deliveries\/([^/]+)$/);
    if (req.method === "GET" && deliveryGet) {
      const delivery = deliveries.get(deliveryGet[1]);
      if (!delivery) return send(404, problem("delivery_unknown", requestId, 404));
      const caller = Object.values(proofFixture.signers).find((candidate) => candidate.installation_id === delivery.installation) ?? proofFixture.signers.alice_signing;
      if (!authorize("relay.delivery.get", caller.principal, caller.installation_id)) return;
      return send(200, { delivery_id: delivery.id, state: delivery.state, envelope_digest: delivery.digest, receipts: Object.values(delivery.receipts) });
    }
    return send(404, problem("invalid_request", requestId, 404));
  }

  const server = createServer((req, res) => handler(req, res).catch((error) => {
    res.writeHead(500, { "content-type": "application/json" });
    res.end(`${JSON.stringify({ code: "internal", detail: error.message })}\n`);
  }));
  return {
    server,
    envelopeFixture,
    setRuntimeNetwork(value) {
      const bindRuntimePrincipal = (source, signingLabel) => {
        const wrapper = structuredClone(source);
        wrapper.document.delivery_endpoints = [{ kind: "relay", url: `${value.descriptor.relay_base_urls[0]}/v1`, priority: 0 }];
        wrapper.principal_signature = detached(
          wrapper.document,
          privateKey(signingLabel),
          wrapper.document.operational_keys.find((record) => record.purpose === "signing").jwk.kid,
          "native-principal+jws",
        );
        wrapper.authority_attestation.statement.document_digest = digestValue(wrapper.document);
        wrapper.authority_attestation.statement.directory_base_url = value.descriptor.directory_base_url;
        wrapper.authority_attestation.signature = detached(
          wrapper.authority_attestation.statement,
          privateKey("native-authority"),
          load("fixtures/verification-keys.json").authority.kid,
          "native-principal-attestation+jws",
        );
        return wrapper;
      };
      runtimeNetwork = value;
      principal = bindRuntimePrincipal(principal, "alice-signing");
      recipientPrincipal = bindRuntimePrincipal(recipientPrincipal, "bob-signing");
    },
    get runtimeNetwork() { return runtimeNetwork; },
  };
}

function runtimeNetworkDescriptor(baseUrl, clock, relayUrl = baseUrl) {
  const wrapper = structuredClone(load("fixtures/positive/network-descriptor.json"));
  const issued = new Date(clock);
  wrapper.descriptor.issued_at = issued.toISOString().replace(".000Z", "Z");
  wrapper.descriptor.fresh_until = new Date(issued.getTime() + 900_000).toISOString().replace(".000Z", "Z");
  wrapper.descriptor.hard_expires_at = new Date(issued.getTime() + 86_400_000).toISOString().replace(".000Z", "Z");
  wrapper.descriptor.directory_base_url = baseUrl;
  wrapper.descriptor.relay_base_urls = [relayUrl];
  const authority = load("fixtures/verification-keys.json").authority;
  wrapper.signature = detached(wrapper.descriptor, privateKey("native-authority"), authority.kid, "native-network-descriptor+jws");
  return wrapper;
}

async function listenFake(clock, port = 0, host = "127.0.0.1", relayUrl) {
  const fake = makeFakeServices(clock);
  await new Promise((resolve, reject) => {
    fake.server.once("error", reject);
    fake.server.listen(port, host, resolve);
  });
  const address = fake.server.address();
  const urlHost = host.includes(":") ? `[${host}]` : host;
  const baseUrl = `http://${urlHost}:${address.port}`;
  fake.setRuntimeNetwork(runtimeNetworkDescriptor(baseUrl, clock, relayUrl ?? baseUrl));
  return { ...fake, baseUrl, runtimeNetwork: fake.runtimeNetwork };
}

let clientProofCounter = 0;

async function request(baseUrl, path, { method = "GET", body, headers = {}, proofSigner, operation, audience, clock = defaultClock, proofOverrides, proofRawBody, timeoutMs = 5000 } = {}) {
  clientProofCounter += 1;
  const hasBody = body !== undefined;
  const rawBody = hasBody ? Buffer.from(JSON.stringify(body)) : Buffer.alloc(0);
  const requestHeaders = { ...(hasBody ? { "content-type": "application/vnd.native.federation+json" } : {}), ...headers };
  let proofRequestId;
  if (proofSigner) {
    const signing = load("fixtures/request-proof-signing.json");
    const signer = signing.signers[proofSigner];
    if (!signer) throw new Error(`unknown proof signer ${proofSigner}`);
    const requestId = fixtureUuid(`client-request:${clientProofCounter}`);
    proofRequestId = requestId;
    const nonce = b64u(deterministic(`request-proof-nonce:${clientProofCounter}`, 16));
    requestHeaders.Authorization = `NativeJWS ${requestProof({ operation, audience: audience ?? baseUrl, signer, requestId, rawBody: proofRawBody ?? rawBody, clock, nonce, overrides: proofOverrides })}`;
  }
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: requestHeaders,
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMs),
    ...(hasBody ? { body: rawBody } : {}),
  });
  const text = await response.text();
  return { status: response.status, headers: response.headers, body: text ? JSON.parse(text) : null, proofRequestId };
}

async function externalServiceResults(clock, directoryUrl, relayUrl, descriptorUrl, timeoutMs) {
  const results = [];
  const check = async (id, layer, operation) => {
    const started = performance.now();
    try {
      await operation();
      results.push({ id, status: "pass", expected: { result: "valid", layers: [layer] }, observed: { result: "valid", layer }, duration_ms: Math.round((performance.now() - started) * 1000) / 1000, crypto_status: "not-applicable" });
    } catch (error) {
      results.push({ id, status: "fail", expected: { result: "valid", layers: [layer] }, observed: { result: "invalid", error: error.message, layer }, duration_ms: Math.round((performance.now() - started) * 1000) / 1000, crypto_status: "not-applicable" });
    }
  };
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  const bounded = (baseUrl, path, options = {}) => request(baseUrl, path, { ...options, timeoutMs });
  const assertReceipt = (wrapper, expected) => {
    validateReceipt(wrapper);
    for (const [key, value] of Object.entries(expected)) assert(jcs(wrapper.receipt[key]) === jcs(value), `receipt ${key} binding mismatch`);
  };
  let network;
  await check("external-directory-configuration", "interoperability", async () => {
    const response = await fetch(descriptorUrl, { redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
    assert(response.status === 200, `descriptor returned HTTP ${response.status}`);
    network = await response.json();
    validateNetwork(network, clock);
    assert(network.descriptor.directory_base_url === directoryUrl, "descriptor did not bind the configured directory URL");
    assert(network.descriptor.relay_base_urls.length === 1 && network.descriptor.relay_base_urls[0] === relayUrl, "descriptor did not bind the configured relay URL");
    assert(directoryUrl !== relayUrl, "replacement proof requires independently configured directory and relay origins");

    const principal = await bounded(directoryUrl, "/v1/principals/alice0001");
    assert(principal.status === 200 && principal.headers.get("etag"), "replacement directory did not return the principal with an ETag");
    validatePrincipal(principal.body, clock, network);
    const cached = await bounded(directoryUrl, "/v1/principals/alice0001", { headers: { "If-None-Match": principal.headers.get("etag") } });
    assert(cached.status === 304, "replacement directory did not support conditional revalidation");
    const alias = await bounded(directoryUrl, "/v1/aliases:resolve", { method: "POST", body: { operation: "directory.alias.resolve", protocol_version: "1.0", system: "email", normalization: "native.email-ascii-v1", value: "Alice@example.com" } });
    assert(alias.status === 200 && alias.headers.get("cache-control") === "no-store", "replacement resolver did not resolve the published alias privately");
    const negotiation = await bounded(directoryUrl, "/v1/profiles:negotiate", { method: "POST", body: { operation: "directory.negotiate", protocol_version: "1.0", profiles: [profileName], capabilities: [], required_capabilities: [] } });
    assert(negotiation.status === 200 && negotiation.body.result.selected_profile === profileName, "replacement directory did not negotiate the profile");
    const authority = network.descriptor.authority_keys.find((entry) => entry.status === "active")?.jwk;
    verifyDetached(negotiation.body.result, negotiation.body.signature, authority, "native-profile-negotiation+jws");
  });

  await check("external-relay-exchange", "interoperability", async () => {
    assert(network, "descriptor validation failed before relay exchange");
    const envelope = load("fixtures/positive/envelope-many-recipients.json");
    const submitted = await bounded(relayUrl, "/v1/envelopes", { method: "POST", proofSigner: "alice_signing", operation: "relay.submit", body: { operation: "relay.submit", envelope } });
    assert(submitted.status === 200 && submitted.body.results?.length === 2, "replacement relay did not fan out the Native reference envelope");
    const rootProof = await bounded(relayUrl, "/v1/envelopes", { method: "POST", proofSigner: "alice_root", operation: "relay.submit", body: { operation: "relay.submit", envelope } });
    assert(rootProof.status === 403, "replacement relay did not classify a valid but out-of-scope root key as forbidden");
    const relay = network.descriptor.relay_keys.find((entry) => entry.status === "active")?.jwk;
    for (const result of submitted.body.results) assertReceipt(result.receipt, { relay_key_id: relay.kid, recipient: result.recipient, state: "queued", delivery_id: result.delivery_id, envelope_id: envelope.envelope.envelope_id, envelope_digest: submitted.body.envelope_digest });
    const mailbox = "00000000-0000-4000-8000-000000000201";
    const collected = await bounded(relayUrl, `/v1/mailboxes/${mailbox}:collect`, { method: "POST", proofSigner: "bob_installation", operation: "relay.collect", body: { operation: "relay.collect", limit: 100, wait_seconds: 0 } });
    assert(collected.status === 200 && collected.body.deliveries?.length === 1, "replacement relay did not deliver to the configured mailbox");
    const carolMailbox = "00000000-0000-4000-8000-000000000202";
    const collectedCarol = await bounded(relayUrl, `/v1/mailboxes/${carolMailbox}:collect`, { method: "POST", proofSigner: "carol_installation", operation: "relay.collect", body: { operation: "relay.collect", limit: 100, wait_seconds: 0 } });
    assert(collectedCarol.status === 200 && collectedCarol.body.deliveries?.length === 1, "replacement relay did not isolate the second recipient mailbox");
    const delivery = collected.body.deliveries[0];
    assert(delivery.envelope_digest === submitted.body.envelope_digest && collectedCarol.body.deliveries[0].envelope_digest === submitted.body.envelope_digest, "replacement relay changed the envelope digest");
    assertReceipt(delivery.queued_receipt, { relay_key_id: relay.kid, recipient: delivery.envelope.envelope.recipients[0].principal, state: "queued", delivery_id: delivery.delivery_id, envelope_id: delivery.envelope.envelope.envelope_id, envelope_digest: delivery.envelope_digest });
    assertReceipt(delivery.collected_receipt, { relay_key_id: relay.kid, recipient: delivery.envelope.envelope.recipients[0].principal, state: "collected", previous_state: "queued", collector_installation_id: mailbox, delivery_id: delivery.delivery_id, envelope_id: delivery.envelope.envelope.envelope_id, envelope_digest: delivery.envelope_digest });
    const acknowledgement = { delivery_id: delivery.delivery_id, envelope_id: delivery.envelope.envelope.envelope_id, envelope_digest: delivery.envelope_digest, lease_token: delivery.lease_token, disposition: "received" };
    const acked = await bounded(relayUrl, `/v1/mailboxes/${mailbox}/acknowledgements`, { method: "POST", proofSigner: "bob_installation", operation: "relay.acknowledge", body: { operation: "relay.acknowledge", acknowledgements: [acknowledgement] } });
    assert(acked.status === 200 && acked.body.receipts?.length === 1, "replacement relay did not acknowledge the delivery");
    assertReceipt(acked.body.receipts[0], { relay_key_id: relay.kid, recipient: delivery.envelope.envelope.recipients[0].principal, state: "acknowledged", previous_state: "collected", collector_installation_id: mailbox, delivery_id: delivery.delivery_id, envelope_id: delivery.envelope.envelope.envelope_id, envelope_digest: delivery.envelope_digest });
    const retried = await bounded(relayUrl, `/v1/mailboxes/${mailbox}/acknowledgements`, { method: "POST", proofSigner: "bob_installation", operation: "relay.acknowledge", body: { operation: "relay.acknowledge", acknowledgements: [acknowledgement] } });
    assert(retried.status === 200 && jcs(retried.body) === jcs(acked.body), "replacement relay acknowledgement retry was not byte-stable");
  });
  return results;
}

async function fakeServiceResults(clock) {
  const fake = await listenFake(clock);
  const results = [];
  const check = async (id, layer, operation) => {
    const started = performance.now();
    try {
      await operation(fake);
      results.push({ id, status: "pass", expected: { result: "valid", layers: [layer] }, observed: { result: "valid", layer }, duration_ms: Math.round((performance.now() - started) * 1000) / 1000, crypto_status: "not-applicable" });
    } catch (error) {
      results.push({ id, status: "fail", expected: { result: "valid", layers: [layer] }, observed: { result: "invalid", error: error.message, layer }, duration_ms: Math.round((performance.now() - started) * 1000) / 1000, crypto_status: "not-applicable" });
    }
  };
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  try {
    await check("fake-directory-read-etag", "service-behaviour", async ({ baseUrl }) => {
      const runtimeDescriptor = await request(baseUrl, "/v1/network");
      assert(runtimeDescriptor.status === 200, "runtime descriptor was not published");
      validateNetwork(runtimeDescriptor.body, clock);
      assert(runtimeDescriptor.body.descriptor.directory_base_url === baseUrl && runtimeDescriptor.body.descriptor.relay_base_urls[0] === baseUrl, "runtime descriptor did not bind the loopback audiences");
      const first = await request(baseUrl, "/v1/principals/alice0001");
      assert(first.status === 200 && first.headers.get("etag"), "principal read did not return ETag");
      const cached = await request(baseUrl, "/v1/principals/alice0001", { headers: { "If-None-Match": first.headers.get("etag") } });
      assert(cached.status === 304 && cached.headers.get("cache-control")?.includes("must-revalidate"), "conditional read did not preserve cache metadata");
    });
    await check("fake-directory-alias-and-negotiation", "service-behaviour", async ({ baseUrl }) => {
      const alias = await request(baseUrl, "/v1/aliases:resolve", { method: "POST", body: { operation: "directory.alias.resolve", protocol_version: "1.0", system: "email", normalization: "native.email-ascii-v1", value: "Alice@example.com" } });
      assert(alias.status === 200 && alias.headers.get("cache-control") === "no-store", "alias resolution was not private and deterministic");
      const localCaseMismatch = await request(baseUrl, "/v1/aliases:resolve", { method: "POST", body: { operation: "directory.alias.resolve", protocol_version: "1.0", system: "email", normalization: "native.email-ascii-v1", value: "alice@EXAMPLE.COM" } });
      assert(localCaseMismatch.status === 404 && localCaseMismatch.body.code === "unknown_alias", "email normalization folded the local part");
      for (const invalid of ["Alice..x@example.com", "Alice@example..com", "Alice@@example.com", "\"Alice\"@example.com", `${"a".repeat(65)}@example.com`]) {
        const rejected = await request(baseUrl, "/v1/aliases:resolve", { method: "POST", body: { operation: "directory.alias.resolve", protocol_version: "1.0", system: "email", normalization: "native.email-ascii-v1", value: invalid } });
        assert(rejected.status === 400 && rejected.body.code === "invalid_request", `invalid email alias was normalized: ${invalid}`);
      }
      const negotiation = await request(baseUrl, "/v1/profiles:negotiate", { method: "POST", body: { operation: "directory.negotiate", protocol_version: "1.0", profiles: [profileName], capabilities: [], required_capabilities: [] } });
      assert(negotiation.status === 200 && negotiation.body.result.selected_profile === profileName && negotiation.body.signature, "profile negotiation failed");
      verifyDetached(negotiation.body.result, negotiation.body.signature, load("fixtures/verification-keys.json").authority, "native-profile-negotiation+jws");
      const mutation = await request(baseUrl, "/v1/principals/alice0001/keys", { method: "POST", proofSigner: "alice_signing", operation: "directory.key.publish", body: { operation: "directory.key.publish", protocol_version: "1.0", principal: { network_id: "native", principal_id: "alice0001" }, statement: {}, signature: load("fixtures/positive/principal-document.json").principal_signature } });
      assert(mutation.status === 200 && mutation.headers.get("cache-control") === "no-store", "authenticated directory mutation failed");
    });
    await check("fake-relay-fanout-lease-ack", "protocol-state", async ({ baseUrl, envelopeFixture }) => {
      const many = load("fixtures/positive/envelope-many-recipients.json");
      const submitted = await request(baseUrl, "/v1/envelopes", { method: "POST", proofSigner: "alice_signing", operation: "relay.submit", body: { operation: "relay.submit", envelope: many } });
      assert(submitted.status === 200 && submitted.body.results.length === 2, "fan-out was not independent per recipient");
      const relayJwk = load("fixtures/verification-keys.json").relay;
      for (const result of submitted.body.results) verifyDetached(result.receipt.receipt, result.receipt.signature, relayJwk, "native-relay-receipt+jws");
      const collected = await request(baseUrl, "/v1/mailboxes/00000000-0000-4000-8000-000000000201:collect", { method: "POST", proofSigner: "bob_installation", operation: "relay.collect", body: { operation: "relay.collect", limit: 100, wait_seconds: 0 } });
      const collectedCarol = await request(baseUrl, "/v1/mailboxes/00000000-0000-4000-8000-000000000202:collect", { method: "POST", proofSigner: "carol_installation", operation: "relay.collect", body: { operation: "relay.collect", limit: 100, wait_seconds: 0 } });
      assert(collected.body.deliveries.length === 1 && collectedCarol.body.deliveries.length === 1 && [...collected.body.deliveries, ...collectedCarol.body.deliveries].every((item) => item.attempt === 1), "fan-out did not isolate recipient mailboxes");
      const item = collected.body.deliveries[0];
      const ackBody = { operation: "relay.acknowledge", acknowledgements: [{ delivery_id: item.delivery_id, envelope_id: item.envelope.envelope.envelope_id, envelope_digest: item.envelope_digest, lease_token: item.lease_token, disposition: "received" }] };
      const acked = await request(baseUrl, "/v1/mailboxes/00000000-0000-4000-8000-000000000201/acknowledgements", { method: "POST", proofSigner: "bob_installation", operation: "relay.acknowledge", body: ackBody });
      const retry = await request(baseUrl, "/v1/mailboxes/00000000-0000-4000-8000-000000000201/acknowledgements", { method: "POST", proofSigner: "bob_installation", operation: "relay.acknowledge", body: ackBody });
      assert(acked.status === 200 && jcs(acked.body) === jcs(retry.body), "ack retry did not return stable receipt bytes");
      verifyDetached(acked.body.receipts[0].receipt, acked.body.receipts[0].signature, relayJwk, "native-relay-receipt+jws");
      const crossMailbox = await request(baseUrl, "/v1/mailboxes/00000000-0000-4000-8000-000000000202/acknowledgements", { method: "POST", proofSigner: "carol_installation", operation: "relay.acknowledge", body: ackBody });
      assert(crossMailbox.status === 409, "ack retry crossed mailbox scope");
      for (const patch of [
        { envelope_id: "00000000-0000-4000-8000-000000000999" },
        { envelope_digest: "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
        { lease_token: "AAAAAAAAAAAAAAAAAAAAAA" },
        { disposition: "rejected" },
      ]) {
        const tamperedBody = { operation: "relay.acknowledge", acknowledgements: [{ ...ackBody.acknowledgements[0], ...patch }] };
        const tampered = await request(baseUrl, "/v1/mailboxes/00000000-0000-4000-8000-000000000201/acknowledgements", { method: "POST", proofSigner: "bob_installation", operation: "relay.acknowledge", body: tamperedBody });
        assert(tampered.status === 409, `ack retry accepted tampered tuple ${JSON.stringify(patch)}`);
      }
      assert(envelopeFixture.envelope.envelope_id, "baseline fixture missing");
    });
    await check("fake-request-proof-fail-closed", "request-proof", async ({ baseUrl }) => {
      const submitBody = { operation: "relay.submit", envelope: load("fixtures/positive/envelope-one-recipient.json") };
      const missing = await request(baseUrl, "/v1/envelopes", { method: "POST", body: submitBody });
      assert(missing.status === 401, "missing request proof was accepted");
      const originalRaw = Buffer.from(JSON.stringify(submitBody));
      const changedBody = structuredClone(submitBody);
      changedBody.envelope.envelope.extensions = { "example.net:changed": true };
      const tampered = await request(baseUrl, "/v1/envelopes", { method: "POST", proofSigner: "alice_signing", operation: "relay.submit", proofRawBody: originalRaw, body: changedBody });
      assert(tampered.status === 401, "request proof did not bind exact body bytes");
      const wrongAudience = await request(baseUrl, "/v1/envelopes", { method: "POST", proofSigner: "alice_signing", operation: "relay.submit", audience: "https://directory.withnative.example", body: submitBody });
      assert(wrongAudience.status === 401, "request proof did not bind audience");
      const expired = await request(baseUrl, "/v1/envelopes", { method: "POST", proofSigner: "alice_signing", operation: "relay.submit", proofOverrides: { created_at: "2026-08-02T08:00:00Z", expires_at: "2026-08-02T08:05:00Z" }, body: submitBody });
      assert(expired.status === 401, "expired request proof was accepted");
      const expiresAtBoundary = await request(baseUrl, "/v1/envelopes", { method: "POST", proofSigner: "alice_signing", operation: "relay.submit", proofOverrides: { created_at: "2026-08-02T09:05:00Z", expires_at: "2026-08-02T09:10:00Z" }, body: submitBody });
      assert(expiresAtBoundary.status === 401, "request proof was accepted at expires_at");
      const replayNonce = "AAAAAAAAAAAAAAAAAAAAAA";
      const first = await request(baseUrl, "/v1/envelopes", { method: "POST", proofSigner: "alice_signing", operation: "relay.submit", proofOverrides: { nonce: replayNonce }, body: submitBody });
      const replayed = await request(baseUrl, "/v1/envelopes", { method: "POST", proofSigner: "alice_signing", operation: "relay.submit", proofOverrides: { nonce: replayNonce }, body: submitBody });
      assert(first.status === 200 && first.headers.get("native-request-id") === first.proofRequestId, "signed request id was not echoed");
      assert(replayed.status === 409 && replayed.body.code === "idempotency_conflict", "nonce replay was not rejected");
      const inboundId = await request(baseUrl, "/v1/envelopes", { method: "POST", proofSigner: "alice_signing", operation: "relay.submit", headers: { "Native-Request-Id": "00000000-0000-4000-8000-000000000999" }, body: submitBody });
      assert(inboundId.status === 200 && inboundId.headers.get("native-request-id") === inboundId.proofRequestId, "unsigned inbound request id changed the authenticated response id");
      const rootScope = await request(baseUrl, "/v1/envelopes", { method: "POST", proofSigner: "alice_root", operation: "relay.submit", body: submitBody });
      assert(rootScope.status === 403, "request proof operation scope was not enforced");
      const installationPutBody = { operation: "directory.installation.put", protocol_version: "1.0", principal: { network_id: "native", principal_id: "alice0001" }, installation: {} };
      const installationPut = await request(baseUrl, "/v1/principals/alice0001/installations/00000000-0000-4000-8000-000000000101", { method: "PUT", proofSigner: "alice_installation", operation: "directory.installation.put", body: installationPutBody });
      assert(installationPut.status === 200, "verified installation authorization could not update its endpoint");
      const crossInstallationPut = await request(baseUrl, "/v1/principals/alice0001/installations/00000000-0000-4000-8000-000000000999", { method: "PUT", proofSigner: "alice_installation", operation: "directory.installation.put", body: installationPutBody });
      assert(crossInstallationPut.status === 403, "installation proof crossed endpoint scope");
      for (const advance of ["-1", "NaN", "9999", "01"]) {
        const invalidAdvance = await request(baseUrl, "/v1/mailboxes/00000000-0000-4000-8000-000000000201:collect", { method: "POST", proofSigner: "bob_installation", operation: "relay.collect", headers: { "Native-Conformance-Advance-Seconds": advance }, body: { operation: "relay.collect", limit: 1, wait_seconds: 0 } });
        assert(invalidAdvance.status === 400 && invalidAdvance.body.code === "invalid_request", `invalid clock advance was accepted: ${advance}`);
      }
      const unauthenticatedAdvance = await request(baseUrl, "/v1/mailboxes/00000000-0000-4000-8000-000000000201:collect", { method: "POST", headers: { "Native-Conformance-Advance-Seconds": "301" }, body: { operation: "relay.collect", limit: 1, wait_seconds: 0 } });
      assert(unauthenticatedAdvance.status === 401, "clock control ran before request-proof authorization");
      const oversized = await fetch(`${baseUrl}/v1/aliases:resolve`, { method: "POST", headers: { "content-type": "application/json" }, body: `{"padding":"${"x".repeat(1048576)}"}` });
      const oversizedBody = await oversized.json();
      assert(oversized.status === 413 && oversizedBody.code === "payload_too_large", "oversized request body was buffered or accepted");
    });
    await check("fake-relay-redelivery-and-quota", "service-behaviour", async ({ baseUrl }) => {
      const submitted = await request(baseUrl, "/v1/envelopes", { method: "POST", proofSigner: "alice_signing", operation: "relay.submit", body: { operation: "relay.submit", envelope: load("fixtures/positive/envelope-one-recipient.json") } });
      assert(submitted.status === 200, "submission failed");
      const first = await request(baseUrl, "/v1/mailboxes/00000000-0000-4000-8000-000000000201:collect", { method: "POST", proofSigner: "bob_installation", operation: "relay.collect", body: { operation: "relay.collect", limit: 100, wait_seconds: 0 } });
      const concurrent = await request(baseUrl, "/v1/mailboxes/00000000-0000-4000-8000-000000000201:collect", { method: "POST", proofSigner: "bob_installation", operation: "relay.collect", body: { operation: "relay.collect", limit: 100, wait_seconds: 0 } });
      assert(first.body.deliveries.length >= 1 && concurrent.body.deliveries.length === 0, "live leases overlapped");
      const retried = await request(baseUrl, "/v1/mailboxes/00000000-0000-4000-8000-000000000201:collect", { method: "POST", proofSigner: "bob_installation", operation: "relay.collect", headers: { "Native-Conformance-Advance-Seconds": "301" }, body: { operation: "relay.collect", limit: 100, wait_seconds: 0 } });
      assert(retried.body.deliveries.some((item) => item.attempt === 2), "expired lease was not redelivered");
      const quota = await request(baseUrl, "/v1/envelopes", { method: "POST", proofSigner: "alice_signing", operation: "relay.submit", clock: "2026-08-02T09:15:01Z", headers: { "Native-Conformance-Scenario": "quota" }, body: { operation: "relay.submit", envelope: load("fixtures/positive/envelope-one-recipient.json") } });
      assert(quota.status === 429 && quota.body.code === "quota_exceeded" && quota.headers.get("retry-after") === "30", "quota response was not distinct and retryable");
    });
  } finally {
    await new Promise((resolve) => fake.server.close(resolve));
  }
  return results;
}

const fakeServiceIndex = [
  ["fake-directory-read-etag", "service-behaviour"],
  ["fake-directory-alias-and-negotiation", "service-behaviour"],
  ["fake-relay-fanout-lease-ack", "protocol-state"],
  ["fake-request-proof-fail-closed", "request-proof"],
  ["fake-relay-redelivery-and-quota", "service-behaviour"],
].map(([id, layer]) => ({ id, expected: { layers: [layer] } }));

async function runAdapter(executable, adapterArgs, baseUrl, clock, limits) {
  const started = performance.now();
  return new Promise((resolvePromise, rejectPromise) => {
    let child;
    try {
      child = spawn(executable, adapterArgs, {
        cwd: repoRoot,
        env: {
          ...process.env,
          NATIVE_FEDERATION_PROFILE: profileName,
          NATIVE_FEDERATION_DIRECTORY_URL: baseUrl,
          NATIVE_FEDERATION_RELAY_URL: baseUrl,
          NATIVE_FEDERATION_CLOCK: clock,
          NATIVE_FEDERATION_FIXTURE_ROOT: profileRoot,
          NATIVE_FEDERATION_MANIFEST: join(profileRoot, "fixtures/manifest.json"),
          NATIVE_FEDERATION_REQUEST_PROOF_SIGNING: join(profileRoot, "fixtures/request-proof-signing.json"),
          NATIVE_FEDERATION_NETWORK_DESCRIPTOR_URL: `${baseUrl}/v1/network`,
          NATIVE_FEDERATION_DIRECTORY_AUDIENCE: baseUrl,
          NATIVE_FEDERATION_RELAY_AUDIENCE: baseUrl,
        },
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (error) {
      rejectPromise(harnessFailure("adapter_spawn_failed", `could not start adapter ${executable}`, error));
      return;
    }

    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let terminalFailure;
    let shutdownTimer;
    const terminate = (failure) => {
      if (terminalFailure) return;
      terminalFailure = failure;
      child.kill("SIGTERM");
      shutdownTimer = setTimeout(() => child.kill("SIGKILL"), limits.shutdownTimeoutMs);
      shutdownTimer.unref();
    };
    const capture = (chunks, streamName) => (chunk) => {
      if (streamName === "stdout") stdoutBytes += chunk.length;
      else stderrBytes += chunk.length;
      if ((streamName === "stdout" ? stdoutBytes : stderrBytes) > limits.outputBytes) {
        terminate(harnessFailure("adapter_output_limit", `adapter ${streamName} exceeded ${limits.outputBytes} bytes`));
        return;
      }
      chunks.push(chunk);
    };
    child.stdout.on("data", capture(stdout, "stdout"));
    child.stderr.on("data", capture(stderr, "stderr"));
    child.once("error", (error) => {
      terminalFailure = harnessFailure("adapter_spawn_failed", `could not start adapter ${executable}`, error);
    });
    const runTimer = setTimeout(
      () => terminate(harnessFailure("adapter_timeout", `adapter exceeded ${limits.timeoutMs}ms startup/run timeout`)),
      limits.timeoutMs,
    );
    runTimer.unref();
    child.once("close", (code, signal) => {
      clearTimeout(runTimer);
      clearTimeout(shutdownTimer);
      if (terminalFailure) {
        rejectPromise(terminalFailure);
        return;
      }
      let report;
      try { report = JSON.parse(Buffer.concat(stdout).toString("utf8")); } catch { report = null; }
      let contractError;
      try { validateAdapterReport(report); } catch (error) { contractError = error.message; }
      const pass = code === 0 && !contractError;
      resolvePromise({
        id: `adapter:${executable}`,
        status: pass ? "pass" : "fail",
        expected: { result: "valid", layers: ["adapter"] },
        observed: {
          result: pass ? "valid" : "invalid",
          layer: "adapter",
          exit_code: code,
          ...(signal ? { error: `terminated by ${signal}` } : {}),
          ...(report ? { report } : {}),
          ...(contractError || signal ? { error: contractError ?? `terminated by ${signal}` } : {}),
          ...(stderr.length ? { stderr: Buffer.concat(stderr).toString("utf8") } : {}),
        },
        duration_ms: Math.round((performance.now() - started) * 1000) / 1000,
        crypto_status: "not-applicable",
      });
    });
  });
}

function validateAdapterReport(report) {
  if (!report || report.status !== "pass") throw new Error("adapter did not report status=pass");
  const manifestBytes = readFileSync(join(profileRoot, "fixtures/manifest.json"));
  const manifest = JSON.parse(manifestBytes);
  if (report.corpus?.manifest_digest !== digestBytes(manifestBytes)) throw new Error("adapter manifest digest mismatch");
  if (!Array.isArray(report.corpus?.results) || report.corpus.results.length !== manifest.cases.length) {
    throw new Error(`adapter corpus is not closed: expected ${manifest.cases.length} results`);
  }
  const byId = new Map();
  for (const result of report.corpus.results) {
    if (!result || typeof result.id !== "string" || byId.has(result.id)) throw new Error("adapter corpus contains a missing or duplicate case id");
    byId.set(result.id, result);
  }
  for (const entry of manifest.cases) {
    const result = byId.get(entry.id);
    if (!result) throw new Error(`adapter omitted manifest case ${entry.id}`);
    const fixtureBytes = readFileSync(join(profileRoot, entry.path));
    if (result.fixture_digest !== digestBytes(fixtureBytes)) throw new Error(`adapter fixture digest mismatch for ${entry.id}`);
    if (result.observed?.result !== entry.expect) throw new Error(`adapter observed wrong result for ${entry.id}`);
    if (entry.expect === "invalid" && result.observed?.error !== entry.error) throw new Error(`adapter observed wrong error for ${entry.id}`);
    if (entry.expect === "invalid" && !entry.validation_layers.includes(result.observed?.layer)) throw new Error(`adapter observed an unlisted layer for ${entry.id}`);
  }
  const extras = [...byId.keys()].filter((id) => !manifest.cases.some((entry) => entry.id === id));
  if (extras.length) throw new Error(`adapter reported non-manifest cases: ${extras.join(",")}`);
}

function matchesFilter(entry, filter) {
  if (!filter) return true;
  const needles = filter.split(",").map((item) => item.trim()).filter(Boolean);
  return needles.some((needle) => entry.id.includes(needle) || entry.validation_layers.some((layer) => layer.includes(needle)));
}

function matchesResultFilter(entry, filter) {
  if (!filter) return true;
  const needles = filter.split(",").map((item) => item.trim()).filter(Boolean);
  return needles.some((needle) => entry.id.includes(needle) || entry.expected.layers.some((layer) => layer.includes(needle)));
}

function emit(report, format) {
  if (format === "jsonl") {
    for (const item of report.cases) process.stdout.write(`${JSON.stringify(item)}\n`);
    const { cases: _cases, ...summary } = report;
    process.stdout.write(`${JSON.stringify({ type: "summary", ...summary })}\n`);
  } else {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  }
}

const valueOptions = new Set([
  "--profile", "--clock", "--filter", "--format", "--adapter", "--adapter-arg",
  "--adapter-timeout-ms", "--adapter-output-bytes", "--adapter-shutdown-timeout-ms",
  "--host", "--port", "--directory-url", "--relay-url", "--network-descriptor-url", "--request-timeout-ms",
]);

function parseArguments(argv) {
  const command = argv[0] ?? "help";
  if (["help", "--help", "-h"].includes(command)) {
    if (argv.length !== 1 && argv.length !== 0) throw harnessFailure("usage", "help does not accept options");
    return { command: "help", values: new Map() };
  }
  if (!new Set(["run", "list", "serve", "probe"]).has(command)) throw harnessFailure("usage", `unknown command: ${command}`);
  const allowed = {
    run: new Set(["--profile", "--clock", "--filter", "--format", "--adapter", "--adapter-arg", "--adapter-timeout-ms", "--adapter-output-bytes", "--adapter-shutdown-timeout-ms"]),
    list: new Set(["--profile", "--filter", "--format"]),
    serve: new Set(["--profile", "--clock", "--host", "--port", "--relay-url"]),
    probe: new Set(["--profile", "--clock", "--format", "--directory-url", "--relay-url", "--network-descriptor-url", "--request-timeout-ms"]),
  }[command];
  const values = new Map();
  for (let index = 1; index < argv.length; index += 1) {
    const flag = argv[index];
    if (!valueOptions.has(flag) || !allowed.has(flag)) throw harnessFailure("usage", `unknown or invalid option for ${command}: ${flag}`);
    if (index + 1 >= argv.length || (flag !== "--adapter-arg" && argv[index + 1].startsWith("--"))) {
      throw harnessFailure("usage", `missing value for ${flag}`);
    }
    const value = argv[++index];
    if (values.has(flag) && flag !== "--adapter-arg") throw harnessFailure("usage", `duplicate option: ${flag}`);
    values.set(flag, flag === "--adapter-arg" ? [...(values.get(flag) ?? []), value] : value);
  }
  if (values.has("--adapter-arg") && !values.has("--adapter")) throw harnessFailure("usage", "--adapter-arg requires --adapter");
  for (const flag of ["--adapter-timeout-ms", "--adapter-output-bytes", "--adapter-shutdown-timeout-ms"]) {
    if (values.has(flag) && !values.has("--adapter")) throw harnessFailure("usage", `${flag} requires --adapter`);
  }
  return { command, values };
}

function serviceUrl(values, flag, allowPath = false) {
  const raw = values.get(flag);
  if (!raw) throw harnessFailure("usage", `${flag} is required for probe`);
  let parsed;
  try { parsed = new URL(raw); } catch { throw harnessFailure("usage", `${flag} must be an absolute URL`); }
  const loopback = new Set(["127.0.0.1", "::1", "localhost"]).has(parsed.hostname);
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
    throw harnessFailure("usage", `${flag} must use HTTPS, except for loopback interoperability tests`);
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash || (!allowPath && parsed.pathname !== "/")) {
    throw harnessFailure("usage", `${flag} contains unsupported URL components`);
  }
  return allowPath ? parsed.href : parsed.origin;
}

function strictInteger(values, flag, fallback, minimum, maximum) {
  const raw = values.get(flag) ?? String(fallback);
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) throw harnessFailure("usage", `${flag} must be an integer`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw harnessFailure("usage", `${flag} must be between ${minimum} and ${maximum}`);
  }
  return value;
}

function strictClock(value) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) || Number.isNaN(Date.parse(value))) {
    throw harnessFailure("usage", "--clock must be an RFC3339 UTC timestamp with whole seconds");
  }
  if (new Date(value).toISOString().replace(".000Z", "Z") !== value) throw harnessFailure("usage", "--clock is not a real timestamp");
  return value;
}

function harnessReport(error, clock = defaultClock) {
  return {
    schema_version: "1.0",
    profile: profileName,
    protocol_version: "1.0",
    clock,
    jose_hpke_status: "work-in-progress",
    warning: "FINAL-RFC JOSE-HPKE fixtures are structural placeholders, not final cryptographic vectors",
    summary: { total: 0, passed: 0, failed: 0, status: "error" },
    cases: [],
    harness_error: { code: error.code ?? "internal_error", message: error.message },
  };
}

async function main() {
  const { command, values } = parseArguments(process.argv.slice(2));
  if (command === "help") {
    process.stdout.write(help);
    return;
  }
  const clock = strictClock(values.get("--clock") ?? defaultClock);
  errorReportClock = clock;
  const requestedProfile = values.get("--profile") ?? profileName;
  if (requestedProfile !== profileName) throw harnessFailure("unsupported_profile", `unsupported profile: ${requestedProfile}`);
  let manifest;
  try {
    manifest = load("fixtures/manifest.json");
    validateManifestAndTree(manifest);
  } catch (error) {
    if (error instanceof HarnessFailure) throw error;
    throw harnessFailure("fixture_manifest_invalid", error.message, error);
  }
  const filter = values.get("--filter") ?? "";
  const format = values.get("--format") ?? "json";
  if (!new Set(["json", "jsonl"]).has(format)) throw harnessFailure("usage", "--format must be json or jsonl");

  if (command === "list") {
    const selected = manifest.cases.filter((entry) => matchesFilter(entry, filter));
    if (selected.length === 0) throw harnessFailure("no_cases_selected", "filter selected zero cases");
    emit({ schema_version: "1.0", profile: profileName, summary: { total: selected.length }, cases: selected }, format);
    return;
  }
  if (command === "serve") {
    const port = strictInteger(values, "--port", 0, 0, 65535);
    const host = values.get("--host") ?? "127.0.0.1";
    if (!new Set(["127.0.0.1", "::1", "localhost"]).has(host)) throw harnessFailure("usage", "--host must be a loopback host");
    const relayUrl = values.has("--relay-url") ? serviceUrl(values, "--relay-url") : undefined;
    const fake = await listenFake(clock, port, host, relayUrl);
    process.stdout.write(`${JSON.stringify({ profile: profileName, directory_url: fake.baseUrl, relay_url: relayUrl ?? fake.baseUrl, clock, warning: "FINAL-RFC JOSE-HPKE values are structural placeholders, not cryptographic vectors" })}\n`);
    await new Promise((resolve) => {
      process.once("SIGINT", resolve);
      process.once("SIGTERM", resolve);
    });
    await new Promise((resolve) => fake.server.close(resolve));
    return;
  }
  if (command === "probe") {
    const directoryUrl = serviceUrl(values, "--directory-url");
    const relayUrl = serviceUrl(values, "--relay-url");
    const descriptorUrl = serviceUrl(values, "--network-descriptor-url", true);
    const requestTimeoutMs = strictInteger(values, "--request-timeout-ms", 5000, 50, 30000);
    const cases = await externalServiceResults(clock, directoryUrl, relayUrl, descriptorUrl, requestTimeoutMs);
    const passed = cases.filter((entry) => entry.status === "pass").length;
    const report = {
      schema_version: "1.0", profile: profileName, protocol_version: "1.0", clock,
      jose_hpke_status: "work-in-progress",
      warning: "FINAL-RFC JOSE-HPKE fixtures are structural placeholders, not final cryptographic vectors",
      summary: { total: cases.length, passed, failed: cases.length - passed, status: passed === cases.length ? "pass" : "fail" },
      cases,
    };
    validateSchema("schemas/conformance-result.schema.json", report);
    emit(report, values.get("--format") ?? "json");
    if (report.summary.status !== "pass") process.exitCode = 1;
    return;
  }
  let cases = manifest.cases.filter((entry) => matchesFilter(entry, filter)).map((entry) => resultFor(entry, clock));
  if (!filter || fakeServiceIndex.some((entry) => matchesResultFilter(entry, filter))) {
    const fakeResults = await fakeServiceResults(clock);
    cases = cases.concat(fakeResults.filter((entry) => matchesResultFilter(entry, filter)));
  }
  const adapter = values.get("--adapter");
  if (adapter) {
    const fake = await listenFake(clock);
    const limits = {
      timeoutMs: strictInteger(values, "--adapter-timeout-ms", 30000, 100, 300000),
      outputBytes: strictInteger(values, "--adapter-output-bytes", 1048576, 1024, 16777216),
      shutdownTimeoutMs: strictInteger(values, "--adapter-shutdown-timeout-ms", 2000, 100, 10000),
    };
    try { cases.push(await runAdapter(adapter, values.get("--adapter-arg") ?? [], fake.baseUrl, clock, limits)); }
    finally { await new Promise((resolve) => fake.server.close(resolve)); }
  }
  if (cases.length === 0) throw harnessFailure("no_cases_selected", "filter selected zero cases");
  const passed = cases.filter((entry) => entry.status === "pass").length;
  const report = {
    schema_version: "1.0",
    profile: profileName,
    protocol_version: "1.0",
    clock,
    jose_hpke_status: "work-in-progress",
    warning: "FINAL-RFC JOSE-HPKE fixtures are structural placeholders, not final cryptographic vectors",
    summary: { total: cases.length, passed, failed: cases.length - passed, status: passed === cases.length ? "pass" : "fail" },
    cases,
  };
  validateSchema("schemas/conformance-result.schema.json", report);
  emit(report, format);
  if (report.summary.status !== "pass") process.exitCode = 1;
}

main().catch((error) => {
  const failure = error instanceof HarnessFailure ? error : harnessFailure("internal_error", error.message ?? String(error), error);
  const report = harnessReport(failure, errorReportClock);
  try { validateSchema("schemas/conformance-result.schema.json", report); } catch {}
  const formatIndex = process.argv.indexOf("--format");
  const errorFormat = formatIndex >= 0 && process.argv[formatIndex + 1] === "jsonl" ? "jsonl" : "json";
  emit(report, errorFormat);
  process.exitCode = 2;
});
