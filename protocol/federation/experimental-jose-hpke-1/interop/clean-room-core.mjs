// Clean-room validation core derived solely from the published specification,
// schemas, and fixture corpus. This module has no Native implementation import.

import { createHash, createPublicKey, verify } from "node:crypto";

export const PROFILE = "native-fed/experimental-jose-hpke-1";

export class ValidationFailure extends Error {
  constructor(layer, code, message = `${layer}: ${code}`) {
    super(message);
    this.layer = layer;
    this.code = code;
  }
}

const fail = (layer, code, message) => { throw new ValidationFailure(layer, code, message); };
const assert = (condition, layer, code, message) => { if (!condition) fail(layer, code, message); };

function assertUnicodeScalars(value, path) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      assert(next >= 0xdc00 && next <= 0xdfff, "schema", "invalid_request", `${path} contains an unpaired surrogate`);
      index += 1;
    } else assert(!(unit >= 0xdc00 && unit <= 0xdfff), "schema", "invalid_request", `${path} contains an unpaired surrogate`);
  }
}

export function validateIJson(value) {
  const seen = new Set();
  const visit = (current, depth, path) => {
    assert(depth <= 32, "schema", "invalid_request", `${path} exceeds the maximum JSON depth`);
    if (current === null || typeof current === "boolean") return;
    if (typeof current === "number") {
      assert(Number.isSafeInteger(current), "schema", "invalid_request", `${path} is not a safe integer`);
      return;
    }
    if (typeof current === "string") {
      assertUnicodeScalars(current, path);
      assert(Buffer.byteLength(current, "utf8") <= 4096, "schema", "invalid_request", `${path} exceeds the string byte limit`);
      return;
    }
    assert(current && typeof current === "object", "schema", "invalid_request", `${path} is not an I-JSON value`);
    assert(!seen.has(current), "schema", "invalid_request", `${path} contains a cycle`);
    seen.add(current);
    if (Array.isArray(current)) {
      assert(current.length <= 256, "schema", "invalid_request", `${path} exceeds the array item limit`);
      current.forEach((item, index) => visit(item, depth + 1, `${path}[${index}]`));
    } else {
      const entries = Object.entries(current);
      assert(entries.length <= 256, "schema", "invalid_request", `${path} exceeds the object member limit`);
      for (const [key, item] of entries) {
        assertUnicodeScalars(key, `${path} member name`);
        assert(Buffer.byteLength(key, "utf8") <= 4096, "schema", "invalid_request", `${path} has an oversized member name`);
        visit(item, depth + 1, `${path}.${key}`);
      }
    }
    seen.delete(current);
  };
  visit(value, 1, "$input");
  assert(Buffer.byteLength(JSON.stringify(value), "utf8") <= 1_048_576, "schema", "invalid_request", "JSON document exceeds the byte limit");
}

export function parseIJsonBytes(input) {
  const bytes = typeof input === "string" ? Buffer.from(input) : Buffer.from(input);
  assert(bytes.length <= 1_048_576, "schema", "invalid_request", "JSON document exceeds the byte limit");
  let source;
  try { source = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { fail("schema", "invalid_request", "JSON is not valid UTF-8"); }
  let index = 0;
  const whitespace = () => { while (index < source.length && /[\u0009\u000a\u000d\u0020]/.test(source[index])) index += 1; };
  const syntax = (message) => fail("schema", "invalid_request", `invalid JSON at offset ${index}: ${message}`);
  const parseStringToken = () => {
    if (source[index] !== '"') syntax("expected string");
    const start = index;
    index += 1;
    while (index < source.length) {
      const code = source.charCodeAt(index);
      if (code === 0x22) {
        index += 1;
        try { return JSON.parse(source.slice(start, index)); }
        catch { syntax("invalid string escape"); }
      }
      if (code < 0x20) syntax("unescaped control character");
      if (code === 0x5c) {
        index += 1;
        if (index >= source.length) syntax("unterminated escape");
        if (source[index] === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(source.slice(index + 1, index + 5))) syntax("invalid Unicode escape");
          index += 5;
          continue;
        }
        if (!'"\\/bfnrt'.includes(source[index])) syntax("invalid escape");
      }
      index += 1;
    }
    syntax("unterminated string");
  };
  const parseNumberToken = () => {
    if (source[index] === "-") index += 1;
    if (source[index] === "0") index += 1;
    else {
      if (!/[1-9]/.test(source[index] ?? "")) syntax("invalid number");
      while (/[0-9]/.test(source[index] ?? "")) index += 1;
    }
    if (source[index] === "." || source[index] === "e" || source[index] === "E") syntax("protocol numbers must use integer lexemes");
  };
  const literal = (value) => {
    if (source.slice(index, index + value.length) !== value) syntax(`expected ${value}`);
    index += value.length;
  };
  const parseValue = (depth) => {
    assert(depth <= 32, "schema", "invalid_request", "JSON exceeds the maximum depth");
    whitespace();
    const token = source[index];
    if (token === '"') { parseStringToken(); return; }
    if (token === "{") {
      index += 1;
      whitespace();
      const names = new Set();
      let members = 0;
      if (source[index] === "}") { index += 1; return; }
      while (true) {
        whitespace();
        const name = parseStringToken();
        assert(!names.has(name), "schema", "invalid_request", `duplicate JSON member name ${JSON.stringify(name)}`);
        names.add(name);
        members += 1;
        assert(members <= 256, "schema", "invalid_request", "JSON object exceeds the member limit");
        whitespace();
        if (source[index] !== ":") syntax("expected colon");
        index += 1;
        parseValue(depth + 1);
        whitespace();
        if (source[index] === "}") { index += 1; return; }
        if (source[index] !== ",") syntax("expected comma or object end");
        index += 1;
      }
    }
    if (token === "[") {
      index += 1;
      whitespace();
      let items = 0;
      if (source[index] === "]") { index += 1; return; }
      while (true) {
        parseValue(depth + 1);
        items += 1;
        assert(items <= 256, "schema", "invalid_request", "JSON array exceeds the item limit");
        whitespace();
        if (source[index] === "]") { index += 1; return; }
        if (source[index] !== ",") syntax("expected comma or array end");
        index += 1;
      }
    }
    if (token === "t") { literal("true"); return; }
    if (token === "f") { literal("false"); return; }
    if (token === "n") { literal("null"); return; }
    if (token === "-" || /[0-9]/.test(token ?? "")) { parseNumberToken(); return; }
    syntax("expected value");
  };
  whitespace();
  parseValue(1);
  whitespace();
  if (index !== source.length) syntax("trailing content");
  let value;
  try { value = JSON.parse(source); }
  catch { fail("schema", "invalid_request", "invalid JSON"); }
  validateIJson(value);
  return value;
}

export function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    assert(Number.isSafeInteger(value), "schema", "invalid_request", "JCS rejects non-integer or unsafe numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  fail("schema", "invalid_request", `JCS rejects ${typeof value}`);
}

export const b64u = (value) => Buffer.from(value).toString("base64url");
export const sha = (value) => createHash("sha256").update(value).digest();
export const digestBytes = (value) => `sha-256:${b64u(sha(value))}`;
export const digestValue = (value) => digestBytes(Buffer.from(canonical(value)));

export function strictServiceUrl(raw, allowPath = false) {
  let parsed;
  try { parsed = new URL(raw); } catch { fail("url", "invalid_request", "service URL must be absolute"); }
  const loopback = new Set(["127.0.0.1", "::1", "localhost"]).has(parsed.hostname);
  assert(parsed.protocol === "https:" || (parsed.protocol === "http:" && loopback), "url", "invalid_request", "service URL requires HTTPS except on loopback");
  assert(!parsed.username && !parsed.password && !parsed.search && !parsed.hash, "url", "invalid_request", "service URL contains forbidden components");
  assert(allowPath || parsed.pathname === "/", "url", "invalid_request", "service base URL must not contain a path");
  return allowPath ? parsed.href : parsed.origin;
}

function strictB64u(value, layer = "jws") {
  assert(typeof value === "string" && /^[A-Za-z0-9_-]+$/.test(value), layer, "signature_invalid", "non-canonical base64url");
  const bytes = Buffer.from(value, "base64url");
  assert(b64u(bytes) === value, layer, "signature_invalid", "non-canonical base64url");
  return bytes;
}

function schemaB64u(value, path, expectedBytes, allowEmpty = false) {
  assert(typeof value === "string" && (allowEmpty ? /^[A-Za-z0-9_-]*$/ : /^[A-Za-z0-9_-]+$/).test(value), "schema", "invalid_request", `${path} is not base64url`);
  const bytes = Buffer.from(value, "base64url");
  assert(b64u(bytes) === value && (expectedBytes === undefined || bytes.length === expectedBytes), "schema", "invalid_request", `${path} is not canonical base64url`);
  return bytes;
}

function assertClosed(value, allowed, required, path) {
  assert(value && typeof value === "object" && !Array.isArray(value), "schema", "invalid_request", `${path} must be an object`);
  for (const key of Object.keys(value)) assert(allowed.includes(key), "schema", "invalid_request", `${path}.${key} is not allowed`);
  for (const key of required) assert(Object.hasOwn(value, key), "schema", "invalid_request", `${path}.${key} is required`);
}

const timestampPattern = /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;
const uuidV4Pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const digestPattern = /^sha-256:[A-Za-z0-9_-]{43}$/;
const capabilityPattern = /^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/;
const signingKidPattern = /^n1\.signing\.[A-Za-z0-9_-]{43}$/;
const encryptionKidPattern = /^n1\.encryption\.[A-Za-z0-9_-]{43}$/;
const relayKidPattern = /^n1\.relay\.[A-Za-z0-9_-]{43}$/;

function timestampMillis(value, path, layer = "schema") {
  assert(typeof value === "string" && timestampPattern.test(value), layer, "invalid_request", `${path} is not a canonical timestamp`);
  const milliseconds = Date.parse(value);
  assert(Number.isFinite(milliseconds) && new Date(milliseconds).toISOString().replace(".000Z", "Z") === value,
    layer, "invalid_request", `${path} is not a real UTC timestamp`);
  return milliseconds;
}

function assertUuid(value, path, layer = "schema") {
  assert(typeof value === "string" && uuidV4Pattern.test(value), layer, "invalid_request", `${path} is not a UUIDv4`);
}

function assertDigest(value, path, layer = "schema") {
  assert(typeof value === "string" && digestPattern.test(value), layer, "invalid_request", `${path} is not a SHA-256 digest`);
  const encoded = value.slice("sha-256:".length);
  const bytes = Buffer.from(encoded, "base64url");
  assert(bytes.length === 32 && b64u(bytes) === encoded, layer, "invalid_request", `${path} is not a canonical SHA-256 digest`);
}

function assertCapabilityArray(value, maximum, path) {
  assert(Array.isArray(value) && value.length <= maximum, "schema", "invalid_request", `${path} has invalid cardinality`);
  assert(new Set(value).size === value.length && value.every((item) => typeof item === "string" && item.length <= 96 && capabilityPattern.test(item)),
    "schema", "invalid_request", `${path} contains an invalid or duplicate capability`);
}

function assertExtensions(value, path) {
  assert(value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length <= 64,
    "schema", "invalid_request", `${path} must be an extensions object`);
  assert(Object.keys(value).every((key) => key.length <= 96 && capabilityPattern.test(key)),
    "schema", "invalid_request", `${path} contains an invalid extension name`);
}

function assertAddress(value, path) {
  assertClosed(value, ["network_id", "principal_id"], ["network_id", "principal_id"], path);
  assert(addressValid(value), "schema", "invalid_request", `${path} is not a principal address`);
}

export function verifyDetached(payload, compact, jwk, typ) {
  assert(jwk && typeof compact === "string", "jws", "signature_invalid", `missing ${typ} material`);
  const parts = compact.split(".");
  assert(parts.length === 3 && parts[1] === "", "jws", "signature_invalid", `${typ} is not detached compact JWS`);
  const header = JSON.parse(strictB64u(parts[0]));
  assert(canonical(header) === canonical({ alg: "EdDSA", kid: jwk.kid, typ }), "jws", "signature_invalid", `${typ} header mismatch`);
  assert(parts[0] === b64u(Buffer.from(canonical(header))), "jws", "signature_invalid", `${typ} header is not canonical`);
  const input = Buffer.from(`${parts[0]}.${b64u(Buffer.from(canonical(payload)))}`);
  assert(verify(null, input, createPublicKey({ key: jwk, format: "jwk" }), strictB64u(parts[2])), "jws", "signature_invalid", `${typ} signature invalid`);
}

function protectedKid(compact) {
  const parts = compact?.split(".") ?? [];
  assert(parts.length === 3, "jws", "signature_invalid");
  return JSON.parse(strictB64u(parts[0])).kid;
}

function expectedKid(jwk, purpose) {
  return `n1.${purpose}.${b64u(sha(Buffer.from(canonical({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }))))}`;
}

function validateJwk(jwk, purpose) {
  const encryption = purpose === "encryption";
  assertClosed(jwk, ["kty", "crv", "x", "alg", "use", "kid"], ["kty", "crv", "x", "alg", "use", "kid"], `${purpose} JWK`);
  assert(jwk?.kty === "OKP" && jwk.crv === (encryption ? "X25519" : "Ed25519")
    && jwk.alg === (encryption ? "HPKE-3-KE" : "EdDSA") && jwk.use === (encryption ? "enc" : "sig"),
  "key-purpose", "invalid_request", `invalid ${purpose} JWK`);
  schemaB64u(jwk.x, `${purpose} public key`, 32);
  assert(jwk.kid === expectedKid(jwk, purpose), "kid", "invalid_request", `invalid ${purpose} kid`);
}

function keyUsable(record, instant) {
  const now = new Date(instant).getTime();
  return record.status === "active" && new Date(record.not_before).getTime() <= now
    && (!record.not_after || now < new Date(record.not_after).getTime())
    && (!record.revocation || now < new Date(record.revocation.effective_at).getTime());
}

function validateWindow(value, instant) {
  const issued = timestampMillis(value.issued_at, "issued_at", "freshness");
  const fresh = timestampMillis(value.fresh_until, "fresh_until", "freshness");
  const hard = timestampMillis(value.hard_expires_at, "hard_expires_at", "freshness");
  const now = timestampMillis(instant, "clock", "freshness");
  assert(issued < fresh && fresh <= hard
    && fresh - issued <= 900_000 && hard - issued <= 86_400_000 && issued <= now,
  "freshness", "invalid_request", "invalid validity window");
  if (now >= hard) fail("freshness", "expired");
  if (now >= fresh) fail("freshness", "stale_document");
}

function addressValid(value) {
  if (!value || typeof value.network_id !== "string" || typeof value.principal_id !== "string") return false;
  const network = value.network_id;
  const principal = value.principal_id;
  const dns = network.startsWith("dns:") ? network.slice(4) : null;
  const networkOk = network === "native"
    || (dns !== null && dns.length <= 253 && dns.split(".").every((label) => /^(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,61}[a-z0-9])$/.test(label)))
    || /^key:[A-Za-z0-9_-]{43}$/.test(network);
  if (!(networkOk && network.length <= 257 && /^(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._~-]{0,62}[A-Za-z0-9])$/.test(principal))) return false;
  if (network.startsWith("key:")) {
    const encoded = network.slice(4);
    const bytes = Buffer.from(encoded, "base64url");
    return bytes.length === 32 && b64u(bytes) === encoded;
  }
  return true;
}

const binding = (principal) => `${principal.network_id}/${principal.principal_id}`;

function normalizeEmail(value) {
  if (typeof value !== "string" || value.length > 254 || value.includes("\"") || value.split("@").length !== 2) return null;
  const [local, domain] = value.split("@");
  if (!local || local.length > 64 || local.startsWith(".") || local.endsWith(".") || local.includes("..")) return null;
  if (!/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)) return null;
  const lower = domain.toLowerCase();
  if (!lower || lower.includes("..") || !lower.split(".").every((label) => /^(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,61}[a-z0-9])$/.test(label))) return null;
  return `${local}@${lower}`;
}

export function validateNetwork(wrapper, clock, load) {
  validateIJson(wrapper);
  assertClosed(wrapper, ["descriptor", "signature"], ["descriptor", "signature"], "network");
  const descriptor = wrapper.descriptor;
  const pinned = load("fixtures/verification-keys.json");
  const required = ["descriptor_type", "protocol_version", "network_id", "descriptor_version", "issued_at", "fresh_until", "hard_expires_at", "directory_base_url", "relay_base_urls", "authority_keys", "relay_keys", "supported_profiles", "profile_preference", "capabilities", "limits", "historical_verification_seconds", "extensions"];
  assert(descriptor && typeof descriptor === "object" && !Array.isArray(descriptor), "schema", "invalid_request", "descriptor must be an object");
  for (const key of required) assert(Object.hasOwn(descriptor, key), "schema", "invalid_request", `descriptor.${key} is required`);
  validateWindow(descriptor, clock);
  assert(descriptor.descriptor_type === "native.federation.network" && descriptor.protocol_version === "1.0" && descriptor.network_id === "native"
    && descriptor.supported_profiles?.includes(PROFILE) && descriptor.profile_preference?.includes(PROFILE),
  "version", "unsupported_profile");
  assert(Number.isSafeInteger(descriptor.descriptor_version) && descriptor.descriptor_version >= 1, "schema", "invalid_request", "invalid descriptor version");
  strictServiceUrl(descriptor.directory_base_url);
  assert(descriptor.directory_base_url.length <= 2048, "schema", "invalid_request", "directory URL is too long");
  assert(Array.isArray(descriptor.relay_base_urls) && descriptor.relay_base_urls.length <= 16 && new Set(descriptor.relay_base_urls).size === descriptor.relay_base_urls.length, "schema", "invalid_request", "invalid relay URL list");
  for (const url of descriptor.relay_base_urls) {
    assert(url.length <= 2048, "schema", "invalid_request", "relay URL is too long");
    strictServiceUrl(url);
  }
  assert(Array.isArray(descriptor.authority_keys) && descriptor.authority_keys.length >= 1 && descriptor.authority_keys.length <= 8, "schema", "invalid_request", "invalid authority key count");
  assert(Array.isArray(descriptor.relay_keys) && descriptor.relay_keys.length >= 1 && descriptor.relay_keys.length <= 16, "schema", "invalid_request", "invalid relay key count");
  for (const [purpose, records] of [["authority", descriptor.authority_keys], ["relay", descriptor.relay_keys]]) {
    for (const record of records) {
      assertClosed(record, ["jwk", "status", "not_before", "not_after"], ["jwk", "status", "not_before"], `${purpose} service key`);
      validateJwk(record.jwk, purpose);
      assert(["active", "retired", "revoked"].includes(record.status), "schema", "invalid_request", `invalid ${purpose} key status`);
      const notBefore = timestampMillis(record.not_before, `${purpose}.not_before`);
      if (record.not_after !== undefined) assert(notBefore < timestampMillis(record.not_after, `${purpose}.not_after`), "schema", "invalid_request", `invalid ${purpose} key window`);
    }
  }
  assert(Array.isArray(descriptor.supported_profiles) && descriptor.supported_profiles.length >= 1 && descriptor.supported_profiles.length <= 16 && new Set(descriptor.supported_profiles).size === descriptor.supported_profiles.length, "schema", "invalid_request", "invalid supported profiles");
  assert(Array.isArray(descriptor.profile_preference) && descriptor.profile_preference.length >= 1 && descriptor.profile_preference.length <= 16 && new Set(descriptor.profile_preference).size === descriptor.profile_preference.length, "schema", "invalid_request", "invalid profile preference");
  assert(descriptor.supported_profiles.every((item) => typeof item === "string" && item.length <= 96)
    && descriptor.profile_preference.every((item) => typeof item === "string" && item.length <= 96), "schema", "invalid_request", "invalid profile identifier");
  assertCapabilityArray(descriptor.capabilities, 128, "descriptor.capabilities");
  assertClosed(descriptor.limits, ["max_envelope_bytes", "max_recipients", "default_retention_seconds", "max_retention_seconds", "collection_limit", "lease_seconds"], ["max_envelope_bytes", "max_recipients", "default_retention_seconds", "max_retention_seconds", "collection_limit", "lease_seconds"], "descriptor.limits");
  const limitBounds = { max_envelope_bytes: [262144, 1048576], max_recipients: [16, 128], default_retention_seconds: [86400, 604800], max_retention_seconds: [86400, 2592000], collection_limit: [1, 100], lease_seconds: [30, 900] };
  for (const [key, [minimum, maximum]] of Object.entries(limitBounds)) assert(Number.isInteger(descriptor.limits[key]) && descriptor.limits[key] >= minimum && descriptor.limits[key] <= maximum, "schema", "invalid_request", `invalid descriptor limit ${key}`);
  assert(Number.isSafeInteger(descriptor.historical_verification_seconds) && descriptor.historical_verification_seconds >= 315_576_000, "schema", "invalid_request", "historical verification window is too short");
  assertExtensions(descriptor.extensions, "descriptor.extensions");
  const authority = descriptor.authority_keys.find((record) => keyUsable(record, clock) && record.jwk.kid === protectedKid(wrapper.signature));
  assert(authority && canonical(authority.jwk) === canonical(pinned.authority), "trust-binding", "signature_invalid");
  assert(descriptor.relay_keys.some((record) => keyUsable(record, clock)), "trust-binding", "signature_invalid", "descriptor has no active relay verification key");
  verifyDetached(descriptor, wrapper.signature, pinned.authority, "native-network-descriptor+jws");
}

export function validatePrincipal(wrapper, clock, load, trustedNetwork) {
  validateIJson(wrapper);
  assertClosed(wrapper, ["document", "principal_signature", "authority_attestation"], ["document", "principal_signature", "authority_attestation"], "principal");
  const document = wrapper.document;
  const required = ["document_type", "protocol_version", "profile", "network_id", "principal_id", "document_version", "issued_at", "fresh_until", "hard_expires_at", "continuity", "root_keys", "operational_keys", "installations", "verified_aliases", "delivery_endpoints", "supported_profiles", "capabilities", "required_capabilities", "extensions"];
  assert(document && typeof document === "object" && !Array.isArray(document), "schema", "invalid_request", "principal document must be an object");
  for (const key of required) assert(Object.hasOwn(document, key), "schema", "invalid_request", `document.${key} is required`);
  assert(document.document_type === "native.federation.principal" && document.protocol_version === "1.0" && document.profile === PROFILE, "schema", "invalid_request", "invalid principal document type, version, or profile");
  assert(addressValid({ network_id: document.network_id, principal_id: document.principal_id }), "address", "invalid_principal_address");
  assert(Number.isSafeInteger(document.document_version) && document.document_version >= 1 && ["continuous", "authority_recovered"].includes(document.continuity), "schema", "invalid_request", "invalid principal version or continuity");
  validateWindow(document, clock);
  const network = trustedNetwork ?? load("fixtures/positive/network-descriptor.json");
  validateNetwork(network, clock, load);
  assert(Array.isArray(document.root_keys) && document.root_keys.length >= 1 && document.root_keys.length <= 8, "schema", "invalid_request", "invalid root key count");
  assert(Array.isArray(document.operational_keys) && document.operational_keys.length >= 2 && document.operational_keys.length <= 32, "schema", "invalid_request", "invalid operational key count");
  assert(Array.isArray(document.installations) && document.installations.length <= 128, "schema", "invalid_request", "invalid installation count");
  const validateRevocation = (revocation, path) => {
    assertClosed(revocation, ["revoked_at", "effective_at", "reason", "replacement_kid"], ["revoked_at", "effective_at", "reason"], path);
    timestampMillis(revocation.revoked_at, `${path}.revoked_at`);
    timestampMillis(revocation.effective_at, `${path}.effective_at`);
    assert(["compromised", "cessation", "authorization_withdrawn"].includes(revocation.reason), "schema", "invalid_request", `invalid ${path} reason`);
  };
  for (const record of document.root_keys) {
    assertClosed(record, ["jwk", "status", "not_before", "not_after", "revocation"], ["jwk", "status", "not_before"], "root key");
    validateJwk(record.jwk, "root");
    assert(["active", "retired", "revoked"].includes(record.status), "schema", "invalid_request", "invalid root key status");
    timestampMillis(record.not_before, "root.not_before");
    if (record.not_after !== undefined) timestampMillis(record.not_after, "root.not_after");
    if (record.revocation) validateRevocation(record.revocation, "root.revocation");
  }
  const principal = { network_id: document.network_id, principal_id: document.principal_id };
  for (const record of document.operational_keys) {
    assertClosed(record, ["purpose", "jwk", "status", "not_before", "not_after", "authorization", "revocation"], ["purpose", "jwk", "status", "not_before", "authorization"], "operational key");
    assert(["signing", "encryption"].includes(record.purpose) && ["active", "retired", "revoked"].includes(record.status), "schema", "invalid_request", "invalid operational key metadata");
    validateJwk(record.jwk, record.purpose);
    timestampMillis(record.not_before, "operational-key.not_before");
    if (record.not_after !== undefined) timestampMillis(record.not_after, "operational-key.not_after");
    if (record.revocation) validateRevocation(record.revocation, "operational-key.revocation");
    const authorization = record.authorization;
    assertClosed(authorization, ["statement", "signature"], ["statement", "signature"], "operational authorization");
    const authorizationKey = authorization.statement?.key;
    assertClosed(authorization.statement, ["statement_type", "protocol_version", "principal", "key", "issued_at"], ["statement_type", "protocol_version", "principal", "key", "issued_at"], "operational authorization statement");
    assertClosed(authorizationKey, ["purpose", "jwk", "status", "not_before", "not_after"], ["purpose", "jwk", "status", "not_before"], "operational authorization key");
    assert(authorization.statement.statement_type === "native.operational-key-authorization" && authorization.statement.protocol_version === "1.0"
      && authorizationKey.purpose === record.purpose && authorizationKey.status === "active"
      && canonical(authorizationKey.jwk) === canonical(record.jwk) && authorizationKey.not_before === record.not_before
      && (record.status === "active" ? authorizationKey.not_after === record.not_after
        : record.not_after !== undefined && Date.parse(record.not_after) <= Date.parse(authorizationKey.not_after)), "authorization-binding", "signature_invalid");
    timestampMillis(authorization.statement.issued_at, "operational authorization issued_at");
    const root = document.root_keys.find((entry) => keyUsable(entry, authorization.statement.issued_at) && entry.jwk.kid === protectedKid(authorization.signature));
    assert(root && canonical(authorization.statement.principal) === canonical(principal), "authorization-binding", "signature_invalid");
    verifyDetached(authorization.statement, authorization.signature, root.jwk, "native-key-authorization+jws");
  }
  for (const installation of document.installations) {
    assertClosed(installation, ["installation_id", "jwk", "status", "endpoint_origin", "scopes", "authorization", "revocation"], ["installation_id", "jwk", "status", "endpoint_origin", "scopes", "authorization"], "installation");
    assertUuid(installation.installation_id, "installation.installation_id");
    validateJwk(installation.jwk, "installation");
    assert(["active", "retired", "revoked"].includes(installation.status), "schema", "invalid_request", "invalid installation status");
    strictServiceUrl(installation.endpoint_origin);
    assert(Array.isArray(installation.scopes) && installation.scopes.length >= 1 && new Set(installation.scopes).size === installation.scopes.length
      && installation.scopes.every((scope) => ["directory.endpoint.update", "relay.collect", "relay.acknowledge"].includes(scope)), "schema", "invalid_request", "invalid installation scopes");
    if (installation.revocation) validateRevocation(installation.revocation, "installation.revocation");
    assertClosed(installation.authorization, ["statement", "signature"], ["statement", "signature"], "installation authorization");
    assertClosed(installation.authorization.statement, ["statement_type", "protocol_version", "principal", "installation", "issued_at"], ["statement_type", "protocol_version", "principal", "installation", "issued_at"], "installation authorization statement");
    assertClosed(installation.authorization.statement.installation, ["installation_id", "jwk", "status", "endpoint_origin", "scopes"], ["installation_id", "jwk", "status", "endpoint_origin", "scopes"], "installation authorization value");
    const signingAt = timestampMillis(installation.authorization.statement.issued_at, "installation authorization issued_at");
    const signing = document.operational_keys.find((entry) => entry.purpose === "signing"
      && entry.jwk.kid === protectedKid(installation.authorization.signature)
      && new Date(entry.not_before).getTime() <= signingAt
      && (!entry.not_after || signingAt < new Date(entry.not_after).getTime())
      && (!entry.revocation || signingAt < new Date(entry.revocation.effective_at).getTime()));
    const authorizedInstallation = installation.authorization.statement.installation;
    assert(signing && installation.authorization.statement.statement_type === "native.installation-key-authorization"
      && installation.authorization.statement.protocol_version === "1.0" && canonical(installation.authorization.statement.principal) === canonical(principal)
      && canonical(authorizedInstallation) === canonical({ installation_id: installation.installation_id, jwk: installation.jwk, status: "active", endpoint_origin: installation.endpoint_origin, scopes: installation.scopes }),
    "authorization-binding", "signature_invalid");
    verifyDetached(installation.authorization.statement, installation.authorization.signature, signing.jwk, "native-key-authorization+jws");
  }
  assert(Array.isArray(document.verified_aliases) && document.verified_aliases.length <= 64, "schema", "invalid_request", "invalid alias count");
  for (const alias of document.verified_aliases) {
    assertClosed(alias, ["system", "value", "normalization", "verified_at", "fresh_until", "verifier", "method", "proof_ref"], ["system", "value", "normalization", "verified_at", "fresh_until", "verifier", "method"], "verified alias");
    assert(alias.system === "email" && alias.normalization === "native.email-ascii-v1" && normalizeEmail(alias.value) === alias.value && typeof alias.verifier === "string" && alias.verifier.length <= 257 && typeof alias.method === "string" && alias.method.length <= 96, "schema", "invalid_request", "invalid verified alias");
    timestampMillis(alias.verified_at, "alias.verified_at");
    timestampMillis(alias.fresh_until, "alias.fresh_until");
  }
  assert(Array.isArray(document.delivery_endpoints) && document.delivery_endpoints.length >= 1 && document.delivery_endpoints.length <= 16, "schema", "invalid_request", "invalid endpoint count");
  for (const endpoint of document.delivery_endpoints) {
    assertClosed(endpoint, ["kind", "url", "priority"], ["kind", "url", "priority"], "delivery endpoint");
    assert(["relay", "direct"].includes(endpoint.kind) && Number.isInteger(endpoint.priority) && endpoint.priority >= 0 && endpoint.priority <= 65535, "schema", "invalid_request", "invalid delivery endpoint");
    assert(typeof endpoint.url === "string" && endpoint.url.length <= 2048, "schema", "invalid_request", "delivery endpoint URL is too long");
    strictServiceUrl(endpoint.url, true);
  }
  assert(Array.isArray(document.supported_profiles) && document.supported_profiles.length >= 1 && document.supported_profiles.length <= 16 && new Set(document.supported_profiles).size === document.supported_profiles.length, "schema", "invalid_request", "invalid principal supported profiles");
  assert(document.supported_profiles.includes(PROFILE) && document.supported_profiles.every((item) => typeof item === "string" && item.length <= 96), "schema", "unsupported_profile", "principal does not support the selected profile");
  assert(document.operational_keys.filter((record) => record.purpose === "encryption" && keyUsable(record, clock)).length <= 2, "schema", "invalid_request", "too many active encryption rollover keys");
  assertCapabilityArray(document.capabilities, 128, "document.capabilities");
  assertCapabilityArray(document.required_capabilities, 32, "document.required_capabilities");
  assertExtensions(document.extensions, "document.extensions");
  const signing = document.operational_keys.find((record) => record.purpose === "signing" && record.jwk.kid === protectedKid(wrapper.principal_signature));
  assert(signing, "jws", "signature_invalid");
  if (signing.status === "revoked") fail("key-state", "key_revoked");
  assert(keyUsable(signing, clock), "key-state", "signature_invalid");
  verifyDetached(document, wrapper.principal_signature, signing.jwk, "native-principal+jws");
  const attestation = wrapper.authority_attestation;
  const expected = {
    statement_type: "native.authority.principal-attestation", protocol_version: "1.0", network_id: document.network_id,
    principal, document_version: document.document_version, document_digest: digestValue(document),
    root_kids: document.root_keys.map((record) => record.jwk.kid), issued_at: document.issued_at,
    fresh_until: document.fresh_until, hard_expires_at: document.hard_expires_at,
    directory_base_url: network.descriptor.directory_base_url,
  };
  assert(canonical(attestation.statement) === canonical(expected), "authority-digest", "conflict");
  const authorityRecord = network.descriptor.authority_keys.find((record) => record.jwk.kid === protectedKid(attestation.signature) && keyUsable(record, attestation.statement.issued_at));
  assert(authorityRecord, "trust-binding", "signature_invalid", "principal attestation authority key is not active");
  verifyDetached(attestation.statement, attestation.signature, authorityRecord.jwk, "native-principal-attestation+jws");
}

export function validateEnvelope(wrapper, clock, load, trust = {}) {
  validateIJson(wrapper);
  assertClosed(wrapper, ["envelope", "signature"], ["envelope", "signature"], "transport-envelope");
  const envelope = wrapper.envelope;
  assert(envelope && typeof envelope === "object" && !Array.isArray(envelope), "schema", "invalid_request", "envelope must be an object");
  for (const key of ["envelope_type", "protocol_version", "profile", "envelope_id", "sender_principal", "sender_key_id", "recipients", "content_type", "content_version", "created_at", "required_capabilities", "extensions", "ciphertext_digest", "jwe"]) {
    assert(Object.hasOwn(envelope, key), "schema", "invalid_request", `envelope.${key} is required`);
  }
  assert(envelope.envelope_type === "native.federation.transport" && envelope.protocol_version === "1.0" && envelope.profile === PROFILE,
    "schema", "invalid_request", "envelope type, protocol version, or profile is invalid");
  assertUuid(envelope.envelope_id, "envelope.envelope_id");
  assertAddress(envelope.sender_principal, "envelope.sender_principal");
  assert(typeof envelope.sender_key_id === "string" && signingKidPattern.test(envelope.sender_key_id), "schema", "invalid_request", "invalid sender key id");
  assert(typeof envelope.content_type === "string" && envelope.content_type.length <= 127
    && /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(envelope.content_type), "schema", "invalid_request", "invalid content type");
  const version = /^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$/.exec(envelope.content_version ?? "");
  assert(version && Number(version[1]) <= 65535 && Number(version[2]) <= 65535, "schema", "invalid_request", "invalid content version");
  assertCapabilityArray(envelope.required_capabilities, 32, "envelope.required_capabilities");
  assertExtensions(envelope.extensions, "envelope.extensions");
  assertDigest(envelope.ciphertext_digest, "envelope.ciphertext_digest");
  const created = timestampMillis(envelope.created_at, "envelope.created_at");
  const now = timestampMillis(clock, "clock");
  assert(created <= now + 300_000, "schema", "invalid_request", "envelope creation is too far in the future");
  if (Object.hasOwn(envelope, "expires_at")) {
    const expires = timestampMillis(envelope.expires_at, "envelope.expires_at");
    assert(created < expires && expires - created <= 2_592_000_000, "schema", "invalid_request", "invalid envelope lifetime");
    assert(now < expires, "expiry", "expired");
  }
  const recipients = envelope.recipients;
  assert(Array.isArray(recipients) && recipients.length >= 1 && recipients.length <= 128, "schema", "invalid_request", "invalid recipient count");
  for (const [index, recipient] of recipients.entries()) {
    assertClosed(recipient, ["principal", "encryption_key_id"], ["principal", "encryption_key_id"], `envelope.recipients[${index}]`);
    assertAddress(recipient.principal, `envelope.recipients[${index}].principal`);
    assert(typeof recipient.encryption_key_id === "string" && encryptionKidPattern.test(recipient.encryption_key_id), "schema", "invalid_request", "invalid recipient encryption key id");
  }
  assert(recipients.every((entry, index) => index === 0 || binding(recipients[index - 1].principal) < binding(entry.principal)), "recipient-order", "invalid_request");
  assertClosed(envelope.jwe, ["protected", "aad", "recipients", "iv", "ciphertext", "tag"], ["protected", "aad", "recipients", "iv", "ciphertext", "tag"], "envelope.jwe");
  schemaB64u(envelope.jwe.protected, "envelope.jwe.protected", undefined, true);
  schemaB64u(envelope.jwe.aad, "envelope.jwe.aad", undefined, true);
  schemaB64u(envelope.jwe.ciphertext, "envelope.jwe.ciphertext", undefined, true);
  schemaB64u(envelope.jwe.iv, "envelope.jwe.iv", 12);
  schemaB64u(envelope.jwe.tag, "envelope.jwe.tag", 16);
  const inner = envelope.jwe.recipients;
  assert(Array.isArray(inner) && inner.length >= 1 && inner.length <= 128, "schema", "invalid_request", "invalid JWE recipient count");
  for (const [index, recipient] of inner.entries()) {
    assertClosed(recipient, ["header", "encrypted_key"], ["header", "encrypted_key"], `envelope.jwe.recipients[${index}]`);
    assertClosed(recipient.header, ["kid", "ek"], ["kid", "ek"], `envelope.jwe.recipients[${index}].header`);
    assert(typeof recipient.header.kid === "string" && encryptionKidPattern.test(recipient.header.kid), "schema", "invalid_request", "invalid JWE recipient kid");
    schemaB64u(recipient.header.ek, `envelope.jwe.recipients[${index}].header.ek`, 32);
    schemaB64u(recipient.encrypted_key, `envelope.jwe.recipients[${index}].encrypted_key`, 48);
  }
  assert(Array.isArray(inner) && inner.length === recipients.length
    && inner.every((entry, index) => entry.header?.kid === recipients[index].encryption_key_id), "recipient-mapping", "recipient_mismatch");
  const context = Object.fromEntries(Object.entries(envelope).filter(([key]) => key !== "jwe" && key !== "ciphertext_digest"));
  assert(envelope.jwe.aad === b64u(Buffer.from(canonical(context))), "context", "malformed_envelope");
  let header;
  try { header = JSON.parse(strictB64u(envelope.jwe.protected)); } catch { fail("protected-header", "malformed_envelope"); }
  const expectedHeader = { alg: "HPKE-3-KE", enc: "A256GCM", typ: "native-federation+jwe", cty: envelope.content_type, native_profile: PROFILE, crit: ["native_profile"] };
  assert(canonical(header) === canonical(expectedHeader) && envelope.jwe.protected === b64u(Buffer.from(canonical(expectedHeader))), "protected-header", "malformed_envelope");
  assert(envelope.ciphertext_digest === digestBytes(strictB64u(envelope.jwe.ciphertext)), "encryption", "malformed_envelope");
  assert(!(envelope.required_capabilities ?? []).some((item) => item !== "native.relay.receipts"), "capability", "required_capability_unsupported");
  const publishedPrincipals = trust.principals ?? Object.values(load("fixtures/request-proof-signing.json").principals);
  const trustedNetwork = trust.network;
  for (const recipient of recipients) {
    const principal = publishedPrincipals.find((wrapper) => wrapper.document.network_id === recipient.principal.network_id && wrapper.document.principal_id === recipient.principal.principal_id);
    if (principal && trustedNetwork) validatePrincipal(principal, clock, load, trustedNetwork);
    const encryption = principal?.document.operational_keys.find((record) => record.purpose === "encryption" && record.jwk.kid === recipient.encryption_key_id && keyUsable(record, clock));
    assert(encryption, "recipient-binding", "recipient_mismatch", `recipient encryption key is not active for ${binding(recipient.principal)}`);
  }
  assert(protectedKid(wrapper.signature) === envelope.sender_key_id, "sender-key-binding", "signature_invalid");
  const principal = publishedPrincipals.find((candidate) => binding(envelope.sender_principal) === `${candidate.document.network_id}/${candidate.document.principal_id}`);
  assert(principal, "sender-key-binding", "signature_invalid", "sender principal is not published");
  validatePrincipal(principal, clock, load, trustedNetwork);
  const signing = principal.document.operational_keys.find((record) => record.purpose === "signing" && record.jwk.kid === envelope.sender_key_id && keyUsable(record, clock));
  assert(signing && binding(envelope.sender_principal) === `${principal.document.network_id}/${principal.document.principal_id}`, "sender-key-binding", "signature_invalid");
  verifyDetached(envelope, wrapper.signature, signing.jwk, "native-envelope+jws");
}

export function validateReceipt(wrapper, load, expected = {}, trustedNetwork, clock) {
  validateIJson(wrapper);
  assertClosed(wrapper, ["receipt", "signature"], ["receipt", "signature"], "relay-receipt");
  const receipt = wrapper.receipt;
  const required = ["receipt_type", "protocol_version", "profile", "receipt_id", "relay_id", "relay_key_id", "delivery_id", "envelope_id", "envelope_digest", "recipient", "state", "observed_at"];
  assert(receipt && typeof receipt === "object" && !Array.isArray(receipt), "schema", "invalid_request", "receipt must be an object");
  for (const key of required) assert(Object.hasOwn(receipt, key), "schema", "invalid_request", `receipt.${key} is required`);
  assert(receipt.receipt_type === "native.relay.delivery-receipt" && receipt.protocol_version === "1.0" && receipt.profile === PROFILE,
    "schema", "invalid_request", "invalid receipt type, version, or profile");
  assertUuid(receipt.receipt_id, "receipt.receipt_id");
  assert(typeof receipt.relay_id === "string" && receipt.relay_id.length >= 1 && receipt.relay_id.length <= 257, "schema", "invalid_request", "invalid relay id");
  assert(typeof receipt.relay_key_id === "string" && relayKidPattern.test(receipt.relay_key_id), "schema", "invalid_request", "invalid relay key id");
  assertUuid(receipt.delivery_id, "receipt.delivery_id");
  assertUuid(receipt.envelope_id, "receipt.envelope_id");
  assertDigest(receipt.envelope_digest, "receipt.envelope_digest");
  assertAddress(receipt.recipient, "receipt.recipient");
  const observedAt = timestampMillis(receipt.observed_at, "receipt.observed_at");
  if (clock !== undefined) assert(observedAt <= timestampMillis(clock, "clock") + 300_000, "schema", "invalid_request", "receipt timestamp is too far in the future");
  if (Object.hasOwn(receipt, "collector_installation_id")) assertUuid(receipt.collector_installation_id, "receipt.collector_installation_id");
  if (Object.hasOwn(receipt, "previous_state")) assert(["queued", "collected"].includes(receipt.previous_state), "schema", "invalid_request", "invalid previous receipt state");
  if (Object.hasOwn(receipt, "reason_code")) assert(["invalid_recipient", "principal_revoked", "key_revoked", "expired", "policy_rejected"].includes(receipt.reason_code), "schema", "invalid_request", "invalid receipt reason code");
  assert(protectedKid(wrapper.signature) === receipt.relay_key_id, "relay-key-binding", "signature_invalid");
  const has = (key) => Object.hasOwn(receipt, key);
  const stateValid = receipt.state === "queued" ? !has("previous_state") && !has("collector_installation_id") && !has("reason_code")
    : receipt.state === "collected" ? receipt.previous_state === "queued" && has("collector_installation_id") && !has("reason_code")
      : receipt.state === "acknowledged" ? receipt.previous_state === "collected" && has("collector_installation_id") && !has("reason_code")
        : receipt.state === "rejected" && has("reason_code") && !has("collector_installation_id");
  assert(stateValid, "receipt-state", "invalid_request");
  assert(receipt.state !== "rejected" || !has("previous_state") || receipt.reason_code === "expired", "receipt-state", "invalid_request", "only expiry may reject an existing delivery state");
  const network = trustedNetwork ?? load("fixtures/positive/network-descriptor.json");
  validateNetwork(network, clock ?? receipt.observed_at, load);
  const relayRecord = network.descriptor.relay_keys.find((record) => record.jwk.kid === receipt.relay_key_id);
  assert(relayRecord && keyUsable(relayRecord, receipt.observed_at), "relay-key-binding", "signature_invalid");
  verifyDetached(receipt, wrapper.signature, relayRecord.jwk, "native-relay-receipt+jws");
  for (const [key, value] of Object.entries(expected)) {
    assert(canonical(receipt[key]) === canonical(value), "receipt-binding", "conflict", `receipt ${key} mismatch`);
  }
}

function assertSubset(actual, expected) {
  if (expected === null || typeof expected !== "object") return assert(actual === expected, "scenario", "invalid_request");
  for (const [key, value] of Object.entries(expected)) assertSubset(actual?.[key], value);
}

function validateScenario(value, id) {
  assert(value.scenario_id === id && Array.isArray(value.steps) && value.steps.length, "schema", "invalid_request");
  const steps = value.steps;
  switch (id) {
    case "directory-etag-revalidation":
      assertSubset({ status: 200, etag: "strong", cache_control: "must-revalidate" }, steps[0].expect);
      assertSubset({ status: steps[1].if_none_match === "previous" ? 304 : 200, cache_control: "must-revalidate" }, steps[1].expect); return;
    case "directory-alias-resolve": {
      const normalized = normalizeEmail(steps[0].value);
      assertSubset(normalized === "Alice@example.com" ? { status: 200, principal: "native/alice0001", cache_control: "no-store" } : { status: 404, code: "unknown_alias" }, steps[0].expect); return;
    }
    case "directory-profile-negotiate":
      assertSubset(steps[0].profiles.includes(PROFILE) ? { status: 200, selected_profile: PROFILE, signed: true } : { status: 406 }, steps[0].expect); return;
    case "envelope-replay-identical":
      assertSubset({ state: "queued" }, steps[0].expect);
      assertSubset(steps[0].digest === steps[1].digest ? { state: "queued", same_delivery_id: true, same_receipt_bytes: true } : { code: "idempotency_conflict" }, steps[1].expect); return;
    case "relay-fanout-lifecycle":
      assertSubset({ state: "queued", independent_results: steps[0].recipients }, steps[0].expect);
      assertSubset({ state: "collected", attempt: 1, lease_seconds: 300 }, steps[1].expect);
      assert(steps[2].disposition === "received", "acknowledgement", "conflict");
      assertSubset({ state: "acknowledged", stable_receipt: true }, steps[2].expect); return;
    case "relay-ack-retry":
      assertSubset({ state: "acknowledged", receipt_id: "stable" }, steps[0].expect);
      assertSubset({ state: "acknowledged", same_receipt_bytes: steps[1].retry === true }, steps[1].expect); return;
    case "relay-lease-redelivery":
      assertSubset({ state: "collected", attempt: 1 }, steps[0].expect);
      assertSubset({ state: "collected", attempt: steps[1].advance_seconds > 300 ? 2 : 1, new_lease: steps[1].advance_seconds > 300, no_new_transition_receipt: true }, steps[2].expect); return;
    case "principal-document-rollback": if (steps[0].received_version < steps[0].cached_version) fail("rollback", "conflict"); return;
    case "alias-unverified": if (!steps[0].verified) fail("alias", "alias_unverified"); return;
    case "alias-collision": if (new Set(steps[0].active_principals).size > 1) fail("alias", "conflict"); return;
    case "alias-reassignment-stale": if (steps[1].version > steps[0].version && steps[1].principal !== steps[0].principal) fail("freshness", "stale_document"); return;
    case "alias-local-part-case-mismatch": if (normalizeEmail(steps[0].query) !== normalizeEmail(steps[0].stored)) fail("alias", "unknown_alias"); return;
    case "directory-mutation-unauthorized": if (!steps[0].request_proof) fail("authorization", "unauthorized"); return;
    case "directory-precondition-failed": if (steps[0].if_match === "stale") fail("etag", "precondition_failed"); return;
    case "directory-unsupported-profile": if (!steps[0].profiles.includes(PROFILE)) fail("negotiation", "unsupported_profile"); return;
    case "directory-required-capability": if (steps[0].required_capabilities.some((item) => item !== "native.relay.receipts")) fail("capability", "required_capability_unsupported"); return;
    case "relay-concurrent-lease": if (steps[0].live_lease_holders > 1) fail("lease", "conflict"); return;
    case "relay-ack-digest-mismatch": if (steps[0].acknowledgement_digest !== steps[0].envelope_digest) fail("acknowledgement", "conflict"); return;
    case "relay-ack-wrong-lease": if (steps[0].lease_token !== steps[0].expected_lease_token) fail("lease", "conflict"); return;
    case "relay-quota-exceeded": if (steps[0].mailbox_quota_remaining < 1) fail("quota", "quota_exceeded"); return;
    case "relay-terminal-transition": if (["acknowledged", "rejected"].includes(steps[0].from)) fail("protocol-state", "delivery_terminal"); return;
    default: fail("scenario", "invalid_request", `unimplemented scenario ${id}`);
  }
}

export function validateCorpusCase(entry, value, clock, load) {
  validateIJson(value);
  if (entry.id === "profile-negotiation-response") {
    assertClosed(value, ["result", "signature"], ["result", "signature"], "negotiation");
    const network = load("fixtures/positive/network-descriptor.json");
    validateNetwork(network, clock, load);
    verifyDetached(value.result, value.signature, load("fixtures/verification-keys.json").authority, "native-profile-negotiation+jws");
    assert(value.result.selected_profile === PROFILE && new Date(clock) < new Date(value.result.fresh_until), "negotiation", "unsupported_profile");
  } else if (entry.id === "idempotency-conflict") {
    if (digestValue(value.first) !== digestValue(value.retry)) fail("idempotency", "idempotency_conflict");
  } else if (entry.schema.includes("scenario.schema.json")) validateScenario(value, entry.id);
  else if (entry.id.startsWith("principal-address-")) assert(addressValid(value), "schema", "invalid_request");
  else if (entry.schema.includes("network-descriptor")) validateNetwork(value, clock, load);
  else if (entry.schema.includes("principal-document")) validatePrincipal(value, clock, load);
  else if (entry.schema.includes("transport-envelope")) validateEnvelope(value, clock, load);
  else if (entry.schema.includes("relay-receipt")) {
    validateReceipt(value, load, {}, undefined, clock);
    if (entry.id === "receipt-envelope-digest" && value.receipt.envelope_digest !== digestValue(load("fixtures/positive/envelope-one-recipient.json"))) fail("envelope-digest", "conflict");
  } else if (entry.id === "error-rate-limited") {
    assert(value && typeof value === "object" && !Array.isArray(value), "schema", "invalid_request", "problem must be an object");
    for (const key of ["type", "title", "status", "code", "request_id", "retryable", "retry_after"]) assert(Object.hasOwn(value, key), "schema", "invalid_request", `problem.${key} is required`);
    assert(value.code === "rate_limited" && value.status === 429 && value.retryable === true, "error-registry", "invalid_request");
  } else fail("schema", "invalid_request", `unsupported corpus case ${entry.id}`);
}

export function evaluateManifest(manifest, clock, load, raw) {
  const results = manifest.cases.map((entry) => {
    const bytes = raw(entry.path);
    let observed = { result: "valid" };
    try { validateCorpusCase(entry, JSON.parse(bytes), clock, load); }
    catch (error) { observed = { result: "invalid", error: error.code ?? "internal", layer: error.layer ?? "clean-room" }; }
    return { id: entry.id, fixture_digest: digestBytes(bytes), observed };
  });
  return { manifest_digest: digestBytes(raw("fixtures/manifest.json")), results };
}
