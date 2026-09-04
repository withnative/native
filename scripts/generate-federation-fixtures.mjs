#!/usr/bin/env node

// Deterministic initial fixtures for the experimental federation profile.
// This generator deliberately does not implement HPKE. JWE ciphertext fields
// are FINAL-RFC structural placeholders; every detached Ed25519 JWS is real.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as edSign,
} from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const profileRoot = process.env.NATIVE_FEDERATION_PROFILE_ROOT
  ? resolve(process.env.NATIVE_FEDERATION_PROFILE_ROOT)
  : join(root, "protocol/federation/experimental-jose-hpke-1");
const check = process.argv.includes("--check");
const expectedWrites = new Set();

function jcs(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("fixtures use safe integers only");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`)
      .join(",")}}`;
  }
  throw new Error(`unsupported JCS type: ${typeof value}`);
}

const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const sha = (bytes) => createHash("sha256").update(bytes).digest();
const digest = (bytes) => `sha-256:${b64u(sha(bytes))}`;
function deterministic(label, length) {
  const chunks = [];
  for (let counter = 0; Buffer.concat(chunks).length < length; counter += 1) {
    chunks.push(sha(Buffer.from(`${label}:${counter}`)));
  }
  return Buffer.concat(chunks).subarray(0, length);
}

function privateKey(label, curve) {
  const oid = curve === "Ed25519" ? "70" : "6e";
  const prefix = Buffer.from(`302e020100300506032b65${oid}04220420`, "hex");
  return createPrivateKey({
    key: Buffer.concat([prefix, deterministic(`native-fed-fixture:${label}`, 32)]),
    format: "der",
    type: "pkcs8",
  });
}

function publicJwk(label, curve, purpose, alg, use) {
  const private_key = privateKey(label, curve);
  const raw = createPublicKey(private_key).export({ format: "jwk" });
  const thumbprintInput = { crv: raw.crv, kty: raw.kty, x: raw.x };
  const kid = `n1.${purpose}.${b64u(sha(Buffer.from(jcs(thumbprintInput))))}`;
  return {
    private_key,
    jwk: { kty: raw.kty, crv: raw.crv, x: raw.x, alg, use, kid },
  };
}

function detached(payload, key, typ) {
  const protectedHeader = { alg: "EdDSA", kid: key.jwk.kid, typ };
  const protectedPart = b64u(Buffer.from(jcs(protectedHeader)));
  const payloadPart = b64u(Buffer.from(jcs(payload)));
  const signature = edSign(
    null,
    Buffer.from(`${protectedPart}.${payloadPart}`),
    key.private_key,
  );
  return `${protectedPart}..${b64u(signature)}`;
}

function signedStatement(statement, key, typ = "native-key-authorization+jws") {
  return { statement, signature: detached(statement, key, typ) };
}

function changedKid(kid) {
  return kid.replace(/.$/, (last) => (last === "A" ? "B" : "A"));
}

function write(relative, value) {
  if (expectedWrites.has(relative)) throw new Error(`duplicate generated fixture path: ${relative}`);
  expectedWrites.add(relative);
  const path = join(profileRoot, relative);
  const output = `${JSON.stringify(value, null, 2)}\n`;
  if (check) {
    const current = readFileSync(path, "utf8");
    if (current !== output) throw new Error(`generated fixture drift: ${relative}`);
  } else {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, output);
  }
}

const rootKey = publicJwk("alice-root", "Ed25519", "root", "EdDSA", "sig");
const signingKey = publicJwk("alice-signing", "Ed25519", "signing", "EdDSA", "sig");
const aliceEncryption = publicJwk("alice-encryption", "X25519", "encryption", "HPKE-3-KE", "enc");
const installationKey = publicJwk("alice-installation", "Ed25519", "installation", "EdDSA", "sig");
const bobRootKey = publicJwk("bob-root", "Ed25519", "root", "EdDSA", "sig");
const bobSigningKey = publicJwk("bob-signing", "Ed25519", "signing", "EdDSA", "sig");
const bobInstallationKey = publicJwk("bob-installation", "Ed25519", "installation", "EdDSA", "sig");
const carolRootKey = publicJwk("carol-root", "Ed25519", "root", "EdDSA", "sig");
const carolSigningKey = publicJwk("carol-signing", "Ed25519", "signing", "EdDSA", "sig");
const carolInstallationKey = publicJwk("carol-installation", "Ed25519", "installation", "EdDSA", "sig");
const authorityKey = publicJwk("native-authority", "Ed25519", "authority", "EdDSA", "sig");
const relayKey = publicJwk("native-relay", "Ed25519", "relay", "EdDSA", "sig");
const bobEncryption = publicJwk("bob-encryption", "X25519", "encryption", "HPKE-3-KE", "enc");
const carolEncryption = publicJwk("carol-encryption", "X25519", "encryption", "HPKE-3-KE", "enc");

const alice = { network_id: "native", principal_id: "alice0001" };
const bob = { network_id: "native", principal_id: "bob00001" };
const carol = { network_id: "native", principal_id: "carol001" };
const issued = "2026-08-02T09:00:00Z";
const fresh = "2026-08-02T09:15:00Z";
const hardExpiry = "2026-08-03T09:00:00Z";

const networkDescriptorBody = {
  descriptor_type: "native.federation.network",
  protocol_version: "1.0",
  network_id: "native",
  descriptor_version: 1,
  issued_at: issued,
  fresh_until: fresh,
  hard_expires_at: hardExpiry,
  directory_base_url: "https://directory.withnative.example",
  relay_base_urls: ["https://relay.withnative.example"],
  authority_keys: [
    {
      jwk: structuredClone(authorityKey.jwk),
      status: "active",
      not_before: issued,
      not_after: "2036-08-02T09:00:00Z",
    },
  ],
  relay_keys: [
    {
      jwk: structuredClone(relayKey.jwk),
      status: "active",
      not_before: issued,
      not_after: "2027-08-02T09:00:00Z",
    },
  ],
  supported_profiles: ["native-fed/experimental-jose-hpke-1"],
  profile_preference: ["native-fed/experimental-jose-hpke-1"],
  capabilities: ["native.relay.receipts"],
  limits: {
    max_envelope_bytes: 1048576,
    max_recipients: 128,
    default_retention_seconds: 604800,
    max_retention_seconds: 2592000,
    collection_limit: 100,
    lease_seconds: 300,
  },
  historical_verification_seconds: 315576000,
  extensions: {},
};
const networkDescriptor = {
  descriptor: networkDescriptorBody,
  signature: detached(
    networkDescriptorBody,
    authorityKey,
    "native-network-descriptor+jws",
  ),
};
const authorityKeyAtNotAfter = structuredClone(networkDescriptor);
authorityKeyAtNotAfter.descriptor.authority_keys[0].not_after = "2026-08-02T09:10:00Z";
authorityKeyAtNotAfter.signature = detached(
  authorityKeyAtNotAfter.descriptor,
  authorityKey,
  "native-network-descriptor+jws",
);
const profileNegotiationResult = {
  operation: "directory.negotiate.result",
  protocol_version: "1.0",
  selected_profile: "native-fed/experimental-jose-hpke-1",
  capabilities: ["native.relay.receipts"],
  unsupported_required_capabilities: [],
  fresh_until: "2026-08-02T09:15:00Z",
};
const profileNegotiationResponse = {
  result: profileNegotiationResult,
  signature: detached(profileNegotiationResult, authorityKey, "native-profile-negotiation+jws"),
};

function operational(purpose, key) {
  const keyRecord = {
    purpose,
    jwk: structuredClone(key.jwk),
    status: "active",
    not_before: issued,
    not_after: "2027-08-02T09:00:00Z",
  };
  const statement = {
    statement_type: "native.operational-key-authorization",
    protocol_version: "1.0",
    principal: alice,
    key: structuredClone(keyRecord),
    issued_at: issued,
  };
  return { ...keyRecord, authorization: signedStatement(statement, rootKey) };
}

function privateFixtureJwk(key) {
  const privateJwk = key.private_key.export({ format: "jwk" });
  return { ...privateJwk, alg: key.jwk.alg, use: key.jwk.use, kid: key.jwk.kid };
}

const installationRecord = {
  installation_id: "00000000-0000-4000-8000-000000000101",
  jwk: structuredClone(installationKey.jwk),
  status: "active",
  endpoint_origin: "https://node.alice.example",
  scopes: ["directory.endpoint.update", "relay.acknowledge", "relay.collect"],
};
const installationStatement = {
  statement_type: "native.installation-key-authorization",
  protocol_version: "1.0",
  principal: alice,
  installation: structuredClone(installationRecord),
  issued_at: issued,
};
installationRecord.authorization = signedStatement(installationStatement, signingKey);

function principalFixture(overrides = {}) {
  const document = {
    document_type: "native.federation.principal",
    protocol_version: "1.0",
    profile: "native-fed/experimental-jose-hpke-1",
    network_id: "native",
    principal_id: "alice0001",
    document_version: 1,
    issued_at: issued,
    fresh_until: fresh,
    hard_expires_at: hardExpiry,
    continuity: "continuous",
    root_keys: [
      {
        jwk: structuredClone(rootKey.jwk),
        status: "active",
        not_before: issued,
        not_after: "2036-08-02T09:00:00Z",
      },
    ],
    operational_keys: [
      operational("signing", signingKey),
      operational("encryption", aliceEncryption),
    ],
    installations: [structuredClone(installationRecord)],
    verified_aliases: [
      {
        system: "email",
        value: "Alice@example.com",
        normalization: "native.email-ascii-v1",
        verified_at: issued,
        fresh_until: "2026-09-01T09:00:00Z",
        verifier: "native",
        method: "email-otp",
      },
    ],
    delivery_endpoints: [
      { kind: "relay", url: "https://relay.withnative.example/v1", priority: 0 },
    ],
    supported_profiles: ["native-fed/experimental-jose-hpke-1"],
    capabilities: ["native.relay.receipts"],
    required_capabilities: [],
    extensions: {},
    ...overrides,
  };
  const statement = {
    statement_type: "native.authority.principal-attestation",
    protocol_version: "1.0",
    network_id: "native",
    principal: alice,
    document_version: document.document_version,
    document_digest: digest(Buffer.from(jcs(document))),
    root_kids: document.root_keys.map((key) => key.jwk.kid),
    issued_at: document.issued_at,
    fresh_until: document.fresh_until,
    hard_expires_at: document.hard_expires_at,
    directory_base_url: "https://directory.withnative.example",
  };
  return {
    document,
    principal_signature: detached(document, signingKey, "native-principal+jws"),
    authority_attestation: signedStatement(
      statement,
      authorityKey,
      "native-principal-attestation+jws",
    ),
  };
}

function proofPrincipalFixture(principal, root, signing, encryption, installation, installationId, label) {
  const operationalRecord = (purpose, key) => {
    const record = {
      purpose,
      jwk: structuredClone(key.jwk),
      status: "active",
      not_before: issued,
      not_after: "2027-08-02T09:00:00Z",
    };
    const statement = {
      statement_type: "native.operational-key-authorization",
      protocol_version: "1.0",
      principal,
      key: structuredClone(record),
      issued_at: issued,
    };
    return { ...record, authorization: signedStatement(statement, root) };
  };
  const installationValue = {
    installation_id: installationId,
    jwk: structuredClone(installation.jwk),
    status: "active",
    endpoint_origin: `https://node.${label}.example`,
    scopes: ["relay.acknowledge", "relay.collect"],
  };
  const installationAuthorization = {
    statement_type: "native.installation-key-authorization",
    protocol_version: "1.0",
    principal,
    installation: structuredClone(installationValue),
    issued_at: issued,
  };
  installationValue.authorization = signedStatement(installationAuthorization, signing);
  const document = {
    document_type: "native.federation.principal",
    protocol_version: "1.0",
    profile: "native-fed/experimental-jose-hpke-1",
    network_id: principal.network_id,
    principal_id: principal.principal_id,
    document_version: 1,
    issued_at: issued,
    fresh_until: fresh,
    hard_expires_at: hardExpiry,
    continuity: "continuous",
    root_keys: [{ jwk: structuredClone(root.jwk), status: "active", not_before: issued, not_after: "2036-08-02T09:00:00Z" }],
    operational_keys: [operationalRecord("signing", signing), operationalRecord("encryption", encryption)],
    installations: [installationValue],
    verified_aliases: [],
    delivery_endpoints: [{ kind: "relay", url: "https://relay.withnative.example/v1", priority: 0 }],
    supported_profiles: ["native-fed/experimental-jose-hpke-1"],
    capabilities: ["native.relay.receipts"],
    required_capabilities: [],
    extensions: {},
  };
  const attestation = {
    statement_type: "native.authority.principal-attestation",
    protocol_version: "1.0",
    network_id: principal.network_id,
    principal,
    document_version: document.document_version,
    document_digest: digest(Buffer.from(jcs(document))),
    root_kids: document.root_keys.map((key) => key.jwk.kid),
    issued_at: document.issued_at,
    fresh_until: document.fresh_until,
    hard_expires_at: document.hard_expires_at,
    directory_base_url: "https://directory.withnative.example",
  };
  return {
    document,
    principal_signature: detached(document, signing, "native-principal+jws"),
    authority_attestation: signedStatement(attestation, authorityKey, "native-principal-attestation+jws"),
  };
}

function resignPrincipal(wrapper) {
  wrapper.principal_signature = detached(
    wrapper.document,
    signingKey,
    "native-principal+jws",
  );
  wrapper.authority_attestation.statement.document_digest = digest(
    Buffer.from(jcs(wrapper.document)),
  );
  wrapper.authority_attestation.signature = detached(
    wrapper.authority_attestation.statement,
    authorityKey,
    "native-principal-attestation+jws",
  );
  return wrapper;
}

function resignPrincipalWith(wrapper, key) {
  wrapper.principal_signature = detached(
    wrapper.document,
    key,
    "native-principal+jws",
  );
  wrapper.authority_attestation.statement.document_version =
    wrapper.document.document_version;
  wrapper.authority_attestation.statement.fresh_until = wrapper.document.fresh_until;
  wrapper.authority_attestation.statement.hard_expires_at =
    wrapper.document.hard_expires_at;
  wrapper.authority_attestation.statement.document_digest = digest(
    Buffer.from(jcs(wrapper.document)),
  );
  wrapper.authority_attestation.signature = detached(
    wrapper.authority_attestation.statement,
    authorityKey,
    "native-principal-attestation+jws",
  );
  return wrapper;
}

function makeEnvelope(recipients, envelopeId, marker = "one") {
  const base = {
    envelope_type: "native.federation.transport",
    protocol_version: "1.0",
    profile: "native-fed/experimental-jose-hpke-1",
    envelope_id: envelopeId,
    sender_principal: alice,
    sender_key_id: signingKey.jwk.kid,
    recipients: recipients.map(({ principal, key }) => ({
      principal,
      encryption_key_id: key.jwk.kid,
    })),
    created_at: "2026-08-02T09:05:00Z",
    expires_at: "2026-08-09T09:05:00Z",
    content_type: "application/vnd.native.message+json",
    content_version: "1.0",
    required_capabilities: [],
    extensions: {},
  };
  const protectedHeader = {
    alg: "HPKE-3-KE",
    enc: "A256GCM",
    typ: "native-federation+jwe",
    cty: base.content_type,
    native_profile: base.profile,
    crit: ["native_profile"],
  };
  const ciphertext = Buffer.from(`FINAL-RFC:${marker}:opaque-ciphertext`);
  const jwe = {
    protected: b64u(Buffer.from(jcs(protectedHeader))),
    aad: b64u(Buffer.from(jcs(base))),
    recipients: recipients.map(({ key }, index) => ({
      header: {
        kid: key.jwk.kid,
        ek: b64u(deterministic(`ek:${marker}:${index}`, 32)),
      },
      encrypted_key: b64u(deterministic(`wrapped-cek:${marker}:${index}`, 48)),
    })),
    iv: b64u(deterministic(`iv:${marker}`, 12)),
    ciphertext: b64u(ciphertext),
    tag: b64u(deterministic(`tag:${marker}`, 16)),
  };
  const envelope = { ...base, jwe, ciphertext_digest: digest(ciphertext) };
  return {
    envelope,
    signature: detached(envelope, signingKey, "native-envelope+jws"),
  };
}

function resignEnvelope(wrapper) {
  wrapper.signature = detached(wrapper.envelope, signingKey, "native-envelope+jws");
  return wrapper;
}

function receiptFixture(envelopeWrapper, state = "queued", overrides = {}) {
  const receipt = {
    receipt_type: "native.relay.delivery-receipt",
    protocol_version: "1.0",
    profile: "native-fed/experimental-jose-hpke-1",
    receipt_id: "00000000-0000-4000-8000-000000000301",
    relay_id: "native-default-relay",
    relay_key_id: relayKey.jwk.kid,
    delivery_id: "00000000-0000-4000-8000-000000000201",
    envelope_id: envelopeWrapper.envelope.envelope_id,
    envelope_digest: digest(Buffer.from(jcs(envelopeWrapper))),
    recipient: envelopeWrapper.envelope.recipients[0].principal,
    state,
    observed_at: "2026-08-02T09:05:01Z",
    ...overrides,
  };
  return {
    receipt,
    signature: detached(receipt, relayKey, "native-relay-receipt+jws"),
  };
}

const principal = principalFixture();
const envelopeOne = makeEnvelope(
  [{ principal: bob, key: bobEncryption }],
  "00000000-0000-4000-8000-000000000001",
  "one",
);
const envelopeMany = makeEnvelope(
  [
    { principal: bob, key: bobEncryption },
    { principal: carol, key: carolEncryption },
  ],
  "00000000-0000-4000-8000-000000000002",
  "many",
);
const queuedReceipt = receiptFixture(envelopeOne);

const invalidKid = principalFixture();
invalidKid.document.operational_keys[0].jwk.kid = changedKid(
  signingKey.jwk.kid,
);
resignPrincipal(invalidKid);

const purposeConfused = principalFixture();
const confusedKey = purposeConfused.document.operational_keys[0];
confusedKey.jwk = structuredClone(aliceEncryption.jwk);
confusedKey.authorization.statement.key.jwk = structuredClone(aliceEncryption.jwk);
confusedKey.authorization.signature = detached(
  confusedKey.authorization.statement,
  rootKey,
  "native-key-authorization+jws",
);
resignPrincipal(purposeConfused);

const unsorted = structuredClone(envelopeMany);
unsorted.envelope.recipients.reverse();
unsorted.envelope.jwe.recipients.reverse();
resignEnvelope(unsorted);

const mismatch = structuredClone(envelopeOne);
mismatch.envelope.jwe.recipients[0].header.kid = carolEncryption.jwk.kid;
resignEnvelope(mismatch);

const protectedHeaderMismatch = structuredClone(envelopeOne);
const mismatchedProtectedHeader = {
  alg: "HPKE-3-KE",
  enc: "A256GCM",
  typ: "native-federation+jwe",
  cty: "application/json",
  native_profile: protectedHeaderMismatch.envelope.profile,
  crit: ["native_profile"],
};
protectedHeaderMismatch.envelope.jwe.protected = b64u(
  Buffer.from(jcs(mismatchedProtectedHeader)),
);
resignEnvelope(protectedHeaderMismatch);

const senderKeyMismatch = structuredClone(envelopeOne);
senderKeyMismatch.envelope.sender_key_id = changedKid(signingKey.jwk.kid);
const senderMismatchContext = Object.fromEntries(
  Object.entries(senderKeyMismatch.envelope).filter(
    ([key]) => key !== "jwe" && key !== "ciphertext_digest",
  ),
);
senderKeyMismatch.envelope.jwe.aad = b64u(Buffer.from(jcs(senderMismatchContext)));
resignEnvelope(senderKeyMismatch);

const unknownCapability = structuredClone(envelopeOne);
unknownCapability.envelope.required_capabilities = ["example.net:future-routing"];
// JWE AAD must continue to mirror the encryption context, keeping the single
// intended failure at the capability layer.
const unknownContext = Object.fromEntries(
  Object.entries(unknownCapability.envelope).filter(
    ([key]) => key !== "jwe" && key !== "ciphertext_digest",
  ),
);
unknownCapability.envelope.jwe.aad = b64u(Buffer.from(jcs(unknownContext)));
resignEnvelope(unknownCapability);

const badReceipt = receiptFixture(envelopeOne);
badReceipt.receipt.envelope_digest = digest(Buffer.from("another-envelope"));
badReceipt.signature = detached(badReceipt.receipt, relayKey, "native-relay-receipt+jws");

const queuedReceiptWithCollector = receiptFixture(envelopeOne, "queued", {
  collector_installation_id: "00000000-0000-4000-8000-000000000101",
});

const collectedReceiptWithWrongPreviousState = receiptFixture(
  envelopeOne,
  "collected",
  {
    previous_state: "collected",
    collector_installation_id: "00000000-0000-4000-8000-000000000101",
  },
);

const receiptRelayKeyMismatch = receiptFixture(envelopeOne);
receiptRelayKeyMismatch.receipt.relay_key_id = changedKid(relayKey.jwk.kid);
receiptRelayKeyMismatch.signature = detached(
  receiptRelayKeyMismatch.receipt,
  relayKey,
  "native-relay-receipt+jws",
);

const conflictA = makeEnvelope(
  [{ principal: bob, key: bobEncryption }],
  "00000000-0000-4000-8000-000000000099",
  "conflict-a",
);
const conflictB = makeEnvelope(
  [{ principal: bob, key: bobEncryption }],
  "00000000-0000-4000-8000-000000000099",
  "conflict-b",
);

const rateProblem = {
  type: "urn:native:federation:error:rate_limited",
  title: "Submission rate exceeded",
  status: 429,
  code: "rate_limited",
  request_id: "00000000-0000-4000-8000-000000000401",
  retryable: true,
  retry_after: 30,
};

// The expanded corpus keeps stateful behavior as deterministic, public JSON
// transcripts. The reusable runner executes these alongside the object
// fixtures and provides live fake HTTP services for implementation adapters.
function scenario(scenario_id, steps, extras = {}) {
  return {
    scenario_type: scenario_id.split("-")[0],
    scenario_id,
    profile: "native-fed/experimental-jose-hpke-1",
    clock: "2026-08-02T09:10:00Z",
    steps,
    ...extras,
  };
}

const rotatedSigning = publicJwk("alice-signing-2", "Ed25519", "signing", "EdDSA", "sig");
const rotatedEncryption = publicJwk("alice-encryption-2", "X25519", "encryption", "HPKE-3-KE", "enc");
const rotatedPrincipal = principalFixture({ document_version: 2 });
rotatedPrincipal.document.operational_keys[0].status = "retired";
rotatedPrincipal.document.operational_keys[0].not_after = "2026-08-02T09:05:00Z";
rotatedPrincipal.document.operational_keys.push(
  operational("signing", rotatedSigning),
  operational("encryption", rotatedEncryption),
);
resignPrincipalWith(rotatedPrincipal, rotatedSigning);

const stalePrincipal = principalFixture({ fresh_until: "2026-08-02T09:09:00Z" });
resignPrincipal(stalePrincipal);
const expiredPrincipal = principalFixture({
  fresh_until: "2026-08-02T09:08:00Z",
  hard_expires_at: "2026-08-02T09:09:00Z",
});
resignPrincipal(expiredPrincipal);
const revokedSigningPrincipal = principalFixture();
revokedSigningPrincipal.document.operational_keys[0].status = "revoked";
revokedSigningPrincipal.document.operational_keys[0].revocation = {
  revoked_at: "2026-08-02T09:06:00Z",
  effective_at: "2026-08-02T09:06:00Z",
  reason: "compromised",
  replacement_kid: rotatedSigning.jwk.kid,
};
resignPrincipal(revokedSigningPrincipal);
const installationAuthorizationAtNotAfter = principalFixture();
installationAuthorizationAtNotAfter.document.operational_keys[0].not_after = issued;
resignPrincipal(installationAuthorizationAtNotAfter);

function refreshEnvelopeContext(wrapper) {
  const context = Object.fromEntries(
    Object.entries(wrapper.envelope).filter(
      ([key]) => key !== "jwe" && key !== "ciphertext_digest",
    ),
  );
  wrapper.envelope.jwe.aad = b64u(Buffer.from(jcs(context)));
  return resignEnvelope(wrapper);
}

const expiredEnvelope = structuredClone(envelopeOne);
expiredEnvelope.envelope.expires_at = "2026-08-02T09:09:00Z";
refreshEnvelopeContext(expiredEnvelope);
const unsupportedVersionEnvelope = structuredClone(envelopeOne);
unsupportedVersionEnvelope.envelope.protocol_version = "2.0";
refreshEnvelopeContext(unsupportedVersionEnvelope);
const downgradeEnvelope = structuredClone(envelopeOne);
downgradeEnvelope.envelope.profile = "native-fed/experimental-jose-hpke-0";
refreshEnvelopeContext(downgradeEnvelope);
const duplicateRecipientEnvelope = structuredClone(envelopeMany);
duplicateRecipientEnvelope.envelope.recipients[1] = structuredClone(
  duplicateRecipientEnvelope.envelope.recipients[0],
);
duplicateRecipientEnvelope.envelope.jwe.recipients[1] = structuredClone(
  duplicateRecipientEnvelope.envelope.jwe.recipients[0],
);
refreshEnvelopeContext(duplicateRecipientEnvelope);
const unknownOptionalEnvelope = structuredClone(envelopeOne);
unknownOptionalEnvelope.envelope.example_optional_trace = "signed-but-ignored";
refreshEnvelopeContext(unknownOptionalEnvelope);

write("fixtures/positive/principal-document.json", principal);
write("fixtures/positive/network-descriptor.json", networkDescriptor);
write("fixtures/positive/profile-negotiation-response.json", profileNegotiationResponse);
write("fixtures/negative/network-descriptor-authority-key-at-not-after.json", authorityKeyAtNotAfter);
write("fixtures/positive/envelope-one-recipient.json", envelopeOne);
write("fixtures/positive/envelope-many-recipients.json", envelopeMany);
write("fixtures/positive/receipt-queued.json", queuedReceipt);
write("fixtures/positive/error-rate-limited.json", rateProblem);
write("fixtures/positive/principal-document-rotated.json", rotatedPrincipal);
write("fixtures/positive/envelope-unknown-optional.json", unknownOptionalEnvelope);
write("fixtures/negative/principal-address-invalid.json", {
  network_id: "dns:Example.com",
  principal_id: "alice0001",
});
write("fixtures/negative/principal-document-bad-kid.json", invalidKid);
write("fixtures/negative/principal-document-purpose-confusion.json", purposeConfused);
write("fixtures/negative/envelope-recipient-order.json", unsorted);
write("fixtures/negative/envelope-recipient-mismatch.json", mismatch);
write("fixtures/negative/envelope-protected-header.json", protectedHeaderMismatch);
write("fixtures/negative/envelope-sender-key-mismatch.json", senderKeyMismatch);
write("fixtures/negative/envelope-required-capability.json", unknownCapability);
write("fixtures/negative/receipt-envelope-digest.json", badReceipt);
write("fixtures/negative/receipt-queued-fields.json", queuedReceiptWithCollector);
write(
  "fixtures/negative/receipt-invalid-transition.json",
  collectedReceiptWithWrongPreviousState,
);
write("fixtures/negative/receipt-relay-key-mismatch.json", receiptRelayKeyMismatch);
write("fixtures/negative/idempotency-conflict.json", scenario(
  "idempotency-conflict",
  [{ operation: "relay.submit", first: conflictA, retry: conflictB }],
  { expect_error: "idempotency_conflict", validation_layer: "idempotency", first: conflictA, retry: conflictB },
));
write("fixtures/negative/principal-document-stale.json", stalePrincipal);
write("fixtures/negative/principal-document-expired.json", expiredPrincipal);
write("fixtures/negative/principal-document-revoked-signing-key.json", revokedSigningPrincipal);
write("fixtures/negative/installation-authorization-at-signing-not-after.json", installationAuthorizationAtNotAfter);
write("fixtures/negative/envelope-expired.json", expiredEnvelope);
write("fixtures/negative/envelope-unsupported-version.json", unsupportedVersionEnvelope);
write("fixtures/negative/envelope-profile-downgrade.json", downgradeEnvelope);
write("fixtures/negative/envelope-duplicate-recipient.json", duplicateRecipientEnvelope);

write("fixtures/positive/directory-etag-revalidation.json", scenario(
  "directory-etag-revalidation",
  [
    { request: "GET /v1/principals/alice0001", expect: { status: 200, etag: "strong", cache_control: "must-revalidate" } },
    { request: "GET /v1/principals/alice0001", if_none_match: "previous", expect: { status: 304, cache_control: "must-revalidate" } },
  ],
));
write("fixtures/positive/directory-alias-resolve.json", scenario(
  "directory-alias-resolve",
  [{ request: "POST /v1/aliases:resolve", value: "Alice@example.com", expect: { status: 200, principal: "native/alice0001", cache_control: "no-store" } }],
));
write("fixtures/positive/directory-profile-negotiate.json", scenario(
  "directory-profile-negotiate",
  [{ request: "POST /v1/profiles:negotiate", profiles: ["native-fed/experimental-jose-hpke-1"], expect: { status: 200, selected_profile: "native-fed/experimental-jose-hpke-1", signed: true } }],
));
write("fixtures/positive/envelope-replay-identical.json", scenario(
  "envelope-replay-identical",
  [
    { operation: "relay.submit", digest: digest(Buffer.from(jcs(envelopeOne))), expect: { state: "queued" } },
    { operation: "relay.submit", digest: digest(Buffer.from(jcs(envelopeOne))), expect: { state: "queued", same_delivery_id: true, same_receipt_bytes: true } },
  ],
));
write("fixtures/positive/relay-fanout-lifecycle.json", scenario(
  "relay-fanout-lifecycle",
  [
    { operation: "relay.submit", recipients: 2, expect: { state: "queued", independent_results: 2 } },
    { operation: "relay.collect", expect: { state: "collected", attempt: 1, lease_seconds: 300 } },
    { operation: "relay.acknowledge", disposition: "received", expect: { state: "acknowledged", stable_receipt: true } },
  ],
));
write("fixtures/positive/relay-ack-retry.json", scenario(
  "relay-ack-retry",
  [
    { operation: "relay.acknowledge", expect: { state: "acknowledged", receipt_id: "stable" } },
    { operation: "relay.acknowledge", retry: true, expect: { state: "acknowledged", same_receipt_bytes: true } },
  ],
));
write("fixtures/positive/relay-lease-redelivery.json", scenario(
  "relay-lease-redelivery",
  [
    { operation: "relay.collect", expect: { state: "collected", attempt: 1 } },
    { advance_seconds: 301 },
    { operation: "relay.collect", expect: { state: "collected", attempt: 2, new_lease: true, no_new_transition_receipt: true } },
  ],
));

write("fixtures/negative/principal-document-rollback.json", scenario(
  "principal-document-rollback",
  [{ cached_version: 2, received_version: 1 }],
  { expect_error: "conflict", validation_layer: "rollback" },
));
write("fixtures/negative/alias-unverified.json", scenario(
  "alias-unverified",
  [{ value: "unverified@example.com", verified: false, expect: { status: 409 } }],
  { expect_error: "alias_unverified", validation_layer: "alias" },
));
write("fixtures/negative/alias-collision.json", scenario(
  "alias-collision",
  [{ normalized_value: "collision@example.com", active_principals: ["native/alice0001", "native/bob00001"] }],
  { expect_error: "conflict", validation_layer: "alias" },
));
write("fixtures/negative/alias-reassignment-stale.json", scenario(
  "alias-reassignment-stale",
  [
    { version: 1, principal: "native/alice0001" },
    { version: 2, principal: "native/bob00001" },
  ],
  { expect_error: "stale_document", validation_layer: "freshness" },
));
write("fixtures/negative/alias-local-part-case-mismatch.json", scenario(
  "alias-local-part-case-mismatch",
  [{ stored: "Alice@example.com", query: "alice@EXAMPLE.COM", expect: { status: 404 } }],
  { expect_error: "unknown_alias", validation_layer: "alias" },
));
write("fixtures/negative/directory-mutation-unauthorized.json", scenario(
  "directory-mutation-unauthorized",
  [{ request: "POST /v1/principals/alice0001/keys", request_proof: null, expect: { status: 401 } }],
  { expect_error: "unauthorized", validation_layer: "authorization" },
));
write("fixtures/negative/directory-precondition-failed.json", scenario(
  "directory-precondition-failed",
  [{ request: "POST /v1/principals/alice0001/keys", if_match: "stale", expect: { status: 412, retryable: true } }],
  { expect_error: "precondition_failed", validation_layer: "etag" },
));
write("fixtures/negative/directory-unsupported-profile.json", scenario(
  "directory-unsupported-profile",
  [{ profiles: ["example.net/other-profile"], expect: { status: 406 } }],
  { expect_error: "unsupported_profile", validation_layer: "negotiation" },
));
write("fixtures/negative/directory-required-capability.json", scenario(
  "directory-required-capability",
  [{ required_capabilities: ["example.net:required"], expect: { status: 422 } }],
  { expect_error: "required_capability_unsupported", validation_layer: "capability" },
));
write("fixtures/negative/relay-concurrent-lease.json", scenario(
  "relay-concurrent-lease",
  [{ collectors: 2, live_lease_holders: 2 }],
  { expect_error: "conflict", validation_layer: "lease" },
));
write("fixtures/negative/relay-ack-digest-mismatch.json", scenario(
  "relay-ack-digest-mismatch",
  [{ state: "collected", envelope_digest: "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", acknowledgement_digest: "sha-256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" }],
  { expect_error: "conflict", validation_layer: "acknowledgement" },
));
write("fixtures/negative/relay-ack-wrong-lease.json", scenario(
  "relay-ack-wrong-lease",
  [{ state: "collected", lease_token: "wrong", expected_lease_token: "expected" }],
  { expect_error: "conflict", validation_layer: "lease" },
));
write("fixtures/negative/relay-quota-exceeded.json", scenario(
  "relay-quota-exceeded",
  [{ operation: "relay.submit", mailbox_quota_remaining: 0, expect: { status: 429, retry_after: 30 } }],
  { expect_error: "quota_exceeded", validation_layer: "quota" },
));
write("fixtures/negative/relay-terminal-transition.json", scenario(
  "relay-terminal-transition",
  [{ from: "acknowledged", operation: "relay.collect" }],
  { expect_error: "delivery_terminal", validation_layer: "protocol-state" },
));
write("fixtures/verification-keys.json", {
  authority: authorityKey.jwk,
  relay: relayKey.jwk,
});
write("fixtures/request-proof-signing.json", {
  warning: "FIXTURE PRIVATE KEYS ONLY - public deterministic labels provide no secrecy",
  principals: {
    alice: principalFixture(),
    bob: proofPrincipalFixture(bob, bobRootKey, bobSigningKey, bobEncryption, bobInstallationKey, "00000000-0000-4000-8000-000000000201", "bob"),
    carol: proofPrincipalFixture(carol, carolRootKey, carolSigningKey, carolEncryption, carolInstallationKey, "00000000-0000-4000-8000-000000000202", "carol"),
  },
  signers: {
    alice_signing: {
      principal: alice,
      installation_id: null,
      jwk: privateFixtureJwk(signingKey),
    },
    alice_root: {
      principal: alice,
      installation_id: null,
      jwk: privateFixtureJwk(rootKey),
    },
    alice_installation: {
      principal: alice,
      installation_id: installationRecord.installation_id,
      jwk: privateFixtureJwk(installationKey),
    },
    bob_installation: {
      principal: bob,
      installation_id: "00000000-0000-4000-8000-000000000201",
      jwk: privateFixtureJwk(bobInstallationKey),
    },
    carol_installation: {
      principal: carol,
      installation_id: "00000000-0000-4000-8000-000000000202",
      jwk: privateFixtureJwk(carolInstallationKey),
    },
  },
});

const cases = [
  ["network-descriptor", "fixtures/positive/network-descriptor.json", "schemas/network-descriptor.schema.json", "valid", null, ["schema", "jws", "kid"], "not-applicable"],
  ["profile-negotiation-response", "fixtures/positive/profile-negotiation-response.json", "schemas/directory.schema.json#/$defs/negotiateResponse", "valid", null, ["schema", "jws", "negotiation"], "not-applicable"],
  ["network-descriptor-authority-key-at-not-after", "fixtures/negative/network-descriptor-authority-key-at-not-after.json", "schemas/network-descriptor.schema.json", "invalid", "signature_invalid", ["trust-binding"], "not-applicable"],
  ["principal-document", "fixtures/positive/principal-document.json", "schemas/principal-document.schema.json", "valid", null, ["schema", "jws", "kid", "authority-digest"], "not-applicable"],
  ["envelope-one-recipient", "fixtures/positive/envelope-one-recipient.json", "schemas/transport-envelope.schema.json", "valid", null, ["schema", "jws", "context", "recipient-mapping"], "FINAL-RFC-structural-placeholder"],
  ["envelope-many-recipients", "fixtures/positive/envelope-many-recipients.json", "schemas/transport-envelope.schema.json", "valid", null, ["schema", "jws", "context", "recipient-order", "recipient-mapping"], "FINAL-RFC-structural-placeholder"],
  ["receipt-queued", "fixtures/positive/receipt-queued.json", "schemas/relay-receipt.schema.json", "valid", null, ["schema", "jws", "envelope-digest"], "not-applicable"],
  ["error-rate-limited", "fixtures/positive/error-rate-limited.json", "schemas/common.schema.json#/$defs/problem", "valid", null, ["schema", "error-registry"], "not-applicable"],
  ["principal-document-rotated", "fixtures/positive/principal-document-rotated.json", "schemas/principal-document.schema.json", "valid", null, ["schema", "jws", "kid", "key-state", "authority-digest"], "not-applicable"],
  ["envelope-unknown-optional", "fixtures/positive/envelope-unknown-optional.json", "schemas/transport-envelope.schema.json", "valid", null, ["schema", "jws", "context", "version"], "FINAL-RFC-structural-placeholder"],
  ["directory-etag-revalidation", "fixtures/positive/directory-etag-revalidation.json", "schemas/scenario.schema.json", "valid", null, ["etag", "freshness", "service-behaviour"], "not-applicable"],
  ["directory-alias-resolve", "fixtures/positive/directory-alias-resolve.json", "schemas/scenario.schema.json", "valid", null, ["alias", "authorization", "service-behaviour"], "not-applicable"],
  ["directory-profile-negotiate", "fixtures/positive/directory-profile-negotiate.json", "schemas/scenario.schema.json", "valid", null, ["negotiation", "capability", "jws"], "not-applicable"],
  ["envelope-replay-identical", "fixtures/positive/envelope-replay-identical.json", "schemas/scenario.schema.json", "valid", null, ["replay", "idempotency"], "FINAL-RFC-structural-placeholder"],
  ["relay-fanout-lifecycle", "fixtures/positive/relay-fanout-lifecycle.json", "schemas/scenario.schema.json", "valid", null, ["fan-out", "lease", "protocol-state", "receipt"], "FINAL-RFC-structural-placeholder"],
  ["relay-ack-retry", "fixtures/positive/relay-ack-retry.json", "schemas/scenario.schema.json", "valid", null, ["acknowledgement", "idempotency", "receipt"], "not-applicable"],
  ["relay-lease-redelivery", "fixtures/positive/relay-lease-redelivery.json", "schemas/scenario.schema.json", "valid", null, ["lease", "retry", "protocol-state"], "not-applicable"],
  ["principal-address-uppercase-dns", "fixtures/negative/principal-address-invalid.json", "schemas/common.schema.json#/$defs/principalAddress", "invalid", "invalid_request", ["schema", "address"], "not-applicable"],
  ["principal-document-bad-kid", "fixtures/negative/principal-document-bad-kid.json", "schemas/principal-document.schema.json", "invalid", "invalid_request", ["jws", "kid"], "not-applicable"],
  ["principal-document-purpose-confusion", "fixtures/negative/principal-document-purpose-confusion.json", "schemas/principal-document.schema.json", "invalid", "invalid_request", ["schema", "key-purpose"], "not-applicable"],
  ["envelope-recipient-order", "fixtures/negative/envelope-recipient-order.json", "schemas/transport-envelope.schema.json", "invalid", "invalid_request", ["jws", "recipient-order"], "FINAL-RFC-structural-placeholder"],
  ["envelope-recipient-mismatch", "fixtures/negative/envelope-recipient-mismatch.json", "schemas/transport-envelope.schema.json", "invalid", "recipient_mismatch", ["jws", "recipient-mapping"], "FINAL-RFC-structural-placeholder"],
  ["envelope-protected-header", "fixtures/negative/envelope-protected-header.json", "schemas/transport-envelope.schema.json", "invalid", "malformed_envelope", ["jws", "protected-header"], "FINAL-RFC-structural-placeholder"],
  ["envelope-sender-key-mismatch", "fixtures/negative/envelope-sender-key-mismatch.json", "schemas/transport-envelope.schema.json", "invalid", "signature_invalid", ["jws", "sender-key-binding"], "FINAL-RFC-structural-placeholder"],
  ["envelope-required-capability", "fixtures/negative/envelope-required-capability.json", "schemas/transport-envelope.schema.json", "invalid", "required_capability_unsupported", ["jws", "context", "capability"], "FINAL-RFC-structural-placeholder"],
  ["receipt-envelope-digest", "fixtures/negative/receipt-envelope-digest.json", "schemas/relay-receipt.schema.json", "invalid", "conflict", ["jws", "envelope-digest"], "not-applicable"],
  ["receipt-queued-fields", "fixtures/negative/receipt-queued-fields.json", "schemas/relay-receipt.schema.json", "invalid", "invalid_request", ["schema", "receipt-state"], "not-applicable"],
  ["receipt-invalid-transition", "fixtures/negative/receipt-invalid-transition.json", "schemas/relay-receipt.schema.json", "invalid", "invalid_request", ["schema", "receipt-state"], "not-applicable"],
  ["receipt-relay-key-mismatch", "fixtures/negative/receipt-relay-key-mismatch.json", "schemas/relay-receipt.schema.json", "invalid", "signature_invalid", ["jws", "relay-key-binding"], "not-applicable"],
  ["idempotency-conflict", "fixtures/negative/idempotency-conflict.json", "schemas/scenario.schema.json", "invalid", "idempotency_conflict", ["jws", "idempotency"], "FINAL-RFC-structural-placeholder"],
  ["principal-document-stale", "fixtures/negative/principal-document-stale.json", "schemas/principal-document.schema.json", "invalid", "stale_document", ["freshness"], "not-applicable"],
  ["principal-document-expired", "fixtures/negative/principal-document-expired.json", "schemas/principal-document.schema.json", "invalid", "expired", ["freshness"], "not-applicable"],
  ["principal-document-revoked-signing-key", "fixtures/negative/principal-document-revoked-signing-key.json", "schemas/principal-document.schema.json", "invalid", "key_revoked", ["key-state"], "not-applicable"],
  ["installation-authorization-at-signing-not-after", "fixtures/negative/installation-authorization-at-signing-not-after.json", "schemas/principal-document.schema.json", "invalid", "signature_invalid", ["authorization-binding", "key-state"], "not-applicable"],
  ["principal-document-rollback", "fixtures/negative/principal-document-rollback.json", "schemas/scenario.schema.json", "invalid", "conflict", ["rollback"], "not-applicable"],
  ["alias-unverified", "fixtures/negative/alias-unverified.json", "schemas/scenario.schema.json", "invalid", "alias_unverified", ["alias"], "not-applicable"],
  ["alias-collision", "fixtures/negative/alias-collision.json", "schemas/scenario.schema.json", "invalid", "conflict", ["alias"], "not-applicable"],
  ["alias-reassignment-stale", "fixtures/negative/alias-reassignment-stale.json", "schemas/scenario.schema.json", "invalid", "stale_document", ["alias", "freshness"], "not-applicable"],
  ["alias-local-part-case-mismatch", "fixtures/negative/alias-local-part-case-mismatch.json", "schemas/scenario.schema.json", "invalid", "unknown_alias", ["alias"], "not-applicable"],
  ["directory-mutation-unauthorized", "fixtures/negative/directory-mutation-unauthorized.json", "schemas/scenario.schema.json", "invalid", "unauthorized", ["authorization"], "not-applicable"],
  ["directory-precondition-failed", "fixtures/negative/directory-precondition-failed.json", "schemas/scenario.schema.json", "invalid", "precondition_failed", ["etag"], "not-applicable"],
  ["directory-unsupported-profile", "fixtures/negative/directory-unsupported-profile.json", "schemas/scenario.schema.json", "invalid", "unsupported_profile", ["negotiation"], "not-applicable"],
  ["directory-required-capability", "fixtures/negative/directory-required-capability.json", "schemas/scenario.schema.json", "invalid", "required_capability_unsupported", ["capability"], "not-applicable"],
  ["envelope-expired", "fixtures/negative/envelope-expired.json", "schemas/transport-envelope.schema.json", "invalid", "expired", ["expiry"], "FINAL-RFC-structural-placeholder"],
  ["envelope-unsupported-version", "fixtures/negative/envelope-unsupported-version.json", "schemas/transport-envelope.schema.json", "invalid", "invalid_request", ["schema", "version"], "FINAL-RFC-structural-placeholder"],
  ["envelope-profile-downgrade", "fixtures/negative/envelope-profile-downgrade.json", "schemas/transport-envelope.schema.json", "invalid", "invalid_request", ["schema", "profile", "downgrade"], "FINAL-RFC-structural-placeholder"],
  ["envelope-duplicate-recipient", "fixtures/negative/envelope-duplicate-recipient.json", "schemas/transport-envelope.schema.json", "invalid", "invalid_request", ["recipient-order", "replay"], "FINAL-RFC-structural-placeholder"],
  ["relay-concurrent-lease", "fixtures/negative/relay-concurrent-lease.json", "schemas/scenario.schema.json", "invalid", "conflict", ["lease"], "not-applicable"],
  ["relay-ack-digest-mismatch", "fixtures/negative/relay-ack-digest-mismatch.json", "schemas/scenario.schema.json", "invalid", "conflict", ["acknowledgement"], "not-applicable"],
  ["relay-ack-wrong-lease", "fixtures/negative/relay-ack-wrong-lease.json", "schemas/scenario.schema.json", "invalid", "conflict", ["lease"], "not-applicable"],
  ["relay-quota-exceeded", "fixtures/negative/relay-quota-exceeded.json", "schemas/scenario.schema.json", "invalid", "quota_exceeded", ["quota", "service-behaviour"], "not-applicable"],
  ["relay-terminal-transition", "fixtures/negative/relay-terminal-transition.json", "schemas/scenario.schema.json", "invalid", "delivery_terminal", ["protocol-state"], "not-applicable"],
].map(([id, path, schema, expect, error, validation_layers, crypto_status]) => ({
  id,
  path,
  schema,
  expect,
  ...(error ? { error } : {}),
  validation_layers,
  crypto_status,
}));

if (new Set(cases.map(({ id }) => id)).size !== cases.length) {
  throw new Error("duplicate federation manifest case id");
}
if (new Set(cases.map(({ path }) => path)).size !== cases.length) {
  throw new Error("duplicate federation manifest case path");
}
const generatedCasePaths = [...expectedWrites].filter((relative) =>
  /^fixtures\/(?:positive|negative)\/.+\.json$/.test(relative));
const manifestCasePaths = new Set(cases.map(({ path }) => path));
const unmanifested = generatedCasePaths.filter((relative) => !manifestCasePaths.has(relative));
if (unmanifested.length || generatedCasePaths.length !== cases.length) {
  throw new Error(`generated fixture manifest is not closed: ${unmanifested.join(", ") || "count mismatch"}`);
}

write("fixtures/manifest.json", {
  profile: "native-fed/experimental-jose-hpke-1",
  protocol_version: "1.0",
  jose_hpke_basis: "draft-ietf-jose-hpke-encrypt-22",
  jose_hpke_status: "work-in-progress",
  verification_keys: "fixtures/verification-keys.json",
  request_proof_signing: "fixtures/request-proof-signing.json",
  cases,
});

const fixtureFiles = (directory, prefix) => readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
  const relative = `${prefix}/${entry.name}`;
  return entry.isDirectory()
    ? fixtureFiles(join(directory, entry.name), relative)
    : entry.isFile() && entry.name.endsWith(".json") ? [relative] : [];
});
const generatedCaseFiles = ["positive", "negative"].flatMap((directory) =>
  fixtureFiles(join(profileRoot, "fixtures", directory), `fixtures/${directory}`));
const orphaned = generatedCaseFiles.filter((relative) => !expectedWrites.has(relative));
if (orphaned.length) {
  throw new Error(`orphaned generated federation fixture(s): ${orphaned.join(", ")}`);
}

console.log(check ? "federation fixtures are current" : "generated federation fixtures");
