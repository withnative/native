# Native federation transport 1.0

Status: **experimental normative specification**

Profile: `native-fed/experimental-jose-hpke-1`

Last updated: 2026-08-02

This document specifies discovery, principal and key authentication, encrypted
multi-recipient transport, relay delivery and relay receipts. It deliberately
does not specify the decrypted payload or how a destination mutates its
database.

The domain protocol in this document is implementation-ready. The JOSE–HPKE
wire profile remains experimental because its upstream Key Encryption
construction is an Internet-Draft. Section 5.2 lists the values that MUST be
reconciled with the eventual RFC before a stable profile is published. The
experimental profile MUST NOT be advertised as stable or silently redefined in
place.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and
**OPTIONAL** are to be interpreted as described by BCP 14 when they appear in
all capitals.

## 1. Contract surface

The contract has four independently replaceable roles:

| Role | Normative responsibility | Not its responsibility |
| --- | --- | --- |
| Principal node | Holds principal private keys; resolves fresh recipient documents; signs and decrypts envelopes; verifies receipts | Trusting plaintext merely because transport authenticated it |
| Network authority and directory | Anchors a `network_id`; attests current principal↔root/key, alias and endpoint associations; preserves public history | Authoring user content or holding principal private keys |
| Relay | Authenticates submitters and collectors; stores opaque envelopes; maintains per-recipient delivery state; signs scoped receipts | Decrypting content, deciding content authorization, or acting as a canonical content ledger |
| Installation | Holds a scoped installation key; registers an endpoint; collects and acknowledges one principal's mailbox | Acting as the durable principal or authoring envelopes |

An implementation can combine these roles operationally, but MUST preserve the
cryptographic and authorization boundaries. OAuth, browser sessions and host
login credentials are outside this protocol. Deployments MAY require them in
addition to protocol proofs; they MUST NOT substitute for protocol proofs.

The wire media types are:

- `application/vnd.native.federation+json` for domain requests and responses;
- `application/problem+json` for errors;
- `application/vnd.native.federation-envelope+json` for a signed envelope;
- `application/vnd.native.federation-principal+json` for a signed principal
  document;
- `application/vnd.native.federation-receipt+json` for a signed relay receipt.

All HTTP endpoints MUST use HTTPS except loopback endpoints explicitly enabled
for development. Redirects for protocol operations MUST NOT be followed.

## 2. Common encoding and bounds

### 2.1 JSON and canonical bytes

Domain values MUST be I-JSON and MUST be canonicalized with the JSON
Canonicalization Scheme (JCS), RFC 8785, before hashing or signing. Inputs with
duplicate member names, invalid Unicode, non-finite numbers, or integers
outside `[-(2^53)+1, (2^53)-1]` MUST be rejected before canonicalization. This
profile uses integers only; floats are forbidden. JSON strings are compared by
their decoded scalar values except where this specification defines a more
restrictive ASCII grammar.

Base64url is the unpadded encoding from RFC 7515. A decoder MUST reject `=`,
non-canonical encodings and non-base64url characters. SHA-256 digests are
serialized as `sha-256:<base64url-32-octets>`.

Unless a schema specifies a lower limit:

- a JSON document is at most 1,048,576 UTF-8 octets;
- nesting depth is at most 32;
- an object has at most 256 members;
- an array has at most 256 items;
- a string has at most 4,096 UTF-8 octets;
- an extension value contributes to the same document and nesting limits.

Unknown fields do not relax these limits.

### 2.2 Time

Timestamps MUST be UTC RFC 3339 strings in the exact form
`YYYY-MM-DDTHH:MM:SSZ`. Fractional seconds, leap seconds and offsets other than
`Z` are forbidden. Intervals are half-open: `not_before <= t < not_after`.
Nodes SHOULD maintain clocks within 300 seconds of UTC. A request proof MAY be
accepted within 300 seconds of its creation time and MUST expire no more than
300 seconds after creation.

### 2.3 Identifiers

`envelope_id`, `delivery_id`, `receipt_id`, `request_id` and `installation_id`
are lowercase canonical UUIDs. New values MUST be UUIDv4 with the RFC 9562
variant. An envelope identifier is chosen once before encryption and remains
unchanged across every retry. Relay delivery and receipt identifiers are
separate namespaces and MUST NOT be derived from private content.

Capability tokens are 1–96 ASCII characters matching
`[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*`. Native-defined tokens start `native.`.
Third-party tokens MUST begin with a DNS name controlled by their definer,
followed by `:`. Extension object member names obey the same rule. Unknown
extensions are ignored only after their containing signature is verified.

## 3. Principal addresses and network namespaces

### 3.1 Grammar

The logical address is a JSON object:

```json
{"network_id":"native","principal_id":"p_01J00000000000000000000000"}
```

The binding form is `<network_id>/<principal_id>`. It is used in local
`native-principal` bindings and in ordering rules; the JSON object is used on
the wire.

The grammar below is augmented ABNF. Numeric bounds are normative in addition
to the productions.

```abnf
principal-address = network-id "/" principal-id

network-id       = native-network / dns-network / key-network
native-network   = "native"
dns-network      = "dns:" dns-name
key-network      = "key:" 43base64url

dns-name         = dns-label *("." dns-label)
dns-label        = alnum / (alnum *61(ldh) alnum)
ldh              = alnum / "-"
alnum            = %x30-39 / %x61-7A

principal-id     = pid-edge / (pid-edge *62pid-char pid-edge)
pid-edge         = ALPHA / DIGIT
pid-char         = ALPHA / DIGIT / "-" / "_" / "." / "~"
43base64url      = 43(ALPHA / DIGIT / "-" / "_")
```

`dns-name` is at most 253 octets and each label is at most 63 octets.
`network_id` is at most 257 octets. `principal_id` is 1–64 octets. The binding
form is therefore at most 322 octets. All are ASCII. `/`, percent escapes,
whitespace, control characters, empty components and a trailing DNS dot are
forbidden.

### 3.2 Normalization and equality

`principal_id` is opaque and case-sensitive. It is never case folded,
percent-decoded or Unicode-normalized. A producer MUST emit it in its assigned
form; a consumer MUST reject rather than repair an invalid form.

`native` is reserved to Native's published authority. No other authority may
mint it. A `dns:` network uses a lowercase DNS A-label name without a trailing
dot. Unicode domain input is converted to IDNA A-label form by the UI before it
becomes a protocol value; the protocol itself never carries a U-label.

A `key:` network suffix is the base64url SHA-256 RFC 7638 thumbprint of the
authority root public JWK. It is self-authenticating but not self-locating: its
descriptor URL must be configured or obtained through a separately trusted
channel.

Two addresses are equal only when both normalized strings are byte-for-byte
equal. Sorting uses unsigned lexicographic comparison of their UTF-8 binding
forms. Recipient lists MUST be strictly sorted and duplicate-free.

### 3.3 Authority discovery and continuity

- `native` uses the trust anchor and descriptor URL shipped by a conforming
  Native distribution.
- `dns:example.com` is initially discovered at
  `https://example.com/.well-known/native-federation`. HTTPS authenticates the
  first fetch; the returned authority root is then pinned. A root change
  requires the dual-signed transition described in section 4.5.
- `key:` requires a configured descriptor URL, and the returned root JWK
  thumbprint MUST equal the network identifier.

A descriptor, whose normative schema is
[`network-descriptor.schema.json`](../protocol/federation/experimental-jose-hpke-1/schemas/network-descriptor.schema.json),
contains its exact `network_id`, directory and optional relay base
URLs, authority and relay signing public keys, supported profiles,
capabilities, operational limits, validity interval and a detached authority
JWS. A resolver MUST reject a descriptor for another network, a trust-anchor
mismatch, an authority rollback, or an HTTPS origin change not authorized by a
signed descriptor transition.

There is no implicit global trust between authorities. Operators choose which
network descriptors they trust. An authority MUST NOT assert a principal in
another network namespace.

## 4. Keys, principal documents and authority

### 4.1 Key hierarchy

Each principal has these distinct key classes:

| Class | Algorithm | May authorize | Must not be used for |
| --- | --- | --- | --- |
| Principal root | Ed25519 | Operational keys and root transitions | Envelopes, routine directory writes, relay collection |
| Operational signing | Ed25519 | Principal documents, envelopes, installation keys and routine authenticated requests | HPKE or root transitions |
| Operational encryption | X25519 in the experimental profile | Nothing; receives one HPKE-wrapped CEK | Signing or another HPKE suite/mode |
| Installation | Ed25519 | Its scoped endpoint registration, collection and acknowledgement requests | Envelopes, principal documents, other installations |
| Authority/relay service | Ed25519, separate keys | Authority attestations/network descriptors or relay receipts respectively | Principal actions |

Private root, operational and installation keys belong to the sovereign node
or its selected custody system. The directory stores public material and
attestations only. Root keys SHOULD be kept offline except for rotation and
operational-key authorization.

Key reuse across rows, purposes, principals, HPKE modes or HPKE suites is
forbidden. Ed25519 and X25519 public values that happen to share underlying
bytes are still invalid key reuse.

### 4.2 JWK and `kid`

Public keys use JWK. Private members (`d`, RSA private members or symmetric
`k`) MUST NOT appear in a principal document, descriptor, envelope or receipt.

- Ed25519: `kty=OKP`, `crv=Ed25519`, `alg=EdDSA`, `use=sig`, 32-octet `x`.
- Experimental HPKE encryption: `kty=OKP`, `crv=X25519`,
  `alg=HPKE-3-KE`, `use=enc`, 32-octet `x`.

The RFC 7638 thumbprint is computed from only the required public members
(`crv`, `kty`, `x`) using RFC 7638's canonical member object. Every key id is:

```text
n1.<purpose>.<base64url(SHA-256(JWK-thumbprint-input))>
```

`purpose` is exactly one of `root`, `signing`, `encryption`, `installation`,
`authority` or `relay`. The resulting `kid` is 51–57 ASCII characters and MUST
equal the JWK's `kid`. A verifier recomputes it; lookup by an unrecomputed
attacker-supplied `kid` is forbidden. JOSE `jku`, `x5u`, embedded `jwk`,
`x5c` and remote key references are forbidden on messages.

### 4.3 Key records and authorization

A key record contains its public JWK, purpose, `status`, `not_before`, optional
`not_after`, and authorization. Status is `active`, `retired` or `revoked`.
An active key is usable only inside its validity interval. A retired key cannot
create new protocol objects at or after `not_after`, but remains available for
historical verification. A revoked key cannot authenticate a newly observed
object, regardless of a sender-controlled timestamp.

An operational-key authorization statement contains:

```json
{
  "statement_type":"native.operational-key-authorization",
  "protocol_version":"1.0",
  "principal":{"network_id":"native","principal_id":"..."},
  "key":{ "...":"complete public JWK and key metadata" },
  "issued_at":"2026-08-02T09:00:00Z"
}
```

It is signed by an active root key using section 5.3. An installation-key
authorization is the analogous statement signed by an active operational
signing key and additionally fixes `installation_id`, endpoint origin and the
allowed subset of `directory.endpoint.update`, `relay.collect` and
`relay.acknowledge`. An installation key cannot widen its own authorization.

### 4.4 Principal document

The normative schema is
[`principal-document.schema.json`](../protocol/federation/experimental-jose-hpke-1/schemas/principal-document.schema.json).
Its top-level members are:

```json
{
  "document": {
    "document_type":"native.federation.principal",
    "protocol_version":"1.0",
    "profile":"native-fed/experimental-jose-hpke-1",
    "network_id":"native",
    "principal_id":"...",
    "document_version":7,
    "issued_at":"2026-08-02T09:00:00Z",
    "fresh_until":"2026-08-02T09:15:00Z",
    "hard_expires_at":"2026-08-03T09:00:00Z",
    "root_keys":[],
    "operational_keys":[],
    "installations":[],
    "verified_aliases":[],
    "delivery_endpoints":[],
    "supported_profiles":[],
    "capabilities":[],
    "required_capabilities":[],
    "extensions":{}
  },
  "principal_signature":"<detached JWS>",
  "authority_attestation":{
    "statement":{},
    "signature":"<detached JWS>"
  }
}
```

`document_version` starts at 1 and increases by exactly one for every semantic
change, including rotation, revocation, alias, endpoint or capability changes.
An authority MUST NOT serve two document digests for the same principal and
version. A client that has observed version `n` MUST reject a lower version.

The principal signature is made by an active operational signing key listed in
the document. The authority attestation statement fixes the principal address,
document version, `sha-256` digest of `JCS(document)`, current root key ids,
authority network, issuance/freshness/hard-expiry times and directory base URL.
The attestation is signed by a current authority key from the pinned network
descriptor. Both signatures are REQUIRED. Authority attestation establishes
the current association; it does not make the authority the content author.

`fresh_until` MUST be no later than 15 minutes after `issued_at` and
`hard_expires_at` no later than 24 hours after `issued_at`. Authorities SHOULD
use a shorter freshness period after a revocation.
Freshness intervals are half-open: a document is stale at
`t >= fresh_until` and hard-expired at `t >= hard_expires_at`. The same rule
applies to a network descriptor before any authority or relay key in it is
trusted.

### 4.5 Rotation, revocation and history

Operational rotation publishes the new root-authorized key as active, overlaps
it with the old key for at least the maximum envelope lifetime, then retires the
old key. Encryption uses only currently active recipient keys. Senders MUST NOT
encrypt to every historical key. During an explicitly advertised encryption
rollover, a recipient may list at most two active encryption keys; a sender
uses the one with the latest `not_before`, breaking ties by `kid`.

A normal root transition statement fixes the principal, old and new root JWKs,
the last old-root document version, activation time and reason. It MUST carry
two detached JWS signatures: one by the old root and one by the new root. The
authority attests the next principal document. Root history and transition
statements remain retrievable.

If an old root is unavailable or compromised, the authority MAY perform an
`authority_recovery` according to its published recovery policy. The next
document MUST set `continuity=authority_recovered`, identify the last trusted
version and revoke the old root. Consumers MUST surface that continuity break;
they MUST NOT describe it as cryptographic proof by the former root.

Revocation records contain `revoked_at`, `effective_at`, `reason` (one of
`compromised`, `cessation`, `authorization_withdrawn`) and an optional
replacement `kid`. They are never deleted. A newly observed object under a
revoked key fails with `key_revoked`, even if its embedded time predates
revocation. A previously recorded valid object remains historically
verifiable. A newly delivered pre-revocation object MAY be classified
`historically_valid` only if a matching relay queued receipt was signed and
observed before `effective_at`; this classification still does not authorize
content ingest.

Directories MUST retain public keys, authorizations, transitions,
revocations, principal document digests and authority keys for at least the
network's declared `historical_verification_seconds`, which MUST be at least
ten years. A self-hosted export MUST carry the principal's private root and
active private operational/installation keys in an encrypted identity bundle,
plus the public history and authorizations. Re-hosting re-registers endpoints
under the same principal and keys, increments the document version, and does
not mint another principal. Export encryption, recovery UX and custody are
implementation concerns; exporting unencrypted private key bytes is forbidden.

### 4.6 Verified aliases

An alias assertion contains `system`, normalized `value`, principal address,
`normalization`, `verified_at`, `fresh_until`, `verifier`, `method` and optional
non-secret `proof_ref`. It is covered by the authority attestation. A bare
display value is never verified.

The only core alias system is `email` with normalization id
`native.email-ascii-v1`: accept an ASCII dot-atom local part and DNS A-label
domain, preserve the local part byte-for-byte, lowercase the domain, remove no
characters, and reject quoted local parts, comments, whitespace and addresses
over 254 octets. Alias equality includes the normalization id. Alias
reassignment increments both principals' document versions and does not move
principal identity or history.

## 5. Cryptographic profile

### 5.1 Mandatory experimental suite

An envelope does not negotiate algorithms. The profile fixes all of them:

| Function | Required value |
| --- | --- |
| JSON canonicalization | RFC 8785 JCS |
| Signatures | JWS `alg=EdDSA` with Ed25519 |
| JWS hash encoding | standard JWS base64url payload; no `b64=false` |
| JWE serialization | RFC 7516 General JWE JSON Serialization |
| HPKE mode | Base mode, Key Encryption of one shared CEK |
| Provisional HPKE `alg` | `HPKE-3-KE`: X25519/HKDF-SHA256/AES-128-GCM |
| JWE content `enc` | `A256GCM` (32-octet CEK, 12-octet IV, 16-octet tag) |
| Digests | SHA-256 |
| Compression | forbidden; `zip` MUST be absent |

`none`, MAC signatures, authenticated/PSK HPKE modes, Integrated Encryption,
mixed recipient algorithms, algorithm fallback and any algorithm not fixed by
this table are forbidden. A verifier configures an allowlist from the profile,
then requires exact `alg`, `enc`, JWK family, curve, purpose and `kid` matches
before performing a cryptographic operation.

### 5.2 FINAL-RFC placeholders and stability gates

As of 2026-08-02, `draft-ietf-jose-hpke-encrypt-22` is an active
Internet-Draft in IETF processing, not an RFC. The following are provisional
and marked `FINAL-RFC` in artifacts:

1. the `HPKE-3-KE` registered spelling and its final IANA status;
2. the per-recipient `ek` header and Key Encryption processing rules;
3. the exact `Recipient_structure` construction and test vectors;
4. references to the final HPKE base specification selected by that RFC.

The experimental profile follows draft-22 for interoperability experiments:
HPKE plaintext is the JWE CEK, HPKE AAD is empty, `ek` carries the encapsulated
secret, and HPKE `info` is the draft `Recipient_structure`. Stable publication
MUST compare the final RFC byte-for-byte with these assumptions. Any difference
creates a new profile id; the experimental id is never reinterpreted.

The stable profile remains blocked until all of these gates pass:

- final JOSE–HPKE RFC and IANA values pinned;
- complete positive and negative cryptographic vectors published;
- threat model and external cryptographic review completed;
- a second independent implementation passes the same suite;
- Native directory, relay and eject/re-host journey pass conformance.

### 5.3 Detached JWS

Principal documents, key authorizations, envelopes and receipts use a detached
JWS Compact Serialization `<protected>..<signature>`. The detached payload is
the JCS UTF-8 bytes of the adjacent member named by that object (`document`,
`statement`, `envelope`, `receipt` or the negotiation `result`).

The protected header MUST contain exactly `alg`, `kid` and `typ`; no
unprotected header exists. The `typ` is one of:

- `native-network-descriptor+jws`;
- `native-principal+jws`;
- `native-principal-attestation+jws`;
- `native-key-authorization+jws`;
- `native-root-transition+jws`;
- `native-envelope+jws`;
- `native-relay-receipt+jws`;
- `native-profile-negotiation+jws`;
- `native-request-proof+jws`.

Let `protected-bytes = UTF8(JCS(protected-header))` and let
`payload-bytes = UTF8(JCS(adjacent-domain-object))`. The signing input is
exactly:

```text
ASCII(BASE64URL(protected-bytes)) || "." ||
ASCII(BASE64URL(payload-bytes))
```

`payload-bytes` are already canonical bytes; they are not parsed or
canonicalized a second time. The compact middle segment MUST be empty.
Verification reconstructs the input; it does not accept a payload supplied
inside the JWS. The whole adjacent domain object is signed: there is no
unsigned routing or extension field.

Every duplicated key label is a mandatory binding, not a lookup hint. The
principal-document JWS `kid` MUST equal an active `purpose=signing` key in that
document; its authority-attestation JWS uses the distinct
`native-principal-attestation+jws` type and an active authority key in the
current network descriptor. A network-descriptor JWS resolves to an active
authority key in that descriptor and the already pinned trust chain. An
envelope's `sender_key_id` MUST equal its outer JWS `kid`. A receipt's
`relay_key_id` MUST equal its outer JWS `kid` and an active relay key in the
descriptor. Any mismatch fails before payload use; a verifier MUST NOT try
another listed key.

### 5.4 Request proof

Authenticated directory mutations and relay operations carry
`Authorization: NativeJWS <compact-JWS>`. Unlike section 5.3, this is a normal
compact JWS with an encoded request-proof payload. Its protected header uses
`native-request-proof+jws`. The payload is:

```json
{
  "protocol_version":"1.0",
  "operation":"relay.submit",
  "aud":"https://relay.example",
  "principal":{"network_id":"native","principal_id":"..."},
  "installation_id":null,
  "request_id":"00000000-0000-4000-8000-000000000000",
  "body_digest":"sha-256:...",
  "created_at":"2026-08-02T09:00:00Z",
  "expires_at":"2026-08-02T09:05:00Z",
  "nonce":"<22-character base64url of 16 random octets>"
}
```

`aud` is the lowercase HTTPS origin with default ports removed and no path.
`body_digest` hashes the exact received HTTP body octets. `operation` is the
operation name specified below. A server checks signature, scope, audience,
body, time and a `(kid, nonce)` replay cache before acting. A replay of the same
`request_id` and body MAY return the original response; reuse with another body
is `idempotency_conflict`.

## 6. Outer envelope and encrypted content

The normative schema is
[`transport-envelope.schema.json`](../protocol/federation/experimental-jose-hpke-1/schemas/transport-envelope.schema.json).
A signed envelope is:

```json
{
  "envelope": {
    "envelope_type":"native.federation.transport",
    "protocol_version":"1.0",
    "profile":"native-fed/experimental-jose-hpke-1",
    "envelope_id":"...",
    "sender_principal":{"network_id":"native","principal_id":"..."},
    "sender_key_id":"n1.signing....",
    "recipients":[
      {"principal":{"network_id":"native","principal_id":"..."},
       "encryption_key_id":"n1.encryption...."}
    ],
    "created_at":"2026-08-02T09:00:00Z",
    "expires_at":"2026-08-09T09:00:00Z",
    "content_type":"application/vnd.native.message+json",
    "content_version":"1.0",
    "required_capabilities":[],
    "extensions":{},
    "jwe":{},
    "ciphertext_digest":"sha-256:..."
  },
  "signature":"<detached JWS>"
}
```

`expires_at`, when present, MUST be after `created_at` and no more than 30 days
later. A sender MUST NOT reuse an `envelope_id`, CEK or JWE IV. The envelope
signature key MUST be an active operational signing key of
`sender_principal` at creation. Sender and recipients may be in different
trusted network namespaces.

`content_type` is a lowercase ASCII media type without parameters, at most 127
octets. `content_version` is `<major>.<minor>` with each integer 0–65535. A
receiver verifies the outer signature and required capabilities before
decrypting. It decrypts only a known content type/version and dispatches only
to its registered non-executing decoder. Unknown content is retained or
quarantined as opaque data and never executed. Decrypted payload semantics are
outside this document.

### 6.1 JWE layout and authenticated context

The JWE protected header contains exactly:

```json
{
  "alg":"HPKE-3-KE",
  "enc":"A256GCM",
  "typ":"native-federation+jwe",
  "cty":"<the outer content_type>",
  "native_profile":"native-fed/experimental-jose-hpke-1",
  "crit":["native_profile"]
}
```

It is JCS serialized before base64url encoding. A shared JWE `unprotected`
member and `zip` are forbidden. Each JWE recipient header contains exactly
`kid` and the provisional `ek`. `kid` MUST equal the corresponding outer
`recipients[i].encryption_key_id`; recipients have the same count and order in
both arrays. Mixed `alg` values are impossible because `alg` is protected and
shared.

Before encryption, form `encryption_context` by copying every envelope member,
including unknown optional members, and omitting only `jwe` and
`ciphertext_digest`. Its bytes are `JCS(encryption_context)`.
The JWE top-level `aad` member is
`BASE64URL(JCS(encryption_context))`. Per RFC 7516, the content AEAD AAD is:

```text
ASCII(jwe.protected || "." || jwe.aad)
```

For recipient index `i`, the experimental profile sets the draft's
`recipient_extra_info` to:

```text
ASCII("native-fed recipient") || 0x00 ||
SHA-256(JCS(encryption_context)) || UINT16_BE(i) || 0x00 ||
UTF8(binding-form(recipients[i].principal)) || 0x00 ||
ASCII(recipients[i].encryption_key_id)
```

The resulting draft-22 HPKE `info` is:

```text
ASCII("JOSE-HPKE rcpt") || 0xFF || ASCII("A256GCM") || 0xFF ||
recipient_extra_info
```

This uses the JOSE–HPKE application-context hook; it does not modify HPKE.
Receivers MUST compare the external AAD, protected header, positional mapping
and derived context before releasing plaintext. HPKE Base mode does not
authenticate the sender; the outer Ed25519 JWS does.

`ciphertext_digest` is SHA-256 of the decoded JWE `ciphertext` octets. The
relay idempotency digest is separately SHA-256 of `JCS(the complete signed
envelope wrapper)`. Both are stable across submission retries because retries
send identical bytes.

### 6.2 Replay and downgrade handling

A node keeps an envelope replay record keyed by `(sender_principal,
envelope_id)` for at least the later of envelope expiry and 30 days after first
observation. Identical digests are idempotent. Another digest is
`idempotency_conflict` and neither object is processed. Expired envelopes are
not decrypted. A future `created_at` beyond clock skew is rejected.

The signed `protocol_version`, `profile`, capabilities and complete JWE prevent
an intermediary from changing algorithms or semantics. A receiver MUST NOT
retry verification with another suite after any failure. Fresh authority
documents prevent profile rollback; section 10 defines transition rules.

## 7. Directory interface

The base URL comes from the signed network descriptor. Responses include
`Native-Request-Id`, and successful reads include a strong `ETag`. Domain
operations are:

| Operation | HTTP shape | Authorization |
| --- | --- | --- |
| `directory.principal.get` | `GET /v1/principals/{principal_id}`; optional `?version=n` | Public |
| `directory.alias.resolve` | `POST /v1/aliases:resolve` | Public, rate-limited |
| `directory.negotiate` | `POST /v1/profiles:negotiate` | Public |
| `directory.installation.put` | `PUT /v1/principals/{id}/installations/{installation_id}` | Operational signing key initially; authorized installation key for same endpoint later |
| `directory.key.publish` | `POST /v1/principals/{id}/keys` | Operational authorization signed by root |
| `directory.key.retire` | `POST /v1/principals/{id}/keys/{kid}:retire` | Active root |
| `directory.key.revoke` | `POST /v1/principals/{id}/keys/{kid}:revoke` | Active root or documented authority recovery |
| `directory.root.rotate` | `POST /v1/principals/{id}/roots:rotate` | Dual root signatures or authority recovery |

Every non-GET directory request body MUST include the `operation` member shown
in [`directory.schema.json`](../protocol/federation/experimental-jose-hpke-1/schemas/directory.schema.json).
Its value, the table operation and any request-proof `operation` MUST be
identical. Mutation bodies additionally carry the complete signed statement
they publish and a request proof. The authenticated proof principal and URL
principal MUST match.
Directory operators may apply abuse and recovery policy, but cannot create a
valid principal authorization without its required key signatures.

Principal reads return the section 4.4 wrapper. Alias resolution accepts an
`operation=directory.alias.resolve` body with `system`, `normalization` and
`value`, and returns either exactly one signed
principal document plus the matching alias assertion, or a stable error. It
MUST NOT return an unverified match as verified. Negotiation accepts ordered
`profiles` and `capabilities` in an `operation=directory.negotiate` body; the
signed response selects one exact profile
and lists unsupported required capabilities, with `fresh_until` at most 15
minutes later. In this experimental profile the response is a wrapper with
exactly `result` and `signature`; `signature` is a detached JWS over the
adjacent complete `result` object and uses
`typ=native-profile-negotiation+jws`. The result binds
`operation=directory.negotiate.result`, `protocol_version`, the one selected
profile, the authority-supported capabilities, the complete unsupported subset
of the request's required capabilities, and `fresh_until`. This explicitly
closes an omitted type in the original experimental publication; it does not
change or silently reinterpret a stable profile.

### 7.1 Freshness and cache behavior

`ETag` is `"pd-<base64url SHA-256(JCS(document))>"`. A response uses
`Cache-Control: public, max-age=<seconds>, must-revalidate`, where max-age does
not extend beyond `fresh_until`. Conditional `If-None-Match` may return 304 but
MUST include current cache metadata. `no-store` is REQUIRED for mutations and
alias lookup requests/responses because aliases can be sensitive.

A fresh principal document is REQUIRED for a new send and for endpoint/key
mutation. Once stale, a client must conditionally revalidate. If the directory
is unavailable, it MUST NOT send to cached encryption keys. It MAY store a
received envelope without decrypting or ingesting it in `pending_freshness`.
Once current revocation state is available, it resumes verification. Past
`hard_expires_at`, cached data is usable only for historical display. Local
database access and attribution never depend on directory availability.

## 8. Relay interface and delivery state machine

The relay base URL and limits come from the authority-attested delivery
endpoint. The core ceilings are 128 recipients, a 1,048,576-octet signed
envelope, 100 deliveries per collection and a 30-day envelope lifetime. A
relay may advertise lower limits before submission, but MUST NOT claim this
core profile if its maximum recipients is below 16 or maximum envelope size
below 262,144 octets.

### 8.1 Operations

| Operation | HTTP shape | Proof key |
| --- | --- | --- |
| `relay.submit` | `POST /v1/envelopes` | Sender operational signing key |
| `relay.collect` | `POST /v1/mailboxes/{installation_id}:collect` | Authorized installation key |
| `relay.acknowledge` | `POST /v1/mailboxes/{installation_id}/acknowledgements` | Same installation key |
| `relay.delivery.get` | `GET /v1/deliveries/{delivery_id}` | Sender signing key or recipient installation key |

Every non-GET relay request body MUST include the `operation` member shown in
[`relay.schema.json`](../protocol/federation/experimental-jose-hpke-1/schemas/relay.schema.json).
Its value, the table operation and the request-proof `operation` MUST be
identical. Submission body is
`{"operation":"relay.submit","envelope":<complete signed-envelope wrapper>}`. The
relay verifies size, schema, sender signature, fresh sender key state,
recipient/JWE correspondence, expiry and the request proof without decrypting.
It computes the signed-envelope digest and creates one independent result per
recipient.

Idempotency is keyed by `(sender_principal, envelope_id, recipient_principal)`.
The same digest returns the original delivery id, state and receipts. Reusing
the key with another digest fails the entire request atomically with
`idempotency_conflict`; the relay MUST NOT append recipients or partially
change prior results. Recipient failures in a first submission are otherwise
independent.

Each result is one of:

- `queued`: accepted, with stable `delivery_id` and signed queued receipt;
- `rejected`: permanent, with stable `delivery_id`, reason and signed rejected
  receipt;
- `error`: transient (`rate_limited`, `quota_exceeded`, `unavailable`), without
  a delivery resource; it may be retried after the indicated time.

### 8.2 Collection and acknowledgement

Collection body contains `operation=relay.collect`, an optional opaque
`cursor`, `limit` (1–100) and `wait_seconds` (0–30). The response has the next
cursor and deliveries. A
delivery includes its exact signed envelope, delivery id, envelope digest,
queued receipt, current state, attempt number, an opaque lease token and lease
expiry. Collection atomically leases each delivery to one request and changes
`queued` to `collected` on first return. The collected receipt is minted only
for that first transition.

The cursor is scoped to the principal and installation and cannot acknowledge
anything. Until acknowledgement, an expired lease makes the delivery eligible
for redelivery even if a cursor advanced. Default lease is 300 seconds; a relay
may advertise 30–900 seconds. Attempt numbers increase on each returned lease.
Concurrent collectors MUST NOT hold overlapping live leases.

Acknowledgement body contains `operation=relay.acknowledge` and 1–100 entries
with `delivery_id`, `envelope_id`, envelope digest, lease token and disposition
exactly `received`. It means the
authenticated installation received the signed envelope bytes; it says
nothing about decryption, content validity or database ingest. A matching
acknowledgement changes `collected` to `acknowledged` and returns a signed
receipt. Repetition returns the same receipt. Acknowledging another principal,
another digest or an uncollected delivery fails closed.

Push notification is an optional hint containing only relay origin and an
opaque wake token. It creates no state and carries no envelope authority; the
installation still collects normally.

### 8.3 State transitions, expiry and retention

The only delivery states are `rejected`, `queued`, `collected` and
`acknowledged`.

| From | Event | To | Effect |
| --- | --- | --- | --- |
| none | permanent submission rejection | rejected | No ciphertext mailbox entry; keep tombstone/receipt |
| none | acceptance | queued | Store opaque signed envelope |
| queued | first collection | collected | Create lease and collected receipt |
| collected | lease expiry/redelivery | collected | New lease and attempt; no new transition receipt |
| collected | valid acknowledgement | acknowledged | Delete ciphertext within 24 hours |
| queued or collected | envelope/relay retention expiry | rejected | Reason `expired`; delete ciphertext within 24 hours |

Destination ingest is never a relay state. State transitions are monotonic
except a collected delivery can be redelivered while remaining collected.

If an envelope omits `expires_at`, the relay applies its advertised default,
which MUST be 1–7 days after `created_at`. The effective expiry is the earliest
of envelope expiry, advertised retention and 30 days after creation. Relays
retry collection until acknowledgement or effective expiry. Tombstones,
digests and receipts are retained for at least 30 days after a terminal state;
ciphertext is not. Services MUST advertise mailbox byte/count quotas and rate
limits. `429` includes `Retry-After`; quota and rate errors remain distinct
protocol codes.

## 9. Relay receipts

The normative schema is
[`relay-receipt.schema.json`](../protocol/federation/experimental-jose-hpke-1/schemas/relay-receipt.schema.json).
A receipt wrapper has `receipt` and a section 5.3 detached relay JWS. The
receipt fixes:

- relay id and relay signing `kid`;
- stable receipt and delivery ids;
- envelope id and complete signed-envelope digest;
- exactly one recipient principal;
- observed state and timestamp;
- previous state when a transition exists;
- collector installation id only for `collected`/`acknowledged`;
- stable reason code for `rejected`.

One receipt exists per state transition. Retrying an operation returns the
same receipt id and bytes. Relay public signing keys and history are in the
signed network descriptor and use the same retirement/revocation distinction
as principal signing keys.

State-specific fields are closed: `queued` has no `previous_state`, collector
or reason; `collected` requires `previous_state=queued` and a collector;
`acknowledged` requires `previous_state=collected` and a collector; `rejected`
requires a reason, forbids a collector, and may name `queued` or `collected` as
its previous state only when expiry terminated an existing delivery.

A queued receipt proves only that this relay accepted those opaque bytes for
that recipient. A collected receipt proves only that it returned them to an
authenticated installation. An acknowledged receipt proves only that such an
installation acknowledged receiving those bytes. None proves sender humanity,
plaintext meaning, recipient decryption, authorization, local reconciliation
or database commit.

## 10. Errors, compatibility and negotiation

### 10.1 Stable error representation

Errors use RFC 9457 Problem Details with required extensions `code`,
`request_id` and `retryable`. `type` is
`urn:native:federation:error:<code>`. `detail` is diagnostic and MUST NOT be
parsed. `retry_after` is an integer seconds value only when retryable.

| Code | HTTP | Retryable | Meaning |
| --- | ---: | --- | --- |
| `invalid_request` | 400 | no | JSON, bounds or operation shape invalid |
| `invalid_principal_address` | 400 | no | Address fails section 3 |
| `malformed_envelope` | 400 | no | Envelope/JWE structural contract fails |
| `signature_invalid` | 400 | no | Required JWS fails |
| `recipient_mismatch` | 400 | no | Outer and JWE recipients differ |
| `unknown_principal` | 404 | no | Principal is not registered |
| `unknown_alias` | 404 | no | No verified alias association |
| `alias_unverified` | 409 | no | Candidate exists but is not verified |
| `principal_revoked` | 410 | no | Principal is no longer active |
| `key_revoked` | 410 | no | Key is revoked for new observations |
| `stale_document` | 409 | yes | Fresh state is required |
| `unsupported_profile` | 406 | no | No common exact profile |
| `required_capability_unsupported` | 422 | no | A required token is unknown |
| `unknown_content_type` | 415 | no | Recipient cannot dispatch content |
| `unauthorized` | 401 | no | Missing/invalid request proof |
| `forbidden` | 403 | no | Valid key lacks operation scope |
| `precondition_failed` | 412 | yes | ETag/document version changed |
| `conflict` | 409 | no | Authority/key/binding conflict |
| `idempotency_conflict` | 409 | no | Stable id reused with other bytes |
| `delivery_unknown` | 404 | no | Delivery absent or outside caller scope |
| `delivery_terminal` | 409 | no | Operation incompatible with terminal state |
| `expired` | 410 | no | Envelope or delivery lifetime ended |
| `payload_too_large` | 413 | no | Advertised or core size limit exceeded |
| `rate_limited` | 429 | yes | Operation rate exceeded |
| `quota_exceeded` | 429 | yes | Mailbox/account quota exceeded |
| `directory_unavailable` | 503 | yes | Fresh identity state unavailable |
| `relay_unavailable` | 503 | yes | Relay temporarily unavailable |
| `internal` | 500 | yes | Unclassified server failure |

Servers may add fields but MUST use one listed code for core failures. Clients
key behavior on `code`, not HTTP status or prose.

### 10.2 Versions and capabilities

`protocol_version` is `<major>.<minor>`. A major change is incompatible. Within
one major, a later minor may add optional fields, capabilities, operations and
error detail but cannot change existing meaning, signing inputs or defaults.
Receivers verify signatures over unknown fields and ignore them only when no
unknown token in `required_capabilities` requires their interpretation.

An algorithm or byte-level JOSE change always creates another exact `profile`
identifier. It is not negotiated from message `alg` values. Principal
documents advertise ordered profile ids. For an N-recipient envelope, a sender
selects the first profile in its preference order supported by every recipient
and itself. No common profile fails before encryption. A receiver accepts only
a currently advertised profile at or above its signed minimum policy and never
falls back after failure.

A network descriptor can publish a signed profile transition with old/new ids,
activation time and `reject_old_after`. Senders use the new profile at
activation when every recipient supports it. Receivers reject old-profile
envelopes created at or after `reject_old_after`. The envelope signature and
JWE AAD bind this choice.

## 11. Security and privacy boundary

### 11.1 Claims

Given uncompromised keys, fresh authenticated directory state, correct
implementations and secure random generation, this profile provides:

- sender-principal authentication and integrity for the complete outer
  envelope;
- confidentiality and integrity of one payload to each listed recipient key;
- integrity binding between plaintext, outer context and recipient mapping;
- replay-detectable stable envelope identity;
- authenticated, scoped relay observations and state transitions;
- principal continuity across normal key rotation and export/re-host.

### 11.2 Non-claims

V1 does **not** provide forward secrecy, post-compromise security, break-in
recovery, deniable authentication, sender anonymity, sealed sender, recipient
anonymity, traffic-analysis resistance, global authority transparency, proof
of human identity, spam prevention, plaintext authorization or proof of
database ingest. A compromised directory can mis-bind current keys/aliases in
its own authority; pinned history and root authorizations make this detectable
in some cases but do not remove that trust. A compromised relay can drop,
delay, reorder, duplicate or selectively reject envelopes and lie only within
the scope of receipts it can sign; it cannot silently alter a valid sender
envelope or decrypt payloads without a recipient key.

Long-lived recipient encryption keys mean later compromise can decrypt
recorded ciphertext encrypted to that key. Rotation limits future exposure but
does not give forward secrecy. Compression is forbidden to avoid introducing
compression-oracle and cross-message leakage into the core profile.

### 11.3 Relay-visible metadata

| Metadata | Relay sees? | Reason |
| --- | --- | --- |
| Sender principal and signing `kid` | yes | Submission authentication and signature verification |
| Recipient principal list and encryption `kid`s | yes | Routing and key-state validation |
| Envelope/profile/content type and version | yes | Validation, compatibility and limits |
| Envelope id, creation/expiry | yes | Idempotency and retention |
| Required capabilities/extensions | yes | Signed outer routing semantics |
| Ciphertext, tag, IV, per-recipient wrapped CEKs | yes, opaque | Store-and-forward transport |
| Ciphertext and total envelope size | yes | Storage and abuse controls |
| Submission, collection, acknowledgement timing/IP | yes | Network operation; IP is not a protocol field |
| Installation id used to collect | yes | Mailbox authorization and receipt scope |
| Plaintext payload and local database outcome | no | End-to-end encrypted and outside relay protocol |

Senders MUST assume the visible rows can be retained and correlated. Padding,
mix networks and sealed-sender constructions are future profiles, not implied
features.

## 12. Conformance artifacts and handoff

Initial artifacts live under
[`protocol/federation/experimental-jose-hpke-1`](../protocol/federation/experimental-jose-hpke-1/README.md).
Schemas are JSON Schema 2020-12. The manifest labels each fixture's expected
result and validation layers. The repository test verifies address vectors,
schema/ref integrity, fixture classification, canonical payloads and actual
Ed25519 detached JWS signatures. JWE/HPKE ciphertext entries are explicitly
`FINAL-RFC` structural placeholders and MUST NOT be presented as final
cryptographic vectors.

Downstream ownership is:

| Task | May implement now | Must retain/gate |
| --- | --- | --- |
| `89eb3e1` key lifecycle | JWK/kid derivation, hierarchy, authorizations, rotation/revocation history, encrypted export/re-host continuity | HPKE algorithm token behind exact profile id; authority-recovery UX |
| `727b7cc` directory | Descriptor, principal/alias reads, signed attestations, writes, freshness/ETag, negotiation, errors | Trust-anchor operations and ten-year history |
| `28cdf43` relay | Opaque submission, per-recipient idempotency, collection leases, ack, states, limits, receipts | Never add ingest state or plaintext dependency |
| `0bb8ad6` publication/conformance | Promote schemas, expand fixtures/harness, clean-room implementation and eject journey | Replace `FINAL-RFC` placeholders only through a new stable profile after every gate |

## 13. Normative references

- [RFC 7515 — JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515)
- [RFC 7516 — JSON Web Encryption](https://www.rfc-editor.org/rfc/rfc7516)
- [RFC 7517 — JSON Web Key](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 7638 — JSON Web Key Thumbprint](https://www.rfc-editor.org/rfc/rfc7638)
- [RFC 8032 — Ed25519](https://www.rfc-editor.org/rfc/rfc8032)
- [RFC 8037 — OKP keys for JOSE](https://www.rfc-editor.org/rfc/rfc8037)
- [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [RFC 9180 — Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180)
- [RFC 9457 — Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc9457)
- [draft-ietf-jose-hpke-encrypt-22 — work in progress](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/)
