# Clean-room interoperability proof

This directory contains a deliberately small second implementation of the
public experimental federation transport profile. It proves two directions:

1. `clean-room-client.mjs` acts as a principal node against the conformance
   runner's Native-compatible directory and relay defaults;
2. the runner's `probe` command acts as the Native reference client against
   `replacement-services.mjs`, which binds its replacement directory and relay
   to two different loopback origins.

The clean-room client is then run against the replacements as a third check.
That last path demonstrates that directory, relay, descriptor and proof
audiences are configuration, not hard-coded Native endpoints.

## Isolation boundary

Both implementations import only `node:` standard-library modules and the
local `clean-room-core.mjs` built from the published contract. They do not
import the Native Rust crate, `scripts/federation-conformance.mjs`, an
`@withnative` package, or any unpublished implementation module. The test
suite checks this import allowlist mechanically.

Inputs crossing the process boundary are limited to the variables documented
in the public profile README:

- exact profile and fixed conformance clock;
- explicit directory, relay and descriptor URLs;
- the published profile/fixture root and exact manifest path; and
- `fixtures/request-proof-signing.json`.

That last file is intentionally public, deterministically generated fixture
material. The programs require its `FIXTURE PRIVATE KEYS ONLY` warning and
refuse a signing path outside the published profile root. No production
credential, application database, environment-specific endpoint, or private
Native source is used. The services bind loopback only.

The JOSE–HPKE ciphertext remains the profile's marked
`FINAL-RFC-structural-placeholder`; this proof does not upgrade it into a
cryptographic known-answer vector or a stable profile.

## Per-case conformance contract

The clean-room adapter does not inherit the Native runner's fixture verdicts.
It independently evaluates every manifest fixture and returns one result with
the case id, exact fixture digest, observed validity, error code and validation
layer. The runner requires the exact manifest digest, unique case ids closed
over the manifest, matching fixture digests, and matching observed outcomes.
A regression test proves that a process which only prints `{"status":"pass"}`
cannot self-certify.

The implementation translates the published JSON schemas and normative bounds
into dependency-free checks: recursive I-JSON depth/member/array/string bounds,
duplicate-aware raw JSON token parsing with decoded member-name comparison and
integer-only number lexemes, schema-defined member closure, canonical base64url,
exact timestamps and
identifiers, freshness and hard expiry, key validity and purpose, Ed25519
authorization chains, envelope lifetime/JWE bounds, negotiation,
recipient/key/AAD mapping, relay state, request-proof replay, receipt semantics
and URL behavior. Signed unknown optional receipt fields remain covered by the
signature and are accepted as the receipt schema requires; malformed known
fields still fail. The live
client verifies the descriptor, resolves and verifies both Alice and the actual
Bob recipient, then selects Bob's active encryption key and authority-attested
relay endpoint. It creates a new envelope id and JCS AAD and signs the outer
envelope itself. Only the explicitly caveated provisional JOSE–HPKE ciphertext
structure is reused from the public fixture, and the client fails if the
resolved recipient/key no longer matches that structural vector rather than
relabelling ciphertext for another key.

## Reproduce

Use Node 24 and the pinned conformance dependencies:

```bash
npm ci --ignore-scripts --prefix protocol/federation/experimental-jose-hpke-1/conformance
node scripts/generate-federation-fixtures.mjs --check
node scripts/federation-conformance.mjs run \
  --adapter "$(command -v node)" \
  --adapter-arg protocol/federation/experimental-jose-hpke-1/interop/clean-room-client.mjs
node --test tests/federation_clean_room_interop.mjs
```

The test starts replacement services on ephemeral ports, passes their emitted
URLs to the bounded `probe` client, and shuts them down. The machine-readable
runner report names the two external cases:

- `external-directory-configuration`
- `external-relay-exchange`

It also exercises impersonation and scoped 403 responses, malformed and
overlong re-signed envelopes, atomic fan-out after recipient resolution,
request-id/body and nonce replay, expired-lease redelivery, signed stale or
revoked live sender/recipient key state, non-canonical base64url, recursive
I-JSON bounds, duplicate members at root and nested scopes, decimal/exponent
number lexemes, compatible repeated names in sibling objects and escaped string
content, signed receipt
schema/key-state tampering and compatible signed receipt extensions, hanging
peers, startup failures and malformed service URLs. Divergence is reported at
its named boundary rather than repaired with a Native-specific fallback.

## Observed result

At implementation time all clean-room/adversarial and existing runner tests
pass. One runner defect was found and fixed: live principal documents now bind
the configured directory and relay endpoint instead of retaining static
fixture URLs. No protocol ambiguity required a Native-specific exception. Any
future discrepancy is a failing per-case result, named runner case or Node
test; CI preserves its output as build evidence.
