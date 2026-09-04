# Experimental JOSE–HPKE federation profile

This directory is the first machine-readable companion to
[`docs/federation-transport-v1.md`](../../../docs/federation-transport-v1.md).

It is intentionally named `experimental-jose-hpke-1`. As of 2026-08-02 the
JOSE–HPKE Key Encryption dependency is
`draft-ietf-jose-hpke-encrypt-22`, an Internet-Draft. Files containing its
provisional `HPKE-3-KE`, `ek`, `Recipient_structure` or ciphertext behavior
are marked `FINAL-RFC` in `fixtures/manifest.json`. They are structural and
JWS conformance material, not final HPKE known-answer vectors.

> **WARNING — FIXTURE KEYS ONLY:** the generator derives private keys from
> public deterministic labels so anyone can reproduce them. They provide no
> secrecy and MUST NEVER be used for a principal, service, test deployment, or
> any purpose outside these checked-in conformance fixtures.

Layout:

- `schemas/`: JSON Schema 2020-12 domain contracts;
- `fixtures/positive/`: objects expected to pass the listed validation layers;
- `fixtures/negative/`: one-fault fixtures with stable expected error codes;
- `fixtures/manifest.json`: the normative fixture index and placeholder state.
- `schemas/conformance-result.schema.json`: the stable machine-readable runner
  result contract.

Run the focused validation with:

```bash
npm ci --ignore-scripts --prefix protocol/federation/experimental-jose-hpke-1/conformance
node scripts/generate-federation-fixtures.mjs --check
node scripts/federation-conformance.mjs run
node --test tests/federation_conformance_runner.mjs
node --test tests/federation_clean_room_interop.mjs
cargo test -p native-federation --test transport_contract
```

The runner uses Node 24 and the exact dependencies pinned in
`conformance/package-lock.json`. Ajv performs Draft 2020-12 validation,
including local references and JSON Pointer fragments. The runner selects an
exact profile, uses a fixed clock by default, discovers cases from the closed
manifest, filters by case id or validation layer, and emits JSON or JSON Lines.
Exit 0 means every selected case passed, exit 1 is a conformance failure, and
exit 2 is a usage or harness failure. Selecting zero cases is a harness
failure. `serve` starts deterministic directory and relay fakes on one
credential-free local HTTP origin:

```bash
node scripts/federation-conformance.mjs list --filter lease --format jsonl
node scripts/federation-conformance.mjs serve --port 8787
```

Operators may run the following as a current advisory check:

```bash
npm audit --omit=dev --prefix protocol/federation/experimental-jose-hpke-1/conformance
```

It is intentionally not a required branch gate: reproducible PR results come
from the pinned lockfile, generator, runner, and tests rather than mutable
registry advisory state.

Resolver, relay and node/client implementations plug in through a small process
adapter. `run --adapter ./path/to/adapter --adapter-arg value` starts the fake
services and supplies these environment variables to the executable:

- `NATIVE_FEDERATION_PROFILE`
- `NATIVE_FEDERATION_CLOCK`
- `NATIVE_FEDERATION_DIRECTORY_URL`
- `NATIVE_FEDERATION_RELAY_URL`
- `NATIVE_FEDERATION_FIXTURE_ROOT`
- `NATIVE_FEDERATION_MANIFEST` (exact closed fixture index)
- `NATIVE_FEDERATION_REQUEST_PROOF_SIGNING` (fixture-only deterministic keys)
- `NATIVE_FEDERATION_NETWORK_DESCRIPTOR_URL` (runtime-signed loopback descriptor)
- `NATIVE_FEDERATION_DIRECTORY_AUDIENCE`
- `NATIVE_FEDERATION_RELAY_AUDIENCE`

Authenticated operations use `Authorization: NativeJWS <compact-JWS>`. The
proof binds the operation, audience from the verified runtime descriptor,
principal and installation, UUIDv4 request id, exact request-body digest,
canonical validity window, and 16-octet one-use nonce. A valid key outside its
published operation/principal/installation scope is `forbidden`; invalid proof
material is `unauthorized`; request-id/body reuse conflicts are tracked. The
adapter uses the public HTTP operations and independently evaluates every
manifest fixture. It writes one JSON object containing `status=pass`, the
manifest digest, and an exact per-case result set with fixture digests. The
runner rejects omissions, duplicates, extra cases, digest mismatches and wrong
observed result/error/layer values. `--adapter-timeout-ms`, `--adapter-output-bytes`, and
`--adapter-shutdown-timeout-ms` bound startup/run time, each output stream, and
termination grace. Spawn, timeout, and output-limit failures produce the same
machine-readable harness-error report as CLI failures. The adapter receives no
production credentials or Native-private code. The fakes use only deterministic
fixture keys, return real Ed25519 signatures, and expose
`Native-Conformance-Advance-Seconds` solely as a test clock control. Never
enable that header in a real service.

[`interop/`](interop/) contains the independently implemented clean-room core,
node and replacement directory/relay proof. They use only the local public
core and Node standard library. The runner's
`probe --directory-url ... --relay-url ... --network-descriptor-url ...`
command drives externally configured services with bounded Native
reference-side checks (`--request-timeout-ms` controls the deadline). See the
interop README for the isolation boundary, exact reproducible commands and
current discrepancy result. The clean-room live send resolves and verifies the
actual recipient document before selecting its active encryption key and
authority-attested relay endpoint. Replacement relay tests also prove
expired-lease redelivery increments the attempt and changes the lease without
minting another collected transition receipt. Live relay acceptance resolves
the sender and every recipient from the replacement directory and verifies
their fresh authority-attested documents instead of consulting static key
fixtures. The clean-room validators also apply the section 2.1 I-JSON limits
recursively, reject duplicate decoded member names and decimal/exponent number
lexemes from raw request/response bytes before ordinary parsing, and preserve
the receipt schema's signed optional-field forward-compatibility.

The Rust test checks schema/ref integrity, address vectors, manifest coverage,
contract invariants, canonical signed payloads and real Ed25519 signatures. A
future stable profile must add final-RFC HPKE encrypt/decrypt vectors and a
second independent implementation; it must not overwrite this directory.
