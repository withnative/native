# Standalone federation relay

`relay` is Native's open, encrypted store-and-forward implementation for the
experimental `native-fed/experimental-jose-hpke-1` profile. It is a separate
process over reusable Rust modules. It is not mounted into `serve` and never
uses `catalog.db` or an ejectable user database.

The relay is a temporary encrypted post office, not a conversation database.
It authenticates transport requests, validates signed envelope metadata,
stores opaque signed-envelope bytes, and signs delivery receipts. It never
decrypts content or observes destination ingest.

## Required configuration

| Variable | Meaning |
| --- | --- |
| `NATIVE_RELAY_PUBLIC_ORIGIN` | Exact HTTPS origin used by request-proof `aud` (loopback HTTP is allowed for conformance) |
| `NATIVE_RELAY_AUTHORITY_FILE` | Preverified development snapshot containing principal documents |
| `NATIVE_RELAY_ID` | Relay identifier published by the network descriptor |
| `NATIVE_RELAY_SIGNING_KID` | Active `n1.relay.*` key id published by the network descriptor |
| `NATIVE_RELAY_SIGNING_SEED` | Base64url 32-octet Ed25519 seed supplied by the deployment secret store |

`NATIVE_RELAY_DB` defaults to `./relay.db`; `NATIVE_RELAY_BIND` defaults to
`0.0.0.0:8081`. Before opening SQLite for writing, the binary inspects an
existing target read-only and rejects every non-relay schema, including Native
catalog and ejectable user databases. Deploy one process against one dedicated
database. V1 does not claim cross-replica lease coordination.

The authority file adapter uses the public conformance principal-cache shape:
an object with `principals`, each containing a complete `document` wrapper. It
rejects duplicate principal addresses and key ids, ignores fixture-only private
signer entries, and fails closed when a document is no longer fresh. Crucially,
the adapter **does not authenticate those wrappers**. It is a preverified
development seam, not a production directory client.

Loopback bind/origin pairs may use it for isolated development. A non-loopback
process refuses to start unless
`NATIVE_RELAY_DANGEROUS_ALLOW_PREVERIFIED_AUTHORITY=1` is set. That opt-in is
appropriate only when an authenticated upstream owns and atomically refreshes
the file. A normal operated deployment must inject a `DirectoryAuthority`
implementation that verifies the signed descriptor, authority/root chain,
principal wrappers, continuity and refresh. The relay does not create a second
principal registry.

The receipt seed and key id must correspond to the active relay key in the
signed network descriptor. Rotation affects newly minted receipts only.
Previously persisted receipt wrappers and signatures are returned byte-stably.

## Limits and retention

Defaults follow the operated-service decision:

- 1 MiB signed envelopes and 128 recipients;
- 100 deliveries per collection, 30 seconds maximum long-poll, and a
  300-second lease;
- seven-day default expiry and retention, bounded by the profile's 30-day
  maximum lifetime;
- 256 MiB or 10,000 active deliveries per recipient mailbox;
- 60 authenticated submissions/minute and 10,000 recipient-deliveries/day per
  sender;
- 120 requests/minute per source IP and 10,000 new deliveries/day per
  recipient.

Mailbox, rate, lease, expiry, retention and cleanup values have corresponding
`NATIVE_RELAY_*` environment overrides. Overrides cannot exceed the wire
profile's ceilings. Quota accounting charges every recipient the complete
canonical signed-envelope size.

Acknowledgement and expiry remove ciphertext immediately (which is stronger
than the required 24-hour bound). Exact digests, transition receipts and
tombstones remain for at least 30 days. Cleanup is transactional, idempotent,
and runs every five minutes by default (`NATIVE_RELAY_CLEANUP_SECS`).

## Operations and privacy

The process exposes `/health` and the four contract operations under `/v1`:
submit, collect, acknowledge, and delivery lookup. Every protocol response is
`no-store`; successful domain responses use
`application/vnd.native.federation+json`, while stable failures use
`application/problem+json`. Body-bearing domain requests must use the domain
media type exactly. `Native-Request-Id` and the Problem Details `request_id`
come from the authenticated request proof after verification, never from an
untrusted inbound correlation header.

Operational output is deliberately sparse. Startup/configuration and cleanup
failures log stable error codes, never request proofs, aliases, signed
envelopes, ciphertext, key material, or destination state. Operators should
derive aggregate request/state/byte/latency metrics at the HTTP boundary and
must not capture bodies.

For local interoperability only, `NATIVE_RELAY_CONFORMANCE_CLOCK` pins the
clock used by the public fixture corpus. Its use is announced on stderr and it
must never be set in an operated deployment.

This profile remains experimental. Its JOSE–HPKE values include provisional
FINAL-RFC placeholders and must not be advertised as a stable standard.
