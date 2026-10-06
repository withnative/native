# Actual core ↔ SDK interoperability fixture

This opt-in test executable compiles the real `src/coedit/registry.rs` and
`refusal.rs` through source-path modules. It does not link `native_ce` or copy
its CRDT/admission algorithm. The SDK suite constructs actual `CoeditClient`
instances, sends their Yjs v1 bytes to Rust and consumes Rust's sync/broadcast
bytes. `FakeHome` is not involved.

Build and run only when authorized by the shared-host load coordinator, with one
heavy command at a time. From the repository root:

```sh
CARGO_BUILD_JOBS=2 cargo build --locked -p coedit-core-fixture --bin coedit-core-fixture
```

Install SDK dependencies separately if absent, then typecheck and run the opt-in
suite as separate commands (from `packages/native-coedit`):

```sh
npm ci
npm run typecheck
COEDIT_CORE_FIXTURE_BIN="$PWD/../../target/debug/coedit-core-fixture" npm run test:core-interop
```

The executable path must be absolute. A missing binary, incompatible handshake,
stale source hash, child failure, malformed output or timeout fails the suite;
nothing is skipped. A non-default Cargo target directory requires its actual
absolute executable path instead. `build.rs` embeds SHA-256 hashes of both
included source files at compile time and requests a rebuild when either changes.
Before attaching any SDK client, the harness compares those hashes with the
current checkout's bytes. The executable is excluded from Rust test-harness
compilation (`cfg(not(test))`); the included core unit tests remain owned and
executed by `native_ce`, while this fixture is exercised by the opt-in SDK suite.
Ordinary SDK `npm test` still selects only
`test/**/*.test.ts`; it does not run this proof. Regular `tsc` includes the harness
and opt-in tests. Tests use one worker and frame receipts, not sleeps for ordering.

## Fixture framing and state

Each JSON line is a fixture-control wrapper `{request_id, control}`. Control ops
are `handshake`, `attach`, `message`, `inspect`, `shutdown`; these are not new
normative session ops. Each result carries `request_id`, `result` (or `error`),
and `events: [{link, message}]`. Nested messages retain `protocol.ts` shapes;
byte arrays are explicitly converted to/from `Uint8Array` without rewriting
Yjs bytes. Request IDs strictly increase and remain unsigned u32.

Two fixed fixture DBs (`db-a`, `db-b`) each own one actual `SessionRegistry`.
Connections attached to the same DB share that registry and document; DBs are
isolated. The synchronous Rust input loop serializes open/apply/leave. Link→DB
and link→peer/session bindings are checked. The only record is `record`, seeded
with `A😀漢é\r\nZ`. Fixed record support and Edit/View mode are test inputs, not
an authority evaluator. The real core handles pool allocation, shape/size/peer
admission, update integration and View refusals.

The adapter echoes the proposed SDK `update_id` extension on ack/refusal. Its
checked `ack.clock` is a fixture delivery counter, not Rust's encoded state
vector or a persisted version. The core's `Ack.broadcast` goes to other live
links on that DB/session. Refusals carry actual core codes and full core sync
from an empty state vector. `base` is fixed seed version 0 plus the seed's UTF-8
SHA-256; `presence.sharing=false` and `person_ref=null` assert no actor identity.
Remote `from.kind="fixture"` is a deliberate non-contract test label, with
`person_ref=null`; it does not identify a human or agent.
`session.version` returns a fixture control-layer error, tested through
`rawMessage`, rather than a link `session.refused` frame: no persistence or
version authority exists.
`session.close` calls real `leave` and emits `session.closed` with reason `left`.
Last leave drops the ephemeral document; reopening reseeds, never reusing leases
within that registry. Close makes no version-cut or durability guarantee.

Input/output lines are capped at 1 MiB (including newline), links at 16;
SDK queues/in-flight requests at 32 and 2 MiB, histories at 128 entries and
2 MiB per link. Requests time out after 5 s; each child lives at most 30 s.
Fixture limits can fail a test even when a broader core operation would be valid;
these bounds are test machinery, not contract policy. Delivery controls can hold
or repeat actual frames, but never force a FakeHome refusal. The rebuild scenario
withholds an original clock-gap update and delivers its SDK-authored fresh replay;
this is explicit test delivery scheduling, not a production cancellation protocol.

## Evidence and boundaries

Assertions cover exact Unicode/CRLF body bytes in both directions, three real
leases disjoint from high-half seeds, same-DB peers and distinct-DB isolation,
real View/size refusals, fresh-author replay, duplicate refusal, exhaustion and
recovery intent, malformed/binding guards, and ephemeral leave/reseed.
They establish interoperability only after this opt-in suite actually executes.
Neither ordinary CI green nor separate Rust/FakeHome tests imply that result.
If real interoperability fails, preserve the source checkpoint and logs and stop
before any broader core/SDK repair.

This is `publish=false`, outside Cargo `default-members`, and has no public host
endpoint, app ingress, Caller/actor/grant minting, device leases, lease refresh,
SQLite, ordinary body writer, snapshot drain, automatic cut or persistence.
It does not satisfy full session contract readiness (including M8a/M8b).
The existing protocol's `update_id` addition remains proposed, not ratified by
this test framing. No CI lane or required-gate policy is added or weakened.

The new workspace member has a tier-1-node boundary tree entry and lock entry.
Changing root Cargo.toml changes authoritative backend source bindings; boundary
registration and test discovery also require normal source-boundary/inventory
review. Root owns fresh authoritative backend manifest generation and inventory
reconciliation after source review, before publication. This can incur the full
engine generator cost despite the fixture's small build graph. The initial source
checkpoint intentionally does not regenerate those artifacts or claim a full gate.
