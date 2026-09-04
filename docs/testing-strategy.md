# Testing strategy: semantic seams and real boundaries

Native should test each behaviour at the lowest layer that owns it, then keep
only enough higher-level coverage to prove that the layers are connected
correctly. This is a cost-shaped test portfolio rather than a target ratio of
unit, integration, and end-to-end tests.

The governing rule is:

> Test decisions comprehensively where they are made; test passage across each
> real boundary with a smaller set of representative contracts.

## Layers and ownership

| Layer | Owns | Preferred proof |
| --- | --- | --- |
| Semantic kernel | State transitions, policy decisions, normalization, no-op detection, event intent | Storage-free, deterministic matrix tests |
| Adapter contract | Transactions, SQL/query shape, locking, projection, rollback, backend error mapping | Tests against the real adapter and database |
| Product boundary | Parsing, authentication and authorization, disclosure, CAS fences, response/event shape | A bounded set through the real MCP or service surface |
| Qualification | Supported deployment wiring and a few critical user journeys | Sparse end-to-end or backend qualification tests |

A behaviour belongs in the semantic kernel when all required facts can be
expressed as stable domain values and the result is a decision or plan. A
physical effect stays at the adapter boundary when its correctness depends on
SQLite/Postgres/Turso semantics, the filesystem, clocks, processes, network
framing, or atomicity across persisted operations.

Higher layers do not need to repeat the entire semantic matrix. They do need
positive, negative, and rollback/corruption cases that prove the adapter
collects the right facts, passes them to the kernel, and applies the returned
plan atomically.

## What a good seam looks like

A seam is capability-shaped and named for domain work. It accepts facts such
as a current policy snapshot and a resolved mutation, and returns a plan such
as `NoChange`, `ReplaceExplicit`, or `RestoreInheritance`. It does not mirror
SQL methods, expose a generic repository, or let a fake pre-program the final
answer.

The adapter still owns:

- transaction and lock boundaries;
- record lookup and subject/account resolution;
- authentication, authorization, and disclosure rules;
- compare-and-set and concurrency fences;
- event append, projection, refresh, and rollback;
- backend-specific failure and recovery behaviour.

The semantic code owns the ordering and meaning of decisions once those facts
are available. Preparation, approval previews, and execution must call the
same planner rather than carry parallel interpretations of a mutation.

## Placement and build cost

Cheap execution and cheap compilation are different claims. A storage-free
test in the root library avoids database setup and normally gives clearer,
faster failures, but it still compiles and links `native-ce` and its default
dependency graph. Moving tests between modules does not improve cold compile
time, and adding a new top-level `tests/*.rs` target adds another full-library
link.

Use the narrow commands in `BUILDING.md`: stay on `cargo check` while changing
types, then switch once to the smallest relevant test target. Keep integration
tests inside the existing grouped `kernel`, `records`, `tools`, `governance`,
`postgres`, and `turso` binaries under `tests/`. Federation protocol, custody,
and relay tests instead live in the focused `native-federation` member; full
engine or hosted composition remains in the relevant root or held suite.
The record-policy pilot has now justified that extra boundary: its stable
types, deterministic grant evaluation, normalization, and mutation planner live
in `native-policy-kernel`; storage snapshots, identity lookup, and bearer walks
remain in the root adapters.
Policy-kernel work should use `cargo test -p native-policy-kernel`; changes to
MCP composition or persistence still require the retained root and grouped
`tools` contracts. Do not generalize that package split to a domain area until
its facts and decisions are similarly stable and measured.

The curated source projection does not include private upstream CI policy,
inventories, or release evidence. The selected tests remain executable locally;
Postgres and Turso require the explicit features and prerequisites in
`BUILDING.md` and their runtime documents.

## First pilot: record-policy mutation planning

The first pilot is `manage_record_policy`. Before this change, executor
preparation and live SQLite execution independently implemented the same
grant, revoke, members-baseline, replacement, and inheritance-restoration
decisions. That duplication made it possible for an approval preview to
describe a different effect from the mutation later persisted.

The storage-free transition planner in `crates/policy-kernel` now owns this
matrix:

- weaker or equal grants are no-ops; stronger or new grants create or replace
  an explicit boundary;
- revoking an absent subject is a no-op, while revoking a present subject
  preserves all other entries;
- members-baseline add, replace, removal, equality, and the prohibition on
  `manage`;
- normalized whole-policy equality versus replacement;
- inheritance restoration, including explicit-boundary and canonical-root
  restrictions;
- the planned effective mode, anchor, entries, and boundary-created flag.

Both executor preparation and live execution use that planner. Compatibility
re-exports keep the existing `native_ce::authorization` and
`native_ce::policy` type paths, so the package is the production model rather
than a parallel test model.

The remaining real `ToolRegistry`/SQLite tests are authoritative for JSON
schema and parsing, authorization and disclosure, person-to-account binding,
content and policy revision fences, event/reason shape, transaction rollback,
and canonical policy projection. The expensive policy integration slice has
eight test functions and seven SQLite database fixtures, down from ten and
nine at the unextracted pilot commit (and nine and eight on `main`).

### Pilot coverage ledger

| Behaviour | Comprehensive owner | Retained real-boundary proof |
| --- | --- | --- |
| Weaker/equal/stronger/new grants in inherited and explicit modes | Kernel matrix | One inherited no-op proves no event, boundary, or anchor change; changed person grant proves boundary creation |
| Revoke absent/present and members baseline equal/change/remove | Kernel matrix | Successful revoke and baseline changes persist through the main policy journey |
| Replacement normalization, duplicate strongest-wins, equality, and inherited boundary creation | Kernel matrix | Successful whole-policy replace plus stale-revision rejection |
| Members `manage` prohibition | Kernel matrix for grant, baseline, and replace | Tool boundary rejection proves validation is reached without persistence |
| Inheritance restoration and root/explicit restrictions | Kernel matrix | Successful restore plus authorized canonical-root refusal |
| Parsing, authorization, disclosure, derived bearers, and person resolution | Tool/SQLite boundary | Schema/shape, viewer/owner, both derived-artifact shapes, and valid/invalid person cases |
| CAS, concurrency, event projection, rebuild, and rollback | Tool/SQLite boundary | Stale revision, concurrent grants, durable reasons, rebuild diff, and injected refresh failure |

### Pilot measurements

The focused semantic edit loop compares the five planner test functions at the
unextracted and extracted seam commits; their pushed equivalents are
`48dd7059` and `9b7e999f`. The extracted version also absorbs the explicit
weaker-grant row previously owned by the integration slice. Measurements used
Rust 1.90.0 on the same shared 16-core host, `CARGO_INCREMENTAL=0`, separate
target directories, one libtest thread, three alternating empty-target cold
runs, and 15 warm runs after two warm-ups. Times are external wall clock, not
libtest's near-zero test-body timer.

| Focused semantic loop | Before | After | Change |
| --- | ---: | ---: | ---: |
| Cold median (range) | 410.19 s (403.81–489.94) | 12.63 s (12.37–12.85) | −397.56 s / **−96.9%** |
| Cold peak RSS median | 6.37 GB | 0.31 GB | **−95.1%** |
| Warm median (IQR) | 0.60 s (0.52–0.65) | 0.33 s (0.32–0.45) | −0.27 s / **−45.0%** |

We initially set a conservative 0.5-second absolute threshold for calling a
warm result material. The observed saving misses that threshold but removes
45% of the median command; 14 of 15 paired reverse-order samples improved and
the IQRs do not overlap. It is therefore reported as a meaningful proportional
improvement with a modest sub-second absolute saving.

After precompiling both revisions, 15 sequential alternating direct-libtest
executions of the complete focused policy portfolio—semantic matrix plus real
MCP/SQLite contracts—measured 5.18 seconds median before (4.98–5.68 range) and
4.04 seconds after (3.92–5.45 range): **1.14 seconds and 22.0% faster**. Both
complete grouped `tools` binaries also passed single-threaded; no full-binary
timing claim is made from that validation run.

Raw samples, exact commands, toolchain, CPU identity, and the RSS collection
method are recorded in [the pilot measurement appendix](testing-strategy-policy-pilot-measurements.md).

These figures are deliberately not described as a full-CI compile reduction:
the real MCP/SQLite boundary still links `native-ce`, and CI still runs it.
Measure the complete grouped `tools` target and matching CI runner/cache class
separately when evaluating suite-wide effects.

## Second pilot: governed relationship reduction

The second pilot applies the same boundary to effective relationship state.
Before extraction, projection and integrity replay both selected a reducer and
then independently overrode its result for retired relationships and unresolved
endpoints. The storage-free `native-relationship-kernel` now owns reducer
selection, assertion semantics, and that final precedence in one operation.
The SQLite adapters only collect facts and map the kernel error.

The kernel matrix covers the reducer registry and versions; default,
`answerable_by`, `assigned_to`, `legacy_link`, and future bilateral semantics;
causal concurrency, transitivity, unresolved pins, cycles, retraction, and
restoration; lifecycle and endpoint precedence; and the durable serialized
assertion-head shape. Existing root relationship, federation, integrity, and
grouped `tools` tests remain authoritative for event validation, SQL atomicity
and projection, federation arrival-order convergence, authorization, wire
shape, paging, and disclosure.

### Relationship pilot coverage ledger

| Behaviour | Comprehensive owner | Retained real-boundary proof |
| --- | --- | --- |
| Reducer registry, versions, and fail-closed selection | Kernel matrix | Projection and integrity replay exercise the production adapter |
| Default and governed-type assertion semantics | Kernel matrix | Five governed worked examples prove manifest admission, binding, SQLite projection, and MCP response shape |
| Causal frontier, concurrency, missing pins, cycles, retraction, and restoration | Kernel matrix | Relationship and federation suites prove arrival-order convergence against persisted events |
| Retired and unresolved-endpoint precedence | Kernel matrix | Endpoint-resolution and integrity-drift tests prove physical fact collection and stored outcomes |
| Assertion-head serialization contract | Kernel regression | Projected digest and watermark tests prove durable database compatibility |
| Authorization, validation, atomicity, idempotency, and visibility | Tool/SQLite boundary | Existing grouped relationship tool tests remain unchanged |

### Relationship pilot measurements

The focused semantic loop compares the three reducer tests at the unextracted
base `a1f711f4` with the seven-test extracted kernel matrix. Measurements used
Rust 1.90.0 on the same shared 16-thread host, `CARGO_INCREMENTAL=0`, separate
target directories, one libtest thread, three empty-target cold runs, and 15
warm runs after two warm-ups. Times are external wall clock.

| Focused semantic loop | Before | After | Change |
| --- | ---: | ---: | ---: |
| Cold median (range) | 397.71 s (396.87–398.79) | 12.96 s (12.96–12.98) | −384.75 s / **−96.7%** |
| Cold peak RSS median | 6.35 GB | 0.31 GB | **−95.1%** |
| Warm median (range) | 0.50 s (0.49–0.51) | 0.31 s (0.31–0.32) | −0.19 s / **−38.0%** |

The warm saving is proportionally clear but sub-second, so the primary result
is the cold compile/link isolation. This is not a full-CI claim: the retained
SQLite and MCP suites still link and exercise `native-ce`, and they passed as
validation rather than being used to infer suite-wide timing.

Raw samples and exact commands are recorded in [the relationship pilot
measurement appendix](testing-strategy-relationship-pilot-measurements.md).

## Third pilot: record-type correction classification

Record-type correction now separates backend fact collection from the shared
eligibility decision. The serde-only `native-record-type-correction-kernel`
owns classification, reason ordering, and the exact execution-mode mapping.
SQLite, Postgres, and Turso retain authorization, transactional reads,
dependency and revision fences, event persistence, rollback, and projection.
All three adapters consume the same production classifier and mode mapping.

Use `cargo test -p native-record-type-correction-kernel` for the focused
semantic loop. This extraction establishes an independently compilable owner;
it does not by itself reduce the retained backend or full-CI suites, and no
before/after timing claim is made without comparable completed measurements.

### Record-type correction coverage ledger

| Behaviour | Comprehensive owner | Retained real-boundary proof |
| --- | --- | --- |
| Autonomous versus confirmed eligibility across uniqueness, same-run references, and shared dependencies | Kernel truth table | SQLite, Postgres, and Turso preparation/execution tests consume collected backend facts |
| Blocking dependencies, sort/dedup, and deterministic reason order | Kernel matrix | Backend dependency digests and stale-plan checks prove physical fact collection |
| Identical or inactive target refusal | Kernel matrix | Adapter tests retain schema admission and target lookup behaviour |
| Exact eligibility and signed-effect serialization | Kernel regression | Existing plan/effect verification tests retain durable wire and digest coverage |
| Authorization, CAS fences, event append, projection, and rollback | Backend adapters | Existing SQLite, Postgres, and Turso boundary suites remain unchanged |

Postgres and Turso still classify `correct_record_type` as partial operated
evidence; this pilot does not promote it into the unrelated five-operation
full-proof closure. Their selected backend suites remain the behavioural
boundary proof.

## Planner convergence without a package split: identity bindings

The same production-duplication principle does not always justify a new crate.
SQLite identity-binding preparation and execution, and the portable
Postgres/Turso domain transaction, previously interpreted the same add,
canonicalize, remove, and binding-only reconcile facts separately. They now
gather physical facts transactionally and consume one typed planner in
`src/identity/binding_plan.rs`. SQLite execution re-gathers those facts and
plans inside its write transaction after the operation's existing revision
fence; it never applies stale preparation-time state. Portable adapters retain
their existing admission, concealment, lock, audit, and rollback ordering while
using the same transition decisions.

This planner remains in `native-ce` because its current edit loop is already
dominated by adapter authorization, visibility, audit, and revision contracts.
No compile-isolation or suite-speed claim is made. The improvement is that a
signed preparation and the later mutation cannot disagree about insert versus
promotion, canonical demotion, no-op behavior, required-durable refusal, stale
ownership, or canonical transfer collision.

### Identity-binding coverage ledger

| Behaviour | Comprehensive owner | Retained real-boundary proof |
| --- | --- | --- |
| Add insert, canonical promotion, existing no-op, and foreign-owner collision | Planner matrix | Executor plan proof plus service collision, disclosure, and canonicalization tests |
| Canonicalize missing, already canonical, and canonical replacement | Planner matrix | Service audit proof and unchanged-response contract |
| Remove absent, present, and only-required-durable refusal | Planner matrix | Service removal journey proves stale fencing, durable audit, and content isolation |
| Reconcile owner validation and target canonical collision | Planner matrix | Executor stale/mid-dispatch proofs and service binding-only transfer journey |
| Authorization, normalization, policy, visibility, state revision, audit ordering, and commit/rollback | Storage adapters | Existing executor and grouped `service` identity suites plus shared Postgres/Turso contract journey |
| Qualified backend equivalence | Backend contract lanes | Postgres and Turso identity proofs exercise planner rejection/no-op rows and hash both the adapter and planner sources |

## Applying the pattern

For the next candidate, write the behaviour matrix before extracting code and
label each row either semantic or physical. Proceed only when the proposed
input facts are stable domain concepts, representative real-boundary tests are
identifiable, and the extraction removes a production duplication or makes an
important decision independently testable. Measure warm test execution
separately from cold compile/link time, and do not delete boundary coverage
until the replacement proves at least the same contract.
