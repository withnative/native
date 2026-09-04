# Context freshness runtime — adversarial proof report

## Verdict

Retain the agent-speed freshness thesis for the SQLite candidate, with the
scope and limitations below. The review-strengthened deterministic vertical
slice passes its backend-neutral twelve-step scenario and SQLite adversarial
suite. Two runtime contract falsifiers and four proof-quality defects were
found and closed; all remain represented by executable assertions or recorded
below.

This is evidence for the internal candidate architecture, not a public tool or
UI commitment. It does not establish live-agent dependency-declaration quality.

## Executed validation

- Review-strengthened `freshness_proof`: 14 passed, 0 failed.
- Exact-value F-02 focused rerun: 1 passed, 0 failed.
- `freshness_kernel`: 11 passed, 0 failed.
- `freshness_runtime`: 12 passed, 0 failed.

The only emitted warnings are pre-existing lifetime-syntax warnings from the
vendored `swc_common` dependency; the proof suite emits no project-owned
warnings.

## Proof layout

- `tests/freshness_contract/harness.rs` defines the opaque, test-only semantic
  harness. Its associated database type is never exposed to shared scenarios.
- `tests/freshness_contract/scenarios.rs` contains the shared stateful
  twelve-step scenario. A source guard rejects storage handles, query APIs,
  physical engine names, and projection-table vocabulary in this file.
- `tests/freshness_contract/sqlite.rs` owns the SQLite adapter, authorization
  fixtures, deliberate representation corruption, replay, barriers, and fault
  injection.
- `tests/kernel/freshness_proof.rs` executes the shared scenario and secondary
  falsifiers.

## Twelve-step result

| Step | Executable observation | Result |
|---|---|---|
| Natural authoring | A1 is usable before any Unit, Occurrence, Receipt, or warning exists. | Pass |
| Lazy promotion | A is renamed after promotion; U keeps the same distinct identity/head, and OA retains the exact pre-rename A1 ref, digest, and canonical selector. | Pass |
| Multiple Occurrences | OA and OB bind one U1 to independent artefact revisions, selectors, and roles. | Pass |
| Broad retrieval, narrow reliance | R1 admits U1, AP1, and IN1 as provenance, declares only DC1, and uses an explicit dependency budget of one. | Pass |
| Source revision | U1 remains exactly readable; U2 becomes the head; C1 is immediately an exact U1→U2 impact candidate. | Pass |
| First-read mismatch | The first assembly after U2 seals DC1/U1→U2 at one high-water without background work. | Pass |
| Task-relative materiality | The hero path is materially uncertain and surfaces; the durability path is immaterial and silent for the same exact change. | Pass |
| Continue with uncertainty | The provisional output continues, surfaces now, pins U2, and carries explicit R1/DC1/U1→U2 lineage. | Pass |
| Successful relocation | OA resolves `Relocated`, retains A1 and its digest, and returns the authorized current range. | Pass |
| Broken anchor | Verified unique B1 bytes are removed; OB resolves exactly `Stale`, retains its original ref/digest/selector, exposes B2 with no range, and performs no artefact-wide substitution. | Pass |
| Evidence reconciliation | Exact DC1/U2/homepage evidence clears only the covered debt while historical C1/R1/DC1 remain explainable. | Pass |
| Declaration audit | Confirmed, Underdeclared, and Overdeclared evidence is durable; malformed declarations are rejected; budget usage is inspectable. | Pass |

## Secondary evidence

### Concurrent high-water trace

The test pauses assembly immediately after its content and authorization
boundary is captured. A second task commits U2 before assembly resumes. The
trace proves:

- captured high-water `<` U2 event sequence;
- the paused assembly selects only U1 and claims no U2 comparison;
- a control assembly after U2 selects U2;
- the slow U1 output commits after U2; and
- that output is an exact U1→U2 impact candidate immediately after commit.

This is a coordinated trace, not an assertion over a fortunate final state.

### Atomic failure matrix

One rich package populates provenance, a dependency, comparison, assessment,
reconciliation, uncertainty, command result, Receipt, and output body. Real
database triggers abort at these internal boundaries:

1. authoritative event append;
2. Receipt row;
3. Dependency row;
4. Assessment row;
5. Reconciliation row;
6. provenance row;
7. comparison row;
8. uncertainty row;
9. command-result row;
10. output-body projection;
11. final transaction commit.

At every boundary the exact event/projection/body footprint is unchanged.
Removing the fault and retrying the same idempotency key creates exactly one
logical result; an identical retry returns the same ids; changed intent under
the occupied key conflicts and writes nothing.

### Authorization leakage matrix

| Probe | Evidence | Result |
|---|---|---|
| Hidden Unit vs absent Unit | Normalized errors are identical. | Pass |
| Hidden Occurrence vs absent Occurrence | Normalized errors are identical. | Pass |
| One hidden source vs two differently shaped hidden sources | Fixtures use the same request, policy, and high-water. Their complete authorized explanations are identical after normalizing only the distinct consumer Receipt/output identities: zero visible evidence and one non-counted `Withheld` marker. | Pass |
| Hidden title/type/rationale/grouping | Secret fixture strings are absent from serialized explanations. | Pass |
| Hidden impact sources | Zero visible candidates plus `withheld_context=true`; no hidden count. | Pass |
| Hidden successor | Visible terminal count and ambiguity reflect only visible successors; one `Withheld` marker records incompleteness. | Pass |
| Secondary Occurrence viewer without original bearer | B remains authorized, while U/OB are unavailable and B's own event history contains no Occurrence occupancy. | Pass |
| Historical Receipt | Grants no new source access. | Pass |

Authorization is re-evaluated inside the output transaction before idempotency
occupancy or writes. Revoking the authority bearer after assembly rejects the
commit with zero content event, semantic projection, or key occupancy. Restoring
access and reassembling succeeds.

### Bearer lifecycle and missing representations

- Archiving the original bearer preserves exact Unit and Occurrence access.
- Revocation hides semantic evidence through the same closed authorization
  intersection.
- Deleting the original bearer makes Unit/Occurrence reads unavailable and
  reduces consumer explanation to authorized content plus `Withheld`.
- Making A1 bytes unavailable while preserving its exact address yields
  `Unavailable`, preserves the original ref/digest, leaves the sibling
  Occurrence current, and leaves U readable. Replay is intentionally not run on
  this deliberately corrupted fixture.
- Generic record mutation cannot change a Unit body; only the specialized exact
  revision command is accepted.

Deletion leaves a fixed-bearer Unit stranded fail-closed. V1 has no authority
rebind or rescue operation; that is an explicit limitation rather than silent
fallback to the Unit envelope's policy.

### Supersession and replay

One successor resolves as a single terminal. Adding a sibling successor returns
both terminals with explicit ambiguity. Hiding one successor returns the one
visible terminal, `ambiguous=false`, and a non-counted `Withheld` marker.
Historical R1/DC1 continues to resolve the predecessor revision exactly.

The replay corpus populates all fifteen freshness projections:

`semantic_units`, `unit_revisions`, `unit_heads`, `occurrences`,
`freshness_command_results`, `freshness_runtime_command_results`,
`dependencies`, `dependency_assessments`, `receipts`, `receipt_provenance`,
`receipt_comparisons`, `receipt_uncertainty_lineage`, `reconciliations`,
`unit_supersessions`, and `dependency_audits`.

After disposable read-log deletion, every live/rebuilt row count is non-zero and
equal and every mismatch set is empty.

## Falsifiers encountered and closed

### F-01: semantic-id occupancy leak

Initial `read_unit`, `list_occurrences`, and `resolve_occurrence` paths loaded
projection state before returning authorization errors. A real hidden id and a
nonexistent id therefore produced distinguishable errors. The proof reported
this before any product change. The fix normalizes untrusted semantic reads to
`Unit unavailable`, `Unit revision unavailable`, or `Occurrence unavailable`
while preserving detailed trusted-local diagnostics. Differential assertions
now pass.

### F-02: incomplete explanation

Initial `FreshnessExplanation` could not reconstruct the Receipt high-water,
request/policy, the sealed U1→U2 comparison, assessment evaluator/rationale,
reconciliation, dependency audit, or Occurrence resolution evidence.
Storage-only assertions would not have satisfied the contract. The explanation
now exposes deterministic, authorization-filtered evidence for each. The proof
inspects original R1 and provisional R2 after reconciliation and asserts exact
Receipt ids, revisions, high-waters, requests, policies, U1/U2 comparison,
assessment scope/verdict/evaluator/rationale, reconciliation, confirmed audit,
and OA/OB resolution evidence. Within redacted cases, hidden cardinality and
shape alter no authorized explanation field; incompleteness is represented by
one non-counted marker.

No further runtime contract falsifier fired in the final deterministic suite.

## Review-discovered proof defects and corrections

The initial 14/14 result was not retained as sufficient evidence. Review found
four places where the tests or report could pass without proving the stated
contract:

1. Step 2 promoted A but never renamed or moved it. The shared scenario now
   renames A and compares the complete stored OA before and after the rename,
   while asserting unchanged Unit identity/head and exact historical digest.
2. Step 10 accepted `Stale | Conflict | Unavailable`. The deterministic fixture
   now verifies one unique B1 expression, removes it, requires exactly `Stale`,
   preserves the original ref/digest/selector, and requires no current range.
3. F-02 checked only JSON field presence. It now makes the exact-value R1/R2
   lineage assertions described above, including sealed comparison evidence.
4. The authorization differential compared selected collection counts and used
   different dependency budgets. It now uses one request, policy, and captured
   high-water and compares the complete authorized explanation after only the
   documented consumer Receipt/output identity normalization.

The first strengthened run also exposed a proof-only assumption that stored
selectors preserved raw input representation. Promotion canonically adds the
verified position hint. The test now snapshots the canonical stored Occurrence
before rename and requires exact equality afterward, which is the actual
historical-preservation contract.

## Untested assumptions and deliberate limits

- Materiality evidence is supplied by the caller and checked for exactness,
  consistency, lineage, policy derivation, and authorization. These tests do not
  prove that an agent judges materiality well.
- Dependency declaration economics remain a calibration question. The shared
  fixture proves auditability and uses an explicit budget of one; the product
  default remains 64 and is not validated as the right user-facing budget.
- Receipt payloads currently record declaration outcome as `declared` even for
  a dependency-free output. Later audit can prove Underdeclared, but the write
  itself does not distinguish “genuinely dependency-free” from “unable or
  unwilling to declare.” This should remain a positioning/product risk.
- The proof adapter is SQLite. The shared scenario is portable, but no second
  storage implementation executed it.
- The missing-byte case models loss/corruption through a privileged test seam;
  it proves fail-closed behavior, not a supported operator workflow.
- Live-agent calibration is deliberately outside this deterministic task and
  must run in the separately isolated evaluation protocol.

## Recommendation

Keep the positioning claim narrowly: native-ce can detect and carry materially
relevant context debt at the moment an agent uses context, without forcing
graph-first authoring or routine stops, while retaining exact provenance and
failing closed under missing or hidden evidence. Do not yet claim that agents
declare dependencies or judge materiality reliably in live work; that claim
depends on the isolated calibration study.
