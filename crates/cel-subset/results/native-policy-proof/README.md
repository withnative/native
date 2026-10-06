# Interim native P1 evidence

Production exposes `Policy::P1` (`cel-subset@1/p1`). P0 is crate-private,
present only for historical tests and evidence comparisons. P1 remains
`interim: true`: this is native estimator/meter and listed stack evidence.
Guest codec/session/fuel, allocator high-water and hosted save-to-evaluate
validation evidence wait for PR 2; browser and adapter work are out of scope.

The final tool source is **b307a2c5954630eb58b69159495f8422ee6c800f**. [build-certificate.json](build-certificate.json)
records the clean source/tree before and after the exact Cargo build, features,
profile, relevant build environment, compiler versions, lockfile/source-list
hashes, resulting binary SHA256 and [build.log](build.log) digest.
[run-certificate.json](run-certificate.json) binds each command/output digest
and start/end time to the rebuilt binary; every final report independently
records the same clean start/end source and binary SHA256. The later artifact
commit is deliberately separate from the measured source, avoiding a
self-referential commit hash. Later api.rs/policy.rs packaging edits only correct
comments; production/test behavior remains identical to measured b307. Runtime
metadata alone is not the build binding.

| P1 dimension | Native value |
|---|---:|
| Rule work / scoped logical H | 16,000,000 WU / 402,653,184 bytes (384 MiB) |
| Separate guard work / scoped logical H | 16,000,000 WU / 1,048,576 bytes |
| Total compact scalar-bindings JSON B | 1,048,576 bytes |
| Many rows / row-input declarations Imax | 5,000 / 16 |
| String scalar S / argument declarations | 4,096 bytes / 1,024 |
| Regex tiers / nesting / K / literal pattern | 256,1024,4096 / 32 / 64 / 256 bytes |
| L1 source / real tokens / expanded AST / body nesting / value | 8,192 / 1,024 / 32 / 2 / 35 |
| L0 source / real tokens / weighted grammar chain | 16,384 / 2,048 / 96 |

B includes names, column keys, escapes, scalar arguments and time bindings;
32-byte list slots and 64-byte map entries are cached metrics, not serialized
JSON allowances. Every complete snapshot is revalidated before conversion or
body. External row fields are safe finite scalar values, with unsupported kinds,
nested values and unknown inputs refused. Column key payload is bounded by B,
not S. Rule prefixes pin association/order and cannot skip unresolved guards.
PR4 must translate dependency-graph order to this internal deterministic seam.

[p1-generated.json](p1-generated.json) uses the deterministic typed grammar v2,
seed `0x67910303621b61e5`, 13,673 attempts and no hidden resampling. Exact parsed,
expanded AST/rule/ordered-guard definitions exclude IDs/positions and generator
type annotations; FNV is reproducibility only. The result is **11,539
admitted AND exercised distinct definitions**, including **9,582
successful** and **1,957 typed semantic-error** definitions.
There are 11,965 candidates, 11,961 actual distinct
candidates, 4 duplicates and 422 visible
permitted cost rejections (419 body, 3 guard); failures, canonical-missing and
unexpected input refusals are zero. All 35 families, overload/type metadata,
semantic prefixes, guard progression, input/body/guard costs and output
nodes/bytes/depth extrema retain representative definition/scenario witnesses.
Successful binding/output JSON is pruned only after the complete audits;
full failure witnesses are always retained. Generated rows use 0/1/4/16 pools:
this does not assert that all 11,539 ASTs were executed at every cap.

[p1-fixtures.json](p1-fixtures.json) supplies separate mandatory 5,000-row,
S/B boundaries, heterogeneous/generic rows, row duplication, payload copies,
min/max, temporal boundaries, body-depth two, wide field references,
max-prefix guards, exact refusal categories/stages and input refusal-before-body
witnesses. Its 195 definitions include duplicates/scenario variants: 180 exact
distinct, 168 admitted distinct and 165 body-exercised distinct. Expected input
refusals account for the remainder; fixture failures and false refusals are zero.
All five original M1 groups / 17 examples are pinned to ref `53c887685` blobs
under `experiments/rule-engine-m1/rules`; sheet has four inputs. Original
required/unknown adapter expectations remain opaque evidence, separately
reported from raw CEL clauses/prefix outcomes. Registry opaque examples are not
claimed executable CEL examples.

[p1-calibrate.json](p1-calibrate.json) measures every legitimate expression,
whole-rule phase and guard independently, without public admission discount.
No legitimate measurement refusal is unresolved. The largest estimated rule
work is 4,612,436 WU (total-B regex map), rule H 182,473,871 bytes (heterogeneous
triple-row retention), guard work 4,584,309 WU (total-B regex guard), guard H
29,176 bytes (15 earlier 5k inputs). Required doubled values are respectively
9,224,872 / 364,947,742 / 9,168,618 / 58,352, all below P1. Actual successful
body maxima are 4,023,130 WU / 8,233,364 H; guard maxima 3,995,004 WU / 409 H.
Output maxima are 65,001 cached nodes / 4,116,670 bytes / depth 4. These actual
numbers and semantic-error prefixes are independent of conservative static
admission maxima; none is allocator RSS or a fuel/time guarantee.

Candidate3 and candidate4 sweeps were committed at tool source
`6a371f168a8ca3945670fe717ff64933c6145444` and remain separate sensitivity
artifacts. Both have zero mandatory false refusals and the same doubled
legitimate estimates. Candidate4 uses rule/guard 32M WU, regex tiers
512/2048/8192, nesting24/K128, and accepts `a{128}` at tier8192 where P1
refuses it at top4096. Their 25 compile/search adversaries retain native
hardware/compiler/timing and library-only compile timings separately from public
check/search. [p1-regex.json](p1-regex.json) reruns all 25 on the certified P1
binary: all 51 admitted searches return Ok(Bool) within their bounds; intended
pattern compile refusals remain separate. K is relative native scaling, not
calibrated guest fuel.

Generic rows use the structural compact-JSON proof: each row with e entries
and p unescaped key/text payload has at least `2+5e-[e>0]+p` bytes, with list
separators/envelope overhead. Therefore aggregate E/P obey **5E+P<=B**.
For coefficients a/b, `aE+bP <= max(a,5b)B/5` with checked-u128 upward rounding.
Per-pass `sum(ceil(x/64)) <= ceil(sum(x)/64)+N` preserves rounding; projection
and retention duplicates multiply their coefficients, distinct key-pass
allowances cannot survive duplicating transforms, and temporary peak uses a
maximal individual row plus aggregate retained growth. Finite zero iterations
remain zero; saturated or pending-overflow bounds remain typed refusals, even
through multiplication by zero. Resource products are refused independently
of W/H (including same-input containment, copies and derived provenance), while
O(1) size references remain allowed. Whole rules compose every when/result
without first-match discount; guards have a separate validated-prefix account.

The [current shared charge table](charge-table.md) records payload work,
construction memory, reference binding, diagnostics and separate load rows.

Native auxiliary control is separate from check-load and evaluation H:
250,000 constructed DAG nodes, 1,000,000 visits, 1,000,000 cumulative table/stack/
coefficient cells and 16,384 shape operations. Reports retain measured maxima
and platform inline payload models, including at most two drop-queue edges per
node; container capacity/alignment/headers, fixed TLS/sentinels and cleanup
bookkeeping are excluded, so these are not an exact allocation census. Mandatory
maxima are 4,531 nodes / 2,700 visits / 9,641 cells / 644 shapes; seeded maxima
and witnesses are in the generated report. Iterative hidden-total DAG drop and
sticky auxiliary refusal cleanup have separate helper/public labels.

[checks.json](checks.json) and logs retain narrow default tests, ordinary seeded
proof, explicit default/tools all-target Clippy, format and inventory checks.
Original test-log capture hashes are retained beside tracked-file hashes where
trailing empty lines were stripped for Git whitespace policy. The full default
suite ran at a490; only the subsequent two-file regex proof
outcome/CLI correction differs, and affected tests were rerun at b307. The final
certified generated report exercises the same unchanged proof core at b307.
The full repository pre-push gate was not run locally; parent owns its private
maintainer-guide CI fallback and required exact-head CI. No reduced crate suite
is reported as that full gate.

[parser-calibration.md](parser-calibration.md) retains the full chosen/rejected
L0 matrix and generated named-frame provenance; final integrated direct
parser/visitor/drop debug/release runs cover all 32 families on 4/8 MiB.
[combined-matrix.json](combined-matrix.json) and logs cover the actual public
P1 expression/rule/guard closures on explicit 4/8 MiB named workers, with a
ThreadId assertion and marker-only negative control. The 82 cost/source/refusal
lines agree across debug/release: AST32/body2/value35, equality/emission/drop,
first-match/phase errors, ordered guards, absorbing exits, owned ranges,
shape clone/rebind/join frontiers and real auxiliary Shapes16385 refusal.
Tiny private quotas/20k graph drops are helper evidence, not public admissions.
Regex stack probes cover all 25 patterns with successful Boolean outcomes.
This is measured 8/4=2x operational native headroom for the listed fixtures,
not a universal stack theorem, a measured minimum stack or guest stack proof.
