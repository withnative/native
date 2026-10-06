# Fork divergences from upstream cel-rust 0.14.5

Every change below is against upstream `cel` 0.14.5 at
`db149ec394af3e47e79cea151cdd87c9b92e6396` (see `VENDORED.md`).
Reasons cite the Native records that ordered the work: 21f5699
(milestone 1 report) and 7e67e57 (WASM-everywhere round 2).

Current PR1b production policy is interim native `Policy::P1`; the sections
below retain historical increments and their then-outstanding work. Later
PR1b entries supersede earlier charge/cap/checkpoint statements. Final source,
build binding, public proof, calibration and listed stack evidence are in
[results/native-policy-proof](results/native-policy-proof/README.md).

## Round 1 — spec fixes + eval budget (spike commit `2a5becdb2`)

Provenance appendix: `experiments/rule-lang-spike/REPORT.md`.

1. `size(string)` counts Unicode code points, not bytes, via the
   `Sizer for String` dispatch path (`src/functions.rs` area).
   Reason: cel-spec conformance (upstream counted bytes).
2. Checked unary negation: new `UnaryOverflow` error variant; release
   `int64_min_negate` now reports `Overflow from unary operator
   'neg'` instead of wrapping (`src/common/types/int.rs`,
   `src/lib.rs`). Reason: spec conformance.
3. `all`/`exists` absorption: the macro shape (`@result` +
   `AND`/`OR(@result, pred)`) folds the predicate directly with error
   memory; the determining value short-circuits, else the first error
   replays (`src/objects.rs`). Reason: cel-spec tri-state logic.
4. Double index + cross-key map: whole-double list indices convert to
   `i64` in `get`/`steal` (fractional/NaN give a clean type error,
   out-of-range gives out-of-bounds); int/uint map-key fallback in
   `get`/`steal`/`contains` (`src/common/types/list.rs`,
   `src/common/types/map.rs`). Reason: spec conformance.
5. Opt-in eval budget: `src/budget.rs` plus `execute_with_budget`,
   TLS step+depth counters, one hook line in `resolve_val`; zero
   behaviour change when unset. Reason: tick-bounded evaluation
   (21f5699 gate condition).

## Round 1 follow-up — NaN ordering (spike commit `d3deaa772`)

6. The four ordering operators (`<`, `<=`, `>`, `>=`) return `false`
   when either operand is a NaN double (`either_nan` in
   `src/objects.rs`), instead of erroring `NoSuchOverload`.
   Reason: IEEE 754 / cel-spec — unordered comparisons are false.

## Round 2 — parse guard (spike commit `8ab19bffb`, task 7e67e57)

7. Bounded parse guard in `Parser::parse`: `MAX_SOURCE_BYTES`
   (64 KiB) checked before lexing, `MAX_PARSE_TOKENS` (1000) checked
   with a throwaway lexer pass before ANTLR recursion, with
   `max_source_bytes` / `max_parse_tokens` setters.
   Reason: long `+`/`&&`/`||`/`.`/index/call chains overflowed the
   native stack (SIGABRT); now refused with clean `input too large`.

## Round 2 — step+alloc budget (spike commit `d8d831258`)

8. `src/budget.rs` counts steps AND allocated bytes (value
   construction: list/map literals, concatenation, macro results),
   with typed `step_budget` / `alloc_budget` refusals; budgets passed
   per evaluation; charging hooks in `bytes.rs`, `list.rs`,
   `string.rs`, `objects.rs`. Reason: the step-only budget missed the
   2^n clone blow-up; the budget must be identical natively and
   in WASM (7e67e57 W1.1).

## Round 2 — one size policy (spike commit `44622a227`)

9. `MAX_SOURCE_BYTES` 4 KiB, `MAX_PARSE_TOKENS` 256 counting only real
   (non-hidden-channel) tokens, new `MAX_PARSE_DEPTH` 32 over ALL
   grammar levels, `parser_pratt` guarded, `max_recursion_depth`
   aligned. Reason: accepted-at-save must imply fits-at-evaluation;
   whitespace/comments no longer count (7e67e57 W1.2).

## Round 2 — regex-lite (spike commit `c9f5a8ec5`)

10. The `regex` feature is backed by `regex-lite` instead of `regex`
    (`Cargo.toml.orig`, `src/functions.rs` `matches` error-text test
    relaxed to a prefix match). Reason: smaller WASM guest; the corpus
    asserts the `invalid_argument` category, not the text.

## Round 2 — stack discipline (spike commit `24d44ac5c`)

11. `STACK_8MIB` plus `Program::execute_on_stack`: parse+evaluate on a
    dedicated thread with an 8 MiB stack (`src/lib.rs`).
    Reason: admitted shapes must evaluate on a known stack in both
    debug and release (7e67e57 W1.3).

## Round 2 — retention charging (spike commit `a1beb4c12`)

12. Deep-size retention charging: list `Adder` charges the appended
    element's deep size via `charge_value` (`src/objects.rs`,
    `src/common/types/list.rs`). Reason: charging only at construction
    missed the 2^n blow-up because deep clones were free; nested
    `.map(x,[x,x])` now refuses identically at n=9-22.

## PR 1a (this PR)

13. Increment 2 — API lockdown plus `Policy` and `p0-interim`:
    new `src/policy.rs` (`Policy` with no `Default`;
    `P0_INTERIM`: W = 2,000,000, M = 8 MiB, `interim: true`) and new
    `src/api.rs` (`check`/`evaluate` plus `Prepared`, `Bindings`,
    `ParseCaps`, `CheckReport`, `EvalReport`; per-call scoped
    worker thread with a ≥ 8 MiB stack). `Program::*`,
    `execute_with_budget`, `execute_on_stack` and all modules are
    `pub(crate)` at most; benches rewritten to the public path;
    doctests on newly-private items marked `ignore`; `compile_fail`
    doctests prove no unbudgeted entry point is exported.
    Reason: design §7.1 and §7.2 items 2 and 10.

14. Increment 3 — cached value metrics: new `src/metrics.rs`
    (`Metrics`, list/map rollups reusing `LIST_ELEM_BYTES` and
    `MAP_ENTRY_BYTES`); `Val::cached_nodes`/`cached_bytes` with
    defaults mirroring the old walk's fallbacks; stored rollups on
    `DefaultList`/`DefaultMap` (computed in `From`, copied on
    clone, incremental `push`); payload-length reads on strings
    and bytes; single-child reads on optionals. `charge_value` is
    now an O(1) cached read with identical amounts (U11 removed).
    Unit tests pin the cache to a naive test-only reference walk.
    Reason: design §1.3 and §7.2 item 3.

15. Increment 4 — charge table, two meters, typed errors: new
    `src/charges.rs` (pure metric→`Cost` rows for §1.3, constants
    moved here from the old `budget.rs`) and new `src/meter.rs`
    (work charged before the operation; memory as a scoped
    high-water mark dropping at iteration ends and comprehension
    exit; depth as an `internal_limit` assertion). Typed
    `WorkBudgetExceeded` / `MemoryBudgetExceeded` / `InternalLimit`
    retire `StepBudgetExceeded` / `AllocBudgetExceeded`; nothing
    classifies message strings. `EvalReport` gains
    `cost {work, memory}`; `Policy::P0_INTERIM` maps onto 2,000,000
    wu and 8 MiB. Existing construction/retention charges are
    re-expressed through the table's memory column; the U1–U14 work
    columns land in increment 5. Golden changes are tabulated in
    `GOLDENS.md`. Reason: design §1.3, §1.4 and §7.2 items 4 and 7.

16. Increment 5 — the U1–U14 work columns and borrowing
    `Select`: `charges::excluding_node_visit` strips each row's
    leading node-visit `1` (charged globally). Wired at their
    operation sites: U1 aggregate equality, U2/U4 `in`/`contains`
    (list, map, string), U4 `startsWith`/`endsWith`, map-key
    hashing, U7 `l + r`, U8 list/map literals, U9 item bind, U12
    result emission, U14 string/bytes ordering, and the `s + t`
    work. U6: a `Select`/index borrows the field when the operand is
    borrowed and charges `nodes(v)` only when it must own a copy. The
    absorbing `all`/`exists` fold restores the memory level on its
    determining short-circuit and its error path. Golden changes are
    tabulated in `GOLDENS.md`. Reason: design §1.3, §7.2 item 5.

17. Increment 6 — U3 removed. `int`, `uint`, `double`, `string` and
    `bytes` now borrow their argument (`&dyn Val` / `downcast_ref`)
    instead of `args.remove(0).into_owned()` + `Box<dyn Val>`, so no
    built-in deep-copies its receiver or round-trips through `Value`;
    only the result is allocated. `size`, `contains`, `startsWith`,
    `endsWith`, `matches` and the duration/timestamp accessors were
    already `Cow`-borrowed via `unary_fn`/`binary_fn`. Enforced by a
    counting-allocator test (`rows.size()`/`v in rows` over 5k rows
    copy nothing) and a registry test that no subset built-in is a
    `Value`-based magic function. Reason: design §1.3 (U3, mandatory
    per review F7) and §7.2 item 5.

18. Step 7.0 — bounded error payloads: new `src/val_desc.rs`
    (`ValueDesc`); error variants that took operand `Value`s take a
    `ValueDesc` instead, rendered by a non-walking `describe` and
    capped at 64 bytes, charging 1 wu. Removes the uncharged O(size)
    copy an error raised once per iteration and absorbed by
    `all`/`exists` could make (review E4). Reason: §1.5 budget/fuel
    soundness.

19. Increment 7 — linear `map`/`filter` (U10): the comprehension fold
    recognises the macro-generated step (`@result + [e]` for `map`,
    `cond ? @result + [x] : @result` for `filter`) and evaluates it as
    take(`@result`) → push(e) → rebind, charging only the increment
    (`1 + nodes(e)` wu, `bytes(e) + 32` mb) through the cached
    incremental `push`; `Context::take_variable` transfers ownership so
    there is no copy or re-walk. Non-append shapes (`exists_one`) keep
    the retention charge. Goldens in `GOLDENS.md`. Reason: design §1.3
    and §7.2 item 6.

20. Increment 8 — `matches` (U5): new `src/regexes.rs`. Patterns are
    **literal-only** (a non-literal is refused at `check`), capped at
    256 bytes, and must compile under one of the policy's NFA size
    tiers (`RegexBuilder::size_limit` / `nest_limit`); the smallest
    such tier is `t(p)`. Every distinct literal pattern compiles once
    during `check` into `Prepared` and is looked up at evaluation, so
    no call recompiles (the `matches` call is intercepted in
    `resolve_val`). Charge: `1 + ⌈len(s) × t(p) / 64⌉` wu before the
    search, `64` the provisional K_re. `Policy` gains the provisional
    tier ladder, nest limit and pattern cap (PR 1b measures them).
    Reason: design §1.3, §2.3 L1, §8 F4, §7.2 item 5.

21. Step 9.0 and Increment 9 — policy and deterministic map order:
    `Policy` gains `regex_k_re` (64) and drops `regex_nest_limit` to 50
    (regex-lite's default); `regexes.rs` notes that compile charging
    lands with the load account in PR 1b. The CEL map's two
    representations (`DefaultMap`/`CelMap` and `Value::Map`) become
    insertion-ordered `indexmap::IndexMap` (already in the workspace
    lock): iteration, serialisation and the `exists`/`all` stopping
    point follow insertion order; equality stays order-insensitive and
    its charge is unchanged; cached metrics carry over. Reason: design
    D1/D-7 and §7.2 item 8.

22. Increment 10a — corpus, parse-proof and review cases in-crate:
    the spike's 225-case corpus moves to `tests/corpus/` and runs
    through the public `check`/`evaluate` under `P0_INTERIM`
    (`src/corpus_tests.rs`) — 222 run, 5 skipped probes, every run
    case matches, so no golden case moved (225 from the spike plus
    the 2 N1 map-key-precedence cases);
    the 30 stack/size-policy shapes run through the public API
    (`src/parse_proof_tests.rs`), 30/30 in debug and release; the
    review's CPU/memory cases (deep equality over 100×5k, the
    `matches` scan, nested mapdoubling to n=22) are all refused by the
    typed meters. Reason: design §7.2 "Must test".

## Charge-table amendments (for 23a4dab §1.3)

Review F4 found scalar string/bytes payload work uncharged (a §1.3
table gap: U1/U2/U9 count nodes, and strings are 1 node whatever
their length). Each row below amends the §1.3 table; the weights are
policy, pinned by `policy_version`, for the design owner to carry
into the note. Goldens in `GOLDENS.md`.

- Scalar `a == b`, `a != b` on strings or bytes: work
  `1 + ⌈min(len a, len b)/64⌉` (`charges::equality_text`).
- Aggregate `==`/`!=`: work `1 + min(nodes a, nodes b) +
  ⌈min(bytes a, bytes b)/64⌉ (`charges::equality_aggregate` gains
  the payload term).
- `x in list`, `list.contains(x)`: work `1 + nodes(list) +
  ⌈bytes(list)/64⌉ (`charges::containment_in_list` gains the
  payload term).
- `size(string)`: work `1 + ⌈len/64⌉` (`charges::size_string`);
  other `size` shapes stay O(1) with no extra charge.
- Comprehension item bind: work `1 + nodes(item) +
  ⌈bytes(item)/64⌉ (`charges::comprehension_item_bind` gains the
  payload term for the per-iteration deep copy).
- `string(x)` / `bytes(x)` conversions: work `1 +
  ⌈bytes(arg)/64⌉` (`charges::string_or_bytes_conversion`).
- Select or index owning a copy of a string or bytes payload: work
  `1 + ⌈len/64⌉` (`charges::aggregate_select_text`, via the U6
  `charge_aggregate_copy` site, including the optional-index wrap);
  a borrowed operand still costs only the node visit.
- `int` / `uint` / `double` / `duration` / `timestamp` on a string
  argument: work `1 + ⌈len(arg)/64⌉` before parsing (reuses the
  `string_or_bytes_conversion` row via `charge_string_parse`);
  non-string arguments convert in O(1) and charge nothing here.
- String or bytes payloads copied into a list or map literal — as
  elements, keys or values: work `⌈text bytes/64⌉`
  (`charges::literal_text_payload`), charged alongside the U8 row
  before the copies, from the already-cached lengths (O(1)).

- `regex` and `chrono` are always on: both are required by the
  `cel-subset@1` allowlist; removing the optionality also keeps the
  test-gate scan and the compiled test set identical.

- Still to land: U13 (input decode at the host boundary). To be listed
  here as it lands.

## PR 1b — declared native inputs (increment 1)

Production `check` requires immutable engine declarations and Prepared pins
those declarations. Production Bindings has only checked insertion; every
evaluation validates the complete current snapshot before conversion. Private
unit-test helpers retain upstream out-of-contract semantic fixtures, never
production validation evidence.

Input bytes are total compact scalar-bindings JSON, including names, keys,
escapes and arguments, counted through a bounded borrowed serializer. The M1
1 MiB total and 5,000 rows/input caps are distinct from cached allocation
metrics (32-byte list slots and 64-byte map entries). P0's string/input-count
measurement domain is provisional and does not constitute calibrated p1.
Serde_json is a normal dependency for byte accounting only; no guest codec
has moved. PR 2 still owns authoritative decode and the save⇒eval boundary.

Increment 1 correction: checked insertion borrows Value before validation and
clones only supported shallow data, so rejection cannot recursively drop a
caller-owned hostile value. Declarations retain row-input order separately
from lexical lookup, recheck named-policy counts at admission, and bound
scalar declarations separately (candidate 1,024; row-input candidate 32).
The early row JSON lower bound is 2+5E−[E>0], plus list delimiters/separators;
exact escaped serialized sizing still determines admission.

## PR 1b — payload charges, extrema and temporal repair (increment 2)

Integrated temporal leaf 0c738be867bc as e7a35d1c7. Duration parsing is
constant-space, exact decimal/exponent with checked prefix sums and global
negation, consumes all input and accepts formatter µs spelling. Saturation,
float rounding, prefix acceptance and negative formatting defects are repaired.
Timestamp +/- duration checks chrono overflow before CEL range checks. Duration
subtraction labels overflow `sub`. Formatter output is <=31 UTF-8 bytes (tight)
in a 32-byte scratch buffer across the full chrono duration range. Parser error
message is fixed 32 bytes; chrono parser messages are <=44 bytes. Existing 222
semantic corpus cases still match; temporal boundary tests cover debug/release
in the leaf and debug on the integrated runtime.

New shared rows deliberately change costs: every evaluated node has 8 logical
memory bytes for scalar construction; payload_copy prices nodes+ceil(bytes/64)
and copied bytes. Fresh list concat, append, aggregate selection and emission
now include text/keys payload work and memory. Conversion prices input and
proven output size before construction (Double Display <=344, duration <=31,
timestamp <=40, int/uint <=20; lossy UTF-8 <=3*bytes). Lossy conversion moves its
owned buffer; bytes concat constructs one result without intermediate vectors.
List literals construct one final output vector. Scalar string parsing charges
linear work and scalar memory before parser entry. All row arithmetic saturates;
zero/max/max-1 tests cover abstract operands without overflow panic.

Map key kind is validated by borrow before clone/conversion on contains,
index/get/steal and literal paths. Valid borrowed key copies are precharged;
steal moves by borrowed lookup. Missing-key diagnostics render at most64chars
rather than copying full text. ValueDesc retains <=64bytes, prices a bounded
448-byte temporary/retention envelope including Double formatting, and uses a
static null description after sticky refusal. Bounded parser FunctionError
construction is separately charged; unsupported overloads return typed errors.

Numeric list min/max have global and receiver forms, homogeneous Int/UInt/
Double only, first ties and winning type. Empty is FunctionError; mixed or
unsupported kinds are NoSuchOverload; homogeneous NaN is FunctionError. Mixed
kind takes precedence over NaN regardless order. The full borrowed list is
precharged and scanned; internally produced infinities are ordered. Strings
are outside this overload. Only the selected scalar is copied, after a shared
charge; no list conversion/copy occurs. External unsafe/nonfinite values remain
input refusals.

Item binding now includes copied bytes in the shared row. Macro loop variables
are explicitly dropped before iteration-level reset; loop-condition temporaries
are inside the iteration scope. A remembered absorbing-fold error reserves a
bounded 1024-byte retained envelope until comprehension exit. Specialized
all/exists/map/filter behavior and sticky refusals are preserved. Generic raw
comprehensions remain private semantic test paths; production L1 closure is
still outstanding at this checkpoint.

Native input conversion borrows a validated complete snapshot and constructs
only the final shallow representation, with charge-before-construction in its
separate account. Source and attempted regex tiers have a separate check-load
account. Reported H remains a deterministic scoped logical metric, not actual
allocator high water; bounded source/AST control structures and allocator
coupling still need the final L1/proof and PR2. No resource closure or P1 freeze
is claimed by this increment. P0/load ceilings are measurement candidates.
Registry RuleExample{name,body} remains opaque; it is not this engine's example
schema. Explicit engine declaration order is an internal checked-prefix seam;
PR4 must translate canonical name/dependency graph order deterministically.

Independent response to runtime review at5bfda5c31: aggregate equality's payload
term is now ceil((bytes(left)+bytes(right))/64), because IndexMap hashes left
keys while probing a smaller right map. Scalar text equality still uses min
length. The authoritative regression uses TWO entries (one-entry IndexMap has
a direct comparison fastpath) and covers nested list/map equality. Numeric
conversion overflow and list index type errors now construct their bounded
payload through precharged helpers. Owned list indexing uses swap_remove;
the remaining owned list is discarded, so selected index semantics are intact.
Shared rows are generic over one Quantity arithmetic interface (runtime u64 and
upcoming symbolic measures), with MAX reserved as sticky refusal sentinel
through ceil division, min and subtraction. Exact overflow assertions cover
regex multiply/divide and text sum/divide; no legal native input reaches MAX.

Accepted parser leaf078fb5f40740 integrated as4a0beaa3d: native L0 is16KiB,
2048real tokens, weighted grammar/visitor frame-chain96. Brackets cost2;
ordinary chain edges1; logical frame terms use ceil-log. These units differ
from exact expanded L1 AST32. Full32-family parse/visitor/drop child matrix
reported debug+release pass at4MiB and8MiB (>=2x operational8MiB headroom).
Rejected original-generated group32/4MiB and group63/8MiB candidates are
retained in the leaf report. Generated frame split names: primary, unary,
member_rec, calc_rec, relation_rec, expr, conditionalAnd, conditionalOr;
#[inline(never)] rule_frame preserves ANTLR operation order. Parent verified
all eight ordered operation lists and unchanged tokens outside those methods.
Program now retains successful Arc<SourceInfo> via parse_with_source_info;
check diagnostics reuse it. Combined evaluation/value stack proof and L1
migration remain outstanding; no guest stack claim follows from these probes.

PR 1b expanded-expression admission now measures L1 independently from L0:
8 KiB / 1024 lexer tokens / expanded AST depth 32 / two nested macro bodies
are provisional measurement candidates. Located refusals retain Program's
SourceInfo. One shared closed-form classifier recognizes all/exists/map/filter/
exists_one; raw upstream comprehension probes remain private semantic helpers.
The historical 30-shape parse proof now records actual L0 results: grouping and
300-token/5-KiB cases pass L0, while missing bindings are evaluation errors.
These private semantic probes are not native scalar-input admission evidence.

PR 1b symbolic measurement checkpoint (not P1 admission freeze): the estimator
calls the generic shared runtime charge rows with symbolic quantities. Native
Prepared exposes work/peak/exit and output size/depth bounds. P0 remains interim;
resource ceilings will be enforced by the calibrated P1 entry after proof.

Distinct-row sums derive from compact JSON B, not a uniform largest row:
E <= floor(B/5), decoded key/string payload P <= B, sum row nodes <= N+E,
row/list metric bytes <= 72E+P+32N. Per-pass scope substitutions preserve
projection/copy multiplicity and ceil rounding (sum ceil <= ceil sum + k-1).
Single-row temporary maxima remain separate from retained output totals.
Affine majorants couple different declarations to the one total JSON quota;
repeated occurrences retain their coefficients. Resource factors survive
mapped/filtered/conditional/concatenated lists and catch implicit scans/copies;
O(1) size references and finite empty loops carry no false product factor.

The native compact JSON contract also gives the stronger joint bound 5E+P<=B:
each scalar map entry uses at least two key quotes, a colon, one scalar byte,
and a separator, plus its raw key/string bytes. The missing first separator
per nonempty row is paid by that row's two braces; list and bindings-envelope
punctuation remain nonnegative, as do scalar argument strings' quotes. Escapes
only increase serialized bytes. For affine coefficients cE/cP, the payload
majorant is min(cE*floor(B/5)+cP*B, ceil(max(cE,5*cP)*B/5)), with coefficient
multiplicities combined first. This tightens static bounds; runtime charges are
unchanged. Pending arithmetic saturation is still checked before tightening.

Overflow refusal sentinels survive arithmetic reductions, including a pending
MAX result multiplied by zero, while finite zero products still disappear.
Maximum/rebind transformations rebuild both bounds of nested parameters;
value/provenance traversal intentionally does not treat total bounds as an
additional per-item cost factor. Native regression tests include the exact
nested-scope counterexample and 113899-byte heterogeneous 5k-row input with
repeated [r,r] / [r,r,r] results. These are foundation tests, not the required
10k admitted-rule proof or calibrated corpus evidence.

Native rule/prefix seam checkpoint: check_rule bounds every when/result clause
(max32, compact encoded clause-array64KiB) and composes all phase peaks/exits,
without a first-match discount. evaluate_rule runs first match under ONE shared
account and reports typed clause/phase errors as no successful decision. Native
required_when guards pin only the ordered earlier input prefix plus scalar args;
complete snapshots are revalidated before conversion and use separate counters.
P0 guard ceilings remain provisional, and P1 rule ceilings are not frozen here.
Guard input order is an internal seam, not incoming registry-array authority.
Regex estimation now uses each call's prepared literal tier, not the largest
tier from an unrelated pattern in the same expression.

Constructed-map iteration retains key kinds separately from value fields, so
Int/UInt/Bool/String keys are not treated as string payload bytes when formatting.
Input row maps keep their string-key aggregate bound. Concat and multi-element
key literals invalidate the distinct-pass lookup shortcut (including union
variants), so key duplication pays repeated projection payload. Filter and
one-to-one mapped key passes preserve only their original pass allowance.
Transactional rule-prefix progress and bounded symbolic DAG destruction remain
outstanding at this checkpoint; this is not a P1 completeness/proof claim.

CEL list ADD now validates the borrowed RHS as a list before the concat row,
including invalid map/scalar/union paths. List+Map formerly admitted map-key
iteration accidentally; it now yields typed NoSuchOverload with no concat
charge or copy. Valid List+List still precharges the same shared concat row.
Public API regressions cover long-key One maps and bounded error-prefix costs;
a direct hook verifies zero concat work/memory/body on invalid kind.

Symbolic summary destruction detaches all last-owner edges iteratively, including
hidden Parameter total bounds. Debug formatting is bounded and interval
majorants are memoized once per value walk rather than recomputed at each Mul.
Normal native tests exercise 20k-node visible/hidden/shared graphs on 4/8MiB
stacks. This is auxiliary graph evidence, not final combined CEL stack proof
or an assertion that all admission-control allocations are already bounded.
The legacy charge_value node refusal is not a general production output cap:
closed production macros reach it only with exists_one's fixed Int accumulator.

Rule evaluation now accepts only immutable CheckedRuleBindings minted by the
exact PreparedRule's transactional ordered prefix. The private rule seal rejects
foreign tokens before conversion/body. Complete scalar arguments are validated
at start; append_next validates borrowed values and the total JSON cap before
visibility/progress. Guarded empty One inputs remain invisible/pending until
their associated pinned guard returns false, or a valid nonempty replacement is
appended. True/semantic-error guards cannot advance or skip a required input.
Guard counters remain separate from the later single whole-rule account.
Tests cover order, declaration/rule association, guarded null/empty map, typed
error/true blocking, false progression, and transactional aggregate-cap failure.
This native admission state provides no fetching, guest codec or hosted evidence.

Estimator control repairs: invalid variadic overload arity is checked before
union-kind Cartesian dispatch. Named contains/startsWith/endsWith retain their
runtime pre-match charges; aggregate operands contribute zero to text_len rows.
A 64-conditional-argument public regression exercises typed error prefixes.
List-shape joins rename both item binders into a globally fresh scope, instead
of renaming one onto a scope free in the other alternative's nested bounds.
The exact free-outer/dependent-inner counterexample has a native regression.

Production check now refuses resource products independently of W/H, and refuses
work or scoped-memory bounds above the policy before issuing Prepared. Errors
retain a source location, measured bound/limit and SQL action. check_rule checks
composed work/peak immediately after EVERY when/result phase, preserving the id
and phase that crossed the ceiling. Individual phases passing does not admit an
oversized whole rule. Private check_native/measurement helpers retain all source,
declaration, shape and name checks but skip cost admission; their preparations
are calibration data, never the public-admitted proof denominator. Existing
foundation/L1 and interim-domain extrema tests use that private path explicitly.
P0's 8MiB ceiling now honestly refuses generic xs.all(x,true) (bound16149105);
calibrated P1 and legitimate-corpus false-refusal evidence remain outstanding.

Select over a conditional union now joins each variant's possible selected field,
including payload shape and conservative owned-copy retention, rather than
falling back to Number. Regressions cover both orientations, nested mixed unions,
semantic-error branches, string/bytes/concat/list-map and owned-map selection.
The 65536-byte One.body public expression now has a sound output bound. The
131072-byte conditional-field regex guard is refused from its corrected static
bound; private candidate execution reproduces the old runtime budget failure.

Private evidence domains now vary S/Imax (1024/8,4096/16,16384/32). Their
8M/128MiB W/H values are provisional measurement ceilings, not a frozen P1;
fixture/generator data is compiled only for tests or native-proof-tools. Rule
and guard ceilings are separate fields/accounts. Guard preparation uses its
own admission budget, not the rule budget. Regex sweep/headroom calibration
and the >=10k actual-public-admission proof remain outstanding.

Native combined stack tests share the actual check/evaluation worker closures
with production, executing them directly on explicit 4/8MiB child workers;
public arbitrary stack/budget APIs remain closed. Normal debug and existing
ignored release selectors include exact admitted AST32 + constructed value35:
30 singleton range wrappers followed by map(r,[[[[r]]]]) combine independent
range/body paths. This uses no deep external input. Related bodies construct
value35 equality operands; successful conversion/emission/drop and long hidden
Parameter total DAG destruction execute on the same explicit worker. Legacy
parser corpus probes remain labeled separately; broad L0 matrix is inherited
from the accepted parser leaf, not rerun as evaluator evidence.

Native symbolic check control is a separate scoped account, with provisional
ceilings of 250,000 constructed DAG nodes, 1,000,000 traversal visits,
1,000,000 cumulative memo/stack/coefficient cells and 16,384 shape operations.
Every node and shape Arc construction and recursive shape clone/rebind/join
checks before allocation; fold tables, traversal slots, affine coefficient
copies/merges and many-factor sets check before adding cells. A denied operation
returns a shared overflow sentinel or terminates the partial fold; check returns
its sticky typed `symbolic_*` refusal before Prepared issuance. Successful
Prepared objects retain the actual auxiliary counts for native calibration.
Private measurement reports now collect those counters for every When/Result
and guard phase independently. They report measured maxima and platform
size_of(Node/Shape/edge) inline payload models, including a 2*nodes edge bound
for last-owner drop queues. Cumulative cells bound traversal/memo/affine records;
the fixed record types and source/declaration/union ceilings make their storage
finite. Rust container capacity, allocator metadata/alignment and fixed TLS/
sentinel bookkeeping are excluded from these payload models. Neither counts nor
payload models are an exact live-allocation census or the CEL scoped H metric.
Cells and node/shape counts bound retained native structures, separately from H;
they do not claim allocator bytes or a guest memory invariant. Source, metadata,
expanded AST and finite union-kind/arity bounds also limit constant auxiliary
objects; the iterative last-owner drop queue has at most two edges per created
DAG node. Rejected and partial tables/drop paths remain within those same counts.
These are calibration candidates, not frozen P1 ceilings. Private upstream
semantic helpers and standalone symbolic unit probes may omit this native
check account; production check and guard/rule phase checks always install it.

Native calibration exposed `rows.map(r,[one].all(q,q.n >= 0))` as a generic-One
copy trap: the old range literal and item binding really copied an arbitrary
One on every outer iteration (estimated4.621B WU at S4096). Closed macro item
bindings now borrow the still-live range, using shared `1WU/8B` reference-bind
charges; raw/private unclassified forms retain the metered owned bind. Child
contexts remove the local reference before lowering the iteration level.
The shared classifier additionally recognizes a nonoptional singleton literal
range: its element is evaluated once and iterated directly, without constructing
an unobservable temporary list. Output append/filter retention and result emission
still precharge every kept payload copy. Errors, lexical shadowing and empty
range semantics remain unchanged. A no-clone hook verifies all five macro forms,
plus refusal-before-copy for retained outputs. Input load remains separately
accounted; earlier fixture diagnostic32014WU is the prior owned-bind table,
whereas5000 reference binds now cost5000WU (binding-name copies separate).
Consequently `xs.all(x,true)` now admits under P0; the numeric refusal regression
uses `xs.map(x,x)`, retaining the independent cross-product refusal assertion.

Auxiliary review follow-up counts the separate two-element Parameter transform
child vector before construction. A partial/refused interval walk now returns
an error directly, without allocating an extra root-error table entry after
refusal. Counters are conservative cumulative controlled-storage units, not an
exact allocation census: the lazily initialized fixed overflow sentinel(s),
fixed thread-local account state and iterative cleanup queue remain separate
bounded bookkeeping. The queue has at most two edges per constructed node;
allocator capacity, alignment and headers remain outside the logical counters.

PR1b native table: production exposes only `Policy::P1` (`cel-subset@1/p1`),
still interim until PR2. P0 is crate-private, present only in tests/evidence
tool builds for historical comparisons. P1 uses S4096/I16, total compact JSON
B1MiB/Many5000, rule16MWU/384MiB logical H, independent guard16MWU/1MiB H,
regex tiers256/1024/4096, nest32/K64/pattern256. Candidate4 retains the broader
8192-byte regex tier as sensitivity evidence. Native measured/static maxima,
false refusals, source/binary identities and headroom belong to the separate
tracked measurement artifact; guest fuel/allocator/browser evidence is PR2+.
The ordinary seeded public-API test requires >=10k admitted AND exercised exact
expanded-AST definitions, canonical_missing0, failures0 and only anchored
permitted candidate refusal codes. Semantic-error definitions are a separate
partition, never reported as successful decisions. Generated input pools use
0/1/4/16 rows; 5000/S/B boundary witnesses are separate mandatory fixtures.
Compact generated execution drops successful binding/result JSON only after
all audits; complete failures and exact identity/count/cost data are retained.

The final native tool was built from clean b307a2c5954630eb58b69159495f8422ee6c800f,
separately from the subsequent artifact commit. Its build certificate and logs
bind exact Cargo command/features/profile, clean pre/post source, binary hash
and run reports. The public P1 report admits and exercises 11539 distinct
definitions:9582 successful and1957 typed semantic-error cases, with zero
failures/canonical-missing/unexpected input refusals.422 candidate cost rejections
remain visible (419 body,3 guard). This does not claim11539 successful decisions
or every generated AST executed at every input cap. Mandatory5k/S/B witnesses,
all17 original M1 opaque adapter expectations and raw CEL outcomes are separate.

Final integrated P1 parser/visitor/drop, actual public rule/guard/eval closures,
shape/error/refusal cleanup and regex searches pass listed debug/release4/8MiB
probes.82 combined evidence lines agree across modes; all51 admitted P1 regex
searches explicitly return Ok(Bool) within bounds, with8 compile refusals
reported separately. These are exercised native headroom fixtures, not a
universal stack theorem or guest invariant. The full repository gate remains
parent-owned CI; narrow crate verification is recorded under its exact scope.
