# Golden changes (increments 4–5)

Earlier sections record historical charges and proof entry points. The current
PR1b charge corrections and private legacy-corpus qualifications are below;
final native P1 measurements live in
[results/native-policy-proof](results/native-policy-proof/README.md).

Increment 4 replaced round 2's step/alloc budget with the two meters
of design §1.3 (work charged before the operation; a scoped memory
high-water mark) and retired the old error categories (§1.4).
Increment 5 wired the U1–U14 **work** columns at their operation
sites and made `Select` borrow. This file records every expectation
that moves, old → new, with its reason.

**Scope note.** The 225-case corpus and the spike's
`results/bounds.json` live under `experiments/` on the spike branch,
not in this crate, so the corpus re-baseline happens when the corpus
is wired into CI (increment 10 / the PR). The rows below are the
behavioural changes; each is explained by the new units, the
scoping, or a wired U-row.

## Increment 4 — meters and categories

| Expectation | Old (round 2 / increment 2) | New | Reason |
|---|---|---|---|
| Too much computation | `StepBudgetExceeded`, prefix `step_budget:` | `WorkBudgetExceeded` (`work_budget`) | §1.4 retires `step_budget`; typed variant, no message classification |
| Too much retained memory | `AllocBudgetExceeded`, prefix `alloc_budget:` | `MemoryBudgetExceeded` (`memory_budget`) | §1.4 retires `alloc_budget` |
| Depth overrun | `StepBudgetExceeded` | `InternalLimit` (`internal_limit`) | §1.3: depth is an assertion, not a budget |
| Work unit | `steps`, LENIENT 1,000,000 | `wu` = node visits, P0 2,000,000 | 1:1 rename; p0 unmoved |
| Memory accounting | Cumulative `alloc_bytes` | Scoped level `L`; refusal on high-water `H`; p0 8 MiB | §1.3 scoping (F3) |

## Increment 5 — the U1–U14 work columns and borrowing `Select`

`charges::excluding_node_visit` strips each row's leading node-visit
`1` (charged globally), so sites add only the size-dependent term.

| Expectation | Before (increment 4) | After (increment 5) | Reason |
|---|---|---|---|
| Node visit | 1 wu | unchanged (1 wu) | base unit |
| Aggregate `==`/`!=` | +0 | + min(nodes a, nodes b) | U1 |
| `x in list`, `list.contains(x)` | +0 | + nodes(list) | U2, U4 |
| `m[k]`, `m.k`, `k in m`, `m.contains(k)` | +0 | + ⌈len(k)/64⌉ | map-key hashing |
| `<`…`>=` on strings/bytes | +0 | + ⌈min(len a, len b)/64⌉ | U14 |
| `s + t` (string/bytes) | memory only | + ⌈(len s + len t)/64⌉ wu | U14-style work |
| `s.contains(t)`, `startsWith`, `endsWith` | +0 | + ⌈(len s + len t)/64⌉ | U4 |
| `l + r`, fresh list | right-side memory only | + nodes(l)+nodes(r) wu; memory bytes(l)+bytes(r) | U7 |
| list literal memory | Σ element bytes | 32 per element + Σ value bytes; + work (1/element + nodes) | U8 |
| map literal memory | Σ value bytes | 64 per entry + key bytes + Σ value bytes; + work (1/entry + value nodes) | U8 |
| comprehension item bind | memory bytes | work (1 + nodes), no memory charge | U9 (the old charge filed work as memory) |
| result emission | +0 | + nodes(result) | U12 |
| `Select`/index of an aggregate | always deep-copies | **borrows** when the operand is borrowed; a copy charges nodes | U6 |
| `map`/`filter` over N rows | passed at N=5,000 | **refused by `work_budget`** at 5,000, until U10 | U7: the accumulator still takes the fresh `l + r` path, so the copy of its own left side makes the work O(n²); increment 7 (U10) recognises the in-place step and restores linearity |
| Exact costs (in-crate test) | `1`=1; `'abc'`=1w/3mb; `'abc'+'de'`=3w/10mb; `[1,2,3]`=4w/24mb; `{'a':1}`=3w/9mb | `1`=2; `'abc'`=2w/3mb; `'abc'+'de'`=5w/10mb; `[1,2,3]`=14w/120mb; `{'a':1}`=7w/74mb | U12 emission adds nodes; U8 adds 32/element (list) or 64/entry+key (map); `s+t` and `in`/`==` add work. The map's 74 includes the key literal's materialisation (1) plus the U8 rollup (73) |

Still unwired: U3 (native `&dyn Val` built-ins, increment 6), U5
(`matches` tiers, increment 8), U10 (linear map/filter, increment 7),
U13 (input decode — the host/codec load phase, outside this crate's
`evaluate`).

## Increment 6 — U3 removed

No charge or result changes: built-ins were not charged for the
copies (U3 charged nothing), so removing the copies leaves every
cost and every result identical. The change is observable only in
allocation: `int`/`uint`/`double`/`string`/`bytes` now borrow their
argument instead of `into_owned()`, and the subset registry serves
every built-in as a borrowed overload. See the U3 tests below.

## Increment 7 — linear `map`/`filter` (U10)

The comprehension fold recognises the macro append step and appends
in place, charging only the increment. Result and wu/mb change:

| Expectation | Before (increment 5) | After | Reason |
|---|---|---|---|
| `map`/`filter` over N rows | refused by `work_budget` at 5,000 (the accumulator took U7's fresh `l + r` path, O(n²)) | passes at 5,000 (pin `map_over_five_thousand_rows_passes_under_p0`); wu exactly linear at 1k/2k/4k/8k | U10: `@result + [e]` appends in place, charging `1 + nodes(e)` wu, `bytes(e) + 32` mb per element |
| Accumulator memory charge | `charge_value(accu)` per iteration (O(size)) | the increment only; the level still tracks the accumulator's growth | U10 |

## Step 7.0 — bounded error payloads

Error variants that named their operands (`UnsupportedBinaryOperator`,
`Overflow`, `DivisionByZero`, `RemainderByZero`, `UnaryOverflow`,
`UnsupportedKeyType`, `UnsupportedTargetType`, `NotSupportedAsMethod`,
`ValuesNotComparable`, `UnsupportedIndex`) now carry `ValueDesc`, a
bounded description, instead of `Value`. No cost or result changes;
only error **text** and allocations:

| Expectation | Before | After | Reason |
|---|---|---|---|
| Operand rendering in errors | full `Value` Debug, e.g. `Timestamp(9999-12-31T23:59:59+00:00), Duration(TimeDelta { secs: 1, nanos: 0 })`, `String("foo")`, `Int(10)`, `List([...])` | bounded: `timestamp`, `duration`, `string(len 3)`, `int(10)`, `list(len N)`, `map(len N)` (≤ 64 bytes) | the payload must not deep-copy an operand that an absorbed per-iteration error would copy O(size) (review E4) |
| Error-payload allocation | O(size) per error | ≤ 64 bytes + 1 wu | as above |

`functions::tests::test_timestamp` was updated for the new text.

## Increment 8 — `matches` (U5)

| Expectation | Before | After | Reason |
|---|---|---|---|
| Non-literal pattern | evaluated with a runtime pattern (`r.p.matches(p)`) | **refused at `check`** with "matches pattern must be a string literal" | §2.3 L1: the pattern must be a string literal |
| Pattern size | any length; `a{100000}` compiled lazily and could blow up | refused at `check` if over 256 bytes or if it compiles under no NFA size tier (`t(p)` = smallest tier) | §1.3/§8 F4 |
| Compilation | `Regex::new` on **every call** | once per distinct literal pattern at `check`; looked up at evaluation | §8 F4 |
| Charge | none (U5) | `1 + ⌈len(s) × t(p) / 64⌉` wu before the search | §1.3 matches row |
| Error timing | an invalid literal pattern errored at evaluation | refused at `check` | literal-only, compile-once |

## Step 9.0 and Increment 9 — policy and deterministic map order

- **9.0:** `K_re` moves into `Policy` as `regex_k_re` (64, provisional);
  `regex_nest_limit` drops to 50 (regex-lite's own default —
  `hir::Config::default` — for the guest's ~1 MiB stack); `regexes.rs`
  records that compile charging belongs to the load account (§1.3) and
  lands in PR 1b. No golden changes.

| Expectation | Before | After | Reason |
|---|---|---|---|
| Map iteration order (`map`/`all`/`exists`/`exists_one`/`filter`, serialisation) | `HashMap` order — random per process natively, fixed-but-toolchain-dependent in wasm (§1.2 D1) | insertion order (`indexmap::IndexMap`): literals in source order, row maps in binding/column order | D1/D-7, ratified as insertion order |
| Map equality | order-insensitive (HashMap) | order-insensitive (`IndexMap` compares as a map); charge unchanged | D1 |
| `exists`/`all` stopping point over a map | hash-order dependent | deterministic, first inserted key | D1 |

No charge or result changes for scalar-only rules; only the *order* of
map iteration and serialisation becomes deterministic.

## Increment 10a — corpus, parse-proof, review cases

- **Corpus:** the spike's 225 cases (`tests/corpus/*.json`) run through
  the public `check`/`evaluate` under `P0_INTERIM`
  (`src/corpus_tests.rs`). **No case changed.** All 225 match the
  corpus expectations, so there are no golden rows attributable to
  increments 4–9; the engine's values and error categories are
  unchanged.
- **`results/bounds.json`:** the spike's step/alloc bound numbers are
  **superseded by wu/mb** — they were recorded under the retired
  `steps`/`alloc_bytes` units, and the two meters replace them.
- **parse-proof:** the 30 stack/size-policy shapes pass 30/30 in debug
  (`parse_proof_debug`) and in release (`parse_proof_release`,
  `#[ignore]`d; run once, passed).
- **Review cases:** `xs.all(i, rows == rows)` over 100 × 5k refuses by
  `work_budget`; the `matches` scan refuses by `work_budget`;
  nested `.map(x,[x,x])` refuses by `memory_budget` up to n=18
  (full sweep to n=22 in `nested_mapdoubling_full_sweep`,
  `#[ignore]`d; run once, passed). None panics or overflows.
- **Linearity:** exact-wu increments unchanged; the ignored release
  timing moved to 1k/16k.

## Review fixes — F4 string-payload work (amends §1.3)

Scalar string/bytes payload work is now charged with ⌈len/64⌉ terms
(review F4; the §1.3 rows are amended in FORK-CHANGES). Results and
error categories are unchanged; only work numbers move, and only
where text payloads are touched:

| Expectation | Before | After | Reason |
|---|---|---|---|
| scalar `a == b` / `a != b` on strings/bytes | +0 | + ⌈min(len a, len b)/64⌉ | `equality_text` row |
| aggregate `==` / `!=` | + min(nodes) | + min(nodes) + ⌈min(bytes)/64⌉ | payload walk inside the deep compare |
| `x in list`, `list.contains(x)` | + nodes(list) | + nodes(list) + ⌈bytes(list)/64⌉ | per-element string compares |
| `size(string)` | +0 | + ⌈len/64⌉ | code-point count walks the payload |
| comprehension item bind | 1 + nodes | 1 + nodes + ⌈bytes/64⌉ | the bind still deep-copies |
| `string(x)` / `bytes(x)` | +0 | + ⌈bytes(arg)/64⌉ | result copy / parse is O(len) |
| select/index owning a string/bytes copy | +0 | + ⌈len/64⌉ | `aggregate_select_text` row (F4b); borrows unchanged |
| `int`/`uint`/`double`/`duration`/`timestamp` on a string | +0 | + ⌈len(arg)/64⌉ | parse is O(len); reuses the conversion row |
| list/map literal text payloads (elements, keys, values) | +0 | + ⌈text bytes/64⌉ | `literal_text_payload` alongside U8; `{'a': 1}` 7→8 wu, `{'a':1}['a']` 9→10, `'x' in ['abc','abd']` 15→16 |
| literal payloads, nested (round 3) | top-level text only | element `cached_bytes` (keys stay exact text) | strings nested in an element are charged; `[1,2,3]` 14→15, `1 in [1,2]` 15→16; `[bigs]`/`{'k': bigs}` over 1k rows now refused |
| `1 in [1, 2]` (in-crate exact) | 13 wu | 15 wu | list bytes 80 → ⌈80/64⌉ = 2 |
| review string probes (4 MiB `big` over 1k rows: `==`, `size`, `in`) | ~5–7k wu, minutes of wall time | refused by `work_budget` | per-iteration cost ≈ 2 × 64k wu |

No corpus case moves (all payloads are a few bytes, so every new
term is 0 or 1); `map`/`filter` linearity is unchanged (the item-bind
term is constant per element shape).

## N1 — map-literal key precedence

F3 resolved every key and value before checking any key's type, so
`{3.3: 1/0}` reported the value's `division_by_zero` instead of the
key's `bad_key_type`. Each key is now converted (type-checked) right
after it resolves, before its value evaluates; charges still wait
for all entries. No cost changes. Corpus cases
`map_bad_key_before_error_value` (`{3.3: 1/0}`) and
`map_bad_key_before_missing_value` (`{3.3: missing}`), both
`bad_key_type`.

## In-crate tests

No pre-existing in-crate test asserted a budget number; all 148
pass unchanged. The goldens are `exact_costs_for_wired_rows`,
`high_water_persists_across_level_drops`,
`refused_operation_body_never_ran` (node visits plus equality, `in`
and `l + r`), the F3 shape tests,
`review_cpu_case_refused_by_work_budget`,
`absorbing_fold_short_circuit_restores_level`,
`map_over_five_thousand_rows_refused_by_work_until_u10`,
`size_and_in_do_not_copy_rows`,
`subset_builtins_are_overloads_not_magic`,
`absorbed_error_payload_is_bounded_per_iteration`,
`map_over_five_thousand_rows_passes_under_p0`,
`map_and_filter_work_is_exactly_linear`,
`user_text_cannot_name_the_accumulator`,
`linearity_wall_time` (ignored; release),
`compiles_once_per_distinct_literal_pattern`,
`pattern_over_top_tier_is_refused`,
`non_literal_pattern_is_refused_at_check`,
`matches_scan_is_refused_under_p0`,
`exact_wu_for_small_matches`,
`map_literal_iteration_follows_source_order`,
`map_equality_is_order_insensitive`,
`map_exists_stops_at_first_key`, the integration test
`map_order::map_order_is_stable_across_processes`,
`corpus_matches_expectations` (225 cases), `parse_proof_debug` /
`parse_proof_release` (30/30), and
`nested_mapdoubling_refused_by_memory_budget` /
`nested_mapdoubling_full_sweep`.

## PR 1b intentional cost and temporal corrections

Payload work/memory rows and node scalar-memory charge supersede earlier
node-only/memory-free rows. Exact native evaluation costs (wu,H) now include
result-copy payload: `1`=(3,16), `'abc'`=(3,14), `'abc'+'de'`=(6,39),
`[1,2,3]`=(17,272), `{'a':1}`=(12,172), `'ab'.matches('a')`=38wu.
Scoped H for exists_one temporaries remains independent of row count; loop
condition charges now drop with each iteration. Large out-of-contract private
work probes use an unbounded memory budget to isolate W after new memory rows
can refuse first. Production budgets remain closed named policies.

Ordinary negative durations, extreme exact duration decimals and timestamp
arithmetic overflow are repaired. Trailing duration junk now errors; µs
formatter output roundtrips. No existing 222-case semantic corpus expectation
changed. Fixed error strings and bounded descriptors retain typed semantic
errors; no successful decision is issued for min/max empty/mixed/NaN errors.
New min/max tests cover 5000 mapped numeric rows, both invocation forms,
winning type/first signed-zero tie, mixed-before-NaN, infinities, and refusal
before traversal. Private upstream corpus helpers are not native input evidence.

Runtime review correction: aggregate comparison prices sum payload bytes to
cover long left map-key hashing even against a small right map; the 4096-byte,
two-entry and nested regressions are priced. Scalar text min-payload comparison
is unchanged. Numeric overflow/bad list-index errors now include diagnostic
charges before message allocation. Owned selection's removed remainder changes
internal order only; no CEL result changes. MAX arithmetic reductions remain
MAX admission-refusal sentinels, never finite bounds or debug overflow panics.

PR1b native calibration repair: closed macro bindings now use the shared
reference row, exactly1WU/8 logical bytes per item plus separately charged
binding-name copies. The prior owned-copy row remains only for private raw
comprehensions: `1+nodes+ceil(bytes/64)` WU and `bytes` memory. The heterogeneous
10000-field+4999-empty-row witness retains its exactJSON113899/metric928890;
32014WU was the old owned bind measurement, not current work.5000 reference
bindings now cost5000WU before names/body/append/emission. Singleton literal
macro ranges evaluate their element directly, eliminating the temporary list
copy; all retained map/filter elements and output emission remain precharged.
The original222 semantic corpus expectations pass unchanged. Public rejection
of repeatedMany scans/copies remains dedicated `cross_product`; simple all/exists
can now admit under P0 because row payload is borrowed. `xs.map(x,x)` replaces
the earlier numeric-memory refusal witness `xs.all(x,true)`.

Current shared charge rows (additional to per-node1WU/8B):

| Row | Work | Scoped logical memory |
|---|---|---|
| classified macro reference bind | 1 | 8 |
| private raw owned bind | 1+nodes+ceil(bytes/64) | bytes |
| binding name copy | 1+ceil(namebytes/64) | namebytes |
| kept append/filter element | 1+nodes+ceil(bytes/64) | bytes+32 |
| result emission | nodes+ceil(bytes/64) | bytes |

The native auxiliary construction/visit/table-cell/shape ceilings remain a
separate check-control account, not additions to check-load or runtime H.

PR1b public policy changed from P0 to native P1:16MWU/384MiB per rule,
independent guard16MWU/1MiB, S4096/I16, regex256/1024/4096/N32/K64.
P0 remains crate-private only for historical semantic/cost tests and tools.
The original222 semantic corpus retains its outcomes; policy-dependent refusal
goldens continue to use the explicit private historical entry. Native P1
admission/guard/whole-rule bounds and output metrics have separate public proofs.
The joint5E+P<=B JSON majorant tightens static bounds without changing runtime
charge rows. H and check auxiliary counts do not assert allocator or guest memory.

The final seeded public P1 artifact has11539 admitted/exercised distinct
definitions (9582 successful,1957 typed semantic errors), no failed bound/output
audits and422 visible work-cost rejections. The ordinary seeded test applies
the same canonical/failure/permitted-rejection/count gates. Final P1 regex
measurements require actual Ok(Bool) outcomes alongside W/H bounds; low-cost
error prefixes cannot stand in for successful admitted searches.
