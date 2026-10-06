# Current shared native charge rows

The authority is `src/charges.rs` at measured source b307a2c59. Runtime and
symbolic estimation instantiate the same generic Quantity rows. All arithmetic
is monotone and saturating; MAX is a sticky admission-refusal sentinel through
min/subtraction/division/zero multiplication. Legitimate runtime operands are
cap-bounded. Earlier FORK/GOLDENS rows retain historical provenance.

Here C(x)=ceil(x/64), n is cached deep nodes, b cached deep bytes, l byte length,
and N element/entry count. A row containing a leading node visit uses
`excluding_node_visit` at a site whose node was already charged. Literal payload
and retained-slot rows are additional charges, rather than replacement visits.
All copy/construction rows run before their work; bounded typed semantic errors
remain no successful decision. Logical H follows actual temporary retention
scopes and high-water, not cumulative loop allocation or allocator/RSS bytes.

| Shared row | WU | Scoped logical bytes |
|---|---:|---:|
| node visit / bounded scalar slot | 1 | 8 |
| string/bytes literal | 1 | l |
| scalar text equality/order | 1+C(min(l1,l2)) | 0 |
| aggregate equality | 1+min(n1,n2)+C(b1+b2) | 0 |
| list containment | 1+n+C(b) | 0 |
| map key lookup | 1+C(key length) | 0 |
| contains/startsWith/endsWith | 1+C(l1+l2) | 0 |
| string/bytes concat | 1+C(l1+l2) | l1+l2 |
| list concat | 1+n1+n2+C(b1+b2) | b1+b2 |
| kept map/filter append | 1+n+C(b) | b+32 |
| list literal | N+sum(element nodes), plus C(payload) | 32N+sum(element bytes) |
| map literal rollup | N+rollup nodes−1, plus C(payload) | 64N+key/value bytes |
| classified macro reference bind | 1 | 8 |
| private raw owned bind | 1+n+C(b) | b |
| binding-name / valid key copy | 1+C(l) | l |
| string size | 1+C(l) | 0 |
| string/bytes conversion | 1+C(argument bytes)+C(output bound) | output bound |
| numeric/time string parse | 1+C(argument bytes) | 8 |
| owning scalar text select | 1+C(l) | l |
| owning aggregate select / payload copy / emission | n+C(b) | b |
| list min/max traversal | 1+2N | 0 |
| min/max selected numeric result | 2 | 8 |
| regex search | 1+ceil(l*tier/K) | 0 |
| regex compile (separate load) | tier | tier |
| bounded descriptor preparation | 8 | 448 |
| source compile (separate load) | source bytes | 64*source bytes |
| native input conversion (separate load) | n+C(b) | b |
| additional retained slot | 0 | b |

Aggregate equality uses summed payload because IndexMap can hash long LEFT
keys even against a small RHS; nested aggregates inherit that work. Unsupported
map keys are rejected on borrowed kind before cloning/conversion; valid long
key copies and bounded missing-key diagnostics are precharged. List ADD rejects
nonlist RHS before concat charging/copying. Owned selection discards its
unobservable remainder using swap_remove, avoiding unpriced tail shifts.

Macros borrow each item from the still-live range, remove its local binding
before dropping the iteration level, and retain/copy only kept output elements.
A nonoptional singleton literal range skips the unobservable temporary list.
Temporary owned ranges, error payloads and result retention still contribute
peak H. The 113899-byte heterogeneous 5k-row witness has 15001 nodes and
928890 cached bytes: 32014 WU is the historical owned-bind measurement;
current 5000 reference binds cost 5000 WU before names/body/append/emission.

Formatting uses proven output bounds before construction, including full f64
Display/subnormal/extreme internal values, bounded duration formatting and
lossy UTF8 output at most three times input bytes. Numeric min/max is global or
receiver, homogeneous Int/UInt/Double, first tie, typed empty/mixed/NaN errors;
mixed kinds take precedence over NaN. It scans/validates all elements after
precharge, accepts internally computed infinities and does not copy the list.
Strings are outside these overloads. External unsafe/nonfinite scalars refuse.

Native conversion occurs only after bounded borrowed compact-JSON validation
of the entire pinned snapshot. Source/regex/input load accounts and fixed
symbolic auxiliary ceilings are separate from evaluation W/H. The guest codec,
fuel/allocator coupling and hosted evidence remain PR 2. None of these logical
rows assert actual allocator bytes, wall-time bounds or a universal stack proof.
