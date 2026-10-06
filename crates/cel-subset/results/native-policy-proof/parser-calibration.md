# Native L0 calibration provenance

Leaf source 078fb5f4074038f43e5f9d4591aa562a36e9ecb2, integrated as 4a0beaa3d45ed2b4332c7c55a5eef27b406633e5. The selected and rejected candidates below are measured parser evidence. Final integrated debug/release matrix reruns at b307a2c5954630eb58b69159495f8422ee6c800f are in logs/p1-l0-*.log. L0 weighted grammar units differ from exact expanded L1 AST depth.

## Calibrated native L0 table and semantics

| Cap | Chosen native value | Provisional L1 value | Evidence |
|---|---:|---:|---|
| source bytes | 16,384 | 8,192 | literal exactly at cap parsed/visited/dropped on 4/8 MiB in both modes; +1 refused before lexing |
| real tokens | 2,048 | 1,024 | exact ceiling `![0,0,...,0]`, 1,023 list elements; 2,049 refused; hidden whitespace/comments excluded |
| weighted grammar/visitor chain | 96 | exact AST 32 (different units) | every family below reaches its last admitted n, n+1 refused before ANTLR; debug+release 4/8 MiB |

A bracket entry reserves **two units**, calibrated for the complete grammar descent plus child/initializer context; this admits **47 nested grouping/list/map/call/index-child frames**, whereas unary/postfix/arithmetic/ternary edges cost one and can reach 95 operations. Bracket weight is explicitly in code/comments. Calls include an additional macro allowance: map3, filter4, all/exists/exists_one2 (existsOne spelling also conservatively covered). It is not correct to claim a 3x AST-depth margin by dividing 96 by 32: the units differ. Byte/token caps are 2x their provisional L1 caps.

Within frames, chain costs accumulate. Closing children preserves parent postfix state **and propagates child peak height**, so `(a.deep...).more...` cannot bypass. &&/|| reset local segments and contribute `ceil_log2(AND_count+1) + ceil_log2(OR_count+1)` per frame (both levels may stack). Commas terminate only argument/initializer expressions. Ternary persistent levels survive question/colon/logical resets until the enclosing expression ends; map-entry colons are distinguished. Optional syntax does not reset chains. Real lexer failures are refused at their first accurate line/column before recursive parsing, so lexer-discarded characters cannot bypass. Structural malformed delimiters/separators are refused early; other malformed cases exercise bounded ANTLR recovery. Caps/errors carry measured value, limit, line/column, character span and concrete next step. Diagnostic SourceInfo copies at most the byte cap, even for a giant rejected source. Token spans use character offsets (not byte offsets).

Wide fixtures are generated as `inputN.a > otherN.b` joined with ` && `: 20/30/40 conditions pass L0 and parse, with respectively **40/60/80 field references**, bytes **476/726/976**, tokens **159/239/319**, weighted chains **9/9/10**. L1/estimator/evaluation of these remains main-owned.

## Native proof commands and outcomes

Hardware: AMD EPYC 7232P, x86_64 Linux 6.8.0-88; rustc 1.98.0 (88d9e12ae), cargo 1.98.0. Default workspace dev profile O0, dependency O1; release uses the repository release profile. No RUSTFLAGS/profile override. `ulimit -c 0` was set on subprocess searches to avoid core artifacts; child aborts still surface as SIGABRT.

```sh
cargo check -p cel-subset
cargo check -p cel-subset --tests
cargo test -p cel-subset --lib parser::l0::tests:: -- --nocapture
cargo test -p cel-subset --release --lib parser::l0::tests:: -- --nocapture
cargo test -p cel-subset --lib parser::parser::tests:: -- --nocapture
rustfmt --edition 2021 --check --config skip_children=true \
  crates/cel-subset/src/parser/l0.rs crates/cel-subset/src/parser/parser.rs \
  crates/cel-subset/src/parser/mod.rs crates/cel-subset/src/parser/gen/celparser.rs
git diff --check
```

Check/test compilation passed. New L0 tests: **7/7 debug, 7/7 release**, zero ignored. Existing parser tests: **14/14 debug** after owned expectation migration. Debug and release new proofs were rerun at committed HEAD. No full crate/root/all-features/held/web suite is claimed.

`native_stack_headroom` spawns **64 isolated subprocesses per mode**: 26 boundary families + 3 volume fixtures + 3 guard-admitted malformed fixtures, each on explicit 4 MiB and 8 MiB threads. Child invokes direct Parser, without public check's 8 MiB wrapper. No global environment mutation: source/stack/error controls belong to Command.env only. It checks listener/parse errors separately from process abort, then expanded AST depth against the conservative guard, SourceInfo, and ordinary AST/SourceInfo drop; parser tree/visitor drop occurs within parse. No leaked AST or catch_unwind stack proof. **All cases pass on 4 MiB, giving at least 8/4 = 2x measured native stack headroom** for the existing 8 MiB operational worker. A true minimum stack was not measured or claimed. Guest 1 MiB and combined evaluation AST32/value35 proof remain out of scope.

### Complete final boundary matrix

| Input family | n | bytes | real tokens | weighted chain | Debug 4 MiB | Debug 8 MiB | Release 4 MiB | Release 8 MiB |
|---|---:|---:|---:|---:|---|---|---|---|
| select | 95 | 191 | 191 | 96 | pass | pass | pass | pass |
| add | 95 | 191 | 191 | 96 | pass | pass | pass | pass |
| relation | 95 | 286 | 191 | 96 | pass | pass | pass | pass |
| unary | 95 | 99 | 96 | 96 | pass | pass | pass | pass |
| negate | 95 | 96 | 96 | 96 | pass | pass | pass | pass |
| group | 47 | 95 | 95 | 95 | pass | pass | pass | pass |
| list | 47 | 95 | 95 | 95 | pass | pass | pass | pass |
| map | 47 | 283 | 189 | 95 | pass | pass | pass | pass |
| call | 47 | 142 | 142 | 95 | pass | pass | pass | pass |
| index_child | 47 | 142 | 142 | 95 | pass | pass | pass | pass |
| index_chain | 47 | 142 | 142 | 95 | pass | pass | pass | pass |
| receiver_chain | 31 | 125 | 125 | 94 | pass | pass | pass | pass |
| ternary_else | 95 | 666 | 381 | 96 | pass | pass | pass | pass |
| all | 13 | 147 | 118 | 92 | pass | pass | pass | pass |
| exists | 13 | 186 | 118 | 92 | pass | pass | pass | pass |
| exists_one | 13 | 238 | 118 | 92 | pass | pass | pass | pass |
| map_macro | 11 | 122 | 100 | 89 | pass | pass | pass | pass |
| filter | 10 | 144 | 91 | 91 | pass | pass | pass | pass |
| filtered_map | 11 | 177 | 122 | 89 | pass | pass | pass | pass |
| mixed | 15 | 226 | 181 | 91 | pass | pass | pass | pass |
| alternating | 9 | 199 | 154 | 91 | pass | pass | pass | pass |
| mixed_arithmetic | 9 | 172 | 145 | 91 | pass | pass | pass | pass |
| mixed_macro | 5 | 156 | 131 | 91 | pass | pass | pass | pass |
| logic_child | 23 | 349 | 162 | 93 | pass | pass | pass | pass |
| logic_and_chain | 87 | 703 | 351 | 96 | pass | pass | pass | pass |
| closed_group_chain | 46 | 189 | 189 | 96 | pass | pass | pass | pass |
| token_ceiling | — | 2048 | 2048 | 4 | pass | pass | pass | pass |
| source_ceiling | — | 16384 | 1 | 1 | pass | pass | pass | pass |
| wide_logic | — | 2558 | 2047 | 12 | pass | pass | pass | pass |
| malformed_add | — | 96 | 96 | 96 | pass | pass | pass | pass |
| malformed_ternary | — | 571 | 286 | 96 | pass | pass | pass | pass |
| malformed_group | — | 95 | 95 | 95 | pass | pass | pass | pass |


The malformed rows return parse errors rather than ASTs, but the child explicitly asserts `l0::check(source).is_ok()` and absence of an L0 refusal in Parser's error, proving these reached actual generated recovery. Their accepted bounds are at or immediately below the chain ceiling. Ordinary boundary tests compare every n+1 refusal with Parser's exact L0 error, proving refusal before the ANTLR body.

Exact generators for every named family are committed in `l0.rs::tests::shapes`; `boundary_shapes` finds the last admitted n for each. Key mixed generators are `f(a[true?1:...]).f`, `!f([{'k':a[true?1:...]}])`, `-f((a.f+(true?1:...)))`, and `([1].map(x,!f(a[true?1:...]+1)).f)`, recursively repeated. Logical mixes include nested `f(true&&true||...)`, a long select branch beneath both OR/AND, and a select chain continued after group close. Macro fixtures include all/exists/exists_one/map/filter/filtered map at their own admitted boundaries.

## Search failures and source-derived generated-frame cause

These are rejected candidates, not hidden failures:

| Phase/candidate | Probe | 4 MiB debug | 8 MiB debug | Outcome |
|---|---|---|---|---|
| original generated parser, unweighted96 | select/add95 | pass | pass | cheap chain family alone insufficient |
| original generated parser, unweighted96 | grouping32 | SIGABRT | pass | original depth32 lacked 2x headroom |
| original generated parser, unweighted64 | grouping63 (chain64) | SIGABRT | SIGABRT | rejects candidate64 even before mixed suite |
| original generated parser, unweighted96 | grouping95 | SIGABRT | SIGABRT | rejects96 |
| original generated parser, unweighted64 | call/list63 | SIGABRT | SIGABRT | additional candidate64 counterexamples |
| original generated parser | grouping20/24 vs28 | pass/pass vsSIGABRT | pass | bracket recursion dominated |
| split1 primary/member/calc alternatives | grouping32 vs47 | pass vsSIGABRT | not used for acceptance | need residual splits |
| split2 unary/relation + tail Result | grouping47 vs63; call/list47 | pass vsSIGABRT; SIGABRT/SIGABRT | not used for acceptance | need thinner first-child path |
| split3 member/calc dispatch + expr ternary | grouping47/call47/list47 | pass/pass/SIGABRT | not used for acceptance | logical first-child residual evidence |
| final named helpers, weighted96 | complete matrix | pass | pass | accepted calibration; release also passes both |

Original generated closures reserve temporary slots for **all alternatives**, including those never taken, at O0. Every nested primary keeps the whole first-child grammar path live. Splitting only primary was insufficient; residual rule closures remained large. `#[inline(never)] rule_frame` creates one monomorphized alternative boundary without changing ANTLR operations. Tail-returned Result matches avoid one ? error slot per alternative. Unary's branch-local `_alt` declaration moved to its original first assignment; no grammar operation moved. No operational stack was raised.

| Always-live rule closure | Before bytes | Final bytes | Necessary helper grouping |
|---|---:|---:|---|
| primary | 46,440 | 1,944 | 7 alternatives; first split8008, tail Result1944 |
| member_rec | 29,976 | 8,568 | 3 alternatives, then alternate-dispatch boundary |
| calc_rec | 16,984 | 8,472 | 2 alternatives, then alternate-dispatch boundary |
| unary | 15,784 | 1,848 | residual 3 alternatives + tail Result |
| relation_rec | 10,840 | 7,512 | residual operator alternative |
| expr | 6,632 | 3,720 | residual ternary body |
| conditionalAnd | 5,848 | 3,736 | measured residual repetition body, after first child |
| conditionalOr | 5,848 | 3,736 | measured residual repetition body, after first child |

These are objdump-derived prologue reservations for the always-live dispatch closures, not total stack use: selected alternative helpers and wrappers also consume stack, so the isolated full parse/visitor/drop proof is decisive. Original primary prologue reserves 0xb000+0x568=46,440 bytes. Full before/after prologues and intermediate snapshots are preserved below.
