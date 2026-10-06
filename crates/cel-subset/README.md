# Common Expression Language (Rust)

[![Rust](https://github.com/cel-rust/cel-rust/actions/workflows/rust.yml/badge.svg)](https://github.com/cel-rust/cel-rust/actions/workflows/rust.yml)

The [Common Expression Language (CEL)](https://github.com/google/cel-spec) is a non-Turing complete language designed
for simplicity, speed, safety, and
portability. CEL's C-like syntax looks nearly identical to equivalent expressions in C++, Go, Java, and TypeScript. CEL
is ideal for lightweight expression evaluation when a fully sandboxed scripting language is too resource intensive.

```java
// Check whether a resource name starts with a group name.
resource.name.startsWith("/groups/" + auth.claims.group)
```

```go
// Determine whether the request is in the permitted time window.
request.time - resource.age < duration("24h")
```

```typescript
// Check whether all resource names in a list match a given filter.
auth.claims.email_verified && resources.all(r, r.startsWith(auth.claims.email))
```

## Getting Started

This vendored subset exposes checked expressions, whole rules and ordered
input-prefix guards. Immutable declarations are pinned at check; every call
validates the complete current snapshot before conversion or body execution.
Raw `Program`, `Context` and custom function registration are private.

Use the workspace package in `Cargo.toml`:

```shell
cel = { package = "cel-subset", path = "crates/cel-subset" }
```

Create and execute a simple CEL expression:

```rust
use cel::{check, evaluate, Bindings, Declarations, Policy, Value};

fn main() {
    let declarations = Declarations::empty();
    let prepared = check("size([1, 2]) == 2", &declarations, &Policy::P1)
        .result.unwrap();
    let bindings = Bindings::empty(&declarations, &Policy::P1);
    let report = evaluate(&prepared, &bindings, &Policy::P1);
    assert_eq!(report.result.unwrap(), Value::Bool(true));
}
```

`Policy::P1` is `cel-subset@1/p1`, with 16 million work units and 384 MiB of
scoped logical memory per whole rule. Each guard has an independent 16 million
work unit / 1 MiB account. Total compact scalar-bindings JSON is at most 1 MiB,
including names, keys, escapes, arguments and time values; this differs from
cached allocation metrics. Each Many has at most 5,000 scalar-only rows,
strings at most 4,096 bytes, and at most 16 row inputs are declared. External
nonfinite or unsafe numbers, nested fields and unsupported scalar kinds refuse.
Construction/value limits are AST32, Value35 and two comprehension body levels;
L0 weighted grammar96 is a separate pre-parse measure.

Native estimator bounds are checked against the native runtime meter. P1 remains
`interim: true`: guest codec/session, fuel, allocator memory and guest stack
composition land in PR 2. No hosted validation evidence claims save-to-evaluate
safety here. H is scoped accounting, not measured allocator/RSS memory.

Global and receiver list `min`/`max` support homogeneous Int, UInt or Double
elements, retain the first tie and charge before traversal. Empty lists,
mixed kinds and homogeneous NaN lists yield typed semantic errors; mixed kinds
take precedence over NaN. Internally computed infinities are ordered; external
nonfinite input is refused. Strings are outside these overloads.

The explicit `native-proof-tools` feature provides `cel-native-evidence`:
`cargo run -p cel-subset --features native-proof-tools --bin cel-native-evidence
-- generated p1 10000 OUTPUT.json`. Reports retain complete failure witnesses,
actual and estimated cost extrema, source/binary provenance and exact-AST
distinctness counts. Native proof, measurements and changes are recorded in
[FORK-CHANGES.md](FORK-CHANGES.md), [GOLDENS.md](GOLDENS.md) and
[the native evidence directory](results/native-policy-proof).

### Upstream examples (provenance)

These upstream examples use APIs unavailable in this checked subset.
The `example/` directory was not vendored into this fork; the links
below point at the upstream repository at this fork's upstream
version (`v0.14.5`, see `VENDORED.md`):

- [Simple](https://github.com/cel-rust/cel-rust/blob/v0.14.5/example/src/simple.rs) - A simple example of how to use the library.
- [Variables](https://github.com/cel-rust/cel-rust/blob/v0.14.5/example/src/variables.rs) - Passing variables and using them in your program.
- [Functions](https://github.com/cel-rust/cel-rust/blob/v0.14.5/example/src/functions.rs) - Defining and using custom functions in your program.
- [Concurrent Execution](https://github.com/cel-rust/cel-rust/blob/v0.14.5/example/src/threads.rs) - Executing the same program concurrently.
