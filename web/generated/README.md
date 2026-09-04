# Generated frontend types

`kinds.ts` and `tools.d.ts` are checked-in outputs of the selected Rust
generators `src/bin/kind_types.rs` and `src/bin/tool_types.rs`. Do not edit them
by hand.

Regenerate from the repository root with:

```sh
cargo run --locked --features dev-tools --bin kind-types
cargo run --locked --features dev-tools --bin tool-types
```

They live outside any particular frontend so selected protocol UI extensions
can consume the shared types without depending on the held commercial
Workbench.
