# Exploring the public source snapshot

This snapshot contains the portable Native node and its selected test and
documentation surface. It contains the SQLite reference node, the local MCP
server, the conformance runner, and the selected tests and docs named in the
README and architecture map.

## Requirements

- Rust 1.98.0, the repository's exact-pinned and tested build toolchain. The
  manifests declare the corresponding `rust-version = "1.98"` supported
  floor.
- Node.js 24 and npm only if you are working on `web/mcp-apps`

SQLite is bundled, so the reference node needs no system database.

## Rust edit and test loop

Stay on `cargo check` while resolving type and borrow errors, then switch once
to the narrowest relevant default-feature test:

```sh
cargo check --locked
cargo test --locked --lib
cargo test --locked --test tools
cargo test --locked --test records
```

Run the complete default-feature suite when the change spans areas:

```sh
cargo test --locked
```

The default features are compile-time switches over code already in the tree.
Postgres and Turso are bounded, opt-in adapters; enable their test features only
when changing those adapters and follow their prerequisites:

```sh
cargo test --locked --features postgres-tests --test postgres
cargo test --locked --features turso-tests --test turso
```

The checked-in inventory generators require the `dev-tools` feature. For
example:

```sh
cargo run --locked --features dev-tools --bin tool-inventory -- --check
```

Avoid `--all-features` as a routine local check: it combines unsupported
backend suites and builds a substantially larger dependency graph.

## Local source-exploration checks

```sh
cargo run --locked --bin conformance
cargo run --locked --bin mcp-stdio -- path/to/native.db
```

The root [README](README.md) includes an exact two-request MCP walkthrough and
its observable success result. The [architecture map](ARCHITECTURE.md) routes
changes to implementation and executable evidence.

For the selected optional MCP App bundles, work inside `web/mcp-apps` and use
the scripts declared in its `package.json`.
