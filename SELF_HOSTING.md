# Run Native from the public source

This is the setup route for an agent helping someone run the **current public
source snapshot** on their own computer. It produces a persistent, local SQLite
database served to an MCP client over stdio. It does not produce a networked
Native service or the browser Workbench. The [README](README.md#roadmap)
describes what comes next, including self-hosting the whole product.

## Give this to your agent

> Help me run Native locally from `https://github.com/withnative/native`.
> Follow `SELF_HOSTING.md` in that repository. First tell me what the current
> public snapshot can and cannot run. Check my OS, Rust toolchain and MCP
> client; clone the public repo, build `mcp-stdio`, put its SQLite database in
> a persistent directory I choose, and configure my client to launch the
> binary over stdio. Verify the connection with `engine_info` and a record
> that survives a client restart. Show me the database path and how to back
> it up. Ask before changing an existing client configuration or database.
> Do not substitute Native's hosted service or a private build.

The agent should report the exact commit it built, the binary and database
paths, client configuration it changed, verification result, and any step it
could not complete. It should stop and explain the missing capability if the
person needs network access, a browser interface, or team accounts.

## What you need

- Git and the Rust toolchain pinned by [`rust-toolchain.toml`](rust-toolchain.toml)
  (Rust 1.98.0). Install Rust with [rustup](https://rustup.rs/) if needed.
- An MCP client that can launch a local stdio server with a command and
  arguments. Its configuration format belongs to that client; inspect its
  current documentation before editing it.
- A directory you control for the SQLite database. Keep it outside the clone
  so replacing the source checkout does not remove your data.

No separate SQLite server is needed. Node.js and npm are not needed for this
local MCP route.

## Build and connect

```sh
git clone https://github.com/withnative/native.git
cd native
git rev-parse HEAD
cargo build --locked --bin mcp-stdio
```

The build produces `target/debug/mcp-stdio` (or `mcp-stdio.exe` on Windows).
Use absolute paths in the client's MCP server configuration:

| Client setting | Value |
|---|---|
| Command | Absolute path to the built `mcp-stdio` binary |
| Arguments | One argument: absolute path to a new or existing `native.db` |
| Transport | stdio |

Create the parent directory before connecting. For example, on macOS or
Linux, `mkdir -p "$HOME/native-data"` creates a place for
`$HOME/native-data/native.db`. On first launch, the node creates a fresh
database at the chosen path. Keep the client launch command pointed at the
same path on every restart. The default MCP surface is the executor surface;
no hosted plan keyring or SMTP configuration is needed for this local route.

Do not place the database on a shared filesystem or launch multiple writers
against the same file. Access to the file also gives access outside the MCP
policy layer; use the operating system's file permissions to protect it.

## Check the result

1. Restart or reload the MCP client after adding the server. Ask it to call
   Native's `engine_info` tool. The response should identify `native-ce`.
2. Ask the agent to create a small test record through Native, then read it
   back and give you its title and reference.
3. Restart the client. Ask the agent to find and read that same record. This
   checks that both launches used the same database file.
4. Note the database path in your own setup notes. Keep the SQLite database
   and its sidecar files together; use `export_snapshot` through Native for a
   verified single-file export rather than copying a live database file.

If the binary exits at startup, run the same command in a terminal and read
stderr. Confirm the binary exists, the database directory is writable, and
the client passed the database path as one argument. For a direct protocol
probe independent of a client, send these two requests to the built binary,
using a separate disposable database:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"native-source","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"engine_info","arguments":{}}}' \
| NATIVE_CE_MCP_SURFACE=legacy target/debug/mcp-stdio /tmp/native-source.db
```

The second response should contain `result.structuredContent.engine` equal
to `native-ce`. That minimal protocol probe selects the legacy compatibility
surface explicitly; keep the default executor surface for the client setup
above. Remove `/tmp/native-source.db` after the probe.

## Current limits

This public snapshot selects the local node and its tool implementation. It
does **not** select the hosted HTTP gateway, authentication and account
composition, hosted backup/recovery operator, or the browser Workbench. A
local client can use the selected tools, but another machine cannot connect
to this stdio process over the network. The SQLite file and export are real;
they do not by themselves qualify a hosted deployment or a team setup.

The exact source boundary is in [`native-boundary.json`](native-boundary.json),
and the [capability map](docs/capability-map.md) labels the selected features
and their limits. Follow the [snapshot notes](RELEASE_NOTES.md) for changes to
this boundary. Do not use deployment commands copied from the private
`native-ce` upstream: its container and hosted runtime are outside this
public repository.
