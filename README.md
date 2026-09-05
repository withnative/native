# Native

Native is a connected, inspectable context system for people and AI agents
working together over time.

Context goes stale when its correction lives somewhere else. A file can remain
plausible after the answer changed, and a later person or agent has no in-band
way to see what superseded it.

It keeps the people, conversations, messages, work, decisions, documents,
collections, and artifacts around a project in one connected, inspectable
world. Records carry their history, placement, relationships, attribution, and
governed state. For example, a message can become accountable work without
losing its origin; later readers can search, traverse, and reconstruct what
changed.

Native does not make context maintain itself. Someone or something still has
to record a correction or supersession. The improvement is that the correction
can travel with the work and remain discoverable instead of being trapped in a
person's head or a detached conversation.

## What Native makes possible

**A shared world, not another context file.** When people and agents work
through Native, their records, reads, changes, tool use, run intent, and
activity contribute context to the same inspectable world. That makes later
work easier to recover and continue across sessions and agents. Bringing
external material into that world still has a real acquisition cost, and the
result still needs smaller ongoing acts of semantic stewardship: recording a
correction, marking a decision, or closing work when reality changes.

**Software that can take the shape of the work.** Native separates governed
data from its presentation. The same authorized records can be deliberately
bound into an authored dashboard, project Kanban, canvas, or visual bookshelf
without turning the view into a new silo. Shipped artifact runtimes support
editable MDX source with named inputs, components, and mediated interactions,
or self-contained HTML over exact read-only inputs. The host continues to own
authorization, writes, provenance, and audit. “All your data” here means all
data the caller may access and the artifact explicitly binds—not ambient
access to a workspace or the network. See [Artifact runtimes](docs/artifact-runtimes.md)
for the concrete contract and limits.

This is part of context ownership too: the freedom to reshape how a person or
group sees and acts through its working world, so software can fit the work
rather than the reverse. Portable context, claims, provenance, and authority
also create a basis for new forms of delegation and coordination between
participants who do not need to share a single owner. Replacing the whole
Workbench shell is a direction, not a capability claimed by this snapshot.

## Start with Native

The easiest route today is the first-party
[`withnative/native-plugin`](https://github.com/withnative/native-plugin). It
connects supported agent clients to Native's hosted MCP service; the client
handles OAuth sign-in and the hosted service remains the authority for your
workspace.

You can simply give your AI agent this prompt:
```
Use the install guide at https://github.com/withnative/native-plugin to help me get started with Native.
```

If you want to run the commands yourself:

Claude Code CLI:
```sh
claude plugin marketplace add withnative/plugins
claude plugin install native@withnative
```

Codex CLI:
```sh
codex plugin marketplace add withnative/plugins
codex plugin add native@withnative
```

Adding the marketplace only makes its packages available; the second command
installs Native.

After installation, restart or reload if prompted and ask the agent to help
you finish Native setup. This hosted-first route is the practical way to begin;
the source snapshot below supports inspection and exploration, not turnkey
meaningful self-hosting today.

> **Public source snapshot.** `withnative/native` publishes selected source for
> Native's node and federation protocol work. It is published so people and
> agents can inspect the implementation, architecture, evidence, and the
> boundary between included and held work. Development happens in a private
> upstream, and this history-free mirror contains only deliberately selected
> source and documentation. See the [snapshot notes](RELEASE_NOTES.md) and
> [contribution policy](CONTRIBUTING.md).

## What is in this snapshot

| Maturity | Included surface |
|---|---|
| **Current — included here** | A portable SQLite reference node, the `mcp-stdio` local MCP server, the public MCP tool implementation, event-authoritative history and rebuildable projections, lexical search and structured retrieval, complete-database `export_snapshot`, the conformance runner, and public documentation and boundary enforcement. |
| **Experimental — included here** | Federation wire schemas and fixtures, a replaceable encrypted relay reference implementation, bounded record-diff and suggestion-review MCP Apps, and the default-on agent-intent experiment. These are not operated directory, trust, or custody services. |
| **Partial / spike — included here** | Bounded Postgres and exact-local Turso adapters. Unsupported operations fail closed; these are not interchangeable backends. |
| **Hosted elsewhere / held** | Native-operated hosting, accounts and authentication, hosted backup and runtime composition, and the full commercial Workbench exist outside this snapshot. |

The machine-readable authority for this boundary is
[`native-boundary.json`](native-boundary.json). The generated snapshot is
deny-by-default: a path is absent unless that manifest selects it.

## Roadmap

Inspection is the first public stage.

| Stage | What it means |
|---|---|
| **Inspection snapshot — this repository today** | Inspect the exact selected source, architecture, capability evidence, and included/held boundary. |
| **Runnable Preview — next** | One exact public candidate that can be built, started, exercised, exported, restored, and operated independently, with explicit image provenance and support boundaries. |
| **Meaningful self-hosting — direction** | A usable independent product: the complete core capability surface, a public Workbench, local identity, authentication and administration, team membership and collaboration, backup, export and verified restore, and private coordination domains. |

Native welcomes people operating their own deployments and building compatible
implementations. Meaningful self-hosting is intended to sit alongside Native's
managed hosting, not merely serve as an emergency exit. Native may also
operate optional global discovery, verification, trust, routing, and conduct
services; those services are not intended to be prerequisites for using and
governing your own Native workspace.

No delivery date is promised. The maturity table and capability map remain
the authority for what is present now.

## Source exploration

The following entry points exercise selected code that is included in this
snapshot. They are useful to maintainers and evaluators.

Requirements: Rust 1.98.0, the repository's exact-pinned and tested build
toolchain. SQLite is bundled. The manifests declare the corresponding
`rust-version = "1.98"` minimum.

To explore the executable contract against a fresh reference database:

```sh
cargo run --locked --bin conformance
```

You can also start the local MCP server, ask it for engine information, and let
stdin close. The first request negotiates the legacy-compatible stdio lifecycle;
the second exercises registry dispatch against a newly created SQLite database.

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"native-source","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"engine_info","arguments":{}}}' \
| NATIVE_CE_MCP_SURFACE=legacy \
    cargo run --quiet --locked --bin mcp-stdio -- /tmp/native-source.db
```

In a working local build, the second response contains
`result.structuredContent.engine` equal to `native-ce`. Remove
`/tmp/native-source.db` when you are finished.

To validate an existing Native SQLite file instead:

```sh
cargo run --locked --bin conformance -- path/to/native.db
```

## One concrete workflow

Native Messages have explicit audiences and expectation semantics. A request
for action can be satisfied by a recipient-owned WorkItem derived from that
Message reaching a governed terminal-positive state. A request for a decision
can be satisfied by a recipient-authored Resolution. The communication, the
work it created, and the outcome therefore remain connected rather than being
split across chat history and a separate task system.

Start with [`docs/message-first-conversations.md`](docs/message-first-conversations.md)
and the evidence routes in [`docs/capability-map.md`](docs/capability-map.md).

## Choose your route

- **Evaluating Native as an agent:** [`docs/for-agents.md`](docs/for-agents.md)
  translates the shared product mechanisms into agent benefits, human or team
  value, verification paths, and limits.
- **Evaluating Native:** [`docs/capability-map.md`](docs/capability-map.md)
  maps material claims to implementation, executable evidence, maturity, and
  boundaries.
- **Understanding the system:** [`ARCHITECTURE.md`](ARCHITECTURE.md) maps the
  read/write flow and routes common changes to the right layer.
- **Finding detailed documentation:** [`docs/README.md`](docs/README.md)
  organises the selected corpus by reader question.
- **Inspecting the operation surface:**
  [`docs/tool-surface.generated.md`](docs/tool-surface.generated.md) is the
  generated inventory; [`docs/tool-surface.md`](docs/tool-surface.md) explains
  its contract.
- **Exploring builds or checks:** [`BUILDING.md`](BUILDING.md) gives the
  source-snapshot edit loop and optional-feature boundaries.

## Further context

The public essay [*Distributed Context*](https://writings.withnative.ai/distributed-context)
gives the architectural context: durable, connected, governed state shared by
people and agents across applications, sessions, organisations and time.
Agents can use the [plain-text edition](https://writings.withnative.ai/distributed-context.txt).
Use the capability map and the included/held snapshot above as the evidence
boundary for which parts of that picture are Current, Partial, Experimental,
Directional, or Held here.

The essay [*Freedom in the age of intelligence*](https://writings.withnative.ai/freedom-in-the-age-of-intelligence)
and its Superagency Charter offer normative context for evaluating Native.
Agents can use the [plain-text edition](https://writings.withnative.ai/freedom-in-the-age-of-intelligence.txt).
Treat the Charter as a standard to apply to Native too, not as proof of its
claims. Ask which rights matter here, which mechanisms and evidence implement
them, and where Native falls short.

## Architecture in one paragraph

MCP operations resolve a caller and enforce policy before governed domain
operations cross the storage boundary. A successful write appends an
authoritative event and applies its projection in one transaction. Reads and
queries use the projections, event history, and visibility rules. Replay folds
the same ordered events through the same projectors, and conformance compares
rebuilt state with live state. See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the
layer map, invariants, and change-routing table.

## License

[GNU Affero General Public License v3.0 only](LICENSE.md)
(SPDX: `AGPL-3.0-only`), copyright 2026 AI Native Work Inc.

This is open-source software: you may use, modify, and redistribute it under
the terms of the GNU Affero General Public License v3.0 only, including the
network-use source-offer requirement in Section 13. See [LICENSE.md](LICENSE.md)
for the full terms.
