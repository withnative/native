# Native architecture

This is a cold-start map of the curated public engine: how requests become
governed state, how that state is read, and where to make a change.
[`native-boundary.json`](native-boundary.json)
is the authority for what belongs in the public repository; update this map
when that selection or a named contract changes.

## Maturity at a glance

- **Current** — the SQLite reference node, MCP-over-stdio server, governed
  domain operations, event logs, projectors, query layer, conformance runner,
  and storage-independent artifact runtimes are included in this repository.
- **Partial** — the opt-in Postgres and exact-local Turso adapters implement
  bounded, contract-tested portions of the same domain boundary. They are not
  interchangeable backends, and an unsupported operation fails closed.
- **Experimental** — federation protocols, cryptographic profiles, and the
  replaceable relay reference implementation are interoperability work, not a
  Native-operated directory or trust service.
- **Held** — the current hosted service composition and Workbench are excluded
  from the public selection. Their existence upstream does not make them a
  capability of this repository.

## Main flow

```text
People, agents and optional views
                |
        MCP operation contracts
                |
     caller identity + authorization
                |
        governed domain operations
                |
       append event + project
          (one transaction)
                |
       authoritative event logs
                |
             projectors
                |
  records + links + facets + search
          |                 |
   history / replay    reads / queries
          `------ conformance ------'
                |
          storage profiles
       SQLite reference node
   Postgres / Turso bounded adapters
```

The write path begins at the registered MCP operation and its typed argument
contract. The caller and requested records are authorized before a governed
domain operation crosses the storage boundary. A successful content mutation
appends an event and applies its projection in the same transaction; projection
tables are never an independent source of business truth.

The read path goes through the query layer. It reads projection state, the
authoritative logs, or the appropriate meta tier and applies the operation's
visibility rules. Replay folds the same ordered events through the same
projectors into fresh projections; conformance checks that rebuilt and live
state agree.

## Layers and invariants

| Layer | Responsibility and invariant | Implementation | Executable proof |
|---|---|---|---|
| MCP contract | Register each operation once; handlers return structured values and transports render them. | [`src/mcp/registry.rs`](src/mcp/registry.rs), [`src/mcp/tools`](src/mcp/tools), [`src/mcp/stdio.rs`](src/mcp/stdio.rs) | [`tests/tools/mcp.rs`](tests/tools/mcp.rs), [`tests/tools/capability_dispatch.rs`](tests/tools/capability_dispatch.rs) |
| Identity, policy and authorization | Resolve a caller and enforce View/Edit/Manage without allowing semantic relationships to grant access. | [`src/identity.rs`](src/identity.rs), [`src/authorization.rs`](src/authorization.rs), [`crates/policy-kernel`](crates/policy-kernel) | [`tests/tools/authorization_contract.rs`](tests/tools/authorization_contract.rs), [`tests/governance/policy_write_funnel.rs`](tests/governance/policy_write_funnel.rs) |
| Governed domain operations | Normalize semantics and projector intent before touching backend-specific transactions; unsupported adapter operations fail closed. | [`src/domain_transaction.rs`](src/domain_transaction.rs), [`src/schema`](src/schema), [`src/relationship`](src/relationship) | [`tests/kernel/write_path.rs`](tests/kernel/write_path.rs), [`tests/governance/relationship_write_funnel.rs`](tests/governance/relationship_write_funnel.rs) |
| Event authority and projection | Append first and project atomically; replay is deterministic, exactly once, and in sequence order. | [`src/store.rs`](src/store.rs), [`src/events.rs`](src/events.rs), [`src/projector`](src/projector) | [`tests/kernel/invariants.rs`](tests/kernel/invariants.rs), [`src/conformance`](src/conformance) |
| Reads and retrieval | Read through the query API, not ad hoc table access; default visibility and historical-read rules stay consistent. | [`src/query`](src/query), [`crates/query-contract`](crates/query-contract) | [`tests/kernel/query.rs`](tests/kernel/query.rs), [`tests/kernel/as_of.rs`](tests/kernel/as_of.rs) |
| Storage and movement | Keep the domain contract backend-neutral while leaving physical transactions, topology, backup, and raw SQL backend-owned. Logical interchange is explicit and validated. | [`src/storage_profile.rs`](src/storage_profile.rs), [`src/interchange.rs`](src/interchange.rs), [`src/postgres`](src/postgres), [`src/turso_local`](src/turso_local) | [`tests/contract`](tests/contract), [`tests/governance/canonical_interchange.rs`](tests/governance/canonical_interchange.rs) |

The smallest end-to-end integrity check is:

```sh
cargo run --bin conformance
```

It exercises the public SQLite reference node's spine and replay contract. See
[`BUILDING.md`](BUILDING.md) before choosing broader Rust checks.

## Side branches

Artifacts branch from governed MCP operations rather than changing the event
and query core. The host resolves publication, inputs, and authorization;
[`crates/artifact-runtime`](crates/artifact-runtime) owns deterministic MDX
compilation and sandbox execution, while
[`crates/artifact-html`](crates/artifact-html) owns HTML sanitization and
verification. The host boundary is in
[`src/mcp/tools/artifacts.rs`](src/mcp/tools/artifacts.rs).

Federation branches at protocol and provenance boundaries. The selected
schemas and fixtures live under [`protocol`](protocol); the experimental
reference implementation and standalone relay entry point live in
[`crates/native-federation`](crates/native-federation).
Protocol comes before implementation: do not infer operated discovery, trust,
or custody services from the presence of the relay.

## Change routing

| Change | Start here | Preserve |
|---|---|---|
| Record type, governed kind, or spine facet | [`src/schema`](src/schema), then generated contracts | Closed record types, governed open kinds, and schema/conformance agreement |
| Record-type correction eligibility | [`crates/record-type-correction-kernel`](crates/record-type-correction-kernel), then the selected storage adapter | One backend-neutral classification and execution-mode mapping; backend-owned authorization, facts, fences, and persistence |
| Write semantics | [`src/domain_transaction.rs`](src/domain_transaction.rs), [`src/events.rs`](src/events.rs), [`src/projector`](src/projector) | Append-event-then-project atomicity and deterministic replay |
| Tool or operation | [`src/mcp/tools`](src/mcp/tools), then [`src/mcp/registry.rs`](src/mcp/registry.rs) | One registration, typed arguments, structured handler results |
| Search or structured retrieval | [`src/query`](src/query), [`crates/query-contract`](crates/query-contract) | Read-only query seams and uniform visibility defaults |
| Permissions or visibility | [`src/authorization.rs`](src/authorization.rs), [`src/policy.rs`](src/policy.rs), [`crates/policy-kernel`](crates/policy-kernel) | Fail-closed authorization and event-backed policy state |
| Message-to-work behaviour | [`src/message_expectation.rs`](src/message_expectation.rs), [`src/relationship`](src/relationship) | Sender intent reconciled from durable recipient-authored evidence |
| Storage support or movement | [`src/storage_profile.rs`](src/storage_profile.rs), [`src/domain_transaction.rs`](src/domain_transaction.rs), then the named adapter | Explicit capability bounds; no generic CRUD abstraction |
| Artifact runtime | [`src/mcp/tools/artifacts.rs`](src/mcp/tools/artifacts.rs), then the relevant artifact crate | Storage-independent compilation and host-owned authorization |
| Federation | [`protocol`](protocol), then [`crates/native-federation`](crates/native-federation) | Wire compatibility, provenance, and experimental boundaries |

Detailed behaviour belongs beside its contract and tests. Keep this file as a
route map: if a statement here cannot be traced to selected implementation and
executable evidence, narrow or remove it.
