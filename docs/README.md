# Native documentation

This index routes readers by question. It links to documents selected into the
curated snapshot; [`native-boundary.json`](../native-boundary.json) is the
authority for that selection.

Maturity labels have the same meaning as in the
[capability and evidence map](capability-map.md): **Current** is implemented
with selected evidence, **Partial** is a real bounded implementation,
**Experimental** is implemented behind an unstable or gated contract,
**Directional** describes a route rather than a supported capability, and
**Held** means the relevant composition exists outside this snapshot.

## Start here

- [Architecture map](../ARCHITECTURE.md) — **Current:** the main write and read
  paths, subsystem invariants, executable evidence, and change-routing table.
- [Capability and evidence map](capability-map.md) — **Current**, **Partial**,
  **Experimental**, and **Directional**: product claims, implementation,
  executable evidence, and the exact boundary beside each claim.
- [Native for agents](for-agents.md) — an agent-facing route through the same
  claims: what becomes easier for the agent, the value to people and teams,
  how to verify it, and what remains dependent on maintenance or judgement.
- [Tool surface](tool-surface.md) — **Current:** concepts and contracts for the
  operations exposed through the selected MCP runtime.
- [Generated tool inventory](tool-surface.generated.md) — **Current:** the
  generated operation list; use the implementation and tests named by the
  capability map for behavioral evidence.
- [Source boundary](source-boundary.md) — **Current** (governance): how the
  machine-readable selection is validated and why held files are absent.

For agents already operating inside Native, the runtime guide corpus begins at
[`src/mcp/guides/README.md`](../src/mcp/guides/README.md). Those guides explain
how to use the product; they are distinct from repository architecture and
evaluation material.

## What is Native's product model?

- [Message-first conversations](message-first-conversations.md) — **Current:**
  immutable Message audiences, thematic Conversations, expectation semantics,
  and honest degradation boundaries.
- [Interpretive claims adoption](interpretive-claims-adoption.md) — **Current:**
  when to preserve an attributed interpretation and when ordinary content is
  the honest choice.
- [Interpretive claims conformance](interpretive-claims-conformance.md) —
  **Current:** validation rules for assertions, assessments, evidence, and
  provenance.

## How do agents find and reconstruct context?

- [Activity query](activity-query.md) — **Current:** activity-oriented reads
  and their visibility and pagination contracts.
- [Temporal reads](temporal-reads.md) — **Current:** reconstructing one
  historical projection with exact `as_of` semantics.
- [What's changed](whats-changed.md) — **Current:** bounded traversal of change
  since a cursor or revision.
- [Agent interventions](agent-interventions.md) — **Current:** durable pause,
  review, and resumption points where human authority is required.
- [Experimental agent intents](experimental-agent-intents.md) —
  **Experimental:** the default-built freshness intent seam and its explicit
  non-production boundary. Private calibration evidence is **Held** and is not
  linked or treated as public proof.

The detailed search and query guides live in the selected runtime corpus:
[effective searching](../src/mcp/guides/effective-searching.md),
[query DSL](../src/mcp/guides/query-dsl.md), and
[query SQL](../src/mcp/guides/query-sql.md).

## How are writes, history, and access governed?

- [Authorization contract](authorization-contract.md) — **Current:** caller
  capabilities, record visibility, mutation authorization, and the distinction
  between authorization and storage possession.
- [Testing strategy](testing-strategy.md) — **Current:** test-suite structure,
  authority, and how behavioral coverage is grouped.

For governed record shapes, facets, and vocabularies, start with the selected
[record-types](../src/mcp/guides/record-types.md),
[facets and vocabularies](../src/mcp/guides/facets-and-vocabularies.md), and
[lifecycle](../src/mcp/guides/lifecycle.md) guides.

## How do storage and portability work?

- [Full-owner local standby contract](local-standby.md) — **Directional:** the
  ratified Milestone 1 read-continuity, snapshot, retention, and status
  contract; runtime and packaging work is not yet implemented.
- [Postgres runtime](postgres-runtime.md) — **Partial:** the opt-in,
  trusted-local Postgres adapter and its exact supported slice. It is not a
  general production-support claim.
- [Turso-local runtime](turso-local-runtime.md) — **Partial:** the exact-local
  Turso adapter and its fail-closed unsupported operations.
- [Storage portability protocol](../protocol/storage-portability/v1/README.md)
  — **Current** contract / **Directional** movement: exact backend profiles and
  canonical interchange vocabulary without promising interchangeable
  backends.
- [Canonical interchange](../protocol/storage-portability/v1/interchange/README.md)
  — **Partial:** the selected interchange envelope and bounded content slice.

SQLite is the complete reference node in this snapshot. Postgres and
Turso-local exercise bounded slices. Postgres-to-SQLite movement, Turso
import/export, and cross-backend round trips are not current capabilities.

## What visual and interactive forms exist?

- [Artifact runtimes](artifact-runtimes.md) — **Current:** durable artifact
  identity, runtime dispatch, governed inputs, and isolation boundaries.
- [`web/mcp-apps`](../web/mcp-apps/) — **Experimental:** two selected optional
  MCP App views for record-version differences and suggestion review.

## What federation work is experimental?

- [Federation transport v1](federation-transport-v1.md) — **Experimental:**
  roles, schemas, discovery, envelope, and receipt contracts.
- [Federated Message content](federated-message-content-v1.md) —
  **Experimental:** the content and expectation subset that may cross the
  protocol boundary.
- [Federation relay](federation-relay.md) — **Experimental:** the standalone
  encrypted store-and-forward reference relay; it is not an operated directory
  or trust service.
- [Cross-database lenses](cross-database-lenses.md) — **Partial** implementation,
  **Directional** federation:
  same-host lens semantics and explicit materialization boundaries.
- [`protocol/federation/experimental-jose-hpke-1`](../protocol/federation/experimental-jose-hpke-1/README.md)
  — **Experimental:** schemas, fixtures, and clean-room interoperability
  material for the gated JOSE–HPKE profile.

## How is the selected source tested?

- [Testing strategy](testing-strategy.md) — **Current:** the public test
  organization and authority model.
- [Source boundary](source-boundary.md) — **Current** (governance): upstream and
  clean-target validation of the exact selected file set.
- [Tool surface](tool-surface.md) and
  [generated tool inventory](tool-surface.generated.md) — **Current:** the
  public MCP contract and generated inventory.
Private CI receipts, operated release evidence, hosted deployment runbooks,
and generated backend attestations are **Held** outside this snapshot.

## Build and contribution guidance

- [`BUILDING.md`](../BUILDING.md) describes the source-snapshot exploration and
  test loop and how to choose optional features.
- The root README gives optional source-exploration entrypoints, the inspection
  snapshot's runtime-qualification boundary, and the license boundary.
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) states the closed-development policy
  and the routes that this public mirror does not accept.

Hosted deployment, account authentication, the HTTP gateway, the commercial
Workbench, and operated backup/release procedures are **Held** outside this
snapshot.
