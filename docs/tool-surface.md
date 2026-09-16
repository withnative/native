# MCP tool-surface contract

Native registers operations once and renders their structured results through
the selected transports. The generated inventory is the authority for exact
operation names, counts, arguments, and exposure metadata:
[`tool-surface.generated.md`](tool-surface.generated.md).

This document describes the stable shape of that selected contract. It does
not describe hosted routing, account management, the commercial Workbench, or
private product history; those surfaces are held outside this snapshot.

## Registration and dispatch

[`src/mcp/registry.rs`](../src/mcp/registry.rs) owns one registry of typed
operations. Each handler returns a structured domain value. Transport code
owns JSON-RPC framing and any text rendering, so domain handlers do not depend
on MCP content blocks.

The selected `mcp-stdio` binary supports newline-delimited JSON-RPC over stdin
and stdout. It negotiates the supported MCP lifecycle, exposes `tools/list`,
and dispatches exact operation names through the same registry. Discovery
filters are intentionally lossy presentation controls: hiding an operation
does not change authorization or exact-name dispatch.

## Contract families

The generated inventory groups the current surface around these domain seams:

- orientation, record lifecycle, placement, facets, links, and relationships;
- lexical search, structured query, activity, and historical reads;
- comments, suggestions, Messages, work, decisions, and interventions;
- governed vocabularies, schema configuration, authorization, and policy;
- citations, attribution, attachments, artifacts, and optional MCP Apps;
- export, storage-profile inspection, and experimental federation operations.

Stored record-body images reuse the attachment aggregate. The portable body
representation and attachment-resolution rules live with the selected
[`record_images` implementation](../src/record_images.rs); hosted browser
ingress and authenticated byte delivery are outside this snapshot.

Exact behavior lives with implementation and executable evidence, not in a
second hand-maintained catalogue. Start with the
[`capability-map.md`](capability-map.md) for claim-to-proof routes, then use the
generated inventory to locate the operation.

## Cross-cutting rules

- Mutations enter governed domain operations; a successful content write
  appends an authoritative event and applies its projection atomically.
- Reads use the query and visibility seams. Possessing a local SQLite file is a
  storage capability and is not equivalent to application authorization.
- Arguments are typed and unknown or invalid fields fail rather than being
  silently interpreted.
- Handlers return structured results. Transport renderers may add text, but
  clients should consume `structuredContent` when available.
- Pagination, bounded traversal, and exact historical-read limits are part of
  each operation contract; broad unbounded reads are not implied.
- Search is lexical FTS, not semantic similarity.
- Optional or experimental operations retain the maturity stated in the
  capability map and generated inventory.

## Work coordination

`start_work` claims a record (`claim`, the default), inspects without writing
(`preview`), or hands a claim back (`release`). Arguments: `record_id`
(required); `action` (`claim` | `preview` | `release`); `agent_id`
(deprecated and ignored — ownership comes from the authenticated account and
validated `run_key`); `expected_holder_run_key` (`string | null`, absent by
default) as the compare-and-release guard for same-account recovery.

Release rules: the exact stored account-and-run holder releases unchanged and
needs no extra argument (a supplied `expected_holder_run_key` must match).
Another run of the same account succeeds only when `expected_holder_run_key`
equals the stored holder run key (explicit null for an account-only holder);
without it the call is refused naming the holding run key, with a wrong value
it is refused as a changed holder to preview and retry. Any other principal is
refused with `claimed by another caller` and learns nothing. Claims never
expire and are never auto-released.

Visibility: a caller under the same account sees `work_state` as `visible`
with the holder's `run_state` (`open` | `closed` | `missing` |
`not_applicable`) and `holder_tier` (`this_run` | `another_run_of_this_agent`
| `another_agent_of_yours`), plus the top-level `held_by*` fields. Any other
principal sees `withheld` exactly as before.

## Regeneration

The inventory generator is selected source and requires the `dev-tools`
feature:

```sh
cargo run --locked --features dev-tools --bin tool-inventory -- --check
```

An inventory drift failure means registration, typed arguments, or checked-in
documentation disagree. Update the generator inputs and regenerated artifact
together; do not hand-edit the generated operation list.
