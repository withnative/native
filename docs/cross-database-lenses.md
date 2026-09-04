# Cross-database MCP lenses

A lens is a named, user-owned list of exact database routing IDs on one Native
host. Its MCP endpoint is `/mcp/lenses/{lens_id}`. Ordinary database connectors
remain unchanged: `/mcp/{db_id}` selects one database, and unscoped `/mcp`
continues to work only when the authenticated user has exactly one database.
Connecting without a lens therefore has no new argument or setup cost.

Lens `search`, `query_record`, and `get_record` calls fan out across the named
scope. Results always carry a composite `{db_id, record_id}` reference. These
live reads are observational: they do not create source records, events,
bindings, read-capture rows, cursors in a constituent database, or cached
content. The catalog keeps only bounded, content-free lens audit state; the
gateway keeps short-lived, bounded cursor snapshots in memory. Membership or
lens-version changes invalidate the whole call; an operational source failure
may instead produce an explicit partial result.

Cursor continuation reauthorizes every successful source and compares its
authorization epoch with the epoch captured around the source call. A change
during a source call discards that source result. A later change invalidates
the cursor. This is deliberately conservative: the epoch can advance for a
broad source write as well as an explicit policy change, so callers restart the
query rather than continuing from a potentially stale authorization snapshot.

Writes on a lens with more than one database require `destination_db_id`. A
one-database lens infers it. This requirement is enforced in the tool call, not
left to conversational convention.

## Governed materialization

`materialize_record` exists only on a lens connector. It takes one exact
`source_ref`, a nonblank reason, and—on a multi-database lens—an explicit
`destination_db_id`. Source and destination must differ.

The default is `identity_only` (or the lens's explicitly configured default):
Native creates or resolves one destination shadow through the portable
`native-record` identity and stores no readable source body. `snapshot` must be
selected explicitly by the call or lens policy. Snapshot calls may select only
the bounded fields advertised by the tool schema and are capped at 256 KiB.
The selected fields and record-scoped revision come from one SQLite read
snapshot, and the digest covers the exact canonical JSON bytes stored. They
also retain freshness, availability, and refresh outcome. Repeating a call
resolves the same shadow and appends a new observation rather than silently
overwriting source truth.

`manage_bindings { action: "observations", record_id, limit }` returns at most
50 view-authorized, payload-free observation summaries. It never returns the
snapshot bytes or record body.

Materialization reauthorizes the complete lens and requires `View` on the exact
source record inside the same SQLite snapshot used for selected bytes and
revision. A denied or missing record has the same non-disclosing response and
does not append destination state. The lens is checked again immediately before
the destination mutation. That second check is the authorization decision for
the in-flight write: once the write commits, its response reports success from
the captured scope instead of turning a committed operation into an apparent
failure. A later scope revocation blocks the next materialization. Existing
destination-authorized snapshots remain honest retained artifacts; they are
not relabelled as a successful fetch.

The v1 boundary is same-host, exact database membership. Cross-node sources,
dynamic selectors, implicit “all accessible databases”, background sync, and
source-record writes are not part of this endpoint.
