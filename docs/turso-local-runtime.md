# Turso-local runtime adapter

Build `mcp-stdio` with the `turso-local` feature and set
`NATIVE_CE_TURSO_LOCAL_CONFIG` to a JSON file to select one authoritative local
Turso database. This is a production-shaped route for the immutable
`turso-local@4` identity, not a support or operational-qualification claim; the
compiled profile remains `spike`.

The stdio boundary is trusted-local and rejects `NATIVE_CE_ACCOUNT`, positional
database paths, SQLite target configuration, and simultaneous Postgres
configuration. The runtime uses the stable, exact `turso` 0.7.2 driver selected
by the `turso-local` feature.

## Configuration and ownership

The format rejects unknown fields:

```json
{
  "format": "native.turso-local-runtime.v1",
  "logical_database_id": "workspace:example",
  "data_directory": "/var/lib/native/turso"
}
```

`data_directory` must be an absolute, non-symlink directory. Native derives the
database and lock filenames from the SHA-256 digest of
`logical_database_id`; callers cannot route a logical database into an
arbitrary file. The database contains a matching engine-owned topology row,
which is checked on every open.

`logical_database_id` is an exact opaque identity and must not contain leading
or trailing whitespace. This prevents visually equivalent configuration values
from deriving different authoritative files.

The runtime acquires a non-blocking exclusive OS lock before opening the
database and retains it for the lifetime of every cloned engine handle. A
second process, or a second independent handle in the same process, fails
closed. Writes inside the owner process are serialized before Turso's
`BEGIN IMMEDIATE` admission, while reads may use independent connections.

### Existing files and local trust boundary

Fresh files use physical engine schema v39 and profile revision 4. Exact v2 and
v3 runtime markers are upgraded atomically on reopen: v2 first crosses its
previously qualified v3 marker step, then v3 advances to v4. Revision 4 changes
only the declared Native lexical-search capability and marker constraint, not
the v39 authoritative content topology. Each step verifies the immutable
predecessor marker and logical database identity, then transactionally rebuilds
only that marker; content and projection tables are not rewritten. A non-empty
target with any earlier or malformed profile marker, a different logical
identity, an old engine schema, missing physical overlays, or incomplete
content and governed-kind genesis fails closed. Moving other data into this
topology remains unqualified until a canonical export/import or migration path
is separately implemented.

The stdio route is trusted-local, not a sandbox against a malicious process
running as the same operating-system user. Leaf symlinks and non-regular
targets are rejected before acquisition/open, and the exclusive lock prevents
ordinary competing owners. The Turso driver accepts a pathname rather than an
already-verified file descriptor, so these checks do not claim protection from
a deliberate same-user filesystem race between validation and driver open. A
hostile-local threat model would require descriptor-relative, no-follow driver
support and is outside this profile.

## Physical overlays

Fresh creation applies the canonical schema with three explicit Turso-owned
differences:

- `facet_values.value_num` is a physical column maintained atomically by the
  shared projector because Turso 0.7.2 does not provide the canonical SQLite
  generated-column implementation.
- `records_turso_fts` and `records_name_turso_fts` are Turso FTS indexes, not
  SQLite FTS5 virtual tables or triggers.
- `_native_turso_runtime` binds the file to one logical database and profile
  revision.

Health and open readiness require the current engine schema, exact normalized
definitions for all three overlays and every table and explicit index used by
the qualified slice, derived from the compiled canonical DDL plus the declared
Turso physical substitution. The comparison therefore includes columns,
defaults, constraints, foreign keys, uniqueness, predicates, and index shape,
not only object names. Readiness also requires complete shipped
vocabulary/core-kind identities and metadata, both canonical roots with their
root policy-anchor projection, the root policy projection/event, and database
identity/audit genesis. This includes the semantic branches reachable through
generic record and link writes:
`annotation_targets`, `attribution_targets`, `semantic_units`, `message_audience_state`,
`message_mentions`, `message_conversations`, and `facet_observations`. Missing
or altered state makes `health` report not-ready/not-write-ready and makes a
subsequent runtime open fail closed. Operation dispatch does not itself run a
health probe, so operators must use readiness as the admission signal. The FTS
indexes expose a qualified Partial Native `search` slice. Backend-native FTS
selects lexical candidates inside the admitted read snapshot; shared code owns
caller/no-oracle filtering, scopes, deterministic ranking and ties, snippets,
pagination caps, and near-miss shaping. Tokenizer/stemmer identity, engine-native
fragment snippets, and physically indexed prefix near misses remain explicit
residuals, so this is not classified Full.

## Qualified runtime slice

The adapter registers `ping`, `engine_info`, `create_record`, `get_record`
(base records plus the bounded `Annotation:comment` count/window),
`update_record`, `delete_record`, `archive_record`, `manage_links`, record-scoped
`get_history`, `attach_text`, `attach_from_url`, `read_attachment`, and
`manage_attachments`, and the Partial backend-native lexical `search` slice.
Record-scoped history defaults to explicit metadata derived after caller
redaction; pass `detail: "full"` for complete caller-visible event payloads.
The qualified profile also registers the isolated, bounded `query_sql` surface.
These handlers use the shared event/projector, authorization, attachment and
request-lifecycle contracts. The fixed profile admits only the exact registered
operation/capability pairs. Successful content commits mark request-local
completion and wake the Turso runtime's broadcast hub once after durability;
overlapping requests cannot attribute another request's commit.

Production consumers can call `TursoLocalDb::subscribe_realtime` to obtain a
bounded `TursoLocalRealtimeTailer`. It emits process-local monotonic generations
for future durable request completions and carries no record data. Consumers
must re-read authorized state after a notification. Lag and runtime closure are
explicit errors requiring authoritative reconciliation/resubscription; the
tailer is a change signal, not a durable event log.

The comment slice is intentionally limited to the registered generic tools:
atomic root/reply creation, comment count and paging on `get_record`, root-only
resolution through `update_record`, and immutable `part_of` bearers through
`manage_links`. `start_work` comment handoff, comment search/tree/activity
views, historical (`as_of`) comment windows, suggestion/citation enrichments,
and bulk moderation are not qualified for Turso-local. Calls for those adjacent
surfaces fail with the stable backend-unimplemented or qualified-boundary error;
they do not return a false empty thread or fall back to SQLite behavior.

Trusted-local stdio calls retain the operator-owned identity boundary. Routed
authenticated calls must resolve to exactly one canonical portable account
binding; `create_record` auto-attributes `owner_id` to that identity and rejects
a different caller-supplied owner. Comment events retain the authenticated actor
and validated run key in ordinary history. The comment record/link event shape
is covered by the Turso replay-equivalence contract; the production adapter does
not expose a rebuild operation.

No handler is registered for enriched record selectors, whole-log or
run-filtered history, export/snapshot, backup/restore, cloud, or sync.
Exact-name calls therefore return the stable backend-unimplemented or
qualified-boundary error rather than falling back to SQLite behavior.

`query_sql` never prepares caller SQL against this authoritative file. One
bounded snapshot copies only caller-visible rows from the ten logical
relations into a fresh `turso::core` `MemoryIO` database; hidden homes and
endpoints are redacted before that copy. Static aggregate preflights inside the
same snapshot admit at most 20,000 candidates and 16 MiB across all source
relations, reject any physical cell above 256 KiB before normalization, and
fetch blob bytes only after their attachment and bearer are visible. The
byte budget is a pre-fetch upper bound on encoded JSON: text and structural
bytes are charged at their worst-case escape expansion, while blob payloads
are charged at their base64 expansion plus JSON delimiters. The complete
projection independently fails atomically above the same row and byte
ceilings. The isolated database receives no source path and has attach, views,
and vacuum disabled.

Caller SQL then passes the exact `turso_parser =0.7.2` SELECT-only AST walker,
which rejects qualified/catalog/table-function/hidden-rowid access and unsafe
functions, casts, collations, or CTE collisions. Core preparation must compile
a read-only program. One absolute two-second control spans source extraction,
MemoryIO schema/load, and the caller VM; its progress callback observes both
deadline and caller cancellation, including after the async task drops its
blocking worker handle. Row, column, cell, and result limits apply separately.
The feature-gated qualification derives its report from bounded progress,
deadline, interrupt, query-only, parser, and recovery probes. The authoritative
CI suite also runs shared SQLite/Turso parity over all ten relations plus
missing, multiple, tombstoned, cyclic, and over-depth derived bearers, direct
and derived Units, redaction, blob expansion, escape-heavy input, cap, timeout,
and cancellation corpus, fingerprinting the authoritative database and
sidecars throughout.
