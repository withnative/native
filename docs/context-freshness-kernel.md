# Experimental context-freshness kernel

Status: implemented internal contract for the agent-speed freshness vertical
slice. This is not a public MCP API or compatibility commitment.

## Scope

Schema 28 introduced Unit, exact Unit revision, and Occurrence. Schema 29 adds
the internal receipt-driven runtime: exact dependency declaration,
task-relative assessment, atomic Receipt finalization, uncertainty lineage,
exact reconciliation, plural Unit supersession, and dependency auditing.
Background repair, public MCP tools, and production UI remain outside this
slice.

The backend-neutral value and operation contract lives in `src/freshness`.
The current adapter uses SQLite and the existing `content_events`
append-then-project transaction. The authoritative semantic event types are:

- `unit.created.v1`
- `unit.revision.recorded.v1`
- `occurrence.bound.v1`
- `receipt.committed.v1`
- `reconciliation.recorded.v1`
- `unit.superseded.v1`
- `receipt.dependency_audited.v1`

All semantic events require a nonblank immutable actor when folded. The
aggregate `receipt.committed.v1` event is additionally runtime-owned: public
`append` and `append_batch` reject it because source, comparison, uncertainty,
and authorization completeness must be derived by the trusted Receipt runtime,
not asserted by a caller. Other low-level semantic events still reject
unattributed authority before payload projection.

`unit.revision.recorded.v1` is the only authoritative byte source for a Unit
revision. Its content projects synchronously into the Unit envelope's current
record body. A generic `record.updated` carrying `body` is rejected after the
record becomes a Unit. Generic updates also cannot change the Unit envelope's
`type` or `kind`; the identity remains `Entity kind:semantic-unit`. Exact
revision references verify event id, global
sequence, subject, source slot, and SHA-256 together.

The `semantic-unit` kind is reserved at generic create/update boundaries. Only
the promotion kernel may mint that envelope, preventing a non-authoritative
lookalike from being silently hidden by generic discovery.

The following tables are rebuildable projections, not independent authority:

- `semantic_units`
- `unit_revisions`
- `unit_heads`
- `occurrences`
- `freshness_command_results`
- `freshness_runtime_command_results`
- `dependencies`
- `dependency_assessments`
- `receipts`
- `receipt_provenance`
- `receipt_comparisons`
- `receipt_uncertainty_lineage`
- `reconciliations`
- `unit_supersessions`
- `dependency_audits`

Generic links and read logs do not participate in correctness.

## Receipt boundary and freshness derivation

Context assembly is a read-only snapshot operation. It captures exact source
revision references, the content high-water, the observed authorization
revision, current-revision dependency comparisons, and inherited uncertainty.
Reading context never declares a dependency.

A durable output is one write transaction. It reauthorizes the consumer and
every nested source reference, verifies the sealed high-water and expected
consumer revision, then appends one aggregate `receipt.committed.v1` event.
That event contains the output body plus its dependency, assessment,
reconciliation, provenance, and uncertainty evidence; its projector validates
and exposes the package atomically. Any error rolls back the event, all
projections, and the idempotency result together.

Receipt execution and disclosure are derived from its sealed policy and
assessments; they are not trusted assertions. A hard-stop category can stop an
otherwise immaterial assessment without rewriting its materiality verdict.
Ordinary material or uncertain changes continue by default and surface only
when the task-relative assessment says they could materially change the answer
or action.

Workspace impact lists consider dependencies on the consumer's exact current
body revision. Historical Receipt explanation remains receipt-scoped, so a new
output does not erase the evidence behind an old one. Exact reconciliation
clears only a matching dependency, pinned source, selected source, task scope,
and affected conclusion when all evidence agrees on a supported outcome.
Conflicting or uncertain evidence leaves the candidate unresolved, and a later
source revision opens a new tuple.

Uncertainty is inherited when a downstream assembly selects the uncertain
Receipt's exact output. Its consumer, pinned, and selected references are each
reauthorized independently. It can be cleared only by supported exact
reconciliation; a new revision or different tuple propagates again.

Unit supersession is plural. Resolution traverses only authorized successors,
is bounded, preserves ambiguous terminal sets, and expands terminal Units to
their exact heads at the read high-water. Hidden branches therefore do not
alter visible grouping or counts, and later terminal revisions reopen impact.

Dependency audits can confirm or challenge declared dependencies and can also
record an observed omitted/underdeclared dependency without laundering it into
the original Receipt.

## Record envelope and containment departure

The candidate contract described promotion as placing a Unit below its source
artefact. The existing spine deliberately permits `home_id` to target only a
live, unarchived, enduring `Collection kind:folder`. This implementation keeps
that global invariant: a promoted Unit envelope is placed in the source
artefact's containing folder, while `unit.created.v1` fixes the source artefact
as `authority_bearer_record_id`.

Effective Unit access is the minimum current capability across the Unit
envelope and its fixed authority-bearer closure. Promotion snapshots the
source's explicit policy boundary onto the new envelope so its creator can use
it immediately; subsequent policy changes remain independent and access always
requires every boundary. Occurrence access further intersects the artefact.
Generic browse, structured-query, SQL, and search visibility excludes semantic
Unit envelopes. Generic lexical/SQL discovery also fails closed for derived
artefacts whose resolved authorization subject is a Unit. Direct identity reads
and the freshness API remain addressable through composite authorization.

The hidden predicate recognizes both projected semantic membership and the
reserved `Entity kind:semantic-unit` envelope. Consequently, a historical
replay pinned between the promotion command's `record.created` and
`unit.created.v1` events still keeps the provisional envelope subordinate.
Trusted-local compatibility callers may bypass grants, but not malformed,
dead, cyclic, or over-depth bearer shapes.

This is a candidate-design departure, not an accidental weakening of either
containment or authorization. Revisit it if users need spatial nesting beneath
arbitrary artefacts or independently republished Unit audiences.

## Exact revision encoding

An artefact body revision hashes the exact UTF-8 bytes carried by a
body-bearing `record.created`, `record.updated`, or aggregate
`receipt.committed.v1` event. Generic history and realtime expose the latter as
one sanitized `record.updated` envelope; nested Receipt evidence is not exposed.
A Unit revision hashes
a versioned, length-delimited representation containing:

1. the `native.unit-content` domain prefix;
2. encoding version;
3. content media type;
4. exact content bytes.

Changing content metadata therefore changes the revision digest even when the
visible text is identical.

## Concurrency, branching, and idempotency

`revise_unit` compares its exact expected revision with the one current head
inside the write transaction. A conflict appends nothing. The storage shape has
no one-child or unique-successor constraint: the projector can represent
multiple children and multiple heads when a later explicit branch operation is
introduced.

Successful command events carry the authorization-subject scope, idempotency
key, canonical intent digest, and observed authorization revision. Keys are
unique only inside that subject's namespace, so unrelated records and
principals cannot collide globally. Every command authorizes its subject and
canonicalizes its capture input before consulting that namespace; denied
callers therefore cannot use retries as an occupancy oracle. The command-result
projection makes an identical, currently authorized retry return the original
result; a retry never treats the originally observed authorization revision as
a durable grant. Reuse with different intent on the same subject conflicts
before any append.

## Occurrence resolution

An Occurrence permanently stores exact Unit and artefact revision references,
its canonical captured selectors, role, actor, and event time. Capture and
projection reuse the citation integrity contract: text quotes must resolve
uniquely, data positions pin a digest of the selected bytes, and RFC 7111
fragments require a paired data-position digest. Exact duplicate semantic
bindings are rejected, while a different role, anchor, or exact revision is a
distinct occurrence. Resolution reuses the citation selector semantics:

- `current`: current artefact bytes still have the pinned digest;
- `relocated`: historical evidence occurs once and selectors agree;
- `conflict`: evidence is ambiguous or selectors disagree;
- `stale`: the historical evidence verifies but has disappeared;
- `unavailable`: an exact historical or current representation cannot be
  recovered or accessed.

Resolution never mutates the binding and never widens a broken anchor to the
whole artefact.

Generic history suppresses an `occurrence.bound.v1` event unless the caller can
also view its artefact. Suppression occurs before pagination and aggregation,
so selectors, event existence, page occupancy, and grouped counts do not leak.
Occurrence binding also does not advance the Unit envelope's
`last_activity_at`, and realtime invalidations independently require artefact
visibility. A private expression therefore cannot perturb caller-visible Unit
activity metadata.
History high-water content and authorization coordinates are read in one SQLite
snapshot.

## Migration and replay

The forward-only 27→28 migration installs the semantic-kernel projections and
28→29 installs the empty receipt-runtime projections. The 27→28
preflight fails with the colliding record ids if a v27 database already
contains `Entity kind:semantic-unit`; operators must rename those legacy kinds
before retrying. Existing records are never inferred to be Units from `kind`;
only `unit.created.v1` establishes semantic membership. Fresh installs use the
same schema.

All semantic-kernel and receipt-runtime projection tables participate in
content rebuild-and-diff. Deleting their rows and replaying `content_events`
reconstructs Unit identity, exact revisions, heads, immutable Occurrences,
dependency and assessment evidence, Receipts, uncertainty lineage,
reconciliations, plural supersession, audit evidence, command idempotency
results, and projected Unit bodies.
