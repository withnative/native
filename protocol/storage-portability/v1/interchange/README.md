# Canonical interchange v1

Canonical interchange v1 is the backend-neutral, logical migration boundary
for Native storage. It is deliberately not a SQLite backup: durable event logs
and logical projections are represented as ordered table sections whose values
carry explicit SQLite storage-class tags. Backend-specific indexes, FTS shadow
tables, caches, jobs, authorization revision counters, and the engine-owned
binding-system registry are excluded.

The public SQLite implementation exports and imports one compact UTF-8 JSON
document matching `bundle.schema.json`. `manifest.schema.json` and
`section.schema.json` ratify the independently reusable manifest and section
contracts.

## Canonical rules

- The manifest format is `native.canonical-interchange.v1`, revision `2`, and
  the section format is `native.canonical-interchange.section.v1`, revision
  `2`. Revision 1 engine-45 inputs remain readable: import classifies every
  legacy content event as `legacy_unknown`, records the engine-45 cutover, and
  never fabricates frontier edges.
- The logical contract is `native.logical.v1`. Implementations reject unknown
  revisions, fields, sections, or column layouts before publishing any data.
- Sections use the contract inventory order. Rows are strictly increasing by
  the declared primary-key tuple under SQLite's default ordering: tuple parts
  are compared left-to-right; storage classes sort NULL, numeric, TEXT, then
  BLOB; INTEGER and REAL share an exact numeric comparison domain; TEXT uses
  UTF-8 BINARY collation; and BLOB uses unsigned byte order. Columns use
  engine-schema order. Importers reject reordered rows even when their section
  and content digests have been recomputed.
- JSON is UTF-8, compact, and emitted from the schemas' property order.
- Integers are signed 64-bit JSON integers. Finite REAL values are their exact
  IEEE-754 bits as 16 lowercase hexadecimal digits. BLOBs are standard padded
  base64. NULL and TEXT have explicit tags.
- Each section digest is SHA-256 over that section's compact canonical JSON.
  `content_sha256` is SHA-256 over the compact canonical JSON section array.
- Exports containing profile-specific embeddings or external blob references
  are rejected because those values are not self-contained logical data.

## Import safety

An importer validates the entire document and its integrity before creating a
staging database. It applies all sections in one transaction with deferred
foreign keys, runs full Native conformance (including authoritative-log rebuild
and projection diff), closes and checkpoints the staged database, and only
then atomically publishes the file at a previously absent destination. Failure
leaves the source open and the destination absent.

Generated columns are not carried in a section; the destination engine derives
them. Import into an existing destination is intentionally unsupported.

The Postgres server profile currently implements a bounded proof, not the full
contract: it validates the whole document, replays supported content events,
and verifies an explicit field-level projection across `content_events`,
`records`, and `facet_values`, plus the rebuilt event cursor. Its structured
report names the exact verified fields, every non-empty section it did not
materialize, and all normalization; unsupported event types fail closed.
Consumers must not interpret that partial result as whole-section verification
or a lossless full-database migration.

## Section inventory

Revision 2 contains exactly these sections, in this order:

```text
content_events
content_event_causal_frontier
content_event_causal_cutover
policy_events
meta_events
control_events
awareness_events
notification_candidate_events
relationship_events
relationship_foreign_action_attestations
relationship_foreign_action_outputs
relationship_federation_events
relationship_federation_quarantine
content_event_sources
replicated_message_provenance
destination_message_ingest
replicated_message_references
provenance_interaction_receipts
provenance_action_attestations
provenance_action_events
provenance_attestation_validity_events
provenance_action_outputs
webhook_endpoints
webhook_credentials
webhook_deliveries
records
record_policies
policy_entries
links
relationships
relationship_endpoints
relationship_legacy_links
relationship_assertion_heads
relationship_endpoint_activity
message_audience_state
message_audiences
message_origin_state
message_origin_principals
message_conversations
awareness_command_intents
human_message_awareness
agent_message_dispositions
awareness_event_evidence
message_inbox_routing
message_preferences
member_destinations
message_mentions
notification_candidates
module_releases
module_release_imports
artifact_source_attestations
artifact_inputs
artifact_module_grants
annotation_targets
attribution_targets
attribution_assertions
attribution_evidence
attribution_retractions
facet_values
facet_observations
semantic_units
unit_revisions
unit_heads
occurrences
freshness_command_results
freshness_runtime_command_results
receipts
receipt_provenance
dependencies
dependency_assessments
receipt_comparisons
receipt_uncertainty_lineage
reconciliations
unit_supersessions
dependency_audits
canvas_objects
canvas_batches
bindings
binding_audit
external_observations
database_identity
database_identity_audit
blobs
vocabularies
vocabulary_values
schema_config
read_log_calls
read_log_touches
member_contexts
instruction_bindings
onboarding_programmes
onboarding_programme_sources
member_obligations
member_obligation_progress
seeded_instruction_sources
control_event_applications
storage_portability_policy
```
