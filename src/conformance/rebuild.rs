//! Rebuild-and-diff — the first-class conformance check the event-authoritative
//! model makes possible (Fork A). Replay a whole log from seq 0 through its
//! projector into a FRESH database, then assert row equality with the live
//! projection tables. Drift between a log and its projections is therefore a
//! failing test, not a silent corruption.
//!
//! SIX checks, one per event-sourced tier:
//!   - [`rebuild_and_diff`] — `content_events` -> `records`, `links`,
//!     facets, annotation targets, Message audience and Conversation indexes
//!   - [`rebuild_and_diff_meta`] — `meta_events` -> `vocabularies`,
//!     `vocabulary_values`, `schema_config`
//!   - [`rebuild_and_diff_policy`] — `policy_events` -> `record_policies`,
//!     `policy_entries`
//!   - [`rebuild_and_diff_relationship`] — `relationship_events` -> portable
//!     relationship heads, receiver-local admission/effect and `rel:` links
//!   - [`rebuild_and_diff_control`] — `control_events` -> portable
//!     instruction/onboarding control projections
//!   - [`rebuild_and_diff_derivation`] — `derivation_events` -> stable series,
//!     immutable revisions and manifests, failed attempts, and application markers
//!
//! They are deliberately separate runs over separate logs rather than one
//! combined pass. The tiers' logs never mix (see `crate::projector`), so a
//! combined check could only be a coincidence of two independent folds — and
//! keeping them apart is what lets the content rebuild stay pure: its fresh
//! database has an EMPTY meta tier, which is correct, because content replay
//! must not depend on schema state.
//!
//! In both, the event snapshot and the live projection dumps are read inside ONE
//! read transaction, so a concurrent write that lands between the two reads
//! cannot masquerade as drift (it is simply outside the snapshot, on both sides).
//!
//! What is still NOT compared: engine-internal surfaces (rowids, the FTS5 shadow
//! tables) and the genuinely direct-write tables — `blobs` (content-addressed),
//! `jobs` (transient), governed `bindings` plus their audit/observations,
//! protected database identity. Policy has its own check and never participates
//! in content replay. The derived `records.policy_anchor_id` is likewise
//! excluded from both projection comparisons.

use sqlx::{Row, SqliteConnection};

use crate::control::{read_all_control_events, replay_control};
use crate::db::{apply_schema, open_database, Db};
use crate::derivation::{read_all_derivation_events, replay_derivations};
use crate::error::Result;
use crate::events::EventRow;
use crate::meta::{read_all_meta_events, SchemaConfigSetPayload};
use crate::policy::{read_all_policy_events, replay_policy};
use crate::projector::meta::replay_meta;
use crate::projector::replay_with_blob_seeds;
use crate::schema::{
    CONTROL_PROJECTION_TABLES, DERIVATION_PROJECTION_TABLES, META_PROJECTION_TABLES,
    POLICY_PROJECTION_TABLES, PROJECTION_TABLES,
};

const RELATIONSHIP_REBUILD_TABLES: [&str; 8] = [
    "relationships",
    "relationship_endpoints",
    "relationship_legacy_links",
    "relationship_assertion_heads",
    "relationship_endpoint_activity",
    "relationship_local_admissions",
    "effective_relationships",
    "links",
];

/// Explicit column lists keep the comparison stable regardless of engine column
/// ordering, and exclude rowid.
fn columns_for(table: &str) -> &'static [&'static str] {
    match table {
        "records" => &[
            "id",
            "type",
            "kind",
            "name",
            "body",
            "home_id",
            "lifecycle",
            "owner_id",
            "claimed_by_account",
            "claimed_run_key",
            "claimed_at",
            // policy_anchor_id is a derived authorization index whose authored
            // replacement boundaries are not content-log projections.
            "persistence",
            "maturity",
            "summary",
            "last_activity_at",
            "created_at",
            "updated_at",
            "deleted_at",
        ],
        "links" => &[
            "id",
            "source_id",
            "target_id",
            "relationship",
            "note",
            "created_at",
        ],
        "facet_values" => &["id", "record_id", "key", "value", "vocab_ref", "created_at"],
        "facet_observations" => &[
            "id",
            "record_id",
            "key",
            "value",
            "op",
            "vocab_ref",
            "as_of",
            "observed_at",
            "event_seq",
        ],
        "annotation_targets" => &[
            "annotation_id",
            "target_record_id",
            "source_slot",
            "source_event_seq",
            "blob_id",
            "source_sha256",
            "selectors",
            "purpose",
            "created_at",
            "updated_at",
        ],
        "attribution_targets" => &[
            "annotation_id",
            "target_record_id",
            "target_scope",
            "source_event_id",
            "source_body_sha256",
            "selectors",
            "bound_event_id",
            "bound_event_seq",
            "bound_at",
        ],
        "attribution_assertions" => &[
            "annotation_id",
            "contract_version",
            "claimant_principal",
            "claim_mode",
            "relation",
            "polarity",
            "attributed_subject_kind",
            "attributed_subject_ref",
            "asserted_at",
            "stance_as_of",
            "confidence",
            "transformation",
            "rationale",
            "asserted_event_id",
            "asserted_event_seq",
        ],
        "attribution_evidence" => &[
            "evidence_id",
            "annotation_id",
            "role",
            "action_attestation_id",
            "added_event_id",
            "event_seq",
            "added_at",
            "added_by",
        ],
        "attribution_retractions" => &[
            "retraction_id",
            "annotation_id",
            "reason",
            "retracted_event_id",
            "retracted_event_seq",
            "retracted_at",
            "retracted_by",
        ],
        "message_audience_state" => &[
            "message_id",
            "status",
            "declaration_event_seq",
            "updated_at",
        ],
        "message_audiences" => &[
            "message_id",
            "principal_id",
            "source",
            "grant_id",
            "event_seq",
            "created_at",
        ],
        "message_origin_state" => &[
            "message_id",
            "status",
            "origin_type",
            "collection_id",
            "direct_set_digest",
            "participant_count",
            "declaration_event_seq",
            "updated_at",
        ],
        "message_origin_principals" => &["message_id", "principal_id", "event_seq", "created_at"],
        "message_conversations" => &[
            "message_id",
            "conversation_id",
            "event_seq",
            "classified_at",
        ],
        "message_mentions" => &[
            "message_id",
            "mention_id",
            "target_kind",
            "target_binding",
            "target_record_id",
            "span_start",
            "span_end",
            "authored_label",
            "source_event_seq",
            "effective",
        ],
        "module_releases" => &[
            "publication_event_id",
            "module_record_id",
            "source_event_id",
            "source_sha256",
            "release_sha256",
            "dependency_closure_sha256",
            "descriptor",
            "status",
            "replacement",
            "local_event_seq",
            "status_event_seq",
            "published_at",
        ],
        "module_release_imports" => &[
            "consumer_publication_event_id",
            "ordinal",
            "specifier",
            "dependency_module_record_id",
            "dependency_publication_event_id",
            "dependency_source_sha256",
            "names",
            "source_range",
            "input_map",
        ],
        "recipe_releases" => &[
            "publication_event_id",
            "program_id",
            "source_event_id",
            "source_sha256",
            "descriptor_sha256",
            "descriptor",
            "status",
            "local_event_seq",
            "status_event_seq",
            "published_at",
        ],
        "recipe_release_input_classes" => &["publication_event_id", "ordinal", "input_class"],
        "artifact_source_attestations" => &[
            "attestation_event_id",
            "artifact_id",
            "source_event_id",
            "source_sha256",
            "descriptor",
            "attestation_sha256",
            "event_seq",
            "created_at",
        ],
        "artifact_inputs" => &[
            "artifact_id",
            "port_name",
            "collection_id",
            "artifact_source_attestation_event_id",
            "artifact_source_event_id",
            "artifact_source_sha256",
            "event_seq",
        ],
        "artifact_module_grants" => &[
            "artifact_id",
            "subject_kind",
            "subject_record_id",
            "subject_event_id",
            "source_sha256",
            "artifact_source_attestation_event_id",
            "artifact_source_event_id",
            "artifact_source_sha256",
            "capability",
            "scope_sha256",
            "scope",
            "event_seq",
        ],
        "semantic_units" => &[
            "unit_id",
            "authority_bearer_record_id",
            "creation_event_id",
            "creation_event_seq",
            "label",
            "created_at",
        ],
        "unit_revisions" => &[
            "revision_event_id",
            "unit_id",
            "revision_seq",
            "based_on_revision_event_id",
            "content_sha256",
            "content_media_type",
            "encoding_version",
            "rationale",
            "actor",
            "created_at",
        ],
        "unit_heads" => &["unit_id", "revision_event_id"],
        "occurrences" => &[
            "occurrence_id",
            "binding_event_id",
            "binding_event_seq",
            "unit_id",
            "unit_revision_event_id",
            "artefact_id",
            "artefact_revision_event_id",
            "artefact_revision_seq",
            "artefact_sha256",
            "selectors",
            "selectors_sha256",
            "expression_role",
            "actor",
            "created_at",
        ],
        "freshness_command_results" => &[
            "scope_record_id",
            "idempotency_key",
            "operation",
            "intent_sha256",
            "result_event_id",
            "event_seq",
            "authorization_revision_observed",
            "created_at",
        ],
        "freshness_runtime_command_results" => &[
            "scope_record_id",
            "idempotency_key",
            "operation",
            "intent_sha256",
            "result_event_id",
            "event_seq",
            "authorization_revision_observed",
            "created_at",
        ],
        "dependencies" => &[
            "dependency_id",
            "receipt_id",
            "declaration_event_id",
            "declaration_event_seq",
            "consumer_record_id",
            "consumer_revision_event_id",
            "consumer_revision",
            "source_record_id",
            "source_revision_event_id",
            "source_revision",
            "semantic_role",
            "affected_conclusion",
            "rationale",
            "reconsideration_trigger",
            "confidence",
            "actor",
            "created_at",
        ],
        "dependency_assessments" => &[
            "assessment_id",
            "assessment_event_id",
            "assessment_event_seq",
            "receipt_id",
            "dependency_id",
            "compared_source_revision_event_id",
            "compared_source_revision",
            "task_scope",
            "category",
            "outcome",
            "could_materially_change",
            "rationale",
            "actor",
            "created_at",
        ],
        "receipts" => &[
            "receipt_id",
            "receipt_event_id",
            "receipt_event_seq",
            "consumer_record_id",
            "output_revision_event_id",
            "output_revision",
            "context_request",
            "resolution_policy",
            "requested_source_record_ids",
            "selected_sources",
            "history_high_water",
            "withheld_context",
            "execution",
            "disclosure",
            "actor",
            "created_at",
        ],
        "receipt_provenance" => &[
            "receipt_id",
            "ordinal",
            "source_record_id",
            "source_revision_event_id",
            "source_revision",
            "reason",
        ],
        "receipt_comparisons" => &[
            "receipt_id",
            "ordinal",
            "dependency_id",
            "pinned_source_revision_event_id",
            "pinned_source_revision",
            "selected_source_revision_event_id",
            "selected_source_revision",
        ],
        "receipt_uncertainty_lineage" => &[
            "receipt_id",
            "ordinal",
            "uncertainty_id",
            "dependency_id",
            "inherited_from_receipt_id",
            "lineage",
            "detail",
        ],
        "reconciliations" => &[
            "reconciliation_id",
            "reconciliation_event_id",
            "reconciliation_event_seq",
            "resolving_receipt_id",
            "resolving_output_revision_event_id",
            "dependency_id",
            "consumer_revision_event_id",
            "pinned_source_revision_event_id",
            "assessed_source_revision_event_id",
            "assessed_source_revision",
            "task_scope",
            "affected_conclusion",
            "outcome",
            "rationale",
            "actor",
            "created_at",
        ],
        "unit_supersessions" => &[
            "supersession_event_id",
            "supersession_event_seq",
            "predecessor_unit_id",
            "ordinal",
            "successor_unit_id",
            "successor_revision_event_id",
            "successor_revision",
            "rationale",
            "actor",
            "created_at",
        ],
        "dependency_audits" => &[
            "audit_event_id",
            "audit_event_seq",
            "receipt_id",
            "declared_dependency_id",
            "observed_dependency",
            "outcome",
            "rationale",
            "actor",
            "created_at",
        ],
        "vocabularies" => &["id", "name", "created_at"],
        "vocabulary_values" => &[
            "id",
            "vocabulary_id",
            "value",
            "gloss",
            "status",
            "ordinal",
            "terminality",
            "metadata",
            "alias_of",
        ],
        "schema_config" => &[
            "id",
            "layer",
            "name",
            "data",
            "applies_to_collection_id",
            "version_lineage",
            "created_at",
        ],
        "record_policies" => &["record_id", "created_at"],
        "policy_entries" => &[
            "policy_anchor_id",
            "subject_kind",
            "subject_id",
            "effect",
            "capability",
        ],
        "agent_runs" => &[
            "activity_id",
            "run_key",
            "account_id",
            "started_at",
            "ended_at",
            "start_event_id",
            "start_event_seq",
            "close_event_id",
            "close_event_seq",
        ],
        "member_contexts" => &[
            "account_id",
            "person_record_id",
            "root_record_id",
            "created_at",
        ],
        "instruction_bindings" => &[
            "id",
            "scope_kind",
            "scope_id",
            "source_record_id",
            "position",
            "enabled",
            "created_by",
            "created_at",
            "updated_at",
        ],
        "onboarding_programmes" => &[
            "id",
            "trigger_key",
            "generation",
            "position",
            "enabled",
            "created_by",
            "legacy_baseline_before",
            "created_at",
            "updated_at",
        ],
        "onboarding_programme_sources" => &[
            "programme_id",
            "source_record_id",
            "source_role",
            "position",
        ],
        "member_obligations" => &[
            "account_id",
            "programme_id",
            "generation",
            "state",
            "created_at",
            "updated_at",
            "updated_by",
            "updated_run_key",
            "reason",
        ],
        "member_obligation_progress" => &[
            "account_id",
            "programme_id",
            "generation",
            "phase",
            "evidence",
            "resume_after",
            "artifact_id",
            "selected_route_id",
            "updated_at",
            "updated_by",
            "updated_run_key",
            "reason",
        ],
        "seeded_instruction_sources" => &[
            "source_record_id",
            "template_key",
            "template_version",
            "last_applied_digest",
            "last_applied_at",
        ],
        "control_event_applications" => &["event_id", "event_seq", "applied_at"],
        "derivation_series" => &[
            "id",
            "series_key",
            "definition",
            "definition_sha256",
            "created_event_id",
            "created_event_seq",
            "created_at",
        ],
        "derivation_revisions" => &[
            "id",
            "series_id",
            "predecessor_revision_id",
            "definition_sha256",
            "canonical_request",
            "canonical_request_sha256",
            "request_identity_sha256",
            "recipe_revision",
            "recipe_revision_ref_sha256",
            "effective_source_boundary",
            "effective_source_boundary_sha256",
            "input_manifest",
            "input_manifest_sha256",
            "output_ref",
            "output_ref_sha256",
            "completion_metadata",
            "completion_metadata_sha256",
            "completed_event_id",
            "completed_event_seq",
            "completed_at",
        ],
        "derivation_revision_inputs" => &[
            "revision_id",
            "ordinal",
            "input_role",
            "input_kind",
            "portable_id",
            "sha256",
            "metadata",
        ],
        "derivation_attempts" => &[
            "id",
            "series_id",
            "canonical_request",
            "canonical_request_sha256",
            "recipe_revision",
            "recipe_revision_ref_sha256",
            "effective_source_boundary",
            "effective_source_boundary_sha256",
            "request_identity_sha256",
            "coordination_request_key_sha256",
            "attempt_ordinal",
            "retryable",
            "executor_descriptor",
            "executor_descriptor_sha256",
            "failure_code",
            "failure_metadata",
            "failure_metadata_sha256",
            "failed_event_id",
            "failed_event_seq",
            "failed_at",
        ],
        "derivation_target_bindings" => &[
            "binding_id",
            "series_id",
            "target_kind",
            "target_record_id",
            "target_slot",
            "generation",
            "bound_event_id",
            "bound_event_seq",
            "bound_at",
            "detached_event_id",
            "detached_event_seq",
            "detached_at",
        ],
        "derivation_target_publications" => &[
            "publication_id",
            "binding_id",
            "generation",
            "target_version",
            "revision_id",
            "output_event_id",
            "output_sha256",
            "published_event_id",
            "published_event_seq",
            "published_at",
        ],
        "derivation_selected_publications" => &[
            "target_kind",
            "target_record_id",
            "target_slot",
            "publication_id",
            "binding_id",
            "generation",
            "target_version",
            "revision_id",
            "output_event_id",
            "output_sha256",
            "selected_at",
        ],
        "derivation_target_heads" => &[
            "target_kind",
            "target_record_id",
            "target_slot",
            "generation",
            "target_version",
            "active_binding_id",
            "selected_publication_id",
        ],
        "derivation_event_applications" => &["event_id", "event_seq", "applied_at"],
        "derivation_artifact_role_assignments" => &[
            "assignment_id",
            "target_kind",
            "target_record_id",
            "target_slot",
            "role",
            "assigned_event_id",
            "assigned_event_seq",
            "assigned_at",
        ],
        "derivation_artifact_role_retirements" => &[
            "retirement_id",
            "assignment_id",
            "retired_event_id",
            "retired_event_seq",
            "retired_at",
        ],
        "derivation_artifact_role_heads" => &[
            "target_kind",
            "target_record_id",
            "target_slot",
            "role",
            "active_assignment_id",
            "head_event_id",
            "head_event_seq",
        ],
        "derivation_revision_confirmations" => &[
            "confirmation_id",
            "assignment_id",
            "series_id",
            "revision_id",
            "publication_id",
            "binding_id",
            "generation",
            "target_version",
            "input_manifest_sha256",
            "output_sha256",
            "predecessor_head_event_id",
            "confirmed_event_id",
            "confirmed_event_seq",
            "confirmed_at",
            "confirmed_by",
        ],
        "derivation_confirmation_retractions" => &[
            "retraction_id",
            "confirmation_id",
            "retracted_event_id",
            "retracted_event_seq",
            "retracted_at",
            "retracted_by",
        ],
        "derivation_confirmation_heads" => &[
            "assignment_id",
            "confirmation_id",
            "head_event_id",
            "head_event_seq",
        ],
        "canvas_objects" => &[
            "canvas_id",
            "object_id",
            "kind",
            "x",
            "y",
            "w",
            "h",
            "z",
            "parent_id",
            "props",
            "deleted",
            "geometry_seq",
            "content_seq",
            "created_seq",
        ],
        "canvas_batches" => &[
            "canvas_id",
            "batch_id",
            "actor",
            "event_id",
            "event_seq",
            "ops_sha256",
            "origin_kind",
        ],
        other => unreachable!("not a projection table: {other}"),
    }
}

fn relationship_columns_for(table: &str) -> &'static [&'static str] {
    match table {
        "relationships" => &[
            "relationship_origin_db_id",
            "relationship_id",
            "relationship_revision",
            "relationship_type",
            "type_definition_id",
            "canonical_proposition_key",
            "endpoint_semantics",
            "identity_qualifiers",
            "reducer_id",
            "reducer_version",
            "stream_version",
            "status",
            "successor_origin_db_id",
            "successor_relationship_id",
            "created_event_issuer_origin_db_id",
            "created_event_id",
            "last_event_issuer_origin_db_id",
            "last_event_id",
            "occurred_at",
        ],
        "relationship_endpoints" => &[
            "relationship_origin_db_id",
            "relationship_id",
            "ordinal",
            "role",
            "portable_ref",
            "record_type",
            "record_kind",
            "record_id",
        ],
        "relationship_legacy_links" => &[
            "relationship_origin_db_id",
            "relationship_id",
            "relationship_token",
            "note",
            "created_at",
            "source_facts",
        ],
        "relationship_assertion_heads" => &[
            "issuer_origin_db_id",
            "assertion_id",
            "relationship_origin_db_id",
            "relationship_id",
            "relationship_revision",
            "relationship_created_event_issuer_origin_db_id",
            "relationship_created_event_id",
            "stream_version",
            "stance",
            "semantic_claimant",
            "on_behalf_of",
            "rationale",
            "valid_from",
            "valid_until",
            "causal_parents",
            "origin_admission",
            "authoring_action_attestation_id",
            "state",
            "created_event_issuer_origin_db_id",
            "created_event_id",
            "last_event_issuer_origin_db_id",
            "last_event_id",
            "occurred_at",
        ],
        "relationship_endpoint_activity" => &[
            "relationship_origin_db_id",
            "relationship_id",
            "event_issuer_origin_db_id",
            "event_id",
            "endpoint_ordinal",
            "endpoint_role",
            "portable_ref",
            "record_id",
            "event_type",
            "occurred_at",
        ],
        "relationship_local_admissions" => &[
            "issuer_origin_db_id",
            "assertion_id",
            "local_admission_state",
            "local_admission_class",
            "type_definition_id",
            "local_policy_version",
            "local_reason",
            "local_evidence_digest",
            // `recomputed_at` is deliberately excluded: this table is
            // receiver-local and absent from canonical interchange, and the
            // timestamp records when the receiver last refreshed the admission
            // (derived from the assertion head at refresh time) rather than
            // portable deterministic state. Later assertion events advance the
            // head without refreshing the admission, so live projection and
            // full replay legitimately disagree on it while every semantic
            // admission field matches.
        ],
        "effective_relationships" => &[
            "relationship_origin_db_id",
            "relationship_id",
            "effective_state",
            "epistemic_state",
            "support_count",
            "contest_count",
            "admission_counts",
            "reducer_id",
            "reducer_version",
            "assertion_set_digest",
            "knowledge_watermark",
            "recomputed_at",
        ],
        "links" => columns_for("links"),
        other => unreachable!("not a relationship projection table: {other}"),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TableDiff {
    pub table: String,
    pub live: usize,
    pub rebuilt: usize,
    pub mismatches: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RebuildDiffResult {
    pub equal: bool,
    pub tables: Vec<TableDiff>,
    pub event_count: usize,
}

async fn read_all_events(conn: &mut SqliteConnection) -> Result<Vec<EventRow>> {
    let rows = sqlx::query(
        "SELECT seq, id, record_id, type, payload, actor,
                run_key, parent_key, intent, created_at,
                causal_envelope_version, causal_status
           FROM content_events ORDER BY seq",
    )
    .fetch_all(&mut *conn)
    .await?;
    // try_get, not get: these values are database-controlled, and the suite's
    // contract is a report + exit code, never a crash — a malformed log (e.g. a
    // TEXT `seq`) must surface as a reportable error, not a decode panic.
    let mut events = Vec::with_capacity(rows.len());
    for r in rows {
        let version: i64 = r.try_get("causal_envelope_version")?;
        if version != 1 {
            return Err(crate::Error::engine(
                "unsupported stored causal envelope version",
            ));
        }
        let event_id: String = r.try_get("id")?;
        let frontier = crate::events::CausalFrontierV1::new(
            sqlx::query_scalar::<_, String>(
                "SELECT parent_event_id FROM content_event_causal_frontier
                  WHERE event_id=? ORDER BY parent_event_id",
            )
            .bind(&event_id)
            .fetch_all(&mut *conn)
            .await?,
        )?;
        let causal_envelope = match r.try_get::<String, _>("causal_status")?.as_str() {
            "complete" => crate::events::CausalEnvelopeV1::complete(frontier),
            "import_incomplete" => crate::events::CausalEnvelopeV1::import_incomplete(frontier),
            "legacy_unknown" if frontier.is_empty() => {
                crate::events::CausalEnvelopeV1::legacy_unknown()
            }
            _ => return Err(crate::Error::engine("invalid stored causal envelope")),
        };
        events.push(EventRow {
            local_seq: r.try_get("seq")?,
            id: event_id,
            record_id: r.try_get("record_id")?,
            event_type: r.try_get("type")?,
            payload: r.try_get("payload")?,
            actor: r.try_get("actor")?,
            run_key: r.try_get("run_key")?,
            parent_key: r.try_get("parent_key")?,
            intent: r.try_get("intent")?,
            created_at: r.try_get("created_at")?,
            causal_envelope,
        });
    }
    Ok(events)
}

async fn dump_table(
    conn: &mut SqliteConnection,
    table: &str,
    columns: &[&str],
) -> Result<Vec<String>> {
    let predicate = if table == "links" {
        "id NOT LIKE 'rel:%'"
    } else {
        "1"
    };
    dump_table_where(conn, table, columns, predicate).await
}

async fn dump_relationship_table(
    conn: &mut SqliteConnection,
    table: &str,
    columns: &[&str],
) -> Result<Vec<String>> {
    let predicate = if table == "links" {
        "id LIKE 'rel:%'"
    } else {
        "1"
    };
    dump_table_where(conn, table, columns, predicate).await
}

async fn dump_table_where(
    conn: &mut SqliteConnection,
    table: &str,
    columns: &[&str],
    predicate: &str,
) -> Result<Vec<String>> {
    let order_column = match table {
        "annotation_targets" => "annotation_id",
        "attribution_targets" => "annotation_id",
        "attribution_assertions" => "annotation_id",
        "attribution_evidence" => "evidence_id",
        "attribution_retractions" => "retraction_id",
        "message_audience_state" => "message_id",
        "message_audiences" => "message_id, principal_id, source, grant_id",
        "message_origin_state" => "message_id",
        "message_origin_principals" => "message_id, principal_id",
        "message_conversations" => "message_id, conversation_id",
        "message_mentions" => "message_id, mention_id",
        "record_policies" => "record_id",
        "policy_entries" => "policy_anchor_id, subject_kind, subject_id, effect, capability",
        "agent_runs" => "activity_id",
        "member_contexts" => "account_id",
        "onboarding_programme_sources" => "programme_id, position, source_record_id",
        "member_obligations" => "account_id, programme_id, generation",
        "member_obligation_progress" => "account_id, programme_id, generation",
        "seeded_instruction_sources" => "source_record_id",
        "control_event_applications" => "event_seq",
        "derivation_revision_inputs" => "revision_id, ordinal",
        "derivation_target_bindings" => "target_kind, target_record_id, target_slot, generation",
        "derivation_target_publications" => "published_event_seq",
        "derivation_selected_publications" => "target_kind, target_record_id, target_slot",
        "derivation_target_heads" => "target_kind, target_record_id, target_slot",
        "derivation_event_applications" => "event_seq",
        "derivation_artifact_role_assignments" => "assigned_event_seq",
        "derivation_artifact_role_retirements" => "retired_event_seq",
        "derivation_artifact_role_heads" => "target_kind,target_record_id,target_slot,role",
        "derivation_revision_confirmations" => "confirmed_event_seq",
        "derivation_confirmation_retractions" => "retracted_event_seq",
        "derivation_confirmation_heads" => "assignment_id",
        "relationships" => "relationship_origin_db_id,relationship_id",
        "relationship_endpoints" => "relationship_origin_db_id,relationship_id,ordinal",
        "relationship_legacy_links" => "relationship_origin_db_id,relationship_id",
        "relationship_assertion_heads" => "issuer_origin_db_id,assertion_id",
        "relationship_endpoint_activity" => "relationship_origin_db_id,relationship_id,event_issuer_origin_db_id,event_id,endpoint_ordinal",
        "relationship_local_admissions" => "issuer_origin_db_id,assertion_id",
        "effective_relationships" => "relationship_origin_db_id,relationship_id",
        "module_releases" => "publication_event_id",
        "module_release_imports" => "consumer_publication_event_id, ordinal",
        "recipe_releases" => "publication_event_id",
        "recipe_release_input_classes" => "publication_event_id, ordinal",
        "artifact_source_attestations" => "attestation_event_id",
        "artifact_inputs" => "artifact_id, port_name",
        "artifact_module_grants" => "artifact_id, subject_kind, subject_record_id, subject_event_id, capability, scope_sha256",
        "semantic_units" => "unit_id",
        "unit_revisions" => "revision_event_id",
        "unit_heads" => "unit_id, revision_event_id",
        "occurrences" => "occurrence_id",
        "freshness_command_results" => "scope_record_id, idempotency_key",
        "freshness_runtime_command_results" => "scope_record_id, idempotency_key",
        "dependencies" => "dependency_id",
        "dependency_assessments" => "assessment_id",
        "receipts" => "receipt_id",
        "receipt_provenance" => "receipt_id, ordinal",
        "receipt_comparisons" => "receipt_id, ordinal",
        "receipt_uncertainty_lineage" => "receipt_id, ordinal",
        "reconciliations" => "reconciliation_id",
        "unit_supersessions" => "supersession_event_id, ordinal",
        "dependency_audits" => "audit_event_id",
        "canvas_objects" => "canvas_id, object_id",
        "canvas_batches" => "canvas_id, batch_id",
        _ => "id",
    };
    let rows = sqlx::query(&format!(
        "SELECT {} FROM {table} WHERE {predicate} ORDER BY {order_column}",
        columns.join(", "),
    ))
    .fetch_all(conn)
    .await?;
    // Canonical JSON per row — column order is fixed by `columns`, so this is a
    // stable, value-level fingerprint of each row.
    rows.into_iter()
        .map(|row| {
            // try_get for the same reason as read_all_events: cell values are
            // database-controlled and must report, not panic, on decode failure.
            let values: Vec<serde_json::Value> = columns
                .iter()
                .enumerate()
                .map(|(i, column)| {
                    if (matches!(
                        table,
                        "facet_observations"
                            | "message_audiences"
                            | "message_origin_principals"
                            | "message_conversations"
                    ) && *column == "event_seq")
                        || (table == "message_mentions"
                            && matches!(
                                *column,
                                "span_start" | "span_end" | "source_event_seq" | "effective"
                            ))
                        || (table == "module_releases"
                            && matches!(*column, "local_event_seq" | "status_event_seq"))
                        || (table == "module_release_imports" && *column == "ordinal")
                        || (table == "recipe_releases"
                            && matches!(*column, "local_event_seq" | "status_event_seq"))
                        || (table == "recipe_release_input_classes" && *column == "ordinal")
                        || (table == "artifact_source_attestations" && *column == "event_seq")
                        || (matches!(table, "artifact_inputs" | "artifact_module_grants")
                            && *column == "event_seq")
                        || (table == "semantic_units" && *column == "creation_event_seq")
                        || (table == "unit_revisions"
                            && matches!(*column, "revision_seq" | "encoding_version"))
                        || (table == "occurrences"
                            && matches!(*column, "binding_event_seq" | "artefact_revision_seq"))
                        || (table == "freshness_command_results"
                            && matches!(*column, "event_seq" | "authorization_revision_observed"))
                        || (table == "freshness_runtime_command_results"
                            && matches!(*column, "event_seq" | "authorization_revision_observed"))
                        || (table == "dependencies" && *column == "declaration_event_seq")
                        || (table == "dependency_assessments"
                            && matches!(
                                *column,
                                "assessment_event_seq" | "could_materially_change"
                            ))
                        || (table == "receipts"
                            && matches!(*column, "receipt_event_seq" | "withheld_context"))
                        || (matches!(
                            table,
                            "receipt_provenance"
                                | "receipt_comparisons"
                                | "receipt_uncertainty_lineage"
                        ) && *column == "ordinal")
                        || (table == "reconciliations" && *column == "reconciliation_event_seq")
                        || (table == "unit_supersessions"
                            && matches!(*column, "supersession_event_seq" | "ordinal"))
                        || (table == "dependency_audits" && *column == "audit_event_seq")
                        || (table == "canvas_objects"
                            && matches!(
                                *column,
                                "deleted" | "geometry_seq" | "content_seq" | "created_seq"
                            ))
                        || (table == "canvas_batches" && *column == "event_seq")
                        || matches!(
                            (table, *column),
                            ("attribution_targets", "bound_event_seq")
                                | ("attribution_assertions", "asserted_event_seq")
                                | ("attribution_evidence", "event_seq")
                                | ("attribution_retractions", "retracted_event_seq")
                                | (
                                    "relationships",
                                    "relationship_revision" | "reducer_version" | "stream_version"
                                )
                                | ("relationship_endpoints", "ordinal")
                                | (
                                    "relationship_assertion_heads",
                                    "relationship_revision" | "stream_version"
                                )
                                | ("relationship_endpoint_activity", "endpoint_ordinal")
                                | ("relationship_local_admissions", "local_policy_version")
                                | (
                                    "effective_relationships",
                                    "support_count" | "contest_count" | "reducer_version"
                                )
                        )
                    {
                        row.try_get::<i64, _>(i).map(serde_json::Value::from)
                    } else if table == "message_origin_state"
                        && matches!(
                            *column,
                            "origin_type" | "collection_id" | "direct_set_digest"
                        )
                    {
                        row.try_get::<Option<String>, _>(i).map(|value| {
                            value.map_or(serde_json::Value::Null, serde_json::Value::from)
                        })
                    } else if matches!(table, "message_audience_state" | "message_origin_state")
                        && matches!(*column, "declaration_event_seq" | "participant_count")
                    {
                        row.try_get::<Option<i64>, _>(i).map(|value| {
                            value.map_or(serde_json::Value::Null, serde_json::Value::from)
                        })
                    } else if table == "annotation_targets" && *column == "source_event_seq" {
                        row.try_get::<Option<i64>, _>(i).map(|value| {
                            value.map_or(serde_json::Value::Null, serde_json::Value::from)
                        })
                    } else if table == "agent_runs" && *column == "close_event_seq" {
                        row.try_get::<Option<i64>, _>(i).map(|value| {
                            value.map_or(serde_json::Value::Null, serde_json::Value::from)
                        })
                    } else if (table == "vocabulary_values" && *column == "ordinal")
                        || (table == "canvas_objects" && matches!(*column, "x" | "y" | "w" | "h"))
                    {
                        row.try_get::<f64, _>(i).map(serde_json::Value::from)
                    } else if table == "dependencies" && *column == "confidence" {
                        row.try_get::<Option<f64>, _>(i).map(|value| {
                            value.map_or(serde_json::Value::Null, serde_json::Value::from)
                        })
                    } else if matches!(
                        (table, *column),
                        ("instruction_bindings", "position" | "enabled")
                            | ("agent_runs", "start_event_seq")
                            | (
                                "onboarding_programmes",
                                "generation" | "position" | "enabled"
                            )
                            | ("onboarding_programme_sources", "position")
                            | ("member_obligations", "generation")
                            | ("member_obligation_progress", "generation")
                            | ("seeded_instruction_sources", "template_version")
                            | ("control_event_applications", "event_seq")
                            | ("derivation_series", "created_event_seq")
                            | ("derivation_revisions", "completed_event_seq")
                            | ("derivation_revision_inputs", "ordinal")
                            | (
                                "derivation_attempts",
                                "attempt_ordinal" | "retryable" | "failed_event_seq"
                            )
                            | ("derivation_event_applications", "event_seq")
                            | (
                                "derivation_target_bindings",
                                "generation" | "bound_event_seq"
                            )
                            | (
                                "derivation_target_publications",
                                "generation" | "target_version" | "published_event_seq"
                            )
                            | (
                                "derivation_selected_publications",
                                "generation" | "target_version"
                            )
                            | ("derivation_target_heads", "generation" | "target_version")
                            | ("derivation_artifact_role_assignments", "assigned_event_seq")
                            | ("derivation_artifact_role_retirements", "retired_event_seq")
                            | ("derivation_artifact_role_heads", "head_event_seq")
                            | (
                                "derivation_revision_confirmations",
                                "generation" | "target_version" | "confirmed_event_seq"
                            )
                            | ("derivation_confirmation_retractions", "retracted_event_seq")
                            | ("derivation_confirmation_heads", "head_event_seq")
                    ) {
                        row.try_get::<i64, _>(i).map(serde_json::Value::from)
                    } else if table == "derivation_target_bindings"
                        && *column == "detached_event_seq"
                    {
                        row.try_get::<Option<i64>, _>(i).map(|value| {
                            value.map_or(serde_json::Value::Null, serde_json::Value::from)
                        })
                    } else {
                        row.try_get::<Option<String>, _>(i).map(|value| {
                            value.map_or(serde_json::Value::Null, serde_json::Value::String)
                        })
                    }
                })
                .collect::<std::result::Result<_, _>>()?;
            Ok(serde_json::to_string(&values)?)
        })
        .collect()
}

/// Replay the live database's event log into a fresh database and diff the
/// projections. The rebuild lands in an ephemeral in-memory database.
pub async fn rebuild_and_diff(live: &Db) -> Result<RebuildDiffResult> {
    // Consistent snapshot: read the event log AND the live projections in a single
    // read transaction so a concurrent write between the reads can't look like drift.
    let mut snapshot = live.write_pool().begin().await?;
    let events = read_all_events(&mut snapshot).await?;
    let mut live_dumps: Vec<(&str, Vec<String>)> = Vec::new();
    for table in PROJECTION_TABLES {
        live_dumps.push((
            table,
            dump_table(&mut snapshot, table, columns_for(table)).await?,
        ));
    }
    snapshot.rollback().await?;

    let rebuilt = fresh_projection_database().await?;
    let result = async {
        {
            let mut conn = rebuilt.write_pool().acquire().await?;
            // Projection equality needs only the FK identities referenced by
            // target events. Do not copy direct-write blob bytes into the
            // scratch rebuild, especially for large finance attachments.
            replay_with_blob_seeds(live, &mut conn, &events, None).await?;
        }
        diff_against(&rebuilt, &live_dumps, events.len()).await
    }
    .await;
    rebuilt.close().await;
    result
}

/// Replay the live database's META log into a fresh database and diff the meta
/// projections (ba9f97e). The exact analogue of [`rebuild_and_diff`], and the
/// half of this decision that gives the meta tier the same forcing function the
/// content tier has had all along: the log is the law, so divergence surfaces as
/// a failing check rather than as quiet corruption nobody notices until they
/// need the history.
pub async fn rebuild_and_diff_meta(live: &Db) -> Result<RebuildDiffResult> {
    let mut snapshot = live.write_pool().begin().await?;
    let events = read_all_meta_events(&mut snapshot).await?;
    let mut live_dumps: Vec<(&str, Vec<String>)> = Vec::new();
    for table in META_PROJECTION_TABLES {
        live_dumps.push((
            table,
            dump_table(&mut snapshot, table, columns_for(table)).await?,
        ));
    }
    snapshot.rollback().await?;

    let rebuilt = fresh_projection_database().await?;
    let result = async {
        {
            let mut conn = rebuilt.write_pool().acquire().await?;
            // `schema_config.applies_to_collection_id` is the one meta
            // projection FK into the independently replayed content tier. A
            // meta-only rebuild intentionally has no content projection, so
            // install inert record identities for every anchor the log ever
            // names. They are not part of the meta diff; they only let the
            // authoritative meta events fold under the same FK enforcement as
            // the live path (including rows whose anchor later moved).
            let mut anchors = std::collections::BTreeSet::new();
            for event in &events {
                if event.event_type != "schema_config.set" {
                    continue;
                }
                let Some(payload) = event.payload.as_deref() else {
                    continue;
                };
                let payload: SchemaConfigSetPayload = serde_json::from_str(payload)?;
                if let Some(anchor) = payload.applies_to_collection_id {
                    anchors.insert(anchor);
                }
            }
            for anchor in anchors {
                sqlx::query("INSERT INTO records (id, type) VALUES (?, 'Entity')")
                    .bind(anchor)
                    .execute(&mut *conn)
                    .await?;
            }
            replay_meta(&mut conn, &events).await?;
        }
        diff_against(&rebuilt, &live_dumps, events.len()).await
    }
    .await;
    rebuilt.close().await;
    result
}

/// Replay the authoritative policy log independently. Inert record identities
/// satisfy projection foreign keys without importing containment or making the
/// policy fold depend on content replay.
pub async fn rebuild_and_diff_policy(live: &Db) -> Result<RebuildDiffResult> {
    let mut snapshot = live.write_pool().begin().await?;
    let events = read_all_policy_events(&mut snapshot).await?;
    let mut live_dumps: Vec<(&str, Vec<String>)> = Vec::new();
    for table in POLICY_PROJECTION_TABLES {
        live_dumps.push((
            table,
            dump_table(&mut snapshot, table, columns_for(table)).await?,
        ));
    }
    snapshot.rollback().await?;

    let rebuilt = fresh_projection_database().await?;
    let result = async {
        let mut conn = rebuilt.write_pool().acquire().await?;
        let anchors = events
            .iter()
            .map(|event| event.record_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        for anchor in anchors {
            sqlx::query("INSERT INTO records (id, type) VALUES (?, 'Entity')")
                .bind(anchor)
                .execute(&mut *conn)
                .await?;
        }
        replay_policy(&mut conn, &events).await?;
        drop(conn);
        diff_against(&rebuilt, &live_dumps, events.len()).await
    }
    .await;
    rebuilt.close().await;
    result
}

/// Replay the independent relationship ledger and re-derive receiver-local
/// admission from the live snapshot's immutable provenance evidence. Content
/// links are copied only as inert ownership guards; this lane compares `rel:`
/// compatibility rows and the content lane compares everything else.
pub async fn rebuild_and_diff_relationship(live: &Db) -> Result<RebuildDiffResult> {
    let mut snapshot = live.write_pool().begin().await?;
    let events = crate::relationship::read_all_relationship_events(&mut snapshot).await?;
    let federated_events = sqlx::query_as::<_, (String, String)>(
        "SELECT issuer_origin_db_id,event_id FROM relationship_federation_events
          ORDER BY issuer_origin_db_id,event_id",
    )
    .fetch_all(&mut *snapshot)
    .await?
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    let mut decisions = Vec::new();
    let mut record_ids = std::collections::BTreeSet::new();
    let mut receiver_bindings = Vec::new();
    for event in &events {
        if let crate::relationship::RelationshipEventPayload::RelationshipCreated(created) =
            &event.payload
        {
            if federated_events
                .contains(&(event.issuer_origin_db_id.clone(), event.event_id.clone()))
            {
                let resolved = sqlx::query_as::<_, (String, String, Option<String>)>(
                    "SELECT role,portable_ref,record_id FROM relationship_endpoints
                      WHERE relationship_origin_db_id=?1 AND relationship_id=?2
                      ORDER BY ordinal",
                )
                .bind(&event.relationship.relationship_origin_db_id)
                .bind(&event.relationship.relationship_id)
                .fetch_all(&mut *snapshot)
                .await?;
                for (role, portable_ref, record_id) in resolved {
                    if let Some(record_id) = record_id {
                        let shape: (String, Option<String>) =
                            sqlx::query_as("SELECT type,kind FROM records WHERE id=?1")
                                .bind(&record_id)
                                .fetch_one(&mut *snapshot)
                                .await?;
                        receiver_bindings.push((portable_ref, record_id, shape.0, shape.1));
                    } else if !created.endpoints.iter().any(|endpoint| {
                        endpoint.role == role && endpoint.portable_ref == portable_ref
                    }) {
                        return Err(crate::Error::engine(
                            "federated relationship endpoint projection differs from its origin event",
                        ));
                    }
                }
            } else {
                record_ids.extend(
                    created
                        .endpoints
                        .iter()
                        .filter_map(|endpoint| endpoint.record_id.clone()),
                );
            }
        }
        if let crate::relationship::RelationshipEventPayload::AssertionCreated(created) =
            &event.payload
        {
            let verified = crate::provenance::verify_receiver_local_assertion_admission_in(
                &mut snapshot,
                &event.issuer_origin_db_id,
                &event.event_id,
                &created.origin_admission,
            )
            .await?;
            decisions.push(crate::relationship::ReceiverAdmissionDecision {
                assertion_event_issuer_origin_db_id: event.issuer_origin_db_id.clone(),
                assertion_created_event_id: event.event_id.clone(),
                verified,
            });
        }
    }
    let legacy_rows = sqlx::query(
        "SELECT id,source_id,target_id,relationship,note,created_at
           FROM links WHERE id NOT LIKE 'rel:%' ORDER BY id",
    )
    .fetch_all(&mut *snapshot)
    .await?;
    let mut legacy_links = Vec::with_capacity(legacy_rows.len());
    for row in legacy_rows {
        let source_id: String = row.try_get("source_id")?;
        let target_id: String = row.try_get("target_id")?;
        record_ids.insert(source_id.clone());
        record_ids.insert(target_id.clone());
        legacy_links.push((
            row.try_get::<String, _>("id")?,
            source_id,
            target_id,
            row.try_get::<String, _>("relationship")?,
            row.try_get::<Option<String>, _>("note")?,
            row.try_get::<String, _>("created_at")?,
        ));
    }
    let mut live_dumps = Vec::new();
    for table in RELATIONSHIP_REBUILD_TABLES {
        live_dumps.push((
            table,
            dump_relationship_table(&mut snapshot, table, relationship_columns_for(table)).await?,
        ));
    }
    snapshot.rollback().await?;

    let rebuilt = fresh_projection_database().await?;
    let result = async {
        let mut tx = crate::db::begin_write(rebuilt.write_pool()).await?;
        for (_, record_id, record_type, record_kind) in &receiver_bindings {
            sqlx::query(
                "INSERT INTO records(id,type,kind) VALUES(?1,?2,?3)
                 ON CONFLICT(id) DO NOTHING",
            )
            .bind(record_id)
            .bind(record_type)
            .bind(record_kind)
            .execute(&mut *tx)
            .await?;
        }
        for record_id in record_ids {
            sqlx::query(
                "INSERT INTO records(id,type) VALUES(?1,'Entity') ON CONFLICT(id) DO NOTHING",
            )
            .bind(record_id)
            .execute(&mut *tx)
            .await?;
        }
        for (portable_ref, record_id, _, _) in &receiver_bindings {
            sqlx::query(
                "INSERT INTO bindings(record_id,system,identifier)
                 VALUES(?1,'native-record',?2) ON CONFLICT DO NOTHING",
            )
            .bind(record_id)
            .bind(portable_ref)
            .execute(&mut *tx)
            .await?;
        }
        for (id, source_id, target_id, relationship, note, created_at) in legacy_links {
            sqlx::query(
                "INSERT INTO links(id,source_id,target_id,relationship,note,created_at)
                 VALUES(?1,?2,?3,?4,?5,?6)",
            )
            .bind(id)
            .bind(source_id)
            .bind(target_id)
            .bind(relationship)
            .bind(note)
            .bind(created_at)
            .execute(&mut *tx)
            .await?;
        }
        crate::relationship::replay_relationship_events(&mut tx, &events, &federated_events)
            .await?;
        crate::relationship::rebuild_receiver_local_state_in(&mut tx, &decisions).await?;
        tx.commit().await?;
        diff_relationship_against(&rebuilt, &live_dumps, events.len()).await
    }
    .await;
    rebuilt.close().await;
    result
}

/// Replay the independent portable control log. Record ids named by control
/// payloads are seeded as inert identities solely to satisfy projection FKs;
/// content and policy history remain independent inputs.
pub async fn rebuild_and_diff_control(live: &Db) -> Result<RebuildDiffResult> {
    let mut snapshot = live.write_pool().begin().await?;
    let events = read_all_control_events(&mut snapshot).await?;
    let mut live_dumps: Vec<(&str, Vec<String>)> = Vec::new();
    for table in CONTROL_PROJECTION_TABLES {
        live_dumps.push((
            table,
            dump_table(&mut snapshot, table, columns_for(table)).await?,
        ));
    }
    snapshot.rollback().await?;

    let rebuilt = fresh_projection_database().await?;
    let result = async {
        let mut conn = rebuilt.write_pool().acquire().await?;
        let mut record_ids = std::collections::BTreeSet::new();
        for event in &events {
            let payload: serde_json::Value = serde_json::from_str(&event.payload)?;
            for key in [
                "person_record_id",
                "root_record_id",
                "source_record_id",
                "artifact_id",
            ] {
                if let Some(id) = payload.get(key).and_then(serde_json::Value::as_str) {
                    record_ids.insert(id.to_string());
                }
            }
        }
        for record_id in record_ids {
            sqlx::query("INSERT INTO records(id,type) VALUES(?,'Entity')")
                .bind(record_id)
                .execute(&mut *conn)
                .await?;
        }
        replay_control(&mut conn, &events).await?;
        drop(conn);
        diff_against(&rebuilt, &live_dumps, events.len()).await
    }
    .await;
    rebuilt.close().await;
    result
}

/// Replay the independent derivation log and compare its product-neutral
/// projections. Derivation state has no foreign-key dependency on another
/// authoritative tier, so its rebuild needs no inert record or meta seeds.
pub async fn rebuild_and_diff_derivation(live: &Db) -> Result<RebuildDiffResult> {
    let mut snapshot = live.pool().begin().await?;
    let events = read_all_derivation_events(&mut snapshot).await?;
    let mut live_dumps: Vec<(&str, Vec<String>)> = Vec::new();
    for table in DERIVATION_PROJECTION_TABLES {
        live_dumps.push((
            table,
            dump_table(&mut snapshot, table, columns_for(table)).await?,
        ));
    }
    snapshot.rollback().await?;

    let rebuilt = fresh_projection_database().await?;
    let result = async {
        let mut conn = rebuilt.write_pool().acquire().await?;
        replay_derivations(&mut conn, &events).await?;
        drop(conn);
        diff_against(&rebuilt, &live_dumps, events.len()).await
    }
    .await;
    rebuilt.close().await;
    result
}

/// Rebuild targets need the DDL but deliberately start with empty projections:
/// their source log, rather than startup seeding, is the only replay input.
async fn fresh_projection_database() -> Result<Db> {
    let db = open_database(":memory:").await?;
    apply_schema(&db).await?;
    Ok(db)
}

/// Dump each table out of the rebuilt database and compare it row-for-row with
/// the live snapshot taken before the replay. Shared by all tiers — the diff is
/// the same operation either way; only the log and the table set differ.
async fn diff_against(
    rebuilt: &Db,
    live_dumps: &[(&str, Vec<String>)],
    event_count: usize,
) -> Result<RebuildDiffResult> {
    let mut tables: Vec<TableDiff> = Vec::new();
    for (table, live_rows) in live_dumps {
        let mut conn = rebuilt.write_pool().acquire().await?;
        let rebuilt_rows = dump_table(&mut conn, table, columns_for(table)).await?;
        let mut mismatches: Vec<String> = Vec::new();
        let max = live_rows.len().max(rebuilt_rows.len());
        for i in 0..max {
            if live_rows.get(i) != rebuilt_rows.get(i) {
                mismatches.push(format!(
                    "row {i}: live={} rebuilt={}",
                    live_rows.get(i).map_or("<none>", |s| s.as_str()),
                    rebuilt_rows.get(i).map_or("<none>", |s| s.as_str())
                ));
            }
        }
        tables.push(TableDiff {
            table: table.to_string(),
            live: live_rows.len(),
            rebuilt: rebuilt_rows.len(),
            mismatches,
        });
    }

    Ok(RebuildDiffResult {
        equal: tables
            .iter()
            .all(|t| t.mismatches.is_empty() && t.live == t.rebuilt),
        tables,
        event_count,
    })
}

async fn diff_relationship_against(
    rebuilt: &Db,
    live_dumps: &[(&str, Vec<String>)],
    event_count: usize,
) -> Result<RebuildDiffResult> {
    let mut tables = Vec::new();
    for (table, live_rows) in live_dumps {
        let mut conn = rebuilt.write_pool().acquire().await?;
        let rebuilt_rows =
            dump_relationship_table(&mut conn, table, relationship_columns_for(table)).await?;
        let mut mismatches = Vec::new();
        let max = live_rows.len().max(rebuilt_rows.len());
        for index in 0..max {
            if live_rows.get(index) != rebuilt_rows.get(index) {
                mismatches.push(format!(
                    "row {index}: live={} rebuilt={}",
                    live_rows.get(index).map_or("<none>", String::as_str),
                    rebuilt_rows.get(index).map_or("<none>", String::as_str),
                ));
            }
        }
        tables.push(TableDiff {
            table: (*table).to_string(),
            live: live_rows.len(),
            rebuilt: rebuilt_rows.len(),
            mismatches,
        });
    }
    Ok(RebuildDiffResult {
        equal: tables
            .iter()
            .all(|table| table.live == table.rebuilt && table.mismatches.is_empty()),
        tables,
        event_count,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::derivation::{
        append_derivation_event_in, DerivationEventPayload, DerivationSeriesCreated,
        NewDerivationEvent,
    };

    #[tokio::test]
    async fn derivation_rebuild_is_equal_and_detects_projection_drift() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        append_derivation_event_in(
            &mut tx,
            NewDerivationEvent::authored(
                "conformance-series",
                "person:alice",
                None,
                "exercise derivation rebuild conformance",
                DerivationEventPayload::SeriesCreated(DerivationSeriesCreated {
                    id: "series:conformance".into(),
                    series_key: "conformance-series".into(),
                    definition: json!({"output_contract":"native.test.v1"}),
                }),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let conforming = rebuild_and_diff_derivation(&db).await.unwrap();
        assert!(conforming.equal, "{conforming:?}");
        assert_eq!(conforming.event_count, 1);
        assert_eq!(conforming.tables.len(), DERIVATION_PROJECTION_TABLES.len());

        sqlx::query(
            "UPDATE derivation_series SET series_key='corrupted' WHERE id='series:conformance'",
        )
        .execute(db.write_pool())
        .await
        .unwrap();
        let drift = rebuild_and_diff_derivation(&db).await.unwrap();
        assert!(!drift.equal);
        let series = drift
            .tables
            .iter()
            .find(|table| table.table == "derivation_series")
            .unwrap();
        assert!(!series.mismatches.is_empty());
        db.close().await;
    }
}
