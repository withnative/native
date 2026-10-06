//! Fail-closed table/column taxonomy for member offline copies.
//!
//! Contract Native record c323277 rev 5, slices F-A increment 1: sections
//! 3.1 (the exhaustive map beside `super::standby_classification`), 3.2 (the
//! disposition table), 3.3 rule 9 (unknown table/column fails the build) and
//! the general column rule (log-position columns dropped).
//!
//! This is descriptive metadata only: it does not select rows in any runtime
//! path yet. Keeping the inventory beside the schema contract makes the first
//! producer implementation fail closed when a required table or column is
//! added without an explicit member disposition.
//!
//! Table order below is the content-digest order (contract section 1.4): each
//! `T_i` covers one shipped table in this fixed order. Do not reorder without
//! a profile major version bump.

/// How an engine table participates in a member copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MemberTableKind {
    /// Rows filtered to E(m), columns from the per-column allowlist.
    Included,
    /// Only rows about the caller.
    CallerBound,
    /// Would be caller-bound, but excluded in v1 (contract section 3.2 row
    /// "Caller-bound (v1: excluded)"). No columns ship.
    CallerBoundExcludedV1,
    /// The online value for m, shipped as data. Applies only to the declared
    /// member-only side table; no engine table carries this class.
    ServerComputed,
    /// Rebuilt locally on the device from the admitted slice, never shipped.
    DerivedLocal,
    /// Absent from the file; any surface that needs it refuses.
    Excluded,
}

/// Disposition of one column of an Included / CallerBound / ServerComputed
/// table (contract section 3.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MemberColumnKind {
    /// Shipped as-is (every shipped column is in the digest, S1).
    Shipped,
    /// Recomputed locally on the device (e.g. generated columns).
    Derived,
    /// Not shipped at all.
    Dropped,
    /// Shipped, but NULLed when the referenced record is outside E(m)
    /// (the online rule, `src/mcp/tools/lifecycle.rs:4822-4828`).
    NulledIfHidden,
    /// Shipped only when the exact-id gate passes (contract section 3.3
    /// rule 6, section 2.4 items 11/11a).
    Gated,
}

use MemberColumnKind::{
    Derived as DerivedCol, Dropped as DroppedCol, Gated as GatedCol, NulledIfHidden as NulledCol,
    Shipped as ShippedCol,
};
use MemberTableKind::{
    CallerBound, CallerBoundExcludedV1 as CallerBoundV1, DerivedLocal as Derived, Excluded,
    Included, ServerComputed as Computed,
};

/// Exhaustive member disposition of every engine table, plus the one declared
/// member-only side table ([`MEMBER_ONLY_TABLES`]).
///
/// Grouping follows contract section 3.2 top to bottom; each Excluded group
/// cites the section 3.2 row that covers it.
pub(crate) const MEMBER_TABLE_DISPOSITIONS: &[(&str, MemberTableKind)] = &[
    // Included: rows filtered to E(m) (section 3.2 "Included" rows).
    ("records", Included),
    ("links", Included),
    ("facet_values", Included),
    ("facet_times", Included),
    ("vocabularies", Included),
    ("vocabulary_values", Included),
    ("schema_config", Included),
    ("blobs", Included),
    ("annotation_targets", Included),
    ("record_mentions", Included),
    // Caller-bound: only rows about the caller (section 3.2 "Caller-bound").
    ("bindings", CallerBound),
    ("member_contexts", CallerBound),
    ("instruction_bindings", CallerBound),
    // Caller-bound in v1-excluded form (section 3.2 "Caller-bound (v1:
    // excluded)" row: "would be subject = caller", not shipped in Q5 v1).
    ("human_message_awareness", CallerBoundV1),
    ("agent_message_dispositions", CallerBoundV1),
    ("message_preferences", CallerBoundV1),
    ("member_destinations", CallerBoundV1),
    ("notification_candidates", CallerBoundV1),
    ("member_obligations", CallerBoundV1),
    ("member_obligation_progress", CallerBoundV1),
    ("alpha_tab_installs", CallerBoundV1),
    ("alpha_tab_orders", CallerBoundV1),
    // Server-computed (section 3.2 "Server-computed" row): the per-record
    // display_reference side table does not exist in the engine yet, so it is
    // a declared member-only table, not engine DDL.
    ("member_display_references", Computed),
    // Derived, rebuilt locally (section 3.2 "Derived, rebuilt locally" row).
    ("records_fts", Derived),
    ("records_name_idx", Derived),
    // Excluded: all 10 sequenced logs and the 3 act-stamped logs (section
    // 3.2 "Excluded: all 10 sequenced logs and the 3 act-stamped logs").
    ("content_events", Excluded),
    ("policy_events", Excluded),
    ("relationship_events", Excluded),
    ("control_events", Excluded),
    ("derivation_events", Excluded),
    ("awareness_events", Excluded),
    ("notification_candidate_events", Excluded),
    ("binding_audit", Excluded),
    ("database_identity_audit", Excluded),
    ("meta_events", Excluded),
    // Internal workspace rules have no admitted member-offline runtime surface.
    ("workspace_rule_installations", Excluded),
    ("provenance_attestation_validity_events", Excluded),
    ("awareness_command_intents", Excluded),
    ("external_observations", Excluded),
    // Excluded: every immutable companion (section 3.2 "Excluded: every
    // immutable companion" row).
    ("content_event_causal_frontier", Excluded),
    ("content_event_sources", Excluded),
    ("replicated_message_provenance", Excluded),
    ("destination_message_ingest", Excluded),
    ("replicated_message_references", Excluded),
    ("provenance_interaction_receipts", Excluded),
    ("provenance_action_attestations", Excluded),
    ("provenance_action_events", Excluded),
    ("provenance_action_outputs", Excluded),
    ("relationship_federation_events", Excluded),
    ("relationship_foreign_action_attestations", Excluded),
    ("relationship_foreign_action_outputs", Excluded),
    // Excluded: pinned state (section 3.2 "Excluded: pinned state" row).
    ("content_event_causal_cutover", Excluded),
    ("act_state", Excluded),
    ("act_cutover", Excluded),
    ("webhook_endpoints", Excluded),
    ("webhook_credentials", Excluded),
    ("binding_systems", Excluded),
    ("storage_portability_policy", Excluded),
    // Excluded: policy, identity and authorization state (section 3.2
    // "Excluded: record_policies ..." row).
    ("record_policies", Excluded),
    ("policy_entries", Excluded),
    ("authorization_revision", Excluded),
    ("authorization_grant_revision", Excluded),
    ("database_identity", Excluded),
    // Excluded: message structure (section 3.2 "Excluded (v1): message
    // structure" row). Message records ship as records; audience/mention
    // sections become markers.
    ("message_audiences", Excluded),
    ("message_mentions", Excluded),
    ("message_conversations", Excluded),
    ("message_audience_state", Excluded),
    ("message_origin_state", Excluded),
    ("message_origin_principals", Excluded),
    ("message_inbox_routing", Excluded),
    // Excluded: relationships, Units/freshness, attributions, artifacts,
    // canvas, derivation, agent runs, onboarding (section 3.2 "Excluded
    // (v1): relationships ... " row: a dedicated gate, a hidden-dependent
    // reduction, or a history dependency; each needs its own closure audit).
    ("relationships", Excluded),
    ("relationship_endpoints", Excluded),
    ("effective_relationships", Excluded),
    ("relationship_legacy_links", Excluded),
    ("relationship_assertion_heads", Excluded),
    ("relationship_endpoint_activity", Excluded),
    ("semantic_units", Excluded),
    ("unit_revisions", Excluded),
    ("unit_heads", Excluded),
    ("occurrences", Excluded),
    ("freshness_command_results", Excluded),
    ("freshness_runtime_command_results", Excluded),
    ("dependencies", Excluded),
    ("dependency_assessments", Excluded),
    ("receipts", Excluded),
    ("receipt_provenance", Excluded),
    ("receipt_comparisons", Excluded),
    ("receipt_uncertainty_lineage", Excluded),
    ("reconciliations", Excluded),
    ("unit_supersessions", Excluded),
    ("dependency_audits", Excluded),
    ("attribution_targets", Excluded),
    ("attribution_assertions", Excluded),
    ("attribution_evidence", Excluded),
    ("attribution_retractions", Excluded),
    ("module_releases", Excluded),
    ("module_release_imports", Excluded),
    ("recipe_releases", Excluded),
    ("recipe_release_input_classes", Excluded),
    ("artifact_source_attestations", Excluded),
    ("artifact_inputs", Excluded),
    ("artifact_module_grants", Excluded),
    ("canvas_objects", Excluded),
    ("canvas_batches", Excluded),
    ("derivation_series", Excluded),
    ("derivation_revisions", Excluded),
    ("derivation_revision_inputs", Excluded),
    ("derivation_attempts", Excluded),
    ("derivation_target_bindings", Excluded),
    ("derivation_target_publications", Excluded),
    ("derivation_selected_publications", Excluded),
    ("derivation_target_heads", Excluded),
    ("derivation_event_applications", Excluded),
    ("derivation_artifact_role_assignments", Excluded),
    ("derivation_artifact_role_retirements", Excluded),
    ("derivation_artifact_role_heads", Excluded),
    ("derivation_revision_confirmations", Excluded),
    ("derivation_confirmation_retractions", Excluded),
    ("derivation_confirmation_heads", Excluded),
    ("agent_runs", Excluded),
    ("control_event_applications", Excluded),
    ("onboarding_programmes", Excluded),
    ("onboarding_programme_sources", Excluded),
    ("seeded_instruction_sources", Excluded),
    ("content_event_claim_meta", Excluded),
    ("content_event_reaction_meta", Excluded),
    // Excluded: valid-time history (contract R3; section 2.3b refuses
    // manage_facet_observations as History). Named explicitly in rev 5
    // §3.2 (observation history plus the global event_seq). Current state
    // ships via facet_values instead.
    ("facet_observations", Excluded),
    // E3 M3's physical parser projections have no member-read-v1 surface yet.
    // Shipping them would change the offline profile and content digest.
    ("body_task_items", Excluded),
    ("body_blocks", Excluded),
    // The v76 JSON-node projection normalises `vocabulary_values.metadata`,
    // which is itself only shipped through the exact-id gate (section 3.3
    // rule 6). Like the E3 M3 parser projections above it has no member-read-v1
    // surface; a member image reconstructs meaning from the shipped value
    // columns instead of carrying node rows.
    ("vocabulary_value_json_nodes", Excluded),
    // Config nodes require the complete caller-filtered source; not shipped.
    ("schema_config_json_nodes", Excluded),
    // Facet-value nodes normalise `facet_values.value`; a member image rebuilds
    // meaning from the shipped value column rather than carrying node rows.
    ("facet_value_json_nodes", Excluded),
    // Excluded: evidence for the excluded awareness logs (contract R3;
    // section 2.3b refuses manage_interventions and the awareness folds
    // have no v1 surface). Named explicitly in rev 5 §3.2
    // (evidence_record_id can name a hidden record).
    ("awareness_event_evidence", Excluded),
    // Excluded: everything ExcludedOperational in standby_classification
    // (section 3.2 "Excluded: everything ExcludedOperational" row).
    ("provenance_local_attestation_authority", Excluded),
    ("webhook_deliveries", Excluded),
    ("relationship_local_admissions", Excluded),
    ("relationship_federation_quarantine", Excluded),
    ("derivation_requests", Excluded),
    ("embeddings", Excluded),
    ("jobs", Excluded),
    ("read_log_calls", Excluded),
    ("read_log_record_ids", Excluded),
    ("read_log_touches", Excluded),
    ("engine_migration_drills", Excluded),
];

/// Member-only tables: declared in [`MEMBER_TABLE_DISPOSITIONS`] but absent
/// from engine DDL. The display_reference side table does not exist in the
/// engine yet (section 3.2 "Server-computed" row); it is declared here, never
/// by changing engine DDL.
///
/// Name choice is an inference: no engine or contract name exists yet. The
/// `member_` prefix marks it as member-profile-only.
pub(crate) const MEMBER_ONLY_TABLES: &[&str] = &["member_display_references"];

/// Declared columns of each member-only table, in allowlist order. Engine
/// tables take their column inventory from live engine DDL (see tests); only
/// member-only tables declare columns here.
pub(crate) const MEMBER_ONLY_TABLE_COLUMNS: &[(&str, &[&str])] = &[(
    "member_display_references",
    &["record_id", "display_reference"],
)];

/// Per-column allowlist for every Included / CallerBound / ServerComputed
/// table: each column carries exactly one [`MemberColumnKind`] (section 3.1).
/// DerivedLocal, CallerBoundExcludedV1 and Excluded tables ship no columns
/// and take no entries here.
pub(crate) const MEMBER_COLUMN_DISPOSITIONS: &[(&str, &str, MemberColumnKind)] = &[
    // records (section 3.2 Included row): value columns shipped; home_id and
    // owner_id nulled when the referent is outside E(m); claim columns and
    // the anchor dropped; deleted_at ships always NULL (tombstones are
    // outside E(m)). `archived` is an inference: it is current-state
    // lifecycle-adjacent state with no excluding row, so it ships.
    ("records", "id", ShippedCol),
    ("records", "type", ShippedCol),
    ("records", "kind", ShippedCol),
    ("records", "name", ShippedCol),
    ("records", "body", ShippedCol),
    ("records", "home_id", NulledCol),
    ("records", "lifecycle", ShippedCol),
    ("records", "owner_id", NulledCol),
    ("records", "claimed_by_account", DroppedCol),
    ("records", "claimed_run_key", DroppedCol),
    ("records", "claimed_at", DroppedCol),
    ("records", "policy_anchor_id", DroppedCol),
    ("records", "persistence", ShippedCol),
    ("records", "maturity", ShippedCol),
    ("records", "summary", ShippedCol),
    // These counts include successors outside E(m); shipping them would
    // disclose facts about records omitted from the member copy.
    ("records", "is_current", DroppedCol),
    ("records", "successor_count", DroppedCol),
    ("records", "last_activity_at", ShippedCol),
    ("records", "created_at", ShippedCol),
    ("records", "updated_at", ShippedCol),
    ("records", "deleted_at", ShippedCol),
    ("records", "archived", ShippedCol),
    // links: both endpoints in E(m); all columns shipped.
    ("links", "id", ShippedCol),
    ("links", "source_id", ShippedCol),
    ("links", "target_id", ShippedCol),
    ("links", "relationship", ShippedCol),
    ("links", "note", ShippedCol),
    ("links", "created_at", ShippedCol),
    // facet_values: value_num is a generated column, recomputed locally.
    ("facet_values", "id", ShippedCol),
    ("facet_values", "record_id", ShippedCol),
    ("facet_values", "key", ShippedCol),
    ("facet_values", "value", ShippedCol),
    ("facet_values", "value_num", DerivedCol),
    ("facet_values", "vocab_ref", ShippedCol),
    ("facet_values", "created_at", ShippedCol),
    // facet_times: all value columns shipped.
    ("facet_times", "record_id", ShippedCol),
    ("facet_times", "key", ShippedCol),
    ("facet_times", "kind", ShippedCol),
    ("facet_times", "all_day", ShippedCol),
    ("facet_times", "start_date", ShippedCol),
    ("facet_times", "end_date", ShippedCol),
    ("facet_times", "start_ms", ShippedCol),
    ("facet_times", "end_ms", ShippedCol),
    ("facet_times", "tz", ShippedCol),
    ("facet_times", "tzdb_version", ShippedCol),
    // vocabularies: caller-independent online; all rows and columns ship.
    ("vocabularies", "id", ShippedCol),
    ("vocabularies", "name", ShippedCol),
    ("vocabularies", "created_at", ShippedCol),
    // vocabulary_values: metadata passes the exact-id gate (section 3.3
    // rule 6); the rest ships.
    ("vocabulary_values", "id", ShippedCol),
    ("vocabulary_values", "vocabulary_id", ShippedCol),
    ("vocabulary_values", "value", ShippedCol),
    ("vocabulary_values", "gloss", ShippedCol),
    ("vocabulary_values", "status", ShippedCol),
    ("vocabulary_values", "ordinal", ShippedCol),
    ("vocabulary_values", "terminality", ShippedCol),
    ("vocabulary_values", "metadata", GatedCol),
    ("vocabulary_values", "alias_of", ShippedCol),
    // schema_config: data passes the exact-id gate (section 3.3 rule 6).
    ("schema_config", "id", ShippedCol),
    ("schema_config", "layer", ShippedCol),
    ("schema_config", "name", ShippedCol),
    ("schema_config", "data", GatedCol),
    ("schema_config", "applies_to_collection_id", ShippedCol),
    ("schema_config", "version_lineage", ShippedCol),
    ("schema_config", "created_at", ShippedCol),
    // blobs: bytes ship for the inline tier only (external-tier bytes are
    // not_held, R2); external_ref passes the exact-id gate (section 2.4
    // item 11a). Producer obligation (review F-A inc1 F6): the producer
    // must emit NULL bytes for storage_tier='external' — Shipped here
    // holds by parity only because engine DDL keeps external rows
    // bytes IS NULL. A gated NULL carries member_only column
    // external_ref_withheld = 1 in the member read schema (a later
    // increment owns that DDL; F5).
    ("blobs", "id", ShippedCol),
    ("blobs", "bytes", ShippedCol),
    ("blobs", "mime", ShippedCol),
    ("blobs", "size_bytes", ShippedCol),
    ("blobs", "sha256", ShippedCol),
    ("blobs", "original_filename", ShippedCol),
    ("blobs", "storage_tier", ShippedCol),
    ("blobs", "external_ref", GatedCol),
    ("blobs", "created_at", ShippedCol),
    // annotation_targets: the log-position column is dropped (general
    // column rule); the rest ships.
    ("annotation_targets", "annotation_id", ShippedCol),
    ("annotation_targets", "target_record_id", ShippedCol),
    ("annotation_targets", "source_slot", ShippedCol),
    ("annotation_targets", "source_event_seq", DroppedCol),
    ("annotation_targets", "blob_id", ShippedCol),
    ("annotation_targets", "source_sha256", ShippedCol),
    ("annotation_targets", "selectors", ShippedCol),
    ("annotation_targets", "purpose", ShippedCol),
    ("annotation_targets", "created_at", ShippedCol),
    ("annotation_targets", "updated_at", ShippedCol),
    // record_mentions: the log-position column is dropped (general column
    // rule); resolution is recomputed over the slice.
    ("record_mentions", "source_id", ShippedCol),
    ("record_mentions", "occurrence_ix", ShippedCol),
    ("record_mentions", "source_event_seq", DroppedCol),
    ("record_mentions", "span_start", ShippedCol),
    ("record_mentions", "span_end", ShippedCol),
    ("record_mentions", "authored_reference", ShippedCol),
    ("record_mentions", "lookup_key", ShippedCol),
    ("record_mentions", "form", ShippedCol),
    ("record_mentions", "parser_version", ShippedCol),
    // bindings (caller-bound): only the caller's own account/email
    // bindings; columns as the governed view.
    ("bindings", "record_id", ShippedCol),
    ("bindings", "system", ShippedCol),
    ("bindings", "identifier", ShippedCol),
    ("bindings", "is_canonical", ShippedCol),
    ("bindings", "url", ShippedCol),
    ("bindings", "etag", ShippedCol),
    ("bindings", "last_seen_at", ShippedCol),
    // member_contexts and instruction_bindings (caller-bound): value
    // columns ship.
    ("member_contexts", "account_id", ShippedCol),
    ("member_contexts", "person_record_id", ShippedCol),
    ("member_contexts", "root_record_id", ShippedCol),
    ("member_contexts", "created_at", ShippedCol),
    ("instruction_bindings", "id", ShippedCol),
    ("instruction_bindings", "scope_kind", ShippedCol),
    ("instruction_bindings", "scope_id", ShippedCol),
    ("instruction_bindings", "source_record_id", ShippedCol),
    ("instruction_bindings", "position", ShippedCol),
    ("instruction_bindings", "enabled", ShippedCol),
    // Review F-A inc1 F1 (security), confirmed by contract rev 5 §3.2:
    // created_by is the authenticated
    // account identity (caller.actor()/caller.credential()), and
    // database-scope rows are created by other members while online
    // manage_instructions list never discloses it. §3.3 rule 5: no actor
    // or run identity travels in v1. Dropped for every row, including the
    // caller's own.
    ("instruction_bindings", "created_by", DroppedCol),
    ("instruction_bindings", "created_at", ShippedCol),
    ("instruction_bindings", "updated_at", ShippedCol),
    // member_display_references (server-computed, member-only): the online
    // display_reference value for each record in E(m), shipped and in the
    // digest (section 1.4, Q6c).
    ("member_display_references", "record_id", ShippedCol),
    ("member_display_references", "display_reference", ShippedCol),
];

/// Shipped columns of one Included / CallerBound / ServerComputed table, in
/// allowlist order: dispositions shipped, nulled_if_hidden and gated.
/// Member-only physical columns appended by the read schema (e.g. blobs'
/// `external_ref_withheld`) are not allowlist columns; callers add them.
pub(crate) fn shipped_column_order(table: &str) -> Vec<&'static str> {
    MEMBER_COLUMN_DISPOSITIONS
        .iter()
        .filter(|(name, _, kind)| {
            *name == table
                && matches!(
                    kind,
                    MemberColumnKind::Shipped
                        | MemberColumnKind::NulledIfHidden
                        | MemberColumnKind::Gated
                )
        })
        .map(|(_, column, _)| *column)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{
        MemberColumnKind, MemberTableKind, MEMBER_COLUMN_DISPOSITIONS, MEMBER_ONLY_TABLES,
        MEMBER_ONLY_TABLE_COLUMNS, MEMBER_TABLE_DISPOSITIONS,
    };
    use crate::schema::ddl::declared_table;
    use crate::schema::DDL_STATEMENTS;

    fn engine_tables() -> BTreeSet<String> {
        DDL_STATEMENTS
            .iter()
            .map(|statement| declared_table(statement))
            .collect::<Result<Vec<_>, _>>()
            .expect("every table-creating DDL statement must be understood")
            .into_iter()
            .flatten()
            .collect()
    }

    #[test]
    fn every_engine_table_has_exactly_one_member_disposition() {
        let classified = MEMBER_TABLE_DISPOSITIONS
            .iter()
            .map(|(table, _)| *table)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            classified.len(),
            MEMBER_TABLE_DISPOSITIONS.len(),
            "duplicate table disposition"
        );
        let engine = engine_tables();
        let member_only = MEMBER_ONLY_TABLES.iter().copied().collect::<BTreeSet<_>>();
        for table in &member_only {
            assert!(
                !engine.contains(*table),
                "member-only table {table} collides with engine DDL"
            );
            assert_eq!(
                MEMBER_TABLE_DISPOSITIONS
                    .iter()
                    .find_map(|(name, kind)| (*name == *table).then_some(*kind)),
                Some(MemberTableKind::ServerComputed),
                "member-only table {table} must be ServerComputed"
            );
        }
        for table in &engine {
            assert!(
                classified.contains(table.as_str()),
                "engine table {table} has no member disposition"
            );
        }
        for table in &classified {
            assert!(
                engine.iter().any(|name| name == table) || member_only.contains(table),
                "member disposition for unknown table {table}"
            );
        }
    }

    /// Raw comma-split fields of a regular (non-virtual) engine CREATE
    /// TABLE body, parsed from live [`DDL_STATEMENTS`] with `--` line
    /// comments stripped (DDL commentary contains commas that would
    /// otherwise split phantom fields).
    fn engine_table_fields(table: &str) -> Vec<String> {
        let statement = DDL_STATEMENTS
            .iter()
            .find(|statement| {
                let words = statement.split_ascii_whitespace().collect::<Vec<_>>();
                !words
                    .iter()
                    .any(|word| word.eq_ignore_ascii_case("VIRTUAL"))
                    && declared_table(statement).ok().flatten().as_deref() == Some(table)
            })
            .unwrap_or_else(|| panic!("no regular CREATE TABLE for {table}"));
        let mut uncommented = String::with_capacity(statement.len());
        let mut in_string = false;
        let mut line_rest: &str = statement;
        while !line_rest.is_empty() {
            let line_end = line_rest
                .find('\n')
                .map(|index| index + 1)
                .unwrap_or(line_rest.len());
            let (line, rest) = line_rest.split_at(line_end);
            line_rest = rest;
            let mut chars = line.char_indices().peekable();
            let mut cut = line.len();
            while let Some((index, ch)) = chars.next() {
                if in_string {
                    if ch == '\'' {
                        if chars.peek().is_some_and(|(_, next)| *next == '\'') {
                            chars.next();
                        } else {
                            in_string = false;
                        }
                    }
                    continue;
                }
                if ch == '\'' {
                    in_string = true;
                } else if ch == '-' && chars.peek().is_some_and(|(_, next)| *next == '-') {
                    cut = index;
                    break;
                }
            }
            uncommented.push_str(&line[..cut]);
        }
        let statement = uncommented;
        let start = statement
            .find('(')
            .unwrap_or_else(|| panic!("CREATE TABLE {table} has no column list"));
        let bytes = statement.as_bytes();
        let mut depth = 0usize;
        let mut end = None;
        for (index, byte) in bytes.iter().enumerate().skip(start) {
            match byte {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(index);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end.unwrap_or_else(|| panic!("unbalanced parens in {table} DDL"));
        let body = &statement[start + 1..end];
        let mut fields = Vec::new();
        let mut field_start = 0;
        depth = 0;
        for (index, byte) in body.bytes().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' => depth -= 1,
                b',' if depth == 0 => {
                    fields.push(&body[field_start..index]);
                    field_start = index + 1;
                }
                _ => {}
            }
        }
        fields.push(&body[field_start..]);
        fields
            .into_iter()
            .map(str::trim)
            .filter(|field| !field.is_empty() && !field.starts_with("--"))
            .map(str::to_owned)
            .collect()
    }

    /// First token of a field, or `None` for table constraints.
    fn field_column(field: &str) -> Option<&str> {
        let first = field.split_ascii_whitespace().next().unwrap_or_default();
        if ["CHECK", "PRIMARY", "FOREIGN", "UNIQUE", "CONSTRAINT"]
            .iter()
            .any(|keyword| first.eq_ignore_ascii_case(keyword))
        {
            return None;
        }
        let column = first
            .trim_matches(|character| matches!(character, '`' | '"' | '[' | ']'))
            .trim_end_matches('(');
        (!column.is_empty()).then_some(column)
    }

    /// Column names of a regular engine CREATE TABLE, so that adding an
    /// engine column without a member disposition fails the build
    /// (contract section 3.3 rule 9).
    fn engine_table_columns(table: &str) -> Vec<String> {
        engine_table_fields(table)
            .iter()
            .filter_map(|field| field_column(field).map(str::to_owned))
            .collect()
    }

    /// Target table of a column-level `REFERENCES` clause, if any.
    /// Review F-A inc1 F4: the general column rule drops log-position
    /// columns *and* FKs to logs, so this must be derived from live DDL.
    fn field_references(field: &str) -> Option<String> {
        let words: Vec<&str> = field.split_ascii_whitespace().collect();
        let pos = words
            .iter()
            .position(|word| word.eq_ignore_ascii_case("REFERENCES"))?;
        let raw = words.get(pos + 1)?;
        let unqualified = raw.split('(').next().unwrap_or(raw);
        let target = unqualified.trim_matches(|c| matches!(c, '`' | '"' | '[' | ']' | ';'));
        (!target.is_empty()).then(|| target.to_owned())
    }

    fn is_log_position(column: &str) -> bool {
        column == "seq" || column == "event_seq" || column.ends_with("_seq")
    }

    #[test]
    fn every_shipped_table_column_has_exactly_one_column_disposition() {
        let pairs = MEMBER_COLUMN_DISPOSITIONS
            .iter()
            .map(|(table, column, _)| (*table, *column))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            pairs.len(),
            MEMBER_COLUMN_DISPOSITIONS.len(),
            "duplicate column disposition"
        );
        let table_kind = MEMBER_TABLE_DISPOSITIONS
            .iter()
            .copied()
            .collect::<BTreeMap<_, _>>();
        for (table, _, _) in MEMBER_COLUMN_DISPOSITIONS {
            match table_kind.get(table) {
                Some(
                    MemberTableKind::Included
                    | MemberTableKind::CallerBound
                    | MemberTableKind::ServerComputed,
                ) => {}
                other => panic!("column disposition for unshipped table {table}: {other:?}"),
            }
        }
        let shipped_tables = MEMBER_TABLE_DISPOSITIONS
            .iter()
            .filter(|(_, kind)| {
                matches!(
                    kind,
                    MemberTableKind::Included
                        | MemberTableKind::CallerBound
                        | MemberTableKind::ServerComputed
                )
            })
            .map(|(table, _)| *table)
            .collect::<Vec<_>>();
        for table in shipped_tables {
            let expected = if MEMBER_ONLY_TABLES.contains(&table) {
                MEMBER_ONLY_TABLE_COLUMNS
                    .iter()
                    .find_map(|(name, columns)| (*name == table).then_some(columns.to_vec()))
                    .unwrap_or_else(|| panic!("member-only table {table} declares no columns"))
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>()
            } else {
                engine_table_columns(table)
                    .into_iter()
                    .collect::<BTreeSet<_>>()
            };
            let actual = MEMBER_COLUMN_DISPOSITIONS
                .iter()
                .filter_map(|(name, column, _)| (*name == table).then_some((*column).to_owned()))
                .collect::<BTreeSet<_>>();
            assert_eq!(
                expected, actual,
                "column disposition mismatch for {table}: expected {expected:?}, have {actual:?}"
            );
        }
    }

    #[test]
    fn member_only_tables_and_columns_name_the_same_set() {
        // Review F-A inc1 F3: an entry in either constant without a match
        // in the other must fail, not pass vacuously.
        let tables = MEMBER_ONLY_TABLES.iter().copied().collect::<BTreeSet<_>>();
        let columns = MEMBER_ONLY_TABLE_COLUMNS
            .iter()
            .map(|(table, _)| *table)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            tables, columns,
            "MEMBER_ONLY_TABLES and MEMBER_ONLY_TABLE_COLUMNS must name the same tables"
        );
        for (table, declared) in MEMBER_ONLY_TABLE_COLUMNS {
            assert!(
                !declared.is_empty(),
                "member-only table {table} must declare at least one column"
            );
        }
    }

    #[test]
    fn no_log_position_column_is_shipped() {
        // Contract section 3.2 general column rule: every column holding a
        // log position is dropped (global coordinates, R5).
        for (table, column, kind) in MEMBER_COLUMN_DISPOSITIONS {
            assert!(
                *kind == MemberColumnKind::Dropped || !is_log_position(column),
                "log-position column {table}.{column} must be dropped, not {kind:?}"
            );
        }
        for statement in DDL_STATEMENTS {
            let words = statement.split_ascii_whitespace().collect::<Vec<_>>();
            if words
                .iter()
                .any(|word| word.eq_ignore_ascii_case("VIRTUAL"))
            {
                continue;
            }
            let Some(table) = declared_table(statement)
                .expect("every table-creating DDL statement must be understood")
            else {
                continue;
            };
            let kind = MEMBER_TABLE_DISPOSITIONS
                .iter()
                .find_map(|(name, kind)| (*name == table).then_some(*kind))
                .unwrap_or_else(|| panic!("unclassified engine table {table}"));
            for column in engine_table_columns(&table) {
                if !is_log_position(&column) {
                    continue;
                }
                match kind {
                    MemberTableKind::Included
                    | MemberTableKind::CallerBound
                    | MemberTableKind::ServerComputed => {
                        let disposition = MEMBER_COLUMN_DISPOSITIONS
                            .iter()
                            .find_map(|(name, col, kind)| {
                                (*name == table && *col == column).then_some(*kind)
                            })
                            .unwrap_or_else(|| {
                                panic!("engine column {table}.{column} has no disposition")
                            });
                        assert_eq!(
                            disposition,
                            MemberColumnKind::Dropped,
                            "log-position column {table}.{column} must be dropped"
                        );
                    }
                    MemberTableKind::CallerBoundExcludedV1
                    | MemberTableKind::DerivedLocal
                    | MemberTableKind::Excluded => {
                        assert!(
                            !MEMBER_COLUMN_DISPOSITIONS
                                .iter()
                                .any(|(name, col, _)| *name == table && *col == column),
                            "unshipped table {table} takes no column entry for {column}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn no_shipped_column_references_an_unshipped_table() {
        // Review F-A inc1 F4 (extended N6): the general column rule drops
        // log-position columns *and* FKs to logs ("or an FK to a log is
        // dropped ... their FK targets are absent"). Derived from live DDL
        // so a future `REFERENCES content_events(...)` (or any excluded
        // table) cannot ship under a non-log name — at column level *or*
        // table level. A table-level `FOREIGN KEY ... REFERENCES` to an
        // unshipped table would otherwise ride into the member DDL as a
        // dangling FK (SQLite accepts the CREATE; `foreign_key_check` on
        // an empty DB is silent), so it fails the build here instead.
        // (`member_schema` drops table constraints mentioning dropped
        // columns regardless; this gate covers the rest.)
        let shipping = |kind: &MemberTableKind| {
            matches!(
                kind,
                MemberTableKind::Included
                    | MemberTableKind::CallerBound
                    | MemberTableKind::ServerComputed
            )
        };
        let table_kind = MEMBER_TABLE_DISPOSITIONS
            .iter()
            .copied()
            .collect::<BTreeMap<_, _>>();
        for (table, kind) in MEMBER_TABLE_DISPOSITIONS {
            if !shipping(kind) || MEMBER_ONLY_TABLES.contains(table) {
                continue;
            }
            for field in engine_table_fields(table) {
                let Some(target) = field_references(&field) else {
                    continue;
                };
                let Some(column) = field_column(&field) else {
                    // Table-level constraint (FOREIGN KEY / CONSTRAINT).
                    // `member_schema` drops any table constraint that names
                    // a dropped local column, so mirror that here: such a
                    // constraint cannot ship, so a dangling target on it is
                    // moot. Anything else must reference a shipped table.
                    let names_dropped = field
                        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
                        .filter(|token| !token.is_empty())
                        .any(|token| {
                            MEMBER_COLUMN_DISPOSITIONS.iter().any(|(name, col, kind)| {
                                *name == *table
                                    && *kind == MemberColumnKind::Dropped
                                    && col.eq_ignore_ascii_case(token)
                            })
                        });
                    if names_dropped {
                        continue;
                    }
                    match table_kind.get(target.as_str()) {
                        Some(target_kind) if shipping(target_kind) => {}
                        other => panic!(
                            "shipped table {table} has a table-level constraint referencing unshipped table {target} ({other:?}): FK targets are absent"
                        ),
                    }
                    continue;
                };
                let disposition = MEMBER_COLUMN_DISPOSITIONS
                    .iter()
                    .find_map(|(name, col, kind)| {
                        (*name == *table && *col == column).then_some(*kind)
                    })
                    .unwrap_or_else(|| panic!("engine column {table}.{column} has no disposition"));
                if disposition == MemberColumnKind::Dropped {
                    continue;
                }
                match table_kind.get(target.as_str()) {
                    Some(target_kind) if shipping(target_kind) => {}
                    other => panic!(
                        "shipped column {table}.{column} references unshipped table {target} ({other:?}): FK targets are absent, drop the column"
                    ),
                }
            }
        }
        // The table-level branch is dormant while no engine table declares a
        // table-level FK, so exercise the parser on a synthetic one to keep
        // the guard non-vacuous: a table-level `FOREIGN KEY` must read as a
        // constraint (no column) with target `content_events` (unshipped).
        let synthetic = "FOREIGN KEY (policy_anchor_id) REFERENCES content_events(seq)";
        assert!(field_column(synthetic).is_none());
        assert_eq!(
            field_references(synthetic).as_deref(),
            Some("content_events")
        );
    }

    /// Golden snapshot of [`MEMBER_TABLE_DISPOSITIONS`] order. The order is
    /// the content-digest order (contract section 1.4): reordering, however
    /// innocent, changes every generation identity, so it needs a profile
    /// major version bump, not a silent diff.
    const EXPECTED_MEMBER_TABLE_ORDER: &[&str] = &[
        "records",
        "links",
        "facet_values",
        "facet_times",
        "vocabularies",
        "vocabulary_values",
        "schema_config",
        "blobs",
        "annotation_targets",
        "record_mentions",
        "bindings",
        "member_contexts",
        "instruction_bindings",
        "human_message_awareness",
        "agent_message_dispositions",
        "message_preferences",
        "member_destinations",
        "notification_candidates",
        "member_obligations",
        "member_obligation_progress",
        "alpha_tab_installs",
        "alpha_tab_orders",
        "member_display_references",
        "records_fts",
        "records_name_idx",
        "content_events",
        "policy_events",
        "relationship_events",
        "control_events",
        "derivation_events",
        "awareness_events",
        "notification_candidate_events",
        "binding_audit",
        "database_identity_audit",
        "meta_events",
        "workspace_rule_installations",
        "provenance_attestation_validity_events",
        "awareness_command_intents",
        "external_observations",
        "content_event_causal_frontier",
        "content_event_sources",
        "replicated_message_provenance",
        "destination_message_ingest",
        "replicated_message_references",
        "provenance_interaction_receipts",
        "provenance_action_attestations",
        "provenance_action_events",
        "provenance_action_outputs",
        "relationship_federation_events",
        "relationship_foreign_action_attestations",
        "relationship_foreign_action_outputs",
        "content_event_causal_cutover",
        "act_state",
        "act_cutover",
        "webhook_endpoints",
        "webhook_credentials",
        "binding_systems",
        "storage_portability_policy",
        "record_policies",
        "policy_entries",
        "authorization_revision",
        "authorization_grant_revision",
        "database_identity",
        "message_audiences",
        "message_mentions",
        "message_conversations",
        "message_audience_state",
        "message_origin_state",
        "message_origin_principals",
        "message_inbox_routing",
        "relationships",
        "relationship_endpoints",
        "effective_relationships",
        "relationship_legacy_links",
        "relationship_assertion_heads",
        "relationship_endpoint_activity",
        "semantic_units",
        "unit_revisions",
        "unit_heads",
        "occurrences",
        "freshness_command_results",
        "freshness_runtime_command_results",
        "dependencies",
        "dependency_assessments",
        "receipts",
        "receipt_provenance",
        "receipt_comparisons",
        "receipt_uncertainty_lineage",
        "reconciliations",
        "unit_supersessions",
        "dependency_audits",
        "attribution_targets",
        "attribution_assertions",
        "attribution_evidence",
        "attribution_retractions",
        "module_releases",
        "module_release_imports",
        "recipe_releases",
        "recipe_release_input_classes",
        "artifact_source_attestations",
        "artifact_inputs",
        "artifact_module_grants",
        "canvas_objects",
        "canvas_batches",
        "derivation_series",
        "derivation_revisions",
        "derivation_revision_inputs",
        "derivation_attempts",
        "derivation_target_bindings",
        "derivation_target_publications",
        "derivation_selected_publications",
        "derivation_target_heads",
        "derivation_event_applications",
        "derivation_artifact_role_assignments",
        "derivation_artifact_role_retirements",
        "derivation_artifact_role_heads",
        "derivation_revision_confirmations",
        "derivation_confirmation_retractions",
        "derivation_confirmation_heads",
        "agent_runs",
        "control_event_applications",
        "onboarding_programmes",
        "onboarding_programme_sources",
        "seeded_instruction_sources",
        "content_event_claim_meta",
        "content_event_reaction_meta",
        "facet_observations",
        "body_task_items",
        "body_blocks",
        "vocabulary_value_json_nodes",
        "schema_config_json_nodes",
        "facet_value_json_nodes",
        "awareness_event_evidence",
        "provenance_local_attestation_authority",
        "webhook_deliveries",
        "relationship_local_admissions",
        "relationship_federation_quarantine",
        "derivation_requests",
        "embeddings",
        "jobs",
        "read_log_calls",
        "read_log_record_ids",
        "read_log_touches",
        "engine_migration_drills",
    ];

    #[test]
    fn member_table_order_is_fixed_digest_order() {
        let actual = MEMBER_TABLE_DISPOSITIONS
            .iter()
            .map(|(table, _)| *table)
            .collect::<Vec<_>>();
        assert_eq!(
            actual, EXPECTED_MEMBER_TABLE_ORDER,
            "MEMBER_TABLE_DISPOSITIONS order is the content-digest order: do not reorder"
        );
    }
}
