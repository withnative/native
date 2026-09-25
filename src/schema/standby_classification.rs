//! Fail-closed table taxonomy for materialised-prefix standby replication.
//!
//! This is descriptive metadata only: it does not select tables in any runtime
//! path yet. Keeping the inventory beside the schema contract makes the first
//! delta implementation fail closed when a required table is added without an
//! explicit carriage, fold, pin, or exclusion decision.

/// How a required schema table participates in standby materialisation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StandbyTableKind {
    /// One of the ten authoritative logs with a global sequence and act stamp.
    SequencedCanonicalLog,
    /// Canonical history stamped by act but positioned by a compound key.
    NonSequencedActStampedCanonicalLog,
    /// Immutable canonical rows carried by joining from delta log rows.
    ImmutableCanonicalCompanion,
    /// Small canonical state requiring a table-specific carry, comparison, or
    /// seed-equality rule in the delta protocol.
    PinnedCanonicalState,
    /// State maintained incrementally by an event fold or a DDL trigger.
    DerivedIncremental,
    /// Derived state whose update would require a global recomputation.
    DerivedGlobal,
    /// Receiver-local, operational, disposable, or otherwise not replicated.
    ExcludedOperational,
}

use StandbyTableKind::{
    DerivedIncremental as Fold, ExcludedOperational as Excluded,
    ImmutableCanonicalCompanion as Companion, NonSequencedActStampedCanonicalLog as ActLog,
    PinnedCanonicalState as Pinned, SequencedCanonicalLog as Log,
};

/// Exhaustive classification of [`super::REQUIRED_TABLES`].
///
/// Grouping by kind makes the empty `DerivedGlobal` bucket visible. A table
/// must not enter that bucket without also defining an incremental algorithm
/// or an explicit lazy/dirty-state protocol.
pub(crate) const TABLE_CLASSIFICATIONS: &[(&str, StandbyTableKind)] = &[
    // Sequenced, act-stamped canonical logs.
    ("content_events", Log),
    ("policy_events", Log),
    ("relationship_events", Log),
    ("control_events", Log),
    ("derivation_events", Log),
    ("awareness_events", Log),
    ("notification_candidate_events", Log),
    ("binding_audit", Log),
    ("database_identity_audit", Log),
    ("meta_events", Log),
    // Canonical history with act identity but no global sequence.
    ("provenance_attestation_validity_events", ActLog),
    ("awareness_command_intents", ActLog),
    ("external_observations", ActLog),
    // Immutable canonical companions selected from delta-log identities.
    ("content_event_causal_frontier", Companion),
    ("content_event_sources", Companion),
    ("replicated_message_provenance", Companion),
    ("destination_message_ingest", Companion),
    ("replicated_message_references", Companion),
    ("provenance_interaction_receipts", Companion),
    ("provenance_action_attestations", Companion),
    ("provenance_action_events", Companion),
    ("provenance_action_outputs", Companion),
    ("relationship_federation_events", Companion),
    ("relationship_foreign_action_attestations", Companion),
    ("relationship_foreign_action_outputs", Companion),
    ("blobs", Companion),
    // Frozen markers and small directly governed canonical state.
    ("content_event_causal_cutover", Pinned),
    ("act_state", Pinned),
    ("act_cutover", Pinned),
    ("webhook_endpoints", Pinned),
    ("webhook_credentials", Pinned),
    ("binding_systems", Pinned),
    ("storage_portability_policy", Pinned),
    // Content-log projections.
    ("records", Fold),
    ("record_mentions", Fold),
    ("links", Fold),
    ("facet_values", Fold),
    ("facet_observations", Fold),
    ("annotation_targets", Fold),
    ("attribution_targets", Fold),
    ("attribution_assertions", Fold),
    ("attribution_evidence", Fold),
    ("attribution_retractions", Fold),
    ("message_audience_state", Fold),
    ("message_audiences", Fold),
    ("message_origin_state", Fold),
    ("message_origin_principals", Fold),
    ("message_conversations", Fold),
    ("message_mentions", Fold),
    ("module_releases", Fold),
    ("module_release_imports", Fold),
    ("recipe_releases", Fold),
    ("recipe_release_input_classes", Fold),
    ("artifact_source_attestations", Fold),
    ("artifact_inputs", Fold),
    ("artifact_module_grants", Fold),
    ("semantic_units", Fold),
    ("unit_revisions", Fold),
    ("unit_heads", Fold),
    ("occurrences", Fold),
    ("freshness_command_results", Fold),
    ("freshness_runtime_command_results", Fold),
    ("dependencies", Fold),
    ("dependency_assessments", Fold),
    ("receipts", Fold),
    ("receipt_provenance", Fold),
    ("receipt_comparisons", Fold),
    ("receipt_uncertainty_lineage", Fold),
    ("reconciliations", Fold),
    ("unit_supersessions", Fold),
    ("dependency_audits", Fold),
    ("canvas_objects", Fold),
    ("canvas_batches", Fold),
    // Awareness and notification-candidate folds.
    ("human_message_awareness", Fold),
    ("agent_message_dispositions", Fold),
    ("awareness_event_evidence", Fold),
    ("message_inbox_routing", Fold),
    ("message_preferences", Fold),
    ("member_destinations", Fold),
    ("notification_candidates", Fold),
    // Policy, binding, identity, relationship, control, derivation, and meta folds.
    ("record_policies", Fold),
    ("policy_entries", Fold),
    ("bindings", Fold),
    ("database_identity", Fold),
    ("authorization_revision", Fold),
    ("relationships", Fold),
    ("relationship_endpoints", Fold),
    ("relationship_legacy_links", Fold),
    ("relationship_assertion_heads", Fold),
    ("relationship_endpoint_activity", Fold),
    ("agent_runs", Fold),
    ("member_contexts", Fold),
    ("instruction_bindings", Fold),
    ("onboarding_programmes", Fold),
    ("onboarding_programme_sources", Fold),
    ("member_obligations", Fold),
    ("member_obligation_progress", Fold),
    ("seeded_instruction_sources", Fold),
    ("alpha_tab_installs", Fold),
    ("control_event_applications", Fold),
    ("derivation_series", Fold),
    ("derivation_revisions", Fold),
    ("derivation_revision_inputs", Fold),
    ("derivation_attempts", Fold),
    ("derivation_target_bindings", Fold),
    ("derivation_target_publications", Fold),
    ("derivation_selected_publications", Fold),
    ("derivation_target_heads", Fold),
    ("derivation_event_applications", Fold),
    ("derivation_artifact_role_assignments", Fold),
    ("derivation_artifact_role_retirements", Fold),
    ("derivation_artifact_role_heads", Fold),
    ("derivation_revision_confirmations", Fold),
    ("derivation_confirmation_retractions", Fold),
    ("derivation_confirmation_heads", Fold),
    ("vocabularies", Fold),
    ("vocabulary_values", Fold),
    ("schema_config", Fold),
    // Trigger-maintained search indexes are folds too, not transported state.
    ("records_fts", Fold),
    ("records_name_idx", Fold),
    // Receiver-local, operational, or disposable state.
    ("provenance_local_attestation_authority", Excluded),
    ("webhook_deliveries", Excluded),
    ("relationship_local_admissions", Excluded),
    ("effective_relationships", Excluded),
    ("relationship_federation_quarantine", Excluded),
    ("derivation_requests", Excluded),
    ("embeddings", Excluded),
    ("jobs", Excluded),
    ("read_log_calls", Excluded),
    ("read_log_record_ids", Excluded),
    ("read_log_touches", Excluded),
    ("engine_migration_drills", Excluded),
];

/// No required table currently needs a global rebuild during refresh.
pub(crate) const DERIVED_GLOBAL_TABLES: &[&str] = &[];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{StandbyTableKind, DERIVED_GLOBAL_TABLES, TABLE_CLASSIFICATIONS};
    use crate::act::{
        ACT_STAMPED_TABLES, CANONICAL_EVENT_TABLES, NON_SEQUENCED_ACT_STAMPED_TABLES,
    };
    use crate::schema::{DDL_STATEMENTS, REQUIRED_TABLES};

    fn names_of(kind: StandbyTableKind) -> BTreeSet<&'static str> {
        TABLE_CLASSIFICATIONS
            .iter()
            .filter_map(|(table, candidate)| (*candidate == kind).then_some(*table))
            .collect()
    }

    fn set(values: &[&'static str]) -> BTreeSet<&'static str> {
        values.iter().copied().collect()
    }

    fn declared_table(statement: &str) -> Result<Option<String>, String> {
        let words = statement.split_ascii_whitespace().collect::<Vec<_>>();
        if !words
            .first()
            .is_some_and(|word| word.eq_ignore_ascii_case("CREATE"))
        {
            return Ok(None);
        }

        let mentions_table = words.iter().any(|word| word.eq_ignore_ascii_case("TABLE"));
        let mut cursor = 1;
        if words.get(cursor).is_some_and(|word| {
            word.eq_ignore_ascii_case("TEMP") || word.eq_ignore_ascii_case("TEMPORARY")
        }) {
            cursor += 1;
        }
        if words
            .get(cursor)
            .is_some_and(|word| word.eq_ignore_ascii_case("VIRTUAL"))
        {
            cursor += 1;
        }
        if !words
            .get(cursor)
            .is_some_and(|word| word.eq_ignore_ascii_case("TABLE"))
        {
            return if mentions_table {
                Err(format!("unrecognised CREATE TABLE statement: {statement}"))
            } else {
                Ok(None)
            };
        }
        cursor += 1;
        if words
            .get(cursor)
            .is_some_and(|word| word.eq_ignore_ascii_case("IF"))
        {
            let guard = words.get(cursor..cursor + 3).unwrap_or_default();
            if guard.len() != 3
                || !guard[0].eq_ignore_ascii_case("IF")
                || !guard[1].eq_ignore_ascii_case("NOT")
                || !guard[2].eq_ignore_ascii_case("EXISTS")
            {
                return Err(format!("unrecognised CREATE TABLE guard: {statement}"));
            }
            cursor += 3;
        }
        let raw = words
            .get(cursor)
            .ok_or_else(|| format!("CREATE TABLE has no table name: {statement}"))?
            .trim_end_matches('(');
        let unqualified = raw.rsplit('.').next().unwrap_or(raw);
        let table =
            unqualified.trim_matches(|character| matches!(character, '`' | '"' | '[' | ']'));
        if table.is_empty() {
            return Err(format!("CREATE TABLE has an empty table name: {statement}"));
        }
        Ok(Some(table.to_owned()))
    }

    #[test]
    fn every_engine_table_has_exactly_one_standby_classification() {
        let classified = TABLE_CLASSIFICATIONS
            .iter()
            .map(|(table, _)| *table)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            classified.len(),
            TABLE_CLASSIFICATIONS.len(),
            "duplicate table classification"
        );
        let engine_tables = DDL_STATEMENTS
            .iter()
            .map(|statement| declared_table(statement))
            .collect::<Result<Vec<_>, _>>()
            .expect("every table-creating DDL statement must be understood")
            .into_iter()
            .flatten()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            classified,
            engine_tables.iter().map(String::as_str).collect()
        );
        assert!(set(&REQUIRED_TABLES).is_subset(&classified));
    }

    #[test]
    fn every_declared_projection_is_an_incremental_fold() {
        for table in crate::schema::PROJECTION_TABLES
            .iter()
            .chain(crate::schema::POLICY_PROJECTION_TABLES.iter())
            .chain(crate::schema::ddl::RELATIONSHIP_PROJECTION_TABLES.iter())
            .chain(crate::schema::CONTROL_PROJECTION_TABLES.iter())
            .chain(crate::schema::DERIVATION_PROJECTION_TABLES.iter())
            .chain(crate::schema::META_PROJECTION_TABLES.iter())
            .chain(crate::awareness::REBUILD_PROJECTION_TABLES.iter())
        {
            assert_eq!(
                TABLE_CLASSIFICATIONS
                    .iter()
                    .find_map(|(name, kind)| (*name == *table).then_some(*kind)),
                Some(StandbyTableKind::DerivedIncremental),
                "declared projection {table} must be classified as an incremental fold"
            );
        }
    }

    #[test]
    fn canonical_log_inventories_are_one_contract() {
        let sequenced = names_of(StandbyTableKind::SequencedCanonicalLog);
        let nonsequenced = names_of(StandbyTableKind::NonSequencedActStampedCanonicalLog);
        assert_eq!(sequenced, set(&CANONICAL_EVENT_TABLES));
        assert_eq!(
            sequenced,
            set(crate::standby::generation_store::SEQUENCED_LOGS)
        );
        assert_eq!(
            sequenced,
            set(crate::standby_snapshot::FRONTIER_SEQUENCED_LOGS)
        );
        assert_eq!(nonsequenced, set(&NON_SEQUENCED_ACT_STAMPED_TABLES));

        let all_act_stamped = sequenced
            .union(&nonsequenced)
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(all_act_stamped, set(&ACT_STAMPED_TABLES));
        for table in all_act_stamped {
            assert!(
                crate::interchange::SECTION_NAMES.contains(&table),
                "rev-5 interchange omits act-stamped canonical table {table}"
            );
        }
    }

    #[test]
    fn legacy_snapshot_prefix_lists_use_only_classified_state() {
        for table in crate::standby::generation_store::UNSEQUENCED_APPEND_ONLY {
            if *table == "engine_migration_drills" {
                continue;
            }
            let kind = TABLE_CLASSIFICATIONS
                .iter()
                .find_map(|(name, kind)| (*name == *table).then_some(*kind))
                .unwrap_or_else(|| panic!("unclassified standby prefix table {table}"));
            assert!(
                matches!(
                    kind,
                    StandbyTableKind::ImmutableCanonicalCompanion
                        | StandbyTableKind::NonSequencedActStampedCanonicalLog
                        | StandbyTableKind::ExcludedOperational
                ),
                "unexpected legacy snapshot prefix kind for {table}: {kind:?}"
            );
        }
        assert_eq!(
            set(crate::standby::generation_store::UNFENCED_EXACT),
            set(&["storage_portability_policy"])
        );
        assert_eq!(
            names_of(StandbyTableKind::DerivedGlobal),
            set(DERIVED_GLOBAL_TABLES)
        );
        assert!(DERIVED_GLOBAL_TABLES.is_empty());
    }
}
