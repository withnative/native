//! Reviewed v1 source-table disposition. Unknown tables block cutover.
//! Imported means consumed by an existing import lane (selection/history
//! options still apply); it does not certify every row activated on v2.
use super::*;

const IMPORTED: &[&str] = &[
    "account_configs",
    "agent_message_dispositions",
    "agent_runs",
    "alpha_tab_installs",
    "alpha_tab_orders",
    "annotation_targets",
    "artifact_inputs",
    "artifact_module_grants",
    "artifact_source_attestations",
    "awareness_events",
    "bindings",
    "blobs",
    "canvas_batches",
    "canvas_objects",
    "content_events",
    "control_events",
    "database_identity",
    "facet_observations",
    "facet_times",
    "facet_values",
    "human_message_awareness",
    "instruction_bindings",
    "links",
    "member_contexts",
    "member_destinations",
    "member_obligation_progress",
    "member_obligations",
    "message_audience_state",
    "message_audiences",
    "message_conversations",
    "message_inbox_routing",
    "message_mentions",
    "message_origin_principals",
    "message_origin_state",
    "message_preferences",
    "message_speakers",
    "module_release_imports",
    "module_releases",
    "notification_candidate_events",
    "notification_candidates",
    "onboarding_programme_sources",
    "onboarding_programmes",
    "personas",
    "policy_entries",
    "policy_events",
    "read_log_calls",
    "record_policies",
    "records",
    "relationship_events",
    "relationship_legacy_links",
    "schema_config",
    "seeded_instruction_sources",
    "vocabularies",
    "vocabulary_values",
];

// Explicitly discarded projections, caches and unsupported domain state.
// This list is deliberately literal: a new source table must be reviewed.
const INTENTIONALLY_DROPPED: &[&str] = &[
    "act_cutover",
    "act_state",
    "attribution_assertions",
    "attribution_evidence",
    "attribution_retractions",
    "attribution_targets",
    "authorization_grant_revision",
    "authorization_revision",
    // Derived viewer fences and transaction-only certification are not v2
    // authority. The importer reconstructs access from policies and bindings.
    "authorization_subject_birth_fence",
    "authorization_subject_births",
    "authorization_subject_revision",
    "awareness_command_intents",
    "awareness_event_evidence",
    "binding_audit",
    "binding_systems",
    "body_blocks",
    "body_task_items",
    "content_event_causal_cutover",
    "content_event_causal_frontier",
    "content_event_claim_meta",
    "content_event_heads",
    "content_event_reaction_meta",
    "content_event_sources",
    "control_event_applications",
    "database_identity_audit",
    "dependencies",
    "dependency_assessments",
    "dependency_audits",
    "derivation_artifact_role_assignments",
    "derivation_artifact_role_heads",
    "derivation_artifact_role_retirements",
    "derivation_attempts",
    "derivation_confirmation_heads",
    "derivation_confirmation_retractions",
    "derivation_event_applications",
    "derivation_events",
    "derivation_requests",
    "derivation_revision_confirmations",
    "derivation_revision_inputs",
    "derivation_revisions",
    "derivation_selected_publications",
    "derivation_series",
    "derivation_target_bindings",
    "derivation_target_heads",
    "derivation_target_publications",
    "destination_message_ingest",
    "effective_relationships",
    "embeddings",
    "engine_migration_drills",
    "external_observations",
    "facet_observation_json_nodes",
    "facet_value_json_nodes",
    "freshness_command_results",
    "freshness_runtime_command_results",
    "jobs",
    "meta_events",
    "occurrences",
    "provenance_action_app_attributions",
    "provenance_action_attestations",
    "provenance_action_events",
    "provenance_action_outputs",
    "provenance_attestation_validity_events",
    "provenance_interaction_receipts",
    "provenance_local_attestation_authority",
    "read_log_record_ids",
    "read_log_touches",
    "receipt_comparisons",
    "receipt_provenance",
    "receipt_uncertainty_lineage",
    "receipts",
    "recipe_release_input_classes",
    "recipe_releases",
    "reconciliations",
    "record_body_json_nodes",
    "record_mentions",
    "records_fts",
    "records_fts_config",
    "records_fts_data",
    "records_fts_docsize",
    "records_fts_idx",
    "records_name_idx",
    "records_name_idx_config",
    "records_name_idx_data",
    "records_name_idx_docsize",
    "records_name_idx_idx",
    "relationship_assertion_heads",
    "relationship_endpoint_activity",
    "relationship_endpoints",
    "relationship_federation_events",
    "relationship_federation_quarantine",
    "relationship_foreign_action_attestations",
    "relationship_foreign_action_outputs",
    "relationship_local_admissions",
    "relationships",
    "replicated_message_provenance",
    "replicated_message_references",
    "schema_config_json_nodes",
    "semantic_units",
    "sql_write_receipts",
    "storage_portability_policy",
    "unit_heads",
    "unit_revisions",
    "unit_supersessions",
    "vocabulary_value_json_nodes",
    "webhook_credentials",
    "webhook_deliveries",
    "webhook_endpoints",
    "workspace_rule_installations",
];

#[derive(Default, Serialize)]
pub struct TableCoverage {
    pub imported: Vec<String>,
    pub intentionally_dropped: Vec<String>,
    pub unclassified: Vec<String>,
}

pub(super) async fn check(source: &mut SqliteConnection) -> Result<TableCoverage> {
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' ORDER BY name").fetch_all(source).await?;
    let mut coverage = TableCoverage::default();
    for name in names {
        if IMPORTED.contains(&name.as_str()) {
            coverage.imported.push(name);
        } else if INTENTIONALLY_DROPPED.contains(&name.as_str()) {
            coverage.intentionally_dropped.push(name);
        } else {
            coverage.unclassified.push(name);
        }
    }
    Ok(coverage)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn current_engine_tables_are_classified_and_unknown_tables_still_refuse() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut conn = db.write_pool().acquire().await.unwrap();
        let coverage = super::check(&mut conn).await.unwrap();
        assert!(
            coverage.unclassified.is_empty(),
            "{:?}",
            coverage.unclassified
        );
        for table in [
            "authorization_subject_revision",
            "authorization_subject_births",
            "authorization_subject_birth_fence",
        ] {
            assert!(coverage
                .intentionally_dropped
                .iter()
                .any(|name| name == table));
        }
        sqlx::query("CREATE TABLE unreviewed_import_state (id TEXT)")
            .execute(&mut *conn)
            .await
            .unwrap();
        assert_eq!(
            super::check(&mut conn).await.unwrap().unclassified,
            ["unreviewed_import_state"]
        );
    }
}
