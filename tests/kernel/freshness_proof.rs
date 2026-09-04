use crate::freshness_contract::{scenarios, sqlite, FreshnessHarness, SqliteFreshnessHarness};

#[tokio::test]
async fn sqlite_executes_the_shared_twelve_step_freshness_contract() {
    let harness = SqliteFreshnessHarness::new();
    let database = harness.fresh_database().await.unwrap();
    let evidence = scenarios::twelve_step(&harness, &database).await.unwrap();
    scenarios::assert_audit_outcomes(&evidence);
    assert_ne!(
        evidence.unit_id.as_str(),
        "f9e50000-0000-4000-8000-000000000007"
    );
    assert_ne!(evidence.u1, evidence.u2);
    assert_ne!(evidence.first_receipt, evidence.provisional_receipt);
    assert_eq!(
        evidence.relocation,
        native_ce::freshness::OccurrenceResolutionState::Relocated
    );
    assert_eq!(
        evidence.broken_anchor,
        native_ce::freshness::OccurrenceResolutionState::Stale
    );
    harness.close(&database).await;
}

#[tokio::test]
async fn concurrent_high_water_is_one_coherent_boundary() {
    let trace = sqlite::concurrent_high_water_trace().await.unwrap();
    assert!(trace.captured.content_seq < trace.source_revision_committed_during_pause.revision_seq);
    assert_eq!(trace.selected_revisions.len(), 1);
    assert!(trace.sealed_comparisons.is_empty());
    assert!(trace.receipt_revision_seq > trace.source_revision_committed_during_pause.revision_seq);
    assert_eq!(trace.immediate_impacts.len(), 1);
    assert_eq!(
        trace.immediate_impacts[0].pinned_source_revision,
        trace.selected_revisions[0]
    );
    assert_eq!(
        trace.immediate_impacts[0].candidate_source_revision,
        trace.source_revision_committed_during_pause
    );
    assert_eq!(
        trace.control_selected_revisions,
        vec![trace.source_revision_committed_during_pause.clone()]
    );
    assert_eq!(trace.control_comparisons.len(), 1);
}

#[tokio::test]
async fn aggregate_receipt_rolls_back_at_every_projection_boundary() {
    let matrix = sqlite::atomic_failure_matrix().await.unwrap();
    assert_eq!(matrix.len(), 11);
    for row in matrix {
        assert_eq!(row.before, row.after_failure, "stage={}", row.stage);
        assert_eq!(row.committed, row.identical_retry, "stage={}", row.stage);
        assert!(
            !row.error.is_empty(),
            "stage={} produced no failure evidence",
            row.stage
        );
        assert!(
            row.after_changed_intent.content_events > row.before.content_events,
            "stage={} did not eventually commit exactly one package",
            row.stage
        );
    }
}

#[tokio::test]
async fn authority_bearer_archive_and_deletion_fail_closed() {
    let evidence = sqlite::authority_lifecycle_evidence().await.unwrap();
    assert!(evidence.archived_unit_readable);
    assert_eq!(
        evidence.archived_occurrence_state,
        native_ce::freshness::OccurrenceResolutionState::Current
    );
    assert!(!evidence.deleted_unit_error.is_empty());
    assert!(!evidence.deleted_occurrence_error.is_empty());
    assert_eq!(
        evidence.deleted_explanation_completeness,
        native_ce::freshness::ProvenanceCompleteness::Withheld
    );
    assert_eq!(evidence.deleted_visible_dependency_count, 0);
}

#[tokio::test]
async fn missing_historical_bytes_preserve_address_and_siblings() {
    let evidence = sqlite::missing_representation_evidence().await.unwrap();
    assert_eq!(
        evidence.resolution.state,
        native_ce::freshness::OccurrenceResolutionState::Unavailable
    );
    assert_eq!(
        evidence.resolution.original_artefact_revision,
        evidence.expected_original_artefact_revision
    );
    assert_eq!(
        evidence.resolution.original_artefact_revision.sha256,
        evidence.expected_original_artefact_revision.sha256
    );
    assert!(evidence.resolution.current_range.is_none());
    assert_eq!(
        evidence.sibling_resolution.state,
        native_ce::freshness::OccurrenceResolutionState::Current
    );
    assert!(evidence.unit_still_readable);
}

#[tokio::test]
async fn all_freshness_projections_rebuild_exactly_from_authoritative_events() {
    let tables = sqlite::full_freshness_replay_evidence().await.unwrap();
    assert_eq!(tables.len(), 15);
    assert!(tables.iter().all(|table| {
        table.live > 0 && table.live == table.rebuilt && table.mismatches.is_empty()
    }));
}

#[tokio::test]
async fn commit_reauthorizes_and_restores_without_partial_occupancy() {
    let evidence = sqlite::revocation_between_assembly_and_commit()
        .await
        .unwrap();
    assert!(!evidence.rejected_error.is_empty());
    assert_eq!(
        evidence.content_events_before,
        evidence.content_events_after_rejection
    );
    assert_eq!(evidence.occupied_keys_after_rejection, 0);
    assert!(!evidence.restored_receipt.as_str().is_empty());
}

#[tokio::test]
async fn secondary_occurrence_does_not_bypass_original_authority() {
    let evidence = sqlite::secondary_occurrence_without_authority()
        .await
        .unwrap();
    assert!(evidence.secondary_artefact_accessible);
    assert!(!evidence.unit_error.is_empty());
    assert!(!evidence.occurrence_error.is_empty());
    assert_eq!(evidence.secondary_history_occurrence_events, 0);
}

#[tokio::test]
async fn plural_supersession_is_explicit_and_authorization_filtered() {
    let evidence = sqlite::plural_supersession_evidence().await.unwrap();
    assert_eq!(evidence.single_terminal.len(), 1);
    assert_eq!(evidence.plural_terminals.len(), 2);
    assert!(evidence.plural_ambiguous);
    assert_eq!(evidence.filtered_terminals.len(), 1);
    assert!(!evidence.filtered_ambiguous);
    assert!(evidence.filtered_withheld);
    assert_ne!(evidence.historical_dependency, evidence.single_terminal[0]);
}

#[tokio::test]
async fn authorization_filters_before_aggregate_without_hidden_counts() {
    let evidence = sqlite::authorization_leakage_matrix().await.unwrap();
    assert_eq!(evidence.one_hidden_shape, evidence.two_hidden_shape);
    assert!(evidence.secret_strings_absent);
    assert_eq!(evidence.impact_candidates_visible, 0);
    assert!(evidence.impact_withheld);
}

#[tokio::test]
async fn generic_unit_body_mutation_is_rejected() {
    let error = sqlite::generic_unit_body_mutation_error().await.unwrap();
    assert!(
        error.contains("body changes require unit.revision.recorded.v1"),
        "{error}"
    );
}

#[tokio::test]
async fn contract_falsifier_hidden_semantic_ids_match_nonexistent_ids() {
    let evidence = sqlite::occupancy_differential().await.unwrap();
    let normalize = |value: &str| {
        value
            // The Unit is a record, so its id is now a UUID; the absent Unit
            // id must stay the same shape or the comparison would be trivial.
            .replace("f9e50000-0000-4000-8000-000000000208", "<id>")
            .replace("f9e50000-0000-4000-8000-0000000004ff", "<id>")
            .replace("occupancy:occurrence", "<id>")
            .replace("occupancy:absent-occurrence", "<id>")
    };
    assert_eq!(
        normalize(&evidence.hidden_unit_error),
        normalize(&evidence.absent_unit_error),
        "hidden Unit occupancy leaked through a distinguishable error"
    );
    assert_eq!(
        normalize(&evidence.hidden_occurrence_error),
        normalize(&evidence.absent_occurrence_error),
        "hidden Occurrence occupancy leaked through a distinguishable error"
    );
}

#[tokio::test]
async fn contract_falsifier_explanation_reconstructs_required_evidence() {
    let harness = SqliteFreshnessHarness::new();
    let database = harness.fresh_database().await.unwrap();
    let evidence = scenarios::twelve_step(&harness, &database).await.unwrap();
    let original = harness
        .explain(&database, evidence.first_receipt.clone())
        .await
        .unwrap();
    let provisional = harness
        .explain(&database, evidence.provisional_receipt.clone())
        .await
        .unwrap();

    let expected_request = native_ce::freshness::ContextRequest {
        intent: "Draft positioning".into(),
        task_scope: "homepage hero".into(),
        risk_inputs: vec!["audience accuracy".into()],
    };
    let mut first_policy = native_ce::freshness::ResolutionPolicy::agent_speed_default();
    first_policy.dependency_budget = 1;
    assert_eq!(original.receipt_id, evidence.first_receipt);
    assert_eq!(original.output_revision, evidence.first_output_revision);
    assert_eq!(
        original.history_high_water,
        evidence.first_history_high_water
    );
    assert_eq!(original.context_request, expected_request);
    assert_eq!(original.resolution_policy, first_policy);
    assert_eq!(
        original.execution,
        native_ce::freshness::ExecutionDisposition::Continued
    );
    assert_eq!(
        original.disclosure,
        native_ce::freshness::DisclosureDecision::Silent
    );
    assert_eq!(original.visible_provenance.len(), 3);
    assert!(original
        .visible_provenance
        .iter()
        .any(|item| item.source_revision == evidence.u1));
    assert_eq!(original.visible_dependencies.len(), 1);
    assert_eq!(
        original.visible_dependencies[0].dependency_id.as_str(),
        "proof:dc1"
    );
    assert_eq!(
        original.visible_dependencies[0].source_revision,
        evidence.u1
    );

    assert_eq!(original.visible_comparisons.len(), 1);
    let comparison = &original.visible_comparisons[0];
    assert_eq!(
        comparison.observed_in_receipt_id,
        evidence.provisional_receipt
    );
    assert_eq!(comparison.dependency_receipt_id, evidence.first_receipt);
    assert_eq!(comparison.dependency_id.as_str(), "proof:dc1");
    assert_eq!(comparison.consumer_revision, evidence.first_output_revision);
    assert_eq!(comparison.pinned_source_revision, evidence.u1);
    assert_eq!(comparison.selected_source_revision, evidence.u2);
    assert_eq!(comparison.task_scope, "homepage hero");
    assert_eq!(
        comparison.affected_conclusion.key,
        "hero.audience_and_language"
    );
    assert_eq!(
        comparison.affected_conclusion.description,
        "Audience named by the homepage hero"
    );
    assert_eq!(
        comparison.history_high_water,
        evidence.provisional_history_high_water
    );
    assert!(comparison.mismatch);

    assert_eq!(original.visible_assessments.len(), 1);
    let assessment = &original.visible_assessments[0];
    assert_eq!(
        assessment.observed_in_receipt_id,
        evidence.provisional_receipt
    );
    assert_eq!(assessment.dependency_receipt_id, evidence.first_receipt);
    assert_eq!(assessment.assessment_id.as_str(), "proof:assessment-h");
    assert_eq!(assessment.dependency_id.as_str(), "proof:dc1");
    assert_eq!(assessment.consumer_revision, evidence.first_output_revision);
    assert_eq!(assessment.pinned_source_revision, evidence.u1);
    assert_eq!(assessment.compared_source_revision, evidence.u2);
    assert_eq!(assessment.task_scope, "homepage hero");
    assert_eq!(
        assessment.affected_conclusion,
        comparison.affected_conclusion
    );
    assert_eq!(
        assessment.history_high_water,
        evidence.provisional_history_high_water
    );
    assert_eq!(assessment.category, "positioning");
    assert_eq!(
        assessment.outcome,
        native_ce::freshness::MaterialityOutcome::MateriallyUncertain
    );
    assert!(assessment.could_materially_change);
    assert_eq!(
        assessment.rationale,
        "This could materially change the audience language"
    );
    assert_eq!(assessment.evaluator, "test:freshness-contract");

    assert_eq!(original.visible_reconciliations.len(), 1);
    let reconciliation = &original.visible_reconciliations[0];
    assert_eq!(
        reconciliation.reconciliation_id.as_str(),
        "proof:reconcile-dc1-u2"
    );
    assert_eq!(reconciliation.dependency_id.as_str(), "proof:dc1");
    assert_eq!(
        reconciliation.consumer_revision,
        evidence.first_output_revision
    );
    assert_eq!(reconciliation.pinned_source_revision, evidence.u1);
    assert_eq!(reconciliation.assessed_source_revision, evidence.u2);
    assert_eq!(reconciliation.task_scope, "homepage hero");
    assert_eq!(
        reconciliation.affected_conclusion,
        comparison.affected_conclusion
    );
    assert_eq!(
        reconciliation.outcome,
        native_ce::freshness::MaterialityOutcome::RemainsValid
    );
    assert_eq!(
        reconciliation.rationale,
        "The provisional replacement incorporates the exact audience change"
    );
    assert_eq!(reconciliation.actor, "test:freshness-contract");
    assert_eq!(reconciliation.resolving_receipt_id, None);
    assert_eq!(reconciliation.resolving_output_revision, None);

    assert_eq!(original.visible_dependency_audits.len(), 1);
    let audit = &original.visible_dependency_audits[0];
    assert_eq!(audit.receipt_id, evidence.first_receipt);
    assert_eq!(
        audit.declared_dependency_id.as_ref().map(|id| id.as_str()),
        Some("proof:dc1")
    );
    assert_eq!(audit.observed_dependency, None);
    assert_eq!(
        audit.outcome,
        native_ce::freshness::DependencyAuditOutcome::Confirmed
    );
    assert_eq!(
        audit.rationale,
        "The audience premise is genuinely load-bearing"
    );
    assert_eq!(audit.actor, "test:freshness-contract");

    assert_eq!(original.visible_occurrence_evidence.len(), 2);
    let occurrence = |id: &str| {
        original
            .visible_occurrence_evidence
            .iter()
            .find(|item| item.occurrence.occurrence_id.as_str() == id)
            .unwrap()
    };
    let oa = occurrence("proof:occurrence-a");
    assert_eq!(oa.occurrence.unit_revision, evidence.u1);
    assert_eq!(
        oa.occurrence.artefact_revision.subject_id,
        "f9e50000-0000-4000-8000-000000000007"
    );
    assert_eq!(
        oa.occurrence.selectors,
        vec![native_ce::freshness::OccurrenceSelector::TextQuote {
            exact: "The primary launch audience is technical founders.".into(),
            prefix: None,
            suffix: None,
            position_hint: Some(0),
        }]
    );
    assert_eq!(
        oa.resolution.state,
        native_ce::freshness::OccurrenceResolutionState::Relocated
    );
    assert_eq!(
        oa.resolution.original_artefact_revision,
        oa.occurrence.artefact_revision
    );
    assert!(oa.resolution.current_range.is_some());
    let ob = occurrence("proof:occurrence-b");
    assert_eq!(ob.occurrence.unit_revision, evidence.u1);
    assert_eq!(
        ob.occurrence.artefact_revision.subject_id,
        "f9e50000-0000-4000-8000-000000000008"
    );
    assert_eq!(
        ob.occurrence.selectors,
        vec![native_ce::freshness::OccurrenceSelector::TextQuote {
            exact: "We are initially building for founders who are comfortable working directly with technical tools.".into(),
            prefix: None,
            suffix: None,
            position_hint: Some(0),
        }]
    );
    assert_eq!(
        ob.resolution.state,
        native_ce::freshness::OccurrenceResolutionState::Stale
    );
    assert_eq!(
        ob.resolution.original_artefact_revision,
        ob.occurrence.artefact_revision
    );
    assert_eq!(ob.resolution.current_range, None);
    assert!(original.visible_impacts.is_empty());
    assert!(original.unresolved_uncertainty.is_empty());

    assert_eq!(provisional.receipt_id, evidence.provisional_receipt);
    assert_eq!(
        provisional.output_revision,
        evidence.provisional_output_revision
    );
    assert_eq!(
        provisional.history_high_water,
        evidence.provisional_history_high_water
    );
    assert_eq!(provisional.context_request, expected_request);
    assert_eq!(
        provisional.resolution_policy,
        native_ce::freshness::ResolutionPolicy::agent_speed_default()
    );
    assert_eq!(
        provisional.execution,
        native_ce::freshness::ExecutionDisposition::Continued
    );
    assert_eq!(
        provisional.disclosure,
        native_ce::freshness::DisclosureDecision::SurfaceNow
    );
    assert_eq!(provisional.visible_dependencies.len(), 1);
    assert_eq!(
        provisional.visible_dependencies[0].dependency_id.as_str(),
        "proof:dc2-provisional"
    );
    assert_eq!(
        provisional.visible_dependencies[0].source_revision,
        evidence.u2
    );
    assert_eq!(provisional.visible_comparisons, vec![comparison.clone()]);
    assert_eq!(provisional.visible_assessments, vec![assessment.clone()]);
    assert_eq!(
        provisional.visible_reconciliations,
        vec![reconciliation.clone()]
    );
    assert!(provisional.visible_dependency_audits.is_empty());
    assert!(provisional.visible_occurrence_evidence.is_empty());
    assert!(provisional.visible_impacts.is_empty());
    assert!(provisional.unresolved_uncertainty.is_empty());
}

#[test]
fn shared_freshness_scenario_stays_above_physical_storage() {
    let source = include_str!("../freshness_contract/scenarios.rs");
    for forbidden in [
        "Db::",
        ".pool()",
        "sqlx::",
        "query_sql",
        "create_database",
        "tempfile",
        "Sqlite",
        "Postgres",
        "content_events",
        "semantic_units",
        "unit_revisions",
    ] {
        assert!(
            !source.contains(forbidden),
            "shared freshness scenario contains physical-storage token {forbidden:?}"
        );
    }
}
