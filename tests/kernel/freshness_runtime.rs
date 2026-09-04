use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability, Principal};
use native_ce::conformance::rebuild_and_diff;
use native_ce::freshness::*;
use native_ce::query::events::events_for_record;
use native_ce::store::{append, append_batch, create_record, update_record, AppendSpec};
use serde_json::json;

const ACTOR: &str = "test:receipt-runtime";
const ACCOUNT: &str = "acct:receipt-runtime";

fn principal() -> Principal<'static> {
    Principal::bound(ACCOUNT, true)
}

async fn document(db: &native_ce::Db, name: &str, body: &str) -> String {
    create_record(
        db,
        json!({"type":"Document","kind":"note","name":name,"body":body}),
    )
    .await
    .unwrap()
}

async fn promoted_unit(db: &native_ce::Db) -> PromoteIdeaResult {
    let source = document(db, "Idea source", "Audience: technical founders.").await;
    let source_revision = current_record_body_revision(db, &source).await.unwrap();
    promote_idea(
        db,
        principal(),
        ACTOR,
        PromoteIdeaInput {
            source_revision,
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: "Audience: technical founders.".into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            first_content: UnitContent::text("Primary audience: technical founders.").unwrap(),
            expression_role: ExpressionRole::Canonical,
            label: Some("Audience".into()),
            requested_unit_id: None,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("runtime-promote").unwrap(),
        },
    )
    .await
    .unwrap()
}

fn request(scope: &str) -> ContextRequest {
    ContextRequest {
        intent: "Draft positioning".into(),
        task_scope: scope.into(),
        risk_inputs: vec!["audience accuracy".into()],
    }
}

fn dependency(id: &str, source_revision: RevisionRef) -> DependencyInput {
    DependencyInput {
        dependency_id: DependencyId::new(id).unwrap(),
        source_revision,
        semantic_role: "audience premise".into(),
        affected_conclusion: AffectedConclusion {
            key: "hero.audience".into(),
            description: "Who the homepage addresses".into(),
        },
        rationale: "The output names the audience".into(),
        reconsideration_trigger: "Audience premise changes".into(),
        confidence: Some(0.9),
    }
}

async fn package(
    db: &native_ce::Db,
    consumer: &str,
    unit_id: &str,
    key: &str,
) -> CommitDurableOutputInput {
    let assembly = assemble_context(
        db,
        principal(),
        request("homepage hero"),
        Some(consumer),
        vec![unit_id.into()],
    )
    .await
    .unwrap();
    let source_revision = assembly.sources[0].clone();
    CommitDurableOutputInput {
        consumer_record_id: consumer.into(),
        expected_consumer_revision: current_record_body_revision(db, consumer).await.unwrap(),
        output_body: "Built for technical founders.".into(),
        assembly,
        policy: ResolutionPolicy::agent_speed_default(),
        provenance: vec![ProvenanceUse {
            source_revision: source_revision.clone(),
            reason: "Used to draft the audience line".into(),
        }],
        dependencies: vec![dependency(&format!("dep-{key}"), source_revision)],
        assessments: vec![],
        reconciliations: vec![],
        unresolved_uncertainty: vec![],
        idempotency_key: IdempotencyKey::new(key).unwrap(),
    }
}

async fn event_count(db: &native_ce::Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn durable_package_is_atomic_idempotent_and_prefix_safe() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let promoted = promoted_unit(&db).await;
    let consumer = document(&db, "Homepage", "Old homepage.").await;
    let mut input = package(&db, &consumer, promoted.unit_id.as_str(), "atomic-package").await;
    input.assembly.request.risk_inputs = vec!["zeta".into(), "alpha".into()];
    input.policy.hard_stop_categories = vec!["zeta".into(), "alpha".into()];
    let before = event_count(&db).await;

    for failure in [
        CommitFailurePoint::AfterOutput,
        CommitFailurePoint::AfterDependency(0),
        CommitFailurePoint::AfterDependencies,
        CommitFailurePoint::BeforeReceipt,
        CommitFailurePoint::BeforeCommit,
    ] {
        commit_durable_output_with_failure(&db, principal(), ACTOR, input.clone(), Some(failure))
            .await
            .unwrap_err();
        assert_eq!(event_count(&db).await, before);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM receipts")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            0
        );
    }

    let committed = commit_durable_output(&db, principal(), ACTOR, input.clone())
        .await
        .unwrap();
    assert_eq!(committed.execution, ExecutionDisposition::Continued);
    assert_eq!(committed.disclosure, DisclosureDecision::Silent);
    let explanation = explain_freshness(&db, principal(), committed.receipt_id.clone())
        .await
        .unwrap();
    let mut expected_request = input.assembly.request.clone();
    expected_request.risk_inputs.sort();
    expected_request.risk_inputs.dedup();
    let mut expected_policy = input.policy.clone();
    expected_policy.hard_stop_categories.sort();
    expected_policy.hard_stop_categories.dedup();
    assert_eq!(explanation.history_high_water, input.assembly.high_water);
    assert_eq!(explanation.context_request, expected_request);
    assert_eq!(explanation.resolution_policy, expected_policy);
    assert_eq!(explanation.visible_occurrence_evidence.len(), 1);
    assert_eq!(
        explanation.visible_occurrence_evidence[0]
            .occurrence
            .occurrence_id,
        promoted.occurrence_id
    );
    assert_eq!(
        explanation.visible_occurrence_evidence[0].resolution.state,
        OccurrenceResolutionState::Current
    );
    let mut reordered_retry = input.clone();
    reordered_retry.assembly.request.risk_inputs.reverse();
    reordered_retry.policy.hard_stop_categories.reverse();
    assert_eq!(
        commit_durable_output(&db, principal(), ACTOR, reordered_retry)
            .await
            .unwrap(),
        committed
    );
    let after = event_count(&db).await;
    assert_eq!(
        after,
        before + 1,
        "the whole package is one aggregate event"
    );
    let mut conflict = input;
    conflict.output_body = "Different output under the same key.".into();
    assert!(commit_durable_output(&db, principal(), ACTOR, conflict)
        .await
        .unwrap_err()
        .to_string()
        .contains("different runtime command"));
    assert_eq!(event_count(&db).await, after);

    let history = events_for_record(&db, &consumer, None, 100).await.unwrap();
    assert!(history
        .events
        .iter()
        .all(|event| !event.event_type.starts_with("dependency.")
            && event.event_type != "receipt.committed.v1"));
    assert_eq!(history.events.last().unwrap().event_type, "record.updated");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            history.events.last().unwrap().payload.as_deref().unwrap(),
        )
        .unwrap(),
        json!({"body":"Built for technical founders."})
    );
    let rebuilt = rebuild_and_diff(&db).await.unwrap();
    assert!(rebuilt.equal, "{:?}", rebuilt.tables);
}

#[tokio::test]
async fn public_append_cannot_bypass_runtime_receipt_completeness() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let promoted = promoted_unit(&db).await;
    let consumer = document(&db, "Head guard", "Initial.").await;
    let committed = commit_durable_output(
        &db,
        principal(),
        ACTOR,
        package(&db, &consumer, promoted.unit_id.as_str(), "head-r1").await,
    )
    .await
    .unwrap();
    let payload: serde_json::Value = serde_json::from_str(
        &sqlx::query_scalar::<_, String>("SELECT payload FROM content_events WHERE id=?")
            .bind(&committed.output_revision.revision_event_id)
            .fetch_one(db.pool())
            .await
            .unwrap(),
    )
    .unwrap();
    update_record(&db, &consumer, json!({"body":"Intervening edit."}))
        .await
        .unwrap();
    let before = event_count(&db).await;
    let mut omitted_comparisons = payload.clone();
    omitted_comparisons["comparisons"] = json!([]);
    let mut omitted_uncertainty = payload.clone();
    omitted_uncertainty["unresolved_uncertainty"] = json!([]);
    let mut false_withheld = payload.clone();
    false_withheld["withheld_context"] = json!(false);
    for adversarial in [
        payload,
        omitted_comparisons,
        omitted_uncertainty,
        false_withheld,
    ] {
        let single = AppendSpec {
            record_id: consumer.clone(),
            event_type: "receipt.committed.v1".into(),
            payload: adversarial.clone(),
            actor: Some(ACTOR.into()),
        };
        assert!(append(&db, single)
            .await
            .unwrap_err()
            .to_string()
            .contains("runtime-owned"));
        assert!(append_batch(
            &db,
            vec![AppendSpec {
                record_id: consumer.clone(),
                event_type: "receipt.committed.v1".into(),
                payload: adversarial,
                actor: Some(ACTOR.into()),
            }],
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("runtime-owned"));
        assert_eq!(event_count(&db).await, before);
    }
}

#[tokio::test]
async fn aggregate_receipt_projects_multiple_dependencies_and_assessments() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let unit_a = promoted_unit(&db).await;
    let unit_b = promoted_unit(&db).await;
    let consumer = document(&db, "Multi-evidence output", "Initial.").await;
    let before_orphan = event_count(&db).await;
    assert!(append(
        &db,
        AppendSpec {
            record_id: consumer.clone(),
            event_type: "dependency.declared.v1".into(),
            payload: json!({}),
            actor: Some(ACTOR.into()),
        },
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("unknown event type"));
    assert_eq!(event_count(&db).await, before_orphan);
    let requested_ids = vec![
        unit_a.unit_id.as_str().to_owned(),
        unit_b.unit_id.as_str().to_owned(),
    ];
    let assembly = assemble_context(
        &db,
        principal(),
        request("multi evidence"),
        Some(&consumer),
        requested_ids.clone(),
    )
    .await
    .unwrap();
    let r1_dependencies = assembly
        .sources
        .iter()
        .enumerate()
        .map(|(index, source)| dependency(&format!("multi-r1-{index}"), source.clone()))
        .collect();
    commit_durable_output(
        &db,
        principal(),
        ACTOR,
        CommitDurableOutputInput {
            consumer_record_id: consumer.clone(),
            expected_consumer_revision: current_record_body_revision(&db, &consumer).await.unwrap(),
            output_body: "First multi-evidence output.".into(),
            assembly,
            policy: ResolutionPolicy::agent_speed_default(),
            provenance: vec![],
            dependencies: r1_dependencies,
            assessments: vec![],
            reconciliations: vec![],
            unresolved_uncertainty: vec![],
            idempotency_key: IdempotencyKey::new("multi-r1").unwrap(),
        },
    )
    .await
    .unwrap();
    for (index, promoted) in [unit_a, unit_b].into_iter().enumerate() {
        revise_unit(
            &db,
            principal(),
            ACTOR,
            ReviseUnitInput {
                unit_id: promoted.unit_id,
                expected_current: promoted.first_revision,
                content: UnitContent::text(format!("Revised premise {index}.")).unwrap(),
                rationale: "Exercise aggregate multiplicity".into(),
                idempotency_key: IdempotencyKey::new(format!("multi-revise-{index}")).unwrap(),
            },
        )
        .await
        .unwrap();
    }
    let assembly = assemble_context(
        &db,
        principal(),
        request("multi evidence"),
        Some(&consumer),
        requested_ids,
    )
    .await
    .unwrap();
    assert_eq!(assembly.comparisons.len(), 2);
    let assessments = assembly
        .comparisons
        .iter()
        .enumerate()
        .map(|(index, comparison)| AssessmentInput {
            assessment_id: AssessmentId::new(format!("multi-assessment-{index}")).unwrap(),
            dependency_id: comparison.dependency_id.clone(),
            compared_source_revision: comparison.candidate_source_revision.clone(),
            category: "general".into(),
            outcome: MaterialityOutcome::RemainsValid,
            could_materially_change: false,
            rationale: "The output remains valid against this exact change".into(),
        })
        .collect();
    let dependencies = assembly
        .sources
        .iter()
        .enumerate()
        .map(|(index, source)| dependency(&format!("multi-r2-{index}"), source.clone()))
        .collect();
    let before = event_count(&db).await;
    let result = commit_durable_output(
        &db,
        principal(),
        ACTOR,
        CommitDurableOutputInput {
            consumer_record_id: consumer.clone(),
            expected_consumer_revision: current_record_body_revision(&db, &consumer).await.unwrap(),
            output_body: "Second multi-evidence output.".into(),
            assembly,
            policy: ResolutionPolicy::agent_speed_default(),
            provenance: vec![],
            dependencies,
            assessments,
            reconciliations: vec![],
            unresolved_uncertainty: vec![],
            idempotency_key: IdempotencyKey::new("multi-r2").unwrap(),
        },
    )
    .await
    .unwrap();
    assert_eq!(event_count(&db).await, before + 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM dependencies WHERE receipt_id=?")
            .bind(result.receipt_id.as_str())
            .fetch_one(db.pool())
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM dependency_assessments WHERE receipt_id=?",
        )
        .bind(result.receipt_id.as_str())
        .fetch_one(db.pool())
        .await
        .unwrap(),
        2
    );
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn assessment_coverage_binds_the_entire_sealed_revision_reference() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let promoted = promoted_unit(&db).await;
    let consumer = document(&db, "Exact assessment binding", "Initial.").await;
    let first = commit_durable_output(
        &db,
        principal(),
        ACTOR,
        package(
            &db,
            &consumer,
            promoted.unit_id.as_str(),
            "exact-binding-u1",
        )
        .await,
    )
    .await
    .unwrap();
    let revised = revise_unit(
        &db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id,
            expected_current: promoted.first_revision,
            content: UnitContent::text("Primary audience: operations leaders.").unwrap(),
            rationale: "Audience changed".into(),
            idempotency_key: IdempotencyKey::new("exact-binding-revise").unwrap(),
        },
    )
    .await
    .unwrap();
    let assembly = assemble_context(
        &db,
        principal(),
        request("exact binding"),
        Some(&consumer),
        vec![revised.new_revision.subject_id.clone()],
    )
    .await
    .unwrap();
    let comparison = assembly.comparisons[0].clone();
    let mut forged = revised.new_revision.clone();
    forged.sha256 = "0".repeat(64);
    let error = commit_durable_output(
        &db,
        principal(),
        ACTOR,
        CommitDurableOutputInput {
            consumer_record_id: consumer,
            expected_consumer_revision: first.output_revision,
            output_body: "Attempted forged assessment binding.".into(),
            assembly,
            policy: ResolutionPolicy::agent_speed_default(),
            provenance: vec![ProvenanceUse {
                source_revision: revised.new_revision.clone(),
                reason: "Used the exact current audience".into(),
            }],
            dependencies: vec![dependency("exact-binding-u2", revised.new_revision)],
            assessments: vec![AssessmentInput {
                assessment_id: AssessmentId::new("exact-binding-assessment").unwrap(),
                dependency_id: comparison.dependency_id,
                compared_source_revision: forged,
                category: "general".into(),
                outcome: MaterialityOutcome::RemainsValid,
                could_materially_change: false,
                rationale: "Purportedly assessed the sealed change".into(),
            }],
            reconciliations: vec![],
            unresolved_uncertainty: vec![],
            idempotency_key: IdempotencyKey::new("exact-binding-u2").unwrap(),
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("every sealed comparison requires exactly one task-relative assessment"),
        "{error}"
    );
}

#[tokio::test]
async fn package_reconciliation_is_atomic_conflict_aware_and_replayable() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let promoted = promoted_unit(&db).await;
    let original_occurrence = list_occurrences(&db, principal(), &promoted.unit_id)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let secondary_text = "The launch audience includes technical founders.";
    let secondary_source = document(&db, "Secondary audience expression", secondary_text).await;
    let secondary_revision = current_record_body_revision(&db, &secondary_source)
        .await
        .unwrap();
    let secondary_occurrence = bind_occurrence(
        &db,
        principal(),
        ACTOR,
        BindOccurrenceInput {
            unit_revision: promoted.first_revision.clone(),
            artefact_revision: secondary_revision,
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: secondary_text.into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            expression_role: ExpressionRole::Paraphrase,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("recon-secondary-occurrence").unwrap(),
        },
    )
    .await
    .unwrap();
    let consumer = document(&db, "Atomic reconciliation", "Initial.").await;
    let first = commit_durable_output(
        &db,
        principal(),
        ACTOR,
        package(&db, &consumer, promoted.unit_id.as_str(), "recon-u1").await,
    )
    .await
    .unwrap();
    let u2 = revise_unit(
        &db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id.clone(),
            expected_current: promoted.first_revision.clone(),
            content: UnitContent::text("Primary audience: operations leaders.").unwrap(),
            rationale: "Audience changed".into(),
            idempotency_key: IdempotencyKey::new("recon-revise-u2").unwrap(),
        },
    )
    .await
    .unwrap();
    let assembly = assemble_context(
        &db,
        principal(),
        request("homepage hero"),
        Some(&consumer),
        vec![u2.new_revision.subject_id.clone()],
    )
    .await
    .unwrap();
    let comparison = assembly.comparisons[0].clone();
    let conclusion =
        dependency("shape", comparison.pinned_source_revision.clone()).affected_conclusion;
    let input = CommitDurableOutputInput {
        consumer_record_id: consumer.clone(),
        expected_consumer_revision: first.output_revision.clone(),
        output_body: "Updated for operations leaders.".into(),
        policy: ResolutionPolicy::agent_speed_default(),
        provenance: vec![ProvenanceUse {
            source_revision: u2.new_revision.clone(),
            reason: "Used the current audience".into(),
        }],
        dependencies: vec![dependency("dep-recon-u2", u2.new_revision.clone())],
        assessments: vec![AssessmentInput {
            assessment_id: AssessmentId::new("assessment-recon-u2").unwrap(),
            dependency_id: comparison.dependency_id.clone(),
            compared_source_revision: u2.new_revision.clone(),
            category: "general".into(),
            outcome: MaterialityOutcome::RemainsValid,
            could_materially_change: false,
            rationale: "Replacement output incorporates the change".into(),
        }],
        reconciliations: vec![ReconciliationEvidence {
            reconciliation_id: ReconciliationId::new("package-reconcile-u2").unwrap(),
            dependency_id: comparison.dependency_id.clone(),
            consumer_revision: first.output_revision.clone(),
            pinned_source_revision: comparison.pinned_source_revision.clone(),
            assessed_source_revision: u2.new_revision.clone(),
            task_scope: "homepage hero".into(),
            affected_conclusion: conclusion.clone(),
            outcome: MaterialityOutcome::RemainsValid,
            rationale: "The replacement output resolves this exact debt".into(),
        }],
        unresolved_uncertainty: vec![],
        idempotency_key: IdempotencyKey::new("package-reconcile-command").unwrap(),
        assembly,
    };
    let before = event_count(&db).await;
    let mut omitted = input.clone();
    omitted.assembly.comparisons.clear();
    omitted.assessments.clear();
    omitted.reconciliations.clear();
    omitted.idempotency_key = IdempotencyKey::new("omitted-comparison-command").unwrap();
    assert!(commit_durable_output(&db, principal(), ACTOR, omitted)
        .await
        .unwrap_err()
        .to_string()
        .contains("comparisons are incomplete"));
    assert_eq!(event_count(&db).await, before);
    let mut contradictory_materiality = input.clone();
    contradictory_materiality.assessments[0].could_materially_change = true;
    contradictory_materiality.idempotency_key =
        IdempotencyKey::new("contradictory-materiality-command").unwrap();
    assert!(
        commit_durable_output(&db, principal(), ACTOR, contradictory_materiality)
            .await
            .unwrap_err()
            .to_string()
            .contains("materiality flag contradicts")
    );
    assert_eq!(event_count(&db).await, before);
    let mut unassessed = input.clone();
    unassessed.assessments.clear();
    unassessed.reconciliations.clear();
    unassessed.idempotency_key = IdempotencyKey::new("unassessed-comparison-command").unwrap();
    assert!(commit_durable_output(&db, principal(), ACTOR, unassessed)
        .await
        .unwrap_err()
        .to_string()
        .contains("exactly one task-relative assessment"));
    assert_eq!(event_count(&db).await, before);
    for failure in [
        CommitFailurePoint::AfterAssessment(0),
        CommitFailurePoint::AfterReconciliation(0),
        CommitFailurePoint::BeforeReceipt,
        CommitFailurePoint::BeforeCommit,
    ] {
        commit_durable_output_with_failure(&db, principal(), ACTOR, input.clone(), Some(failure))
            .await
            .unwrap_err();
        assert_eq!(event_count(&db).await, before);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM reconciliations")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            0
        );
    }
    let committed = commit_durable_output(&db, principal(), ACTOR, input.clone())
        .await
        .unwrap();
    let resolving: (String, String) = sqlx::query_as(
        "SELECT resolving_receipt_id,resolving_output_revision_event_id
           FROM reconciliations WHERE reconciliation_id='package-reconcile-u2'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(resolving.0, committed.receipt_id.as_str());
    assert_eq!(resolving.1, committed.output_revision.revision_event_id);
    update_record(
        &db,
        &original_occurrence.artefact_revision.subject_id,
        json!({"body":"Context before.\n\nAudience: technical founders.\n\nContext after."}),
    )
    .await
    .unwrap();
    update_record(
        &db,
        &secondary_source,
        json!({"body":"The secondary expression was removed."}),
    )
    .await
    .unwrap();

    let explanation = explain_freshness(&db, principal(), committed.receipt_id.clone())
        .await
        .unwrap();
    assert_eq!(explanation.visible_comparisons.len(), 1);
    let sealed_comparison = &explanation.visible_comparisons[0];
    assert_eq!(
        sealed_comparison.observed_in_receipt_id,
        committed.receipt_id
    );
    assert_eq!(sealed_comparison.dependency_receipt_id, first.receipt_id);
    assert_eq!(sealed_comparison.dependency_id, comparison.dependency_id);
    assert_eq!(sealed_comparison.consumer_revision, first.output_revision);
    assert_eq!(
        sealed_comparison.pinned_source_revision,
        promoted.first_revision
    );
    assert_eq!(sealed_comparison.selected_source_revision, u2.new_revision);
    assert_eq!(sealed_comparison.task_scope, "homepage hero");
    assert_eq!(sealed_comparison.affected_conclusion, conclusion);
    assert_eq!(
        sealed_comparison.history_high_water,
        input.assembly.high_water
    );
    assert!(sealed_comparison.mismatch);
    assert_eq!(explanation.visible_assessments.len(), 1);
    let assessment = &explanation.visible_assessments[0];
    assert_eq!(assessment.observed_in_receipt_id, committed.receipt_id);
    assert_eq!(assessment.dependency_receipt_id, first.receipt_id);
    assert_eq!(assessment.assessment_id.as_str(), "assessment-recon-u2");
    assert_eq!(assessment.pinned_source_revision, promoted.first_revision);
    assert_eq!(assessment.compared_source_revision, u2.new_revision);
    assert_eq!(assessment.task_scope, "homepage hero");
    assert_eq!(assessment.affected_conclusion, conclusion);
    assert_eq!(assessment.outcome, MaterialityOutcome::RemainsValid);
    assert_eq!(assessment.evaluator, ACTOR);
    assert_eq!(
        assessment.rationale,
        "Replacement output incorporates the change"
    );
    assert_eq!(explanation.visible_reconciliations.len(), 1);
    assert_eq!(
        explanation.visible_reconciliations[0]
            .reconciliation_id
            .as_str(),
        "package-reconcile-u2"
    );
    assert_eq!(
        explanation.visible_reconciliations[0]
            .resolving_receipt_id
            .as_ref(),
        Some(&committed.receipt_id)
    );
    assert!(explanation.visible_occurrence_evidence.is_empty());

    let original_explanation = explain_freshness(&db, principal(), first.receipt_id.clone())
        .await
        .unwrap();
    assert!(original_explanation.visible_impacts.is_empty());
    assert_eq!(original_explanation.visible_dependencies.len(), 1);
    assert_eq!(
        original_explanation.visible_dependencies[0].source_revision,
        promoted.first_revision
    );
    assert_eq!(original_explanation.visible_comparisons.len(), 1);
    assert_eq!(
        original_explanation.visible_comparisons[0],
        sealed_comparison.clone()
    );
    assert_eq!(original_explanation.visible_assessments.len(), 1);
    assert_eq!(
        original_explanation.visible_assessments[0],
        assessment.clone()
    );
    assert_eq!(original_explanation.visible_reconciliations.len(), 1);
    assert_eq!(original_explanation.visible_occurrence_evidence.len(), 2);
    let relocated = original_explanation
        .visible_occurrence_evidence
        .iter()
        .find(|evidence| evidence.occurrence.occurrence_id == original_occurrence.occurrence_id)
        .unwrap();
    assert_eq!(
        relocated.resolution.state,
        OccurrenceResolutionState::Relocated
    );
    assert_eq!(
        relocated.resolution.original_artefact_revision,
        original_occurrence.artefact_revision
    );
    let stale = original_explanation
        .visible_occurrence_evidence
        .iter()
        .find(|evidence| {
            evidence.occurrence.occurrence_id == secondary_occurrence.occurrence.occurrence_id
        })
        .unwrap();
    assert_eq!(stale.resolution.state, OccurrenceResolutionState::Stale);
    assert_eq!(
        stale.resolution.original_artefact_revision,
        secondary_occurrence.occurrence.artefact_revision
    );

    reconcile_dependency(
        &db,
        principal(),
        ACTOR,
        ReconcileDependencyInput {
            reconciliation_id: ReconciliationId::new("conflicting-reconcile-u2").unwrap(),
            dependency_id: comparison.dependency_id.clone(),
            assessed_source_revision: u2.new_revision.clone(),
            task_scope: "homepage hero".into(),
            outcome: MaterialityOutcome::Contradicted,
            rationale: "A later reviewer disputes the resolution".into(),
            idempotency_key: IdempotencyKey::new("conflicting-reconcile-command").unwrap(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        explain_freshness(&db, principal(), first.receipt_id)
            .await
            .unwrap()
            .visible_impacts
            .len(),
        1
    );
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn hard_stops_and_declared_or_omitted_dependency_audits_are_derived_and_replayable() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let promoted = promoted_unit(&db).await;
    let consumer = document(&db, "Policy", "Initial.").await;
    let first = commit_durable_output(
        &db,
        principal(),
        ACTOR,
        package(&db, &consumer, promoted.unit_id.as_str(), "policy-u1").await,
    )
    .await
    .unwrap();
    let revised = revise_unit(
        &db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id,
            expected_current: promoted.first_revision,
            content: UnitContent::text("Primary audience: safety-critical operators.").unwrap(),
            rationale: "Safety category changed".into(),
            idempotency_key: IdempotencyKey::new("policy-revise").unwrap(),
        },
    )
    .await
    .unwrap();
    let assembly = assemble_context(
        &db,
        principal(),
        request("policy copy"),
        Some(&consumer),
        vec![revised.new_revision.subject_id.clone()],
    )
    .await
    .unwrap();
    let comparison = assembly.comparisons[0].clone();
    let mut policy = ResolutionPolicy::agent_speed_default();
    policy.hard_stop_categories = vec!["safety".into()];
    let committed = commit_durable_output(
        &db,
        principal(),
        ACTOR,
        CommitDurableOutputInput {
            consumer_record_id: consumer,
            expected_consumer_revision: first.output_revision,
            output_body: "Reviewed safety copy.".into(),
            assembly,
            policy,
            provenance: vec![ProvenanceUse {
                source_revision: revised.new_revision.clone(),
                reason: "Reviewed the latest audience".into(),
            }],
            dependencies: vec![dependency("dep-policy-u2", revised.new_revision.clone())],
            assessments: vec![AssessmentInput {
                assessment_id: AssessmentId::new("assessment-policy-u2").unwrap(),
                dependency_id: comparison.dependency_id,
                compared_source_revision: revised.new_revision.clone(),
                category: "safety".into(),
                outcome: MaterialityOutcome::Immaterial,
                could_materially_change: false,
                rationale: "Text remains valid, but policy requires review".into(),
            }],
            reconciliations: vec![],
            unresolved_uncertainty: vec![],
            idempotency_key: IdempotencyKey::new("policy-u2").unwrap(),
        },
    )
    .await
    .unwrap();
    assert_eq!(committed.execution, ExecutionDisposition::Stopped);
    assert_eq!(committed.disclosure, DisclosureDecision::SurfaceNow);

    audit_dependency(
        &db,
        principal(),
        ACTOR,
        AuditDependencyInput {
            receipt_id: committed.receipt_id.clone(),
            declared_dependency_id: Some(DependencyId::new("dep-policy-u2").unwrap()),
            observed_dependency: None,
            outcome: DependencyAuditOutcome::Confirmed,
            rationale: "The declared premise is supported".into(),
            idempotency_key: IdempotencyKey::new("audit-declared").unwrap(),
        },
    )
    .await
    .unwrap();
    let duplicate_observation = audit_dependency(
        &db,
        principal(),
        ACTOR,
        AuditDependencyInput {
            receipt_id: committed.receipt_id.clone(),
            declared_dependency_id: None,
            observed_dependency: Some(dependency(
                "same-structure-different-id",
                revised.new_revision.clone(),
            )),
            outcome: DependencyAuditOutcome::Underdeclared,
            rationale: "Must not relabel a declared dependency as omitted".into(),
            idempotency_key: IdempotencyKey::new("audit-contradiction").unwrap(),
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(duplicate_observation.contains("already declared"));
    let mut genuinely_omitted = dependency("dep-audit-omitted", revised.new_revision);
    genuinely_omitted.semantic_role = "omitted operational constraint".into();
    genuinely_omitted.affected_conclusion.key = "hero.operational_constraint".into();
    genuinely_omitted.reconsideration_trigger = "Operational constraint changes".into();
    audit_dependency(
        &db,
        principal(),
        ACTOR,
        AuditDependencyInput {
            receipt_id: committed.receipt_id.clone(),
            declared_dependency_id: None,
            observed_dependency: Some(genuinely_omitted),
            outcome: DependencyAuditOutcome::Underdeclared,
            rationale: "Audit found an omitted semantic use".into(),
            idempotency_key: IdempotencyKey::new("audit-omitted").unwrap(),
        },
    )
    .await
    .unwrap();
    let explanation = explain_freshness(&db, principal(), committed.receipt_id)
        .await
        .unwrap();
    assert_eq!(explanation.visible_assessments.len(), 1);
    assert_eq!(explanation.visible_dependency_audits.len(), 2);
    assert_eq!(
        explanation.visible_dependency_audits[0].outcome,
        DependencyAuditOutcome::Confirmed
    );
    assert_eq!(
        explanation.visible_dependency_audits[1].outcome,
        DependencyAuditOutcome::Underdeclared
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM dependency_audits WHERE observed_dependency IS NOT NULL",
        )
        .fetch_one(db.pool())
        .await
        .unwrap(),
        1
    );
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn source_change_before_or_after_package_yields_the_same_exact_impact() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let promoted = promoted_unit(&db).await;
    let before_consumer = document(&db, "Before consumer", "Initial.").await;
    let after_consumer = document(&db, "After consumer", "Initial.").await;

    let before_input = package(
        &db,
        &before_consumer,
        promoted.unit_id.as_str(),
        "source-before",
    )
    .await;
    let after_input = package(
        &db,
        &after_consumer,
        promoted.unit_id.as_str(),
        "source-after",
    )
    .await;
    commit_durable_output(&db, principal(), ACTOR, after_input)
        .await
        .unwrap();
    let revised = revise_unit(
        &db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id.clone(),
            expected_current: promoted.first_revision.clone(),
            content: UnitContent::text("Primary audience: nontechnical operators.").unwrap(),
            rationale: "Positioning changed".into(),
            idempotency_key: IdempotencyKey::new("runtime-revise").unwrap(),
        },
    )
    .await
    .unwrap();
    assert!(before_input.assembly.high_water.content_seq < revised.new_revision.revision_seq);
    assert_eq!(
        before_input.assembly.sources,
        vec![promoted.first_revision.clone()],
        "a post-capture change must not tear the sealed assembly"
    );
    commit_durable_output(&db, principal(), ACTOR, before_input)
        .await
        .unwrap();

    for consumer in [&before_consumer, &after_consumer] {
        let impacts = list_impact_candidates(&db, principal(), consumer)
            .await
            .unwrap();
        assert!(!impacts.withheld_context);
        assert_eq!(impacts.candidates.len(), 1);
        assert_eq!(
            impacts.candidates[0].pinned_source_revision,
            promoted.first_revision
        );
        assert_eq!(
            impacts.candidates[0].candidate_source_revision,
            revised.new_revision
        );
    }
}

#[tokio::test]
async fn materiality_is_task_relative_and_explanations_do_not_leak_hidden_sources() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let promoted = promoted_unit(&db).await;
    let homepage = document(&db, "Homepage", "Initial.").await;
    let changelog = document(&db, "Changelog", "Initial.").await;
    let first_homepage = commit_durable_output(
        &db,
        principal(),
        ACTOR,
        package(&db, &homepage, promoted.unit_id.as_str(), "home-u1").await,
    )
    .await
    .unwrap();
    let first_changelog = commit_durable_output(
        &db,
        principal(),
        ACTOR,
        package(&db, &changelog, promoted.unit_id.as_str(), "log-u1").await,
    )
    .await
    .unwrap();
    let revised = revise_unit(
        &db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id.clone(),
            expected_current: promoted.first_revision.clone(),
            content: UnitContent::text("Primary audience: operations leaders.").unwrap(),
            rationale: "Positioning changed".into(),
            idempotency_key: IdempotencyKey::new("materiality-revise").unwrap(),
        },
    )
    .await
    .unwrap();

    async fn assessed_package(
        db: &native_ce::Db,
        consumer: &str,
        unit_id: &str,
        scope: &str,
        key: &str,
        outcome: MaterialityOutcome,
    ) -> CommitDurableOutputInput {
        let assembly = assemble_context(
            db,
            principal(),
            request(scope),
            Some(consumer),
            vec![unit_id.into()],
        )
        .await
        .unwrap();
        let comparison = assembly.comparisons[0].clone();
        let current = assembly.sources[0].clone();
        CommitDurableOutputInput {
            consumer_record_id: consumer.into(),
            expected_consumer_revision: current_record_body_revision(db, consumer).await.unwrap(),
            output_body: format!("Reconsidered for {scope}."),
            assembly,
            policy: ResolutionPolicy::agent_speed_default(),
            provenance: vec![ProvenanceUse {
                source_revision: current.clone(),
                reason: "Reconsidered against current audience".into(),
            }],
            dependencies: vec![dependency(&format!("dep-{key}-u2"), current.clone())],
            assessments: vec![AssessmentInput {
                assessment_id: AssessmentId::new(format!("assessment-{key}")).unwrap(),
                dependency_id: comparison.dependency_id,
                compared_source_revision: current,
                category: "general".into(),
                outcome,
                could_materially_change: outcome == MaterialityOutcome::Material,
                rationale: format!("Effect assessed for {scope}"),
            }],
            reconciliations: vec![],
            unresolved_uncertainty: vec![],
            idempotency_key: IdempotencyKey::new(key).unwrap(),
        }
    }

    let material = commit_durable_output(
        &db,
        principal(),
        ACTOR,
        assessed_package(
            &db,
            &homepage,
            promoted.unit_id.as_str(),
            "homepage hero",
            "home-u2",
            MaterialityOutcome::Material,
        )
        .await,
    )
    .await
    .unwrap();
    let immaterial = commit_durable_output(
        &db,
        principal(),
        ACTOR,
        assessed_package(
            &db,
            &changelog,
            promoted.unit_id.as_str(),
            "historical changelog",
            "log-u2",
            MaterialityOutcome::Immaterial,
        )
        .await,
    )
    .await
    .unwrap();
    assert_eq!(material.disclosure, DisclosureDecision::SurfaceNow);
    assert_eq!(material.execution, ExecutionDisposition::Continued);
    assert_eq!(immaterial.disclosure, DisclosureDecision::Silent);
    assert!(list_impact_candidates(&db, principal(), &homepage)
        .await
        .unwrap()
        .candidates
        .is_empty());
    assert_eq!(
        revised.new_revision,
        explain_freshness(&db, principal(), first_homepage.receipt_id.clone())
            .await
            .unwrap()
            .visible_impacts[0]
            .candidate_source_revision
    );

    const OTHER: &str = "acct:receipt-reader";
    replace_explicit_policy(
        &db,
        ACTOR,
        &homepage,
        vec![
            AllowEntry::account(ACCOUNT, Capability::Manage),
            AllowEntry::account(OTHER, Capability::View),
        ],
    )
    .await
    .unwrap();
    let bearer: String =
        sqlx::query_scalar("SELECT authority_bearer_record_id FROM semantic_units WHERE unit_id=?")
            .bind(promoted.unit_id.as_str())
            .fetch_one(db.pool())
            .await
            .unwrap();
    for hidden in [promoted.unit_id.as_str(), bearer.as_str()] {
        replace_explicit_policy(
            &db,
            ACTOR,
            hidden,
            vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
        )
        .await
        .unwrap();
    }
    let explanation = explain_freshness(&db, Principal::bound(OTHER, true), material.receipt_id)
        .await
        .unwrap();
    assert!(explanation.visible_dependencies.is_empty());
    assert!(explanation.visible_provenance.is_empty());
    assert!(explanation.visible_assessments.is_empty());
    assert!(explanation.visible_reconciliations.is_empty());
    assert!(explanation.visible_dependency_audits.is_empty());
    assert!(explanation.visible_occurrence_evidence.is_empty());
    assert!(explanation.visible_impacts.is_empty());
    assert_eq!(
        explanation.provenance_completeness,
        ProvenanceCompleteness::Withheld
    );
    assert_ne!(first_homepage.receipt_id, first_changelog.receipt_id);
}

#[tokio::test]
async fn authorization_redacted_debt_is_opaque_and_transitively_inherited() {
    const OTHER: &str = "acct:redacted-editor";
    let db = native_ce::create_database(":memory:").await.unwrap();
    let promoted = promoted_unit(&db).await;
    let consumer = document(&db, "Redacted debt consumer", "Initial.").await;
    commit_durable_output(
        &db,
        principal(),
        ACTOR,
        package(&db, &consumer, promoted.unit_id.as_str(), "redacted-r1").await,
    )
    .await
    .unwrap();
    let bearer: String =
        sqlx::query_scalar("SELECT authority_bearer_record_id FROM semantic_units WHERE unit_id=?")
            .bind(promoted.unit_id.as_str())
            .fetch_one(db.pool())
            .await
            .unwrap();
    for hidden in [promoted.unit_id.as_str(), bearer.as_str()] {
        replace_explicit_policy(
            &db,
            ACTOR,
            hidden,
            vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
        )
        .await
        .unwrap();
    }
    replace_explicit_policy(
        &db,
        ACTOR,
        &consumer,
        vec![
            AllowEntry::account(ACCOUNT, Capability::Manage),
            AllowEntry::account(OTHER, Capability::Edit),
        ],
    )
    .await
    .unwrap();
    let other = Principal::bound(OTHER, true);
    let assembly = assemble_context(
        &db,
        other,
        request("redacted continuation"),
        Some(&consumer),
        vec![],
    )
    .await
    .unwrap();
    assert!(assembly.withheld_context);
    assert!(assembly.comparisons.is_empty());
    let impacts = list_impact_candidates(&db, other, &consumer).await.unwrap();
    assert!(impacts.withheld_context);
    assert!(impacts.candidates.is_empty());
    let r2 = commit_durable_output(
        &db,
        other,
        ACTOR,
        CommitDurableOutputInput {
            consumer_record_id: consumer.clone(),
            expected_consumer_revision: current_record_body_revision(&db, &consumer).await.unwrap(),
            output_body: "Continued without laundering hidden debt.".into(),
            assembly,
            policy: ResolutionPolicy::agent_speed_default(),
            provenance: vec![],
            dependencies: vec![],
            assessments: vec![],
            reconciliations: vec![],
            unresolved_uncertainty: vec![],
            idempotency_key: IdempotencyKey::new("redacted-r2").unwrap(),
        },
    )
    .await
    .unwrap();
    assert_eq!(r2.execution, ExecutionDisposition::Continued);
    assert_eq!(r2.disclosure, DisclosureDecision::SurfaceNow);
    let r2_impacts = list_impact_candidates(&db, other, &consumer).await.unwrap();
    assert!(r2_impacts.withheld_context);
    assert!(r2_impacts.candidates.is_empty());
    assert_eq!(
        explain_freshness(&db, other, r2.receipt_id.clone())
            .await
            .unwrap()
            .provenance_completeness,
        ProvenanceCompleteness::Withheld
    );

    let r3_assembly = assemble_context(
        &db,
        other,
        request("next redacted continuation"),
        Some(&consumer),
        vec![],
    )
    .await
    .unwrap();
    assert!(r3_assembly.withheld_context);
    let downstream = assemble_context(
        &db,
        other,
        request("downstream use"),
        None,
        vec![consumer.clone()],
    )
    .await
    .unwrap();
    assert!(downstream.withheld_context);
    assert_eq!(downstream.sources, vec![r2.output_revision]);
}

#[tokio::test]
async fn semantic_runtime_reads_do_not_reveal_hidden_target_occupancy() {
    const OTHER: &str = "acct:semantic-runtime-reader";
    let db = native_ce::create_database(":memory:").await.unwrap();
    let promoted = promoted_unit(&db).await;
    let consumer = document(&db, "Hidden freshness target", "Initial.").await;
    commit_durable_output(
        &db,
        principal(),
        ACTOR,
        package(
            &db,
            &consumer,
            promoted.unit_id.as_str(),
            "hidden-target-r1",
        )
        .await,
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        ACTOR,
        &consumer,
        vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
    )
    .await
    .unwrap();
    let other = Principal::bound(OTHER, true);
    assert_eq!(
        list_impact_candidates(&db, other, &consumer)
            .await
            .unwrap_err()
            .to_string(),
        list_impact_candidates(&db, other, "missing-freshness-target")
            .await
            .unwrap_err()
            .to_string(),
        "impact lookup must not distinguish a hidden target from an absent target"
    );

    let bearer: String =
        sqlx::query_scalar("SELECT authority_bearer_record_id FROM semantic_units WHERE unit_id=?")
            .bind(promoted.unit_id.as_str())
            .fetch_one(db.pool())
            .await
            .unwrap();
    for hidden in [promoted.unit_id.as_str(), bearer.as_str()] {
        replace_explicit_policy(
            &db,
            ACTOR,
            hidden,
            vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
        )
        .await
        .unwrap();
    }
    let high_water = current_history_high_water(&db).await.unwrap();
    assert_eq!(
        resolve_current_units(&db, other, promoted.unit_id, high_water.clone())
            .await
            .unwrap_err()
            .to_string(),
        resolve_current_units(
            &db,
            other,
            UnitId::new("missing-runtime-unit").unwrap(),
            high_water,
        )
        .await
        .unwrap_err()
        .to_string(),
        "current Unit resolution must not distinguish hidden occupancy from absence"
    );
}

#[tokio::test]
async fn uncertainty_cannot_be_laundered_and_exact_reconciliation_reopens_on_u3() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let promoted = promoted_unit(&db).await;
    let consumer = document(&db, "Plan", "Initial.").await;
    let first = commit_durable_output(
        &db,
        principal(),
        ACTOR,
        package(&db, &consumer, promoted.unit_id.as_str(), "uncertain-u1").await,
    )
    .await
    .unwrap();
    let u2 = revise_unit(
        &db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id.clone(),
            expected_current: promoted.first_revision.clone(),
            content: UnitContent::text("Primary audience: operations leaders.").unwrap(),
            rationale: "Audience evidence is incomplete".into(),
            idempotency_key: IdempotencyKey::new("uncertain-u2").unwrap(),
        },
    )
    .await
    .unwrap();
    let assembly = assemble_context(
        &db,
        principal(),
        request("launch plan"),
        Some(&consumer),
        vec![promoted.unit_id.as_str().into()],
    )
    .await
    .unwrap();
    let comparison = assembly.comparisons[0].clone();
    let current = assembly.sources[0].clone();
    let make = |lineage: Vec<UncertaintyLineage>, key: &str| CommitDurableOutputInput {
        consumer_record_id: consumer.clone(),
        expected_consumer_revision: first.output_revision.clone(),
        output_body: "Proceeding provisionally for operations leaders.".into(),
        assembly: assembly.clone(),
        policy: ResolutionPolicy::agent_speed_default(),
        provenance: vec![ProvenanceUse {
            source_revision: current.clone(),
            reason: "Current audience evidence".into(),
        }],
        dependencies: vec![dependency(&format!("dep-{key}"), current.clone())],
        assessments: vec![AssessmentInput {
            assessment_id: AssessmentId::new(format!("assessment-{key}")).unwrap(),
            dependency_id: comparison.dependency_id.clone(),
            compared_source_revision: current.clone(),
            category: "general".into(),
            outcome: MaterialityOutcome::MateriallyUncertain,
            could_materially_change: true,
            rationale: "Could change the plan, but evidence is incomplete".into(),
        }],
        reconciliations: vec![],
        unresolved_uncertainty: lineage,
        idempotency_key: IdempotencyKey::new(key).unwrap(),
    };
    let before = event_count(&db).await;
    assert!(
        commit_durable_output(&db, principal(), ACTOR, make(vec![], "missing-lineage"),)
            .await
            .unwrap_err()
            .to_string()
            .contains("uncertainty cannot be omitted")
    );
    assert_eq!(event_count(&db).await, before);
    let conclusion =
        dependency("shape-only", comparison.pinned_source_revision.clone()).affected_conclusion;
    let valid_lineage = UncertaintyLineage {
        uncertainty_id: UncertaintyId::new("uncertainty-u2").unwrap(),
        dependency_id: comparison.dependency_id.clone(),
        inherited_from_receipt_id: Some(comparison.receipt_id.clone()),
        consumer_revision: first.output_revision.clone(),
        pinned_source_revision: comparison.pinned_source_revision.clone(),
        selected_source_revision: current.clone(),
        affected_conclusion: conclusion.clone(),
        assessment_task_scope: "launch plan".into(),
        verdict: MaterialityOutcome::MateriallyUncertain,
        evidence: "Audience evidence remains incomplete".into(),
        detail: "The launch plan may need revisiting".into(),
    };
    let mut wrong_tuple = valid_lineage.clone();
    wrong_tuple.affected_conclusion.key = "different.conclusion".into();
    assert!(commit_durable_output(
        &db,
        principal(),
        ACTOR,
        make(vec![wrong_tuple], "wrong-lineage-tuple"),
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("exact dependency debt tuple"));
    let mut blank_evidence = valid_lineage.clone();
    blank_evidence.evidence.clear();
    assert!(commit_durable_output(
        &db,
        principal(),
        ACTOR,
        make(vec![blank_evidence], "blank-lineage-evidence"),
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("must not be blank"));
    assert_eq!(event_count(&db).await, before);
    let provisional = commit_durable_output(
        &db,
        principal(),
        ACTOR,
        make(vec![valid_lineage], "with-lineage"),
    )
    .await
    .unwrap();

    let mut laundering = package(
        &db,
        &consumer,
        current.subject_id.as_str(),
        "launder-inherited-uncertainty",
    )
    .await;
    assert!(!laundering.assembly.inherited_uncertainty.is_empty());
    laundering.assembly.inherited_uncertainty.clear();
    laundering.unresolved_uncertainty.clear();
    laundering.expected_consumer_revision = provisional.output_revision.clone();
    let before_laundering = event_count(&db).await;
    assert!(commit_durable_output(&db, principal(), ACTOR, laundering)
        .await
        .unwrap_err()
        .to_string()
        .contains("inherited uncertainty is incomplete"));
    assert_eq!(event_count(&db).await, before_laundering);

    reconcile_dependency(
        &db,
        principal(),
        ACTOR,
        ReconcileDependencyInput {
            reconciliation_id: ReconciliationId::new("reconcile-u2").unwrap(),
            dependency_id: comparison.dependency_id.clone(),
            assessed_source_revision: u2.new_revision.clone(),
            task_scope: "launch plan".into(),
            outcome: MaterialityOutcome::RemainsValid,
            rationale: "The original output remains valid for its exact scope".into(),
            idempotency_key: IdempotencyKey::new("reconcile-u2-command").unwrap(),
        },
    )
    .await
    .unwrap();
    assert!(assemble_context(
        &db,
        principal(),
        request("post-reconciliation"),
        Some(&consumer),
        vec![current.subject_id.clone()],
    )
    .await
    .unwrap()
    .inherited_uncertainty
    .is_empty());
    let provisional_explanation =
        explain_freshness(&db, principal(), provisional.receipt_id.clone())
            .await
            .unwrap();
    assert!(provisional_explanation.unresolved_uncertainty.is_empty());
    assert_eq!(provisional_explanation.visible_comparisons.len(), 1);
    let sealed = &provisional_explanation.visible_comparisons[0];
    assert_eq!(sealed.observed_in_receipt_id, provisional.receipt_id);
    assert_eq!(sealed.dependency_receipt_id, first.receipt_id);
    assert_eq!(sealed.dependency_id, comparison.dependency_id);
    assert_eq!(sealed.pinned_source_revision, promoted.first_revision);
    assert_eq!(sealed.selected_source_revision, u2.new_revision);
    assert_eq!(sealed.task_scope, "launch plan");
    assert_eq!(sealed.affected_conclusion, conclusion);
    assert_eq!(sealed.history_high_water, assembly.high_water);
    assert!(sealed.mismatch);
    assert_eq!(provisional_explanation.visible_assessments.len(), 1);
    let assessment = &provisional_explanation.visible_assessments[0];
    assert_eq!(assessment.observed_in_receipt_id, provisional.receipt_id);
    assert_eq!(assessment.dependency_receipt_id, first.receipt_id);
    assert_eq!(assessment.pinned_source_revision, promoted.first_revision);
    assert_eq!(assessment.compared_source_revision, u2.new_revision);
    assert_eq!(assessment.task_scope, "launch plan");
    assert_eq!(assessment.outcome, MaterialityOutcome::MateriallyUncertain);
    assert_eq!(assessment.evaluator, ACTOR);
    assert_eq!(
        assessment.rationale,
        "Could change the plan, but evidence is incomplete"
    );
    assert_eq!(provisional_explanation.visible_reconciliations.len(), 1);
    assert_eq!(
        provisional_explanation.visible_reconciliations[0]
            .reconciliation_id
            .as_str(),
        "reconcile-u2"
    );

    let original_explanation = explain_freshness(&db, principal(), first.receipt_id.clone())
        .await
        .unwrap();
    assert_eq!(
        original_explanation.visible_comparisons,
        vec![sealed.clone()]
    );
    assert_eq!(
        original_explanation.visible_assessments,
        vec![assessment.clone()]
    );
    assert_eq!(original_explanation.visible_reconciliations.len(), 1);
    assert!(original_explanation
        .visible_impacts
        .iter()
        .any(|impact| impact.dependency_id == comparison.dependency_id));
    assert!(list_impact_candidates(&db, principal(), &consumer)
        .await
        .unwrap()
        .candidates
        .iter()
        .all(|impact| impact.dependency_id != comparison.dependency_id));

    let u3 = revise_unit(
        &db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id,
            expected_current: u2.new_revision,
            content: UnitContent::text("Primary audience: regulated enterprises.").unwrap(),
            rationale: "Audience changed again".into(),
            idempotency_key: IdempotencyKey::new("uncertain-u3").unwrap(),
        },
    )
    .await
    .unwrap();
    assert!(list_impact_candidates(&db, principal(), &consumer)
        .await
        .unwrap()
        .candidates
        .iter()
        .any(|impact| impact.dependency_id.as_str() == "dep-with-lineage"
            && impact.candidate_source_revision == u3.new_revision));
}

#[tokio::test]
async fn plural_supersession_returns_all_terminals_and_rejects_cycles() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let predecessor = promoted_unit(&db).await;
    let successor_a = promoted_unit(&db).await;
    let successor_b = promoted_unit(&db).await;
    supersede_unit(
        &db,
        principal(),
        ACTOR,
        SupersedeUnitInput {
            predecessor_unit_id: predecessor.unit_id.clone(),
            successors: vec![
                successor_b.first_revision.clone(),
                successor_a.first_revision.clone(),
            ],
            rationale: "The premise split into two independently changing ideas".into(),
            idempotency_key: IdempotencyKey::new("split-predecessor").unwrap(),
        },
    )
    .await
    .unwrap();
    let resolution = resolve_current_units(
        &db,
        principal(),
        predecessor.unit_id.clone(),
        current_history_high_water(&db).await.unwrap(),
    )
    .await
    .unwrap();
    assert!(resolution.ambiguous);
    assert_eq!(resolution.terminal_successors.len(), 2);
    let mut future = current_history_high_water(&db).await.unwrap();
    future.content_seq += 1;
    assert!(
        resolve_current_units(&db, principal(), predecessor.unit_id.clone(), future)
            .await
            .unwrap_err()
            .to_string()
            .contains("beyond the snapshot head")
    );
    let assembled_split = assemble_context(
        &db,
        principal(),
        request("superseded premise"),
        None,
        vec![predecessor.unit_id.as_str().into()],
    )
    .await
    .unwrap();
    assert_eq!(assembled_split.sources, resolution.terminal_successors);
    const OTHER: &str = "acct:supersession-reader";
    for unit in [&predecessor, &successor_a] {
        let bearer: String = sqlx::query_scalar(
            "SELECT authority_bearer_record_id FROM semantic_units WHERE unit_id=?",
        )
        .bind(unit.unit_id.as_str())
        .fetch_one(db.pool())
        .await
        .unwrap();
        for record_id in [unit.unit_id.as_str(), bearer.as_str()] {
            replace_explicit_policy(
                &db,
                ACTOR,
                record_id,
                vec![
                    AllowEntry::account(ACCOUNT, Capability::Manage),
                    AllowEntry::account(OTHER, Capability::View),
                ],
            )
            .await
            .unwrap();
        }
    }
    let successor_b_bearer: String =
        sqlx::query_scalar("SELECT authority_bearer_record_id FROM semantic_units WHERE unit_id=?")
            .bind(successor_b.unit_id.as_str())
            .fetch_one(db.pool())
            .await
            .unwrap();
    for hidden in [successor_b.unit_id.as_str(), successor_b_bearer.as_str()] {
        replace_explicit_policy(
            &db,
            ACTOR,
            hidden,
            vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
        )
        .await
        .unwrap();
    }
    let filtered = resolve_current_units(
        &db,
        Principal::bound(OTHER, true),
        predecessor.unit_id.clone(),
        current_history_high_water(&db).await.unwrap(),
    )
    .await
    .unwrap();
    assert!(!filtered.ambiguous);
    assert!(filtered.withheld_context);
    assert_eq!(
        filtered.terminal_successors,
        vec![successor_a.first_revision.clone()]
    );
    assert_eq!(
        assemble_context(
            &db,
            Principal::bound(OTHER, true),
            request("visible successor only"),
            None,
            vec![predecessor.unit_id.as_str().into()],
        )
        .await
        .unwrap()
        .sources,
        vec![successor_a.first_revision.clone()]
    );
    let diamond_terminal = promoted_unit(&db).await;
    for (successor, key) in [(&successor_a, "diamond-a"), (&successor_b, "diamond-b")] {
        supersede_unit(
            &db,
            principal(),
            ACTOR,
            SupersedeUnitInput {
                predecessor_unit_id: successor.unit_id.clone(),
                successors: vec![diamond_terminal.first_revision.clone()],
                rationale: "Both branches converge on one successor".into(),
                idempotency_key: IdempotencyKey::new(key).unwrap(),
            },
        )
        .await
        .unwrap();
    }
    let diamond = resolve_current_units(
        &db,
        principal(),
        predecessor.unit_id.clone(),
        current_history_high_water(&db).await.unwrap(),
    )
    .await
    .unwrap();
    assert!(!diamond.ambiguous);
    assert_eq!(
        diamond.terminal_successors,
        vec![diamond_terminal.first_revision.clone()]
    );
    assert_eq!(
        assemble_context(
            &db,
            principal(),
            request("converged premise"),
            None,
            vec![predecessor.unit_id.as_str().into()],
        )
        .await
        .unwrap()
        .sources,
        vec![diamond_terminal.first_revision.clone()]
    );
    let before = event_count(&db).await;
    assert!(supersede_unit(
        &db,
        principal(),
        ACTOR,
        SupersedeUnitInput {
            predecessor_unit_id: diamond_terminal.unit_id,
            successors: vec![predecessor.first_revision],
            rationale: "Would create a cycle".into(),
            idempotency_key: IdempotencyKey::new("reject-cycle").unwrap(),
        },
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("cycle"));
    assert_eq!(event_count(&db).await, before);
}

#[tokio::test]
async fn commit_reauthorizes_after_assembly_before_idempotency_or_writes() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let promoted = promoted_unit(&db).await;
    let consumer = document(&db, "Revocation consumer", "Initial.").await;
    let input = package(
        &db,
        &consumer,
        promoted.unit_id.as_str(),
        "revoked-after-assembly",
    )
    .await;
    let bearer: String =
        sqlx::query_scalar("SELECT authority_bearer_record_id FROM semantic_units WHERE unit_id=?")
            .bind(promoted.unit_id.as_str())
            .fetch_one(db.pool())
            .await
            .unwrap();
    replace_explicit_policy(
        &db,
        ACTOR,
        &bearer,
        vec![AllowEntry::account("acct:someone-else", Capability::Manage)],
    )
    .await
    .unwrap();
    let before = event_count(&db).await;
    let error = commit_durable_output(&db, principal(), ACTOR, input)
        .await
        .unwrap_err()
        .to_string();
    assert!(!error.contains("idempotency"), "{error}");
    assert_eq!(event_count(&db).await, before);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM freshness_runtime_command_results WHERE idempotency_key='revoked-after-assembly'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0
    );
}
