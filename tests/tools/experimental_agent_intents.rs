#![cfg(feature = "experimental-agent-intents")]

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability, Principal};
use native_ce::freshness::*;
use std::sync::Arc;

use native_ce::export::LocalSnapshotSource;
use native_ce::mcp::{
    register_build_enabled_experimental_tools, register_builtin_tools,
    register_experimental_agent_intent_tool, register_snapshot_tool, register_surface_tools,
    Caller, ExposureProfile, ToolKind, ToolRegistry,
};
use native_ce::store::create_record;
use serde_json::json;

const ACTOR: &str = "test:experimental-agent-intent";
const ACCOUNT: &str = "acct:experimental-agent-intent";
const OTHER: &str = "acct:hidden-agent-intent";
const TOOL: &str = "experimental_freshness_agent_intent";

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

async fn count(db: &native_ce::Db, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn execute(
    registry: &ToolRegistry,
    db: &native_ce::Db,
    account: &str,
    intention: &ExperimentalAgentIntent,
) -> ExperimentalAgentIntentEvidence {
    let mut value = registry
        .call(
            db.clone(),
            Caller::authenticated(account),
            TOOL,
            serde_json::to_value(intention).unwrap(),
        )
        .await
        .unwrap();
    let object = value.as_object_mut().unwrap();
    object.remove("run_context");
    if let Some(attestation_ids) = object.remove("action_attestation_ids") {
        let ids = attestation_ids
            .as_array()
            .expect("action_attestation_ids must be an array");
        assert!(
            !ids.is_empty(),
            "attached action attestations must be non-empty"
        );
        assert!(
            ids.iter().all(|id| id
                .as_str()
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())),
            "action_attestation_ids must contain only UUID identifiers"
        );
    }
    serde_json::from_value(value).unwrap()
}

async fn execute_error(
    registry: &ToolRegistry,
    db: &native_ce::Db,
    account: &str,
    intention: &ExperimentalAgentIntent,
) -> String {
    registry
        .call(
            db.clone(),
            Caller::authenticated(account),
            TOOL,
            serde_json::to_value(intention).unwrap(),
        )
        .await
        .unwrap_err()
        .to_string()
}

fn replace_assessment_key(intention: &mut ExperimentalAgentIntent, key: &str) {
    let ExperimentalAgentIntent::AssessExactChange { output, .. } = intention else {
        panic!("expected assess exact change intent");
    };
    output.idempotency_key = IdempotencyKey::new(key).unwrap();
}

fn request() -> ContextRequest {
    ContextRequest {
        intent: "Draft the homepage hero".into(),
        task_scope: "homepage hero".into(),
        risk_inputs: vec!["audience accuracy".into()],
    }
}

fn conclusion() -> AffectedConclusion {
    AffectedConclusion {
        key: "hero.audience".into(),
        description: "Who the homepage addresses".into(),
    }
}

fn reliance(id: &str, source_revision: RevisionRef) -> SourceRelianceIntent {
    SourceRelianceIntent {
        source_revision,
        dependency_id: DependencyId::new(id).unwrap(),
        semantic_role: "audience premise".into(),
        provenance_reason: "Used to draft the audience claim".into(),
        rationale: "The output directly names this audience".into(),
        reconsideration_trigger: "The audience premise changes".into(),
        confidence: Some(0.9),
    }
}

async fn output(
    db: &native_ce::Db,
    consumer: &str,
    body: &str,
    unit_id: &UnitId,
    source: RevisionRef,
    dependency_id: &str,
    key: &str,
) -> DurableOutputIntent {
    DurableOutputIntent {
        consumer_record_id: consumer.into(),
        expected_consumer_revision: current_record_body_revision(db, consumer).await.unwrap(),
        output_body: body.into(),
        request: request(),
        policy: ResolutionPolicy::agent_speed_default(),
        source_record_ids: vec![unit_id.as_str().into()],
        affected_conclusion: conclusion(),
        sources: vec![reliance(dependency_id, source)],
        idempotency_key: IdempotencyKey::new(key).unwrap(),
    }
}

async fn promoted_source(
    db: &native_ce::Db,
    source_name: &str,
    source_text: &str,
    unit_text: &str,
    key: &str,
) -> (PromoteIdeaResult, RevisionRef) {
    let source = document(db, source_name, source_text).await;
    let source_revision = current_record_body_revision(db, &source).await.unwrap();
    let promoted = promote_idea(
        db,
        principal(),
        ACTOR,
        PromoteIdeaInput {
            source_revision: source_revision.clone(),
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: source_text.into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            first_content: UnitContent::text(unit_text).unwrap(),
            expression_role: ExpressionRole::Canonical,
            label: Some(source_name.into()),
            requested_unit_id: None,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new(key).unwrap(),
        },
    )
    .await
    .unwrap();
    (promoted, source_revision)
}

fn committed(
    evidence: &ExperimentalAgentIntentEvidence,
) -> (&CommitDurableOutputResult, &FreshnessExplanation) {
    match &evidence.result {
        ExperimentalAgentIntentResult::DeclareSources {
            committed,
            explanation,
        }
        | ExperimentalAgentIntentResult::AssessExactChange {
            committed,
            explanation,
        } => (committed, explanation),
        _ => panic!("expected committed output evidence"),
    }
}

#[test]
fn descriptor_exposes_closed_nested_contracts_and_run_correlation() {
    fn audit_nested_schema(value: &serde_json::Value) {
        if value["type"] == "object" {
            assert_eq!(value["additionalProperties"], false, "{value}");
            let properties = value["properties"].as_object().unwrap();
            let required = value["required"].as_array().unwrap();
            for name in required {
                assert!(properties.contains_key(name.as_str().unwrap()), "{value}");
            }
            for property in properties.values() {
                audit_nested_schema(property);
            }
        }
        if value["type"] == "array" {
            assert!(value.get("items").is_some(), "{value}");
            audit_nested_schema(&value["items"]);
        }
        if let Some(branches) = value.get("oneOf").and_then(|value| value.as_array()) {
            assert!(!branches.is_empty());
            for branch in branches {
                audit_nested_schema(branch);
            }
        }
    }

    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    assert!(registry.get(TOOL).is_none());
    let stable_count = registry.specs().count();
    assert_eq!(stable_count, ToolKind::ALL.len() - 3);
    assert!(registry.specs().all(|spec| spec.kind.is_some()));
    register_experimental_agent_intent_tool(&mut registry).unwrap();
    register_snapshot_tool(&mut registry, Arc::new(LocalSnapshotSource::new())).unwrap();
    assert_eq!(registry.specs().count(), ToolKind::ALL.len() - 1);
    assert!(registry.get(TOOL).unwrap().kind.is_none());
    assert!(!registry
        .specs_for_profile(ExposureProfile::Focused)
        .any(|spec| spec.name == TOOL));
    assert!(registry
        .specs_for_profile(ExposureProfile::Complete)
        .any(|spec| spec.name == TOOL));
    registry
        .validate_profile_budgets()
        .expect("feature-enabled stdio-shaped registry fits both profile budgets");
    let schema = &registry.get(TOOL).unwrap().input_schema;
    assert!(schema["required"]
        .as_array()
        .unwrap()
        .contains(&json!("run_key")));
    let branches = schema["oneOf"].as_array().unwrap();
    assert_eq!(branches.len(), 4);
    for branch in branches {
        audit_nested_schema(branch);
        assert_eq!(branch["additionalProperties"], false);
        assert!(branch["required"]
            .as_array()
            .unwrap()
            .contains(&json!("run_key")));
        assert_eq!(branch["properties"]["run_key"]["type"], "string");
        assert_eq!(branch["properties"]["parent_key"]["type"], "string");
    }
    let branch = |intention: &str| {
        branches
            .iter()
            .find(|branch| branch["properties"]["intention"]["const"] == intention)
            .unwrap()
    };
    let promote = &branch("promote_exact_expression")["properties"]["input"];
    assert_eq!(promote["additionalProperties"], false);
    assert!(promote["required"]
        .as_array()
        .unwrap()
        .contains(&json!("source_revision")));
    assert_eq!(
        promote["properties"]["expression_role"]["enum"],
        json!(["canonical", "paraphrase", "summary", "quotation"])
    );
    for selector in promote["properties"]["selectors"]["items"]["oneOf"]
        .as_array()
        .unwrap()
    {
        assert_eq!(selector["additionalProperties"], false);
    }
    let output = &branch("assess_exact_change")["properties"]["output"];
    assert_eq!(output["additionalProperties"], false);
    assert!(output["required"]
        .as_array()
        .unwrap()
        .contains(&json!("affected_conclusion")));
    assert_eq!(
        output["properties"]["expected_consumer_revision"]["additionalProperties"],
        false
    );
    assert_eq!(
        output["properties"]["policy"]["properties"]["disclosure_rule"]["enum"],
        json!(["material_only", "explain_on_inspection"])
    );
    let assessment = &branch("assess_exact_change")["properties"]["assessments"]["items"];
    assert_eq!(assessment["additionalProperties"], false);
    assert!(assessment["required"]
        .as_array()
        .unwrap()
        .contains(&json!("compared_source_revision")));
    assert_eq!(
        assessment["properties"]["outcome"]["enum"],
        json!([
            "immaterial",
            "remains_valid",
            "material",
            "materially_uncertain",
            "contradicted",
            "unable_to_assess"
        ])
    );
    let reconcile = &branch("reconcile_affected_output")["properties"]["input"];
    assert_eq!(reconcile["additionalProperties"], false);
    assert!(reconcile["required"]
        .as_array()
        .unwrap()
        .contains(&json!("assessed_source_revision")));

    let valid_outer = serde_json::to_value(ExperimentalAgentIntent::ReconcileAffectedOutput {
        receipt_id: ReceiptId::new("receipt-schema-probe").unwrap(),
        input: ReconcileDependencyInput {
            reconciliation_id: ReconciliationId::new("reconciliation-schema-probe").unwrap(),
            dependency_id: DependencyId::new("dependency-schema-probe").unwrap(),
            assessed_source_revision: RevisionRef {
                subject_kind: RevisionSubjectKind::Artefact,
                subject_id: "record-schema-probe".into(),
                revision_event_id: "event-schema-probe".into(),
                revision_seq: 1,
                source_slot: RevisionSourceSlot::RecordBody,
                sha256: "0".repeat(64),
            },
            task_scope: "schema probe".into(),
            outcome: MaterialityOutcome::RemainsValid,
            rationale: "Prove the wire rejects undeclared outer fields".into(),
            idempotency_key: IdempotencyKey::new("schema-probe").unwrap(),
        },
    })
    .unwrap();
    let mut schema_valid = valid_outer.clone();
    schema_valid
        .as_object_mut()
        .unwrap()
        .insert("run_key".into(), json!("scout-chair-schema005"));
    let validator = jsonschema::validator_for(schema).unwrap();
    assert!(
        validator.is_valid(&schema_valid),
        "experimental schema rejected its valid reconciliation fixture"
    );
    let mut schema_invalid = schema_valid.clone();
    schema_invalid
        .as_object_mut()
        .unwrap()
        .insert("unexpected".into(), json!(true));
    assert!(
        !validator.is_valid(&schema_invalid),
        "experimental schema accepted an undeclared field"
    );

    let mut unexpected_outer = valid_outer;
    unexpected_outer
        .as_object_mut()
        .unwrap()
        .insert("unexpected".into(), json!(true));
    assert!(
        serde_json::from_value::<ExperimentalAgentIntent>(unexpected_outer)
            .unwrap_err()
            .to_string()
            .contains("unknown field")
    );
}

#[tokio::test]
async fn source_declarations_must_equal_all_selected_sources_exactly_once() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_build_enabled_experimental_tools(&mut registry).unwrap();
    let (first, _) = promoted_source(
        &db,
        "Audience",
        "Audience: technical founders.",
        "Primary audience: technical founders.",
        "declaration-matrix-promote-audience",
    )
    .await;
    let (second, _) = promoted_source(
        &db,
        "Channel",
        "Channel: product-led onboarding.",
        "Primary channel: product-led onboarding.",
        "declaration-matrix-promote-channel",
    )
    .await;
    let extra_source = document(&db, "Undeclared selection", "Not selected.").await;
    let extra_revision = current_record_body_revision(&db, &extra_source)
        .await
        .unwrap();
    let consumer = document(&db, "Two-source output", "Initial.").await;
    let base_output = DurableOutputIntent {
        consumer_record_id: consumer.clone(),
        expected_consumer_revision: current_record_body_revision(&db, &consumer).await.unwrap(),
        output_body: "Built for technical founders through product-led onboarding.".into(),
        request: request(),
        policy: ResolutionPolicy::agent_speed_default(),
        source_record_ids: vec![
            first.unit_id.as_str().into(),
            second.unit_id.as_str().into(),
        ],
        affected_conclusion: conclusion(),
        sources: vec![
            reliance("dep-matrix-audience", first.first_revision),
            reliance("dep-matrix-channel", second.first_revision),
        ],
        idempotency_key: IdempotencyKey::new("declaration-matrix-valid").unwrap(),
    };
    let before = count(&db, "content_events").await;

    let mut missing = base_output.clone();
    missing.sources.pop();
    missing.idempotency_key = IdempotencyKey::new("declaration-matrix-missing").unwrap();
    let missing = ExperimentalAgentIntent::DeclareSources { output: missing };
    assert!(execute_error(&registry, &db, ACCOUNT, &missing)
        .await
        .contains("declare every exact selected source once"));

    let mut duplicate = base_output.clone();
    duplicate.sources.push(duplicate.sources[0].clone());
    duplicate.idempotency_key = IdempotencyKey::new("declaration-matrix-duplicate").unwrap();
    let duplicate = ExperimentalAgentIntent::DeclareSources { output: duplicate };
    assert!(execute_error(&registry, &db, ACCOUNT, &duplicate)
        .await
        .contains("declare every exact selected source once"));

    let mut extra = base_output.clone();
    extra
        .sources
        .push(reliance("dep-matrix-extra", extra_revision));
    extra.idempotency_key = IdempotencyKey::new("declaration-matrix-extra").unwrap();
    let extra = ExperimentalAgentIntent::DeclareSources { output: extra };
    assert!(execute_error(&registry, &db, ACCOUNT, &extra)
        .await
        .contains("declare every exact selected source once"));
    assert_eq!(count(&db, "content_events").await, before);

    let valid = ExperimentalAgentIntent::DeclareSources {
        output: base_output,
    };
    assert_eq!(
        committed(&execute(&registry, &db, ACCOUNT, &valid).await)
            .0
            .dependency_ids
            .len(),
        2
    );
}

#[tokio::test]
async fn feature_gated_dispatcher_exercises_exact_agent_intentions_end_to_end() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    assert!(registry.get(TOOL).is_none());
    register_build_enabled_experimental_tools(&mut registry).unwrap();
    assert!(registry.get(TOOL).is_some());

    let source_text = "Audience: technical founders.";
    let source = document(&db, "Audience source", source_text).await;
    let source_revision = current_record_body_revision(&db, &source).await.unwrap();
    let promotion = ExperimentalAgentIntent::PromoteExactExpression {
        input: PromoteIdeaInput {
            source_revision,
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: source_text.into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            first_content: UnitContent::text("Primary audience: technical founders.").unwrap(),
            expression_role: ExpressionRole::Canonical,
            label: Some("Audience".into()),
            requested_unit_id: None,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("intent-promote").unwrap(),
        },
    };
    let promoted_evidence = execute(&registry, &db, ACCOUNT, &promotion).await;
    assert_eq!(
        promoted_evidence.experimental_contract,
        EXPERIMENTAL_AGENT_INTENT_CONTRACT
    );
    let promoted = match promoted_evidence.result {
        ExperimentalAgentIntentResult::PromoteExactExpression {
            promoted,
            unit,
            occurrence,
        } => {
            assert_eq!(unit.unit_id, promoted.unit_id);
            assert_eq!(occurrence.occurrence.occurrence_id, promoted.occurrence_id);
            assert_eq!(
                occurrence.resolution.state,
                OccurrenceResolutionState::Current
            );
            promoted
        }
        _ => panic!("expected promotion evidence"),
    };

    let quiet_consumer = document(&db, "Quiet output", "Initial.").await;
    let material_consumer = document(&db, "Material output", "Initial.").await;
    let quiet_declare = ExperimentalAgentIntent::DeclareSources {
        output: output(
            &db,
            &quiet_consumer,
            "Built for technical founders.",
            &promoted.unit_id,
            promoted.first_revision.clone(),
            "dep-quiet-u1",
            "declare-quiet-u1",
        )
        .await,
    };
    let quiet_r1 = execute(&registry, &db, ACCOUNT, &quiet_declare).await;
    let (quiet_committed, quiet_explanation) = committed(&quiet_r1);
    assert_eq!(quiet_explanation.visible_dependencies.len(), 1);
    assert_eq!(
        quiet_explanation.provenance_completeness,
        ProvenanceCompleteness::Complete
    );
    let quiet_r1_receipt = quiet_committed.receipt_id.clone();
    let quiet_r1_output = quiet_committed.output_revision.clone();
    let replay = execute(&registry, &db, ACCOUNT, &quiet_declare).await;
    assert_eq!(committed(&replay).0.receipt_id, quiet_r1_receipt);
    let ExperimentalAgentIntent::DeclareSources {
        output: declared_output,
    } = quiet_declare.clone()
    else {
        unreachable!();
    };
    let declare_as_assess_collision = ExperimentalAgentIntent::AssessExactChange {
        output: declared_output,
        assessments: Vec::new(),
    };
    assert!(
        execute_error(&registry, &db, ACCOUNT, &declare_as_assess_collision)
            .await
            .contains("different experimental agent intent")
    );

    let material_declare = ExperimentalAgentIntent::DeclareSources {
        output: output(
            &db,
            &material_consumer,
            "Built for technical founders.",
            &promoted.unit_id,
            promoted.first_revision.clone(),
            "dep-material-u1",
            "declare-material-u1",
        )
        .await,
    };
    let material_r1 = execute(&registry, &db, ACCOUNT, &material_declare).await;
    let material_r1_receipt = committed(&material_r1).0.receipt_id.clone();
    let material_r1_output = committed(&material_r1).0.output_revision.clone();

    let revised = revise_unit(
        &db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id.clone(),
            expected_current: promoted.first_revision.clone(),
            content: UnitContent::text("Primary audience: operations leaders.").unwrap(),
            rationale: "Positioning decision changed".into(),
            idempotency_key: IdempotencyKey::new("intent-revise-u2").unwrap(),
        },
    )
    .await
    .unwrap();

    let quiet_assess = ExperimentalAgentIntent::AssessExactChange {
        output: DurableOutputIntent {
            expected_consumer_revision: quiet_r1_output,
            ..output(
                &db,
                &quiet_consumer,
                "The existing wording remains safe.",
                &promoted.unit_id,
                revised.new_revision.clone(),
                "dep-quiet-u2",
                "assess-quiet-u2",
            )
            .await
        },
        assessments: vec![ChangeAssessmentIntent {
            assessment_id: AssessmentId::new("assessment-quiet-u2").unwrap(),
            dependency_id: DependencyId::new("dep-quiet-u1").unwrap(),
            compared_source_revision: revised.new_revision.clone(),
            category: "general".into(),
            outcome: MaterialityOutcome::Immaterial,
            could_materially_change: false,
            rationale: "The bounded conclusion is unchanged".into(),
            uncertainty_id: None,
            uncertainty_evidence: None,
            uncertainty_detail: None,
        }],
    };
    let mut irrelevant_uncertainty = quiet_assess.clone();
    replace_assessment_key(
        &mut irrelevant_uncertainty,
        "assess-quiet-uncertainty-fields",
    );
    let ExperimentalAgentIntent::AssessExactChange { assessments, .. } =
        &mut irrelevant_uncertainty
    else {
        unreachable!();
    };
    assessments[0].uncertainty_detail = Some("Must be rejected, not ignored".into());
    assert!(
        execute_error(&registry, &db, ACCOUNT, &irrelevant_uncertainty)
            .await
            .contains("uncertainty fields are only valid")
    );
    let quiet_r2 = execute(&registry, &db, ACCOUNT, &quiet_assess).await;
    assert_eq!(
        committed(&quiet_r2).0.execution,
        ExecutionDisposition::Continued
    );
    assert_eq!(
        committed(&quiet_r2).0.disclosure,
        DisclosureDecision::Silent
    );
    assert_eq!(committed(&quiet_r2).1.visible_comparisons.len(), 1);

    let material_assess = ExperimentalAgentIntent::AssessExactChange {
        output: DurableOutputIntent {
            expected_consumer_revision: material_r1_output,
            ..output(
                &db,
                &material_consumer,
                "Proceeding provisionally for operations leaders.",
                &promoted.unit_id,
                revised.new_revision.clone(),
                "dep-material-u2",
                "assess-material-u2",
            )
            .await
        },
        assessments: vec![ChangeAssessmentIntent {
            assessment_id: AssessmentId::new("assessment-material-u2").unwrap(),
            dependency_id: DependencyId::new("dep-material-u1").unwrap(),
            compared_source_revision: revised.new_revision.clone(),
            category: "general".into(),
            outcome: MaterialityOutcome::MateriallyUncertain,
            could_materially_change: true,
            rationale: "The audience change could alter the hero".into(),
            uncertainty_id: Some(UncertaintyId::new("uncertainty-material-u2").unwrap()),
            uncertainty_evidence: Some(
                "The new audience is exact but product evidence is incomplete".into(),
            ),
            uncertainty_detail: Some(
                "Revisit the hero after validating the audience decision".into(),
            ),
        }],
    };

    let mut missing_assessment = material_assess.clone();
    replace_assessment_key(&mut missing_assessment, "assess-material-missing");
    let ExperimentalAgentIntent::AssessExactChange { assessments, .. } = &mut missing_assessment
    else {
        unreachable!();
    };
    assessments.clear();
    assert!(execute_error(&registry, &db, ACCOUNT, &missing_assessment)
        .await
        .contains("requires exactly one assessment for every sealed comparison"));

    let mut duplicate_assessment = material_assess.clone();
    replace_assessment_key(&mut duplicate_assessment, "assess-material-duplicate");
    let ExperimentalAgentIntent::AssessExactChange { assessments, .. } = &mut duplicate_assessment
    else {
        unreachable!();
    };
    assessments.push(assessments[0].clone());
    assert!(
        execute_error(&registry, &db, ACCOUNT, &duplicate_assessment)
            .await
            .contains("requires exactly one assessment for every sealed comparison")
    );

    let mut extra_assessment = material_assess.clone();
    replace_assessment_key(&mut extra_assessment, "assess-material-extra");
    let ExperimentalAgentIntent::AssessExactChange { assessments, .. } = &mut extra_assessment
    else {
        unreachable!();
    };
    assessments.push(ChangeAssessmentIntent {
        assessment_id: AssessmentId::new("assessment-material-extra").unwrap(),
        dependency_id: DependencyId::new("dep-not-sealed").unwrap(),
        compared_source_revision: revised.new_revision.clone(),
        category: "general".into(),
        outcome: MaterialityOutcome::Immaterial,
        could_materially_change: false,
        rationale: "Not part of the sealed assembly".into(),
        uncertainty_id: None,
        uncertainty_evidence: None,
        uncertainty_detail: None,
    });
    assert!(execute_error(&registry, &db, ACCOUNT, &extra_assessment)
        .await
        .contains("requires exactly one assessment for every sealed comparison"));

    let mut forged_revision = material_assess.clone();
    replace_assessment_key(&mut forged_revision, "assess-material-forged-revision");
    let ExperimentalAgentIntent::AssessExactChange { assessments, .. } = &mut forged_revision
    else {
        unreachable!();
    };
    assessments[0].compared_source_revision.sha256 = "0".repeat(64);
    assert!(execute_error(&registry, &db, ACCOUNT, &forged_revision)
        .await
        .contains("requires exactly one assessment for every sealed comparison"));

    let mut crossed_conclusion = material_assess.clone();
    replace_assessment_key(&mut crossed_conclusion, "assess-material-cross-conclusion");
    let ExperimentalAgentIntent::AssessExactChange { output, .. } = &mut crossed_conclusion else {
        unreachable!();
    };
    output.affected_conclusion = AffectedConclusion {
        key: "hero.pricing".into(),
        description: "How pricing is presented".into(),
    };
    assert!(execute_error(&registry, &db, ACCOUNT, &crossed_conclusion)
        .await
        .contains("cannot cross or combine bounded conclusions"));

    let material_r2 = execute(&registry, &db, ACCOUNT, &material_assess).await;
    assert_eq!(
        committed(&material_r2).0.execution,
        ExecutionDisposition::Continued
    );
    assert_eq!(
        committed(&material_r2).0.disclosure,
        DisclosureDecision::SurfaceNow
    );
    assert_eq!(committed(&material_r2).1.unresolved_uncertainty.len(), 1);

    let before_wrong_receipt_events = count(&db, "content_events").await;
    let before_wrong_receipt_projections = count(&db, "reconciliations").await;
    let wrong_receipt = ExperimentalAgentIntent::ReconcileAffectedOutput {
        receipt_id: quiet_r1_receipt,
        input: ReconcileDependencyInput {
            reconciliation_id: ReconciliationId::new("intent-wrong-receipt").unwrap(),
            dependency_id: DependencyId::new("dep-material-u1").unwrap(),
            assessed_source_revision: revised.new_revision.clone(),
            task_scope: "homepage hero".into(),
            outcome: MaterialityOutcome::RemainsValid,
            rationale: "Must not reconcile against an unrelated Receipt".into(),
            idempotency_key: IdempotencyKey::new("intent-wrong-receipt-command").unwrap(),
        },
    };
    assert!(execute_error(&registry, &db, ACCOUNT, &wrong_receipt)
        .await
        .contains("does not own the requested dependency"));
    assert_eq!(
        count(&db, "content_events").await,
        before_wrong_receipt_events
    );
    assert_eq!(
        count(&db, "reconciliations").await,
        before_wrong_receipt_projections
    );

    let reconcile = ExperimentalAgentIntent::ReconcileAffectedOutput {
        receipt_id: material_r1_receipt,
        input: ReconcileDependencyInput {
            reconciliation_id: ReconciliationId::new("intent-reconcile-material-u2").unwrap(),
            dependency_id: DependencyId::new("dep-material-u1").unwrap(),
            assessed_source_revision: revised.new_revision,
            task_scope: "homepage hero".into(),
            outcome: MaterialityOutcome::RemainsValid,
            rationale: "The provisional output now incorporates the exact audience change".into(),
            idempotency_key: IdempotencyKey::new("intent-reconcile-command").unwrap(),
        },
    };
    let reconciled = execute(&registry, &db, ACCOUNT, &reconcile).await;
    match reconciled.result {
        ExperimentalAgentIntentResult::ReconcileAffectedOutput { explanation } => {
            assert_eq!(explanation.visible_reconciliations.len(), 1);
            assert!(explanation.visible_impacts.is_empty());
        }
        _ => panic!("expected reconciliation evidence"),
    }
}

#[tokio::test]
async fn replay_reauthorizes_the_exact_committed_sources() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_build_enabled_experimental_tools(&mut registry).unwrap();
    let source_text = "Audience: technical founders.";
    let source = document(&db, "Replay source", source_text).await;
    let promotion = ExperimentalAgentIntent::PromoteExactExpression {
        input: PromoteIdeaInput {
            source_revision: current_record_body_revision(&db, &source).await.unwrap(),
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: source_text.into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            first_content: UnitContent::text("Primary audience: technical founders.").unwrap(),
            expression_role: ExpressionRole::Canonical,
            label: Some("Replay audience".into()),
            requested_unit_id: None,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("replay-auth-promote").unwrap(),
        },
    };
    let promoted = match execute(&registry, &db, ACCOUNT, &promotion).await.result {
        ExperimentalAgentIntentResult::PromoteExactExpression { promoted, .. } => promoted.clone(),
        _ => panic!("expected promotion evidence"),
    };
    let consumer = document(&db, "Replay output", "Initial.").await;
    let declaration = ExperimentalAgentIntent::DeclareSources {
        output: output(
            &db,
            &consumer,
            "Built for technical founders.",
            &promoted.unit_id,
            promoted.first_revision,
            "dep-replay-auth",
            "declare-replay-auth",
        )
        .await,
    };
    execute(&registry, &db, ACCOUNT, &declaration).await;
    replace_explicit_policy(
        &db,
        ACTOR,
        &source,
        vec![AllowEntry::account(OTHER, Capability::Manage)],
    )
    .await
    .unwrap();
    let before = count(&db, "content_events").await;
    let error = execute_error(&registry, &db, ACCOUNT, &declaration).await;
    assert!(error.contains("requires View"), "{error}");
    assert_eq!(count(&db, "content_events").await, before);
}

#[tokio::test]
async fn transitively_hidden_dependency_returns_only_withheld_completeness() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_build_enabled_experimental_tools(&mut registry).unwrap();
    let (promoted, hidden_source_revision) = promoted_source(
        &db,
        "Hidden source",
        "Private premise.",
        "Private semantic premise.",
        "hidden-promote",
    )
    .await;
    let hidden_source = hidden_source_revision.subject_id;
    let consumer = document(&db, "Visible consumer", "Initial.").await;
    let establishing_declaration = ExperimentalAgentIntent::DeclareSources {
        output: output(
            &db,
            &consumer,
            "Initial output using the private premise.",
            &promoted.unit_id,
            promoted.first_revision,
            "dep-hidden-u1",
            "hidden-establish",
        )
        .await,
    };
    execute(&registry, &db, ACCOUNT, &establishing_declaration).await;
    for hidden in [promoted.unit_id.as_str(), hidden_source.as_str()] {
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
    let intention = ExperimentalAgentIntent::DeclareSources {
        output: DurableOutputIntent {
            consumer_record_id: consumer.clone(),
            expected_consumer_revision: current_record_body_revision(&db, &consumer).await.unwrap(),
            output_body: "Continued without exposing private context.".into(),
            request: request(),
            policy: ResolutionPolicy::agent_speed_default(),
            // Hidden debt is inherited from the prior Receipt. Directly naming
            // an unreadable source would correctly fail authorization.
            source_record_ids: Vec::new(),
            affected_conclusion: conclusion(),
            sources: Vec::new(),
            idempotency_key: IdempotencyKey::new("hidden-declare").unwrap(),
        },
    };
    let evidence = execute(&registry, &db, OTHER, &intention).await;
    assert_eq!(
        evidence.provenance_completeness,
        ProvenanceCompleteness::Withheld
    );
    let (committed_output, explanation) = committed(&evidence);
    assert!(committed_output.dependency_ids.is_empty());
    assert!(explanation.visible_provenance.is_empty());
    assert!(explanation.visible_dependencies.is_empty());
    assert_eq!(
        explanation.provenance_completeness,
        ProvenanceCompleteness::Withheld
    );
    let wire = serde_json::to_string(&evidence).unwrap();
    assert!(!wire.contains(&hidden_source));
    assert!(!wire.contains(promoted.unit_id.as_str()));
}
