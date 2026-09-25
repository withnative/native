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
use serde_json::{json, Value};

const ACTOR: &str = "test:experimental-agent-intent";
const ACCOUNT: &str = "acct:experimental-agent-intent";
const OTHER: &str = "acct:hidden-agent-intent";
const TOOL: &str = "experimental_freshness_agent_intent";
const READ_FRESHNESS_CONTRACT: &str = "native.read-freshness.v1-experimental";

/// A registry serving both the experimental intent tool and the stable
/// surface, so `get_record` reads observe kernel state the intent tool wrote.
fn freshness_read_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    register_build_enabled_experimental_tools(&mut registry).unwrap();
    registry
}

async fn get_record_as(
    registry: &ToolRegistry,
    db: &native_ce::Db,
    account: &str,
    args: Value,
) -> Value {
    registry
        .call(
            db.clone(),
            Caller::authenticated(account),
            "get_record",
            args,
        )
        .await
        .unwrap()
}

fn sole_record(output: &Value) -> &Value {
    let records = output["records"].as_array().unwrap();
    assert_eq!(records.len(), 1, "{output}");
    assert_eq!(records[0]["status"], "found", "{output}");
    &records[0]
}

/// Promote a Unit from a fresh source document and return the source id plus
/// the promotion result. The bound Occurrence quotes the whole body, so its
/// anchor resolves `current` until the body is rewritten.
async fn promote_freshness_source(
    db: &native_ce::Db,
    source_name: &str,
    source_text: &str,
    unit_text: &str,
    key: &str,
) -> (String, PromoteIdeaResult) {
    let source = document(db, source_name, source_text).await;
    let source_revision = current_record_body_revision(db, &source).await.unwrap();
    let promoted = promote_idea(
        db,
        principal(),
        ACTOR,
        PromoteIdeaInput {
            source_revision,
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
    (source, promoted)
}

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
    let separately_registered = [
        ToolKind::StandbyStatus,
        ToolKind::ExportSnapshot,
        ToolKind::ManageMemberships,
        ToolKind::WorkspaceRead,
        ToolKind::ReachRead,
        ToolKind::ReachConnect,
        ToolKind::AuthorityActHead,
        ToolKind::AuthorityActDelta,
    ];
    assert_eq!(
        stable_count,
        ToolKind::ALL.len() - separately_registered.len()
    );
    for kind in separately_registered {
        assert!(registry.get(kind.name()).is_none(), "{}", kind.name());
    }
    assert!(registry.specs().all(|spec| spec.kind.is_some()));
    register_experimental_agent_intent_tool(&mut registry).unwrap();
    register_snapshot_tool(&mut registry, Arc::new(LocalSnapshotSource::new())).unwrap();
    assert_eq!(registry.specs().count(), stable_count + 2);
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
    assert_eq!(branches.len(), 6);
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
    let bind = &branch("bind_exact_expression")["properties"]["input"];
    assert_eq!(bind["additionalProperties"], false);
    for required in [
        "unit_revision",
        "artefact_revision",
        "selectors",
        "expression_role",
        "idempotency_key",
    ] {
        assert!(
            bind["required"]
                .as_array()
                .unwrap()
                .contains(&json!(required)),
            "{bind}"
        );
    }
    assert_eq!(
        bind["properties"]["expression_role"]["enum"],
        json!(["canonical", "paraphrase", "summary", "quotation"])
    );
    assert_eq!(
        bind["properties"]["expression_role"]["enum"],
        json!(["canonical", "paraphrase", "summary", "quotation"])
    );
    for selector in bind["properties"]["selectors"]["items"]["oneOf"]
        .as_array()
        .unwrap()
    {
        assert_eq!(selector["additionalProperties"], false);
    }

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

async fn bind_setup(
    db: &native_ce::Db,
    source_name: &str,
    source_text: &str,
    unit_text: &str,
    target_name: &str,
    target_body: &str,
    promote_key: &str,
) -> (PromoteIdeaResult, String) {
    let (promoted, _) = promoted_source(db, source_name, source_text, unit_text, promote_key).await;
    let target = document(db, target_name, target_body).await;
    (promoted, target)
}

fn bind_intent(
    promoted: &PromoteIdeaResult,
    artefact_revision: RevisionRef,
    exact: &str,
    key: &str,
) -> ExperimentalAgentIntent {
    ExperimentalAgentIntent::BindExactExpression {
        input: BindOccurrenceInput {
            unit_revision: promoted.first_revision.clone(),
            artefact_revision,
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: exact.into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            expression_role: ExpressionRole::Quotation,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new(key).unwrap(),
        },
    }
}

fn bound_parts(
    evidence: &ExperimentalAgentIntentEvidence,
) -> (&BindOccurrenceResult, &UnitView, &OccurrenceEvidence) {
    match &evidence.result {
        ExperimentalAgentIntentResult::BindExactExpression {
            bound,
            unit,
            occurrence,
        } => (bound, unit, occurrence),
        _ => panic!("expected bind exact expression evidence"),
    }
}

#[tokio::test]
async fn bind_exact_expression_binds_existing_unit_into_another_record() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_build_enabled_experimental_tools(&mut registry).unwrap();
    let target_body = "The second record repeats the shared anchor phrase exactly once.";
    let (promoted, target) = bind_setup(
        &db,
        "Bind source",
        "Source holds the promotable sentence.",
        "Promotable sentence.",
        "Bind target",
        target_body,
        "bind-promote-source",
    )
    .await;
    let before = count(&db, "occurrences").await;
    let intention = bind_intent(
        &promoted,
        current_record_body_revision(&db, &target).await.unwrap(),
        "shared anchor phrase",
        "bind-first",
    );
    let evidence = execute(&registry, &db, ACCOUNT, &intention).await;
    assert_eq!(
        evidence.experimental_contract,
        EXPERIMENTAL_AGENT_INTENT_CONTRACT
    );
    let (bound, unit, occurrence) = bound_parts(&evidence);
    assert_eq!(unit.unit_id, promoted.unit_id);
    assert_eq!(
        occurrence.occurrence.occurrence_id,
        bound.occurrence.occurrence_id
    );
    assert_eq!(
        occurrence.resolution.state,
        OccurrenceResolutionState::Current
    );
    assert_eq!(bound.occurrence.unit_revision, promoted.first_revision);
    assert_eq!(count(&db, "occurrences").await, before + 1);
    let listed = list_occurrences(&db, principal(), &promoted.unit_id)
        .await
        .unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed
        .iter()
        .any(|view| view.occurrence_id == bound.occurrence.occurrence_id));
}

#[tokio::test]
async fn bind_exact_expression_replay_returns_the_same_occurrence() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_build_enabled_experimental_tools(&mut registry).unwrap();
    let target_body = "Replay target carries the repeatable anchor phrase once.";
    let (promoted, target) = bind_setup(
        &db,
        "Replay bind source",
        "Replay source sentence.",
        "Replay sentence.",
        "Replay bind target",
        target_body,
        "bind-replay-promote",
    )
    .await;
    let intention = bind_intent(
        &promoted,
        current_record_body_revision(&db, &target).await.unwrap(),
        "repeatable anchor phrase",
        "bind-replay-key",
    );
    let first = execute(&registry, &db, ACCOUNT, &intention).await;
    let (first_bound, _, _) = bound_parts(&first);
    let first_id = first_bound.occurrence.occurrence_id.clone();
    let before = count(&db, "occurrences").await;
    let second = execute(&registry, &db, ACCOUNT, &intention).await;
    let (second_bound, _, _) = bound_parts(&second);
    assert_eq!(second_bound.occurrence.occurrence_id, first_id);
    assert_eq!(count(&db, "occurrences").await, before);
}

#[tokio::test]
async fn bind_exact_expression_without_target_view_fails_authorization() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_build_enabled_experimental_tools(&mut registry).unwrap();
    let target_body = "Hidden target carries the guarded anchor phrase once.";
    let (promoted, target) = bind_setup(
        &db,
        "Guarded bind source",
        "Guarded source sentence.",
        "Guarded sentence.",
        "Guarded bind target",
        target_body,
        "bind-guarded-promote",
    )
    .await;
    // The sealed artefact revision is observed before the policy changed, so
    // the bind still names the exact revision while the caller loses access.
    let artefact_revision = current_record_body_revision(&db, &target).await.unwrap();
    replace_explicit_policy(
        &db,
        ACTOR,
        &target,
        vec![AllowEntry::account(OTHER, Capability::Manage)],
    )
    .await
    .unwrap();
    let before = count(&db, "occurrences").await;
    let intention = bind_intent(
        &promoted,
        artefact_revision,
        "guarded anchor phrase",
        "bind-guarded",
    );
    let error = execute_error(&registry, &db, ACCOUNT, &intention).await;
    assert!(error.contains("requires Edit"), "{error}");
    assert_eq!(count(&db, "occurrences").await, before);
}

#[tokio::test]
async fn bind_exact_expression_with_unresolvable_selector_fails() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_build_enabled_experimental_tools(&mut registry).unwrap();
    let (promoted, target) = bind_setup(
        &db,
        "Miss bind source",
        "Miss source sentence.",
        "Miss sentence.",
        "Miss bind target",
        "Nothing here matches the requested quote.",
        "bind-miss-promote",
    )
    .await;
    let before = count(&db, "occurrences").await;
    let intention = bind_intent(
        &promoted,
        current_record_body_revision(&db, &target).await.unwrap(),
        "a phrase that never appears in the target",
        "bind-miss",
    );
    let error = execute_error(&registry, &db, ACCOUNT, &intention).await;
    assert!(
        error.contains("text_quote must identify exactly one anchored segment"),
        "{error}"
    );
    assert_eq!(count(&db, "occurrences").await, before);
}

#[tokio::test]
async fn bind_exact_expression_without_bearer_edit_hides_the_bearer() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_build_enabled_experimental_tools(&mut registry).unwrap();
    let target_body = "Bearer-hidden target carries the veiled anchor phrase once.";
    let (promoted, target) = bind_setup(
        &db,
        "Bearer-hidden source",
        "Bearer-hidden source sentence.",
        "Bearer-hidden sentence.",
        "Bearer-hidden target",
        target_body,
        "bind-bearer-promote",
    )
    .await;
    // The Unit's authority bearer is the promotion source record.
    let bearer = read_unit(&db, principal(), &promoted.unit_id)
        .await
        .unwrap()
        .authority_bearer_record_id;
    let artefact_revision = current_record_body_revision(&db, &target).await.unwrap();
    replace_explicit_policy(
        &db,
        ACTOR,
        promoted.unit_id.as_str(),
        vec![AllowEntry::account(ACCOUNT, Capability::Edit)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        ACTOR,
        &target,
        vec![AllowEntry::account(ACCOUNT, Capability::Edit)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        ACTOR,
        &bearer,
        vec![AllowEntry::account(OTHER, Capability::Manage)],
    )
    .await
    .unwrap();
    let before = count(&db, "occurrences").await;
    let intention = bind_intent(
        &promoted,
        artefact_revision,
        "veiled anchor phrase",
        "bind-bearer-veiled",
    );
    let error = execute_error(&registry, &db, ACCOUNT, &intention).await;
    assert_eq!(error, "Unit unavailable");
    assert!(
        !error.contains(&bearer),
        "sanitized error must not leak the bearer id: {error}"
    );
    assert_eq!(count(&db, "occurrences").await, before);
}

// ---------------------------------------------------------------------------
// `get_record` advisory freshness block
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_record_without_occurrences_omits_freshness_entirely() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = freshness_read_registry();
    let id = document(&db, "Plain note", "Nothing bound here.").await;
    let output = get_record_as(&registry, &db, ACCOUNT, json!({ "ids": [id] })).await;
    let record = sole_record(&output);
    assert!(
        record.get("freshness").is_none(),
        "records with no Occurrences must carry no freshness key, not null: {record}"
    );
    let rendered = native_ce::mcp::render::render("get_record", &output).unwrap();
    assert!(
        !rendered.contains("Freshness"),
        "text rendering must stay silent without the block: {rendered}"
    );
}

#[tokio::test]
async fn get_record_with_bound_occurrence_reports_current_projection() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = freshness_read_registry();
    let source_text = "Audience: technical founders.";
    let (source, promoted) = promote_freshness_source(
        &db,
        "Fresh audience",
        source_text,
        "Primary audience: technical founders.",
        "freshness-promote-current",
    )
    .await;
    let output = get_record_as(&registry, &db, ACCOUNT, json!({ "ids": [source] })).await;
    let record = sole_record(&output);
    let freshness = record
        .get("freshness")
        .expect("bound record gains the block");
    assert_eq!(freshness["contract"], READ_FRESHNESS_CONTRACT);
    assert_eq!(freshness["possibly_stale"], false);
    let occurrences = freshness["occurrences"].as_array().unwrap();
    assert_eq!(occurrences.len(), 1);
    let occurrence = &occurrences[0];
    assert_eq!(occurrence["anchor"], "current");
    assert_eq!(occurrence["expression_role"], "canonical");
    assert_eq!(occurrence["unit_id"], json!(promoted.unit_id.as_str()));
    assert!(occurrence.get("unit").is_none());
    assert_eq!(occurrence["unit_moved"], false);
    assert_eq!(
        occurrence["current_range"],
        json!({ "start": 0, "end": source_text.len() as u64 })
    );
    let bound = &occurrence["bound_unit_revision"];
    let current = &occurrence["current_unit_revision"];
    assert_eq!(bound, current);
    assert_eq!(
        bound["event_id"],
        json!(promoted.first_revision.revision_event_id)
    );
    assert_eq!(
        bound["revision_seq"],
        json!(promoted.first_revision.revision_seq)
    );
    assert!(occurrence.get("unit_superseded_by").is_none());
    let rendered = native_ce::mcp::render::render("get_record", &output).unwrap();
    assert!(
        rendered.contains("Freshness: not possibly stale (1 bound occurrences)"),
        "{rendered}"
    );
    assert!(rendered.contains("anchor current"), "{rendered}");
}

#[tokio::test]
async fn get_record_flags_a_moved_unit_behind_a_live_anchor() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = freshness_read_registry();
    let (source, promoted) = promote_freshness_source(
        &db,
        "Moving audience",
        "Audience: technical founders.",
        "Primary audience: technical founders.",
        "freshness-promote-moved",
    )
    .await;
    let revised = revise_unit(
        &db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id.clone(),
            expected_current: promoted.first_revision.clone(),
            content: UnitContent::text("Primary audience: operations leaders.").unwrap(),
            rationale: "Positioning decision changed".into(),
            idempotency_key: IdempotencyKey::new("freshness-revise-moved").unwrap(),
        },
    )
    .await
    .unwrap();
    let output = get_record_as(&registry, &db, ACCOUNT, json!({ "ids": [source] })).await;
    let freshness = sole_record(&output).get("freshness").unwrap().clone();
    assert_eq!(freshness["possibly_stale"], true);
    let occurrence = &freshness["occurrences"].as_array().unwrap()[0];
    assert_eq!(occurrence["anchor"], "current");
    assert_eq!(occurrence["unit_moved"], true);
    assert_eq!(
        occurrence["bound_unit_revision"]["event_id"],
        json!(promoted.first_revision.revision_event_id)
    );
    assert_eq!(
        occurrence["current_unit_revision"]["event_id"],
        json!(revised.new_revision.revision_event_id)
    );
    assert_eq!(
        occurrence["current_unit_revision"]["revision_seq"],
        json!(revised.new_revision.revision_seq)
    );
    assert!(
        occurrence["current_unit_revision"]["revision_seq"]
            .as_i64()
            .unwrap()
            > occurrence["bound_unit_revision"]["revision_seq"]
                .as_i64()
                .unwrap()
    );
    let rendered = native_ce::mcp::render::render("get_record", &output).unwrap();
    assert!(
        rendered.contains("Freshness: possibly stale (1 of 1 bound occurrences: unit moved)"),
        "{rendered}"
    );
}

#[tokio::test]
async fn get_record_reports_stale_anchor_without_flagging_the_moved_unit() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = freshness_read_registry();
    let (source, promoted) = promote_freshness_source(
        &db,
        "Edited audience",
        "Audience: technical founders.",
        "Primary audience: technical founders.",
        "freshness-promote-stale",
    )
    .await;
    revise_unit(
        &db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id.clone(),
            expected_current: promoted.first_revision.clone(),
            content: UnitContent::text("Primary audience: operations leaders.").unwrap(),
            rationale: "Positioning decision changed".into(),
            idempotency_key: IdempotencyKey::new("freshness-revise-stale").unwrap(),
        },
    )
    .await
    .unwrap();
    native_ce::store::update_record(
        &db,
        &source,
        json!({ "body": "Rewritten without the quoted passage." }),
    )
    .await
    .unwrap();
    let output = get_record_as(&registry, &db, ACCOUNT, json!({ "ids": [source] })).await;
    let freshness = sole_record(&output).get("freshness").unwrap().clone();
    assert_eq!(freshness["possibly_stale"], false);
    let occurrence = &freshness["occurrences"].as_array().unwrap()[0];
    assert_eq!(occurrence["anchor"], "stale");
    assert!(
        occurrence["current_range"].is_null(),
        "a stale anchor carries a null range: {occurrence}"
    );
    // The Unit still moved behind the broken anchor; movement is reported but
    // must not flag once the anchor is no longer live.
    assert_eq!(occurrence["unit_moved"], true);
    // The kernel's free-text resolution detail is never forwarded: the block
    // projects state, not prose.
    assert!(
        occurrence.get("detail").is_none(),
        "occurrences carry no detail key: {occurrence}"
    );
}

#[tokio::test]
async fn get_record_withholds_unit_identity_without_view_on_its_bearer() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = freshness_read_registry();
    let bearer_text = "Bearer premise: onboarding owns activation.";
    let (bearer, promoted) = promote_freshness_source(
        &db,
        "Bearer source",
        bearer_text,
        "Onboarding owns activation.",
        "freshness-promote-withheld",
    )
    .await;
    // A second artefact carries an Occurrence against the same Unit, so the
    // bearer (the first source) can be hidden while the artefact stays
    // visible to the unprivileged caller.
    let artefact = document(
        &db,
        "Bound artefact",
        "Artefact premise: onboarding owns activation.",
    )
    .await;
    let artefact_body = "Artefact premise: onboarding owns activation.";
    native_ce::freshness::bind_occurrence(
        &db,
        principal(),
        ACTOR,
        BindOccurrenceInput {
            unit_revision: promoted.first_revision.clone(),
            artefact_revision: current_record_body_revision(&db, &artefact).await.unwrap(),
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: artefact_body.into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            expression_role: ExpressionRole::Canonical,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("freshness-bind-withheld").unwrap(),
        },
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
            content: UnitContent::text("Onboarding owns expansion.").unwrap(),
            rationale: "Scope decision changed".into(),
            idempotency_key: IdempotencyKey::new("freshness-revise-withheld").unwrap(),
        },
    )
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
        &artefact,
        vec![
            AllowEntry::account(ACCOUNT, Capability::Manage),
            AllowEntry::account(OTHER, Capability::View),
        ],
    )
    .await
    .unwrap();
    let output = get_record_as(&registry, &db, OTHER, json!({ "ids": [artefact] })).await;
    let freshness = sole_record(&output).get("freshness").unwrap().clone();
    let occurrence = &freshness["occurrences"].as_array().unwrap()[0];
    assert_eq!(occurrence["unit"], "withheld");
    for absent in [
        "unit_id",
        "bound_unit_revision",
        "current_unit_revision",
        "unit_superseded_by",
    ] {
        assert!(
            occurrence.get(absent).is_none(),
            "withheld occurrences omit {absent}: {occurrence}"
        );
    }
    // Movement is still reported and still counts: the anchor is live and the
    // Unit moved, so the record flags despite the redaction.
    assert_eq!(occurrence["unit_moved"], true);
    assert_eq!(occurrence["anchor"], "current");
    assert_eq!(freshness["possibly_stale"], true);
    let wire = serde_json::to_string(&freshness).unwrap();
    assert!(!wire.contains(promoted.unit_id.as_str()), "{wire}");
    assert!(
        !wire.contains(&revised.new_revision.revision_event_id),
        "{wire}"
    );
    assert!(!wire.contains(&bearer), "{wire}");
    // The text rendering names the redaction and leaks no Unit identifiers:
    // neither the Unit, nor the bearer, nor either revision event.
    let rendered = native_ce::mcp::render::render("get_record", &output).unwrap();
    assert!(rendered.contains("withheld"), "{rendered}");
    for secret in [
        promoted.unit_id.as_str(),
        bearer.as_str(),
        promoted.first_revision.revision_event_id.as_str(),
        revised.new_revision.revision_event_id.as_str(),
    ] {
        assert!(!rendered.contains(secret), "{rendered}");
    }
}

#[tokio::test]
async fn get_record_with_as_of_omits_freshness() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = freshness_read_registry();
    let (source, _) = promote_freshness_source(
        &db,
        "Historical audience",
        "Audience: technical founders.",
        "Primary audience: technical founders.",
        "freshness-promote-historical",
    )
    .await;
    let live = get_record_as(&registry, &db, ACCOUNT, json!({ "ids": [source.clone()] })).await;
    assert!(sole_record(&live).get("freshness").is_some());
    let head = current_history_high_water(&db).await.unwrap().content_seq;
    let historical = get_record_as(
        &registry,
        &db,
        ACCOUNT,
        json!({ "ids": [source], "as_of": { "content_seq": head } }),
    )
    .await;
    let record = sole_record(&historical);
    assert!(
        record.get("freshness").is_none(),
        "historical reads omit the block: {record}"
    );
}

#[tokio::test]
async fn get_record_reports_relocated_anchor_when_the_expression_moves() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = freshness_read_registry();
    let exact = "Audience: technical founders.";
    let (source, promoted) = promote_freshness_source(
        &db,
        "Relocated audience",
        exact,
        "Primary audience: technical founders.",
        "freshness-promote-relocated",
    )
    .await;
    let revised = revise_unit(
        &db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id.clone(),
            expected_current: promoted.first_revision.clone(),
            content: UnitContent::text("Primary audience: operations leaders.").unwrap(),
            rationale: "Positioning decision changed".into(),
            idempotency_key: IdempotencyKey::new("freshness-revise-relocated").unwrap(),
        },
    )
    .await
    .unwrap();
    // The bound expression survives verbatim at a new offset, so the kernel
    // relocates rather than going stale.
    let prefix = "Note: ";
    native_ce::store::update_record(&db, &source, json!({ "body": format!("{prefix}{exact}") }))
        .await
        .unwrap();
    let output = get_record_as(&registry, &db, ACCOUNT, json!({ "ids": [source] })).await;
    let freshness = sole_record(&output).get("freshness").unwrap().clone();
    assert_eq!(freshness["possibly_stale"], true);
    let occurrence = &freshness["occurrences"].as_array().unwrap()[0];
    assert_eq!(occurrence["anchor"], "relocated");
    assert_eq!(occurrence["unit_moved"], true);
    assert_eq!(
        occurrence["current_range"],
        json!({ "start": prefix.len() as u64, "end": (prefix.len() + exact.len()) as u64 })
    );
    assert_eq!(
        occurrence["current_unit_revision"]["event_id"],
        json!(revised.new_revision.revision_event_id)
    );
}

#[tokio::test]
async fn get_record_lists_only_viewable_successors_and_flags_through_them() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = freshness_read_registry();
    let (source, first) = promote_freshness_source(
        &db,
        "Superseded audience",
        "Audience: technical founders.",
        "Primary audience: technical founders.",
        "freshness-promote-superseded",
    )
    .await;
    let (_, second) = promote_freshness_source(
        &db,
        "Successor audience",
        "Audience: operations leaders.",
        "Primary audience: operations leaders.",
        "freshness-promote-successor",
    )
    .await;
    native_ce::freshness::supersede_unit(
        &db,
        principal(),
        ACTOR,
        SupersedeUnitInput {
            predecessor_unit_id: first.unit_id.clone(),
            successors: vec![second.first_revision.clone()],
            rationale: "Positioning moved to the successor Unit".into(),
            idempotency_key: IdempotencyKey::new("freshness-supersede").unwrap(),
        },
    )
    .await
    .unwrap();
    // The Unit itself never moved: the flag comes from the successor alone.
    let output = get_record_as(&registry, &db, ACCOUNT, json!({ "ids": [source.clone()] })).await;
    let freshness = sole_record(&output).get("freshness").unwrap().clone();
    let occurrence = &freshness["occurrences"].as_array().unwrap()[0];
    assert_eq!(occurrence["anchor"], "current");
    assert_eq!(occurrence["unit_moved"], false);
    assert_eq!(
        occurrence["unit_superseded_by"],
        json!([second.unit_id.as_str()])
    );
    assert_eq!(freshness["possibly_stale"], true);
    // A caller who can View the predecessor but not the successor loses the
    // successor list — and with it the flag, since hidden successors never
    // contribute through the boolean.
    let successor_bearer = second.first_revision.subject_id.clone();
    for hidden in [second.unit_id.as_str(), successor_bearer.as_str()] {
        replace_explicit_policy(
            &db,
            ACTOR,
            hidden,
            vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
        )
        .await
        .unwrap();
    }
    for visible in [first.unit_id.as_str(), source.as_str()] {
        replace_explicit_policy(
            &db,
            ACTOR,
            visible,
            vec![
                AllowEntry::account(ACCOUNT, Capability::Manage),
                AllowEntry::account(OTHER, Capability::View),
            ],
        )
        .await
        .unwrap();
    }
    let output = get_record_as(&registry, &db, OTHER, json!({ "ids": [source] })).await;
    let freshness = sole_record(&output).get("freshness").unwrap().clone();
    let occurrence = &freshness["occurrences"].as_array().unwrap()[0];
    assert_eq!(
        occurrence["unit_id"],
        json!(first.unit_id.as_str()),
        "the predecessor itself stays visible: {occurrence}"
    );
    assert!(
        occurrence.get("unit_superseded_by").is_none(),
        "hidden successors are dropped, not nulled: {occurrence}"
    );
    assert_eq!(occurrence["unit_moved"], false);
    assert_eq!(freshness["possibly_stale"], false);
    let wire = serde_json::to_string(&freshness).unwrap();
    assert!(!wire.contains(second.unit_id.as_str()), "{wire}");
}

#[tokio::test]
async fn get_record_lists_every_bound_occurrence_in_binding_order() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = freshness_read_registry();
    let (source, first) = promote_freshness_source(
        &db,
        "Twice-bound record",
        "Alpha premise. Beta premise.",
        "The alpha premise.",
        "freshness-promote-multi",
    )
    .await;
    let other = document(&db, "Other source", "Unrelated content here.").await;
    let other_revision = current_record_body_revision(&db, &other).await.unwrap();
    let second = promote_idea(
        &db,
        principal(),
        ACTOR,
        PromoteIdeaInput {
            source_revision: other_revision,
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: "Unrelated content here.".into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            first_content: UnitContent::text("The beta premise.").unwrap(),
            expression_role: ExpressionRole::Summary,
            label: Some("Beta unit".into()),
            requested_unit_id: None,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("freshness-promote-multi-second").unwrap(),
        },
    )
    .await
    .unwrap();
    native_ce::freshness::bind_occurrence(
        &db,
        principal(),
        ACTOR,
        BindOccurrenceInput {
            unit_revision: second.first_revision.clone(),
            artefact_revision: current_record_body_revision(&db, &source).await.unwrap(),
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: "Beta premise.".into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            expression_role: ExpressionRole::Summary,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("freshness-bind-multi-second").unwrap(),
        },
    )
    .await
    .unwrap();
    let output = get_record_as(&registry, &db, ACCOUNT, json!({ "ids": [source] })).await;
    let freshness = sole_record(&output).get("freshness").unwrap().clone();
    let occurrences = freshness["occurrences"].as_array().unwrap();
    assert_eq!(occurrences.len(), 2);
    assert_eq!(
        occurrences[0]["occurrence_id"],
        json!(first.occurrence_id.as_str())
    );
    assert_eq!(occurrences[0]["expression_role"], "canonical");
    assert_eq!(occurrences[1]["expression_role"], "summary");
    assert_eq!(occurrences[1]["unit_id"], json!(second.unit_id.as_str()));
    assert_ne!(
        occurrences[0]["occurrence_id"],
        occurrences[1]["occurrence_id"]
    );
    assert_eq!(freshness["possibly_stale"], false);
    let rendered = native_ce::mcp::render::render("get_record", &output).unwrap();
    assert_eq!(
        rendered
            .lines()
            .filter(|line| line.starts_with("  Occurrence "))
            .count(),
        2,
        "{rendered}"
    );
}

#[tokio::test]
async fn get_record_withholds_when_only_the_bearer_is_hidden() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = freshness_read_registry();
    let (bearer, promoted) = promote_freshness_source(
        &db,
        "Bearer-only source",
        "Bearer premise: onboarding owns activation.",
        "Onboarding owns activation.",
        "freshness-promote-bearer-only",
    )
    .await;
    let artefact_body = "Artefact premise: onboarding owns activation.";
    let artefact = document(&db, "Bearer-only artefact", artefact_body).await;
    native_ce::freshness::bind_occurrence(
        &db,
        principal(),
        ACTOR,
        BindOccurrenceInput {
            unit_revision: promoted.first_revision.clone(),
            artefact_revision: current_record_body_revision(&db, &artefact).await.unwrap(),
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: artefact_body.into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            expression_role: ExpressionRole::Canonical,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("freshness-bind-bearer-only").unwrap(),
        },
    )
    .await
    .unwrap();
    // View on the Unit record alone is not enough: the authority bearer stays
    // hidden, so the occurrence is withheld.
    replace_explicit_policy(
        &db,
        ACTOR,
        promoted.unit_id.as_str(),
        vec![
            AllowEntry::account(ACCOUNT, Capability::Manage),
            AllowEntry::account(OTHER, Capability::View),
        ],
    )
    .await
    .unwrap();
    for hidden in [bearer.as_str(), artefact.as_str()] {
        let mut entries = vec![AllowEntry::account(ACCOUNT, Capability::Manage)];
        if hidden == artefact.as_str() {
            entries.push(AllowEntry::account(OTHER, Capability::View));
        }
        replace_explicit_policy(&db, ACTOR, hidden, entries)
            .await
            .unwrap();
    }
    let output = get_record_as(&registry, &db, OTHER, json!({ "ids": [artefact] })).await;
    let occurrence = sole_record(&output)["freshness"]["occurrences"]
        .as_array()
        .unwrap()[0]
        .clone();
    assert_eq!(occurrence["unit"], "withheld");
    assert!(occurrence.get("unit_id").is_none());
    assert_eq!(occurrence["anchor"], "current");
}

// ---------------------------------------------------------------------------
// `revise_exact_expression` and Occurrence reconciliation
// ---------------------------------------------------------------------------

fn revise_intent(
    unit_id: &UnitId,
    expected_current: RevisionRef,
    content: &str,
    key: &str,
) -> ExperimentalAgentIntent {
    ExperimentalAgentIntent::ReviseExactExpression {
        input: ReviseUnitInput {
            unit_id: unit_id.clone(),
            expected_current,
            content: UnitContent::text(content).unwrap(),
            rationale: "Test revision".into(),
            idempotency_key: IdempotencyKey::new(key).unwrap(),
        },
    }
}

fn revised_parts(evidence: &ExperimentalAgentIntentEvidence) -> (&ReviseUnitResult, &UnitView) {
    match &evidence.result {
        ExperimentalAgentIntentResult::ReviseExactExpression { revised, unit } => (revised, unit),
        _ => panic!("expected revise exact expression evidence"),
    }
}

#[tokio::test]
async fn revise_exact_expression_revises_the_unit_and_flags_the_source() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = freshness_read_registry();
    let source_text = "Audience: technical founders.";
    let (source, promoted) = promote_freshness_source(
        &db,
        "Revise source",
        source_text,
        "Primary audience: technical founders.",
        "revise-intent-promote",
    )
    .await;
    let evidence = execute(
        &registry,
        &db,
        ACCOUNT,
        &revise_intent(
            &promoted.unit_id,
            promoted.first_revision.clone(),
            "Primary audience: operations leaders.",
            "revise-intent-first",
        ),
    )
    .await;
    assert_eq!(
        evidence.experimental_contract,
        EXPERIMENTAL_AGENT_INTENT_CONTRACT
    );
    let (revised, unit) = revised_parts(&evidence);
    assert_eq!(revised.previous_revision, promoted.first_revision);
    // Promotion appends the first revision and then its binding Occurrence,
    // so a tight revise lands exactly two sequence steps past the previous
    // revision: revision, binding, revision. The registry wrapper appends no
    // content events of its own.
    assert_eq!(
        revised.new_revision.revision_seq,
        revised.previous_revision.revision_seq + 2
    );
    assert_eq!(unit.unit_id, promoted.unit_id);
    assert_eq!(unit.current_heads, vec![revised.new_revision.clone()]);
    let read = read_unit(&db, principal(), &promoted.unit_id)
        .await
        .unwrap();
    assert_eq!(read.current_heads, vec![revised.new_revision.clone()]);
    let output = get_record_as(&registry, &db, ACCOUNT, json!({ "ids": [source] })).await;
    let freshness = sole_record(&output).get("freshness").unwrap().clone();
    assert_eq!(freshness["possibly_stale"], true);
    let occurrence = &freshness["occurrences"].as_array().unwrap()[0];
    assert_eq!(occurrence["unit_moved"], true);
    assert!(
        occurrence.get("reconciled_by").is_none(),
        "no later head-bound binding exists yet: {occurrence}"
    );
}

#[tokio::test]
async fn revised_unit_rebound_into_the_same_record_reconciles_the_earlier_binding() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = freshness_read_registry();
    let source_text = "Audience: technical founders.";
    let (source, promoted) = promote_freshness_source(
        &db,
        "Reconcile source",
        source_text,
        "Primary audience: technical founders.",
        "revise-reconcile-promote",
    )
    .await;
    let revised = revise_unit(
        &db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id.clone(),
            expected_current: promoted.first_revision.clone(),
            content: UnitContent::text("Primary audience: operations leaders.").unwrap(),
            rationale: "Positioning decision changed".into(),
            idempotency_key: IdempotencyKey::new("revise-reconcile-revise").unwrap(),
        },
    )
    .await
    .unwrap();
    let bind = execute(
        &registry,
        &db,
        ACCOUNT,
        &ExperimentalAgentIntent::BindExactExpression {
            input: BindOccurrenceInput {
                unit_revision: revised.new_revision.clone(),
                artefact_revision: current_record_body_revision(&db, &source).await.unwrap(),
                selectors: vec![OccurrenceSelector::TextQuote {
                    exact: source_text.into(),
                    prefix: None,
                    suffix: None,
                    position_hint: None,
                }],
                expression_role: ExpressionRole::Canonical,
                requested_occurrence_id: None,
                idempotency_key: IdempotencyKey::new("revise-reconcile-bind").unwrap(),
            },
        },
    )
    .await;
    let newer_id = match &bind.result {
        ExperimentalAgentIntentResult::BindExactExpression { bound, .. } => {
            bound.occurrence.occurrence_id.clone()
        }
        _ => panic!("expected bind exact expression evidence"),
    };
    let output = get_record_as(&registry, &db, ACCOUNT, json!({ "ids": [source] })).await;
    let freshness = sole_record(&output).get("freshness").unwrap().clone();
    assert_eq!(freshness["possibly_stale"], false);
    let occurrences = freshness["occurrences"].as_array().unwrap().clone();
    assert_eq!(occurrences.len(), 2);
    assert_eq!(occurrences[0]["unit_moved"], true);
    assert_eq!(
        occurrences[0]["reconciled_by"],
        json!(newer_id.as_str()),
        "the earlier binding names the head-bound rebind: {occurrences:?}"
    );
    assert_eq!(occurrences[1]["occurrence_id"], json!(newer_id.as_str()));
    assert_eq!(occurrences[1]["unit_moved"], false);
    assert!(
        occurrences[1].get("reconciled_by").is_none(),
        "the head-bound rebind is evaluated normally: {occurrences:?}"
    );
    let rendered = native_ce::mcp::render::render("get_record", &output).unwrap();
    assert!(
        rendered.contains("reconciled by"),
        "text rendering names the reconciliation: {rendered}"
    );
    assert!(
        rendered.contains(newer_id.as_str()),
        "text rendering names the reconciling Occurrence: {rendered}"
    );
}

#[tokio::test]
async fn binding_a_superseded_revision_does_not_reconcile() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = freshness_read_registry();
    let (source, promoted) = promote_freshness_source(
        &db,
        "Stale rebind source",
        "Alpha anchor phrase. Beta anchor phrase.",
        "Alpha anchor phrase.",
        "revise-stale-rebind-promote",
    )
    .await;
    revise_unit(
        &db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id.clone(),
            expected_current: promoted.first_revision.clone(),
            content: UnitContent::text("Beta anchor phrase, revised.").unwrap(),
            rationale: "Wording decision changed".into(),
            idempotency_key: IdempotencyKey::new("revise-stale-rebind-revise").unwrap(),
        },
    )
    .await
    .unwrap();
    // A later bind names the superseded revision, not the head, so nothing
    // is reconciled even though the binding itself is newer.
    execute(
        &registry,
        &db,
        ACCOUNT,
        &ExperimentalAgentIntent::BindExactExpression {
            input: BindOccurrenceInput {
                unit_revision: promoted.first_revision.clone(),
                artefact_revision: current_record_body_revision(&db, &source).await.unwrap(),
                selectors: vec![OccurrenceSelector::TextQuote {
                    exact: "Beta anchor phrase.".into(),
                    prefix: None,
                    suffix: None,
                    position_hint: None,
                }],
                expression_role: ExpressionRole::Quotation,
                requested_occurrence_id: None,
                idempotency_key: IdempotencyKey::new("revise-stale-rebind-bind").unwrap(),
            },
        },
    )
    .await;
    let output = get_record_as(&registry, &db, ACCOUNT, json!({ "ids": [source] })).await;
    let freshness = sole_record(&output).get("freshness").unwrap().clone();
    assert_eq!(freshness["possibly_stale"], true);
    let occurrences = freshness["occurrences"].as_array().unwrap();
    assert_eq!(occurrences.len(), 2);
    for occurrence in occurrences {
        assert!(
            occurrence.get("reconciled_by").is_none(),
            "a non-head rebind reconciles nothing: {occurrence}"
        );
    }
}

#[tokio::test]
async fn reconciled_occurrences_stay_withheld_without_bearer_view() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = freshness_read_registry();
    let source_text = "Audience: technical founders.";
    let (source, promoted) = promote_freshness_source(
        &db,
        "Withheld reconcile source",
        source_text,
        "Primary audience: technical founders.",
        "revise-withheld-promote",
    )
    .await;
    let revised = revise_unit(
        &db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id.clone(),
            expected_current: promoted.first_revision.clone(),
            content: UnitContent::text("Primary audience: operations leaders.").unwrap(),
            rationale: "Positioning decision changed".into(),
            idempotency_key: IdempotencyKey::new("revise-withheld-revise").unwrap(),
        },
    )
    .await
    .unwrap();
    let bound = native_ce::freshness::bind_occurrence(
        &db,
        principal(),
        ACTOR,
        BindOccurrenceInput {
            unit_revision: revised.new_revision.clone(),
            artefact_revision: current_record_body_revision(&db, &source).await.unwrap(),
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: source_text.into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            expression_role: ExpressionRole::Canonical,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("revise-withheld-bind").unwrap(),
        },
    )
    .await
    .unwrap();
    let newer_id = bound.occurrence.occurrence_id.clone();
    // The promotion source is the Unit's authority bearer: hide the Unit and
    // its bearer while the artefact (the same source record) stays visible.
    replace_explicit_policy(
        &db,
        ACTOR,
        promoted.unit_id.as_str(),
        vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        ACTOR,
        &source,
        vec![
            AllowEntry::account(ACCOUNT, Capability::Manage),
            AllowEntry::account(OTHER, Capability::View),
        ],
    )
    .await
    .unwrap();
    let output = get_record_as(&registry, &db, OTHER, json!({ "ids": [source] })).await;
    let freshness = sole_record(&output).get("freshness").unwrap().clone();
    assert_eq!(freshness["possibly_stale"], false);
    let occurrences = freshness["occurrences"].as_array().unwrap();
    assert_eq!(occurrences.len(), 2);
    for occurrence in occurrences {
        assert_eq!(occurrence["unit"], "withheld");
        assert!(occurrence.get("unit_id").is_none());
    }
    assert_eq!(
        occurrences[0]["reconciled_by"],
        json!(newer_id.as_str()),
        "reconciliation survives redaction: {occurrences:?}"
    );
    // The older occurrence really moved off the head: the clean flag comes
    // from reconciliation, not from a Unit that never changed.
    assert_eq!(occurrences[0]["unit_moved"], true);
    let wire = serde_json::to_string(&freshness).unwrap();
    assert!(!wire.contains(promoted.unit_id.as_str()), "{wire}");
    assert!(!wire.contains(&source), "{wire}");
}

#[tokio::test]
async fn revise_exact_expression_replay_returns_the_same_revision() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_build_enabled_experimental_tools(&mut registry).unwrap();
    let (_, promoted) = promote_freshness_source(
        &db,
        "Replay revise source",
        "Replay revise premise.",
        "Replay revise sentence.",
        "revise-replay-promote",
    )
    .await;
    let intention = revise_intent(
        &promoted.unit_id,
        promoted.first_revision.clone(),
        "Replay revise sentence, refined.",
        "revise-replay-key",
    );
    let first = execute(&registry, &db, ACCOUNT, &intention).await;
    let (first_revised, _) = revised_parts(&first);
    let first_new = first_revised.new_revision.clone();
    let before = count(&db, "unit_revisions").await;
    let second = execute(&registry, &db, ACCOUNT, &intention).await;
    let (second_revised, _) = revised_parts(&second);
    assert_eq!(second_revised.new_revision, first_new);
    assert_eq!(second_revised.previous_revision, promoted.first_revision);
    assert_eq!(count(&db, "unit_revisions").await, before);
}

#[tokio::test]
async fn revise_exact_expression_with_a_stale_expected_current_fails_cleanly() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_build_enabled_experimental_tools(&mut registry).unwrap();
    let (_, promoted) = promote_freshness_source(
        &db,
        "Stale revise source",
        "Stale revise premise.",
        "Stale revise sentence.",
        "revise-stale-promote",
    )
    .await;
    execute(
        &registry,
        &db,
        ACCOUNT,
        &revise_intent(
            &promoted.unit_id,
            promoted.first_revision.clone(),
            "Stale revise sentence, refined.",
            "revise-stale-first",
        ),
    )
    .await;
    let before = count(&db, "unit_revisions").await;
    let error = execute_error(
        &registry,
        &db,
        ACCOUNT,
        &revise_intent(
            &promoted.unit_id,
            promoted.first_revision.clone(),
            "A conflicting revision.",
            "revise-stale-second",
        ),
    )
    .await;
    assert!(
        error.contains("expected-current"),
        "stale expected revisions must fail on the head check: {error}"
    );
    assert_eq!(count(&db, "unit_revisions").await, before);
}

#[tokio::test]
async fn revise_exact_expression_without_bearer_edit_hides_the_bearer() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_build_enabled_experimental_tools(&mut registry).unwrap();
    let (bearer, promoted) = promote_freshness_source(
        &db,
        "Revise bearer source",
        "Revise bearer premise.",
        "Revise bearer sentence.",
        "revise-bearer-promote",
    )
    .await;
    replace_explicit_policy(
        &db,
        ACTOR,
        promoted.unit_id.as_str(),
        vec![AllowEntry::account(ACCOUNT, Capability::Edit)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        ACTOR,
        &bearer,
        vec![AllowEntry::account(OTHER, Capability::Manage)],
    )
    .await
    .unwrap();
    let before = count(&db, "unit_revisions").await;
    let error = execute_error(
        &registry,
        &db,
        ACCOUNT,
        &revise_intent(
            &promoted.unit_id,
            promoted.first_revision.clone(),
            "A revision the caller may not record.",
            "revise-bearer-veiled",
        ),
    )
    .await;
    assert_eq!(error, "Unit unavailable");
    assert!(
        !error.contains(&bearer),
        "sanitized error must not leak the bearer id: {error}"
    );
    assert_eq!(count(&db, "unit_revisions").await, before);
}

#[test]
fn revise_schema_branch_matches_the_revise_unit_input() {
    let mut registry = ToolRegistry::new();
    register_experimental_agent_intent_tool(&mut registry).unwrap();
    let schema = &registry.get(TOOL).unwrap().input_schema;
    let branches = schema["oneOf"].as_array().unwrap();
    assert_eq!(branches.len(), 6);
    let mut consts: Vec<&str> = branches
        .iter()
        .map(|branch| {
            branch["properties"]["intention"]["const"]
                .as_str()
                .expect("every branch names its intention")
        })
        .collect();
    consts.sort();
    assert_eq!(
        consts,
        vec![
            "assess_exact_change",
            "bind_exact_expression",
            "declare_sources",
            "promote_exact_expression",
            "reconcile_affected_output",
            "revise_exact_expression",
        ]
    );
    let revise = branches
        .iter()
        .find(|branch| branch["properties"]["intention"]["const"] == "revise_exact_expression")
        .expect("revise branch");
    assert_eq!(revise["additionalProperties"], false);
    // The registry wrapper adds run correlation alongside the intention.
    for required in ["intention", "input", "run_key"] {
        assert!(
            revise["required"]
                .as_array()
                .unwrap()
                .contains(&json!(required)),
            "{revise}"
        );
    }
    let input = &revise["properties"]["input"];
    assert_eq!(input["additionalProperties"], false);
    for required in [
        "unit_id",
        "expected_current",
        "content",
        "rationale",
        "idempotency_key",
    ] {
        assert!(
            input["required"]
                .as_array()
                .unwrap()
                .contains(&json!(required)),
            "{input}"
        );
    }
}

#[tokio::test]
async fn head_bound_sibling_bindings_do_not_reconcile() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = freshness_read_registry();
    // Both bindings name the head revision: the second is newer but there is
    // nothing to reconcile, regardless of quote or expression role.
    let (source, promoted) = promote_freshness_source(
        &db,
        "Sibling source",
        "Alpha anchor phrase. Beta anchor phrase.",
        "Alpha anchor phrase.",
        "head-sibling-promote",
    )
    .await;
    native_ce::freshness::bind_occurrence(
        &db,
        principal(),
        ACTOR,
        BindOccurrenceInput {
            unit_revision: promoted.first_revision.clone(),
            artefact_revision: current_record_body_revision(&db, &source).await.unwrap(),
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: "Beta anchor phrase.".into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            expression_role: ExpressionRole::Quotation,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("head-sibling-bind").unwrap(),
        },
    )
    .await
    .unwrap();
    let output = get_record_as(&registry, &db, ACCOUNT, json!({ "ids": [source] })).await;
    let freshness = sole_record(&output).get("freshness").unwrap().clone();
    assert_eq!(freshness["possibly_stale"], false);
    let occurrences = freshness["occurrences"].as_array().unwrap();
    assert_eq!(occurrences.len(), 2);
    for occurrence in occurrences {
        assert_eq!(occurrence["unit_moved"], false);
        assert!(
            occurrence.get("reconciled_by").is_none(),
            "a head-bound Occurrence needs no reconciling: {occurrence}"
        );
    }
}

#[tokio::test]
async fn revise_exact_expression_on_a_missing_unit_hides_the_unit() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_build_enabled_experimental_tools(&mut registry).unwrap();
    let ghost = UnitId::new("unit-that-was-never-created").unwrap();
    let error = execute_error(
        &registry,
        &db,
        ACCOUNT,
        &ExperimentalAgentIntent::ReviseExactExpression {
            input: ReviseUnitInput {
                unit_id: ghost.clone(),
                expected_current: RevisionRef {
                    subject_kind: RevisionSubjectKind::Unit,
                    subject_id: ghost.as_str().into(),
                    revision_event_id: "event-that-was-never-created".into(),
                    revision_seq: 1,
                    source_slot: RevisionSourceSlot::UnitContent,
                    sha256: "0".repeat(64),
                },
                content: UnitContent::text("Ghost content.").unwrap(),
                rationale: "Probing a missing Unit".into(),
                idempotency_key: IdempotencyKey::new("revise-ghost-unit").unwrap(),
            },
        },
    )
    .await;
    assert_eq!(error, "Unit unavailable");
}

/// Reconciliation is a read-time projection of the current head, not stored
/// state: while rev3 is the head, the rev1 and rev2 bindings are both
/// reconciled by the rev3 binding and nothing flags; after a further revise
/// to rev4 with no rebind, no occurrence is head-bound-later, so all three
/// lose `reconciled_by` and all three flag as moved.
#[tokio::test]
async fn reconciliation_follows_the_head_across_a_bind_chain() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = freshness_read_registry();
    let source_text = "Audience: technical founders.";
    let (source, promoted) = promote_freshness_source(
        &db,
        "Chain source",
        source_text,
        "Primary audience: technical founders.",
        "chain-promote",
    )
    .await;
    async fn revise_to(
        db: &native_ce::Db,
        unit_id: &UnitId,
        expected_current: RevisionRef,
        content: &str,
        key: &str,
    ) -> RevisionRef {
        revise_unit(
            db,
            principal(),
            ACTOR,
            ReviseUnitInput {
                unit_id: unit_id.clone(),
                expected_current,
                content: UnitContent::text(content).unwrap(),
                rationale: "Chain revision".into(),
                idempotency_key: IdempotencyKey::new(key).unwrap(),
            },
        )
        .await
        .unwrap()
        .new_revision
    }
    async fn bind_head(
        db: &native_ce::Db,
        unit_revision: RevisionRef,
        artefact: &str,
        exact: &str,
        key: &str,
    ) -> OccurrenceId {
        native_ce::freshness::bind_occurrence(
            db,
            principal(),
            ACTOR,
            BindOccurrenceInput {
                unit_revision,
                artefact_revision: current_record_body_revision(db, artefact).await.unwrap(),
                selectors: vec![OccurrenceSelector::TextQuote {
                    exact: exact.into(),
                    prefix: None,
                    suffix: None,
                    position_hint: None,
                }],
                expression_role: ExpressionRole::Canonical,
                requested_occurrence_id: None,
                idempotency_key: IdempotencyKey::new(key).unwrap(),
            },
        )
        .await
        .unwrap()
        .occurrence
        .occurrence_id
    }
    let rev2 = revise_to(
        &db,
        &promoted.unit_id,
        promoted.first_revision.clone(),
        "Primary audience: operations leaders.",
        "chain-revise-2",
    )
    .await;
    bind_head(&db, rev2.clone(), &source, source_text, "chain-bind-2").await;
    let rev3 = revise_to(
        &db,
        &promoted.unit_id,
        rev2,
        "Primary audience: finance leaders.",
        "chain-revise-3",
    )
    .await;
    let third = bind_head(&db, rev3.clone(), &source, source_text, "chain-bind-3").await;
    let output = get_record_as(&registry, &db, ACCOUNT, json!({ "ids": [source] })).await;
    let freshness = sole_record(&output).get("freshness").unwrap().clone();
    assert_eq!(freshness["possibly_stale"], false);
    let occurrences = freshness["occurrences"].as_array().unwrap().clone();
    assert_eq!(occurrences.len(), 3);
    assert_eq!(occurrences[0]["unit_moved"], true);
    assert_eq!(occurrences[1]["unit_moved"], true);
    assert_eq!(occurrences[2]["unit_moved"], false);
    for occurrence in &occurrences[..2] {
        assert_eq!(
            occurrence["reconciled_by"],
            json!(third.as_str()),
            "both earlier bindings name the head-bound rebind: {occurrence}"
        );
    }
    assert!(
        occurrences[2].get("reconciled_by").is_none(),
        "the head-bound rebind is evaluated normally: {occurrences:?}"
    );
    // A further revise with no rebind moves the head past every binding:
    // nothing is head-bound-later anymore, so reconciliation evaporates and
    // every occurrence flags.
    revise_to(
        &db,
        &promoted.unit_id,
        rev3,
        "Primary audience: legal leaders.",
        "chain-revise-4",
    )
    .await;
    let output = get_record_as(&registry, &db, ACCOUNT, json!({ "ids": [source] })).await;
    let freshness = sole_record(&output).get("freshness").unwrap().clone();
    assert_eq!(freshness["possibly_stale"], true);
    let occurrences = freshness["occurrences"].as_array().unwrap();
    assert_eq!(occurrences.len(), 3);
    for occurrence in occurrences {
        assert_eq!(occurrence["unit_moved"], true);
        assert!(
            occurrence.get("reconciled_by").is_none(),
            "no head-bound-later binding remains: {occurrence}"
        );
    }
}
