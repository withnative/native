//! Observable freshness scenario shared by every persistence adapter.
//!
//! Keep this module above the physical-storage boundary. It speaks only in
//! exact domain references, logical callers, and semantic harness operations.

use native_ce::freshness::*;
use native_ce::Result;

use super::{AuditEvidence, FreshnessHarness};

const A_ID: &str = "f9e50000-0000-4000-8000-000000000007";
const B_ID: &str = "f9e50000-0000-4000-8000-000000000008";
const AP_ID: &str = "f9e50000-0000-4000-8000-000000000001";
const IN_ID: &str = "f9e50000-0000-4000-8000-000000000004";
const C_ID: &str = "f9e50000-0000-4000-8000-000000000003";
const D_ID: &str = "f9e50000-0000-4000-8000-000000000002";
const OMIT_ID: &str = "f9e50000-0000-4000-8000-000000000005";
const OVER_ID: &str = "f9e50000-0000-4000-8000-000000000006";

const A1: &str = "The primary launch audience is technical founders.";
const U1: &str = "Primary launch audience: technical founders.";
const B1: &str = "We are initially building for founders who are comfortable working directly with technical tools.";
const U2: &str = "Primary launch audience: nontechnical operators adopting agents.";

#[derive(Clone, Debug)]
pub struct TwelveStepEvidence {
    pub unit_id: UnitId,
    pub u1: RevisionRef,
    pub u2: RevisionRef,
    pub first_receipt: ReceiptId,
    pub first_output_revision: RevisionRef,
    pub first_history_high_water: HistoryHighWater,
    pub provisional_receipt: ReceiptId,
    pub provisional_output_revision: RevisionRef,
    pub provisional_history_high_water: HistoryHighWater,
    pub relocation: OccurrenceResolutionState,
    pub broken_anchor: OccurrenceResolutionState,
    pub material_disclosure: DisclosureDecision,
    pub immaterial_disclosure: DisclosureDecision,
    pub confirmed_audit: AuditEvidence,
    pub underdeclared_audit: AuditEvidence,
    pub overdeclared_audit: AuditEvidence,
}

fn request(intent: &str, scope: &str) -> ContextRequest {
    ContextRequest {
        intent: intent.into(),
        task_scope: scope.into(),
        risk_inputs: vec!["audience accuracy".into()],
    }
}

fn conclusion() -> AffectedConclusion {
    AffectedConclusion {
        key: "hero.audience_and_language".into(),
        description: "Audience named by the homepage hero".into(),
    }
}

fn dependency(id: &str, source_revision: RevisionRef) -> DependencyInput {
    DependencyInput {
        dependency_id: DependencyId::new(id).unwrap(),
        source_revision,
        semantic_role: "premise".into(),
        affected_conclusion: conclusion(),
        rationale: "The hero names the audience selected by this premise".into(),
        reconsideration_trigger: "The launch audience materially broadens, narrows, or changes"
            .into(),
        confidence: Some(0.94),
    }
}

fn provenance(sources: &[RevisionRef]) -> Vec<ProvenanceUse> {
    sources
        .iter()
        .map(|source_revision| ProvenanceUse {
            source_revision: source_revision.clone(),
            reason: "Admitted while drafting the output".into(),
        })
        .collect()
}

fn one_dependency_policy() -> ResolutionPolicy {
    let mut policy = ResolutionPolicy::agent_speed_default();
    policy.dependency_budget = 1;
    policy
}

fn text_selector(exact: &str) -> OccurrenceSelector {
    OccurrenceSelector::TextQuote {
        exact: exact.into(),
        prefix: None,
        suffix: None,
        position_hint: None,
    }
}

/// Execute the complete twelve-step fixture through a semantic harness.
pub async fn twelve_step<H: FreshnessHarness>(
    harness: &H,
    database: &H::Database,
) -> Result<TwelveStepEvidence> {
    // 1. Natural authoring: ordinary work exists before semantic atomisation.
    let a1 = harness
        .create_artefact(database, A_ID, "Launch audience source", A1)
        .await?;
    let initial = harness.semantic_inventory(database).await?;
    assert_eq!(
        (initial.units, initial.occurrences, initial.receipts),
        (0, 0, 0)
    );
    assert_eq!(harness.artefact_body(database, A_ID).await?, A1);

    // 2. Lazy promotion survives source metadata movement without laundering
    // the original expression address into the Unit identity.
    let a1_selector = text_selector(A1);
    let promoted = harness
        .promote_idea(
            database,
            PromoteIdeaInput {
                source_revision: a1.clone(),
                selectors: vec![a1_selector.clone()],
                first_content: UnitContent::text(U1)?,
                expression_role: ExpressionRole::Canonical,
                label: Some("Primary launch audience".into()),
                requested_unit_id: Some(UnitId::new("f9e50000-0000-4000-8000-000000000009")?),
                requested_occurrence_id: Some(OccurrenceId::new("proof:occurrence-a")?),
                idempotency_key: IdempotencyKey::new("proof:promote-audience")?,
            },
        )
        .await?;
    assert_ne!(promoted.unit_id.as_str(), A_ID);
    assert_eq!(harness.artefact_body(database, A_ID).await?, A1);
    let unit = harness.read_unit(database, &promoted.unit_id).await?;
    assert_eq!(unit.current_heads, vec![promoted.first_revision.clone()]);
    assert_eq!(unit.authority_bearer_record_id, A_ID);
    assert!(
        harness
            .is_subordinate_in_ordinary_listing(database, &promoted.unit_id)
            .await?
    );
    let occurrence_before_source_rename = harness
        .list_occurrences(database, &promoted.unit_id)
        .await?
        .into_iter()
        .find(|occurrence| occurrence.occurrence_id == promoted.occurrence_id)
        .expect("promoted source occurrence must be stored before rename");
    harness
        .rename_artefact(database, A_ID, "Audience research — renamed")
        .await?;
    assert_eq!(
        harness.artefact_name(database, A_ID).await?,
        "Audience research — renamed"
    );
    let unit_after_source_rename = harness.read_unit(database, &promoted.unit_id).await?;
    assert_eq!(unit_after_source_rename.unit_id, promoted.unit_id);
    assert_eq!(
        unit_after_source_rename.current_heads,
        vec![promoted.first_revision.clone()]
    );
    let occurrence_after_source_rename = harness
        .list_occurrences(database, &promoted.unit_id)
        .await?
        .into_iter()
        .find(|occurrence| occurrence.occurrence_id == promoted.occurrence_id)
        .expect("promoted source occurrence must remain addressable after rename");
    assert_eq!(
        occurrence_after_source_rename,
        occurrence_before_source_rename
    );
    assert_eq!(occurrence_after_source_rename.artefact_revision, a1);
    assert_eq!(occurrence_after_source_rename.selectors.len(), 1);
    assert!(matches!(
        &occurrence_after_source_rename.selectors[0],
        OccurrenceSelector::TextQuote {
            exact,
            prefix: None,
            suffix: None,
            position_hint: Some(0),
        } if exact == A1
    ));
    assert_eq!(
        occurrence_after_source_rename.artefact_revision.sha256,
        a1.sha256
    );

    // 3. One immutable idea may have independently anchored expressions.
    let b1 = harness
        .create_artefact(database, B_ID, "Product description", B1)
        .await?;
    let bound_b = harness
        .bind_occurrence(
            database,
            BindOccurrenceInput {
                unit_revision: promoted.first_revision.clone(),
                artefact_revision: b1.clone(),
                selectors: vec![text_selector(B1)],
                expression_role: ExpressionRole::Paraphrase,
                requested_occurrence_id: Some(OccurrenceId::new("proof:occurrence-b")?),
                idempotency_key: IdempotencyKey::new("proof:bind-b")?,
            },
        )
        .await?;
    let occurrences = harness
        .list_occurrences(database, &promoted.unit_id)
        .await?;
    assert_eq!(occurrences.len(), 2);
    assert_ne!(occurrences[0].occurrence_id, occurrences[1].occurrence_id);
    assert!(occurrences
        .iter()
        .all(|occurrence| occurrence.unit_revision == promoted.first_revision));

    // 4. Retrieval is broad; only the declared semantic reliance bears freshness.
    let ap1 = harness
        .create_artefact(
            database,
            AP_ID,
            "Adoption principle",
            "Setup should be simple.",
        )
        .await?;
    let in1 = harness
        .create_artefact(
            database,
            IN_ID,
            "Infrastructure note",
            "The service uses an embedded event store.",
        )
        .await?;
    let c0 = harness
        .create_artefact(database, C_ID, "Homepage", "Unreviewed homepage.")
        .await?;
    let d0 = harness
        .create_artefact(
            database,
            D_ID,
            "Durability review",
            "Unreviewed durability note.",
        )
        .await?;
    let omit0 = harness
        .create_artefact(
            database,
            OMIT_ID,
            "Omission audit",
            "Unreviewed omission fixture.",
        )
        .await?;
    let over0 = harness
        .create_artefact(
            database,
            OVER_ID,
            "Over-declaration audit",
            "Unreviewed over fixture.",
        )
        .await?;
    let requested = vec![promoted.unit_id.as_str().into(), AP_ID.into(), IN_ID.into()];
    let c_assembly = harness
        .assemble_context(
            database,
            request("Draft positioning", "homepage hero"),
            Some(C_ID),
            requested.clone(),
        )
        .await?;
    assert_eq!(c_assembly.sources.len(), 3);
    assert!(c_assembly.comparisons.is_empty());
    let u1_selected = c_assembly
        .sources
        .iter()
        .find(|reference| reference.subject_kind == RevisionSubjectKind::Unit)
        .unwrap()
        .clone();
    let first_history_high_water = c_assembly.high_water.clone();
    let c1 = harness
        .commit_output(
            database,
            CommitDurableOutputInput {
                consumer_record_id: C_ID.into(),
                expected_consumer_revision: c0,
                output_body: "A technical workspace for founders building with agents.".into(),
                provenance: provenance(&c_assembly.sources),
                dependencies: vec![dependency("proof:dc1", u1_selected.clone())],
                assessments: vec![],
                reconciliations: vec![],
                unresolved_uncertainty: vec![],
                policy: one_dependency_policy(),
                idempotency_key: IdempotencyKey::new("proof:commit-c1")?,
                assembly: c_assembly,
            },
        )
        .await?;
    let c1_explanation = harness.explain(database, c1.receipt_id.clone()).await?;
    assert_eq!(c1_explanation.visible_provenance.len(), 3);
    assert_eq!(c1_explanation.visible_dependencies.len(), 1);
    assert_eq!(
        c1_explanation.visible_dependencies[0]
            .dependency_id
            .as_str(),
        "proof:dc1"
    );

    let d_assembly = harness
        .assemble_context(
            database,
            request("Inspect durability", "database durability"),
            Some(D_ID),
            requested.clone(),
        )
        .await?;
    let d1 = harness
        .commit_output(
            database,
            CommitDurableOutputInput {
                consumer_record_id: D_ID.into(),
                expected_consumer_revision: d0,
                output_body: "The durability design is event-authoritative.".into(),
                provenance: provenance(&d_assembly.sources),
                dependencies: vec![dependency("proof:dd1", u1_selected.clone())],
                assessments: vec![],
                reconciliations: vec![],
                unresolved_uncertainty: vec![],
                policy: ResolutionPolicy::agent_speed_default(),
                idempotency_key: IdempotencyKey::new("proof:commit-d1")?,
                assembly: d_assembly,
            },
        )
        .await?;

    let omission_assembly = harness
        .assemble_context(
            database,
            request("Audit omission", "dependency declaration audit"),
            Some(OMIT_ID),
            requested.clone(),
        )
        .await?;
    let omission_receipt = harness
        .commit_output(
            database,
            CommitDurableOutputInput {
                consumer_record_id: OMIT_ID.into(),
                expected_consumer_revision: omit0,
                output_body: "An output that used the audience premise without declaring it."
                    .into(),
                provenance: provenance(&omission_assembly.sources),
                dependencies: vec![],
                assessments: vec![],
                reconciliations: vec![],
                unresolved_uncertainty: vec![],
                policy: ResolutionPolicy::agent_speed_default(),
                idempotency_key: IdempotencyKey::new("proof:commit-omission")?,
                assembly: omission_assembly,
            },
        )
        .await?;

    let over_assembly = harness
        .assemble_context(
            database,
            request("Audit over-declaration", "dependency declaration audit"),
            Some(OVER_ID),
            requested.clone(),
        )
        .await?;
    let over_receipt = harness
        .commit_output(
            database,
            CommitDurableOutputInput {
                consumer_record_id: OVER_ID.into(),
                expected_consumer_revision: over0,
                output_body: "An audience output independent of the infrastructure note.".into(),
                provenance: provenance(&over_assembly.sources),
                dependencies: vec![dependency("proof:unnecessary-in1", in1.clone())],
                assessments: vec![],
                reconciliations: vec![],
                unresolved_uncertainty: vec![],
                policy: ResolutionPolicy::agent_speed_default(),
                idempotency_key: IdempotencyKey::new("proof:commit-overdeclared")?,
                assembly: over_assembly,
            },
        )
        .await?;

    // 5. Exact U1 remains immutable while the active Unit moves to U2.
    let revised = harness
        .revise_unit(
            database,
            ReviseUnitInput {
                unit_id: promoted.unit_id.clone(),
                expected_current: promoted.first_revision.clone(),
                content: UnitContent::text(U2)?,
                rationale: "The launch audience changed".into(),
                idempotency_key: IdempotencyKey::new("proof:revise-u2")?,
            },
        )
        .await?;
    assert_eq!(
        harness
            .read_unit_revision(database, &promoted.first_revision)
            .await?
            .content
            .content,
        U1
    );
    let immediate = harness.impact_candidates(database, C_ID).await?;
    assert_eq!(immediate.candidates.len(), 1);
    assert_eq!(
        immediate.candidates[0].pinned_source_revision,
        promoted.first_revision
    );
    assert_eq!(
        immediate.candidates[0].candidate_source_revision,
        revised.new_revision
    );

    // 6. The first read after revision seals the exact mismatch at one boundary.
    let h_assembly = harness
        .assemble_context(
            database,
            request("Draft positioning", "homepage hero"),
            Some(C_ID),
            requested.clone(),
        )
        .await?;
    assert_eq!(h_assembly.comparisons.len(), 1);
    let h_comparison = h_assembly.comparisons[0].clone();
    let provisional_history_high_water = h_assembly.high_water.clone();
    assert_eq!(h_comparison.pinned_source_revision, promoted.first_revision);
    assert_eq!(h_comparison.candidate_source_revision, revised.new_revision);
    assert!(h_assembly
        .sources
        .iter()
        .all(|source| source.revision_seq <= h_assembly.high_water.content_seq));

    // 7. The same exact change is material for the hero and quiet for durability.
    let d_assembly = harness
        .assemble_context(
            database,
            request("Inspect durability", "database durability"),
            Some(D_ID),
            requested.clone(),
        )
        .await?;
    assert_eq!(d_assembly.comparisons.len(), 1);
    let d_comparison = d_assembly.comparisons[0].clone();
    let current_d_source = d_assembly
        .sources
        .iter()
        .find(|reference| reference.subject_kind == RevisionSubjectKind::Unit)
        .unwrap()
        .clone();
    let d2 = harness
        .commit_output(
            database,
            CommitDurableOutputInput {
                consumer_record_id: D_ID.into(),
                expected_consumer_revision: d1.output_revision,
                output_body: "The durability design remains event-authoritative.".into(),
                provenance: provenance(&d_assembly.sources),
                dependencies: vec![dependency("proof:dd2", current_d_source.clone())],
                assessments: vec![AssessmentInput {
                    assessment_id: AssessmentId::new("proof:assessment-d")?,
                    dependency_id: d_comparison.dependency_id,
                    compared_source_revision: d_comparison.candidate_source_revision,
                    category: "positioning".into(),
                    outcome: MaterialityOutcome::Immaterial,
                    could_materially_change: false,
                    rationale: "Audience wording does not affect the durability conclusion".into(),
                }],
                reconciliations: vec![],
                unresolved_uncertainty: vec![],
                policy: ResolutionPolicy::agent_speed_default(),
                idempotency_key: IdempotencyKey::new("proof:commit-d2")?,
                assembly: d_assembly,
            },
        )
        .await?;
    assert_eq!(d2.execution, ExecutionDisposition::Continued);
    assert_eq!(d2.disclosure, DisclosureDecision::Silent);

    // 8. Material uncertainty does not stop execution or lose exact lineage.
    let current_h_source = h_assembly
        .sources
        .iter()
        .find(|reference| reference.subject_kind == RevisionSubjectKind::Unit)
        .unwrap()
        .clone();
    let uncertainty = UncertaintyLineage {
        uncertainty_id: UncertaintyId::new("proof:uncertainty-u2")?,
        dependency_id: h_comparison.dependency_id.clone(),
        inherited_from_receipt_id: Some(h_comparison.receipt_id.clone()),
        consumer_revision: c1.output_revision.clone(),
        pinned_source_revision: h_comparison.pinned_source_revision.clone(),
        selected_source_revision: h_comparison.candidate_source_revision.clone(),
        affected_conclusion: conclusion(),
        assessment_task_scope: "homepage hero".into(),
        verdict: MaterialityOutcome::MateriallyUncertain,
        evidence: "The audience changed, but product judgment is incomplete".into(),
        detail: "The provisional hero must inherit this exact uncertainty".into(),
    };
    let provisional = harness
        .commit_output(
            database,
            CommitDurableOutputInput {
                consumer_record_id: C_ID.into(),
                expected_consumer_revision: c1.output_revision.clone(),
                output_body: "A workspace for operators adopting agents.".into(),
                provenance: provenance(&h_assembly.sources),
                dependencies: vec![dependency("proof:dc2-provisional", current_h_source)],
                assessments: vec![AssessmentInput {
                    assessment_id: AssessmentId::new("proof:assessment-h")?,
                    dependency_id: h_comparison.dependency_id.clone(),
                    compared_source_revision: h_comparison.candidate_source_revision.clone(),
                    category: "positioning".into(),
                    outcome: MaterialityOutcome::MateriallyUncertain,
                    could_materially_change: true,
                    rationale: "This could materially change the audience language".into(),
                }],
                reconciliations: vec![],
                unresolved_uncertainty: vec![uncertainty],
                policy: ResolutionPolicy::agent_speed_default(),
                idempotency_key: IdempotencyKey::new("proof:commit-provisional")?,
                assembly: h_assembly,
            },
        )
        .await?;
    assert_eq!(provisional.execution, ExecutionDisposition::Continued);
    assert_eq!(provisional.disclosure, DisclosureDecision::SurfaceNow);
    let provisional_explanation = harness
        .explain(database, provisional.receipt_id.clone())
        .await?;
    assert_eq!(provisional_explanation.unresolved_uncertainty.len(), 1);

    // 9. Moving exact expression bytes relocates the anchor without changing U.
    let a2 = harness
        .update_artefact(
            database,
            A_ID,
            &a1,
            "Research note.\nThe primary launch audience is technical founders.",
        )
        .await?;
    let relocated = harness
        .resolve_occurrence(database, &promoted.occurrence_id)
        .await?;
    assert_eq!(relocated.state, OccurrenceResolutionState::Relocated);
    assert_eq!(relocated.original_artefact_revision, a1);
    assert_eq!(relocated.current_artefact_revision, Some(a2));
    assert!(relocated.current_range.is_some());
    assert_eq!(
        harness
            .read_unit(database, &promoted.unit_id)
            .await?
            .unit_id,
        promoted.unit_id
    );

    // 10. Deterministically remove one uniquely verified expression. The
    // anchor becomes Stale while retaining its exact historical address; it
    // must not silently widen into an artefact-level substitution.
    let b1_body = harness.artefact_body(database, B_ID).await?;
    assert_eq!(b1_body, B1);
    assert_eq!(b1_body.matches(B1).count(), 1);
    assert_eq!(bound_b.occurrence.artefact_revision, b1);
    assert_eq!(bound_b.occurrence.selectors.len(), 1);
    assert!(matches!(
        &bound_b.occurrence.selectors[0],
        OccurrenceSelector::TextQuote {
            exact,
            prefix: None,
            suffix: None,
            position_hint: Some(0),
        } if exact == B1
    ));
    let b2 = harness
        .update_artefact(database, B_ID, &b1, "The product description was removed.")
        .await?;
    let b2_body = harness.artefact_body(database, B_ID).await?;
    assert_eq!(b2_body, "The product description was removed.");
    assert!(!b2_body.contains(B1));
    let broken = harness
        .resolve_occurrence(database, &bound_b.occurrence.occurrence_id)
        .await?;
    assert_eq!(broken.state, OccurrenceResolutionState::Stale);
    assert_eq!(broken.original_artefact_revision, b1);
    assert_eq!(broken.current_artefact_revision, Some(b2));
    assert_eq!(broken.current_range, None);
    let persisted_b_occurrence = harness
        .list_occurrences(database, &promoted.unit_id)
        .await?
        .into_iter()
        .find(|occurrence| occurrence.occurrence_id == bound_b.occurrence.occurrence_id)
        .expect("stale occurrence must preserve its historical address");
    assert_eq!(persisted_b_occurrence.artefact_revision, b1);
    assert_eq!(
        persisted_b_occurrence.selectors,
        bound_b.occurrence.selectors
    );
    assert_eq!(persisted_b_occurrence.artefact_revision.sha256, b1.sha256);
    assert_eq!(
        harness
            .resolve_occurrence(database, &promoted.occurrence_id)
            .await?
            .state,
        OccurrenceResolutionState::Relocated
    );

    // 11. Evidence covers only this debt tuple; history remains explainable.
    harness
        .reconcile(
            database,
            ReconcileDependencyInput {
                reconciliation_id: ReconciliationId::new("proof:reconcile-dc1-u2")?,
                dependency_id: DependencyId::new("proof:dc1")?,
                assessed_source_revision: revised.new_revision.clone(),
                task_scope: "homepage hero".into(),
                outcome: MaterialityOutcome::RemainsValid,
                rationale: "The provisional replacement incorporates the exact audience change"
                    .into(),
                idempotency_key: IdempotencyKey::new("proof:reconcile-command")?,
            },
        )
        .await?;
    assert!(harness
        .explain(database, c1.receipt_id.clone())
        .await?
        .visible_impacts
        .is_empty());
    assert!(harness
        .explain(database, provisional.receipt_id.clone())
        .await?
        .unresolved_uncertainty
        .is_empty());
    harness.assert_replay_equivalent(database).await?;

    // 12. Declaration quality is durable, bounded, and structurally checked.
    let confirmed = harness
        .audit(
            database,
            AuditDependencyInput {
                receipt_id: c1.receipt_id.clone(),
                declared_dependency_id: Some(DependencyId::new("proof:dc1")?),
                observed_dependency: None,
                outcome: DependencyAuditOutcome::Confirmed,
                rationale: "The audience premise is genuinely load-bearing".into(),
                idempotency_key: IdempotencyKey::new("proof:audit-confirmed")?,
            },
        )
        .await?;
    let underdeclared = harness
        .audit(
            database,
            AuditDependencyInput {
                receipt_id: omission_receipt.receipt_id.clone(),
                declared_dependency_id: None,
                observed_dependency: Some(dependency("proof:observed-u1", u1_selected)),
                outcome: DependencyAuditOutcome::Underdeclared,
                rationale: "The fixture omitted its load-bearing audience premise".into(),
                idempotency_key: IdempotencyKey::new("proof:audit-underdeclared")?,
            },
        )
        .await?;
    let overdeclared = harness
        .audit(
            database,
            AuditDependencyInput {
                receipt_id: over_receipt.receipt_id.clone(),
                declared_dependency_id: Some(DependencyId::new("proof:unnecessary-in1")?),
                observed_dependency: None,
                outcome: DependencyAuditOutcome::Overdeclared,
                rationale: "The infrastructure note did not affect the bounded conclusion".into(),
                idempotency_key: IdempotencyKey::new("proof:audit-overdeclared")?,
            },
        )
        .await?;
    let mut malformed = dependency("proof:malformed-observation", ap1);
    malformed.affected_conclusion.description.clear();
    assert!(harness
        .audit(
            database,
            AuditDependencyInput {
                receipt_id: omission_receipt.receipt_id,
                declared_dependency_id: None,
                observed_dependency: Some(malformed),
                outcome: DependencyAuditOutcome::Underdeclared,
                rationale: "Malformed observations must not become audit evidence".into(),
                idempotency_key: IdempotencyKey::new("proof:audit-malformed")?,
            },
        )
        .await
        .is_err());
    assert_eq!(
        harness
            .receipt_dependency_budget(database, &c1.receipt_id)
            .await?,
        (1, 1)
    );
    harness.assert_replay_equivalent(database).await?;

    Ok(TwelveStepEvidence {
        unit_id: promoted.unit_id,
        u1: promoted.first_revision,
        u2: revised.new_revision,
        first_receipt: c1.receipt_id,
        first_output_revision: c1.output_revision,
        first_history_high_water,
        provisional_receipt: provisional.receipt_id,
        provisional_output_revision: provisional.output_revision,
        provisional_history_high_water,
        relocation: relocated.state,
        broken_anchor: broken.state,
        material_disclosure: provisional.disclosure,
        immaterial_disclosure: d2.disclosure,
        confirmed_audit: confirmed,
        underdeclared_audit: underdeclared,
        overdeclared_audit: overdeclared,
    })
}

pub fn assert_audit_outcomes(evidence: &TwelveStepEvidence) {
    assert_eq!(
        evidence.confirmed_audit.outcome,
        DependencyAuditOutcome::Confirmed
    );
    assert!(evidence.confirmed_audit.has_declared_dependency);
    assert_eq!(
        evidence.underdeclared_audit.outcome,
        DependencyAuditOutcome::Underdeclared
    );
    assert!(evidence.underdeclared_audit.has_observed_dependency);
    assert_eq!(
        evidence.overdeclared_audit.outcome,
        DependencyAuditOutcome::Overdeclared
    );
    assert!(evidence.overdeclared_audit.has_declared_dependency);
    assert_eq!(evidence.material_disclosure, DisclosureDecision::SurfaceNow);
    assert_eq!(evidence.immaterial_disclosure, DisclosureDecision::Silent);
}
