//! Feature-gated development seam for exercising agent-speed freshness.
//!
//! This is deliberately one intention dispatcher rather than a stable tool per
//! kernel primitive. It may change or disappear with the experiment.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::authorization::{require_capability_on, Capability, Principal};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::events::ReceiptCommittedPayload;

use super::*;

pub const EXPERIMENTAL_AGENT_INTENT_CONTRACT: &str =
    "native.experimental.freshness-agent-intent.v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRelianceIntent {
    pub source_revision: RevisionRef,
    pub dependency_id: DependencyId,
    pub semantic_role: String,
    pub provenance_reason: String,
    pub rationale: String,
    pub reconsideration_trigger: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableOutputIntent {
    pub consumer_record_id: String,
    pub expected_consumer_revision: RevisionRef,
    pub output_body: String,
    pub request: ContextRequest,
    pub policy: ResolutionPolicy,
    pub source_record_ids: Vec<String>,
    pub affected_conclusion: AffectedConclusion,
    pub sources: Vec<SourceRelianceIntent>,
    pub idempotency_key: IdempotencyKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeAssessmentIntent {
    pub assessment_id: AssessmentId,
    pub dependency_id: DependencyId,
    pub compared_source_revision: RevisionRef,
    pub category: String,
    pub outcome: MaterialityOutcome,
    pub could_materially_change: bool,
    pub rationale: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncertainty_id: Option<UncertaintyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncertainty_evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncertainty_detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "intention", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ExperimentalAgentIntent {
    PromoteExactExpression {
        input: PromoteIdeaInput,
    },
    DeclareSources {
        output: DurableOutputIntent,
    },
    AssessExactChange {
        output: DurableOutputIntent,
        assessments: Vec<ChangeAssessmentIntent>,
    },
    ReconcileAffectedOutput {
        receipt_id: ReceiptId,
        input: ReconcileDependencyInput,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "intention", rename_all = "snake_case")]
pub enum ExperimentalAgentIntentResult {
    PromoteExactExpression {
        promoted: PromoteIdeaResult,
        unit: UnitView,
        occurrence: OccurrenceEvidence,
    },
    DeclareSources {
        committed: CommitDurableOutputResult,
        explanation: FreshnessExplanation,
    },
    AssessExactChange {
        committed: CommitDurableOutputResult,
        explanation: FreshnessExplanation,
    },
    ReconcileAffectedOutput {
        explanation: FreshnessExplanation,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentalAgentIntentEvidence {
    pub experimental_contract: String,
    pub observed_high_water: HistoryHighWater,
    pub provenance_completeness: ProvenanceCompleteness,
    pub result: ExperimentalAgentIntentResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayIntention {
    DeclareSources,
    AssessExactChange,
}

fn carries_unresolved_uncertainty(assessment: &ChangeAssessmentIntent) -> bool {
    match assessment.outcome {
        MaterialityOutcome::MateriallyUncertain => true,
        MaterialityOutcome::UnableToAssess => assessment.could_materially_change,
        _ => false,
    }
}

fn validate_uncertainty_fields(assessments: &[ChangeAssessmentIntent]) -> Result<()> {
    for assessment in assessments {
        let carries_uncertainty = carries_unresolved_uncertainty(assessment);
        let fields = [
            assessment.uncertainty_id.is_some(),
            assessment.uncertainty_evidence.is_some(),
            assessment.uncertainty_detail.is_some(),
        ];
        if carries_uncertainty && fields.iter().any(|present| !present) {
            return Err(Error::engine(
                "material uncertainty requires id, evidence, and detail",
            ));
        }
        if !carries_uncertainty && fields.iter().any(|present| *present) {
            return Err(Error::engine(
                "uncertainty fields are only valid for an unresolved material assessment",
            ));
        }
    }
    Ok(())
}

fn declared_evidence(output: &DurableOutputIntent) -> (Vec<ProvenanceUse>, Vec<DependencyInput>) {
    let provenance = output
        .sources
        .iter()
        .map(|source| ProvenanceUse {
            source_revision: source.source_revision.clone(),
            reason: source.provenance_reason.clone(),
        })
        .collect();
    let dependencies = output
        .sources
        .iter()
        .map(|source| DependencyInput {
            dependency_id: source.dependency_id.clone(),
            source_revision: source.source_revision.clone(),
            semantic_role: source.semantic_role.clone(),
            affected_conclusion: output.affected_conclusion.clone(),
            rationale: source.rationale.clone(),
            reconsideration_trigger: source.reconsideration_trigger.clone(),
            confidence: source.confidence,
        })
        .collect();
    (provenance, dependencies)
}

fn assessment_inputs(assessments: &[ChangeAssessmentIntent]) -> Vec<AssessmentInput> {
    assessments
        .iter()
        .map(|assessment| AssessmentInput {
            assessment_id: assessment.assessment_id.clone(),
            dependency_id: assessment.dependency_id.clone(),
            compared_source_revision: assessment.compared_source_revision.clone(),
            category: assessment.category.clone(),
            outcome: assessment.outcome,
            could_materially_change: assessment.could_materially_change,
            rationale: assessment.rationale.clone(),
        })
        .collect()
}

async fn replay_committed_output(
    db: &Db,
    principal: Principal<'_>,
    output: &DurableOutputIntent,
    assessments: &[ChangeAssessmentIntent],
    intention: ReplayIntention,
) -> Result<Option<(CommitDurableOutputResult, FreshnessExplanation)>> {
    validate_uncertainty_fields(assessments)?;
    let mut tx = db.pool().begin().await?;
    require_capability_on(
        &mut tx,
        principal,
        &output.consumer_record_id,
        Capability::Edit,
    )
    .await?;
    let row = sqlx::query(
        "SELECT e.payload
           FROM freshness_runtime_command_results c
           JOIN content_events e ON e.id=c.result_event_id
          WHERE c.scope_record_id=? AND c.idempotency_key=?
            AND c.operation='commit_durable_output'",
    )
    .bind(&output.consumer_record_id)
    .bind(output.idempotency_key.as_str())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(None);
    };
    let payload: ReceiptCommittedPayload =
        serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
    super::runtime::reauthorize_receipt_payload_on(&mut tx, principal, &payload).await?;
    let mut expected_request = output.request.clone();
    expected_request.risk_inputs.sort();
    expected_request.risk_inputs.dedup();
    let mut expected_policy = output.policy.clone();
    expected_policy.hard_stop_categories.sort();
    expected_policy.hard_stop_categories.dedup();
    let mut expected_source_ids = output.source_record_ids.clone();
    expected_source_ids.sort();
    expected_source_ids.dedup();
    let (mut expected_provenance, mut expected_dependencies) = declared_evidence(output);
    expected_provenance.sort_by(|left, right| {
        (
            &left.source_revision.subject_id,
            &left.source_revision.revision_event_id,
            &left.reason,
        )
            .cmp(&(
                &right.source_revision.subject_id,
                &right.source_revision.revision_event_id,
                &right.reason,
            ))
    });
    expected_dependencies.sort_by(|left, right| left.dependency_id.cmp(&right.dependency_id));
    let mut expected_assessments = assessment_inputs(assessments);
    expected_assessments.sort_by(|left, right| left.assessment_id.cmp(&right.assessment_id));
    let same_branch = match intention {
        ReplayIntention::DeclareSources => {
            payload.comparisons.is_empty() && payload.assessments.is_empty()
        }
        ReplayIntention::AssessExactChange => {
            !payload.comparisons.is_empty() && !payload.assessments.is_empty()
        }
    };
    let same_intent = same_branch
        && payload.expected_consumer_revision == output.expected_consumer_revision
        && payload.body == output.output_body
        && payload.context_request == expected_request
        && payload.resolution_policy == expected_policy
        && payload.requested_source_record_ids == expected_source_ids
        && payload.provenance == expected_provenance
        && payload.dependencies == expected_dependencies
        && payload.assessments == expected_assessments
        && payload.command.idempotency_key == output.idempotency_key.as_str()
        && assessments.iter().all(|assessment| {
            if !carries_unresolved_uncertainty(assessment) {
                return true;
            }
            payload.unresolved_uncertainty.iter().any(|lineage| {
                Some(&lineage.uncertainty_id) == assessment.uncertainty_id.as_ref()
                    && lineage.dependency_id == assessment.dependency_id
                    && lineage.selected_source_revision == assessment.compared_source_revision
                    && lineage.verdict == assessment.outcome
                    && Some(&lineage.evidence) == assessment.uncertainty_evidence.as_ref()
                    && Some(&lineage.detail) == assessment.uncertainty_detail.as_ref()
            })
        });
    if !same_intent {
        return Err(Error::engine(
            "idempotency key was already used for a different experimental agent intent",
        ));
    }
    let dependency_ids = payload
        .dependencies
        .iter()
        .map(|dependency| dependency.dependency_id.clone())
        .collect();
    let committed = CommitDurableOutputResult {
        receipt_id: payload.receipt_id.clone(),
        output_revision: serde_json::from_str(
            &sqlx::query_scalar::<_, String>(
                "SELECT output_revision FROM receipts WHERE receipt_id=?",
            )
            .bind(payload.receipt_id.as_str())
            .fetch_one(&mut *tx)
            .await?,
        )?,
        dependency_ids,
        execution: payload.execution,
        disclosure: payload.disclosure,
        high_water: payload.history_high_water,
    };
    tx.rollback().await?;
    let explanation = explain_freshness(db, principal, committed.receipt_id.clone()).await?;
    Ok(Some((committed, explanation)))
}

async fn assemble_output(
    db: &Db,
    principal: Principal<'_>,
    output: &DurableOutputIntent,
) -> Result<(ContextAssembly, Vec<ProvenanceUse>, Vec<DependencyInput>)> {
    let assembly = assemble_context(
        db,
        principal,
        output.request.clone(),
        Some(&output.consumer_record_id),
        output.source_record_ids.clone(),
    )
    .await?;
    let mut selected = assembly.sources.clone();
    selected.sort_by(|left, right| {
        (&left.subject_id, &left.revision_event_id)
            .cmp(&(&right.subject_id, &right.revision_event_id))
    });
    selected.dedup();
    let mut declared = output
        .sources
        .iter()
        .map(|source| source.source_revision.clone())
        .collect::<Vec<_>>();
    declared.sort_by(|left, right| {
        (&left.subject_id, &left.revision_event_id)
            .cmp(&(&right.subject_id, &right.revision_event_id))
    });
    if declared.windows(2).any(|pair| pair[0] == pair[1]) || declared != selected {
        return Err(Error::engine(
            "experimental agent intent must declare every exact selected source once",
        ));
    }
    let (provenance, dependencies) = declared_evidence(output);
    Ok((assembly, provenance, dependencies))
}

fn uncertainty_lineage(
    output: &DurableOutputIntent,
    assembly: &ContextAssembly,
    assessments: &[ChangeAssessmentIntent],
) -> Result<Vec<UncertaintyLineage>> {
    let mut lineage = Vec::new();
    for assessment in assessments {
        if !carries_unresolved_uncertainty(assessment) {
            continue;
        }
        let comparison = assembly
            .comparisons
            .iter()
            .find(|comparison| {
                comparison.dependency_id == assessment.dependency_id
                    && comparison.candidate_source_revision == assessment.compared_source_revision
            })
            .ok_or_else(|| {
                Error::engine("experimental assessment does not bind an exact context comparison")
            })?;
        lineage.push(UncertaintyLineage {
            uncertainty_id: assessment
                .uncertainty_id
                .clone()
                .ok_or_else(|| Error::engine("material uncertainty requires an uncertainty_id"))?,
            dependency_id: assessment.dependency_id.clone(),
            inherited_from_receipt_id: Some(comparison.receipt_id.clone()),
            consumer_revision: output.expected_consumer_revision.clone(),
            pinned_source_revision: comparison.pinned_source_revision.clone(),
            selected_source_revision: comparison.candidate_source_revision.clone(),
            affected_conclusion: output.affected_conclusion.clone(),
            assessment_task_scope: assembly.request.task_scope.clone(),
            verdict: assessment.outcome,
            evidence: assessment.uncertainty_evidence.clone().ok_or_else(|| {
                Error::engine("material uncertainty requires uncertainty_evidence")
            })?,
            detail: assessment
                .uncertainty_detail
                .clone()
                .ok_or_else(|| Error::engine("material uncertainty requires uncertainty_detail"))?,
        });
    }
    Ok(lineage)
}

async fn validate_assessment_contract(
    db: &Db,
    principal: Principal<'_>,
    output: &DurableOutputIntent,
    assembly: &ContextAssembly,
    assessments: &[ChangeAssessmentIntent],
) -> Result<()> {
    // Keep fresh commits independently safe even if replay lookup is later
    // refactored or bypassed by another embedding.
    validate_uncertainty_fields(assessments)?;
    let comparison_keys = assembly
        .comparisons
        .iter()
        .map(|comparison| {
            (
                comparison.dependency_id.clone(),
                comparison.candidate_source_revision.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let assessment_keys = assessments
        .iter()
        .map(|assessment| {
            (
                assessment.dependency_id.clone(),
                assessment.compared_source_revision.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    if comparison_keys != assessment_keys || assessment_keys.len() != assessments.len() {
        return Err(Error::engine(
            "assess_exact_change requires exactly one assessment for every sealed comparison",
        ));
    }
    for comparison in &assembly.comparisons {
        let prior = explain_freshness(db, principal, comparison.receipt_id.clone()).await?;
        let dependency = prior
            .visible_dependencies
            .iter()
            .find(|dependency| dependency.dependency_id == comparison.dependency_id)
            .ok_or_else(|| Error::engine("experimental assessment dependency is unavailable"))?;
        if dependency.affected_conclusion != output.affected_conclusion {
            return Err(Error::engine(
                "assess_exact_change cannot cross or combine bounded conclusions",
            ));
        }
    }
    Ok(())
}

fn package(
    output: DurableOutputIntent,
    assembly: ContextAssembly,
    provenance: Vec<ProvenanceUse>,
    dependencies: Vec<DependencyInput>,
    assessments: Vec<AssessmentInput>,
    unresolved_uncertainty: Vec<UncertaintyLineage>,
) -> CommitDurableOutputInput {
    CommitDurableOutputInput {
        consumer_record_id: output.consumer_record_id,
        expected_consumer_revision: output.expected_consumer_revision,
        output_body: output.output_body,
        assembly,
        policy: output.policy,
        provenance,
        dependencies,
        assessments,
        reconciliations: Vec::new(),
        unresolved_uncertainty,
        idempotency_key: output.idempotency_key,
    }
}

pub async fn execute_experimental_agent_intent(
    db: &Db,
    principal: Principal<'_>,
    actor: &str,
    intention: ExperimentalAgentIntent,
) -> Result<ExperimentalAgentIntentEvidence> {
    let (result, completeness) = match intention {
        ExperimentalAgentIntent::PromoteExactExpression { input } => {
            let promoted = promote_idea(db, principal, actor, input).await?;
            let unit = read_unit(db, principal, &promoted.unit_id).await?;
            let occurrence = list_occurrences(db, principal, &promoted.unit_id)
                .await?
                .into_iter()
                .find(|occurrence| occurrence.occurrence_id == promoted.occurrence_id)
                .ok_or_else(|| Error::engine("promoted Occurrence is unavailable"))?;
            let resolution = resolve_occurrence(db, principal, &promoted.occurrence_id).await?;
            (
                ExperimentalAgentIntentResult::PromoteExactExpression {
                    promoted,
                    unit,
                    occurrence: OccurrenceEvidence {
                        occurrence,
                        resolution,
                    },
                },
                ProvenanceCompleteness::Complete,
            )
        }
        ExperimentalAgentIntent::DeclareSources { output } => {
            if let Some((committed, explanation)) = replay_committed_output(
                db,
                principal,
                &output,
                &[],
                ReplayIntention::DeclareSources,
            )
            .await?
            {
                let completeness = explanation.provenance_completeness;
                return Ok(ExperimentalAgentIntentEvidence {
                    experimental_contract: EXPERIMENTAL_AGENT_INTENT_CONTRACT.into(),
                    observed_high_water: current_history_high_water(db).await?,
                    provenance_completeness: completeness,
                    result: ExperimentalAgentIntentResult::DeclareSources {
                        committed,
                        explanation,
                    },
                });
            }
            let (assembly, provenance, dependencies) =
                assemble_output(db, principal, &output).await?;
            if !assembly.comparisons.is_empty() {
                return Err(Error::engine(
                    "declare_sources encountered an exact change; use assess_exact_change",
                ));
            }
            let committed = commit_durable_output(
                db,
                principal,
                actor,
                package(
                    output,
                    assembly,
                    provenance,
                    dependencies,
                    Vec::new(),
                    Vec::new(),
                ),
            )
            .await?;
            let explanation =
                explain_freshness(db, principal, committed.receipt_id.clone()).await?;
            let completeness = explanation.provenance_completeness;
            (
                ExperimentalAgentIntentResult::DeclareSources {
                    committed,
                    explanation,
                },
                completeness,
            )
        }
        ExperimentalAgentIntent::AssessExactChange {
            output,
            assessments,
        } => {
            if let Some((committed, explanation)) = replay_committed_output(
                db,
                principal,
                &output,
                &assessments,
                ReplayIntention::AssessExactChange,
            )
            .await?
            {
                let completeness = explanation.provenance_completeness;
                return Ok(ExperimentalAgentIntentEvidence {
                    experimental_contract: EXPERIMENTAL_AGENT_INTENT_CONTRACT.into(),
                    observed_high_water: current_history_high_water(db).await?,
                    provenance_completeness: completeness,
                    result: ExperimentalAgentIntentResult::AssessExactChange {
                        committed,
                        explanation,
                    },
                });
            }
            let (assembly, provenance, dependencies) =
                assemble_output(db, principal, &output).await?;
            if assembly.comparisons.is_empty() {
                return Err(Error::engine(
                    "assess_exact_change requires at least one exact comparison",
                ));
            }
            validate_assessment_contract(db, principal, &output, &assembly, &assessments).await?;
            let unresolved_uncertainty = uncertainty_lineage(&output, &assembly, &assessments)?;
            let assessment_inputs = assessment_inputs(&assessments);
            let committed = commit_durable_output(
                db,
                principal,
                actor,
                package(
                    output,
                    assembly,
                    provenance,
                    dependencies,
                    assessment_inputs,
                    unresolved_uncertainty,
                ),
            )
            .await?;
            let explanation =
                explain_freshness(db, principal, committed.receipt_id.clone()).await?;
            let completeness = explanation.provenance_completeness;
            (
                ExperimentalAgentIntentResult::AssessExactChange {
                    committed,
                    explanation,
                },
                completeness,
            )
        }
        ExperimentalAgentIntent::ReconcileAffectedOutput { receipt_id, input } => {
            let reconciliation_id = input.reconciliation_id.clone();
            let dependency_id = input.dependency_id.clone();
            let prior = explain_freshness(db, principal, receipt_id.clone()).await?;
            if !prior
                .visible_dependencies
                .iter()
                .any(|evidence| evidence.dependency_id == dependency_id)
            {
                return Err(Error::engine(
                    "reconciliation Receipt does not own the requested dependency",
                ));
            }
            reconcile_dependency(db, principal, actor, input).await?;
            let explanation = explain_freshness(db, principal, receipt_id).await?;
            if !explanation.visible_reconciliations.iter().any(|evidence| {
                evidence.reconciliation_id == reconciliation_id
                    && evidence.dependency_id == dependency_id
            }) {
                return Err(Error::engine(
                    "reconciliation evidence is not associated with the requested Receipt",
                ));
            }
            let completeness = explanation.provenance_completeness;
            (
                ExperimentalAgentIntentResult::ReconcileAffectedOutput { explanation },
                completeness,
            )
        }
    };
    Ok(ExperimentalAgentIntentEvidence {
        experimental_contract: EXPERIMENTAL_AGENT_INTENT_CONTRACT.into(),
        observed_high_water: current_history_high_water(db).await?,
        provenance_completeness: completeness,
        result,
    })
}
