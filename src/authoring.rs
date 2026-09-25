//! Bounded, Receipt-backed authoring for ordinary notes.
//!
//! The public contract names exact record-body source revisions. The existing
//! freshness runtime remains the only storage authority for the authored body
//! and its declared basis.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authorization::Principal;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::events::ReceiptCommittedPayload;
use crate::freshness::{
    assemble_context, explain_freshness, record_body_revision, AffectedConclusion, AssessmentId,
    AssessmentInput, CommitDurableOutputInput, CommitDurableOutputResult, ContextRequest,
    DependencyId, DependencyInput, IdempotencyKey, MaterialityOutcome, ProvenanceUse,
    ResolutionPolicy, RevisionRef, RevisionSourceSlot, RevisionSubjectKind, UncertaintyId,
    UncertaintyLineage,
};

pub const MAX_SAVE_ACCOUNT_SOURCES: usize = 50;
const AUTHORING_INTENT: &str = "native.save-account.v1";
const CONCLUSION_KEY: &str = "authored-account.body";
const CONCLUSION_DESCRIPTION: &str =
    "The authored body conclusions supported by the declared source basis";
const RECONSIDERATION_TRIGGER: &str = "The declared source body revision changes";
const CHANGE_CATEGORY: &str = "declared_source_changed";
const CHANGE_RATIONALE: &str =
    "The selected source revision changed; this bounded save does not judge whether the prior conclusion remains valid";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveAccountSource {
    pub record_id: String,
    pub revision_event_id: String,
    pub role: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveAccountInput {
    pub record_id: String,
    pub expected_revision_event_id: String,
    pub body: String,
    pub sources: Vec<SaveAccountSource>,
    pub idempotency_key: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveAccountResult {
    pub record_id: String,
    pub revision_event_id: String,
    pub receipt_id: String,
    pub source_count: usize,
    pub withheld_context: bool,
    pub execution: crate::freshness::ExecutionDisposition,
    pub disclosure: crate::freshness::DisclosureDecision,
    /// The act this save allocated; a true no-op omits it. A keyed replay
    /// returns the original save's act.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<i64>,
}

/// Shared source-line validation for `save_account` and the ordinary-write
/// declared basis: the same vocabulary must not store different things in two
/// places. `tool` names the caller in the error.
pub(crate) fn validate_identifier(tool: &str, value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(Error::engine(format!(
            "{tool}: '{label}' must contain non-whitespace text without control characters"
        )));
    }
    Ok(())
}

pub(crate) fn validate_prose(tool: &str, value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::engine(format!(
            "{tool}: '{label}' must contain non-whitespace text"
        )));
    }
    Ok(())
}

fn normalize_input(input: &mut SaveAccountInput) -> Result<IdempotencyKey> {
    validate_identifier("save_account", &input.record_id, "record_id")?;
    validate_identifier(
        "save_account",
        &input.expected_revision_event_id,
        "expected_revision_event_id",
    )?;
    validate_prose("save_account", &input.body, "body")?;
    validate_prose("save_account", &input.reason, "reason")?;
    if input.sources.is_empty() || input.sources.len() > MAX_SAVE_ACCOUNT_SOURCES {
        return Err(Error::engine(format!(
            "save_account: 'sources' must contain between 1 and {MAX_SAVE_ACCOUNT_SOURCES} entries"
        )));
    }
    for source in &input.sources {
        validate_identifier("save_account", &source.record_id, "sources[].record_id")?;
        validate_identifier(
            "save_account",
            &source.revision_event_id,
            "sources[].revision_event_id",
        )?;
        validate_prose("save_account", &source.role, "sources[].role")?;
        validate_prose("save_account", &source.reason, "sources[].reason")?;
    }
    input.sources.sort_by(|left, right| {
        (
            &left.record_id,
            &left.revision_event_id,
            &left.role,
            &left.reason,
        )
            .cmp(&(
                &right.record_id,
                &right.revision_event_id,
                &right.role,
                &right.reason,
            ))
    });
    if input
        .sources
        .windows(2)
        .any(|pair| pair[0].record_id == pair[1].record_id)
    {
        return Err(Error::engine(
            "save_account: each source record may be declared only once",
        ));
    }
    IdempotencyKey::new(input.idempotency_key.clone())
        .map_err(|_| Error::engine("save_account: 'idempotency_key' is invalid"))
}

fn affected_conclusion() -> AffectedConclusion {
    AffectedConclusion {
        key: CONCLUSION_KEY.into(),
        description: CONCLUSION_DESCRIPTION.into(),
    }
}

fn digest_id(prefix: &str, input: &SaveAccountInput, source: &SaveAccountSource) -> String {
    let mut hasher = Sha256::new();
    for value in [
        input.record_id.as_bytes(),
        input.expected_revision_event_id.as_bytes(),
        input.idempotency_key.as_bytes(),
        source.record_id.as_bytes(),
        source.revision_event_id.as_bytes(),
        source.role.as_bytes(),
        source.reason.as_bytes(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    format!("{prefix}-{:x}", hasher.finalize())
}

fn dependency_id(input: &SaveAccountInput, source: &SaveAccountSource) -> Result<DependencyId> {
    DependencyId::new(digest_id("save-account-source", input, source))
}

fn comparison_digest_id(
    prefix: &str,
    input: &SaveAccountInput,
    comparison: &crate::freshness::ImpactCandidate,
) -> String {
    let mut hasher = Sha256::new();
    for value in [
        input.record_id.as_bytes(),
        input.expected_revision_event_id.as_bytes(),
        input.idempotency_key.as_bytes(),
        comparison.dependency_id.as_str().as_bytes(),
        comparison
            .pinned_source_revision
            .revision_event_id
            .as_bytes(),
        comparison
            .candidate_source_revision
            .revision_event_id
            .as_bytes(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    format!("{prefix}-{:x}", hasher.finalize())
}

fn source_revision<'a>(
    sources: &'a [RevisionRef],
    declared: &SaveAccountSource,
) -> Option<&'a RevisionRef> {
    sources.iter().find(|reference| {
        reference.subject_kind == RevisionSubjectKind::Artefact
            && reference.source_slot == RevisionSourceSlot::RecordBody
            && reference.subject_id == declared.record_id
            && reference.revision_event_id == declared.revision_event_id
    })
}

fn public_request_matches_receipt(
    input: &SaveAccountInput,
    payload: &ReceiptCommittedPayload,
) -> bool {
    if payload.expected_consumer_revision.subject_id != input.record_id
        || payload.expected_consumer_revision.revision_event_id != input.expected_revision_event_id
        || payload.body != input.body
        || payload.context_request.intent != AUTHORING_INTENT
        || payload.context_request.task_scope != input.reason
        || !payload.context_request.risk_inputs.is_empty()
        || payload.resolution_policy != ResolutionPolicy::agent_speed_default()
        || payload.selected_sources.len() != input.sources.len()
        || payload.provenance.len() != input.sources.len()
        || payload.dependencies.len() != input.sources.len()
        || !payload.reconciliations.is_empty()
        || payload.comparisons.len() != payload.assessments.len()
        || payload.assessments.iter().any(|assessment| {
            assessment.category != CHANGE_CATEGORY
                || assessment.outcome != MaterialityOutcome::UnableToAssess
                || !assessment.could_materially_change
                || assessment.rationale != CHANGE_RATIONALE
        })
        || payload.comparisons.iter().any(|comparison| {
            !payload.assessments.iter().any(|assessment| {
                assessment.dependency_id == comparison.dependency_id
                    && assessment.compared_source_revision == comparison.candidate_source_revision
            }) || !payload.unresolved_uncertainty.iter().any(|lineage| {
                lineage.dependency_id == comparison.dependency_id
                    && lineage.pinned_source_revision == comparison.pinned_source_revision
                    && lineage.selected_source_revision == comparison.candidate_source_revision
                    && lineage.verdict == MaterialityOutcome::UnableToAssess
            })
        })
    {
        return false;
    }
    let mut requested = input
        .sources
        .iter()
        .map(|source| source.record_id.as_str())
        .collect::<Vec<_>>();
    requested.sort_unstable();
    if payload
        .requested_source_record_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != requested
    {
        return false;
    }
    input.sources.iter().all(|declared| {
        let Some(reference) = source_revision(&payload.selected_sources, declared) else {
            return false;
        };
        payload
            .provenance
            .iter()
            .any(|item| item.source_revision == *reference && item.reason == declared.reason)
            && payload.dependencies.iter().any(|item| {
                item.source_revision == *reference
                    && item.semantic_role == declared.role
                    && item.affected_conclusion == affected_conclusion()
                    && item.rationale == declared.reason
                    && item.reconsideration_trigger == RECONSIDERATION_TRIGGER
                    && item.confidence.is_none()
            })
    })
}

async fn unresolved_source_changes(
    db: &Db,
    principal: Principal<'_>,
    input: &SaveAccountInput,
    expected_consumer_revision: &RevisionRef,
    assembly: &crate::freshness::ContextAssembly,
) -> Result<(Vec<AssessmentInput>, Vec<UncertaintyLineage>)> {
    let mut assessments = Vec::with_capacity(assembly.comparisons.len());
    let mut uncertainty = Vec::with_capacity(assembly.comparisons.len());
    for comparison in &assembly.comparisons {
        let explanation = explain_freshness(db, principal, comparison.receipt_id.clone())
            .await
            .map_err(|_| {
                Error::engine("save_account: prior source-change evidence is unavailable")
            })?;
        let prior = explanation
            .visible_dependencies
            .iter()
            .find(|dependency| dependency.dependency_id == comparison.dependency_id)
            .ok_or_else(|| {
                Error::engine("save_account: prior source-change evidence is unavailable")
            })?;
        let assessment_id = AssessmentId::new(comparison_digest_id(
            "save-account-assessment",
            input,
            comparison,
        ))?;
        let uncertainty_id = UncertaintyId::new(comparison_digest_id(
            "save-account-uncertainty",
            input,
            comparison,
        ))?;
        assessments.push(AssessmentInput {
            assessment_id,
            dependency_id: comparison.dependency_id.clone(),
            compared_source_revision: comparison.candidate_source_revision.clone(),
            category: CHANGE_CATEGORY.into(),
            outcome: MaterialityOutcome::UnableToAssess,
            could_materially_change: true,
            rationale: CHANGE_RATIONALE.into(),
        });
        uncertainty.push(UncertaintyLineage {
            uncertainty_id,
            dependency_id: comparison.dependency_id.clone(),
            inherited_from_receipt_id: Some(comparison.receipt_id.clone()),
            consumer_revision: expected_consumer_revision.clone(),
            pinned_source_revision: comparison.pinned_source_revision.clone(),
            selected_source_revision: comparison.candidate_source_revision.clone(),
            affected_conclusion: prior.affected_conclusion.clone(),
            assessment_task_scope: input.reason.clone(),
            verdict: MaterialityOutcome::UnableToAssess,
            evidence: "An exact source body revision changed after the prior authored output"
                .into(),
            detail: "The supported save continues with explicit unresolved uncertainty; it does not infer semantic equivalence or validity"
                .into(),
        });
    }
    Ok((assessments, uncertainty))
}

fn result(
    record_id: String,
    source_count: usize,
    withheld_context: bool,
    committed: CommitDurableOutputResult,
) -> SaveAccountResult {
    SaveAccountResult {
        record_id,
        revision_event_id: committed.output_revision.revision_event_id,
        receipt_id: committed.receipt_id.as_str().into(),
        source_count,
        withheld_context,
        execution: committed.execution,
        disclosure: committed.disclosure,
        act: committed.act,
    }
}

async fn fresh_save_attempt(
    db: &Db,
    principal: Principal<'_>,
    actor: &str,
    input: &SaveAccountInput,
    idempotency_key: &IdempotencyKey,
) -> Result<(CommitDurableOutputResult, bool)> {
    let request = ContextRequest {
        intent: AUTHORING_INTENT.into(),
        task_scope: input.reason.clone(),
        risk_inputs: Vec::new(),
    };
    let source_record_ids = input
        .sources
        .iter()
        .map(|source| source.record_id.clone())
        .collect::<Vec<_>>();
    let assembly = assemble_context(
        db,
        principal,
        request,
        Some(&input.record_id),
        source_record_ids,
    )
    .await
    .map_err(|_| Error::engine("save_account: declared context is unavailable"))?;
    if input
        .sources
        .iter()
        .any(|declared| source_revision(&assembly.sources, declared).is_none())
        || assembly.sources.len() != input.sources.len()
    {
        return Err(Error::engine(
            "save_account: a declared source revision is no longer current; reconsider the draft against current source heads",
        ));
    }
    let expected_consumer_revision =
        record_body_revision(db, &input.record_id, &input.expected_revision_event_id)
            .await
            .map_err(|_| {
                Error::engine("save_account: expected output revision is unavailable or invalid")
            })?;
    let (assessments, unresolved_uncertainty) =
        unresolved_source_changes(db, principal, input, &expected_consumer_revision, &assembly)
            .await?;
    let mut provenance = Vec::with_capacity(input.sources.len());
    let mut dependencies = Vec::with_capacity(input.sources.len());
    for declared in &input.sources {
        let reference = source_revision(&assembly.sources, declared)
            .expect("source set was checked above")
            .clone();
        provenance.push(ProvenanceUse {
            source_revision: reference.clone(),
            reason: declared.reason.clone(),
        });
        dependencies.push(DependencyInput {
            dependency_id: dependency_id(input, declared)?,
            source_revision: reference,
            semantic_role: declared.role.clone(),
            affected_conclusion: affected_conclusion(),
            rationale: declared.reason.clone(),
            reconsideration_trigger: RECONSIDERATION_TRIGGER.into(),
            confidence: None,
        });
    }
    let withheld_context = assembly.withheld_context;
    let committed = crate::freshness::commit_ordinary_note_output(
        db,
        principal,
        actor,
        CommitDurableOutputInput {
            consumer_record_id: input.record_id.clone(),
            expected_consumer_revision,
            output_body: input.body.clone(),
            assembly,
            policy: ResolutionPolicy::agent_speed_default(),
            provenance,
            dependencies,
            assessments,
            reconciliations: Vec::new(),
            unresolved_uncertainty,
            idempotency_key: idempotency_key.clone(),
        },
    )
    .await?;
    Ok((committed, withheld_context))
}

/// Save an authored ordinary note and its exact declared source basis.
pub async fn save_account(
    db: &Db,
    principal: Principal<'_>,
    actor: &str,
    mut input: SaveAccountInput,
) -> Result<SaveAccountResult> {
    let idempotency_key = normalize_input(&mut input)?;

    // Check the occupied key before assembling fresh heads. A true retry is
    // defined by its original public request, so it remains recoverable after
    // the output or a source has subsequently advanced.
    let replay = crate::freshness::replay_ordinary_note_output(
        db,
        principal,
        &input.record_id,
        &idempotency_key,
    )
    .await
    .map_err(|_| Error::engine("save_account: authorization or prior result is unavailable"))?;
    if let Some((payload, committed)) = replay {
        if !public_request_matches_receipt(&input, &payload) {
            return Err(Error::engine(
                "save_account: idempotency key was already used for a different request",
            ));
        }
        return Ok(result(
            input.record_id,
            input.sources.len(),
            payload.withheld_context,
            committed,
        ));
    }

    match fresh_save_attempt(db, principal, actor, &input, &idempotency_key).await {
        Ok((committed, withheld_context)) => Ok(result(
            input.record_id,
            input.sources.len(),
            withheld_context,
            committed,
        )),
        Err(original) => {
            // Another identical first attempt may commit at any point after
            // our initial empty lookup. Re-read the occupied key under full
            // authorization and recover only when the original public request
            // is exactly the same; otherwise preserve the fresh-path error.
            match crate::freshness::replay_ordinary_note_output(
                db,
                principal,
                &input.record_id,
                &idempotency_key,
            )
            .await
            {
                Ok(Some((payload, committed)))
                    if public_request_matches_receipt(&input, &payload) =>
                {
                    Ok(result(
                        input.record_id,
                        input.sources.len(),
                        payload.withheld_context,
                        committed,
                    ))
                }
                _ => Err(original),
            }
        }
    }
}
