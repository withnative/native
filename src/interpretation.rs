//! Conservative read-time interpretation of governed attribution claims.
//!
//! This module derives presentation state only. It never writes a winning
//! claim, endorsement flag, confidence score, or consensus result. Authored
//! attribution and Native-issued provenance remain the source facts.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use chrono::DateTime;
use serde::Serialize;
use serde_json::Value;

use crate::attribution::{AttributionEvidenceView, AttributionView};
use crate::citations::ValidationStatus;
use crate::provenance::{AttestationInspection, AttestationTrust};

pub const MAX_INTERPRETATION_CLAIMS: i64 = 100;
pub const MAX_INTERPRETATION_EVIDENCE: i64 = 256;
pub const MAX_INTERPRETATION_INSPECTIONS: i64 = 256;
pub const MAX_INTERPRETATION_OUTPUT_RECORDS: usize = 256;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionStatus {
    None,
    Current,
    Conflicted,
    HistoricalOnly,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Active,
    Superseded,
    Retracted,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SupersessionState {
    None,
    HasSuccessors,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetState {
    Current,
    Relocated,
    Stale,
    Conflict,
    Unavailable,
}

impl From<ValidationStatus> for TargetState {
    fn from(value: ValidationStatus) -> Self {
        match value {
            ValidationStatus::Current => Self::Current,
            ValidationStatus::Relocated => Self::Relocated,
            ValidationStatus::Stale => Self::Stale,
            ValidationStatus::Conflict => Self::Conflict,
            ValidationStatus::Unavailable => Self::Unavailable,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolarityState {
    Affirmed,
    Denied,
    Conflicted,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimClass {
    DirectDeclaration,
    AssessedHumanStance,
    AgentOpinion,
    UnverifiedDeclaration,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExactReviewState {
    ReceiverLocalConfirmed,
    NotConfirmed,
    UnknownOrWithheld,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    NativeActionBasis,
    VerifiedHumanInteractionBasis,
    ExactTargetConfirmation,
    Counterevidence,
    ForeignUnverified,
    Invalidated,
    UnknownOrWithheld,
}

#[derive(Debug, Clone)]
pub struct InspectedEvidence {
    pub annotation_id: String,
    pub evidence_id: String,
    pub role: String,
    pub action_attestation_id: String,
    pub inspection: Option<AttestationInspection>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterpretationTarget {
    pub scope: String,
    pub source_event_id: String,
    pub source_body_sha256: String,
    pub selectors: Value,
    pub state: TargetState,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterpretationSubject {
    pub kind: String,
    #[serde(rename = "ref")]
    pub reference: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterpretationClaim {
    pub annotation_id: String,
    pub lifecycle_state: LifecycleState,
    pub supersession_state: SupersessionState,
    pub successor_ids: Vec<String>,
    pub claim_class: ClaimClass,
    pub subject: InterpretationSubject,
    pub relation: String,
    pub polarity: String,
    pub confidence: Option<String>,
    pub transformation: String,
    pub rationale: String,
    pub claimant_principal: String,
    pub asserted_at: String,
    pub stance_as_of: String,
    pub target_state: TargetState,
    pub exact_review_state: ExactReviewState,
    pub evidence_classes: Vec<EvidenceClass>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterpretationGroup {
    pub target: InterpretationTarget,
    pub subject: InterpretationSubject,
    pub relation: String,
    pub status: ProjectionStatus,
    pub frontier_as_of: Option<String>,
    pub polarity_state: Option<PolarityState>,
    pub exact_review_state: ExactReviewState,
    pub claims: Vec<InterpretationClaim>,
    pub evidence_classes: Vec<EvidenceClass>,
    pub headline: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterpretationProjection {
    pub bearer_id: String,
    pub as_of_event_seq: Option<i64>,
    /// Caller-visible claim count. `None` means the request-wide bounded read
    /// was unavailable; it must never be replaced with a stored/global count.
    pub attribution_count: Option<i64>,
    pub complete: bool,
    pub status: ProjectionStatus,
    pub groups: Vec<InterpretationGroup>,
    pub historical_claim_count: usize,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceVisibility {
    Complete,
    UnknownOrWithheld,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExplainedEvidence {
    pub evidence_id: String,
    pub role: String,
    pub action_attestation_id: String,
    pub classes: Vec<EvidenceClass>,
    pub attestation: AttestationInspection,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterpretationExplanation {
    pub annotation_id: String,
    pub complete: bool,
    pub target: InterpretationTarget,
    pub claim: InterpretationClaim,
    pub evidence_visibility: EvidenceVisibility,
    pub evidence: Vec<ExplainedEvidence>,
    pub authoring_evidence_visibility: EvidenceVisibility,
    pub authoring_attestation: Option<AttestationInspection>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GroupKey {
    source_event_id: String,
    source_body_sha256: String,
    scope: String,
    selectors: String,
    subject_kind: String,
    subject_ref: String,
    relation: String,
}

const BASE_LIMITATIONS: [&str; 3] = [
    "delegation_does_not_establish_endorsement",
    "confidence_does_not_establish_truth",
    "claim_counts_do_not_establish_consensus",
];

fn limitations() -> Vec<String> {
    BASE_LIMITATIONS
        .iter()
        .map(|value| (*value).into())
        .collect()
}

fn subject(view: &AttributionView) -> InterpretationSubject {
    InterpretationSubject {
        kind: view
            .assertion
            .attributed_subject
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .into(),
        reference: view
            .assertion
            .attributed_subject
            .get("ref")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .into(),
    }
}

fn target(view: &AttributionView) -> InterpretationTarget {
    InterpretationTarget {
        scope: view.target.scope.clone(),
        source_event_id: view.target.source_event_id.clone(),
        source_body_sha256: view.target.source_body_sha256.clone(),
        selectors: view.target.selectors.clone(),
        state: view.target.validation.status.into(),
    }
}

fn group_key(view: &AttributionView) -> GroupKey {
    let subject = subject(view);
    GroupKey {
        source_event_id: view.target.source_event_id.clone(),
        source_body_sha256: view.target.source_body_sha256.clone(),
        scope: view.target.scope.clone(),
        selectors: serde_json::to_string(&view.target.selectors).unwrap_or_default(),
        subject_kind: subject.kind,
        subject_ref: subject.reference,
        relation: view.assertion.relation.clone(),
    }
}

fn lifecycle(view: &AttributionView) -> LifecycleState {
    if view.retraction.is_some() {
        LifecycleState::Retracted
    } else if !view.successor_ids.is_empty() {
        LifecycleState::Superseded
    } else {
        LifecycleState::Active
    }
}

fn claim_class(view: &AttributionView) -> ClaimClass {
    match view.assertion.claim_mode.as_str() {
        "declaration" => ClaimClass::DirectDeclaration,
        "unverified_declaration" => ClaimClass::UnverifiedDeclaration,
        _ if view
            .assertion
            .attributed_subject
            .get("kind")
            .and_then(Value::as_str)
            == Some("agent_execution") =>
        {
            ClaimClass::AgentOpinion
        }
        _ => ClaimClass::AssessedHumanStance,
    }
}

fn evidence_classes(role: &str, inspection: Option<&AttestationInspection>) -> Vec<EvidenceClass> {
    let Some(inspection) = inspection else {
        return vec![EvidenceClass::UnknownOrWithheld];
    };
    let mut classes = BTreeSet::new();
    if inspection.attestation.validity == "invalidated" {
        classes.insert(EvidenceClass::Invalidated);
    } else {
        match inspection.attestation.trust {
            AttestationTrust::NativeVerified => {
                if role == "basis" {
                    classes.insert(EvidenceClass::NativeActionBasis);
                    if inspection.attestation.has_verified_interaction {
                        classes.insert(EvidenceClass::VerifiedHumanInteractionBasis);
                    }
                }
                if role == "exact_target_confirmation" {
                    classes.insert(EvidenceClass::ExactTargetConfirmation);
                }
            }
            AttestationTrust::ForeignUnverified => {
                classes.insert(EvidenceClass::ForeignUnverified);
            }
        }
    }
    if role == "counterevidence" {
        classes.insert(EvidenceClass::Counterevidence);
    }
    classes.into_iter().collect()
}

fn evidence_for<'a>(
    inspections: &'a [InspectedEvidence],
    annotation_id: &str,
) -> Vec<&'a InspectedEvidence> {
    inspections
        .iter()
        .filter(move |item| item.annotation_id == annotation_id)
        .collect()
}

fn exact_review(view: &AttributionView, classes: &[EvidenceClass]) -> ExactReviewState {
    if view.assertion.claim_mode == "declaration"
        && classes.contains(&EvidenceClass::ExactTargetConfirmation)
    {
        ExactReviewState::ReceiverLocalConfirmed
    } else if classes.contains(&EvidenceClass::UnknownOrWithheld) {
        ExactReviewState::UnknownOrWithheld
    } else {
        ExactReviewState::NotConfirmed
    }
}

fn claim(view: &AttributionView, inspections: &[InspectedEvidence]) -> InterpretationClaim {
    let mut classes = evidence_for(inspections, &view.annotation_id)
        .into_iter()
        .flat_map(|item| evidence_classes(&item.role, item.inspection.as_ref()))
        .collect::<BTreeSet<_>>();
    if !view.evidence_complete {
        classes.insert(EvidenceClass::UnknownOrWithheld);
    }
    let classes = classes.into_iter().collect::<Vec<_>>();
    InterpretationClaim {
        annotation_id: view.annotation_id.clone(),
        lifecycle_state: lifecycle(view),
        supersession_state: if view.successor_ids.is_empty() {
            SupersessionState::None
        } else {
            SupersessionState::HasSuccessors
        },
        successor_ids: view.successor_ids.clone(),
        claim_class: claim_class(view),
        subject: subject(view),
        relation: view.assertion.relation.clone(),
        polarity: view.assertion.polarity.clone(),
        confidence: view.assertion.confidence.clone(),
        transformation: view.assertion.transformation.clone(),
        rationale: view.assertion.rationale.clone(),
        claimant_principal: view.assertion.claimant_principal.clone(),
        asserted_at: view.assertion.asserted_at.clone(),
        stance_as_of: view.assertion.stance_as_of.clone(),
        target_state: view.target.validation.status.into(),
        exact_review_state: exact_review(view, &classes),
        evidence_classes: classes,
    }
}

fn timestamp_cmp(left: &str, right: &str) -> Ordering {
    match (
        DateTime::parse_from_rfc3339(left),
        DateTime::parse_from_rfc3339(right),
    ) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}

fn same_timestamp(left: &str, right: &str) -> bool {
    timestamp_cmp(left, right) == Ordering::Equal
}

fn confidence_rank(value: Option<&str>) -> u8 {
    match value {
        Some("confident") => 4,
        Some("likely") => 3,
        Some("plausible") => 2,
        Some("tentative") => 1,
        _ => 0,
    }
}

fn claim_sort(left: &InterpretationClaim, right: &InterpretationClaim) -> Ordering {
    let lifecycle_rank = |state| match state {
        LifecycleState::Active => 0,
        LifecycleState::Superseded => 1,
        LifecycleState::Retracted => 2,
    };
    let class_rank = |class| match class {
        ClaimClass::DirectDeclaration => 0,
        ClaimClass::UnverifiedDeclaration => 1,
        ClaimClass::AssessedHumanStance => 2,
        ClaimClass::AgentOpinion => 3,
    };
    lifecycle_rank(left.lifecycle_state)
        .cmp(&lifecycle_rank(right.lifecycle_state))
        .then_with(|| timestamp_cmp(&right.stance_as_of, &left.stance_as_of))
        .then_with(|| class_rank(left.claim_class).cmp(&class_rank(right.claim_class)))
        .then_with(|| {
            confidence_rank(right.confidence.as_deref())
                .cmp(&confidence_rank(left.confidence.as_deref()))
        })
        .then_with(|| timestamp_cmp(&right.asserted_at, &left.asserted_at))
        .then_with(|| left.annotation_id.cmp(&right.annotation_id))
}

fn latest_group_stance(group: &InterpretationGroup) -> Option<&str> {
    group.frontier_as_of.as_deref().or_else(|| {
        group
            .claims
            .iter()
            .map(|claim| claim.stance_as_of.as_str())
            .max_by(|left, right| timestamp_cmp(left, right))
    })
}

fn group_headline(
    relation: &str,
    status: ProjectionStatus,
    polarity: Option<PolarityState>,
    frontier: &[&InterpretationClaim],
) -> String {
    if frontier.is_empty() {
        return "Historical attribution claims exist; none is active.".into();
    }
    if status == ProjectionStatus::Unavailable {
        return "The attribution target is unavailable.".into();
    }
    if polarity == Some(PolarityState::Conflicted) {
        return format!(
            "Conflicting claims remain about relation {relation}; no consensus is inferred."
        );
    }
    let verb = if polarity == Some(PolarityState::Denied) {
        "denies"
    } else {
        "affirms"
    };
    if frontier.len() > 1 {
        return format!(
            "Multiple aligned claims {verb} relation {relation}; this is not a consensus determination."
        );
    }
    let claim = frontier[0];
    match claim.claim_class {
        ClaimClass::DirectDeclaration => format!(
            "A receiver-local direct declaration {verb} relation {relation} for the exact source target."
        ),
        ClaimClass::AgentOpinion => format!(
            "An agent opinion {verb} relation {relation} with {} confidence; it is not an endorsement upgrade.",
            claim.confidence.as_deref().unwrap_or("unspecified")
        ),
        ClaimClass::AssessedHumanStance => format!(
            "A human-stance assessment {verb} relation {relation} with {} confidence; exact confirmation is separate.",
            claim.confidence.as_deref().unwrap_or("unspecified")
        ),
        ClaimClass::UnverifiedDeclaration => format!(
            "A source declaration {verb} relation {relation}, but receiver-local confirmation is absent."
        ),
    }
}

fn group(views: &[&AttributionView], inspections: &[InspectedEvidence]) -> InterpretationGroup {
    let first = views[0];
    let mut claims = views
        .iter()
        .map(|view| claim(view, inspections))
        .collect::<Vec<_>>();
    claims.sort_by(claim_sort);
    let active = claims
        .iter()
        .filter(|claim| claim.lifecycle_state == LifecycleState::Active)
        .collect::<Vec<_>>();
    let frontier_as_of = active
        .iter()
        .map(|claim| claim.stance_as_of.as_str())
        .max_by(|left, right| timestamp_cmp(left, right))
        .map(str::to_owned);
    let frontier = active
        .iter()
        .copied()
        .filter(|claim| {
            frontier_as_of
                .as_deref()
                .is_some_and(|frontier| same_timestamp(frontier, &claim.stance_as_of))
        })
        .collect::<Vec<_>>();
    let affirmed = frontier.iter().any(|claim| claim.polarity == "affirmed");
    let denied = frontier.iter().any(|claim| claim.polarity == "denied");
    let polarity_state = match (affirmed, denied) {
        (true, true) => Some(PolarityState::Conflicted),
        (true, false) => Some(PolarityState::Affirmed),
        (false, true) => Some(PolarityState::Denied),
        (false, false) => None,
    };
    let target = target(first);
    let status = if frontier.is_empty() {
        ProjectionStatus::HistoricalOnly
    } else if target.state == TargetState::Unavailable {
        ProjectionStatus::Unavailable
    } else if polarity_state == Some(PolarityState::Conflicted) {
        ProjectionStatus::Conflicted
    } else {
        // `current` describes the live semantic head. Exact applicability is
        // reported independently by target.state; a relocated or stale target
        // must not make a still-active authored claim look superseded/history.
        ProjectionStatus::Current
    };
    let exact_review_state = if frontier
        .iter()
        .any(|claim| claim.exact_review_state == ExactReviewState::ReceiverLocalConfirmed)
    {
        ExactReviewState::ReceiverLocalConfirmed
    } else if frontier
        .iter()
        .any(|claim| claim.exact_review_state == ExactReviewState::UnknownOrWithheld)
    {
        ExactReviewState::UnknownOrWithheld
    } else {
        ExactReviewState::NotConfirmed
    };
    let evidence_classes = frontier
        .iter()
        .flat_map(|claim| claim.evidence_classes.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let headline = group_headline(&first.assertion.relation, status, polarity_state, &frontier);
    InterpretationGroup {
        target,
        subject: subject(first),
        relation: first.assertion.relation.clone(),
        status,
        frontier_as_of,
        polarity_state,
        exact_review_state,
        claims,
        evidence_classes,
        headline,
        limitations: limitations(),
    }
}

pub fn project(
    bearer_id: &str,
    as_of_event_seq: Option<i64>,
    attribution_count: i64,
    views: &[AttributionView],
    inspections: &[InspectedEvidence],
) -> InterpretationProjection {
    let mut grouped = BTreeMap::<GroupKey, Vec<&AttributionView>>::new();
    for view in views {
        grouped.entry(group_key(view)).or_default().push(view);
    }
    let mut groups = grouped
        .into_iter()
        .map(|(key, views)| (key, group(&views, inspections)))
        .collect::<Vec<_>>();
    groups.sort_by(|(left_key, left), (right_key, right)| {
        let applicability_rank = |state| match state {
            TargetState::Current => 0,
            TargetState::Relocated => 1,
            TargetState::Stale => 2,
            TargetState::Conflict => 3,
            TargetState::Unavailable => 4,
        };
        let active_rank = |group: &InterpretationGroup| {
            if group
                .claims
                .iter()
                .any(|claim| claim.lifecycle_state == LifecycleState::Active)
            {
                0
            } else {
                1
            }
        };
        applicability_rank(left.target.state)
            .cmp(&applicability_rank(right.target.state))
            .then_with(|| active_rank(left).cmp(&active_rank(right)))
            .then_with(
                || match (latest_group_stance(left), latest_group_stance(right)) {
                    (Some(left), Some(right)) => timestamp_cmp(right, left),
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (None, None) => Ordering::Equal,
                },
            )
            .then_with(|| left_key.cmp(right_key))
    });
    let groups = groups
        .into_iter()
        .map(|(_, group)| group)
        .collect::<Vec<_>>();
    let historical_claim_count = groups
        .iter()
        .flat_map(|group| &group.claims)
        .filter(|claim| claim.lifecycle_state != LifecycleState::Active)
        .count();
    let status = if groups.is_empty() {
        ProjectionStatus::None
    } else if groups
        .iter()
        .any(|group| group.status == ProjectionStatus::Conflicted)
    {
        ProjectionStatus::Conflicted
    } else if groups
        .iter()
        .any(|group| group.status == ProjectionStatus::Current)
    {
        ProjectionStatus::Current
    } else if groups
        .iter()
        .all(|group| group.status == ProjectionStatus::Unavailable)
    {
        ProjectionStatus::Unavailable
    } else {
        ProjectionStatus::HistoricalOnly
    };
    InterpretationProjection {
        bearer_id: bearer_id.into(),
        as_of_event_seq,
        attribution_count: Some(attribution_count),
        complete: true,
        status,
        groups,
        historical_claim_count,
        limitations: limitations(),
    }
}

pub fn bounded_unavailable(
    bearer_id: &str,
    as_of_event_seq: Option<i64>,
    attribution_count: i64,
) -> InterpretationProjection {
    let mut projection = InterpretationProjection {
        bearer_id: bearer_id.into(),
        as_of_event_seq,
        attribution_count: Some(attribution_count),
        complete: false,
        status: ProjectionStatus::Unavailable,
        groups: Vec::new(),
        historical_claim_count: 0,
        limitations: limitations(),
    };
    projection
        .limitations
        .push("claim_set_exceeds_bounded_projection_limit".into());
    projection
}

/// Fail-closed generic-read result. Request-wide overflow deliberately omits
/// each bearer's claim cardinality so a limitation cannot become a side
/// channel for hidden infrastructure records.
pub fn request_bounded_unavailable(bearer_id: &str, limitation: &str) -> InterpretationProjection {
    let mut projection = InterpretationProjection {
        bearer_id: bearer_id.into(),
        as_of_event_seq: None,
        attribution_count: None,
        complete: false,
        status: ProjectionStatus::Unavailable,
        groups: Vec::new(),
        historical_claim_count: 0,
        limitations: limitations(),
    };
    projection.limitations.push(limitation.into());
    projection
}

pub fn evidence_bounded_unavailable(
    bearer_id: &str,
    as_of_event_seq: Option<i64>,
    attribution_count: i64,
    limitation: &str,
) -> InterpretationProjection {
    let mut projection = bounded_unavailable(bearer_id, as_of_event_seq, attribution_count);
    projection
        .limitations
        .retain(|value| value != "claim_set_exceeds_bounded_projection_limit");
    projection.limitations.push(limitation.into());
    projection
}

pub fn explain(
    view: &AttributionView,
    inspections: &[InspectedEvidence],
    authoring_attestation: Option<AttestationInspection>,
    complete: bool,
) -> InterpretationExplanation {
    let claim = claim(view, inspections);
    let mut evidence_visibility = if complete && view.evidence_complete {
        EvidenceVisibility::Complete
    } else {
        EvidenceVisibility::UnknownOrWithheld
    };
    let mut evidence = Vec::new();
    for item in evidence_for(inspections, &view.annotation_id) {
        let Some(inspection) = item.inspection.clone() else {
            evidence_visibility = EvidenceVisibility::UnknownOrWithheld;
            continue;
        };
        evidence.push(ExplainedEvidence {
            evidence_id: item.evidence_id.clone(),
            role: item.role.clone(),
            action_attestation_id: item.action_attestation_id.clone(),
            classes: evidence_classes(&item.role, Some(&inspection)),
            attestation: inspection,
        });
    }
    InterpretationExplanation {
        annotation_id: view.annotation_id.clone(),
        complete,
        target: target(view),
        claim,
        evidence_visibility,
        evidence,
        authoring_evidence_visibility: if authoring_attestation.is_some() {
            EvidenceVisibility::Complete
        } else {
            EvidenceVisibility::UnknownOrWithheld
        },
        authoring_attestation,
        limitations: limitations(),
    }
}

pub fn inspected_evidence(
    view: &AttributionView,
    inspections: &BTreeMap<String, Option<AttestationInspection>>,
) -> Vec<InspectedEvidence> {
    view.evidence
        .iter()
        .map(|evidence: &AttributionEvidenceView| InspectedEvidence {
            annotation_id: view.annotation_id.clone(),
            evidence_id: evidence.evidence_id.clone(),
            role: evidence.role.clone(),
            action_attestation_id: evidence.action_attestation_id.clone(),
            inspection: inspections
                .get(&evidence.action_attestation_id)
                .cloned()
                .flatten(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribution::{
        AttributionAssertionView, AttributionRetractionView, AttributionTargetView,
    };
    use crate::citations::ValidationSummary;
    use serde_json::json;

    fn view(
        id: &str,
        stance_as_of: &str,
        polarity: &str,
        validation: ValidationStatus,
    ) -> AttributionView {
        AttributionView {
            annotation_id: id.into(),
            bearer_id: "bearer".into(),
            target: AttributionTargetView {
                scope: "whole_revision".into(),
                source_event_id: "source-event".into(),
                source_body_sha256: "a".repeat(64),
                selectors: json!([]),
                validation: ValidationSummary {
                    status: validation,
                    detail: None,
                },
            },
            assertion: AttributionAssertionView {
                claimant_principal: format!("claimant-{id}"),
                claim_mode: "assessment".into(),
                relation: "endorses".into(),
                polarity: polarity.into(),
                attributed_subject: json!({"kind":"person_record","ref":"person"}),
                asserted_at: "2026-08-11T00:00:00Z".into(),
                stance_as_of: stance_as_of.into(),
                confidence: Some("likely".into()),
                transformation: "summary".into(),
                rationale: "test rationale".into(),
                authoring_event_id: format!("event-{id}"),
                action_attestation_id: None,
            },
            evidence_count: 0,
            evidence_complete: true,
            evidence: Vec::new(),
            retraction: None,
            successor_ids: Vec::new(),
        }
    }

    #[test]
    fn equivalent_rfc3339_instants_share_one_conflicted_frontier() {
        let claims = vec![
            view(
                "affirmed",
                "2026-08-11T01:00:00+01:00",
                "affirmed",
                ValidationStatus::Current,
            ),
            view(
                "denied",
                "2026-08-11T00:00:00Z",
                "denied",
                ValidationStatus::Current,
            ),
        ];
        let projection = project("bearer", None, 2, &claims, &[]);
        assert_eq!(projection.status, ProjectionStatus::Conflicted);
        assert_eq!(projection.groups.len(), 1);
        assert_eq!(
            projection.groups[0].polarity_state,
            Some(PolarityState::Conflicted)
        );
    }

    #[test]
    fn active_stale_target_is_not_misreported_as_historical_claim() {
        let claims = vec![view(
            "stale",
            "2026-08-11T00:00:00Z",
            "affirmed",
            ValidationStatus::Stale,
        )];
        let projection = project("bearer", None, 1, &claims, &[]);
        assert_eq!(projection.status, ProjectionStatus::Current);
        assert_eq!(projection.groups[0].status, ProjectionStatus::Current);
        assert_eq!(projection.groups[0].target.state, TargetState::Stale);
    }

    #[test]
    fn superseded_and_retracted_claims_stay_historical_without_reactivation() {
        let mut superseded = view(
            "old",
            "2026-08-09T00:00:00Z",
            "affirmed",
            ValidationStatus::Current,
        );
        superseded.successor_ids.push("new".into());
        let mut retracted_successor = view(
            "new",
            "2026-08-10T00:00:00Z",
            "denied",
            ValidationStatus::Current,
        );
        retracted_successor.retraction = Some(AttributionRetractionView {
            retraction_id: "retraction".into(),
            reason: "erroneous".into(),
            retracted_at: "2026-08-11T00:00:00Z".into(),
            retracted_by: "reviewer".into(),
        });
        let projection = project("bearer", None, 2, &[superseded, retracted_successor], &[]);
        assert_eq!(projection.status, ProjectionStatus::HistoricalOnly);
        assert_eq!(projection.historical_claim_count, 2);
        assert!(projection.groups[0]
            .limitations
            .contains(&"claim_counts_do_not_establish_consensus".into()));
    }

    #[test]
    fn groups_order_by_applicability_activity_latest_stance_then_key() {
        let mut current_older = view(
            "current-older",
            "2026-08-09T00:00:00Z",
            "affirmed",
            ValidationStatus::Current,
        );
        current_older.target.source_event_id = "z-current-older".into();
        let mut current_newer = view(
            "current-newer",
            "2026-08-10T00:00:00Z",
            "affirmed",
            ValidationStatus::Current,
        );
        current_newer.target.source_event_id = "y-current-newer".into();
        let mut current_historical = view(
            "current-historical",
            "2026-08-11T00:00:00Z",
            "affirmed",
            ValidationStatus::Current,
        );
        current_historical.target.source_event_id = "a-current-historical".into();
        current_historical.successor_ids.push("later".into());
        let mut stale_active = view(
            "stale-active",
            "2026-08-12T00:00:00Z",
            "affirmed",
            ValidationStatus::Stale,
        );
        stale_active.target.source_event_id = "b-stale-active".into();

        let projection = project(
            "bearer",
            None,
            4,
            &[
                stale_active,
                current_historical,
                current_older,
                current_newer,
            ],
            &[],
        );
        assert_eq!(
            projection
                .groups
                .iter()
                .map(|group| group.target.source_event_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "y-current-newer",
                "z-current-older",
                "a-current-historical",
                "b-stale-active",
            ]
        );
    }
}
