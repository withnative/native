//! Governed, exact-target attribution Annotations.
//!
//! Attribution is authored semantic state, not trusted provenance. The closed
//! assertion below remains separate from Native-issued action attestations:
//! those attest who physically executed accepted events, while this aggregate
//! says what one claimant declares or assesses about one attributed subject.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{QueryBuilder, Row, Sqlite, Transaction};

use crate::citations::{canonicalize_selectors, SelectorInput};
use crate::error::{Error, Result};
use crate::events::{AttributionAssertedPayload, AttributionTargetBoundPayload};

pub const CONTRACT_VERSION: &str = "native.attribution.v1";
pub const MAX_ATTRIBUTION_EVIDENCE_PER_CLAIM: i64 = 32;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetScope {
    WholeRevision,
    Passage,
}

impl TargetScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WholeRevision => "whole_revision",
            Self::Passage => "passage",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactBodyTargetInput {
    pub source_event_id: String,
    pub source_body_sha256: String,
    pub scope: TargetScope,
    #[serde(default)]
    pub selectors: Vec<SelectorInput>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    ExpressesView,
    Endorses,
}

impl Relation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExpressesView => "expresses_view",
            Self::Endorses => "endorses",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Polarity {
    Affirmed,
    Denied,
}

impl Polarity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Affirmed => "affirmed",
            Self::Denied => "denied",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Tentative,
    Plausible,
    Likely,
    Confident,
}

impl Confidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tentative => "tentative",
            Self::Plausible => "plausible",
            Self::Likely => "likely",
            Self::Confident => "confident",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Transformation {
    None,
    Selection,
    Paraphrase,
    Summary,
    Synthesis,
}

impl Transformation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Selection => "selection",
            Self::Paraphrase => "paraphrase",
            Self::Summary => "summary",
            Self::Synthesis => "synthesis",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SubjectInput {
    SelfPerson,
    SelfAgentExecution,
    PersonRecord { record_id: String },
    AgentExecution { action_attestation_id: String },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRole {
    Basis,
    ExactTargetConfirmation,
    Counterevidence,
}

impl EvidenceRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Basis => "basis",
            Self::ExactTargetConfirmation => "exact_target_confirmation",
            Self::Counterevidence => "counterevidence",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceInput {
    pub role: EvidenceRole,
    pub action_attestation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttributionDeclaration {
    pub target_record_id: String,
    pub source_event_id: String,
    pub relation: Relation,
    pub polarity: Polarity,
    accepted_scope_digest: String,
}

impl VerifiedAttributionDeclaration {
    pub(crate) fn from_accepted_arguments(arguments: &Value) -> Result<Self> {
        let object = arguments.as_object().ok_or_else(|| {
            Error::engine("attribution declaration gesture requires object arguments")
        })?;
        let subject_kind = object
            .get("subject")
            .and_then(Value::as_object)
            .and_then(|subject| subject.get("kind"))
            .and_then(Value::as_str);
        let transformation = object.get("transformation").and_then(Value::as_str);
        if subject_kind != Some("self_person") || transformation != Some("none") {
            return Err(Error::engine(
                "attribution declaration gesture requires self_person and transformation none",
            ));
        }
        let target_record_id = object
            .get("bearer_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| Error::engine("attribution declaration gesture requires bearer_id"))?;
        let source_event_id = object
            .get("target")
            .and_then(Value::as_object)
            .and_then(|target| target.get("source_event_id"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                Error::engine("attribution declaration gesture requires target.source_event_id")
            })?;
        let relation = match object.get("relation").and_then(Value::as_str) {
            Some("expresses_view") => Relation::ExpressesView,
            Some("endorses") => Relation::Endorses,
            _ => {
                return Err(Error::engine(
                    "attribution declaration gesture requires a governed relation",
                ))
            }
        };
        let polarity = match object.get("polarity").and_then(Value::as_str) {
            Some("affirmed") => Polarity::Affirmed,
            Some("denied") => Polarity::Denied,
            _ => {
                return Err(Error::engine(
                    "attribution declaration gesture requires a governed polarity",
                ))
            }
        };
        Ok(Self {
            target_record_id: target_record_id.into(),
            source_event_id: source_event_id.into(),
            relation,
            polarity,
            accepted_scope_digest: crate::canonical_json::digest_json(
                &crate::provenance::verified_action_scope("create_attribution", arguments),
            ),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AttributionView {
    pub annotation_id: String,
    pub bearer_id: String,
    pub target: AttributionTargetView,
    pub assertion: AttributionAssertionView,
    pub evidence_count: i64,
    pub evidence_complete: bool,
    pub evidence: Vec<AttributionEvidenceView>,
    pub retraction: Option<AttributionRetractionView>,
    pub successor_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InterpretationEvidenceBounds {
    pub claim_count: i64,
    pub evidence_count: i64,
    pub max_evidence_per_claim: i64,
    pub unique_evidence_inspections: i64,
    pub has_authoring_attestation: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct GenericInterpretationBounds {
    pub attribution_counts: BTreeMap<String, i64>,
    pub claim_count: i64,
    pub evidence_count: i64,
    pub max_evidence_per_claim: i64,
    pub unique_evidence_inspections: i64,
    pub unique_inspection_output_records: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttributionTargetView {
    pub scope: String,
    pub source_event_id: String,
    pub source_body_sha256: String,
    pub selectors: Value,
    pub validation: crate::citations::ValidationSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttributionAssertionView {
    pub claimant_principal: String,
    pub claim_mode: String,
    pub relation: String,
    pub polarity: String,
    pub attributed_subject: Value,
    pub asserted_at: String,
    pub stance_as_of: String,
    pub confidence: Option<String>,
    pub transformation: String,
    pub rationale: String,
    pub authoring_event_id: String,
    /// Filled by the provenance join when the creation action attestation is
    /// available. It stays distinct from the attributed subject and evidence.
    pub action_attestation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttributionEvidenceView {
    pub evidence_id: String,
    pub role: String,
    pub action_attestation_id: String,
    pub added_at: String,
    pub added_by: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttributionRetractionView {
    pub retraction_id: String,
    pub reason: String,
    pub retracted_at: String,
    pub retracted_by: String,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) async fn capture_exact_body_target_in(
    tx: &mut Transaction<'static, Sqlite>,
    bearer_id: &str,
    input: ExactBodyTargetInput,
) -> Result<AttributionTargetBoundPayload> {
    if !valid_sha256(&input.source_body_sha256) {
        return Err(Error::engine(
            "create_attribution: source_body_sha256 must be a lowercase SHA-256 digest",
        ));
    }
    let row = sqlx::query("SELECT body, deleted_at FROM records WHERE id = ?")
        .bind(bearer_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| {
            Error::engine(format!(
                "create_attribution: bearer {bearer_id} does not exist"
            ))
        })?;
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Err(Error::engine(format!(
            "create_attribution: bearer {bearer_id} is deleted"
        )));
    }
    let revision = sqlx::query(
        "SELECT id FROM content_events
          WHERE record_id = ?
            AND (type = 'record.created'
              OR (type = 'record.updated' AND json_type(payload, '$.body') IS NOT NULL))
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(bearer_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::engine("create_attribution: bearer has no body revision event"))?;
    let current_event_id: String = revision.try_get("id")?;
    let bytes = row
        .try_get::<Option<String>, _>("body")?
        .unwrap_or_default()
        .into_bytes();
    let current_sha256 = digest(&bytes);
    if current_event_id != input.source_event_id || current_sha256 != input.source_body_sha256 {
        return Err(Error::engine(format!(
            "create_attribution: exact target conflict; current body revision is {current_event_id} with SHA-256 {current_sha256}"
        )));
    }
    let selectors = match input.scope {
        TargetScope::WholeRevision => {
            if !input.selectors.is_empty() {
                return Err(Error::engine(
                    "create_attribution: whole_revision target must not carry passage selectors",
                ));
            }
            Vec::new()
        }
        TargetScope::Passage => canonicalize_selectors(input.selectors, &bytes)?,
    };
    Ok(AttributionTargetBoundPayload {
        target_record_id: bearer_id.into(),
        target_scope: input.scope.as_str().into(),
        source_event_id: input.source_event_id,
        source_body_sha256: input.source_body_sha256,
        selectors: serde_json::to_value(selectors)?,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn assertion_payload(
    claimant_principal: String,
    claim_mode: &str,
    relation: Relation,
    polarity: Polarity,
    subject_kind: &str,
    subject_ref: String,
    stance_as_of: String,
    confidence: Option<Confidence>,
    transformation: Transformation,
    rationale: String,
) -> Result<AttributionAssertedPayload> {
    if claimant_principal.trim().is_empty() {
        return Err(Error::engine(
            "create_attribution: accepted action has no claimant executor",
        ));
    }
    if rationale.trim().is_empty() {
        return Err(Error::engine(
            "create_attribution: rationale must not be blank",
        ));
    }
    if chrono::DateTime::parse_from_rfc3339(&stance_as_of).is_err() {
        return Err(Error::engine(
            "create_attribution: stance_as_of must be an RFC3339 timestamp",
        ));
    }
    match claim_mode {
        "declaration" if confidence.is_some() => {
            return Err(Error::engine(
                "create_attribution: a direct declaration must not carry confidence",
            ))
        }
        "assessment" if confidence.is_none() => {
            return Err(Error::engine(
                "create_attribution: an assessment requires ordinal confidence",
            ))
        }
        "declaration" | "assessment" => {}
        _ => return Err(Error::engine("create_attribution: invalid claim mode")),
    }
    if claim_mode == "declaration" && transformation != Transformation::None {
        return Err(Error::engine(
            "create_attribution: a direct declaration must use transformation none",
        ));
    }
    Ok(AttributionAssertedPayload {
        contract_version: CONTRACT_VERSION.into(),
        claimant_principal,
        claim_mode: claim_mode.into(),
        relation: relation.as_str().into(),
        polarity: polarity.as_str().into(),
        attributed_subject_kind: subject_kind.into(),
        attributed_subject_ref: subject_ref,
        stance_as_of,
        confidence: confidence.map(|value| value.as_str().into()),
        transformation: transformation.as_str().into(),
        rationale,
    })
}

pub(crate) async fn valid_person_subject_in(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
) -> Result<bool> {
    let predicate = crate::generated::kinds::CoreKind::EntityPerson.sql_matches("r");
    let exists: i64 = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM records r WHERE r.id=? AND r.deleted_at IS NULL AND {predicate})"
    ))
        .bind(record_id)
        .fetch_one(&mut **tx)
        .await?;
    Ok(exists != 0)
}

pub(crate) async fn caller_person_in(
    tx: &mut Transaction<'static, Sqlite>,
    credential: &str,
) -> Result<Option<String>> {
    let predicate = crate::generated::kinds::CoreKind::EntityPerson.sql_matches("r");
    Ok(sqlx::query_scalar(&format!(
        "SELECT r.id FROM bindings b JOIN records r ON r.id = b.record_id
          WHERE b.system = 'account' AND b.identifier = ? AND b.is_canonical = 1
            AND r.deleted_at IS NULL AND {predicate}
          ORDER BY r.id LIMIT 1"
    ))
    .bind(credential)
    .fetch_optional(&mut **tx)
    .await?)
}

pub(crate) fn direct_declaration_matches(
    verified: Option<&VerifiedAttributionDeclaration>,
    accepted_arguments: &Value,
    bearer_id: &str,
    source_event_id: &str,
    relation: Relation,
    polarity: Polarity,
) -> bool {
    verified.is_some_and(|verified| {
        verified.accepted_scope_digest
            == crate::canonical_json::digest_json(&crate::provenance::verified_action_scope(
                "create_attribution",
                accepted_arguments,
            ))
            && verified.target_record_id == bearer_id
            && verified.source_event_id == source_event_id
            && verified.relation == relation
            && verified.polarity == polarity
    })
}

fn selector_validation(
    scope: &str,
    selectors: &[SelectorInput],
    anchored: &[u8],
    current: &[u8],
    same_revision: bool,
) -> crate::citations::ValidationSummary {
    use crate::citations::{ValidationStatus, ValidationSummary};
    if same_revision {
        return ValidationSummary {
            status: ValidationStatus::Current,
            detail: None,
        };
    }
    if scope == "whole_revision" {
        return ValidationSummary {
            status: ValidationStatus::Stale,
            detail: Some("the bearer has a later body revision".into()),
        };
    }
    let anchored_ranges = match crate::citations::selector_ranges(selectors, anchored, None) {
        Ok(ranges) => ranges,
        Err(error) => {
            return ValidationSummary {
                status: ValidationStatus::Conflict,
                detail: Some(error.to_string()),
            }
        }
    };
    let evidence = &anchored[anchored_ranges[0].0..anchored_ranges[0].1];
    match crate::citations::selector_ranges(selectors, current, Some(evidence)) {
        Ok(_) => ValidationSummary {
            status: ValidationStatus::Relocated,
            detail: Some(
                "the exact passage exists exactly once in the current body revision".into(),
            ),
        },
        Err(error)
            if error.to_string().contains("multiple") || error.to_string().contains("disagree") =>
        {
            ValidationSummary {
                status: ValidationStatus::Conflict,
                detail: Some(error.to_string()),
            }
        }
        Err(error) => ValidationSummary {
            status: ValidationStatus::Stale,
            detail: Some(error.to_string()),
        },
    }
}

pub(crate) async fn body_at_event_in(
    tx: &mut Transaction<'_, Sqlite>,
    record_id: &str,
    event_id: &str,
) -> Result<Option<Vec<u8>>> {
    let seq: Option<i64> =
        sqlx::query_scalar("SELECT seq FROM content_events WHERE id = ? AND record_id = ?")
            .bind(event_id)
            .bind(record_id)
            .fetch_optional(&mut **tx)
            .await?;
    let Some(seq) = seq else { return Ok(None) };
    // Fold only body-bearing record events up to the immutable source event.
    let events = sqlx::query(
        "SELECT type, payload FROM content_events
          WHERE record_id = ? AND seq <= ?
            AND (type = 'record.created' OR type = 'record.updated')
          ORDER BY seq",
    )
    .bind(record_id)
    .bind(seq)
    .fetch_all(&mut **tx)
    .await?;
    let mut body: Option<String> = None;
    for event in events {
        let payload: Value = serde_json::from_str(&event.try_get::<String, _>("payload")?)?;
        if event.try_get::<String, _>("type")? == "record.created" || payload.get("body").is_some()
        {
            body = payload
                .get("body")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
    }
    Ok(Some(body.unwrap_or_default().into_bytes()))
}

pub(crate) async fn read_window_in(
    tx: &mut Transaction<'_, Sqlite>,
    bearer_id: &str,
    limit: i64,
    offset: i64,
    as_of_event_seq: Option<i64>,
) -> Result<(i64, Vec<AttributionView>)> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM attribution_assertions a
          JOIN attribution_targets t ON t.annotation_id = a.annotation_id
          JOIN records r ON r.id = a.annotation_id AND r.deleted_at IS NULL
          WHERE t.target_record_id = ? AND (? IS NULL OR a.asserted_event_seq <= ?)",
    )
    .bind(bearer_id)
    .bind(as_of_event_seq)
    .bind(as_of_event_seq)
    .fetch_one(&mut **tx)
    .await?;
    let ids = sqlx::query_scalar::<_, String>(
        "SELECT a.annotation_id FROM attribution_assertions a
          JOIN attribution_targets t ON t.annotation_id = a.annotation_id
          JOIN records r ON r.id = a.annotation_id AND r.deleted_at IS NULL
          WHERE t.target_record_id = ? AND (? IS NULL OR a.asserted_event_seq <= ?)
          ORDER BY a.asserted_at DESC, a.annotation_id DESC LIMIT ? OFFSET ?",
    )
    .bind(bearer_id)
    .bind(as_of_event_seq)
    .bind(as_of_event_seq)
    .bind(limit)
    .bind(offset)
    .fetch_all(&mut **tx)
    .await?;
    let mut views = Vec::with_capacity(ids.len());
    for id in ids {
        views.push(
            read_one_in(tx, &id, as_of_event_seq)
                .await?
                .ok_or_else(|| {
                    Error::engine(format!(
                        "attribution projection {id} disappeared during snapshot"
                    ))
                })?,
        );
    }
    Ok((count, views))
}

pub(crate) async fn interpretation_evidence_bounds_for_bearer_in(
    tx: &mut Transaction<'_, Sqlite>,
    bearer_id: &str,
    as_of_event_seq: Option<i64>,
) -> Result<InterpretationEvidenceBounds> {
    let row = sqlx::query(
        "WITH eligible(annotation_id) AS (
             SELECT a.annotation_id
               FROM attribution_assertions a
               JOIN attribution_targets t ON t.annotation_id=a.annotation_id
               JOIN records r ON r.id=a.annotation_id AND r.deleted_at IS NULL
              WHERE t.target_record_id=? AND (? IS NULL OR a.asserted_event_seq<=?)
         ),
         per_claim(annotation_id,evidence_count) AS (
             SELECT eligible.annotation_id,COUNT(e.evidence_id)
               FROM eligible
               LEFT JOIN attribution_evidence e
                 ON e.annotation_id=eligible.annotation_id
                AND (? IS NULL OR e.event_seq<=?)
              GROUP BY eligible.annotation_id
         ),
         inspection_ids(action_attestation_id) AS (
             SELECT e.action_attestation_id
               FROM eligible
               JOIN attribution_evidence e ON e.annotation_id=eligible.annotation_id
              WHERE (? IS NULL OR e.event_seq<=?)
         )
         SELECT (SELECT COUNT(*) FROM eligible) AS claim_count,
                COALESCE(SUM(evidence_count),0) AS evidence_count,
                COALESCE(MAX(evidence_count),0) AS max_evidence_per_claim,
                (SELECT COUNT(DISTINCT action_attestation_id) FROM inspection_ids)
                    AS unique_evidence_inspections
           FROM per_claim",
    )
    .bind(bearer_id)
    .bind(as_of_event_seq)
    .bind(as_of_event_seq)
    .bind(as_of_event_seq)
    .bind(as_of_event_seq)
    .bind(as_of_event_seq)
    .bind(as_of_event_seq)
    .fetch_one(&mut **tx)
    .await?;
    Ok(InterpretationEvidenceBounds {
        claim_count: row.try_get("claim_count")?,
        evidence_count: row.try_get("evidence_count")?,
        max_evidence_per_claim: row.try_get("max_evidence_per_claim")?,
        unique_evidence_inspections: row.try_get("unique_evidence_inspections")?,
        has_authoring_attestation: false,
    })
}

pub(crate) async fn interpretation_evidence_bounds_for_claim_in(
    tx: &mut Transaction<'_, Sqlite>,
    annotation_id: &str,
    bearer_id: &str,
    as_of_event_seq: Option<i64>,
) -> Result<Option<InterpretationEvidenceBounds>> {
    let row = sqlx::query(
        "WITH eligible(annotation_id,asserted_event_id) AS (
             SELECT a.annotation_id,a.asserted_event_id
               FROM attribution_assertions a
               JOIN attribution_targets t ON t.annotation_id=a.annotation_id
               JOIN records r ON r.id=a.annotation_id AND r.deleted_at IS NULL
              WHERE a.annotation_id=? AND t.target_record_id=?
                AND (? IS NULL OR a.asserted_event_seq<=?)
         ),
         eligible_evidence(action_attestation_id) AS (
             SELECT e.action_attestation_id
               FROM eligible
               JOIN attribution_evidence e ON e.annotation_id=eligible.annotation_id
              WHERE (? IS NULL OR e.event_seq<=?)
         )
         SELECT (SELECT COUNT(*) FROM eligible) AS claim_count,
                (SELECT COUNT(*) FROM eligible_evidence) AS evidence_count,
                (SELECT COUNT(DISTINCT action_attestation_id) FROM eligible_evidence)
                    AS unique_evidence_inspections,
                EXISTS(
                    SELECT 1 FROM eligible
                    JOIN provenance_action_outputs p
                      ON p.output_domain='content'
                     AND p.output_event_id=eligible.asserted_event_id
                ) AS has_authoring_attestation",
    )
    .bind(annotation_id)
    .bind(bearer_id)
    .bind(as_of_event_seq)
    .bind(as_of_event_seq)
    .bind(as_of_event_seq)
    .bind(as_of_event_seq)
    .fetch_one(&mut **tx)
    .await?;
    let claim_count: i64 = row.try_get("claim_count")?;
    if claim_count == 0 {
        return Ok(None);
    }
    let evidence_count = row.try_get("evidence_count")?;
    Ok(Some(InterpretationEvidenceBounds {
        claim_count,
        evidence_count,
        max_evidence_per_claim: evidence_count,
        unique_evidence_inspections: row.try_get("unique_evidence_inspections")?,
        has_authoring_attestation: row.try_get::<i64, _>("has_authoring_attestation")? != 0,
    }))
}

async fn has_receiver_local_exact_confirmation_in(
    tx: &mut Transaction<'_, Sqlite>,
    annotation_id: &str,
    asserted_event_id: &str,
    as_of_event_seq: Option<i64>,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(
             SELECT 1
               FROM attribution_assertions assertion
               JOIN attribution_targets target
                 ON target.annotation_id=assertion.annotation_id
               JOIN attribution_evidence evidence
                 ON evidence.annotation_id=assertion.annotation_id
                AND evidence.role='exact_target_confirmation'
               JOIN content_events evidence_event
                 ON evidence_event.id=evidence.added_event_id
               JOIN provenance_action_attestations attestation
                 ON attestation.id=evidence.action_attestation_id
               JOIN provenance_local_attestation_authority local
                 ON local.attestation_id=attestation.id
                AND local.principal=attestation.principal
                AND local.operation=attestation.operation
               JOIN provenance_interaction_receipts interaction
                 ON interaction.id=attestation.interaction_receipt_id
                AND interaction.principal=attestation.principal
              WHERE assertion.annotation_id=?
                AND assertion.asserted_event_id=?
                AND assertion.claim_mode='declaration'
                AND attestation.operation='create_attribution'
                AND attestation.executor_kind='human'
                AND attestation.executor_ref=assertion.claimant_principal
                AND (? IS NULL OR evidence.event_seq<=?)
                AND COALESCE((
                    SELECT status FROM provenance_attestation_validity_events validity
                     WHERE validity.attestation_id=attestation.id
                     ORDER BY ordinal DESC LIMIT 1
                ),'valid')!='invalidated'
                AND EXISTS(
                    SELECT 1 FROM provenance_action_outputs membership
                     WHERE membership.action_attestation_id=attestation.id
                       AND membership.output_domain='content'
                       AND membership.output_event_id=assertion.asserted_event_id
                )
                AND EXISTS(
                    SELECT 1
                      FROM provenance_action_outputs membership
                      JOIN content_events target_event
                        ON target_event.id=membership.output_event_id
                     WHERE membership.action_attestation_id=attestation.id
                       AND membership.output_domain='content'
                       AND target_event.record_id=assertion.annotation_id
                       AND target_event.seq=target.bound_event_seq
                       AND target_event.type='attribution.target.bound.v1'
                )
                AND EXISTS(
                    SELECT 1 FROM provenance_action_outputs membership
                     WHERE membership.action_attestation_id=attestation.id
                       AND membership.output_domain='content'
                       AND membership.output_event_id=evidence_event.id
                )
         )",
    )
    .bind(annotation_id)
    .bind(asserted_event_id)
    .bind(as_of_event_seq)
    .bind(as_of_event_seq)
    .fetch_one(&mut **tx)
    .await?
        != 0)
}

fn push_string_set<'args>(builder: &mut QueryBuilder<'args, Sqlite>, values: &'args [String]) {
    let mut separated = builder.separated(", ");
    for value in values {
        separated.push_bind(value);
    }
}

/// Preflight the complete, already-authorized generic-read bearer window.
/// Only aggregate counts are returned; no claim/evidence identifiers are
/// materialized before the request-wide limits have been accepted.
pub(crate) async fn generic_interpretation_bounds_in(
    tx: &mut Transaction<'_, Sqlite>,
    bearer_ids: &[String],
) -> Result<GenericInterpretationBounds> {
    let mut attribution_counts = bearer_ids
        .iter()
        .cloned()
        .map(|id| (id, 0))
        .collect::<BTreeMap<_, _>>();
    if bearer_ids.is_empty() {
        return Ok(GenericInterpretationBounds {
            attribution_counts,
            claim_count: 0,
            evidence_count: 0,
            max_evidence_per_claim: 0,
            unique_evidence_inspections: 0,
            unique_inspection_output_records: 0,
        });
    }

    let mut totals = QueryBuilder::<Sqlite>::new(
        "WITH eligible(annotation_id) AS (\
         SELECT a.annotation_id FROM attribution_assertions a \
         JOIN attribution_targets t ON t.annotation_id=a.annotation_id \
         JOIN records r ON r.id=a.annotation_id AND r.deleted_at IS NULL \
         WHERE t.target_record_id IN (",
    );
    push_string_set(&mut totals, bearer_ids);
    totals.push(
        ")), per_claim(annotation_id,evidence_count) AS (\
         SELECT eligible.annotation_id,COUNT(e.evidence_id) FROM eligible \
         LEFT JOIN attribution_evidence e ON e.annotation_id=eligible.annotation_id \
         GROUP BY eligible.annotation_id) \
         SELECT (SELECT COUNT(*) FROM eligible) AS claim_count, \
                COALESCE(SUM(evidence_count),0) AS evidence_count, \
                COALESCE(MAX(evidence_count),0) AS max_evidence_per_claim, \
                (SELECT COUNT(DISTINCT e.action_attestation_id) \
                   FROM eligible JOIN attribution_evidence e \
                     ON e.annotation_id=eligible.annotation_id) \
                  AS unique_evidence_inspections, \
                (SELECT COUNT(DISTINCT output.record_id) \
                   FROM eligible JOIN attribution_evidence e \
                     ON e.annotation_id=eligible.annotation_id \
                   JOIN provenance_action_outputs membership \
                     ON membership.action_attestation_id=e.action_attestation_id \
                    AND membership.output_domain='content' \
                   JOIN content_events output ON output.id=membership.output_event_id) \
                  AS unique_inspection_output_records \
           FROM per_claim",
    );
    let row = totals.build().fetch_one(&mut **tx).await?;

    let mut per_bearer = QueryBuilder::<Sqlite>::new(
        "SELECT t.target_record_id,COUNT(*) AS claim_count \
           FROM attribution_assertions a \
           JOIN attribution_targets t ON t.annotation_id=a.annotation_id \
           JOIN records r ON r.id=a.annotation_id AND r.deleted_at IS NULL \
          WHERE t.target_record_id IN (",
    );
    push_string_set(&mut per_bearer, bearer_ids);
    per_bearer.push(") GROUP BY t.target_record_id");
    for count_row in per_bearer.build().fetch_all(&mut **tx).await? {
        attribution_counts.insert(
            count_row.try_get("target_record_id")?,
            count_row.try_get("claim_count")?,
        );
    }

    Ok(GenericInterpretationBounds {
        attribution_counts,
        claim_count: row.try_get("claim_count")?,
        evidence_count: row.try_get("evidence_count")?,
        max_evidence_per_claim: row.try_get("max_evidence_per_claim")?,
        unique_evidence_inspections: row.try_get("unique_evidence_inspections")?,
        unique_inspection_output_records: row.try_get("unique_inspection_output_records")?,
    })
}

/// Set-based loader for the bounded live generic-read window. The caller must
/// run `generic_interpretation_bounds_in` first and reject every overflowing
/// request before entering this function.
pub(crate) async fn read_generic_interpretation_views_in(
    tx: &mut Transaction<'_, Sqlite>,
    bearer_ids: &[String],
) -> Result<Vec<AttributionView>> {
    if bearer_ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut claims = QueryBuilder::<Sqlite>::new(
        "SELECT a.annotation_id,t.target_record_id,t.target_scope,t.source_event_id,\
                t.source_body_sha256,t.selectors,a.claimant_principal,a.claim_mode,\
                a.relation,a.polarity,a.attributed_subject_kind,a.attributed_subject_ref,\
                a.asserted_at,a.stance_as_of,a.confidence,a.transformation,a.rationale,\
                a.asserted_event_id,source.id AS anchored_event_id,\
                json_extract(source.payload,'$.body') AS anchored_body,\
                bearer.body AS current_body,bearer.deleted_at AS bearer_deleted_at,\
                (SELECT id FROM content_events revision \
                  WHERE revision.record_id=t.target_record_id \
                    AND (revision.type='record.created' OR \
                      (revision.type='record.updated' AND json_type(revision.payload,'$.body') IS NOT NULL)) \
                  ORDER BY revision.seq DESC LIMIT 1) AS current_revision \
           FROM attribution_assertions a \
           JOIN attribution_targets t ON t.annotation_id=a.annotation_id \
           JOIN records annotation ON annotation.id=a.annotation_id AND annotation.deleted_at IS NULL \
           LEFT JOIN records bearer ON bearer.id=t.target_record_id \
           LEFT JOIN content_events source ON source.id=t.source_event_id \
             AND source.record_id=t.target_record_id \
          WHERE t.target_record_id IN (",
    );
    push_string_set(&mut claims, bearer_ids);
    claims.push(") ORDER BY a.asserted_at DESC,a.annotation_id DESC");
    let claim_rows = claims.build().fetch_all(&mut **tx).await?;
    let annotation_ids = claim_rows
        .iter()
        .map(|row| row.try_get::<String, _>("annotation_id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if annotation_ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut evidence_by_claim = BTreeMap::<String, Vec<AttributionEvidenceView>>::new();
    let mut evidence = QueryBuilder::<Sqlite>::new(
        "SELECT annotation_id,evidence_id,role,action_attestation_id,added_at,added_by \
           FROM attribution_evidence WHERE annotation_id IN (",
    );
    push_string_set(&mut evidence, &annotation_ids);
    evidence.push(") ORDER BY event_seq,evidence_id");
    for row in evidence.build().fetch_all(&mut **tx).await? {
        evidence_by_claim
            .entry(row.try_get("annotation_id")?)
            .or_default()
            .push(AttributionEvidenceView {
                evidence_id: row.try_get("evidence_id")?,
                role: row.try_get("role")?,
                action_attestation_id: row.try_get("action_attestation_id")?,
                added_at: row.try_get("added_at")?,
                added_by: row.try_get("added_by")?,
            });
    }

    let mut retraction_by_claim = BTreeMap::<String, AttributionRetractionView>::new();
    let mut retractions = QueryBuilder::<Sqlite>::new(
        "SELECT annotation_id,retraction_id,reason,retracted_at,retracted_by \
           FROM attribution_retractions WHERE annotation_id IN (",
    );
    push_string_set(&mut retractions, &annotation_ids);
    retractions.push(")");
    for row in retractions.build().fetch_all(&mut **tx).await? {
        retraction_by_claim.insert(
            row.try_get("annotation_id")?,
            AttributionRetractionView {
                retraction_id: row.try_get("retraction_id")?,
                reason: row.try_get("reason")?,
                retracted_at: row.try_get("retracted_at")?,
                retracted_by: row.try_get("retracted_by")?,
            },
        );
    }

    let mut successors_by_claim = BTreeMap::<String, Vec<String>>::new();
    let mut successors = QueryBuilder::<Sqlite>::new(
        "SELECT l.target_id,l.source_id FROM links l \
           JOIN attribution_assertions successor ON successor.annotation_id=l.source_id \
           JOIN records successor_record ON successor_record.id=l.source_id \
             AND successor_record.deleted_at IS NULL \
          WHERE l.relationship='supersedes' AND l.target_id IN (",
    );
    push_string_set(&mut successors, &annotation_ids);
    successors.push(") ORDER BY l.created_at,l.source_id");
    for row in successors.build().fetch_all(&mut **tx).await? {
        successors_by_claim
            .entry(row.try_get("target_id")?)
            .or_default()
            .push(row.try_get("source_id")?);
    }

    let mut confirmations = QueryBuilder::<Sqlite>::new(
        "SELECT DISTINCT assertion.annotation_id \
           FROM attribution_assertions assertion \
           JOIN attribution_targets target ON target.annotation_id=assertion.annotation_id \
           JOIN attribution_evidence evidence ON evidence.annotation_id=assertion.annotation_id \
             AND evidence.role='exact_target_confirmation' \
           JOIN content_events evidence_event ON evidence_event.id=evidence.added_event_id \
           JOIN provenance_action_attestations attestation \
             ON attestation.id=evidence.action_attestation_id \
           JOIN provenance_local_attestation_authority local \
             ON local.attestation_id=attestation.id \
             AND local.principal=attestation.principal AND local.operation=attestation.operation \
           JOIN provenance_interaction_receipts interaction \
             ON interaction.id=attestation.interaction_receipt_id \
             AND interaction.principal=attestation.principal \
          WHERE assertion.annotation_id IN (",
    );
    push_string_set(&mut confirmations, &annotation_ids);
    confirmations.push(
        ") AND assertion.claim_mode='declaration' \
           AND attestation.operation='create_attribution' \
           AND attestation.executor_kind='human' \
           AND attestation.executor_ref=assertion.claimant_principal \
           AND COALESCE((SELECT status FROM provenance_attestation_validity_events validity \
                          WHERE validity.attestation_id=attestation.id \
                          ORDER BY ordinal DESC LIMIT 1),'valid')!='invalidated' \
           AND EXISTS(SELECT 1 FROM provenance_action_outputs membership \
                       WHERE membership.action_attestation_id=attestation.id \
                         AND membership.output_domain='content' \
                         AND membership.output_event_id=assertion.asserted_event_id) \
           AND EXISTS(SELECT 1 FROM provenance_action_outputs membership \
                       JOIN content_events target_event ON target_event.id=membership.output_event_id \
                       WHERE membership.action_attestation_id=attestation.id \
                         AND membership.output_domain='content' \
                         AND target_event.record_id=assertion.annotation_id \
                         AND target_event.seq=target.bound_event_seq \
                         AND target_event.type='attribution.target.bound.v1') \
           AND EXISTS(SELECT 1 FROM provenance_action_outputs membership \
                       WHERE membership.action_attestation_id=attestation.id \
                         AND membership.output_domain='content' \
                         AND membership.output_event_id=evidence_event.id)",
    );
    let confirmed = confirmations
        .build_query_scalar::<String>()
        .fetch_all(&mut **tx)
        .await?
        .into_iter()
        .collect::<BTreeSet<_>>();

    let mut views = Vec::with_capacity(claim_rows.len());
    for row in claim_rows {
        let annotation_id: String = row.try_get("annotation_id")?;
        let bearer_id: String = row.try_get("target_record_id")?;
        let source_event_id: String = row.try_get("source_event_id")?;
        let source_sha256: String = row.try_get("source_body_sha256")?;
        let scope: String = row.try_get("target_scope")?;
        let selectors_value: Value = serde_json::from_str(&row.try_get::<String, _>("selectors")?)?;
        let selectors: Vec<SelectorInput> = serde_json::from_value(selectors_value.clone())?;
        let anchored_event_id: Option<String> = row.try_get("anchored_event_id")?;
        let anchored = anchored_event_id
            .as_ref()
            .map(|_| row.try_get::<Option<String>, _>("anchored_body"))
            .transpose()?
            .map(|body| body.unwrap_or_default().into_bytes());
        let current = row
            .try_get::<Option<String>, _>("current_body")?
            .map(String::into_bytes);
        let current_revision: Option<String> = row.try_get("current_revision")?;
        let current_deleted = row
            .try_get::<Option<String>, _>("bearer_deleted_at")?
            .is_some();
        let validation = match (anchored.as_deref(), current.as_deref()) {
            (None, _) => crate::citations::ValidationSummary {
                status: crate::citations::ValidationStatus::Unavailable,
                detail: Some("the immutable source event is unavailable".into()),
            },
            (Some(bytes), _) if digest(bytes) != source_sha256 => {
                crate::citations::ValidationSummary {
                    status: crate::citations::ValidationStatus::Unavailable,
                    detail: Some(
                        "the immutable source event no longer verifies its body digest".into(),
                    ),
                }
            }
            (Some(_), None) => crate::citations::ValidationSummary {
                status: crate::citations::ValidationStatus::Stale,
                detail: Some("the bearer is unavailable".into()),
            },
            (Some(_), Some(_)) if current_deleted => crate::citations::ValidationSummary {
                status: crate::citations::ValidationStatus::Stale,
                detail: Some("the bearer is deleted".into()),
            },
            (Some(anchored), Some(current)) => selector_validation(
                &scope,
                &selectors,
                anchored,
                current,
                current_revision.as_deref() == Some(source_event_id.as_str()),
            ),
        };
        let stored_claim_mode: String = row.try_get("claim_mode")?;
        let claim_mode =
            if stored_claim_mode == "declaration" && !confirmed.contains(&annotation_id) {
                "unverified_declaration".into()
            } else {
                stored_claim_mode
            };
        let evidence = evidence_by_claim.remove(&annotation_id).unwrap_or_default();
        let evidence_count = evidence.len() as i64;
        views.push(AttributionView {
            annotation_id: annotation_id.clone(),
            bearer_id,
            target: AttributionTargetView {
                scope,
                source_event_id,
                source_body_sha256: source_sha256,
                selectors: selectors_value,
                validation,
            },
            assertion: AttributionAssertionView {
                claimant_principal: row.try_get("claimant_principal")?,
                claim_mode,
                relation: row.try_get("relation")?,
                polarity: row.try_get("polarity")?,
                attributed_subject: json!({
                    "kind": row.try_get::<String, _>("attributed_subject_kind")?,
                    "ref": row.try_get::<String, _>("attributed_subject_ref")?,
                }),
                asserted_at: row.try_get("asserted_at")?,
                stance_as_of: row.try_get("stance_as_of")?,
                confidence: row.try_get("confidence")?,
                transformation: row.try_get("transformation")?,
                rationale: row.try_get("rationale")?,
                authoring_event_id: row.try_get("asserted_event_id")?,
                action_attestation_id: None,
            },
            evidence_count,
            evidence_complete: true,
            evidence,
            retraction: retraction_by_claim.remove(&annotation_id),
            successor_ids: successors_by_claim
                .remove(&annotation_id)
                .unwrap_or_default(),
        });
    }
    Ok(views)
}

pub(crate) async fn read_one_in(
    tx: &mut Transaction<'_, Sqlite>,
    annotation_id: &str,
    as_of_event_seq: Option<i64>,
) -> Result<Option<AttributionView>> {
    read_one_with_evidence_in(tx, annotation_id, as_of_event_seq, true).await
}

pub(crate) async fn read_one_without_evidence_in(
    tx: &mut Transaction<'_, Sqlite>,
    annotation_id: &str,
    as_of_event_seq: Option<i64>,
) -> Result<Option<AttributionView>> {
    read_one_with_evidence_in(tx, annotation_id, as_of_event_seq, false).await
}

async fn read_one_with_evidence_in(
    tx: &mut Transaction<'_, Sqlite>,
    annotation_id: &str,
    as_of_event_seq: Option<i64>,
    include_evidence: bool,
) -> Result<Option<AttributionView>> {
    let row = sqlx::query(
        "SELECT t.target_record_id,t.target_scope,t.source_event_id,t.source_body_sha256,t.selectors,
                a.claimant_principal,a.claim_mode,a.relation,a.polarity,a.attributed_subject_kind,a.attributed_subject_ref,
                a.asserted_at,a.stance_as_of,a.confidence,a.transformation,a.rationale,a.asserted_event_id
           FROM attribution_targets t JOIN attribution_assertions a USING(annotation_id)
          JOIN records r ON r.id=t.annotation_id AND r.deleted_at IS NULL
          WHERE t.annotation_id = ? AND (? IS NULL OR a.asserted_event_seq <= ?)",
    )
    .bind(annotation_id)
    .bind(as_of_event_seq)
    .bind(as_of_event_seq)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let bearer_id: String = row.try_get("target_record_id")?;
    let source_event_id: String = row.try_get("source_event_id")?;
    let source_sha256: String = row.try_get("source_body_sha256")?;
    let scope: String = row.try_get("target_scope")?;
    let selectors_value: Value = serde_json::from_str(&row.try_get::<String, _>("selectors")?)?;
    let selectors: Vec<SelectorInput> = serde_json::from_value(selectors_value.clone())?;
    let anchored = body_at_event_in(tx, &bearer_id, &source_event_id).await?;
    let (current_body, current_revision, current_deleted) = if let Some(as_of) = as_of_event_seq {
        let created: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='record.created' AND seq<=?)",
        )
        .bind(&bearer_id)
        .bind(as_of)
        .fetch_one(&mut **tx)
        .await?;
        if created == 0 {
            (None, None, false)
        } else {
            let deleted: i64 = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='record.deleted' AND seq<=?)",
            )
            .bind(&bearer_id)
            .bind(as_of)
            .fetch_one(&mut **tx)
            .await?;
            let revision: Option<String> = sqlx::query_scalar(
                "SELECT id FROM content_events WHERE record_id=? AND seq<=? AND
                  (type='record.created' OR (type='record.updated' AND json_type(payload,'$.body') IS NOT NULL))
                  ORDER BY seq DESC LIMIT 1",
            )
            .bind(&bearer_id)
            .bind(as_of)
            .fetch_optional(&mut **tx)
            .await?;
            let body = match revision.as_deref() {
                Some(revision) => body_at_event_in(tx, &bearer_id, revision).await?,
                None => None,
            };
            (body, revision, deleted != 0)
        }
    } else {
        let current = sqlx::query("SELECT body,deleted_at FROM records WHERE id=?")
            .bind(&bearer_id)
            .fetch_optional(&mut **tx)
            .await?;
        let revision: Option<String> = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE record_id=? AND
              (type='record.created' OR (type='record.updated' AND json_type(payload,'$.body') IS NOT NULL))
              ORDER BY seq DESC LIMIT 1",
        )
        .bind(&bearer_id)
        .fetch_optional(&mut **tx)
        .await?;
        match current {
            Some(row) => (
                Some(
                    row.try_get::<Option<String>, _>("body")?
                        .unwrap_or_default()
                        .into_bytes(),
                ),
                revision,
                row.try_get::<Option<String>, _>("deleted_at")?.is_some(),
            ),
            None => (None, revision, false),
        }
    };
    let validation = match (anchored.as_deref(), current_body.as_deref()) {
        (None, _) => crate::citations::ValidationSummary {
            status: crate::citations::ValidationStatus::Unavailable,
            detail: Some("the immutable source event is unavailable".into()),
        },
        (Some(bytes), _) if digest(bytes) != source_sha256 => crate::citations::ValidationSummary {
            status: crate::citations::ValidationStatus::Unavailable,
            detail: Some("the immutable source event no longer verifies its body digest".into()),
        },
        (Some(_), None) => crate::citations::ValidationSummary {
            status: crate::citations::ValidationStatus::Stale,
            detail: Some("the bearer is unavailable".into()),
        },
        (Some(_), Some(_)) if current_deleted => crate::citations::ValidationSummary {
            status: crate::citations::ValidationStatus::Stale,
            detail: Some("the bearer is deleted".into()),
        },
        (Some(anchored), Some(current)) => selector_validation(
            &scope,
            &selectors,
            anchored,
            current,
            current_revision.as_deref() == Some(source_event_id.as_str()),
        ),
    };
    // Count before materializing evidence rows. Raw claim reads preserve their
    // shape but bound nested work and report honest completeness metadata.
    let evidence_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM attribution_evidence
          WHERE annotation_id=? AND (? IS NULL OR event_seq<=?)",
    )
    .bind(annotation_id)
    .bind(as_of_event_seq)
    .bind(as_of_event_seq)
    .fetch_one(&mut **tx)
    .await?;
    let evidence = if include_evidence {
        sqlx::query(
            "SELECT evidence_id,role,action_attestation_id,added_at,added_by
               FROM attribution_evidence WHERE annotation_id=? AND (? IS NULL OR event_seq<=?)
              ORDER BY event_seq,evidence_id LIMIT ?",
        )
        .bind(annotation_id)
        .bind(as_of_event_seq)
        .bind(as_of_event_seq)
        .bind(MAX_ATTRIBUTION_EVIDENCE_PER_CLAIM)
        .fetch_all(&mut **tx)
        .await?
        .into_iter()
        .map(|row| {
            Ok(AttributionEvidenceView {
                evidence_id: row.try_get("evidence_id")?,
                role: row.try_get("role")?,
                action_attestation_id: row.try_get("action_attestation_id")?,
                added_at: row.try_get("added_at")?,
                added_by: row.try_get("added_by")?,
            })
        })
        .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    let retraction = sqlx::query(
        "SELECT retraction_id,reason,retracted_at,retracted_by FROM attribution_retractions
          WHERE annotation_id=? AND (? IS NULL OR retracted_event_seq<=?)",
    )
    .bind(annotation_id)
    .bind(as_of_event_seq)
    .bind(as_of_event_seq)
    .fetch_optional(&mut **tx)
    .await?
    .map(|row| {
        Ok::<_, crate::Error>(AttributionRetractionView {
            retraction_id: row.try_get("retraction_id")?,
            reason: row.try_get("reason")?,
            retracted_at: row.try_get("retracted_at")?,
            retracted_by: row.try_get("retracted_by")?,
        })
    })
    .transpose()?;
    let successor_ids = sqlx::query_scalar(
        "SELECT l.source_id FROM links l JOIN attribution_assertions a ON a.annotation_id=l.source_id
          WHERE l.target_id=? AND l.relationship='supersedes'
            AND (? IS NULL OR a.asserted_event_seq<=?) ORDER BY l.created_at,l.source_id",
    )
    .bind(annotation_id)
    .bind(as_of_event_seq)
    .bind(as_of_event_seq)
    .fetch_all(&mut **tx)
    .await?;
    let asserted_event_id: String = row.try_get("asserted_event_id")?;
    let stored_claim_mode: String = row.try_get("claim_mode")?;
    let claim_mode = if stored_claim_mode == "declaration"
        && !has_receiver_local_exact_confirmation_in(
            tx,
            annotation_id,
            &asserted_event_id,
            as_of_event_seq,
        )
        .await?
    {
        // Preserve the portable source claim while making the missing receiver-
        // local authority explicit. Import never turns a foreign declaration
        // into a Native-verified declaration on the receiving database.
        "unverified_declaration".to_string()
    } else {
        stored_claim_mode
    };
    // The precise membership schema is owned by provenance v31. This join is
    // intentionally optional: replayed/historical content can remain readable
    // when infrastructure evidence was not copied into the scratch projection.
    let action_attestation_id = sqlx::query_scalar(
        "SELECT action_attestation_id FROM provenance_action_outputs WHERE output_domain='content' AND output_event_id=? ORDER BY ordinal LIMIT 1",
    )
    .bind(&asserted_event_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(Some(AttributionView {
        annotation_id: annotation_id.into(),
        bearer_id,
        target: AttributionTargetView {
            scope,
            source_event_id,
            source_body_sha256: source_sha256,
            selectors: selectors_value,
            validation,
        },
        assertion: AttributionAssertionView {
            claim_mode,
            claimant_principal: row.try_get("claimant_principal")?,
            relation: row.try_get("relation")?,
            polarity: row.try_get("polarity")?,
            attributed_subject: json!({
                "kind": row.try_get::<String, _>("attributed_subject_kind")?,
                "ref": row.try_get::<String, _>("attributed_subject_ref")?,
            }),
            asserted_at: row.try_get("asserted_at")?,
            stance_as_of: row.try_get("stance_as_of")?,
            confidence: row.try_get("confidence")?,
            transformation: row.try_get("transformation")?,
            rationale: row.try_get("rationale")?,
            authoring_event_id: asserted_event_id,
            action_attestation_id,
        },
        evidence_count,
        evidence_complete: include_evidence && evidence_count <= MAX_ATTRIBUTION_EVIDENCE_PER_CLAIM,
        evidence,
        retraction,
        successor_ids,
    }))
}
