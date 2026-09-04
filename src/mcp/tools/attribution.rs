//! Governed attribution authoring, lifecycle, and dedicated reads.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use uuid::Uuid;

use crate::attribution::{
    AttributionView, Confidence, EvidenceInput, EvidenceRole, ExactBodyTargetInput,
    InterpretationEvidenceBounds, Polarity, Relation, SubjectInput, Transformation,
};
use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::events::{
    AttributionEvidenceAddedPayload, AttributionRetractedPayload, LinkAddedPayload,
};
use crate::store::{append_in, now_iso, AppendSpec};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{parse_args, require_record_in};

const MAX_ATTRIBUTION_WINDOW: i64 = 100;
pub(crate) const MAX_GENERIC_INTERPRETATION_BEARERS: usize = 50;
pub(crate) const MAX_GENERIC_INTERPRETATION_CLAIMS: i64 = 100;

fn not_found(tool: &str, id: &str) -> Error {
    Error::engine(format!("{tool}: attribution {id} does not exist"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateAttributionArgs {
    id: Option<String>,
    idempotency_key: String,
    bearer_id: String,
    target: ExactBodyTargetInput,
    subject: SubjectInput,
    relation: Relation,
    polarity: Polarity,
    stance_as_of: Option<String>,
    confidence: Option<Confidence>,
    transformation: Transformation,
    rationale: String,
    #[serde(default)]
    evidence: Vec<EvidenceInput>,
    successor_of: Option<String>,
}

async fn retry_result_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    attestation_id: &str,
    bearer_id: &str,
) -> Result<Value> {
    let row = sqlx::query(
        "SELECT e.record_id AS annotation_id,
                json_extract(e.payload,'$.claim_mode') AS claim_mode
           FROM provenance_action_outputs membership
           JOIN content_events e ON e.id=membership.output_event_id
           JOIN attribution_targets target ON target.annotation_id=e.record_id
          WHERE membership.action_attestation_id=?
            AND membership.output_domain='content'
            AND e.type='attribution.asserted.v1'
            AND target.target_record_id=?",
    )
    .bind(attestation_id)
    .bind(bearer_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| {
        Error::engine("create_attribution: durable idempotency result is unavailable")
    })?;
    Ok(json!({
        "annotation_id": row.try_get::<String, _>("annotation_id")?,
        "bearer_id": bearer_id,
        "claim_mode": row.try_get::<String, _>("claim_mode")?,
        "action_attestation_id": attestation_id,
    }))
}

async fn evidence_visible_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    id: &str,
    required_executor_kind: Option<&str>,
) -> Result<bool> {
    Ok(crate::provenance::validate_action_attestation_evidence_in(
        tx,
        caller,
        id,
        required_executor_kind,
    )
    .await
    .is_ok())
}

async fn attribution_evidence_visible_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    id: &str,
    required_executor_kind: Option<&str>,
    annotation_id: &str,
) -> Result<bool> {
    Ok(
        crate::provenance::validate_attribution_attestation_evidence_in(
            tx,
            caller,
            id,
            required_executor_kind,
            annotation_id,
        )
        .await
        .is_ok(),
    )
}

async fn attribution_bearer_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    id: &str,
) -> Result<Option<String>> {
    let row = sqlx::query(
        "SELECT t.target_record_id,
                (SELECT COUNT(*) FROM links l WHERE l.source_id=t.annotation_id AND l.relationship='part_of') AS bearer_count,
                r.type,r.kind,r.deleted_at
           FROM attribution_targets t JOIN records r ON r.id=t.annotation_id
          WHERE t.annotation_id=?",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else { return Ok(None) };
    if row.try_get::<String, _>("type")? != "Annotation"
        || row.try_get::<Option<String>, _>("kind")?.as_deref() != Some("attribution")
        || row.try_get::<Option<String>, _>("deleted_at")?.is_some()
        || row.try_get::<i64, _>("bearer_count")? != 1
    {
        return Ok(None);
    }
    Ok(Some(row.try_get("target_record_id")?))
}

async fn create_attribution(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "create_attribution";
    let accepted_arguments = arguments.clone();
    let args: CreateAttributionArgs = parse_args(TOOL, arguments)?;
    if args.idempotency_key.trim().is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: idempotency_key must not be blank"
        )));
    }
    if args
        .evidence
        .iter()
        .any(|item| item.role == EvidenceRole::ExactTargetConfirmation)
    {
        return Err(Error::engine(format!(
            "{TOOL}: exact_target_confirmation is created only by Native's accepted direct-declaration action"
        )));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    require_record_in(&mut tx, &caller, TOOL, &args.bearer_id, Capability::Edit).await?;

    if let Some(attestation_id) = crate::provenance::lookup_authorized_command_attestation(
        &db,
        caller.credential(),
        TOOL,
        &accepted_arguments,
        caller.intent(),
    )
    .await?
    {
        let result = retry_result_in(&mut tx, &attestation_id, &args.bearer_id).await?;
        tx.rollback().await?;
        return Ok(result);
    }

    let annotation_id = args.id.unwrap_or_else(|| Uuid::new_v4().to_string());

    let target =
        crate::attribution::capture_exact_body_target_in(&mut tx, &args.bearer_id, args.target)
            .await?;
    let source_event_id = target.source_event_id.clone();

    // Reserve before writing so self-as-agent and exact structured declarations
    // can cite the same Native-issued action identity that will be finalized
    // against the complete ordered event set below.
    let attestation_draft = crate::provenance::reserve_action_attestation()?;
    let authoring_attestation_id = attestation_draft.id().to_string();

    let caller_person = crate::attribution::caller_person_in(&mut tx, caller.credential()).await?;
    let (subject_kind, subject_ref) = match args.subject {
        SubjectInput::SelfPerson => (
            "person_record",
            caller_person.clone().ok_or_else(|| {
                Error::engine(format!("{TOOL}: caller has no canonical person binding"))
            })?,
        ),
        SubjectInput::SelfAgentExecution => {
            if caller.verified_agent_executor().is_none() {
                return Err(Error::engine(format!(
                    "{TOOL}: self_agent_execution requires trusted agent executor provenance"
                )));
            }
            ("agent_execution", authoring_attestation_id.clone())
        }
        SubjectInput::PersonRecord { record_id } => {
            if !crate::attribution::valid_person_subject_in(&mut tx, &record_id).await?
                || require_record_in(&mut tx, &caller, TOOL, &record_id, Capability::View)
                    .await
                    .is_err()
            {
                return Err(Error::engine(format!(
                    "{TOOL}: attributed subject does not exist"
                )));
            }
            ("person_record", record_id)
        }
        SubjectInput::AgentExecution {
            action_attestation_id,
        } => {
            if !evidence_visible_in(&mut tx, &caller, &action_attestation_id, Some("agent")).await?
            {
                return Err(Error::engine(format!(
                    "{TOOL}: attributed subject does not exist"
                )));
            }
            ("agent_execution", action_attestation_id)
        }
    };

    let declaration = subject_kind == "person_record"
        && caller_person.as_deref() == Some(subject_ref.as_str())
        && args.transformation == Transformation::None
        && crate::attribution::direct_declaration_matches(
            caller.verified_attribution_declaration(),
            &accepted_arguments,
            &args.bearer_id,
            &source_event_id,
            args.relation,
            args.polarity,
        );
    let claim_mode = if declaration {
        "declaration"
    } else {
        "assessment"
    };
    let stance_as_of = args.stance_as_of.unwrap_or_else(now_iso);
    let claimant_principal = crate::provenance::accepted_executor_ref()?;
    let assertion = crate::attribution::assertion_payload(
        claimant_principal,
        claim_mode,
        args.relation,
        args.polarity,
        subject_kind,
        subject_ref,
        stance_as_of,
        args.confidence,
        args.transformation,
        args.rationale,
    )?;

    let mut evidence = args.evidence;
    if declaration {
        evidence.push(EvidenceInput {
            role: EvidenceRole::ExactTargetConfirmation,
            action_attestation_id: authoring_attestation_id.clone(),
        });
    }
    let mut unique_evidence = std::collections::BTreeSet::new();
    for item in &evidence {
        let key = (item.role.as_str(), item.action_attestation_id.as_str());
        if !unique_evidence.insert(key) {
            return Err(Error::engine(format!(
                "{TOOL}: duplicate evidence role and action_attestation_id"
            )));
        }
        if item.action_attestation_id != authoring_attestation_id
            && !evidence_visible_in(&mut tx, &caller, &item.action_attestation_id, None).await?
        {
            return Err(Error::engine(format!("{TOOL}: evidence does not exist")));
        }
    }

    if let Some(predecessor) = args.successor_of.as_deref() {
        let predecessor_bearer = attribution_bearer_in(&mut tx, predecessor).await?;
        if predecessor_bearer.as_deref() != Some(args.bearer_id.as_str()) {
            return Err(Error::engine(format!(
                "{TOOL}: predecessor attribution does not exist"
            )));
        }
    }

    let mut events = Vec::new();
    events.push(
        append_in(
            &db,
            &mut tx,
            AppendSpec {
                record_id: annotation_id.clone(),
                event_type: "record.created".into(),
                payload: json!({
                    "type":"Annotation",
                    "kind":"attribution",
                    "name":"Attribution claim",
                    "home_id":crate::schema::ROOT_RECORD_ID,
                    "reason":"Create one immutable exact-target attribution aggregate"
                }),
                actor: Some(caller.actor().into()),
            },
        )
        .await?,
    );
    events.push(
        append_in(
            &db,
            &mut tx,
            AppendSpec {
                record_id: annotation_id.clone(),
                event_type: "link.added".into(),
                payload: serde_json::to_value(LinkAddedPayload {
                    id: None,
                    source_id: annotation_id.clone(),
                    target_id: args.bearer_id.clone(),
                    relationship: "part_of".into(),
                    note: None,
                })?,
                actor: Some(caller.actor().into()),
            },
        )
        .await?,
    );
    if let Some(predecessor) = args.successor_of {
        events.push(
            append_in(
                &db,
                &mut tx,
                AppendSpec {
                    record_id: annotation_id.clone(),
                    event_type: "link.added".into(),
                    payload: serde_json::to_value(LinkAddedPayload {
                        id: None,
                        source_id: annotation_id.clone(),
                        target_id: predecessor,
                        relationship: "supersedes".into(),
                        note: Some(
                            "Corrects or materially succeeds the earlier attribution".into(),
                        ),
                    })?,
                    actor: Some(caller.actor().into()),
                },
            )
            .await?,
        );
    }
    events.push(
        append_in(
            &db,
            &mut tx,
            AppendSpec {
                record_id: annotation_id.clone(),
                event_type: "attribution.target.bound.v1".into(),
                payload: serde_json::to_value(target)?,
                actor: Some(caller.actor().into()),
            },
        )
        .await?,
    );
    events.push(
        append_in(
            &db,
            &mut tx,
            AppendSpec {
                record_id: annotation_id.clone(),
                event_type: "attribution.asserted.v1".into(),
                payload: serde_json::to_value(assertion)?,
                actor: Some(caller.actor().into()),
            },
        )
        .await?,
    );
    for item in evidence {
        events.push(
            append_in(
                &db,
                &mut tx,
                AppendSpec {
                    record_id: annotation_id.clone(),
                    event_type: "attribution.evidence.added.v1".into(),
                    payload: serde_json::to_value(AttributionEvidenceAddedPayload {
                        evidence_id: Uuid::new_v4().to_string(),
                        role: item.role.as_str().into(),
                        action_attestation_id: item.action_attestation_id,
                    })?,
                    actor: Some(caller.actor().into()),
                },
            )
            .await?,
        );
    }
    crate::provenance::issue_action_attestation_in(&mut tx, attestation_draft, &events).await?;
    db.commit_content(tx).await?;
    Ok(json!({
        "annotation_id": annotation_id,
        "bearer_id": args.bearer_id,
        "claim_mode": claim_mode,
        "action_attestation_id": authoring_attestation_id,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadAttributionsArgs {
    bearer_id: String,
    limit: Option<i64>,
    offset: Option<i64>,
    as_of_event_seq: Option<i64>,
    explain_annotation_id: Option<String>,
}

struct ValidatedReadAttributions {
    bearer_id: String,
    limit: i64,
    offset: i64,
    as_of_event_seq: Option<i64>,
    explain_annotation_id: Option<String>,
}

struct AttributionReadBounds {
    projection: InterpretationEvidenceBounds,
    explanation: Option<InterpretationEvidenceBounds>,
}

struct ProjectionReadStage {
    limitation: Option<&'static str>,
    attributions: Vec<AttributionView>,
}

impl ProjectionReadStage {
    fn available(&self) -> bool {
        self.limitation.is_none()
    }
}

struct ExplanationReadStage {
    limitation: Option<&'static str>,
    attribution: Option<AttributionView>,
}

impl ExplanationReadStage {
    fn available(&self) -> bool {
        self.limitation.is_none()
    }
}

type AttributionInspections = BTreeMap<String, Option<crate::provenance::AttestationInspection>>;

struct AttributionReadSnapshot {
    count: i64,
    attributions: Vec<AttributionView>,
    projection: ProjectionReadStage,
    explanation: ExplanationReadStage,
    inspection_inputs: Vec<AttributionView>,
    inspections: AttributionInspections,
}

async fn inspect_attribution_evidence_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    attributions: &[AttributionView],
    explanation_id: Option<&str>,
) -> Result<AttributionInspections> {
    let mut ids = BTreeMap::<String, (String, bool)>::new();
    for attribution in attributions {
        let is_explanation = Some(attribution.annotation_id.as_str()) == explanation_id;
        for evidence in &attribution.evidence {
            ids.entry(evidence.action_attestation_id.clone())
                .and_modify(|entry| entry.1 |= is_explanation)
                .or_insert((attribution.annotation_id.clone(), is_explanation));
        }
        if is_explanation {
            if let Some(id) = &attribution.assertion.action_attestation_id {
                ids.entry(id.clone())
                    .or_insert((attribution.annotation_id.clone(), true));
            }
        }
    }
    if ids.len() as i64 > crate::interpretation::MAX_INTERPRETATION_INSPECTIONS {
        return Err(Error::engine(
            "read_attributions: bounded evidence inspection is unavailable",
        ));
    }
    if explanation_id.is_none() {
        let requests = ids
            .into_iter()
            .map(|(id, (authorized_attribution_id, _))| (id, authorized_attribution_id))
            .collect();
        return crate::provenance::inspect_action_attestation_summaries_in(tx, caller, &requests)
            .await;
    }
    let mut inspections = BTreeMap::new();
    for (id, (authorized_attribution_id, explain)) in ids {
        let detail = if explain {
            crate::provenance::InspectionDetail::Why
        } else {
            crate::provenance::InspectionDetail::Summary
        };
        inspections.insert(
            id.clone(),
            crate::provenance::inspect_action_attestation_in(
                tx,
                caller,
                &id,
                detail,
                Some(&authorized_attribution_id),
            )
            .await?,
        );
    }
    Ok(inspections)
}

pub(crate) struct AuthorizedInterpretationBearers(Vec<String>);

fn authorized_bearer_window(
    ids: impl IntoIterator<Item = String>,
) -> AuthorizedInterpretationBearers {
    AuthorizedInterpretationBearers(
        ids.into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    )
}

/// Construct only from the already filtered `found` items returned by the
/// live get transaction.
pub(crate) fn authorized_get_interpretation_bearers(
    items: &[Value],
) -> AuthorizedInterpretationBearers {
    authorized_bearer_window(items.iter().filter_map(|item| {
        (item.get("status").and_then(Value::as_str) == Some("found"))
            .then(|| item.get("id").and_then(Value::as_str).map(String::from))
            .flatten()
    }))
}

/// Construct only from the caller-authorized live query terminal rows.
pub(crate) fn authorized_query_interpretation_bearers(
    records: &[Value],
) -> AuthorizedInterpretationBearers {
    authorized_bearer_window(
        records
            .iter()
            .filter_map(|record| record.get("id").and_then(Value::as_str).map(String::from)),
    )
}

/// Construct only after `render_record` has required the one bearer inside the
/// caller-owned transaction.
pub(crate) fn authorized_render_interpretation_bearer(
    bearer_id: &str,
) -> AuthorizedInterpretationBearers {
    authorized_bearer_window([bearer_id.to_owned()])
}

/// Project interpretations for one already-selected generic read page.
///
/// The typed window is constructed from a live surface's already authorized
/// result, then defended at this trust boundary by one constant-query canonical
/// authorization preload. The single global provenance integrity scan therefore
/// follows authorization without adding an N+1 pass. Aggregate bounds are
/// accepted before any claim/evidence identifier is loaded. Request-wide
/// overflow returns an unavailable projection for every bearer without
/// per-bearer counts or identifiers.
pub(crate) async fn project_generic_interpretations_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    bearer_window: AuthorizedInterpretationBearers,
) -> Result<BTreeMap<String, crate::interpretation::InterpretationProjection>> {
    let bearer_ids = bearer_window.0;
    if bearer_ids.len() > MAX_GENERIC_INTERPRETATION_BEARERS {
        return Err(Error::engine(format!(
            "interpretation projection supports at most {MAX_GENERIC_INTERPRETATION_BEARERS} visible records per request"
        )));
    }
    if bearer_ids.is_empty() {
        // In particular, do not turn a hidden/not-found-only request into a
        // global provenance integrity oracle.
        return Ok(BTreeMap::new());
    }
    let visible = crate::mcp::tools::visible_ids_preloaded_in(tx, caller, &bearer_ids).await?;
    if visible.len() != bearer_ids.len()
        || bearer_ids
            .iter()
            .any(|bearer_id| !visible.contains(bearer_id))
    {
        return Err(Error::engine(
            "interpretation projection authorization window is invalid",
        ));
    }
    if !crate::provenance::state_violations_in(tx).await?.is_empty() {
        return Err(Error::engine("provenance attestation state is invalid"));
    }
    let bounds = crate::attribution::generic_interpretation_bounds_in(tx, &bearer_ids).await?;
    let limitation = if bounds.claim_count > MAX_GENERIC_INTERPRETATION_CLAIMS {
        Some("request_claim_set_exceeds_bounded_projection_limit")
    } else if bounds.max_evidence_per_claim > crate::attribution::MAX_ATTRIBUTION_EVIDENCE_PER_CLAIM
    {
        Some("claim_evidence_exceeds_bounded_projection_limit")
    } else if bounds.evidence_count > crate::interpretation::MAX_INTERPRETATION_EVIDENCE {
        Some("request_evidence_set_exceeds_bounded_projection_limit")
    } else if bounds.unique_evidence_inspections
        > crate::interpretation::MAX_INTERPRETATION_INSPECTIONS
    {
        Some("request_inspection_set_exceeds_bounded_projection_limit")
    } else if bounds.unique_inspection_output_records
        > crate::interpretation::MAX_INTERPRETATION_OUTPUT_RECORDS as i64
    {
        Some("request_inspection_output_set_exceeds_bounded_projection_limit")
    } else {
        None
    };
    if let Some(limitation) = limitation {
        return Ok(bearer_ids
            .into_iter()
            .map(|bearer_id| {
                let projection =
                    crate::interpretation::request_bounded_unavailable(&bearer_id, limitation);
                (bearer_id, projection)
            })
            .collect());
    }

    let attributions =
        crate::attribution::read_generic_interpretation_views_in(tx, &bearer_ids).await?;
    let inspections = inspect_attribution_evidence_in(tx, caller, &attributions, None).await?;
    let inspected = attributions
        .iter()
        .flat_map(|attribution| {
            crate::interpretation::inspected_evidence(attribution, &inspections)
        })
        .collect::<Vec<_>>();
    Ok(bearer_ids
        .into_iter()
        .map(|bearer_id| {
            let views = attributions
                .iter()
                .filter(|view| view.bearer_id == bearer_id)
                .cloned()
                .collect::<Vec<_>>();
            let count = bounds
                .attribution_counts
                .get(&bearer_id)
                .copied()
                .unwrap_or(0);
            let projection =
                crate::interpretation::project(&bearer_id, None, count, &views, &inspected);
            (bearer_id, projection)
        })
        .collect())
}

pub(crate) fn attach_generic_interpretations(
    records: &mut [Value],
    projections: &BTreeMap<String, crate::interpretation::InterpretationProjection>,
) -> Result<()> {
    for record in records {
        let Some(record_id) = record.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(projection) = projections.get(record_id) else {
            continue;
        };
        record
            .as_object_mut()
            .expect("record result serializes as an object")
            .insert("interpretation".into(), serde_json::to_value(projection)?);
    }
    Ok(())
}

fn projection_evidence_limitation(bounds: InterpretationEvidenceBounds) -> Option<&'static str> {
    if bounds.max_evidence_per_claim > crate::attribution::MAX_ATTRIBUTION_EVIDENCE_PER_CLAIM {
        Some("claim_evidence_exceeds_bounded_projection_limit")
    } else if bounds.evidence_count > crate::interpretation::MAX_INTERPRETATION_EVIDENCE {
        Some("evidence_set_exceeds_bounded_projection_limit")
    } else if bounds.unique_evidence_inspections
        > crate::interpretation::MAX_INTERPRETATION_INSPECTIONS
    {
        Some("inspection_set_exceeds_bounded_projection_limit")
    } else {
        None
    }
}

fn explanation_evidence_limitation(
    bounds: InterpretationEvidenceBounds,
    projection_bounds: InterpretationEvidenceBounds,
    projection_available: bool,
) -> Option<&'static str> {
    if bounds.evidence_count > crate::attribution::MAX_ATTRIBUTION_EVIDENCE_PER_CLAIM {
        return Some("claim_evidence_exceeds_bounded_explanation_limit");
    }
    let unique_inspections = if projection_available {
        projection_bounds.unique_evidence_inspections + i64::from(bounds.has_authoring_attestation)
    } else {
        bounds.unique_evidence_inspections + i64::from(bounds.has_authoring_attestation)
    };
    if unique_inspections > crate::interpretation::MAX_INTERPRETATION_INSPECTIONS {
        Some("inspection_set_exceeds_bounded_explanation_limit")
    } else {
        None
    }
}

fn validated_read_attributions(arguments: Value) -> Result<ValidatedReadAttributions> {
    const TOOL: &str = "read_attributions";
    let args: ReadAttributionsArgs = parse_args(TOOL, arguments)?;
    let limit = args.limit.unwrap_or(50);
    let offset = args.offset.unwrap_or(0);
    if !(0..=MAX_ATTRIBUTION_WINDOW).contains(&limit) || offset < 0 {
        return Err(Error::engine(format!(
            "{TOOL}: limit must be 0..={MAX_ATTRIBUTION_WINDOW} and offset must be >= 0"
        )));
    }
    if args.as_of_event_seq.is_some_and(|seq| seq <= 0) {
        return Err(Error::engine(format!(
            "{TOOL}: as_of_event_seq must be positive"
        )));
    }
    Ok(ValidatedReadAttributions {
        bearer_id: args.bearer_id,
        limit,
        offset,
        as_of_event_seq: args.as_of_event_seq,
        explain_annotation_id: args.explain_annotation_id,
    })
}

async fn authorize_attribution_read_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    request: &ValidatedReadAttributions,
) -> Result<()> {
    const TOOL: &str = "read_attributions";
    // The bearer is the first authorization boundary: callers who cannot view
    // it must not gain a global provenance-integrity oracle. Authorization and
    // integrity validation run in the same snapshot as every returned row.
    if require_record_in(tx, caller, TOOL, &request.bearer_id, Capability::View)
        .await
        .is_err()
    {
        return Err(Error::engine(format!("{TOOL}: bearer does not exist")));
    }
    if !crate::provenance::state_violations_in(tx).await?.is_empty() {
        return Err(Error::engine("provenance attestation state is invalid"));
    }
    Ok(())
}

async fn read_attribution_bounds_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    request: &ValidatedReadAttributions,
) -> Result<AttributionReadBounds> {
    const TOOL: &str = "read_attributions";
    // Aggregate counts run before any evidence rows are materialized. They
    // bound the projection work and the nested evidence in the raw page.
    let projection = crate::attribution::interpretation_evidence_bounds_for_bearer_in(
        tx,
        &request.bearer_id,
        request.as_of_event_seq,
    )
    .await?;
    let explanation = if let Some(annotation_id) = &request.explain_annotation_id {
        Some(
            crate::attribution::interpretation_evidence_bounds_for_claim_in(
                tx,
                annotation_id,
                &request.bearer_id,
                request.as_of_event_seq,
            )
            .await?
            .ok_or_else(|| not_found(TOOL, annotation_id))?,
        )
    } else {
        None
    };
    Ok(AttributionReadBounds {
        projection,
        explanation,
    })
}

async fn read_projection_stage_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    request: &ValidatedReadAttributions,
    count: i64,
    bounds: InterpretationEvidenceBounds,
) -> Result<ProjectionReadStage> {
    let limitation = if count > crate::interpretation::MAX_INTERPRETATION_CLAIMS {
        Some("claim_set_exceeds_bounded_projection_limit")
    } else {
        projection_evidence_limitation(bounds)
    };
    let attributions = if limitation.is_none() {
        crate::attribution::read_window_in(
            tx,
            &request.bearer_id,
            crate::interpretation::MAX_INTERPRETATION_CLAIMS,
            0,
            request.as_of_event_seq,
        )
        .await?
        .1
    } else {
        Vec::new()
    };
    Ok(ProjectionReadStage {
        limitation,
        attributions,
    })
}

async fn read_explanation_stage_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    request: &ValidatedReadAttributions,
    bounds: &AttributionReadBounds,
    projection: &ProjectionReadStage,
) -> Result<ExplanationReadStage> {
    const TOOL: &str = "read_attributions";
    let limitation = bounds.explanation.and_then(|explanation| {
        explanation_evidence_limitation(explanation, bounds.projection, projection.available())
    });
    let available = limitation.is_none();
    let attribution = if let Some(annotation_id) = &request.explain_annotation_id {
        let mut attribution = if projection.available() {
            projection
                .attributions
                .iter()
                .find(|attribution| attribution.annotation_id == *annotation_id)
                .cloned()
                .ok_or_else(|| not_found(TOOL, annotation_id))?
        } else if available {
            crate::attribution::read_one_in(tx, annotation_id, request.as_of_event_seq)
                .await?
                .ok_or_else(|| not_found(TOOL, annotation_id))?
        } else {
            crate::attribution::read_one_without_evidence_in(
                tx,
                annotation_id,
                request.as_of_event_seq,
            )
            .await?
            .ok_or_else(|| not_found(TOOL, annotation_id))?
        };
        if !available {
            attribution.evidence.clear();
            attribution.evidence_complete = false;
        }
        Some(attribution)
    } else {
        None
    };
    Ok(ExplanationReadStage {
        limitation,
        attribution,
    })
}

fn attribution_inspection_inputs(
    projection: &ProjectionReadStage,
    explanation: &ExplanationReadStage,
) -> Vec<AttributionView> {
    let mut inputs = projection.attributions.clone();
    if explanation.available() {
        if let Some(explanation) = &explanation.attribution {
            if !inputs
                .iter()
                .any(|attribution| attribution.annotation_id == explanation.annotation_id)
            {
                inputs.push(explanation.clone());
            }
        }
    }
    inputs
}

async fn filter_raw_attribution_evidence_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    attributions: &mut [AttributionView],
) -> Result<()> {
    for attribution in attributions {
        let stored_evidence_count = attribution.evidence_count;
        let mut visible = Vec::with_capacity(attribution.evidence.len());
        for item in std::mem::take(&mut attribution.evidence) {
            if attribution_evidence_visible_in(
                tx,
                caller,
                &item.action_attestation_id,
                None,
                &attribution.annotation_id,
            )
            .await?
            {
                visible.push(item);
            }
        }
        // Raw evidence metadata is disclosure-scoped too. Never expose the
        // stored cardinality when evidence is withheld, and never call a
        // filtered or truncated page complete.
        attribution.evidence_complete =
            attribution.evidence_complete && visible.len() as i64 == stored_evidence_count;
        attribution.evidence_count = visible.len() as i64;
        attribution.evidence = visible;
    }
    Ok(())
}

async fn read_attribution_snapshot(
    db: Db,
    caller: &Caller,
    request: &ValidatedReadAttributions,
) -> Result<AttributionReadSnapshot> {
    let mut tx = db.write_pool().begin().await?;
    if let Err(error) = authorize_attribution_read_in(&mut tx, caller, request).await {
        tx.rollback().await?;
        return Err(error);
    }
    let bounds = read_attribution_bounds_in(&mut tx, request).await?;
    let (count, mut attributions) = crate::attribution::read_window_in(
        &mut tx,
        &request.bearer_id,
        request.limit,
        request.offset,
        request.as_of_event_seq,
    )
    .await?;
    let projection = read_projection_stage_in(&mut tx, request, count, bounds.projection).await?;
    let explanation = read_explanation_stage_in(&mut tx, request, &bounds, &projection).await?;
    let inspection_inputs = attribution_inspection_inputs(&projection, &explanation);
    // Claims, lifecycle state, current target validation and current
    // provenance validity/authority are read through one SQLite snapshot.
    // Historical content is filtered by as_of_event_seq, while present-day
    // invalidation remains authoritative and cannot be time-travelled away.
    let inspections = inspect_attribution_evidence_in(
        &mut tx,
        caller,
        &inspection_inputs,
        request
            .explain_annotation_id
            .as_deref()
            .filter(|_| explanation.available()),
    )
    .await?;
    filter_raw_attribution_evidence_in(&mut tx, caller, &mut attributions).await?;
    tx.rollback().await?;
    Ok(AttributionReadSnapshot {
        count,
        attributions,
        projection,
        explanation,
        inspection_inputs,
        inspections,
    })
}

fn render_attribution_snapshot(
    request: ValidatedReadAttributions,
    snapshot: AttributionReadSnapshot,
) -> Value {
    let inspected_evidence = snapshot
        .inspection_inputs
        .iter()
        .flat_map(|attribution| {
            crate::interpretation::inspected_evidence(attribution, &snapshot.inspections)
        })
        .collect::<Vec<_>>();
    let interpretation = if snapshot.projection.available() {
        crate::interpretation::project(
            &request.bearer_id,
            request.as_of_event_seq,
            snapshot.count,
            &snapshot.projection.attributions,
            &inspected_evidence,
        )
    } else {
        crate::interpretation::evidence_bounded_unavailable(
            &request.bearer_id,
            request.as_of_event_seq,
            snapshot.count,
            snapshot
                .projection
                .limitation
                .unwrap_or("bounded_projection_unavailable"),
        )
    };
    let explanation = snapshot
        .explanation
        .attribution
        .as_ref()
        .map(|attribution| {
            let authoring_attestation = attribution
                .assertion
                .action_attestation_id
                .as_ref()
                .and_then(|id| snapshot.inspections.get(id))
                .cloned()
                .flatten();
            let explanation_inspections = if snapshot.explanation.available() {
                inspected_evidence.as_slice()
            } else {
                &[]
            };
            let mut explanation = crate::interpretation::explain(
                attribution,
                explanation_inspections,
                authoring_attestation,
                snapshot.explanation.available(),
            );
            if let Some(limitation) = snapshot.explanation.limitation {
                explanation.limitations.push(limitation.into());
            }
            explanation
        });
    json!({
        "bearer_id": request.bearer_id,
        "attribution_count": snapshot.count,
        "attributions": snapshot.attributions,
        "interpretation": interpretation,
        "explanation": explanation,
        "limit": request.limit,
        "offset": request.offset,
        "as_of_event_seq": request.as_of_event_seq,
    })
}

async fn read_attributions(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let request = validated_read_attributions(arguments)?;
    let snapshot = read_attribution_snapshot(db, &caller, &request).await?;
    Ok(render_attribution_snapshot(request, snapshot))
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum ManageAttributionsArgs {
    Retract {
        annotation_id: String,
        reason: String,
    },
    AddEvidence {
        annotation_id: String,
        evidence: EvidenceInput,
    },
}

async fn manage_attributions(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "manage_attributions";
    let args: ManageAttributionsArgs = parse_args(TOOL, arguments)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let (annotation_id, event_type, payload, action) = match args {
        ManageAttributionsArgs::Retract {
            annotation_id,
            reason,
        } => {
            if reason.trim().is_empty() {
                return Err(Error::engine(format!("{TOOL}: reason must not be blank")));
            }
            let bearer = attribution_bearer_in(&mut tx, &annotation_id)
                .await?
                .ok_or_else(|| not_found(TOOL, &annotation_id))?;
            require_record_in(&mut tx, &caller, TOOL, &bearer, Capability::Edit)
                .await
                .map_err(|_| not_found(TOOL, &annotation_id))?;
            let already: i64 = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM attribution_retractions WHERE annotation_id=?)",
            )
            .bind(&annotation_id)
            .fetch_one(&mut *tx)
            .await?;
            if already != 0 {
                return Err(Error::engine(format!(
                    "{TOOL}: attribution is already retracted"
                )));
            }
            (
                annotation_id,
                "attribution.retracted.v1",
                serde_json::to_value(AttributionRetractedPayload {
                    retraction_id: Uuid::new_v4().to_string(),
                    reason,
                })?,
                "retracted",
            )
        }
        ManageAttributionsArgs::AddEvidence {
            annotation_id,
            evidence,
        } => {
            let bearer = attribution_bearer_in(&mut tx, &annotation_id)
                .await?
                .ok_or_else(|| not_found(TOOL, &annotation_id))?;
            require_record_in(&mut tx, &caller, TOOL, &bearer, Capability::Edit)
                .await
                .map_err(|_| not_found(TOOL, &annotation_id))?;
            if evidence.role == EvidenceRole::ExactTargetConfirmation {
                return Err(Error::engine(format!(
                    "{TOOL}: exact_target_confirmation is internal to the accepted direct-declaration action"
                )));
            }
            if !attribution_evidence_visible_in(
                &mut tx,
                &caller,
                &evidence.action_attestation_id,
                None,
                &annotation_id,
            )
            .await?
            {
                return Err(Error::engine(format!("{TOOL}: evidence does not exist")));
            }
            (
                annotation_id,
                "attribution.evidence.added.v1",
                serde_json::to_value(AttributionEvidenceAddedPayload {
                    evidence_id: Uuid::new_v4().to_string(),
                    role: evidence.role.as_str().into(),
                    action_attestation_id: evidence.action_attestation_id,
                })?,
                "evidence_added",
            )
        }
    };
    append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: annotation_id.clone(),
            event_type: event_type.into(),
            payload,
            actor: Some(caller.actor().into()),
        },
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(json!({ "annotation_id": annotation_id, "action": action }))
}

pub fn register_attribution_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::CreateAttribution,
        "Atomically create one governed Annotation kind:attribution over an exact body revision or passage. Native derives declaration versus assessment from trusted ingress, keeps claimant/executor/subject/evidence distinct, and never infers endorsement from delegation.",
        json!({
            "type":"object",
            "properties":{
                "id":{"type":"string"},
                "idempotency_key":{"type":"string","minLength":1},
                "bearer_id":{"type":"string"},
                "target":{
                    "type":"object",
                    "properties":{
                        "source_event_id":{"type":"string"},
                        "source_body_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                        "scope":{"type":"string","enum":["whole_revision","passage"]},
                        "selectors":{"type":"array","items":super::citations::target_schema()["properties"]["selectors"]["items"].clone()}
                    },
                    "required":["source_event_id","source_body_sha256","scope"],
                    "additionalProperties":false
                },
                "subject":{"oneOf":[
                    {"type":"object","properties":{"kind":{"const":"self_person"}},"required":["kind"],"additionalProperties":false},
                    {"type":"object","properties":{"kind":{"const":"self_agent_execution"}},"required":["kind"],"additionalProperties":false},
                    {"type":"object","properties":{"kind":{"const":"person_record"},"record_id":{"type":"string"}},"required":["kind","record_id"],"additionalProperties":false},
                    {"type":"object","properties":{"kind":{"const":"agent_execution"},"action_attestation_id":{"type":"string"}},"required":["kind","action_attestation_id"],"additionalProperties":false}
                ]},
                "relation":{"type":"string","enum":["expresses_view","endorses"]},
                "polarity":{"type":"string","enum":["affirmed","denied"]},
                "stance_as_of":{"type":"string","format":"date-time"},
                "confidence":{"type":"string","enum":["tentative","plausible","likely","confident"]},
                "transformation":{"type":"string","enum":["none","selection","paraphrase","summary","synthesis"]},
                "rationale":{"type":"string","minLength":1},
                "evidence":{"type":"array","items":{"type":"object","properties":{
                    "role":{"type":"string","enum":["basis","counterevidence"]},
                    "action_attestation_id":{"type":"string"}
                },"required":["role","action_attestation_id"],"additionalProperties":false}},
                "successor_of":{"type":"string"}
            },
            "required":["idempotency_key","bearer_id","target","subject","relation","polarity","transformation","rationale"],
            "additionalProperties":false
        }),
        create_attribution,
    )?;
    registry.register(
        ToolKind::ReadAttributions,
        "Read a bounded dedicated attribution window, a conservative derived interpretation, and optionally one authorized claim-specific evidence explanation. Delegation, confidence, and claim counts never become endorsement or consensus.",
        json!({
            "type":"object",
            "properties":{"bearer_id":{"type":"string"},"limit":{"type":"integer","minimum":0,"maximum":100},"offset":{"type":"integer","minimum":0},"as_of_event_seq":{"type":"integer","minimum":1},"explain_annotation_id":{"type":"string"}},
            "required":["bearer_id"],"additionalProperties":false
        }),
        read_attributions,
    )?;
    registry.register(
        ToolKind::ManageAttributions,
        "Append lifecycle facts to an attribution: retract an erroneous assertion or add later Native-issued action-attestation evidence. Assertions and targets are immutable; changed stance creates a new claim.",
        json!({
            "type":"object",
            "properties":{
                "action":{"type":"string","enum":["retract","add_evidence"]},
                "annotation_id":{"type":"string"},
                "reason":{"type":"string","minLength":1},
                "evidence":{"type":"object","properties":{
                    "role":{"type":"string","enum":["basis","counterevidence"]},
                    "action_attestation_id":{"type":"string"}
                },"required":["role","action_attestation_id"],"additionalProperties":false}
            },
            "required":["action","annotation_id"],"additionalProperties":false
        }),
        manage_attributions,
    )?;
    Ok(())
}

#[cfg(test)]
mod generic_snapshot_tests {
    use std::sync::Arc;

    use serde_json::json;
    use sha2::{Digest, Sha256};
    use sqlx::Row;

    use super::*;

    async fn call(
        registry: &ToolRegistry,
        db: &Db,
        caller: Caller,
        tool: &str,
        arguments: Value,
    ) -> Value {
        registry
            .call(db.clone(), caller, tool, arguments)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn generic_projection_remains_on_the_authorized_base_snapshot() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let registry = Arc::new(registry);
        let bearer = call(
            &registry,
            &db,
            Caller::local(),
            "create_record",
            json!({
                "id":"a77b0000-0000-4000-8000-000000000001","type":"Document","kind":"note",
                "name":"Projection snapshot","body":"before","reason":"test setup"
            }),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_string();
        let source = sqlx::query(
            "SELECT e.id,r.body FROM records r JOIN content_events e ON e.record_id=r.id \
              WHERE r.id=? AND e.type='record.created'",
        )
        .bind(&bearer)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let source_event_id: String = source.try_get("id").unwrap();
        let source_body: String = source
            .try_get::<Option<String>, _>("body")
            .unwrap()
            .unwrap();
        let issuer = crate::awareness::HumanInteractionTokenIssuer::random("snapshot-agent");
        let ids = vec![bearer.clone()];
        let token = issuer
            .issue(
                "local",
                "agent-executor:snapshot-agent:snapshot-delegation",
                &ids,
                60,
            )
            .unwrap();
        let agent = Caller::local()
            .with_agent_executor_token(
                &issuer,
                &token,
                "snapshot-agent",
                "snapshot-delegation",
                &ids,
            )
            .unwrap();
        call(
            &registry,
            &db,
            agent,
            "create_attribution",
            json!({
                "idempotency_key":"projection-snapshot-attribution",
                "bearer_id":bearer,
                "target":{
                    "source_event_id":source_event_id,
                    "source_body_sha256":hex::encode(Sha256::digest(source_body.as_bytes())),
                    "scope":"whole_revision","selectors":[]
                },
                "subject":{"kind":"self_agent_execution"},
                "relation":"expresses_view","polarity":"affirmed","confidence":"likely",
                "transformation":"summary","rationale":"snapshot regression"
            }),
        )
        .await;

        let mut snapshot = db.write_pool().begin().await.unwrap();
        require_record_in(
            &mut snapshot,
            &Caller::local(),
            "snapshot test",
            &bearer,
            Capability::View,
        )
        .await
        .unwrap();
        let _: String = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
            .bind(&bearer)
            .fetch_one(&mut *snapshot)
            .await
            .unwrap();
        let writer_db = db.clone();
        let writer_registry = registry.clone();
        let writer_bearer = bearer.clone();
        tokio::spawn(async move {
            writer_registry
                .call(
                    writer_db,
                    Caller::local(),
                    "update_record",
                    json!({
                        "id": writer_bearer,
                        "body": "after",
                        "if_body_digest": hex::encode(sha2::Sha256::digest(b"before")),
                        "reason": "snapshot race"
                    }),
                )
                .await
                .unwrap();
        })
        .await
        .unwrap();
        let projection = project_generic_interpretations_in(
            &mut snapshot,
            &Caller::local(),
            authorized_render_interpretation_bearer(&bearer),
        )
        .await
        .unwrap()
        .remove(&bearer)
        .unwrap();
        assert_eq!(
            serde_json::to_value(&projection).unwrap()["groups"][0]["target"]["state"],
            "current"
        );
        snapshot.rollback().await.unwrap();

        let current = call(
            &registry,
            &db,
            Caller::local(),
            "get_record",
            json!({"ids":[bearer],"resolve":false,"include_interpretation":true}),
        )
        .await;
        assert_ne!(
            current["records"][0]["interpretation"]["groups"][0]["target"]["state"],
            "current"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn fabricated_unentitled_window_cannot_reach_provenance_integrity() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let registry = Arc::new(registry);
        let bearer = call(
            &registry,
            &db,
            Caller::local(),
            "create_record",
            json!({
                "id":"a77b0000-0000-4000-8000-000000000002","type":"Document","kind":"note",
                "name":"Fabricated window","body":"hidden","reason":"test setup"
            }),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_string();
        crate::authorization::replace_explicit_policy(
            &db,
            "test:projection-window",
            &bearer,
            vec![],
        )
        .await
        .unwrap();

        sqlx::query("DROP TRIGGER provenance_action_attestations_no_update")
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query(
            "UPDATE provenance_action_attestations SET action_digest=printf('%064d',0) \
              WHERE id=(SELECT id FROM provenance_action_attestations ORDER BY id LIMIT 1)",
        )
        .execute(db.write_pool())
        .await
        .unwrap();

        let mut snapshot = db.write_pool().begin().await.unwrap();
        let error = project_generic_interpretations_in(
            &mut snapshot,
            &Caller::authenticated("unentitled-caller"),
            authorized_render_interpretation_bearer(&bearer),
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "interpretation projection authorization window is invalid"
        );
        snapshot.rollback().await.unwrap();
        db.close().await;
    }

    #[tokio::test]
    async fn inspection_output_overflow_stops_before_identifier_materialization() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let registry = Arc::new(registry);
        let bearer = call(
            &registry,
            &db,
            Caller::local(),
            "create_record",
            json!({
                "id":"a77b0000-0000-4000-8000-000000000003","type":"Document","kind":"note",
                "name":"Output overflow","body":"bounded","reason":"test setup"
            }),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_string();
        let source = sqlx::query(
            "SELECT e.id,r.body FROM records r JOIN content_events e ON e.record_id=r.id \
              WHERE r.id=? AND e.type='record.created'",
        )
        .bind(&bearer)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let source_event_id: String = source.try_get("id").unwrap();
        let source_body: String = source
            .try_get::<Option<String>, _>("body")
            .unwrap()
            .unwrap();

        let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
            &Caller::local(),
            "output_overflow_fixture",
            &json!({}),
            None,
        );
        let output_count = crate::interpretation::MAX_INTERPRETATION_OUTPUT_RECORDS + 1;
        let specs = (0..output_count)
            .map(|ordinal| crate::store::AppendSpec {
                record_id: format!("a77b0001-0000-4000-8000-{ordinal:012}"),
                event_type: "record.created".into(),
                payload: json!({
                    "type":"Document","kind":"note","name":format!("Output {ordinal}"),
                    "home_id":crate::schema::ROOT_RECORD_ID
                }),
                actor: Some("test:output-overflow".into()),
            })
            .collect();
        dispatch
            .scope(crate::store::append_batch(&db, specs))
            .await
            .unwrap();
        let evidence_attestation_id = dispatch.receipt_ids().pop().unwrap();

        let issuer = crate::awareness::HumanInteractionTokenIssuer::random("overflow-agent");
        let ids = vec![bearer.clone()];
        let token = issuer
            .issue(
                "local",
                "agent-executor:overflow-agent:overflow-delegation",
                &ids,
                60,
            )
            .unwrap();
        let agent = Caller::local()
            .with_agent_executor_token(
                &issuer,
                &token,
                "overflow-agent",
                "overflow-delegation",
                &ids,
            )
            .unwrap();
        let created = call(
            &registry,
            &db,
            agent,
            "create_attribution",
            json!({
                "idempotency_key":"output-overflow-attribution",
                "bearer_id":bearer,
                "target":{
                    "source_event_id":source_event_id,
                    "source_body_sha256":hex::encode(Sha256::digest(source_body.as_bytes())),
                    "scope":"whole_revision","selectors":[]
                },
                "subject":{"kind":"self_agent_execution"},
                "relation":"expresses_view","polarity":"affirmed","confidence":"likely",
                "transformation":"summary","rationale":"output overflow regression",
                "evidence":[{
                    "role":"basis","action_attestation_id":evidence_attestation_id
                }]
            }),
        )
        .await;
        let annotation_id = created["annotation_id"].as_str().unwrap().to_string();

        let generic = call(
            &registry,
            &db,
            Caller::local(),
            "get_record",
            json!({"ids":[bearer],"resolve":false,"include_interpretation":true}),
        )
        .await;
        let projection = &generic["records"][0]["interpretation"];
        assert!(projection["attribution_count"].is_null());
        assert_eq!(projection["complete"], false);
        assert!(projection["groups"].as_array().unwrap().is_empty());
        assert!(projection["limitations"]
            .as_array()
            .unwrap()
            .contains(&json!(
                "request_inspection_output_set_exceeds_bounded_projection_limit"
            )));
        let serialized = serde_json::to_string(projection).unwrap();
        assert!(!serialized.contains(&annotation_id));
        assert!(!serialized.contains(&evidence_attestation_id));
        db.close().await;
    }
}
