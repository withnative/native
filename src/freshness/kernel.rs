//! SQLite implementation of the backend-neutral freshness kernel contract.

use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{Row, SqliteConnection};
use uuid::Uuid;

use crate::authorization::{
    authorization_target_on, effective_policy_entries_on, replace_explicit_policy_on,
    require_capability_on, Capability, Principal,
};
use crate::db::{begin_write, Db};
use crate::error::{Error, Result};
use crate::events::{
    EventRow, OccurrenceBoundPayload, SemanticCommandFinalization, UnitCreatedPayload,
    UnitRevisionRecordedPayload,
};
use crate::store::{append_in, AppendSpec};

use super::domain::*;

pub(crate) fn canonicalize_occurrence_selectors(
    selectors: Vec<OccurrenceSelector>,
    bytes: &[u8],
) -> Result<Vec<OccurrenceSelector>> {
    let mut selectors = crate::citations::canonicalize_selectors(selectors, bytes)?;
    selectors.sort_by_cached_key(|selector| {
        serde_json::to_string(selector).expect("Occurrence selectors always serialize")
    });
    if selectors.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Error::engine(
            "Occurrence capture must not repeat an identical selector",
        ));
    }
    Ok(selectors)
}

#[derive(Debug, Clone)]
struct CommandResultRow {
    result_event_id: String,
    event_seq: i64,
    authorization_revision_observed: i64,
}

fn require_actor(actor: &str) -> Result<()> {
    if actor.trim().is_empty() {
        Err(Error::engine("freshness command actor must not be blank"))
    } else {
        Ok(())
    }
}

fn command_finalization(
    operation: &str,
    scope_record_id: &str,
    key: &IdempotencyKey,
    intent_sha256: String,
    authorization_revision_observed: i64,
) -> SemanticCommandFinalization {
    SemanticCommandFinalization {
        operation: operation.into(),
        scope_record_id: scope_record_id.into(),
        idempotency_key: key.as_str().into(),
        intent_sha256,
        authorization_revision_observed,
    }
}

async fn prior_command(
    conn: &mut SqliteConnection,
    scope_record_id: &str,
    key: &IdempotencyKey,
    operation: &str,
    expected_intent_sha256: &str,
) -> Result<Option<CommandResultRow>> {
    let row = sqlx::query(
        "SELECT operation,intent_sha256,result_event_id,event_seq,
                authorization_revision_observed
           FROM freshness_command_results
          WHERE scope_record_id=? AND idempotency_key=?",
    )
    .bind(scope_record_id)
    .bind(key.as_str())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let stored_operation: String = row.try_get("operation")?;
    let stored_intent: String = row.try_get("intent_sha256")?;
    if stored_operation != operation || stored_intent != expected_intent_sha256 {
        return Err(Error::engine(format!(
            "idempotency key '{}' was already used for a different freshness command",
            key.as_str()
        )));
    }
    Ok(Some(CommandResultRow {
        result_event_id: row.try_get("result_event_id")?,
        event_seq: row.try_get("event_seq")?,
        authorization_revision_observed: row.try_get("authorization_revision_observed")?,
    }))
}

fn high_water(row: &CommandResultRow) -> HistoryHighWater {
    HistoryHighWater {
        content_seq: row.event_seq,
        authorization_revision_observed: row.authorization_revision_observed,
        semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
    }
}

fn revision_ref_from_unit_event(event: &EventRow, content_sha256: String) -> RevisionRef {
    RevisionRef {
        subject_kind: RevisionSubjectKind::Unit,
        subject_id: event.record_id.clone(),
        revision_event_id: event.id.clone(),
        revision_seq: event.local_seq,
        source_slot: RevisionSourceSlot::UnitContent,
        sha256: content_sha256,
    }
}

fn body_from_record_event(event_type: &str, payload: &str) -> Result<Vec<u8>> {
    if !matches!(
        event_type,
        "record.created" | "record.updated" | "receipt.committed.v1"
    ) {
        return Err(Error::engine(
            "artefact body RevisionRef must identify a body-bearing record event",
        ));
    }
    let payload: Value = serde_json::from_str(payload)?;
    let body = payload
        .as_object()
        .and_then(|object| object.get("body"))
        .ok_or_else(|| Error::engine("record event is not body-bearing"))?;
    match body {
        Value::Null => Ok(Vec::new()),
        Value::String(body) => Ok(body.as_bytes().to_vec()),
        _ => Err(Error::engine(
            "record body event contains a non-string body",
        )),
    }
}

/// Verify all coordinates of an exact reference and return its canonical bytes.
/// The projector calls the same function, so raw event appends cannot bypass the
/// command-layer verification.
pub(crate) async fn verify_revision_ref_on(
    conn: &mut SqliteConnection,
    reference: &RevisionRef,
) -> Result<Vec<u8>> {
    reference.validate()?;
    let row = sqlx::query("SELECT seq,id,record_id,type,payload FROM content_events WHERE id=?")
        .bind(&reference.revision_event_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| Error::engine("exact revision event is unavailable"))?;
    let seq: i64 = row.try_get("seq")?;
    let record_id: String = row.try_get("record_id")?;
    if seq != reference.revision_seq || record_id != reference.subject_id {
        return Err(Error::engine("exact revision identity does not verify"));
    }
    let event_type: String = row.try_get("type")?;
    let payload: String = row
        .try_get::<Option<String>, _>("payload")?
        .ok_or_else(|| Error::engine("exact revision event has no payload"))?;
    let bytes = match (reference.subject_kind, reference.source_slot) {
        (RevisionSubjectKind::Unit, RevisionSourceSlot::UnitContent) => {
            if event_type != "unit.revision.recorded.v1" {
                return Err(Error::engine(
                    "Unit RevisionRef does not identify unit.revision.recorded.v1",
                ));
            }
            let payload: UnitRevisionRecordedPayload = serde_json::from_str(&payload)?;
            if payload.format != UNIT_REVISION_FORMAT
                || payload.semantic_contract_version != SEMANTIC_CONTRACT_VERSION
                || payload.content.sha256() != payload.content_sha256
            {
                return Err(Error::engine("Unit revision payload does not verify"));
            }
            payload.content.canonical_bytes()
        }
        (RevisionSubjectKind::Artefact, RevisionSourceSlot::RecordBody) => {
            body_from_record_event(&event_type, &payload)?
        }
        (RevisionSubjectKind::Artefact, RevisionSourceSlot::Blob) => {
            return Err(Error::engine(
                "blob RevisionRefs are reserved but not implemented by the v1 kernel",
            ));
        }
        _ => return Err(Error::engine("revision subject and slot do not agree")),
    };
    if sha256(&bytes) != reference.sha256 {
        return Err(Error::engine("exact revision digest does not verify"));
    }
    Ok(bytes)
}

pub(crate) async fn body_revision_from_event_on(
    conn: &mut SqliteConnection,
    record_id: &str,
    event_id: &str,
) -> Result<RevisionRef> {
    let row = sqlx::query("SELECT seq,type,payload FROM content_events WHERE id=? AND record_id=?")
        .bind(event_id)
        .bind(record_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| Error::engine("body revision event not found"))?;
    let event_type: String = row.try_get("type")?;
    let payload: String = row
        .try_get::<Option<String>, _>("payload")?
        .ok_or_else(|| Error::engine("body revision event has no payload"))?;
    let bytes = body_from_record_event(&event_type, &payload)?;
    Ok(RevisionRef {
        subject_kind: RevisionSubjectKind::Artefact,
        subject_id: record_id.into(),
        revision_event_id: event_id.into(),
        revision_seq: row.try_get("seq")?,
        source_slot: RevisionSourceSlot::RecordBody,
        sha256: sha256(&bytes),
    })
}

pub(crate) async fn current_body_revision_on(
    conn: &mut SqliteConnection,
    record_id: &str,
) -> Result<Option<(RevisionRef, Vec<u8>)>> {
    let live: Option<Option<String>> =
        sqlx::query_scalar("SELECT deleted_at FROM records WHERE id=?")
            .bind(record_id)
            .fetch_optional(&mut *conn)
            .await?;
    if !matches!(live, Some(None)) {
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT id,seq,type,payload FROM content_events
          WHERE record_id=? AND type IN ('record.created','record.updated','receipt.committed.v1')
            AND json_type(payload,'$.body') IS NOT NULL
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(record_id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let event_id: String = row.try_get("id")?;
    let event_type: String = row.try_get("type")?;
    let payload: String = row.try_get("payload")?;
    let bytes = body_from_record_event(&event_type, &payload)?;
    Ok(Some((
        RevisionRef {
            subject_kind: RevisionSubjectKind::Artefact,
            subject_id: record_id.into(),
            revision_event_id: event_id,
            revision_seq: row.try_get("seq")?,
            source_slot: RevisionSourceSlot::RecordBody,
            sha256: sha256(&bytes),
        },
        bytes,
    )))
}

pub async fn record_body_revision(db: &Db, record_id: &str, event_id: &str) -> Result<RevisionRef> {
    let mut conn = db.pool().acquire().await?;
    body_revision_from_event_on(&mut conn, record_id, event_id).await
}

pub async fn current_record_body_revision(db: &Db, record_id: &str) -> Result<RevisionRef> {
    let mut conn = db.pool().acquire().await?;
    current_body_revision_on(&mut conn, record_id)
        .await?
        .map(|(reference, _)| reference)
        .ok_or_else(|| Error::engine("record has no current body-bearing revision"))
}

pub(crate) async fn unit_bearer_on(conn: &mut SqliteConnection, unit_id: &str) -> Result<String> {
    sqlx::query_scalar("SELECT authority_bearer_record_id FROM semantic_units WHERE unit_id=?")
        .bind(unit_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| Error::engine("Unit not found"))
}

pub(crate) async fn authorization_revision_on(conn: &mut SqliteConnection) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT epoch FROM authorization_revision WHERE id=1")
            .fetch_one(&mut *conn)
            .await?,
    )
}

async fn load_unit_revision_on(
    conn: &mut SqliteConnection,
    event_id: &str,
) -> Result<UnitRevisionView> {
    let row = sqlx::query(
        "SELECT r.unit_id,r.revision_seq,r.based_on_revision_event_id,r.content_sha256,
                r.rationale,r.actor,r.created_at,e.payload
           FROM unit_revisions r JOIN content_events e ON e.id=r.revision_event_id
          WHERE r.revision_event_id=?",
    )
    .bind(event_id)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| Error::engine("Unit revision not found"))?;
    let payload: UnitRevisionRecordedPayload =
        serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
    Ok(UnitRevisionView {
        revision: RevisionRef {
            subject_kind: RevisionSubjectKind::Unit,
            subject_id: row.try_get("unit_id")?,
            revision_event_id: event_id.into(),
            revision_seq: row.try_get("revision_seq")?,
            source_slot: RevisionSourceSlot::UnitContent,
            sha256: row.try_get("content_sha256")?,
        },
        content: payload.content,
        based_on_revision_event_id: row.try_get("based_on_revision_event_id")?,
        rationale: row.try_get("rationale")?,
        actor: row.try_get("actor")?,
        created_at: row.try_get("created_at")?,
    })
}

pub(crate) async fn load_occurrence_on(
    conn: &mut SqliteConnection,
    occurrence_id: &str,
) -> Result<OccurrenceView> {
    let row = sqlx::query(
        "SELECT o.occurrence_id,o.unit_revision_event_id,o.artefact_id,
                o.artefact_revision_event_id,o.artefact_revision_seq,o.artefact_sha256,
                o.selectors,o.expression_role,o.actor,o.created_at,
                u.unit_id,u.revision_seq,u.content_sha256
           FROM occurrences o
           JOIN unit_revisions u ON u.revision_event_id=o.unit_revision_event_id
          WHERE o.occurrence_id=?",
    )
    .bind(occurrence_id)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| Error::engine("Occurrence not found"))?;
    let role = match row.try_get::<String, _>("expression_role")?.as_str() {
        "canonical" => ExpressionRole::Canonical,
        "paraphrase" => ExpressionRole::Paraphrase,
        "summary" => ExpressionRole::Summary,
        "quotation" => ExpressionRole::Quotation,
        _ => return Err(Error::engine("Occurrence has an invalid expression role")),
    };
    Ok(OccurrenceView {
        occurrence_id: OccurrenceId::new(row.try_get::<String, _>("occurrence_id")?)?,
        unit_revision: RevisionRef {
            subject_kind: RevisionSubjectKind::Unit,
            subject_id: row.try_get("unit_id")?,
            revision_event_id: row.try_get("unit_revision_event_id")?,
            revision_seq: row.try_get("revision_seq")?,
            source_slot: RevisionSourceSlot::UnitContent,
            sha256: row.try_get("content_sha256")?,
        },
        artefact_revision: RevisionRef {
            subject_kind: RevisionSubjectKind::Artefact,
            subject_id: row.try_get("artefact_id")?,
            revision_event_id: row.try_get("artefact_revision_event_id")?,
            revision_seq: row.try_get("artefact_revision_seq")?,
            source_slot: RevisionSourceSlot::RecordBody,
            sha256: row.try_get("artefact_sha256")?,
        },
        selectors: serde_json::from_str(&row.try_get::<String, _>("selectors")?)?,
        expression_role: role,
        actor: row.try_get("actor")?,
        created_at: row.try_get("created_at")?,
    })
}

fn event_spec<T: Serialize>(
    record_id: impl Into<String>,
    event_type: &str,
    payload: &T,
    actor: &str,
) -> Result<AppendSpec> {
    Ok(AppendSpec {
        record_id: record_id.into(),
        event_type: event_type.into(),
        payload: serde_json::to_value(payload)?,
        actor: Some(actor.into()),
    })
}

pub async fn promote_idea(
    db: &Db,
    principal: Principal<'_>,
    actor: &str,
    mut input: PromoteIdeaInput,
) -> Result<PromoteIdeaResult> {
    require_actor(actor)?;
    input.source_revision.validate()?;
    input.first_content.validate()?;
    if let Some(unit_id) = &input.requested_unit_id {
        unit_id.validate()?;
    }
    if let Some(occurrence_id) = &input.requested_occurrence_id {
        occurrence_id.validate()?;
    }
    input.idempotency_key.validate()?;
    if input.source_revision.subject_kind != RevisionSubjectKind::Artefact
        || input.source_revision.source_slot != RevisionSourceSlot::RecordBody
        || input.selectors.is_empty()
        || input
            .label
            .as_deref()
            .is_some_and(|label| label.trim().is_empty())
    {
        return Err(Error::engine("invalid idea promotion input"));
    }
    let mut tx = begin_write(db.write_pool()).await?;
    // Authorize the command subject before consulting its idempotency
    // namespace. A denied caller must not be able to probe key occupancy.
    require_capability_on(
        &mut tx,
        principal,
        &input.source_revision.subject_id,
        Capability::Edit,
    )
    .await?;
    let anchored = verify_revision_ref_on(&mut tx, &input.source_revision).await?;
    input.selectors = canonicalize_occurrence_selectors(input.selectors, &anchored)?;
    let intent = intent_sha256(&input)?;
    if let Some(prior) = prior_command(
        &mut tx,
        &input.source_revision.subject_id,
        &input.idempotency_key,
        "promote_idea",
        &intent,
    )
    .await?
    {
        let occurrence_id: String =
            sqlx::query_scalar("SELECT occurrence_id FROM occurrences WHERE binding_event_id=?")
                .bind(&prior.result_event_id)
                .fetch_one(&mut *tx)
                .await?;
        let occurrence = load_occurrence_on(&mut tx, &occurrence_id).await?;
        require_capability_on(
            &mut tx,
            principal,
            &occurrence.unit_revision.subject_id,
            Capability::View,
        )
        .await?;
        require_capability_on(
            &mut tx,
            principal,
            &occurrence.artefact_revision.subject_id,
            Capability::View,
        )
        .await?;
        return Ok(PromoteIdeaResult {
            unit_id: UnitId::new(&occurrence.unit_revision.subject_id)?,
            first_revision: occurrence.unit_revision,
            occurrence_id: occurrence.occurrence_id,
            high_water: high_water(&prior),
        });
    }
    let source = sqlx::query("SELECT home_id,deleted_at FROM records WHERE id=?")
        .bind(&input.source_revision.subject_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| Error::engine("promotion source not found"))?;
    if source.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Err(Error::engine("promotion source not found"));
    }
    let home_id: String = source
        .try_get::<Option<String>, _>("home_id")?
        .ok_or_else(|| Error::engine("promotion source has no valid containing folder"))?;
    let policy_target = authorization_target_on(&mut tx, &input.source_revision.subject_id).await?;
    let owner_id: Option<String> =
        sqlx::query_scalar("SELECT owner_id FROM records WHERE id=? AND deleted_at IS NULL")
            .bind(&policy_target)
            .fetch_one(&mut *tx)
            .await?;
    let source_policy_entries =
        effective_policy_entries_on(&mut tx, &input.source_revision.subject_id).await?;
    let unit_id = input
        .requested_unit_id
        .clone()
        .unwrap_or(UnitId::new(Uuid::new_v4().to_string())?);
    let occurrence_id = input
        .requested_occurrence_id
        .clone()
        .unwrap_or(OccurrenceId::new(Uuid::new_v4().to_string())?);
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: unit_id.as_str().into(),
            event_type: "record.created".into(),
            payload: json!({
                "type": "Entity",
                "kind": "semantic-unit",
                "name": input.label.clone().unwrap_or_default(),
                "home_id": home_id,
                "owner_id": owner_id,
                "persistence": "enduring"
            }),
            actor: Some(actor.into()),
        },
    )
    .await?;
    replace_explicit_policy_on(&mut tx, actor, unit_id.as_str(), source_policy_entries).await?;
    append_in(
        db,
        &mut tx,
        event_spec(
            unit_id.as_str(),
            "unit.created.v1",
            &UnitCreatedPayload {
                semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
                authority_bearer_record_id: input.source_revision.subject_id.clone(),
                label: input.label.clone(),
            },
            actor,
        )?,
    )
    .await?;
    let content_sha256 = input.first_content.sha256();
    let revision_event = append_in(
        db,
        &mut tx,
        event_spec(
            unit_id.as_str(),
            "unit.revision.recorded.v1",
            &UnitRevisionRecordedPayload {
                format: UNIT_REVISION_FORMAT.into(),
                semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
                content: input.first_content,
                content_sha256: content_sha256.clone(),
                based_on_revision_event_id: None,
                rationale: None,
                command: None,
            },
            actor,
        )?,
    )
    .await?;
    let revision = revision_ref_from_unit_event(&revision_event, content_sha256);
    let auth_revision = authorization_revision_on(&mut tx).await?;
    let command = command_finalization(
        "promote_idea",
        &input.source_revision.subject_id,
        &input.idempotency_key,
        intent,
        auth_revision,
    );
    let occurrence_event = append_in(
        db,
        &mut tx,
        event_spec(
            unit_id.as_str(),
            "occurrence.bound.v1",
            &OccurrenceBoundPayload {
                semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
                occurrence_id: occurrence_id.clone(),
                unit_revision: revision.clone(),
                artefact_revision: input.source_revision,
                selectors: input.selectors,
                expression_role: input.expression_role.as_str().into(),
                command,
            },
            actor,
        )?,
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(PromoteIdeaResult {
        unit_id,
        first_revision: revision,
        occurrence_id,
        high_water: HistoryHighWater {
            content_seq: occurrence_event.local_seq,
            authorization_revision_observed: auth_revision,
            semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
        },
    })
}

pub async fn bind_occurrence(
    db: &Db,
    principal: Principal<'_>,
    actor: &str,
    mut input: BindOccurrenceInput,
) -> Result<BindOccurrenceResult> {
    require_actor(actor)?;
    input.unit_revision.validate()?;
    input.artefact_revision.validate()?;
    if let Some(occurrence_id) = &input.requested_occurrence_id {
        occurrence_id.validate()?;
    }
    input.idempotency_key.validate()?;
    if input.unit_revision.subject_kind != RevisionSubjectKind::Unit
        || input.artefact_revision.subject_kind != RevisionSubjectKind::Artefact
        || input.selectors.is_empty()
    {
        return Err(Error::engine("invalid Occurrence binding input"));
    }
    let mut tx = begin_write(db.write_pool()).await?;
    let bearer = unit_bearer_on(&mut tx, &input.unit_revision.subject_id).await?;
    for record_id in [
        input.unit_revision.subject_id.as_str(),
        bearer.as_str(),
        input.artefact_revision.subject_id.as_str(),
    ] {
        require_capability_on(&mut tx, principal, record_id, Capability::Edit).await?;
    }
    verify_revision_ref_on(&mut tx, &input.unit_revision).await?;
    let anchored = verify_revision_ref_on(&mut tx, &input.artefact_revision).await?;
    input.selectors = canonicalize_occurrence_selectors(input.selectors, &anchored)?;
    let intent = intent_sha256(&input)?;
    if let Some(prior) = prior_command(
        &mut tx,
        &input.unit_revision.subject_id,
        &input.idempotency_key,
        "bind_occurrence",
        &intent,
    )
    .await?
    {
        let occurrence_id: String =
            sqlx::query_scalar("SELECT occurrence_id FROM occurrences WHERE binding_event_id=?")
                .bind(&prior.result_event_id)
                .fetch_one(&mut *tx)
                .await?;
        let occurrence = load_occurrence_on(&mut tx, &occurrence_id).await?;
        let bearer = unit_bearer_on(&mut tx, &occurrence.unit_revision.subject_id).await?;
        for record_id in [
            occurrence.unit_revision.subject_id.as_str(),
            bearer.as_str(),
            occurrence.artefact_revision.subject_id.as_str(),
        ] {
            require_capability_on(&mut tx, principal, record_id, Capability::Edit).await?;
        }
        return Ok(BindOccurrenceResult {
            occurrence,
            high_water: high_water(&prior),
        });
    }
    let selectors_sha256 = intent_sha256(&input.selectors)?;
    let duplicate: bool = sqlx::query_scalar(
        "SELECT EXISTS(
           SELECT 1 FROM occurrences
            WHERE unit_revision_event_id = ?
              AND artefact_revision_event_id = ?
              AND selectors_sha256 = ?
              AND expression_role = ?
         )",
    )
    .bind(&input.unit_revision.revision_event_id)
    .bind(&input.artefact_revision.revision_event_id)
    .bind(&selectors_sha256)
    .bind(input.expression_role.as_str())
    .fetch_one(&mut *tx)
    .await?;
    if duplicate {
        return Err(Error::engine(
            "an identical semantic Occurrence binding already exists",
        ));
    }
    let auth_revision = authorization_revision_on(&mut tx).await?;
    let occurrence_id = input
        .requested_occurrence_id
        .clone()
        .unwrap_or(OccurrenceId::new(Uuid::new_v4().to_string())?);
    let unit_id = input.unit_revision.subject_id.clone();
    let command = command_finalization(
        "bind_occurrence",
        &unit_id,
        &input.idempotency_key,
        intent,
        auth_revision,
    );
    let event = append_in(
        db,
        &mut tx,
        event_spec(
            unit_id,
            "occurrence.bound.v1",
            &OccurrenceBoundPayload {
                semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
                occurrence_id: occurrence_id.clone(),
                unit_revision: input.unit_revision,
                artefact_revision: input.artefact_revision,
                selectors: input.selectors,
                expression_role: input.expression_role.as_str().into(),
                command,
            },
            actor,
        )?,
    )
    .await?;
    let occurrence = load_occurrence_on(&mut tx, occurrence_id.as_str()).await?;
    db.commit_content(tx).await?;
    Ok(BindOccurrenceResult {
        occurrence,
        high_water: HistoryHighWater {
            content_seq: event.local_seq,
            authorization_revision_observed: auth_revision,
            semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
        },
    })
}

pub async fn revise_unit(
    db: &Db,
    principal: Principal<'_>,
    actor: &str,
    input: ReviseUnitInput,
) -> Result<ReviseUnitResult> {
    require_actor(actor)?;
    input.unit_id.validate()?;
    input.expected_current.validate()?;
    input.content.validate()?;
    input.idempotency_key.validate()?;
    if input.expected_current.subject_kind != RevisionSubjectKind::Unit
        || input.expected_current.subject_id != input.unit_id.as_str()
        || input.rationale.trim().is_empty()
    {
        return Err(Error::engine("invalid Unit revision input"));
    }
    let mut tx = begin_write(db.write_pool()).await?;
    let bearer = unit_bearer_on(&mut tx, input.unit_id.as_str()).await?;
    for record_id in [input.unit_id.as_str(), bearer.as_str()] {
        require_capability_on(&mut tx, principal, record_id, Capability::Edit).await?;
    }
    verify_revision_ref_on(&mut tx, &input.expected_current).await?;
    let intent = intent_sha256(&input)?;
    if let Some(prior) = prior_command(
        &mut tx,
        input.unit_id.as_str(),
        &input.idempotency_key,
        "revise_unit",
        &intent,
    )
    .await?
    {
        let revision = load_unit_revision_on(&mut tx, &prior.result_event_id).await?;
        let bearer = unit_bearer_on(&mut tx, &revision.revision.subject_id).await?;
        for record_id in [revision.revision.subject_id.as_str(), bearer.as_str()] {
            require_capability_on(&mut tx, principal, record_id, Capability::Edit).await?;
        }
        let previous = revision
            .based_on_revision_event_id
            .as_deref()
            .ok_or_else(|| Error::engine("idempotent revised Unit lacks based_on"))?;
        return Ok(ReviseUnitResult {
            previous_revision: load_unit_revision_on(&mut tx, previous).await?.revision,
            new_revision: revision.revision,
            high_water: high_water(&prior),
        });
    }
    let heads: Vec<String> = sqlx::query_scalar(
        "SELECT revision_event_id FROM unit_heads WHERE unit_id=? ORDER BY revision_event_id",
    )
    .bind(input.unit_id.as_str())
    .fetch_all(&mut *tx)
    .await?;
    if heads.len() != 1 || heads[0] != input.expected_current.revision_event_id {
        return Err(Error::engine("Unit expected-current revision conflict"));
    }
    let auth_revision = authorization_revision_on(&mut tx).await?;
    let content_sha256 = input.content.sha256();
    let command = command_finalization(
        "revise_unit",
        input.unit_id.as_str(),
        &input.idempotency_key,
        intent,
        auth_revision,
    );
    let event = append_in(
        db,
        &mut tx,
        event_spec(
            input.unit_id.as_str(),
            "unit.revision.recorded.v1",
            &UnitRevisionRecordedPayload {
                format: UNIT_REVISION_FORMAT.into(),
                semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
                content: input.content,
                content_sha256: content_sha256.clone(),
                based_on_revision_event_id: Some(input.expected_current.revision_event_id.clone()),
                rationale: Some(input.rationale),
                command: Some(command),
            },
            actor,
        )?,
    )
    .await?;
    let new_revision = revision_ref_from_unit_event(&event, content_sha256);
    db.commit_content(tx).await?;
    Ok(ReviseUnitResult {
        previous_revision: input.expected_current,
        new_revision,
        high_water: HistoryHighWater {
            content_seq: event.local_seq,
            authorization_revision_observed: auth_revision,
            semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
        },
    })
}

pub async fn read_unit(db: &Db, principal: Principal<'_>, unit_id: &UnitId) -> Result<UnitView> {
    let mut tx = db.pool().begin().await?;
    let bearer: Option<String> =
        sqlx::query_scalar("SELECT authority_bearer_record_id FROM semantic_units WHERE unit_id=?")
            .bind(unit_id.as_str())
            .fetch_optional(&mut *tx)
            .await?;
    let bearer = bearer.ok_or_else(|| {
        Error::engine(if principal.is_trusted_local() {
            "Unit not found"
        } else {
            "Unit unavailable"
        })
    })?;
    require_capability_on(&mut tx, principal, unit_id.as_str(), Capability::View)
        .await
        .map_err(|error| semantic_read_error(principal, "Unit unavailable", error))?;
    require_capability_on(&mut tx, principal, &bearer, Capability::View)
        .await
        .map_err(|error| semantic_read_error(principal, "Unit unavailable", error))?;
    let row = sqlx::query(
        "SELECT creation_event_id,creation_event_seq,label FROM semantic_units WHERE unit_id=?",
    )
    .bind(unit_id.as_str())
    .fetch_one(&mut *tx)
    .await?;
    let head_ids: Vec<String> = sqlx::query_scalar(
        "SELECT revision_event_id FROM unit_heads WHERE unit_id=? ORDER BY revision_event_id",
    )
    .bind(unit_id.as_str())
    .fetch_all(&mut *tx)
    .await?;
    let mut current_heads = Vec::with_capacity(head_ids.len());
    for head in head_ids {
        current_heads.push(load_unit_revision_on(&mut tx, &head).await?.revision);
    }
    Ok(UnitView {
        unit_id: unit_id.clone(),
        authority_bearer_record_id: bearer,
        label: row.try_get("label")?,
        creation_event_id: row.try_get("creation_event_id")?,
        creation_event_seq: row.try_get("creation_event_seq")?,
        current_heads,
    })
}

pub async fn read_unit_revision(
    db: &Db,
    principal: Principal<'_>,
    reference: &RevisionRef,
) -> Result<UnitRevisionView> {
    if reference.subject_kind != RevisionSubjectKind::Unit {
        return Err(Error::engine("not a Unit RevisionRef"));
    }
    let mut tx = db.pool().begin().await?;
    let bearer = unit_bearer_on(&mut tx, &reference.subject_id)
        .await
        .map_err(|error| semantic_read_error(principal, "Unit revision unavailable", error))?;
    require_capability_on(&mut tx, principal, &reference.subject_id, Capability::View)
        .await
        .map_err(|error| semantic_read_error(principal, "Unit revision unavailable", error))?;
    require_capability_on(&mut tx, principal, &bearer, Capability::View)
        .await
        .map_err(|error| semantic_read_error(principal, "Unit revision unavailable", error))?;
    verify_revision_ref_on(&mut tx, reference).await?;
    load_unit_revision_on(&mut tx, &reference.revision_event_id).await
}

pub async fn list_occurrences(
    db: &Db,
    principal: Principal<'_>,
    unit_id: &UnitId,
) -> Result<Vec<OccurrenceView>> {
    let mut tx = db.pool().begin().await?;
    let bearer = unit_bearer_on(&mut tx, unit_id.as_str())
        .await
        .map_err(|error| semantic_read_error(principal, "Unit unavailable", error))?;
    require_capability_on(&mut tx, principal, unit_id.as_str(), Capability::View)
        .await
        .map_err(|error| semantic_read_error(principal, "Unit unavailable", error))?;
    require_capability_on(&mut tx, principal, &bearer, Capability::View)
        .await
        .map_err(|error| semantic_read_error(principal, "Unit unavailable", error))?;
    let rows = sqlx::query("SELECT occurrence_id,artefact_id FROM occurrences WHERE unit_id=? ORDER BY binding_event_seq")
        .bind(unit_id.as_str())
        .fetch_all(&mut *tx)
        .await?;
    let mut result = Vec::new();
    for row in rows {
        let artefact_id: String = row.try_get("artefact_id")?;
        if require_capability_on(&mut tx, principal, &artefact_id, Capability::View)
            .await
            .is_ok()
        {
            result.push(
                load_occurrence_on(&mut tx, &row.try_get::<String, _>("occurrence_id")?).await?,
            );
        }
    }
    Ok(result)
}

pub async fn resolve_occurrence(
    db: &Db,
    principal: Principal<'_>,
    occurrence_id: &OccurrenceId,
) -> Result<OccurrenceResolution> {
    let mut tx = db.pool().begin().await?;
    if !principal.is_trusted_local() {
        let target = sqlx::query(
            "SELECT u.unit_id,s.authority_bearer_record_id,o.artefact_id
               FROM occurrences o
               JOIN unit_revisions u ON u.revision_event_id=o.unit_revision_event_id
               JOIN semantic_units s ON s.unit_id=u.unit_id
              WHERE o.occurrence_id=?",
        )
        .bind(occurrence_id.as_str())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| Error::engine("Occurrence unavailable"))?;
        for record_id in [
            target.try_get::<String, _>("unit_id")?,
            target.try_get::<String, _>("authority_bearer_record_id")?,
            target.try_get::<String, _>("artefact_id")?,
        ] {
            require_capability_on(&mut tx, principal, &record_id, Capability::View)
                .await
                .map_err(|_| Error::engine("Occurrence unavailable"))?;
        }
    }
    let occurrence = load_occurrence_on(&mut tx, occurrence_id.as_str()).await?;
    let bearer = unit_bearer_on(&mut tx, &occurrence.unit_revision.subject_id).await?;
    for record_id in [
        occurrence.unit_revision.subject_id.as_str(),
        bearer.as_str(),
        occurrence.artefact_revision.subject_id.as_str(),
    ] {
        require_capability_on(&mut tx, principal, record_id, Capability::View)
            .await
            .map_err(|error| semantic_read_error(principal, "Occurrence unavailable", error))?;
    }
    resolve_occurrence_view_on(&mut tx, occurrence).await
}

pub(crate) async fn resolve_occurrence_view_on(
    conn: &mut SqliteConnection,
    occurrence: OccurrenceView,
) -> Result<OccurrenceResolution> {
    let anchored = match verify_revision_ref_on(conn, &occurrence.artefact_revision).await {
        Ok(bytes) => bytes,
        Err(error) => {
            return Ok(OccurrenceResolution {
                occurrence_id: occurrence.occurrence_id,
                state: OccurrenceResolutionState::Unavailable,
                original_artefact_revision: occurrence.artefact_revision,
                current_artefact_revision: None,
                current_range: None,
                detail: Some(error.to_string()),
            })
        }
    };
    let anchored_ranges =
        match crate::citations::selector_ranges(&occurrence.selectors, &anchored, None) {
            Ok(ranges) => ranges,
            Err(error) => {
                return Ok(OccurrenceResolution {
                    occurrence_id: occurrence.occurrence_id,
                    state: OccurrenceResolutionState::Conflict,
                    original_artefact_revision: occurrence.artefact_revision,
                    current_artefact_revision: None,
                    current_range: None,
                    detail: Some(error.to_string()),
                })
            }
        };
    let Some((current_ref, current_bytes)) =
        current_body_revision_on(conn, &occurrence.artefact_revision.subject_id).await?
    else {
        return Ok(OccurrenceResolution {
            occurrence_id: occurrence.occurrence_id,
            state: OccurrenceResolutionState::Unavailable,
            original_artefact_revision: occurrence.artefact_revision,
            current_artefact_revision: None,
            current_range: None,
            detail: Some("current artefact representation is unavailable".into()),
        });
    };
    if current_ref.sha256 == occurrence.artefact_revision.sha256 {
        let range = anchored_ranges[0];
        return Ok(OccurrenceResolution {
            occurrence_id: occurrence.occurrence_id,
            state: OccurrenceResolutionState::Current,
            original_artefact_revision: occurrence.artefact_revision,
            current_artefact_revision: Some(current_ref),
            current_range: Some(ResolvedRange {
                start: range.0 as u64,
                end: range.1 as u64,
            }),
            detail: None,
        });
    }
    let evidence = &anchored[anchored_ranges[0].0..anchored_ranges[0].1];
    match crate::citations::selector_ranges(&occurrence.selectors, &current_bytes, Some(evidence)) {
        Ok(ranges) => Ok(OccurrenceResolution {
            occurrence_id: occurrence.occurrence_id,
            state: OccurrenceResolutionState::Relocated,
            original_artefact_revision: occurrence.artefact_revision,
            current_artefact_revision: Some(current_ref),
            current_range: Some(ResolvedRange {
                start: ranges[0].0 as u64,
                end: ranges[0].1 as u64,
            }),
            detail: Some("the exact anchored evidence relocated uniquely".into()),
        }),
        Err(error)
            if error.to_string().contains("multiple") || error.to_string().contains("disagree") =>
        {
            Ok(OccurrenceResolution {
                occurrence_id: occurrence.occurrence_id,
                state: OccurrenceResolutionState::Conflict,
                original_artefact_revision: occurrence.artefact_revision,
                current_artefact_revision: Some(current_ref),
                current_range: None,
                detail: Some(error.to_string()),
            })
        }
        Err(error) => Ok(OccurrenceResolution {
            occurrence_id: occurrence.occurrence_id,
            state: OccurrenceResolutionState::Stale,
            original_artefact_revision: occurrence.artefact_revision,
            current_artefact_revision: Some(current_ref),
            current_range: None,
            detail: Some(error.to_string()),
        }),
    }
}

fn semantic_read_error(principal: Principal<'_>, public: &str, error: Error) -> Error {
    if principal.is_trusted_local() {
        error
    } else {
        Error::engine(public)
    }
}

pub async fn current_history_high_water(db: &Db) -> Result<HistoryHighWater> {
    // Both coordinates describe one receipt boundary and must be observed from
    // one SQLite read snapshot, never from two independently advancing reads.
    let mut snapshot = db.pool().begin().await?;
    let content_seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(&mut *snapshot)
        .await?;
    let authorization_revision_observed = authorization_revision_on(&mut snapshot).await?;
    snapshot.rollback().await?;
    Ok(HistoryHighWater {
        content_seq,
        authorization_revision_observed,
        semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
    })
}
