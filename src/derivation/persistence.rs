use sha2::{Digest, Sha256};
use sqlx::{Connection, Row, Sqlite, SqliteConnection, Transaction};

use crate::error::{Error, Result};
use crate::store::now_iso;

use super::events::{DerivationEventRow, NewDerivationEvent, DERIVATION_EVENT_SCHEMA_VERSION};
use super::projector::{project_event, validate_event};

async fn content_event_payload_digest(
    conn: &mut SqliteConnection,
    event_id: &str,
) -> Result<String> {
    let payload: Option<Option<String>> =
        sqlx::query_scalar("SELECT payload FROM content_events WHERE id=?")
            .bind(event_id)
            .fetch_optional(&mut *conn)
            .await?;
    let payload = payload.ok_or_else(|| {
        Error::engine(format!(
            "derivation reference names missing content event '{event_id}'"
        ))
    })?;
    let value = payload.map_or(Ok(serde_json::Value::Null), |payload| {
        serde_json::from_str(&payload).map_err(Error::from)
    })?;
    Ok(super::events::digest_json(&value))
}

async fn verify_live_completion_references(
    conn: &mut SqliteConnection,
    value: &super::events::DerivationRevisionCompleted,
) -> Result<()> {
    let recipe_digest: Option<String> = sqlx::query_scalar(
        "SELECT descriptor_sha256 FROM recipe_releases
          WHERE program_id=? AND publication_event_id=?",
    )
    .bind(&value.recipe_revision.definition_id)
    .bind(&value.recipe_revision.publication_id)
    .fetch_optional(&mut *conn)
    .await?;
    if recipe_digest.as_deref() != Some(value.recipe_revision.sha256.as_str()) {
        return Err(Error::engine(
            "derivation recipe reference does not match its governed release descriptor",
        ));
    }
    let output_digest = content_event_payload_digest(conn, &value.output_ref.event_id).await?;
    if output_digest != value.output_ref.sha256 {
        return Err(Error::engine(
            "derivation output digest does not match its content event",
        ));
    }
    for input in &value.inputs {
        let actual = match input.input_kind.as_str() {
            "content_event" => content_event_payload_digest(conn, &input.portable_id).await?,
            "record_body" => {
                let payload: Option<Option<String>> =
                    sqlx::query_scalar("SELECT payload FROM content_events WHERE id=?")
                        .bind(&input.portable_id)
                        .fetch_optional(&mut *conn)
                        .await?;
                let payload = payload.ok_or_else(|| {
                    Error::engine(format!(
                        "derivation record-body input names missing event '{}'",
                        input.portable_id
                    ))
                })?;
                let payload: serde_json::Value = serde_json::from_str(
                    payload
                        .as_deref()
                        .ok_or_else(|| Error::engine("record-body input event has no payload"))?,
                )?;
                let body = payload
                    .get("body")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        Error::engine("record-body input event does not carry a string body")
                    })?;
                hex::encode(Sha256::digest(body.as_bytes()))
            }
            "blob" => sqlx::query_scalar::<_, String>("SELECT sha256 FROM blobs WHERE id=?")
                .bind(&input.portable_id)
                .fetch_optional(&mut *conn)
                .await?
                .ok_or_else(|| {
                    Error::engine(format!(
                        "derivation blob input names missing blob '{}'",
                        input.portable_id
                    ))
                })?,
            "versioned" => {
                return Err(Error::engine(
                    "versioned derivation inputs require a registered verifier",
                ));
            }
            _ => continue,
        };
        if actual != input.sha256 {
            return Err(Error::engine(format!(
                "derivation input digest does not match '{}'",
                input.portable_id
            )));
        }
    }
    Ok(())
}

fn row_from_sql(row: sqlx::sqlite::SqliteRow) -> Result<DerivationEventRow> {
    Ok(DerivationEventRow {
        seq: row.try_get("seq")?,
        id: row.try_get("id")?,
        idempotency_key: row.try_get("idempotency_key")?,
        event_type: row.try_get("type")?,
        schema_version: row.try_get("schema_version")?,
        aggregate_kind: row.try_get("aggregate_kind")?,
        aggregate_id: row.try_get("aggregate_id")?,
        actor: row.try_get("actor")?,
        run_key: row.try_get("run_key")?,
        reason: row.try_get("reason")?,
        payload: row.try_get("payload")?,
        created_at: row.try_get("created_at")?,
    })
}

pub(crate) async fn read_by_key(
    conn: &mut SqliteConnection,
    key: &str,
) -> Result<Option<DerivationEventRow>> {
    sqlx::query(
        "SELECT seq,id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,
                actor,run_key,reason,payload,created_at
           FROM derivation_events WHERE idempotency_key=?",
    )
    .bind(key)
    .fetch_optional(&mut *conn)
    .await?
    .map(row_from_sql)
    .transpose()
}

async fn append_derivation_event_on(
    conn: &mut SqliteConnection,
    input: NewDerivationEvent,
) -> Result<DerivationEventRow> {
    let event_type = input.payload.event_type().to_string();
    let aggregate_kind = input.payload.aggregate_kind().to_string();
    let aggregate_id = input.payload.aggregate_id().to_string();
    let payload = input.payload.to_json()?;
    for (label, value) in [
        ("idempotency key", input.idempotency_key.as_str()),
        ("actor", input.actor.as_str()),
        ("reason", input.reason.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(Error::engine(format!(
                "derivation event {label} cannot be empty"
            )));
        }
    }
    if let Some(existing) = read_by_key(conn, &input.idempotency_key).await? {
        let same = existing.event_type == event_type
            && existing.schema_version == DERIVATION_EVENT_SCHEMA_VERSION
            && existing.aggregate_kind == aggregate_kind
            && existing.aggregate_id == aggregate_id
            && existing.actor == input.actor
            && existing.reason == input.reason
            && existing.payload == payload;
        if !same {
            return Err(Error::engine(format!(
                "derivation event idempotency key '{}' was reused for different intent",
                input.idempotency_key
            )));
        }
        project_event(conn, &existing).await?;
        return Ok(existing);
    }
    if let super::events::DerivationEventPayload::RevisionCompleted(value) = &input.payload {
        verify_live_completion_references(conn, value).await?;
    }
    let mut event = DerivationEventRow {
        seq: 1,
        id: uuid::Uuid::new_v4().to_string(),
        idempotency_key: input.idempotency_key,
        event_type,
        schema_version: DERIVATION_EVENT_SCHEMA_VERSION,
        aggregate_kind,
        aggregate_id,
        actor: input.actor,
        run_key: input.run_key,
        reason: input.reason,
        payload,
        created_at: now_iso(),
    };
    validate_event(&event)?;
    event.seq = sqlx::query_scalar(
        "INSERT INTO derivation_events
         (id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,actor,run_key,reason,payload,created_at)
         VALUES(?,?,?,?,?,?,?,?,?,?,?) RETURNING seq",
    )
    .bind(&event.id)
    .bind(&event.idempotency_key)
    .bind(&event.event_type)
    .bind(event.schema_version)
    .bind(&event.aggregate_kind)
    .bind(&event.aggregate_id)
    .bind(&event.actor)
    .bind(&event.run_key)
    .bind(&event.reason)
    .bind(&event.payload)
    .bind(&event.created_at)
    .fetch_one(&mut *conn)
    .await?;
    project_event(conn, &event).await?;
    Ok(event)
}

pub(crate) async fn append_derivation_event_in(
    tx: &mut Transaction<'_, Sqlite>,
    input: NewDerivationEvent,
) -> Result<DerivationEventRow> {
    append_derivation_event_on(tx, input).await
}

pub async fn read_all_derivation_events(
    conn: &mut SqliteConnection,
) -> Result<Vec<DerivationEventRow>> {
    sqlx::query(
        "SELECT seq,id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,
                actor,run_key,reason,payload,created_at
           FROM derivation_events ORDER BY seq",
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(row_from_sql)
    .collect()
}

pub async fn replay_derivations(
    conn: &mut SqliteConnection,
    events: &[DerivationEventRow],
) -> Result<()> {
    let mut tx = conn.begin().await?;
    for event in events {
        project_event(&mut tx, event).await?;
    }
    tx.commit().await?;
    Ok(())
}
