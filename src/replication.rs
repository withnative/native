//! Sealed identity-preserving ingestion for authenticated Native Messages.
//!
//! This module is a private child of `store`: it can construct the append
//! kernel's private `PreparedEvent`, while no sibling module can acquire
//! preserved-id authority. The future decrypted-content verifier (868d4c69)
//! will own canonicalization, safe-integer validation, authentication and
//! construction of these opaque verified values. Until then, only this module's
//! tests construct them; this seam does not pretend to authenticate transport input.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::Row;
use uuid::Uuid;

use super::{
    append_in, append_prepared_in, current_event_annotations, AppendSpec, NativeEventSource,
    PreparedEvent,
};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::events::EventRow;

const MAX_MESSAGES_PER_BATCH: usize = 32;
const MAX_PROSE_BYTES: usize = 128 * 1024;
const MAX_NAME_BYTES: usize = 512;

/// Opaque fixed-size digest produced by the future verified-content boundary.
/// This lower seam compares and persists it but never computes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifiedSourceFingerprint([u8; 32]);

/// One already-verified batch of immutable Message creations.
#[derive(Debug, Clone)]
struct VerifiedMessageBatch {
    origin_database_id: String,
    messages: Vec<VerifiedMessageCreate>,
}

/// The only preservation-bearing semantic operation admitted by v1.
/// Destination-owned identity and placement have already been resolved.
#[derive(Debug, Clone)]
struct VerifiedMessageCreate {
    event_id: String,
    source_seq: i64,
    message_record_id: String,
    source_principal: String,
    created_at: String,
    source_fingerprint: VerifiedSourceFingerprint,
    kind: String,
    /// Required semantic content from canonical decrypted MessageUnitV1. The
    /// verifier includes this field in `source_fingerprint` before constructing
    /// the opaque verified value.
    expectation: String,
    prose: String,
    name: Option<String>,
    destination_actor: String,
    destination_home_id: String,
    destination_owner_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MessageIngestStatus {
    Inserted(EventRow),
    Duplicate(EventRow),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MessageIngestOutcome {
    /// One result per input Message, in batch order. An identical repeated event
    /// id is inserted at first occurrence and reported duplicate thereafter.
    messages: Vec<MessageIngestStatus>,
}

#[derive(Debug)]
struct Candidate {
    source: NativeEventSource,
    prepared: PreparedEvent,
    expectation: String,
}

#[derive(Debug, Clone, Copy)]
enum Classification {
    NewFirst,
    Existing,
    Repeated,
}

/// Apply a sealed Message-create batch in one serialized transaction.
/// Every event and preserved Message id is classified before the first append.
async fn ingest_verified_native_messages(
    db: &Db,
    batch: VerifiedMessageBatch,
) -> Result<MessageIngestOutcome> {
    require_nonempty("origin_database_id", &batch.origin_database_id)?;
    if batch.messages.is_empty() || batch.messages.len() > MAX_MESSAGES_PER_BATCH {
        return Err(Error::engine(format!(
            "verified Native Message batch requires 1..={MAX_MESSAGES_PER_BATCH} messages"
        )));
    }

    let mut candidates = Vec::with_capacity(batch.messages.len());
    for message in batch.messages {
        candidates.push(compile_message(&batch.origin_database_id, message)?);
    }
    let input_ids: Vec<String> = candidates
        .iter()
        .map(|candidate| candidate.prepared.event.id.clone())
        .collect();

    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut first_by_event_id: HashMap<String, usize> = HashMap::new();
    let mut first_event_by_record_id: HashMap<String, String> = HashMap::new();
    let mut classification = vec![Classification::NewFirst; candidates.len()];
    let mut stored: HashMap<String, EventRow> = HashMap::new();

    // Reject conflicting event repeats and distinct creations claiming one
    // preserved Message id before consulting or mutating durable state.
    for (index, candidate) in candidates.iter().enumerate() {
        let event_id = &candidate.prepared.event.id;
        if let Some(first) = first_by_event_id.get(event_id).copied() {
            if candidates[first].source != candidate.source {
                return Err(event_collision(event_id));
            }
            classification[index] = Classification::Repeated;
            continue;
        }
        first_by_event_id.insert(event_id.clone(), index);
        let record_id = &candidate.prepared.event.record_id;
        if let Some(other_event_id) = first_event_by_record_id.get(record_id) {
            return Err(message_collision(record_id, other_event_id, event_id));
        }
        first_event_by_record_id.insert(record_id.clone(), event_id.clone());
    }

    // BEGIN IMMEDIATE serializes concurrent deliveries. Classify every unique
    // event and every new preserved Message id before the first projection.
    for (index, candidate) in candidates.iter().enumerate() {
        if first_by_event_id.get(&candidate.prepared.event.id) != Some(&index) {
            continue;
        }
        let event_id = &candidate.prepared.event.id;
        if let Some((event, source)) = load_existing(&mut tx, event_id).await? {
            let Some(existing_source) = source else {
                return Err(event_collision(event_id));
            };
            if existing_source != candidate.source {
                return Err(event_collision(event_id));
            }
            if event.causal_envelope
                != candidate
                    .prepared
                    .governed_causal_envelope
                    .clone()
                    .unwrap_or_else(crate::events::CausalEnvelopeV1::legacy_unknown)
            {
                return Err(event_collision(event_id));
            }
            classification[index] = Classification::Existing;
            stored.insert(event_id.clone(), event);
            continue;
        }

        let record_id = &candidate.prepared.event.record_id;
        let record_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM records WHERE id = ?)")
                .bind(record_id)
                .fetch_one(&mut *tx)
                .await?;
        if record_exists {
            return Err(message_record_exists(record_id, event_id));
        }
    }

    // Destination-local sequence follows first-occurrence batch order.
    for (index, candidate) in candidates.into_iter().enumerate() {
        if !matches!(classification[index], Classification::NewFirst) {
            continue;
        }
        let event_id = candidate.prepared.event.id.clone();
        let record_id = candidate.prepared.event.record_id.clone();
        let actor = candidate.prepared.event.actor.clone();
        let event = append_prepared_in(db, &mut tx, candidate.prepared).await?;
        // The facet is a destination-local projection event, but it commits in
        // the same transaction as the preserved Message creation. A duplicate
        // source event never enters this branch and therefore emits neither a
        // second creation nor a second facet event.
        append_in(
            db,
            &mut tx,
            AppendSpec {
                record_id,
                event_type: "facet.set".into(),
                payload: json!({
                    "key": crate::message_expectation::EXPECTATION_FACET_KEY,
                    "value": candidate.expectation,
                    "vocab_ref": crate::meta::vocab_ref(
                        crate::message_expectation::EXPECTATION_VOCABULARY_ID,
                    ),
                }),
                actor,
            },
        )
        .await?;
        stored.insert(event_id, event);
    }
    db.commit_content(tx).await?;

    let mut messages = Vec::with_capacity(classification.len());
    for (event_id, class) in input_ids.into_iter().zip(classification) {
        let event = stored.get(&event_id).cloned().ok_or_else(|| {
            Error::engine(format!(
                "verified Native Message ingest lost classification for event {event_id}"
            ))
        })?;
        messages.push(match class {
            Classification::NewFirst => MessageIngestStatus::Inserted(event),
            Classification::Existing | Classification::Repeated => {
                MessageIngestStatus::Duplicate(event)
            }
        });
    }
    Ok(MessageIngestOutcome { messages })
}

fn compile_message(origin_database_id: &str, message: VerifiedMessageCreate) -> Result<Candidate> {
    validate_uuid("source event id", &message.event_id)?;
    validate_uuid("Message record id", &message.message_record_id)?;
    if message.source_seq <= 0 {
        return Err(Error::engine(
            "verified Native Message source_seq must be positive",
        ));
    }
    require_nonempty("source_principal", &message.source_principal)?;
    require_nonempty("kind", &message.kind)?;
    if !crate::message_expectation::EXPECTATION_VALUES.contains(&message.expectation.as_str()) {
        return Err(Error::engine(format!(
            "unsupported verified Native Message expectation '{}' (required native.message.v1 value)",
            message.expectation
        )));
    }
    require_nonempty("prose", &message.prose)?;
    require_nonempty("destination_actor", &message.destination_actor)?;
    require_nonempty("destination_home_id", &message.destination_home_id)?;
    if message.prose.len() > MAX_PROSE_BYTES {
        return Err(Error::engine(format!(
            "verified Native Message prose exceeds {MAX_PROSE_BYTES} bytes"
        )));
    }
    if message
        .name
        .as_ref()
        .is_some_and(|name| name.len() > MAX_NAME_BYTES)
    {
        return Err(Error::engine(format!(
            "verified Native Message name exceeds {MAX_NAME_BYTES} bytes"
        )));
    }
    if let Some(name) = &message.name {
        require_nonempty("name", name)?;
    }
    if let Some(owner_id) = &message.destination_owner_id {
        require_nonempty("destination_owner_id", owner_id)?;
    }
    validate_timestamp(&message.created_at)?;

    let mut payload = json!({
        "type": "Message",
        "kind": message.kind,
        "body": message.prose,
        "home_id": message.destination_home_id,
        "persistence": "occurrent",
    });
    let object = payload
        .as_object_mut()
        .expect("Message compiler always creates an object payload");
    if let Some(name) = message.name {
        object.insert("name".into(), Value::String(name));
    }
    if let Some(owner_id) = message.destination_owner_id {
        object.insert("owner_id".into(), Value::String(owner_id));
    }

    let annotations = current_event_annotations();
    let source = NativeEventSource {
        origin_database_id: origin_database_id.to_owned(),
        source_seq: message.source_seq,
        source_record_id: message.message_record_id.clone(),
        source_principal: message.source_principal,
        fingerprint: message.source_fingerprint.0,
    };
    let event = EventRow {
        local_seq: -1,
        id: message.event_id,
        record_id: message.message_record_id,
        event_type: "record.created".into(),
        payload: Some(serde_json::to_string(&payload)?),
        actor: Some(message.destination_actor),
        run_key: annotations.run_key,
        parent_key: annotations.parent_key,
        intent: annotations.intent,
        created_at: message.created_at,
        causal_envelope: crate::events::CausalEnvelopeV1::import_incomplete(
            crate::events::CausalFrontierV1::empty(),
        ),
    };
    Ok(Candidate {
        source: source.clone(),
        expectation: message.expectation,
        prepared: PreparedEvent {
            event,
            payload,
            native_source: Some(source),
            governed_causal_envelope: Some(crate::events::CausalEnvelopeV1::import_incomplete(
                crate::events::CausalFrontierV1::empty(),
            )),
        },
    })
}

async fn load_existing(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    id: &str,
) -> Result<Option<(EventRow, Option<NativeEventSource>)>> {
    let row = sqlx::query(
        "SELECT e.seq, e.id, e.record_id, e.type, e.payload, e.actor,
                e.run_key, e.parent_key, e.intent, e.created_at,
                e.causal_envelope_version, e.causal_status,
                s.origin_database_id, s.source_seq, s.source_record_id,
                s.source_principal, s.source_fingerprint
           FROM content_events e
           LEFT JOIN content_event_sources s ON s.event_id = e.id
          WHERE e.id = ?",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let causal_version: i64 = row.try_get("causal_envelope_version")?;
    if causal_version != 1 {
        return Err(Error::engine("unsupported stored causal envelope version"));
    }
    let frontier = crate::events::CausalFrontierV1::new(
        sqlx::query_scalar::<_, String>(
            "SELECT parent_event_id FROM content_event_causal_frontier
              WHERE event_id=? ORDER BY parent_event_id",
        )
        .bind(id)
        .fetch_all(&mut **tx)
        .await?,
    )?;
    let causal_envelope = match row.try_get::<String, _>("causal_status")?.as_str() {
        "complete" => crate::events::CausalEnvelopeV1::complete(frontier),
        "import_incomplete" => crate::events::CausalEnvelopeV1::import_incomplete(frontier),
        "legacy_unknown" if frontier.is_empty() => {
            crate::events::CausalEnvelopeV1::legacy_unknown()
        }
        _ => return Err(Error::engine("invalid stored causal envelope")),
    };
    let event = EventRow {
        local_seq: row.try_get("seq")?,
        id: row.try_get("id")?,
        record_id: row.try_get("record_id")?,
        event_type: row.try_get("type")?,
        payload: row.try_get("payload")?,
        actor: row.try_get("actor")?,
        run_key: row.try_get("run_key")?,
        parent_key: row.try_get("parent_key")?,
        intent: row.try_get("intent")?,
        created_at: row.try_get("created_at")?,
        causal_envelope,
    };
    let fingerprint: Option<String> = row.try_get("source_fingerprint")?;
    let source = match fingerprint {
        None => None,
        Some(fingerprint) => {
            let bytes = hex::decode(&fingerprint).map_err(|_| {
                Error::engine(format!(
                    "stored Native source fingerprint for event {id} is not hexadecimal"
                ))
            })?;
            let fingerprint: [u8; 32] = bytes.try_into().map_err(|_| {
                Error::engine(format!(
                    "stored Native source fingerprint for event {id} is not 32 bytes"
                ))
            })?;
            Some(NativeEventSource {
                origin_database_id: row.try_get("origin_database_id")?,
                source_seq: row.try_get("source_seq")?,
                source_record_id: row.try_get("source_record_id")?,
                source_principal: row.try_get("source_principal")?,
                fingerprint,
            })
        }
    };
    Ok(Some((event, source)))
}

fn validate_uuid(field: &str, value: &str) -> Result<()> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| Error::engine(format!("verified Native {field} '{value}' is not a UUID")))?;
    if parsed.hyphenated().to_string() != value {
        return Err(Error::engine(format!(
            "verified Native {field} '{value}' is not canonical lowercase UUID text"
        )));
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<()> {
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|_| {
        Error::engine(format!(
            "verified Native Message created_at '{value}' is not RFC 3339"
        ))
    })?;
    let canonical = parsed
        .with_timezone(&Utc)
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    if canonical != value {
        return Err(Error::engine(format!(
            "verified Native Message created_at '{value}' is not canonical UTC millisecond form"
        )));
    }
    Ok(())
}

fn require_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::engine(format!(
            "verified Native Message {field} must not be empty"
        )));
    }
    Ok(())
}

fn event_collision(id: &str) -> Error {
    Error::engine(format!(
        "verified Native event identity collision for {id}: preserved UUID has different verified source facts"
    ))
}

fn message_collision(record_id: &str, first_event_id: &str, second_event_id: &str) -> Error {
    Error::engine(format!(
        "verified Native Message identity collision for {record_id}: events {first_event_id} and {second_event_id} both claim the preserved record UUID"
    ))
}

fn message_record_exists(record_id: &str, event_id: &str) -> Error {
    Error::engine(format!(
        "verified Native Message identity collision for {record_id}: new source event {event_id} cannot claim an existing local record"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance::rebuild_and_diff;
    use crate::schema::UNFILED_RECORD_ID;
    use crate::store::{append, create_record, AppendSpec};

    const ORIGIN: &str = "native-db:sender";
    const AT: &str = "2025-01-02T03:04:05.006Z";

    fn message(
        event_id: &str,
        source_seq: i64,
        record_id: &str,
        prose: &str,
    ) -> VerifiedMessageCreate {
        VerifiedMessageCreate {
            event_id: event_id.into(),
            source_seq,
            message_record_id: record_id.into(),
            source_principal: "acct:sender".into(),
            created_at: AT.into(),
            source_fingerprint: VerifiedSourceFingerprint([source_seq as u8; 32]),
            kind: "text".into(),
            expectation: "none".into(),
            prose: prose.into(),
            name: Some(format!("Message {source_seq}")),
            destination_actor: "acct:local-sender".into(),
            destination_home_id: UNFILED_RECORD_ID.into(),
            destination_owner_id: None,
        }
    }

    fn batch(messages: Vec<VerifiedMessageCreate>) -> VerifiedMessageBatch {
        VerifiedMessageBatch {
            origin_database_id: ORIGIN.into(),
            messages,
        }
    }

    fn row(status: &MessageIngestStatus) -> &EventRow {
        match status {
            MessageIngestStatus::Inserted(row) | MessageIngestStatus::Duplicate(row) => row,
        }
    }

    async fn count(db: &Db, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn first_delivery_preserves_identity_and_atomically_sets_expectation() {
        let db = crate::create_database(":memory:").await.unwrap();
        create_record(
            &db,
            json!({
                "id": "4e900000-0000-4000-8000-000000000001",
                "type": "Entity",
                "kind": "person",
                "name": "Local sender"
            }),
        )
        .await
        .unwrap();
        let mut input = message(
            "10000000-0000-4000-8000-000000000001",
            41,
            "20000000-0000-4000-8000-000000000001",
            "hello from source",
        );
        input.destination_owner_id = Some("4e900000-0000-4000-8000-000000000001".into());
        let outcome = ingest_verified_native_messages(&db, batch(vec![input]))
            .await
            .unwrap();
        assert!(matches!(
            outcome.messages[0],
            MessageIngestStatus::Inserted(_)
        ));
        let stored = row(&outcome.messages[0]);
        assert_eq!(stored.id, "10000000-0000-4000-8000-000000000001");
        assert_eq!(stored.record_id, "20000000-0000-4000-8000-000000000001");
        assert_eq!(stored.event_type, "record.created");
        assert_eq!(stored.created_at, AT);
        assert_ne!(
            stored.local_seq, 41,
            "destination local_seq is locally allocated"
        );
        assert_eq!(stored.actor.as_deref(), Some("acct:local-sender"));

        let record: (String, String, String, String, String, String) = sqlx::query_as(
            "SELECT type, kind, body, persistence, home_id, owner_id
               FROM records WHERE id = ?",
        )
        .bind(&stored.record_id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(
            record,
            (
                "Message".into(),
                "text".into(),
                "hello from source".into(),
                "occurrent".into(),
                UNFILED_RECORD_ID.into(),
                "4e900000-0000-4000-8000-000000000001".into(),
            )
        );
        let source: (String, i64, String, String, String) = sqlx::query_as(
            "SELECT origin_database_id, source_seq, source_record_id,
                    source_principal, source_fingerprint
               FROM content_event_sources WHERE event_id = ?",
        )
        .bind(&stored.id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(source.0, ORIGIN);
        assert_eq!(source.1, 41);
        assert_eq!(source.2, stored.record_id);
        assert_eq!(source.3, "acct:sender");
        assert_eq!(source.4, hex::encode([41_u8; 32]));
        let facet: (String, String) = sqlx::query_as(
            "SELECT value, vocab_ref FROM facet_values WHERE record_id = ? AND key = 'expectation'",
        )
        .bind(&stored.record_id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(facet.0, "none");
        assert_eq!(facet.1, "rec:voc:message-expectation");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM content_events WHERE record_id = ? AND type = 'facet.set'"
            )
            .bind(&stored.record_id)
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            1
        );
        assert!(rebuild_and_diff(&db).await.unwrap().equal);
    }

    #[tokio::test]
    async fn expectation_preflight_accepts_the_closed_vocabulary_and_rejects_unknown() {
        for expectation in crate::message_expectation::EXPECTATION_VALUES {
            let mut input = message(
                "10000000-0000-4000-8000-000000000015",
                55,
                "20000000-0000-4000-8000-000000000015",
                "expectation",
            );
            input.expectation = expectation.into();
            assert_eq!(
                compile_message(ORIGIN, input).unwrap().expectation,
                expectation
            );
        }

        let db = crate::create_database(":memory:").await.unwrap();
        let before = count(&db, "content_events").await;
        let mut input = message(
            "10000000-0000-4000-8000-000000000016",
            56,
            "20000000-0000-4000-8000-000000000016",
            "unsupported",
        );
        input.expectation = "maybe".into();
        let error = ingest_verified_native_messages(&db, batch(vec![input]))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("unsupported"));
        assert_eq!(count(&db, "content_events").await, before);
    }

    #[tokio::test]
    async fn unknown_message_kind_keeps_its_raw_discriminator_and_readable_prose() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut input = message(
            "10000000-0000-4000-8000-000000000014",
            54,
            "20000000-0000-4000-8000-000000000014",
            "read this even without richer-kind support",
        );
        input.kind = "vendor.example/rich-text-v2".into();

        let outcome = ingest_verified_native_messages(&db, batch(vec![input]))
            .await
            .unwrap();
        let stored = row(&outcome.messages[0]);
        let record: (String, String) =
            sqlx::query_as("SELECT kind, body FROM records WHERE id = ?")
                .bind(&stored.record_id)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(record.0, "vendor.example/rich-text-v2");
        assert_eq!(record.1, "read this even without richer-kind support");
        assert_eq!(
            serde_json::from_str::<Value>(stored.payload.as_deref().unwrap()).unwrap()["kind"],
            "vendor.example/rich-text-v2"
        );
        assert!(rebuild_and_diff(&db).await.unwrap().equal);
    }

    #[tokio::test]
    async fn exact_replay_is_noop_and_different_verified_fingerprint_collides() {
        let db = crate::create_database(":memory:").await.unwrap();
        let input = message(
            "10000000-0000-4000-8000-000000000002",
            42,
            "20000000-0000-4000-8000-000000000002",
            "replay",
        );
        ingest_verified_native_messages(&db, batch(vec![input.clone()]))
            .await
            .unwrap();
        let events_before = count(&db, "content_events").await;
        let replay = ingest_verified_native_messages(&db, batch(vec![input.clone()]))
            .await
            .unwrap();
        assert!(matches!(
            replay.messages[0],
            MessageIngestStatus::Duplicate(_)
        ));
        assert_eq!(count(&db, "content_events").await, events_before);

        let mut collision = input;
        collision.source_fingerprint = VerifiedSourceFingerprint([0x99; 32]);
        let error = ingest_verified_native_messages(&db, batch(vec![collision]))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("event identity collision"));
        assert_eq!(count(&db, "content_events").await, events_before);
    }

    #[tokio::test]
    async fn local_event_uuid_collision_is_never_a_duplicate() {
        let db = crate::create_database(":memory:").await.unwrap();
        let local_id: String = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE record_id = 'native:root' LIMIT 1",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        let error = ingest_verified_native_messages(
            &db,
            batch(vec![message(
                &local_id,
                43,
                "20000000-0000-4000-8000-000000000003",
                "collision",
            )]),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("event identity collision"));
    }

    #[tokio::test]
    async fn new_source_event_cannot_claim_an_existing_local_record() {
        let db = crate::create_database(":memory:").await.unwrap();
        let record_id = "20000000-0000-4000-8000-000000000004";
        create_record(
            &db,
            json!({
                "id": record_id,
                "type": "Message",
                "kind": "text",
                "name": "local",
                "body": "already here"
            }),
        )
        .await
        .unwrap();
        let event_id = "10000000-0000-4000-8000-000000000004";
        let events_before = count(&db, "content_events").await;
        let error = ingest_verified_native_messages(
            &db,
            batch(vec![message(event_id, 44, record_id, "foreign")]),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("existing local record"));
        assert_eq!(count(&db, "content_events").await, events_before);
        let event_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE id = ?")
                .bind(event_id)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        let source_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_event_sources WHERE event_id = ?")
                .bind(event_id)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!((event_rows, source_rows), (0, 0));
    }

    #[tokio::test]
    async fn mixed_batch_coalesces_repeats_and_assigns_new_sequences_in_order() {
        let db = crate::create_database(":memory:").await.unwrap();
        let existing = message(
            "10000000-0000-4000-8000-000000000005",
            45,
            "20000000-0000-4000-8000-000000000005",
            "existing",
        );
        ingest_verified_native_messages(&db, batch(vec![existing.clone()]))
            .await
            .unwrap();
        let first_new = message(
            "10000000-0000-4000-8000-000000000006",
            10,
            "20000000-0000-4000-8000-000000000006",
            "first",
        );
        let second_new = message(
            "10000000-0000-4000-8000-000000000007",
            9,
            "20000000-0000-4000-8000-000000000007",
            "second",
        );
        let outcome = ingest_verified_native_messages(
            &db,
            batch(vec![existing, first_new.clone(), first_new, second_new]),
        )
        .await
        .unwrap();
        assert!(matches!(
            outcome.messages[0],
            MessageIngestStatus::Duplicate(_)
        ));
        assert!(matches!(
            outcome.messages[1],
            MessageIngestStatus::Inserted(_)
        ));
        assert!(matches!(
            outcome.messages[2],
            MessageIngestStatus::Duplicate(_)
        ));
        assert!(matches!(
            outcome.messages[3],
            MessageIngestStatus::Inserted(_)
        ));
        assert_eq!(
            row(&outcome.messages[1]).local_seq + 2,
            row(&outcome.messages[3]).local_seq
        );
        assert_eq!(row(&outcome.messages[1]), row(&outcome.messages[2]));
    }

    #[tokio::test]
    async fn concurrent_exact_deliveries_insert_and_project_once() {
        let db = crate::create_database(":memory:").await.unwrap();
        let input = message(
            "10000000-0000-4000-8000-000000000008",
            48,
            "20000000-0000-4000-8000-000000000008",
            "concurrent",
        );
        let before = count(&db, "content_events").await;
        let (left, right) = tokio::join!(
            ingest_verified_native_messages(&db, batch(vec![input.clone()])),
            ingest_verified_native_messages(&db, batch(vec![input])),
        );
        let statuses = [
            left.unwrap().messages.remove(0),
            right.unwrap().messages.remove(0),
        ];
        assert_eq!(
            statuses
                .iter()
                .filter(|status| matches!(status, MessageIngestStatus::Inserted(_)))
                .count(),
            1
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|status| matches!(status, MessageIngestStatus::Duplicate(_)))
                .count(),
            1
        );
        assert_eq!(count(&db, "content_events").await, before + 2);
    }

    #[tokio::test]
    async fn collision_and_projector_failure_roll_back_the_whole_batch() {
        let db = crate::create_database(":memory:").await.unwrap();
        let first = message(
            "10000000-0000-4000-8000-000000000009",
            49,
            "20000000-0000-4000-8000-000000000009",
            "repeat",
        );
        let mut conflicting = first.clone();
        conflicting.source_fingerprint = VerifiedSourceFingerprint([0xaa; 32]);
        let before = count(&db, "content_events").await;
        assert!(
            ingest_verified_native_messages(&db, batch(vec![first, conflicting]))
                .await
                .unwrap_err()
                .to_string()
                .contains("event identity collision")
        );
        assert_eq!(count(&db, "content_events").await, before);

        let good = message(
            "10000000-0000-4000-8000-000000000010",
            50,
            "20000000-0000-4000-8000-000000000010",
            "must roll back",
        );
        let mut bad_home = message(
            "10000000-0000-4000-8000-000000000011",
            51,
            "20000000-0000-4000-8000-000000000011",
            "bad home",
        );
        bad_home.destination_home_id = "missing-local-home".into();
        assert!(
            ingest_verified_native_messages(&db, batch(vec![good, bad_home]))
                .await
                .is_err()
        );
        assert_eq!(count(&db, "content_events").await, before);
        assert_eq!(count(&db, "content_event_sources").await, 0);
    }

    #[tokio::test]
    async fn replicated_commit_wakes_realtime_subscribers() {
        let db = crate::create_database(":memory:").await.unwrap();
        let (db, hub) = crate::realtime::RealtimeHub::install(db).await.unwrap();
        let mut subscriber = hub.subscribe();
        let input = message(
            "10000000-0000-4000-8000-000000000012",
            52,
            "20000000-0000-4000-8000-000000000012",
            "realtime",
        );
        let outcome = ingest_verified_native_messages(&db, batch(vec![input]))
            .await
            .unwrap();
        let inserted = row(&outcome.messages[0]);
        let invalidation =
            tokio::time::timeout(std::time::Duration::from_secs(2), subscriber.recv())
                .await
                .expect("replicated commit wakes the realtime pump")
                .unwrap();
        assert_eq!(invalidation.local_seq, inserted.local_seq);
        assert_eq!(invalidation.id, inserted.id);
        assert_eq!(invalidation.record_id, inserted.record_id);
        assert_eq!(invalidation.event_type, "record.created");
    }

    #[tokio::test]
    async fn physical_snapshot_preserves_provenance_and_duplicate_stays_silent() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("source.db");
        let exported_path = dir.path().join("exported.db");
        let db = crate::create_database(&source_path.to_string_lossy())
            .await
            .unwrap();
        let input = message(
            "10000000-0000-4000-8000-000000000013",
            53,
            "20000000-0000-4000-8000-000000000013",
            "survives export",
        );
        ingest_verified_native_messages(&db, batch(vec![input.clone()]))
            .await
            .unwrap();
        let before: (String, String, i64, String, String, String) = sqlx::query_as(
            "SELECT event_id, origin_database_id, source_seq, source_record_id,
                    source_principal, source_fingerprint
               FROM content_event_sources WHERE event_id = ?",
        )
        .bind(&input.event_id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();

        sqlx::query(&format!(
            "VACUUM INTO '{}'",
            exported_path.to_string_lossy().replace('\'', "''")
        ))
        .execute(db.write_pool())
        .await
        .unwrap();
        db.close().await;

        let reopened = crate::open_existing_database_at(&exported_path)
            .await
            .unwrap();
        let (reopened, hub) = crate::realtime::RealtimeHub::install(reopened)
            .await
            .unwrap();
        let mut subscriber = hub.subscribe();
        let after: (String, String, i64, String, String, String) = sqlx::query_as(
            "SELECT event_id, origin_database_id, source_seq, source_record_id,
                    source_principal, source_fingerprint
               FROM content_event_sources WHERE event_id = ?",
        )
        .bind(&input.event_id)
        .fetch_one(reopened.write_pool())
        .await
        .unwrap();
        assert_eq!(after, before, "physical snapshot changed source facts");

        let events_before = count(&reopened, "content_events").await;
        let records_before = count(&reopened, "records").await;
        let replay = ingest_verified_native_messages(&reopened, batch(vec![input]))
            .await
            .unwrap();
        assert!(matches!(
            replay.messages[0],
            MessageIngestStatus::Duplicate(_)
        ));
        assert_eq!(count(&reopened, "content_events").await, events_before);
        assert_eq!(count(&reopened, "records").await, records_before);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(150), subscriber.recv())
                .await
                .is_err()
        );
        assert!(rebuild_and_diff(&reopened).await.unwrap().equal);
        reopened.close().await;
    }

    #[tokio::test]
    async fn ordinary_append_still_mints_and_has_no_source_sidecar() {
        let db = crate::create_database(":memory:").await.unwrap();
        let event = append(
            &db,
            AppendSpec {
                record_id: "4e900000-0000-4000-8000-000000000002".into(),
                event_type: "record.created".into(),
                payload: json!({
                    "type": "Message",
                    "kind": "text",
                    "name": "minted"
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(Uuid::parse_str(&event.id).unwrap().get_version_num(), 4);
        let sources: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_event_sources WHERE event_id = ?")
                .bind(event.id)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(sources, 0);
    }
}
