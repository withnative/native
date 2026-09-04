//! The meta-tier write path — append-event-then-project, atomically (ba9f97e).
//!
//! The analogue of `crate::store` for the system tier: we append the event to
//! the authoritative `meta_events` log, fold it into the meta projections via
//! `crate::projector::meta`, and commit. There are no ad-hoc writes of
//! `vocabularies`, `vocabulary_values` or `schema_config` anywhere outside the
//! meta projector.
//!
//! Every entry point takes the caller's transaction. That is not a stylistic
//! preference: the guards in `crate::meta::vocabulary` are read-check + write
//! pairs that must stay inside ONE write transaction (a concurrent writer could
//! otherwise interleave between check and mutation), and the append has to land
//! in that same transaction or a rejected mutation could leave an authoritative
//! event behind describing a write that never happened.

use serde_json::{json, Value};
use sqlx::Row;
use uuid::Uuid;

use crate::error::Result;
use crate::meta::events::MetaEventRow;
use crate::projector::meta::project_meta;
use crate::store::now_iso;

/// One meta event to append: the envelope fields plus a JSON payload.
pub(super) struct MetaAppendSpec {
    /// The meta row this event acts on — vocabulary id, value id, or
    /// `schema_config` row id.
    subject_id: String,
    event_type: String,
    payload: Value,
    actor: Option<String>,
}

impl MetaAppendSpec {
    /// A spec whose verb plus subject is the whole event (`vocabulary.deleted`,
    /// `vocab_value.promoted`/`.deprecated`/`.deleted`).
    pub(super) fn bare(subject_id: impl Into<String>, event_type: impl Into<String>) -> Self {
        Self {
            subject_id: subject_id.into(),
            event_type: event_type.into(),
            payload: json!({}),
            actor: None,
        }
    }

    /// A spec carrying a payload.
    pub(super) fn with_payload(
        subject_id: impl Into<String>,
        event_type: impl Into<String>,
        payload: Value,
    ) -> Self {
        Self {
            subject_id: subject_id.into(),
            event_type: event_type.into(),
            payload,
            actor: None,
        }
    }

    pub(super) fn with_actor(mut self, actor: Option<&str>) -> Self {
        self.actor = actor.map(String::from);
        self
    }
}

/// Append one meta event and fold it INSIDE an already-open write transaction.
/// The caller decides when to commit, so a guard that rejects after the append
/// rolls the event back with the mutation.
pub(super) async fn append_meta_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    spec: MetaAppendSpec,
) -> Result<MetaEventRow> {
    let payload = if spec.payload.is_null() {
        json!({})
    } else {
        spec.payload
    };
    let mut event = MetaEventRow {
        seq: -1, // filled in after insert
        id: Uuid::new_v4().to_string(),
        subject_id: spec.subject_id,
        event_type: spec.event_type,
        payload: Some(serde_json::to_string(&payload)?),
        actor: spec.actor,
        created_at: now_iso(),
    };
    let inserted = sqlx::query(
        "INSERT INTO meta_events (id, subject_id, type, payload, actor, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            RETURNING seq",
    )
    .bind(&event.id)
    .bind(&event.subject_id)
    .bind(&event.event_type)
    .bind(&event.payload)
    .bind(&event.actor)
    .bind(&event.created_at)
    .fetch_one(&mut **tx)
    .await?;
    event.seq = inserted.try_get::<i64, _>("seq")?;
    project_meta(&mut *tx, &event).await?;
    Ok(event)
}

/// Read the whole meta log in `seq` order — the input to the meta
/// rebuild-and-diff.
pub async fn read_all_meta_events(conn: &mut sqlx::SqliteConnection) -> Result<Vec<MetaEventRow>> {
    let rows = sqlx::query(
        "SELECT seq, id, subject_id, type, payload, actor, created_at
          FROM meta_events ORDER BY seq",
    )
    .fetch_all(conn)
    .await?;
    // try_get, not get: same contract as the content harness — a malformed log
    // must surface as a reportable error, never a decode panic.
    rows.into_iter()
        .map(|r| {
            Ok(MetaEventRow {
                seq: r.try_get("seq")?,
                id: r.try_get("id")?,
                subject_id: r.try_get("subject_id")?,
                event_type: r.try_get("type")?,
                payload: r.try_get("payload")?,
                actor: r.try_get("actor")?,
                created_at: r.try_get("created_at")?,
            })
        })
        .collect()
}
