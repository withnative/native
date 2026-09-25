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
    act_alloc: &mut crate::act::ActAllocation,
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
        "INSERT INTO meta_events (id, subject_id, type, payload, actor, created_at, act)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            RETURNING seq",
    )
    .bind(&event.id)
    .bind(&event.subject_id)
    .bind(&event.event_type)
    .bind(&event.payload)
    .bind(&event.actor)
    .bind(&event.created_at)
    .bind(act_alloc.get_or_allocate(&mut *tx).await?)
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
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter().map(row_from_sql).collect()
}

/// The meta-only act-range reader: exactly the rows whose `act` falls in the
/// half-open interval `(from_exclusive, to_inclusive]`, in `seq` order, decoded
/// by the same [`row_from_sql`] the full reader uses. Legacy rows whose act is
/// `NULL` never satisfy the strict `act > ?` predicate and are excluded.
#[allow(dead_code)] // R3 wires the bounded fold; the reader lands ahead of its caller.
pub(crate) async fn meta_events_in_act_range(
    conn: &mut sqlx::SqliteConnection,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<Vec<MetaEventRow>> {
    let rows = sqlx::query(
        "SELECT seq, id, subject_id, type, payload, actor, created_at
          FROM meta_events WHERE act > ? AND act <= ? ORDER BY seq",
    )
    .bind(from_exclusive_act)
    .bind(to_inclusive_act)
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter().map(row_from_sql).collect()
}

// try_get, not get: same contract as the content harness — a malformed log
// must surface as a reportable error, never a decode panic.
fn row_from_sql(r: sqlx::sqlite::SqliteRow) -> Result<MetaEventRow> {
    Ok(MetaEventRow {
        seq: r.try_get("seq")?,
        id: r.try_get("id")?,
        subject_id: r.try_get("subject_id")?,
        event_type: r.try_get("type")?,
        payload: r.try_get("payload")?,
        actor: r.try_get("actor")?,
        created_at: r.try_get("created_at")?,
    })
}

#[cfg(test)]
mod act_range_tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::db::create_database;
    use crate::meta::vocabulary::create_vocabulary;

    const LEGACY: &str = "meta-event-legacy-null-act";

    /// Bounded meta reads select exactly the half-open `(from, to]` interval,
    /// preserve `seq` order, exclude a legacy `NULL` act, and agree exactly with
    /// the full reader filtered to the same observed acts.
    #[tokio::test]
    async fn meta_events_in_act_range_is_bounded_ordered_and_excludes_null_acts() {
        let db = create_database(":memory:").await.unwrap();
        // Three real authored vocabularies, each committed by its own seam call
        // so each carries its own act stamp.
        for name in ["act-range-alpha", "act-range-beta", "act-range-gamma"] {
            create_vocabulary(&db, name, None).await.unwrap();
        }
        // A legacy grouping-unknown row: `NULL` act, schema-valid, narrow.
        sqlx::query(
            "INSERT INTO meta_events (id, subject_id, type, payload, actor, created_at, act)
             VALUES (?, 'voc:legacy', 'vocabulary.created', '{}', 'engine:seed',
                     '2026-01-01T00:00:00.000Z', NULL)",
        )
        .bind(LEGACY)
        .execute(db.write_pool())
        .await
        .unwrap();

        let mut conn = db.pool().acquire().await.unwrap();
        let full = read_all_meta_events(&mut conn).await.unwrap();

        let act_of: BTreeMap<i64, Option<i64>> = sqlx::query("SELECT seq, act FROM meta_events")
            .fetch_all(&mut *conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.get("seq"), row.get("act")))
            .collect();
        let mut acts: Vec<i64> = act_of.values().flatten().copied().collect();
        acts.sort_unstable();
        acts.dedup();
        assert!(
            acts.len() >= 3,
            "the test expects at least three stamped acts"
        );

        for (from_exclusive, to_inclusive) in
            [(acts[0], acts[2]), (acts[1], acts[2]), (acts[0], acts[1])]
        {
            let bounded = meta_events_in_act_range(&mut conn, from_exclusive, to_inclusive)
                .await
                .unwrap();
            assert!(bounded.windows(2).all(|pair| pair[0].seq < pair[1].seq));
            let expected: Vec<MetaEventRow> = full
                .iter()
                .filter(|event| {
                    act_of[&event.seq]
                        .is_some_and(|act| act > from_exclusive && act <= to_inclusive)
                })
                .cloned()
                .collect();
            assert_eq!(
                bounded, expected,
                "range ({from_exclusive}, {to_inclusive}]"
            );
            assert!(
                !bounded.iter().any(|event| event.id == LEGACY),
                "a NULL-act row never matches the range predicate"
            );
        }

        // Equal bounds are the empty half-open interval, not a widening.
        assert!(meta_events_in_act_range(&mut conn, acts[2], acts[2])
            .await
            .unwrap()
            .is_empty());
        // The NULL row is still part of the full log, proving it was excluded by
        // the predicate and not dropped by the decoder.
        assert!(full.iter().any(|event| event.id == LEGACY));
    }
}
