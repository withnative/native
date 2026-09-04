//! Engine-owned read seams for hosted federation.
//!
//! The hosted federation adapter may consume coherent source bytes and opaque
//! revision counters, but it does not receive a database pool or participate
//! in SQLite transaction and authorization details.

use serde_json::{json, Value};
use sqlx::Row;

use crate::{Db, Error, Result};

/// Record bytes and content-event revision captured from one SQLite snapshot.
#[doc(hidden)]
pub struct FederatedRecordSnapshot {
    pub record: Value,
    pub revision: i64,
}

/// Capture every field materialization may select from one authorized SQLite
/// read snapshot.
#[doc(hidden)]
pub async fn capture_federated_record_snapshot(
    db: &Db,
    caller_identity: &str,
    record_id: &str,
) -> Result<Option<FederatedRecordSnapshot>> {
    capture_federated_record_snapshot_with_hook(db, caller_identity, record_id, || async { Ok(()) })
        .await
}

/// Return the authorization revision used to invalidate a federated source or
/// cursor when its effective access changes.
#[doc(hidden)]
pub async fn federated_authorization_revision(db: &Db) -> Result<i64> {
    crate::authorization::authorization_revision(db).await
}

/// Return the content and metadata revisions disclosed for one completed
/// constituent federated read.
#[doc(hidden)]
pub async fn federated_engine_revision(db: &Db) -> Result<Value> {
    let content_revision: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
            .fetch_one(db.write_pool())
            .await?;
    let meta_revision: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM meta_events")
        .fetch_one(db.write_pool())
        .await?;
    Ok(json!({
        "content_event_seq": content_revision,
        "meta_event_seq": meta_revision,
    }))
}

/// Private scheduling seam for the deterministic WAL race test. Production
/// always enters through [`capture_federated_record_snapshot`].
async fn capture_federated_record_snapshot_with_hook<F, Fut>(
    db: &Db,
    caller_identity: &str,
    record_id: &str,
    after_selected_reads: F,
) -> Result<Option<FederatedRecordSnapshot>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let mut tx = db.write_pool().begin().await?;
    if crate::authorization::require_capability_on(
        &mut tx,
        crate::authorization::Principal::bound(caller_identity, true),
        record_id,
        crate::authorization::Capability::View,
    )
    .await
    .is_err()
    {
        tx.rollback().await?;
        return Ok(None);
    }
    // The first read establishes SQLite's snapshot before any selected bytes
    // are fetched. All later reads, including the test's post-race check, see
    // this exact point in the WAL history.
    let revision: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events WHERE record_id=?")
            .bind(record_id)
            .fetch_one(&mut *tx)
            .await?;
    let Some(row) =
        sqlx::query("SELECT type,kind,name,summary,body,updated_at FROM records WHERE id=?")
            .bind(record_id)
            .fetch_optional(&mut *tx)
            .await?
    else {
        tx.commit().await?;
        return Ok(None);
    };
    let facets = sqlx::query(
        "SELECT key,value,vocab_ref FROM facet_values \
             WHERE record_id=? AND key <> 'archived' ORDER BY key",
    )
    .bind(record_id)
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .map(|facet| {
        Ok(json!({
            "key": facet.try_get::<String, _>("key")?,
            "value": facet.try_get::<Option<String>, _>("value")?,
            "vocab_ref": facet.try_get::<Option<String>, _>("vocab_ref")?,
        }))
    })
    .collect::<Result<Vec<_>>>()?;
    let record = json!({
        "type": row.try_get::<String, _>("type")?,
        "kind": row.try_get::<Option<String>, _>("kind")?,
        "name": row.try_get::<String, _>("name")?,
        "summary": row.try_get::<Option<String>, _>("summary")?,
        "body": row.try_get::<Option<String>, _>("body")?,
        "facets": facets,
        "updated_at": row.try_get::<String, _>("updated_at")?,
    });

    after_selected_reads().await?;
    let snapshot_revision: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events WHERE record_id=?")
            .bind(record_id)
            .fetch_one(&mut *tx)
            .await?;
    if revision != snapshot_revision {
        return Err(Error::engine("SOURCE_CAPTURE_UNSTABLE"));
    }
    tx.commit().await?;
    Ok(Some(FederatedRecordSnapshot { record, revision }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn source_capture_keeps_selected_bytes_and_revision_on_one_wal_snapshot() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let record_id = "fed00000-0000-4000-8000-000000000001";
        let created = crate::store::append(
            &db,
            crate::store::AppendSpec {
                record_id: record_id.into(),
                event_type: "record.created".into(),
                payload: json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "before",
                    "body": "old bytes",
                    "persistence": "enduring"
                }),
                actor: Some("test".into()),
            },
        )
        .await
        .unwrap();
        let writer = db.clone();
        let captured = capture_federated_record_snapshot_with_hook(
            &db,
            "local",
            record_id,
            move || async move {
                crate::store::append(
                    &writer,
                    crate::store::AppendSpec {
                        record_id: record_id.into(),
                        event_type: "record.updated".into(),
                        payload: json!({"name": "after", "body": "new bytes"}),
                        actor: Some("test".into()),
                    },
                )
                .await?;
                Ok(())
            },
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(captured.revision, created.local_seq);
        assert_eq!(captured.record["name"], "before");
        assert_eq!(captured.record["body"], "old bytes");
        let current_revision: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events WHERE record_id=?")
                .bind(record_id)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        let current_name: String = sqlx::query_scalar("SELECT name FROM records WHERE id=?")
            .bind(record_id)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert!(current_revision > captured.revision);
        assert_eq!(current_name, "after");
    }
}
