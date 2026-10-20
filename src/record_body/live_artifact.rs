//! Live artifact source and snapshot identity from one SQLite statement.

use sqlx::{sqlite::SqliteRow, Executor, Sqlite};

/// Latest three-family source carrying a top-level body, optionally strictly
/// before an event sequence. This is source identity selection, not an exact
/// event pin or projection-body read. Null/non-text count as present; SQLite's
/// first-duplicate semantics and malformed-JSON errors remain caller-visible.
/// Callers retain String decoding, missing-source errors and their executor.
pub(crate) async fn latest_present_source_on<'e, E>(
    executor: E,
    record_id: &str,
    exclusive_before_seq: Option<i64>,
) -> std::result::Result<Option<SqliteRow>, sqlx::Error>
where
    E: Executor<'e, Database = Sqlite>,
{
    latest_present_source_with_policy_on(
        executor,
        record_id,
        PresentSourceFamilies::ThreeFamily,
        exclusive_before_seq,
    )
    .await
}

/// Family policy is explicit: the plugin bridge historically accepts any
/// body-present event, whereas artifact attestations accept only three families.
#[derive(Clone, Copy)]
pub(crate) enum PresentSourceFamilies {
    ThreeFamily,
    Unrestricted,
}

fn present_source_sql(columns: &str, horizon: &str, families: PresentSourceFamilies) -> String {
    let family_filter = match families {
        PresentSourceFamilies::ThreeFamily => {
            " AND type IN ('record.created','record.updated','receipt.committed.v1')"
        }
        PresentSourceFamilies::Unrestricted => "",
    };
    format!(
        "SELECT {columns} FROM content_events WHERE record_id=?{horizon}{family_filter}
           AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1"
    )
}

/// Optional source row, retaining caller-owned String decoding and executor.
/// The existing exclusive API above always selects the three-family policy.
pub(crate) async fn latest_present_source_with_policy_on<'e, E>(
    executor: E,
    record_id: &str,
    families: PresentSourceFamilies,
    exclusive_before_seq: Option<i64>,
) -> std::result::Result<Option<SqliteRow>, sqlx::Error>
where
    E: Executor<'e, Database = Sqlite>,
{
    let horizon = if exclusive_before_seq.is_some() {
        " AND seq < ?"
    } else {
        ""
    };
    let sql = present_source_sql(
        "id,json_extract(payload,'$.body') AS body",
        horizon,
        families,
    );
    let mut query = sqlx::query(&sql).bind(record_id);
    if let Some(before_seq) = exclusive_before_seq {
        query = query.bind(before_seq);
    }
    query.fetch_optional(executor).await
}

/// Receipt replay's inclusive three-family previous body. Decode as a nullable
/// scalar before flattening: SQL NULL must stay None, unlike SQLite String
/// decoding. Missing/bodyless, duplicate keys and malformed SQL stay lenient.
pub(crate) async fn latest_present_body_through_on<'e, E>(
    executor: E,
    record_id: &str,
    inclusive_through_seq: i64,
) -> std::result::Result<Option<String>, sqlx::Error>
where
    E: Executor<'e, Database = Sqlite>,
{
    let sql = present_source_sql(
        "json_extract(payload,'$.body')",
        " AND seq <= ?",
        PresentSourceFamilies::ThreeFamily,
    );
    Ok(sqlx::query_scalar::<_, Option<String>>(&sql)
        .bind(record_id)
        .bind(inclusive_through_seq)
        .fetch_optional(executor)
        .await?
        .flatten())
}

/// Read a live governed artifact with its latest three-family present body.
/// JSON null/non-text count; SQLite keeps the first duplicate and malformed
/// JSON remains a SQL error. No projection-body substitution or cell cap.
///
/// `governed_identity_predicate` is trusted internal SQL constructed by the
/// caller for alias `r`, preserving its existing Document/artifact governance.
/// It must never contain user input. This reader grants no authority, opens no
/// transaction and retains nullable columns and SQLx errors for caller decoding.
pub(crate) async fn live_artifact_body_source_on<'e, E>(
    executor: E,
    artifact_id: &str,
    governed_identity_predicate: &str,
) -> std::result::Result<Option<SqliteRow>, sqlx::Error>
where
    E: Executor<'e, Database = Sqlite>,
{
    let sql = format!(
        "WITH body_source AS (
             SELECT e.id, e.seq, json_extract(e.payload, '$.body') AS body
               FROM content_events e
              WHERE e.record_id = ?
                AND e.type IN ('record.created', 'record.updated', 'receipt.committed.v1')
                AND json_type(e.payload, '$.body') IS NOT NULL
              ORDER BY e.seq DESC
              LIMIT 1
         )
         SELECT body_source.id AS body_event_id, body_source.body, body_source.seq AS body_event_seq,
                (SELECT id FROM content_events ORDER BY seq DESC LIMIT 1) AS snapshot_event_id,
                (SELECT COALESCE(MAX(seq), 0) FROM content_events) AS snapshot_event_seq,
                f.value AS runtime FROM records r
           LEFT JOIN body_source ON TRUE
           LEFT JOIN facet_values f ON f.record_id = r.id AND f.key = 'runtime'
          WHERE r.id = ? AND r.deleted_at IS NULL AND {governed_identity_predicate}"
    );
    sqlx::query(&sql)
        .bind(artifact_id)
        .bind(artifact_id)
        .fetch_optional(executor)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    #[tokio::test]
    async fn inclusive_nullable_body_keeps_horizon_family_and_sql_decoding() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        assert_eq!(
            latest_present_body_through_on(&mut *tx, "fixture", i64::MAX)
                .await
                .unwrap(),
            None
        );
        for (payload, expected) in [
            (r#"{"body":"café🦮"}"#, Some("café🦮")),
            (r#"{"body":"first","body":"last"}"#, Some("first")),
            (r#"{"body":null,"body":"last"}"#, None),
            (r#"{"body":""}"#, Some("")),
            (r#"{"body":{"key":"value"}}"#, Some(r#"{"key":"value"}"#)),
            (r#"{"body":["value"]}"#, Some(r#"["value"]"#)),
        ] {
            let id = uuid::Uuid::new_v4().to_string();
            let seq: i64 = sqlx::query_scalar("INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) VALUES (?,'fixture','receipt.committed.v1',?,1,'legacy_unknown') RETURNING seq")
                .bind(&id).bind(payload).fetch_one(&mut *tx).await.unwrap();
            let body = latest_present_body_through_on(&mut *tx, "fixture", seq)
                .await
                .unwrap();
            assert_eq!(body.as_deref(), expected, "{payload}");
            let source = latest_present_source_on(&mut *tx, "fixture", None)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(source.try_get::<String, _>("id").unwrap(), id);
            assert_eq!(
                source.try_get::<String, _>("body").unwrap(),
                expected.unwrap_or("")
            );
            // Same-transaction visibility, with an inclusive exact-sequence head.
            if payload.contains("café") {
                assert_eq!(body.unwrap().chars().count(), 5);
                assert!(latest_present_source_on(&mut *tx, "fixture", Some(seq))
                    .await
                    .unwrap()
                    .is_none());
            }
        }
        let before: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        for (family, payload) in [
            ("record.updated", "{}"),
            ("unit.revision.recorded.v1", r#"{"body":"excluded"}"#),
            ("other.family", r#"{"body":"excluded"}"#),
        ] {
            sqlx::query("INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) VALUES (?,'fixture',?,?,1,'legacy_unknown')")
                .bind(uuid::Uuid::new_v4().to_string()).bind(family).bind(payload).execute(&mut *tx).await.unwrap();
        }
        assert_eq!(
            latest_present_body_through_on(&mut *tx, "fixture", i64::MAX)
                .await
                .unwrap(),
            latest_present_body_through_on(&mut *tx, "fixture", before)
                .await
                .unwrap()
        );
        for payload in [r#"{"body":42}"#, r#"{"body":true}"#] {
            sqlx::query("INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) VALUES (?,'fixture','record.updated',?,1,'legacy_unknown')")
                .bind(uuid::Uuid::new_v4().to_string()).bind(payload).execute(&mut *tx).await.unwrap();
            assert!(matches!(
                latest_present_body_through_on(&mut *tx, "fixture", i64::MAX).await,
                Err(sqlx::Error::ColumnDecode { .. })
            ));
        }
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn inclusive_nullable_body_keeps_malformed_sql_errors_at_exact_horizon() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let valid: i64 = sqlx::query_scalar("INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) VALUES (?,'fixture','record.created','{\"body\":\"café🦮\"}',1,'legacy_unknown') RETURNING seq")
            .bind(uuid::Uuid::new_v4().to_string()).fetch_one(&mut *tx).await.unwrap();
        // Isolate a disposable malformed legacy INSERT. Never disable the
        // immutable append guards; restore metadata admission before reading.
        let ddl: String = sqlx::query_scalar("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='content_event_claim_meta_insert'")
            .fetch_one(&mut *tx).await.unwrap();
        sqlx::query("DROP TRIGGER content_event_claim_meta_insert")
            .persistent(false)
            .execute(&mut *tx)
            .await
            .unwrap();
        let malformed: i64 = sqlx::query_scalar("INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) VALUES (?,'fixture','record.updated','{malformed',1,'legacy_unknown') RETURNING seq")
            .bind(uuid::Uuid::new_v4().to_string()).fetch_one(&mut *tx).await.unwrap();
        sqlx::query(&ddl)
            .persistent(false)
            .execute(&mut *tx)
            .await
            .unwrap();
        assert_eq!(
            latest_present_body_through_on(&mut *tx, "fixture", valid)
                .await
                .unwrap()
                .as_deref(),
            Some("café🦮")
        );
        let error = latest_present_body_through_on(&mut *tx, "fixture", malformed)
            .await
            .unwrap_err();
        assert!(matches!(error, sqlx::Error::Database(_)));
        assert!(error.to_string().contains("malformed JSON"));
        tx.rollback().await.unwrap();
    }
}
