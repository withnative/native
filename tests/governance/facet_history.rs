//! The `facet_observations` valid-time projection: one universal history fold
//! alongside `facet_values`, with deterministic correction semantics and
//! rebuild coverage.

use native_ce::conformance::{check_required_tables, rebuild_and_diff};
use native_ce::events::{FacetSetPayload, FacetUnsetPayload};
use native_ce::query::sql;
use native_ce::store::{append, create_record, set_facet, AppendSpec};
use native_ce::{create_database, Db};
use serde_json::json;
use sqlx::Row;

async fn set_at(
    db: &Db,
    record_id: &str,
    key: &str,
    value: Option<&str>,
    as_of: &str,
) -> native_ce::events::EventRow {
    append(
        db,
        AppendSpec {
            record_id: record_id.into(),
            event_type: "facet.set".into(),
            payload: serde_json::to_value(FacetSetPayload {
                key: key.into(),
                value: value.map(str::to_string),
                vocab_ref: None,
                as_of: Some(as_of.into()),
                observation_only: false,
            })
            .unwrap(),
            actor: None,
        },
    )
    .await
    .unwrap()
}

async fn unset_at(db: &Db, record_id: &str, key: &str, as_of: &str) -> native_ce::events::EventRow {
    append(
        db,
        AppendSpec {
            record_id: record_id.into(),
            event_type: "facet.unset".into(),
            payload: serde_json::to_value(FacetUnsetPayload {
                key: key.into(),
                as_of: Some(as_of.into()),
                observation_only: false,
            })
            .unwrap(),
            actor: None,
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn set_set_unset_is_a_three_point_series_ordered_by_valid_time() {
    let db = create_database(":memory:").await.unwrap();
    let record_id = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "metric" }),
    )
    .await
    .unwrap();

    // A set-to-NULL remains distinguishable from the final unset through `op`.
    let first = set_at(&db, &record_id, "current", None, "2026-07-01").await;
    let second = set_at(&db, &record_id, "current", Some("12"), "2026-07-02").await;
    let third = unset_at(&db, &record_id, "current", "2026-07-03").await;

    let rows = sqlx::query(
        "SELECT id, value, op, as_of, event_seq
           FROM facet_observations
          WHERE record_id = ? AND key = 'current'
          ORDER BY as_of",
    )
    .bind(&record_id)
    .fetch_all(db.pool())
    .await
    .unwrap();
    let actual: Vec<(String, Option<String>, String, String, i64)> = rows
        .iter()
        .map(|row| {
            (
                row.get("id"),
                row.get("value"),
                row.get("op"),
                row.get("as_of"),
                row.get("event_seq"),
            )
        })
        .collect();
    assert_eq!(
        actual,
        vec![
            (
                format!("fo:{record_id}:current:2026-07-01"),
                None,
                "set".into(),
                "2026-07-01".into(),
                first.local_seq,
            ),
            (
                format!("fo:{record_id}:current:2026-07-02"),
                Some("12".into()),
                "set".into(),
                "2026-07-02".into(),
                second.local_seq,
            ),
            (
                format!("fo:{record_id}:current:2026-07-03"),
                None,
                "unset".into(),
                "2026-07-03".into(),
                third.local_seq,
            ),
        ]
    );
    assert!(
        sql::query_sql(
            &db,
            &native_ce::mcp::Caller::authenticated("test-account"),
            "SELECT as_of, value FROM facet_observations ORDER BY as_of"
        )
        .await
        .is_ok(),
        "the observation series must be available through query_sql"
    );
    db.close().await;
}

#[tokio::test]
async fn a_correction_at_the_same_valid_time_upserts_the_natural_key() {
    let db = create_database(":memory:").await.unwrap();
    let record_id = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "metric" }),
    )
    .await
    .unwrap();
    let as_of = "2026-07-01T00:00:00Z";

    set_at(&db, &record_id, "current", Some("10"), as_of).await;
    let correction = set_at(&db, &record_id, "current", Some("11"), as_of).await;

    let row = sqlx::query(
        "SELECT id, value, op, event_seq, COUNT(*) OVER () AS n
           FROM facet_observations
          WHERE record_id = ? AND key = 'current'",
    )
    .bind(&record_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(row.get::<i64, _>("n"), 1);
    assert_eq!(
        row.get::<String, _>("id"),
        format!("fo:{record_id}:current:{as_of}")
    );
    assert_eq!(row.get::<String, _>("value"), "11");
    assert_eq!(row.get::<String, _>("op"), "set");
    assert_eq!(row.get::<i64, _>("event_seq"), correction.local_seq);
    db.close().await;
}

#[tokio::test]
async fn spine_facets_are_excluded_but_archived_is_observed() {
    let db = create_database(":memory:").await.unwrap();
    let record_id = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "subject" }),
    )
    .await
    .unwrap();

    set_facet(
        &db,
        &record_id,
        FacetSetPayload {
            key: "lifecycle".into(),
            value: Some("active".into()),
            vocab_ref: None,
            as_of: Some("2026-07-01".into()),
            observation_only: false,
        },
    )
    .await
    .unwrap();
    set_at(&db, &record_id, "archived", Some("true"), "2026-07-02").await;
    unset_at(&db, &record_id, "archived", "2026-07-03").await;

    let spine_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM facet_observations
          WHERE record_id = ? AND key = 'lifecycle'",
    )
    .bind(&record_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(spine_count, 0);

    let archive_ops: Vec<String> = sqlx::query_scalar(
        "SELECT op FROM facet_observations
          WHERE record_id = ? AND key = 'archived' ORDER BY as_of",
    )
    .bind(&record_id)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(archive_ops, vec!["set", "unset"]);
    db.close().await;
}

#[tokio::test]
async fn payload_valid_time_overrides_transaction_time_and_absence_defaults_to_it() {
    let db = create_database(":memory:").await.unwrap();
    let record_id = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "metric" }),
    )
    .await
    .unwrap();

    let backfill = set_at(
        &db,
        &record_id,
        "current",
        Some("10"),
        "2026-01-01T00:00:00Z",
    )
    .await;
    let row = sqlx::query(
        "SELECT as_of, observed_at FROM facet_observations
          WHERE record_id = ? AND key = 'current'",
    )
    .bind(&record_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("as_of"), "2026-01-01T00:00:00Z");
    assert_eq!(row.get::<String, _>("observed_at"), backfill.created_at);

    let event = append(
        &db,
        AppendSpec {
            record_id: record_id.clone(),
            event_type: "facet.set".into(),
            payload: json!({ "key": "confidence", "value": "high" }),
            actor: None,
        },
    )
    .await
    .unwrap();
    let defaulted: String = sqlx::query_scalar(
        "SELECT as_of FROM facet_observations
          WHERE record_id = ? AND key = 'confidence'",
    )
    .bind(&record_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(defaulted, event.created_at);

    assert_eq!(
        serde_json::to_value(FacetSetPayload {
            key: "confidence".into(),
            value: Some("high".into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        })
        .unwrap(),
        json!({ "key": "confidence", "value": "high" })
    );
    assert_eq!(
        serde_json::to_value(FacetUnsetPayload {
            key: "confidence".into(),
            as_of: None,
            observation_only: false,
        })
        .unwrap(),
        json!({ "key": "confidence" })
    );
    db.close().await;
}

#[tokio::test]
async fn rebuild_and_structural_conformance_cover_facet_observations() {
    let db = create_database(":memory:").await.unwrap();
    let record_id = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "metric" }),
    )
    .await
    .unwrap();
    set_at(&db, &record_id, "current", Some("10"), "2026-07-01").await;
    set_at(&db, &record_id, "current", Some("11"), "2026-07-01").await;
    set_at(&db, &record_id, "current", Some("12"), "2026-07-02").await;
    unset_at(&db, &record_id, "current", "2026-07-03").await;

    let rebuilt = rebuild_and_diff(&db).await.unwrap();
    assert!(rebuilt.equal, "{:?}", rebuilt.tables);
    assert!(
        rebuilt
            .tables
            .iter()
            .any(|table| table.table == "facet_observations"),
        "rebuild-and-diff did not include facet_observations"
    );
    assert!(check_required_tables(&db).await.unwrap().ok);

    sqlx::query("DROP TABLE facet_observations")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let required = check_required_tables(&db).await.unwrap();
    assert!(!required.ok);
    assert!(required
        .violations
        .contains(&"required table missing: facet_observations".into()));
    db.close().await;
}
