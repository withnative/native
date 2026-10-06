//! E3 M3 increment 2A: physical `body_task_items` projection and its live
//! fold conformance with the GFM extractor.
//!
//! Contract under test: the table is a pure function of each record's current
//! body — creation scans the stored body, an update carrying a body deletes
//! and re-scans, an update naming no body leaves rows and provenance alone,
//! null/empty bodies yield no rows, and a tombstone keeps rows (deletion
//! carries no body; the caller-visible view excludes deleted records). Every
//! stored row matches `extract_task_items` exactly, including marker spelling,
//! flags, byte offsets and the supplying event's sequence.

use native_ce::store::{create_record, delete_record, update_record};
use native_ce::{create_database, Db};
use serde_json::json;

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

async fn doc(db: &Db, name: &str, body: serde_json::Value) -> String {
    let mut fields = json!({"type": "Document", "kind": "note", "name": name});
    if !body.is_null() {
        fields["body"] = body;
    }
    create_record(db, fields).await.unwrap()
}

type TaskRow = (i64, i64, String, i64, i64, i64, i64);

async fn task_rows(db: &Db, id: &str) -> Vec<TaskRow> {
    sqlx::query_as(
        "SELECT item_index, source_event_seq, marker,
                checked, in_quote, start_offset, end_offset
         FROM body_task_items WHERE record_id = ? ORDER BY item_index",
    )
    .bind(id)
    .fetch_all(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap()
}

/// The live fold stores exactly what the extractor finds: marker spelling,
/// flags, offsets and the supplying event sequence.
#[tokio::test]
async fn create_folds_extractor_rows_with_body_provenance() {
    let db = db().await;
    let body =
        "- [ ] dash\n* [x] star done\n> + [ ] quoted\n```\n- [ ] fenced\n```\n1. [ ] ordered";
    let id = doc(&db, "tasks", json!(body)).await;
    let expected = native_ce::body_task_items::extract_task_items(body).unwrap();
    assert_eq!(expected.len(), 4);
    let rows = task_rows(&db, &id).await;
    assert_eq!(rows.len(), expected.len());
    // One body writer (the create event): every row shares its sequence.
    let first_seq = rows[0].1;
    assert!(first_seq > 0);
    assert!(rows.iter().all(|row| row.1 == first_seq));
    for (row, item) in rows.iter().zip(expected.iter()) {
        assert_eq!(row.0, item.index as i64);
        assert_eq!(
            row.2,
            native_ce::body_task_items::TaskMarker::as_str(&item.marker).unwrap()
        );
        assert_eq!(row.3, i64::from(item.checked));
        assert_eq!(row.4, i64::from(item.in_quote));
        assert_eq!(row.5, item.start_offset as i64);
        assert_eq!(row.6, item.end_offset as i64);
    }
    db.close().await;
}

/// A carried body replaces rows with the new body's provenance; a body-less
/// update leaves rows and provenance untouched; null/empty bodies clear rows.
#[tokio::test]
async fn update_body_replaces_while_metadata_update_preserves() {
    let db = db().await;
    let id = doc(&db, "tasks", json!("- [ ] first\n- [ ] second")).await;
    let created = task_rows(&db, &id).await;
    assert_eq!(created.len(), 2);
    let created_seq = created[0].1;

    update_record(&db, &id, json!({"summary": "metadata only"}))
        .await
        .unwrap();
    let kept = task_rows(&db, &id).await;
    assert_eq!(kept.len(), 2);
    assert!(kept.iter().all(|row| row.1 == created_seq));

    update_record(&db, &id, json!({"body": "+ [ ] replaced"}))
        .await
        .unwrap();
    let replaced = task_rows(&db, &id).await;
    assert_eq!(replaced.len(), 1);
    assert_eq!(replaced[0].2, "+");
    assert!(replaced[0].1 > 1);

    update_record(&db, &id, json!({"body": ""})).await.unwrap();
    assert!(task_rows(&db, &id).await.is_empty());

    update_record(&db, &id, json!({"body": "- [ ] back"}))
        .await
        .unwrap();
    assert_eq!(task_rows(&db, &id).await.len(), 1);
    update_record(&db, &id, json!({"body": null}))
        .await
        .unwrap();
    assert!(task_rows(&db, &id).await.is_empty());
    db.close().await;
}

/// Body-less, non-string and task-free bodies yield no rows; a tombstone
/// keeps the rows its last body supplied.
#[tokio::test]
async fn empty_and_tombstoned_bodies_behave() {
    let db = db().await;
    let no_body = doc(&db, "no-body", serde_json::Value::Null).await;
    assert!(task_rows(&db, &no_body).await.is_empty());
    let number = doc(&db, "number", json!(5)).await;
    assert!(task_rows(&db, &number).await.is_empty());
    let prose = doc(&db, "prose", json!("just words, no tasks")).await;
    assert!(task_rows(&db, &prose).await.is_empty());

    let doomed = doc(&db, "doomed", json!("- [ ] doomed task")).await;
    assert_eq!(task_rows(&db, &doomed).await.len(), 1);
    delete_record(&db, &doomed).await.unwrap();
    let kept = task_rows(&db, &doomed).await;
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].2, "-");
    db.close().await;
}
