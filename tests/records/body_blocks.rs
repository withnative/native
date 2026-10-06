use native_ce::store::{create_record, delete_record, update_record};
use native_ce::{
    body_blocks::{extract_projectable_body_blocks, BodyFormat},
    create_database,
};
use serde_json::json;

type BodyBlockRow = (i64, i64, i64, i64, String, String, String, i64, i64);

#[tokio::test]
async fn sqlite_blocks_reassemble_large_body_and_preserve_event_provenance() {
    let db = create_database(":memory:").await.unwrap();
    let body = format!("# A\n\n```\n{}\n```\n", "é".repeat(160_000));
    assert!(body.len() > 256 * 1024);
    let id = create_record(
        &db,
        json!({"type":"Document","kind":"note","name":"large","body":body.clone()}),
    )
    .await
    .unwrap();
    let pool = crate::common::fixture_write_pool(&db).await;
    let rows: Vec<BodyBlockRow> = sqlx::query_as(
        "SELECT block_index,chunk_index,chunk_count,source_event_seq,heading_path,block_kind,text,start_offset,end_offset FROM body_blocks WHERE record_id=? ORDER BY block_index,chunk_index"
    ).bind(&id).fetch_all(&pool).await.unwrap();
    let expected = extract_projectable_body_blocks(Some(&body), BodyFormat::Markdown).unwrap();
    assert_eq!(rows.len(), expected.len());
    assert_eq!(
        rows.iter().map(|row| row.6.as_str()).collect::<String>(),
        body
    );
    for (row, chunk) in rows.iter().zip(expected.iter()) {
        assert_eq!(
            (row.0, row.1, row.2, row.7, row.8),
            (
                chunk.block_index as i64,
                chunk.chunk_index as i64,
                chunk.chunk_count as i64,
                chunk.start_offset as i64,
                chunk.end_offset as i64
            )
        );
        assert_eq!(row.4, serde_json::to_string(&chunk.heading_path).unwrap());
        assert_eq!(row.5, chunk.block_kind);
        assert_eq!(row.6, chunk.text);
        assert!(row.6.len() <= 32 * 1024);
        assert_eq!(row.3, rows[0].3);
    }
    update_record(&db, &id, json!({"summary":"metadata"}))
        .await
        .unwrap();
    let seq: i64 =
        sqlx::query_scalar("SELECT MIN(source_event_seq) FROM body_blocks WHERE record_id=?")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(seq, rows[0].3);
    update_record(&db, &id, json!({"body":{"heading":"# opaque"}}))
        .await
        .unwrap();
    let kind: String = sqlx::query_scalar("SELECT block_kind FROM body_blocks WHERE record_id=?")
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kind, "opaque");
    delete_record(&db, &id).await.unwrap();
    let kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM body_blocks WHERE record_id=?")
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kept, 1);
    let diff = native_ce::conformance::rebuild_and_diff(&db).await.unwrap();
    assert!(
        diff.equal,
        "{}",
        serde_json::to_string(&diff.tables).unwrap()
    );
    db.close().await;
}

#[tokio::test]
async fn sqlite_oversized_body_update_preserves_previous_projection() {
    let db = create_database(":memory:").await.unwrap();
    let id = create_record(
        &db,
        json!({"type":"Document","kind":"note","name":"small","body":"# kept"}),
    )
    .await
    .unwrap();
    let pool = crate::common::fixture_write_pool(&db).await;
    let before: Vec<(i64,String)> = sqlx::query_as("SELECT source_event_seq,text FROM body_blocks WHERE record_id=? ORDER BY block_index,chunk_index")
        .bind(&id).fetch_all(&pool).await.unwrap();
    let huge = "x".repeat(native_ce::body_blocks::MAX_PROJECTED_BODY_BYTES + 1);
    let error = update_record(&db, &id, json!({"body":huge}))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("16777216-byte"), "{error}");
    let after: Vec<(i64,String)> = sqlx::query_as("SELECT source_event_seq,text FROM body_blocks WHERE record_id=? ORDER BY block_index,chunk_index")
        .bind(&id).fetch_all(&pool).await.unwrap();
    assert_eq!(after, before);
    let stored: String = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, "# kept");
    db.close().await;
}
