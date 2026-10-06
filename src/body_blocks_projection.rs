//! SQLite physical body-block fold and v74→75 backfill.
//!
//! This is intentionally separate from the pure parser. Every persisted row
//! names the exact event that supplied the current body. Backfill verifies
//! the event's coerced bytes against `records.body`, so it cannot guess the
//! Markdown/opaque format from a JSON-looking TEXT value.

use serde_json::Value;
use sqlx::{Row, SqliteConnection};

use crate::body_blocks::{self, BodyFormat};
use crate::error::{Error, Result};

pub(crate) fn event_body_value<'a>(event_type: &str, payload: &'a Value) -> Option<&'a Value> {
    match event_type {
        "record.created" | "record.updated" | "receipt.committed.v1" => payload.get("body"),
        "unit.revision.recorded.v1" => payload.get("content")?.get("content"),
        _ => None,
    }
}

pub(crate) fn body_format(value: &Value) -> BodyFormat {
    if value.is_string() {
        BodyFormat::Markdown
    } else {
        BodyFormat::Opaque
    }
}

/// Replace all rows for one body-writing event. Extraction and admission run
/// before the DELETE; the caller's event transaction owns both operations.
pub(crate) async fn replace_sqlite(
    conn: &mut SqliteConnection,
    record_id: &str,
    source_event_seq: i64,
    body: Option<&str>,
    format: BodyFormat,
) -> Result<()> {
    let chunks = body_blocks::extract_projectable_body_blocks(body, format).map_err(|error| {
        Error::engine(format!(
            "body_blocks extraction failed for record {record_id}: {error}"
        ))
    })?;
    sqlx::query("DELETE FROM body_blocks WHERE record_id=?")
        .bind(record_id)
        .execute(&mut *conn)
        .await?;
    for chunk in &chunks {
        let heading_path = serde_json::to_string(&chunk.heading_path)?;
        sqlx::query(
            "INSERT INTO body_blocks
             (record_id,block_index,chunk_index,chunk_count,source_event_seq,
              heading_path,block_kind,text,start_offset,end_offset)
             VALUES(?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(record_id)
        .bind(chunk.block_index as i64)
        .bind(chunk.chunk_index as i64)
        .bind(chunk.chunk_count as i64)
        .bind(source_event_seq)
        .bind(heading_path)
        .bind(chunk.block_kind)
        .bind(&chunk.text)
        .bind(chunk.start_offset as i64)
        .bind(chunk.end_offset as i64)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Backfill one record at a time to bound memory even for a large workspace.
/// A nonempty stored body with missing or mismatched event provenance refuses
/// the whole migration transaction. No row is silently classified as Markdown.
pub(crate) async fn backfill_sqlite(conn: &mut SqliteConnection) -> Result<()> {
    let provenance_sql = format!(
        "SELECT seq,type,payload FROM content_events WHERE record_id=? AND ({}) ORDER BY seq DESC LIMIT 1",
        crate::record_body::BODY_CARRYING_EVENT_SQL
    );
    let mut after = String::new();
    loop {
        let source = sqlx::query(
            "SELECT id,body FROM records WHERE id>? AND typeof(body)='text' AND body<>'' ORDER BY id LIMIT 1",
        )
        .bind(&after)
        .fetch_optional(&mut *conn)
        .await?;
        let Some(source) = source else { break };
        let record_id: String = source.try_get("id")?;
        let body: String = source.try_get("body")?;
        let provenance = sqlx::query(&provenance_sql)
            .bind(&record_id)
            .fetch_optional(&mut *conn)
            .await?
            .ok_or_else(|| {
                Error::engine(format!(
                    "engine-75 backfill refuses nonempty body without event provenance for record {record_id}"
                ))
            })?;
        let seq: i64 = provenance.try_get("seq")?;
        let event_type: String = provenance.try_get("type")?;
        let payload_text: String = provenance.try_get("payload")?;
        let payload: Value = serde_json::from_str(&payload_text)?;
        let value = event_body_value(&event_type, &payload).ok_or_else(|| {
            Error::engine(format!(
                "engine-75 backfill cannot identify body value for record {record_id} event {seq}"
            ))
        })?;
        if crate::record_body::coerce_body(value).as_deref() != Some(body.as_str()) {
            return Err(Error::engine(format!(
                "engine-75 backfill body bytes disagree with event {seq} for record {record_id}"
            )));
        }
        replace_sqlite(conn, &record_id, seq, Some(&body), body_format(value)).await?;
        after = record_id;
    }
    Ok(())
}
