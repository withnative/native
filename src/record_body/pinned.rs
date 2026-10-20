//! Active top-level source pins, preserving each caller's SQLite contract.
//!
//! These readers intentionally do not use the strict budgeted JSON parser:
//! SQLite's first duplicate key wins, and some callers propagate malformed
//! JSON or SQL cell decoding errors. No payload is transported or transaction
//! opened here. Callers keep their authorization, decoding and budget checks.
//! Returned rows include id/record_id/type/seq so reconstruction can retain the
//! exact revision rather than substitute a newer body with the same bytes.

use sqlx::{sqlite::SqliteRow, Executor, Sqlite};

use crate::error::Result;

const SOURCE_TYPES: &str = "'record.created','record.updated','receipt.committed.v1'";
const GUARDED_TEXT: &str = "CASE WHEN json_valid(payload) THEN CASE WHEN json_type(payload,'$.body')='text' THEN json_extract(payload,'$.body') END END";
const GUARDED_TEXT_PRESENT: &str =
    "CASE WHEN json_valid(payload) THEN json_type(payload,'$.body')='text' ELSE 0 END";

pub(crate) enum ExactSourcePolicy<'a> {
    /// Malformed/non-text/null/absent bodies read as SQL NULL; no size cap.
    GuardedTextForRecord(&'a str),
    /// Select any present body (including JSON null), preserving SQL errors
    /// and leaving cell decoding to the caller.
    PresentBodyForRecord(&'a str),
    /// Recipe validates record identity, event family and body type itself,
    /// after lookup, preserving its diagnostic and validation ordering.
    AnyEvent,
}

pub(crate) async fn exact_source_on<'e, E>(
    executor: E,
    event_id: &str,
    policy: ExactSourcePolicy<'_>,
) -> Result<Option<SqliteRow>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let (body, body_type) = match policy {
        ExactSourcePolicy::GuardedTextForRecord(_) => (
            GUARDED_TEXT,
            "CASE WHEN json_valid(payload) THEN json_type(payload,'$.body') END",
        ),
        _ => (
            "json_extract(payload,'$.body')",
            "json_type(payload,'$.body')",
        ),
    };
    let mut sql = format!("SELECT id,record_id,type,seq,{body_type} AS body_type,{body} AS body FROM content_events WHERE id=?");
    let record_id = match policy {
        ExactSourcePolicy::GuardedTextForRecord(record_id) => {
            sql.push_str(&format!(
                " AND record_id=? AND type IN ({SOURCE_TYPES}) LIMIT 1"
            ));
            Some(record_id)
        }
        ExactSourcePolicy::PresentBodyForRecord(record_id) => {
            sql.push_str(&format!(" AND record_id=? AND type IN ({SOURCE_TYPES}) AND json_type(payload,'$.body') IS NOT NULL"));
            Some(record_id)
        }
        ExactSourcePolicy::AnyEvent => None,
    };
    let mut query = sqlx::query(&sql).bind(event_id);
    if let Some(record_id) = record_id {
        query = query.bind(record_id);
    }
    Ok(query.fetch_optional(executor).await?)
}

/// Latest text source, skipping malformed/null/non-text/bodyless events.
/// This is artifact classification's fallback, not latest-writer selection.
pub(crate) async fn latest_guarded_text_on<'e, E>(
    executor: E,
    record_id: &str,
) -> Result<Option<SqliteRow>>
where
    E: Executor<'e, Database = Sqlite>,
{
    Ok(sqlx::query(&format!(
        "SELECT id,record_id,type,seq,{GUARDED_TEXT} AS body FROM content_events
         WHERE record_id=? AND type IN ({SOURCE_TYPES}) AND {GUARDED_TEXT_PRESENT}
         ORDER BY seq DESC LIMIT 1"
    ))
    .bind(record_id)
    .fetch_optional(executor)
    .await?)
}

/// Recipe's exclusive publication fence: every present top-level body counts,
/// including JSON null/non-text; malformed JSON retains its SQL error.
pub(crate) async fn has_intervening_source_on<'e, E>(
    executor: E,
    record_id: &str,
    after: i64,
    before: Option<i64>,
) -> Result<i64>
where
    E: Executor<'e, Database = Sqlite>,
{
    let horizon = if before.is_some() { " AND seq<?" } else { "" };
    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM content_events
        WHERE record_id=? AND seq>?{horizon} AND type IN ({SOURCE_TYPES})
        AND json_type(payload,'$.body') IS NOT NULL)"
    );
    let mut query = sqlx::query_scalar(&sql).bind(record_id).bind(after);
    if let Some(before) = before {
        query = query.bind(before);
    }
    Ok(query.fetch_one(executor).await?)
}
