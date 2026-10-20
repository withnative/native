//! Change-summary context heads: latest text body across every event family.
//! SQLite keeps its first duplicate key and refuses malformed JSON. This is
//! neither projected-body provenance nor the guarded pinned-source policy.

use sqlx::{sqlite::SqliteRow, Executor, Sqlite};

/// Read current record metadata and the exact selected body event atomically.
/// The inner join returns None for a missing record or no text-bearing event.
/// Missing/null/non-text bodies are skipped, without a json_valid guard or
/// event-family restriction. Callers retain authorization, String decoding,
/// digests, missing-row mapping and their transaction; no payload is transported.
pub(crate) async fn exact_context_head_on<'e, E>(
    executor: E,
    record_id: &str,
) -> std::result::Result<Option<SqliteRow>, sqlx::Error>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "SELECT r.type,r.kind,r.deleted_at,e.id AS body_event_id,
                json_extract(e.payload,'$.body') AS body
           FROM records r JOIN content_events e ON e.id=(
                SELECT id FROM content_events WHERE record_id=r.id
                 AND json_type(payload,'$.body')='text' ORDER BY seq DESC LIMIT 1)
          WHERE r.id=?",
    )
    .bind(record_id)
    .fetch_optional(executor)
    .await
}
