//! V1's current typed-time fold over retained events, within live View staging.
use crate::{domain_transaction, typed_time::TimeFacetType, Result};
use sqlx::{Row, SqliteConnection};

pub(super) async fn stage(conn: &mut SqliteConnection) -> Result<()> {
    sqlx::query(
        "CREATE TEMP TABLE facet_times (
         record_id TEXT,key TEXT,kind TEXT,all_day INTEGER,
         start_date TEXT,end_date TEXT,start_ms INTEGER,end_ms INTEGER,
         tz TEXT,tzdb_version TEXT)",
    )
    .execute(&mut *conn)
    .await?;
    // New snapshots retain v1's current projection, including an empty set,
    // so snapshot-only imports need no historical log to recover typing.
    sqlx::query(r#"CREATE TEMP TABLE _v2_time_snapshots(record_id TEXT PRIMARY KEY,payload TEXT);
        INSERT INTO temp._v2_time_snapshots
        SELECT v.id,json_extract(e.payload,'$.legacy.payload.facet_times')
        FROM temp._v2_visible v
        JOIN main.kernel_legacy_sql_events h ON h.seq=(
          SELECT max(p.seq) FROM main.kernel_legacy_sql_events p
          WHERE p.record_id=v.id AND p.source_stream='snapshot_provenance')
        JOIN main.content_events e ON e.seq=h.seq
        WHERE json_type(e.payload,'$.legacy.payload.facet_times')='array';
        INSERT INTO temp.facet_times
        SELECT s.record_id,json_extract(t.value,'$.key'),json_extract(t.value,'$.kind'),
          json_extract(t.value,'$.all_day'),json_extract(t.value,'$.start_date'),
          json_extract(t.value,'$.end_date'),json_extract(t.value,'$.start_ms'),
          json_extract(t.value,'$.end_ms'),json_extract(t.value,'$.tz'),
          json_extract(t.value,'$.tzdb_version')
        FROM temp._v2_time_snapshots s JOIN json_each(s.payload) t
        JOIN main.kernel_facets f ON f.record_id=s.record_id AND f.key=json_extract(t.value,'$.key')
        JOIN main.content_events current ON current.seq=f.event_seq
        WHERE f.value=json_extract(t.value,'$.value') AND current.type!='kernel.facet_observed.v1'"#)
        .execute(&mut *conn).await?;
    // Match projector::replace_facet_time / fold_facet_time_candidates:
    // current writes follow v1 source sequence, NOT as_of or import order.
    // Observation-only set/unset events never replace the current time row.
    // A native winning untyped write clears it, just as an untyped v1 set
    // does. An older losing native observation cannot clear the current row.
    // Materialize authorized rows before the caller's predicates can run.
    let rows = sqlx::query(
        r#"WITH writes AS (
          SELECT h.record_id,e.id,json_extract(e.payload,'$.legacy.payload.key') AS key,
           json_extract(e.payload,'$.legacy.payload.value') AS value,
           json_extract(e.payload,'$.legacy.payload.time_kind') AS time_kind,
           h.event_type,
           row_number() OVER (
             PARTITION BY h.record_id,json_extract(e.payload,'$.legacy.payload.key')
             ORDER BY json_extract(e.payload,'$.legacy.source.metadata.seq') DESC
           ) AS rank
          FROM temp._v2_visible v
          JOIN main.kernel_legacy_sql_events h ON h.record_id=v.id
          JOIN main.content_events e ON e.seq=h.seq
          WHERE h.source_stream='content_events'
           AND NOT EXISTS(SELECT 1 FROM temp._v2_time_snapshots s WHERE s.record_id=v.id)
           AND h.event_type IN ('facet.set','facet.unset')
           AND json_type(e.payload,'$.legacy.source.metadata.seq')='integer'
           AND coalesce(json_extract(e.payload,'$.legacy.payload.observation_only'),0)=0
         )
         SELECT w.* FROM writes w
         JOIN main.kernel_facets f ON f.record_id=w.record_id AND f.key=w.key
         JOIN main.content_events current ON current.seq=f.event_seq
         WHERE w.rank=1 AND w.event_type='facet.set' AND w.time_kind IS NOT NULL
          AND f.value=w.value AND current.type!='kernel.facet_observed.v1'"#,
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut dropped_rows = 0usize;
    let mut decoded = Vec::with_capacity(256);
    for row in rows {
        // Decode one retained row in isolation. Even JSON scalar type errors
        // are row defects; database/query failures outside decoding still fail.
        let time = (|| {
            let kind: String = row.try_get("time_kind").ok()?;
            let kind = TimeFacetType::parse(&kind)?;
            // Shared v1 decoder reads persisted offsets and tzdb tags, never
            // re-resolving a stored zone against today's timezone database.
            domain_transaction::facet_time_row(
                &row.try_get::<String, _>("id").ok()?,
                &row.try_get::<String, _>("key").ok()?,
                row.try_get::<Option<String>, _>("value").ok()?.as_deref(),
                kind,
            )
            .ok()
        })();
        let Some(time) = time else {
            dropped_rows += 1;
            continue;
        };
        decoded.push(serde_json::json!([
            row.try_get::<String, _>("record_id")?,
            row.try_get::<String, _>("key")?,
            time.kind.as_str(),
            i64::from(time.all_day),
            time.start_date,
            time.end_date,
            time.start_ms,
            time.end_ms,
            time.tz,
            time.tzdb_version,
        ]));
        if decoded.len() == 256 {
            insert_rows(conn, &decoded).await?;
            decoded.clear();
        }
    }
    insert_rows(conn, &decoded).await?;
    if dropped_rows != 0 {
        // Never log the event, record, key, kind, value or decoder error:
        // the diagnostic discloses only an aggregate over caller-visible rows.
        tracing::warn!(
            code = "facet_times_invalid_retained_row",
            dropped_rows,
            "Excluded invalid retained typed-time rows"
        );
    }
    Ok(())
}

// Bound each SQLx/SQLite handoff; one handoff per time row dominates dense
// history imports. JSON scalar extraction preserves the ten SQLite affinities.
async fn insert_rows(conn: &mut SqliteConnection, rows: &[serde_json::Value]) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO temp.facet_times SELECT
        json_extract(value,'$[0]'),json_extract(value,'$[1]'),
        json_extract(value,'$[2]'),json_extract(value,'$[3]'),
        json_extract(value,'$[4]'),json_extract(value,'$[5]'),
        json_extract(value,'$[6]'),json_extract(value,'$[7]'),
        json_extract(value,'$[8]'),json_extract(value,'$[9]') FROM json_each(?)",
    )
    .bind(serde_json::to_string(rows)?)
    .execute(conn)
    .await?;
    Ok(())
}
