//! Event-derived typed-time read cache. No authority; reads join live View.
use crate::{
    domain_transaction, error::Error, events::EventRow, typed_time::TimeFacetType, Result,
};
use sqlx::{Row, SqliteConnection};

async fn refresh_on(conn: &mut SqliteConnection, record: Option<&str>) -> Result<()> {
    sqlx::query("CREATE TEMP TABLE IF NOT EXISTS _facet_time_refresh_targets(id TEXT PRIMARY KEY);
        CREATE TEMP TABLE IF NOT EXISTS _facet_time_snapshots(record_id TEXT PRIMARY KEY,payload TEXT);
        DELETE FROM temp._facet_time_refresh_targets; DELETE FROM temp._facet_time_snapshots;")
        .execute(&mut *conn).await?;
    if let Some(record) = record {
        sqlx::query("INSERT INTO temp._facet_time_refresh_targets SELECT id FROM main.kernel_records WHERE id=?")
            .bind(record).execute(&mut *conn).await?;
    } else {
        sqlx::query(
            "INSERT INTO temp._facet_time_refresh_targets SELECT id FROM main.kernel_records",
        )
        .execute(&mut *conn)
        .await?;
    }
    for table in ["kernel_facet_time_rows", "kernel_facet_time_invalid"] {
        if let Some(record) = record {
            sqlx::query(&format!("DELETE FROM {table} WHERE record_id=?"))
                .bind(record)
                .execute(&mut *conn)
                .await?;
        } else {
            sqlx::query(&format!("DELETE FROM {table}"))
                .execute(&mut *conn)
                .await?;
        }
    }
    // New snapshots retain v1's current projection, including an empty set,
    // so snapshot-only imports need no historical log to recover typing.
    sqlx::query(r#"INSERT INTO temp._facet_time_snapshots
        SELECT v.id,json_extract(e.payload,'$.legacy.payload.facet_times')
        FROM temp._facet_time_refresh_targets v
        JOIN main.kernel_legacy_sql_events h ON h.seq=(
          SELECT max(p.seq) FROM main.kernel_legacy_sql_events p
          WHERE p.record_id=v.id AND p.source_stream='snapshot_provenance')
        JOIN main.content_events e ON e.seq=h.seq
        WHERE json_type(e.payload,'$.legacy.payload.facet_times')='array';
        INSERT INTO main.kernel_facet_time_rows
        SELECT s.record_id,json_extract(t.value,'$.key'),json_extract(t.value,'$.kind'),
          json_extract(t.value,'$.all_day'),json_extract(t.value,'$.start_date'),
          json_extract(t.value,'$.end_date'),json_extract(t.value,'$.start_ms'),
          json_extract(t.value,'$.end_ms'),json_extract(t.value,'$.tz'),
          json_extract(t.value,'$.tzdb_version')
        FROM temp._facet_time_snapshots s JOIN json_each(s.payload) t
        JOIN main.kernel_facets f ON f.record_id=s.record_id AND f.key=json_extract(t.value,'$.key')
        JOIN main.content_events current ON current.seq=f.event_seq
        WHERE f.value=json_extract(t.value,'$.value') AND current.type!='kernel.facet_observed.v1'"#)
        .execute(&mut *conn).await?;
    // Match projector::replace_facet_time / fold_facet_time_candidates:
    // current writes follow v1 source sequence, NOT as_of or import order.
    // Observation-only set/unset events never replace the current time row.
    // A native winning untyped write clears it, just as an untyped v1 set
    // does. An older losing native observation cannot clear the current row.
    // The resulting cache is joined with live visibility only during reads.
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
          FROM temp._facet_time_refresh_targets v
          CROSS JOIN main.kernel_legacy_sql_events h INDEXED BY idx_kernel_legacy_sql_record ON h.record_id=v.id
          JOIN main.content_events e ON e.seq=h.seq
          WHERE h.source_stream='content_events'
           AND NOT EXISTS(SELECT 1 FROM temp._facet_time_snapshots s WHERE s.record_id=v.id)
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
    let mut invalid = Vec::new();
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
            invalid.push(serde_json::json!([
                row.try_get::<String, _>("record_id")?,
                row.try_get::<String, _>("key")?
            ]));
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
    for chunk in invalid.chunks(256) {
        sqlx::query("INSERT INTO kernel_facet_time_invalid SELECT json_extract(value,'$[0]'),json_extract(value,'$[1]') FROM json_each(?)")
            .bind(serde_json::to_string(chunk)?).execute(&mut *conn).await?;
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
        "INSERT INTO main.kernel_facet_time_rows SELECT
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

const VERSION: i64 = 1;
const RELEVANT: &str = "type IN ('kernel.legacy_recorded.v1','kernel.import_state.v1','kernel.import_state_delta.v1','kernel.facet_observed.v1')";
const DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS kernel_facet_time_rows (record_id TEXT NOT NULL,key TEXT NOT NULL,kind TEXT NOT NULL,all_day INTEGER NOT NULL,start_date TEXT,end_date TEXT,start_ms INTEGER,end_ms INTEGER,tz TEXT,tzdb_version TEXT,PRIMARY KEY(record_id,key))",
    "CREATE TABLE IF NOT EXISTS kernel_facet_time_invalid (record_id TEXT NOT NULL,key TEXT NOT NULL,PRIMARY KEY(record_id,key))",
    "CREATE TABLE IF NOT EXISTS kernel_facet_time_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL,projected_seq INTEGER NOT NULL,gap_free INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_kernel_facet_time_frontier ON content_events(seq) WHERE type IN ('kernel.legacy_recorded.v1','kernel.import_state.v1','kernel.import_state_delta.v1','kernel.facet_observed.v1')",
];

pub(crate) async fn ensure_schema_on(conn: &mut SqliteConnection) -> Result<()> {
    for ddl in DDL {
        sqlx::query(ddl).execute(&mut *conn).await?;
    }
    sqlx::query("INSERT OR IGNORE INTO kernel_facet_time_meta VALUES(1,?1,0,1)")
        .bind(VERSION)
        .execute(conn)
        .await?;
    Ok(())
}

fn relevant(event: &EventRow) -> bool {
    matches!(
        event.event_type.as_str(),
        "kernel.legacy_recorded.v1"
            | "kernel.import_state.v1"
            | "kernel.import_state_delta.v1"
            | "kernel.facet_observed.v1"
    )
}

/// Runs after the ordinary event interpreter, in its transaction. Recompute
/// only the affected record with the exact retained-source/current-write fold.
/// A skipped older writer leaves a sticky gap until explicit preparation.
pub(crate) async fn project_on(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if !relevant(event) {
        return Ok(());
    }
    let present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='kernel_facet_time_meta')")
        .fetch_one(&mut *conn).await?;
    if !present {
        return Ok(());
    }
    let previous: i64 = sqlx::query_scalar(&format!(
        "SELECT coalesce(max(seq),0) FROM main.content_events WHERE {RELEVANT} AND seq<?"
    ))
    .bind(event.local_seq)
    .fetch_one(&mut *conn)
    .await?;
    refresh_on(conn, Some(&event.record_id)).await?;
    sqlx::query("UPDATE kernel_facet_time_meta SET gap_free=(gap_free=1 AND projected_seq=?1),projected_seq=?2 WHERE singleton=1 AND version=?3")
        .bind(previous).bind(event.local_seq).bind(VERSION).execute(conn).await?;
    Ok(())
}

/// Explicit and idempotent upgrade, never invoked by a serving read. The
/// source is retained event envelopes plus their ordinary event projections.
pub(crate) async fn prepare_on(conn: &mut SqliteConnection) -> Result<()> {
    ensure_schema_on(conn).await?;
    refresh_on(conn, None).await?;
    sqlx::query(&format!("UPDATE kernel_facet_time_meta SET version=?1,gap_free=1,projected_seq=(SELECT coalesce(max(seq),0) FROM main.content_events WHERE {RELEVANT}) WHERE singleton=1"))
        .bind(VERSION).execute(conn).await?;
    Ok(())
}

pub(crate) async fn require_ready_on(conn: &mut SqliteConnection) -> Result<()> {
    // Inspect before selecting a new table: old v2 files receive an actionable
    // readiness refusal, never SQLite's no-such-table error or a read repair.
    let objects: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_schema WHERE (type='table' AND name IN ('kernel_facet_time_rows','kernel_facet_time_invalid','kernel_facet_time_meta')) OR (type='index' AND name='idx_kernel_facet_time_frontier')")
        .fetch_one(&mut *conn).await?;
    if objects == 4 {
        let ready: bool = sqlx::query_scalar(&format!("SELECT EXISTS(SELECT 1 FROM kernel_facet_time_meta WHERE singleton=1 AND version=?1 AND gap_free=1 AND projected_seq=(SELECT coalesce(max(seq),0) FROM main.content_events WHERE {RELEVANT}))"))
            .bind(VERSION).fetch_one(&mut *conn).await?;
        if ready {
            return Ok(());
        }
    }
    Err(Error::engine("v2 facet-time read projection is not ready; run explicit v2 import/preparation before serving"))
}
