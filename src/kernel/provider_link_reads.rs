//! Replayable interpreted link read projection. Contains no authority: readers
//! must still admit every provider subject and both endpoints in their live
//! caller snapshot. Frozen interpreters and their versioned codecs are the only
//! source of these rows; preparation uses precisely the same callback as replay.
use super::{provider_catalogue, InterpretationPins};
use crate::{error::Error, Result};
use serde_json::json;
use sqlx::SqliteConnection;

const VERSION: i64 = 1;
const READ_INDEXES: &[(&str,&str)] = &[
    ("idx_kernel_provider_state_heads","CREATE INDEX IF NOT EXISTS idx_kernel_provider_state_heads ON kernel_provider_state(provider_key,id,head)"),
    ("idx_kernel_provider_link_coverage","CREATE INDEX IF NOT EXISTS idx_kernel_provider_link_coverage ON kernel_provider_link_heads(aggregate_id,head,row_count)"),
    ("idx_kernel_event_birth","CREATE INDEX IF NOT EXISTS idx_kernel_event_birth ON content_events(seq,created_at)"),
    ("idx_kernel_read_type","CREATE INDEX IF NOT EXISTS idx_kernel_read_type ON kernel_record_fields(record_id,value_json) WHERE name='v1_type'"),
    ("idx_kernel_read_kind","CREATE INDEX IF NOT EXISTS idx_kernel_read_kind ON kernel_record_fields(record_id,value_json) WHERE name='v1_kind'"),
];
const DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS kernel_provider_link_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS kernel_provider_link_heads (aggregate_id TEXT PRIMARY KEY,head INTEGER NOT NULL,pins_json TEXT NOT NULL,left_id TEXT NOT NULL,right_id TEXT NOT NULL,active INTEGER NOT NULL,row_count INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS kernel_provider_link_rows (aggregate_id TEXT NOT NULL,ordinal INTEGER NOT NULL,id TEXT NOT NULL,source_id TEXT NOT NULL,target_id TEXT NOT NULL,note TEXT,created_at TEXT,created_at_ms INTEGER,raw_json TEXT NOT NULL,if_absent INTEGER NOT NULL,PRIMARY KEY(aggregate_id,ordinal))",
    "CREATE INDEX IF NOT EXISTS idx_kernel_provider_link_identity ON kernel_provider_link_rows(id,aggregate_id,ordinal)",
];

pub(crate) struct LinkView {
    pub left: String,
    pub right: String,
    pub active: bool,
    pub rows: Vec<LinkOperation>,
}
pub(crate) struct LinkOperation {
    pub id: String,
    pub source: String,
    pub target: String,
    pub note: Option<String>,
    pub timestamp: String,
    pub if_absent: bool,
}

pub(crate) async fn ensure_schema_on(conn: &mut SqliteConnection) -> Result<()> {
    for ddl in DDL {
        sqlx::query(ddl).execute(&mut *conn).await?;
    }
    for (_, ddl) in READ_INDEXES {
        sqlx::query(ddl).execute(&mut *conn).await?;
    }
    // Never bless an older projection format by changing its version here.
    sqlx::query("INSERT OR IGNORE INTO kernel_provider_link_meta VALUES(1,?)")
        .bind(VERSION)
        .execute(conn)
        .await?;
    Ok(())
}

pub(crate) async fn store_on(
    conn: &mut SqliteConnection,
    aggregate: &str,
    head: i64,
    pins: &InterpretationPins,
    view: LinkView,
) -> Result<()> {
    sqlx::query("DELETE FROM kernel_provider_link_rows WHERE aggregate_id=?")
        .bind(aggregate)
        .execute(&mut *conn)
        .await?;
    sqlx::query("INSERT INTO kernel_provider_link_heads VALUES(?,?,?,?,?,?,?) ON CONFLICT(aggregate_id) DO UPDATE SET head=excluded.head,pins_json=excluded.pins_json,left_id=excluded.left_id,right_id=excluded.right_id,active=excluded.active,row_count=excluded.row_count")
        .bind(aggregate).bind(head).bind(serde_json::to_string(pins)?).bind(view.left).bind(view.right).bind(view.active).bind(view.rows.len() as i64).execute(&mut *conn).await?;
    let rows: Vec<_> = view
        .rows
        .into_iter()
        .enumerate()
        .map(|(ordinal, row)| {
            let raw = json!([row.id, row.source, row.target, row.note, row.timestamp]);
            json!([
                ordinal,
                raw[0],
                raw[1],
                raw[2],
                raw[3],
                raw[4],
                raw.to_string(),
                row.if_absent
            ])
        })
        .collect();
    for chunk in rows.chunks(500) {
        sqlx::query("INSERT INTO kernel_provider_link_rows SELECT ?1,json_extract(value,'$[0]'),json_extract(value,'$[1]'),json_extract(value,'$[2]'),json_extract(value,'$[3]'),json_extract(value,'$[4]'),strftime('%Y-%m-%dT%H:%M:%fZ',json_extract(value,'$[5]')),CAST(strftime('%s',json_extract(value,'$[5]')) AS INTEGER)*1000+CAST(substr(strftime('%f',json_extract(value,'$[5]')),4,3) AS INTEGER),json_extract(value,'$[6]'),json_extract(value,'$[7]') FROM json_each(?2)")
            .bind(aggregate).bind(serde_json::to_string(chunk)?).execute(&mut *conn).await?;
    }
    Ok(())
}

pub(crate) async fn prepare_on(conn: &mut SqliteConnection) -> Result<()> {
    ensure_schema_on(conn).await?;
    sqlx::query("DELETE FROM kernel_provider_link_rows")
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM kernel_provider_link_heads")
        .execute(&mut *conn)
        .await?;
    let states: Vec<(String, i64, String)> =
        sqlx::query_as("SELECT id,head,state_json FROM kernel_provider_state ORDER BY id")
            .fetch_all(&mut *conn)
            .await?;
    for (id, head, state) in states {
        let stored: provider_catalogue::StoredState = serde_json::from_str(&state)?;
        let entry = provider_catalogue::lookup(&stored.pins)?;
        if let Some(project) = entry.link_read {
            store_on(
                conn,
                &id,
                head,
                &stored.pins,
                project((entry.state_codec)(&stored)?)?,
            )
            .await?;
        }
    }
    sqlx::query("UPDATE kernel_provider_link_meta SET version=? WHERE singleton=1")
        .bind(VERSION)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Check coverage, not merely MAX(head): a missing older aggregate or a partly
/// written row set must refuse too. No stored-state JSON is decoded on reads.
pub(crate) async fn require_ready_on(conn: &mut SqliteConnection) -> Result<()> {
    for (name, _) in READ_INDEXES {
        let ready: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?)",
        )
        .bind(name)
        .fetch_one(&mut *conn)
        .await?;
        if !ready {
            return Err(Error::engine("v2 provider-link read projection is not ready; run explicit v2 import/preparation before serving"));
        }
    }
    let objects: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_schema WHERE (type='table' AND name IN ('kernel_provider_link_meta','kernel_provider_link_heads','kernel_provider_link_rows')) OR (type='index' AND name='idx_kernel_provider_link_identity')").fetch_one(&mut *conn).await?;
    if objects != 4 {
        return Err(Error::engine("v2 provider-link read projection is not ready; run explicit v2 import/preparation before serving"));
    }
    let version: Option<i64> =
        sqlx::query_scalar("SELECT version FROM kernel_provider_link_meta WHERE singleton=1")
            .fetch_optional(&mut *conn)
            .await?;
    let stale: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_provider_state p LEFT JOIN kernel_provider_link_heads h INDEXED BY idx_kernel_provider_link_coverage ON h.aggregate_id=p.id WHERE p.provider_key='relates_to.v1' AND (h.aggregate_id IS NULL OR h.head<>p.head)) OR EXISTS(SELECT 1 FROM kernel_provider_link_heads h WHERE NOT EXISTS(SELECT 1 FROM kernel_provider_state p INDEXED BY idx_kernel_provider_state_heads WHERE p.provider_key='relates_to.v1' AND p.id=h.aggregate_id) OR h.row_count<>(SELECT count(*) FROM kernel_provider_link_rows r WHERE r.aggregate_id=h.aggregate_id)) OR EXISTS(SELECT 1 FROM kernel_provider_link_rows r WHERE NOT EXISTS(SELECT 1 FROM kernel_provider_link_heads h WHERE h.aggregate_id=r.aggregate_id))")
        .fetch_one(&mut *conn).await?;
    if version != Some(VERSION) || stale {
        return Err(Error::engine("v2 provider-link read projection is not ready; run explicit v2 import/preparation before serving"));
    }
    let pins: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT pins_json FROM kernel_provider_link_heads")
            .fetch_all(&mut *conn)
            .await?;
    for pins in pins {
        provider_catalogue::lookup(&serde_json::from_str(&pins)?)?;
    }
    Ok(())
}
