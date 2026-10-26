//! Schema-derived projection coverage and a bounded-memory, full-state digest.
use super::*;
use futures::TryStreamExt;
use sha2::{Digest, Sha256};
use sqlx::{Row, TypeInfo, ValueRef};

/// Canonical authority is transported separately, not rebuilt by projectors.
/// FTS shadow tables are physical index layout; the logical FTS table and its
/// version metadata ARE included. Exact exclusions cannot hide a future table.
pub const EXCLUDED_TABLES: &[&str] = &[
    "content_events",
    "meta_events",
    "act_state",
    "act_cutover",
    "content_event_causal_frontier",
    "content_event_causal_cutover",
    // Trigger-maintained function of the two canonical tables above: it moves
    // whenever events are appended (including by an import resume), never by
    // projection replay, so it cannot be part of the projection digest. Tests
    // pin it equal to the frontier anti-join instead.
    "content_event_heads",
    "kernel_blobs",
    // Hosted MCP's lazy idempotency ledger is durable adapter state, never
    // rebuilt by content/meta projectors or copied in an event-tail delta.
    "kernel_mcp_write_receipts",
    // Preparation can advance this gap-free scan cursor independently of event
    // folding. It is derived recovery progress, not user-visible content. The
    // canonical envelopes and kernel_legacy_sql_events headers remain checked.
    "kernel_legacy_sql_progress",
    "kernel_search_fts_data",
    "kernel_search_fts_idx",
    "kernel_search_fts_content",
    "kernel_search_fts_docsize",
    "kernel_search_fts_config",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionTableDump {
    pub name: String,
    pub rows: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionDump {
    pub tables: Vec<ProjectionTableDump>,
    pub sha256: String,
}

pub async fn dump(db: &Db) -> Result<ProjectionDump> {
    let mut tx = db.pool().begin().await?;
    let result = dump_on(&mut tx).await?;
    tx.commit().await?;
    Ok(result)
}

pub(crate) async fn dump_on(conn: &mut SqliteConnection) -> Result<ProjectionDump> {
    let v2: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(&mut *conn)
        .await?;
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' ORDER BY name")
        .fetch_all(&mut *conn).await?;
    let mut tables = Vec::new();
    for name in names {
        // Bare v2 owns every non-canonical table. Compatibility kernel tests
        // also carry the unrelated frozen v1 schema: only that older test
        // mode needs a namespace filter for its kernel/registry projections.
        if EXCLUDED_TABLES.contains(&name.as_str())
            || (v2 != crate::db::V2_APPLICATION_ID
                && !name.starts_with("kernel_")
                && ![
                    "definition_artifacts",
                    "definition_adoptions",
                    "package_artifacts",
                    "consumer_requirements",
                    "rule_installations",
                ]
                .contains(&name.as_str()))
        {
            continue;
        }
        let quoted = quote(&name);
        #[allow(clippy::type_complexity)]
        let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
            sqlx::query_as(&format!("PRAGMA table_info({quoted})"))
                .fetch_all(&mut *conn)
                .await?;
        let mut keys: Vec<_> = columns.iter().filter(|c| c.5 > 0).collect();
        keys.sort_by_key(|c| c.5);
        if keys.is_empty() {
            keys = columns.iter().collect();
        }
        let order = keys
            .iter()
            .map(|c| quote(&c.1))
            .collect::<Vec<_>>()
            .join(",");
        let mut digest = Sha256::new();
        digest.update(b"native.kernel-projection-table.v1\0");
        frame(&mut digest, &serde_json::to_vec(&(&name, &columns))?);
        let query = format!("SELECT * FROM {quoted} ORDER BY {order}");
        let mut stream = sqlx::query(&query).fetch(&mut *conn);
        let mut rows = 0_u64;
        while let Some(row) = stream.try_next().await? {
            digest.update(b"row\0");
            for index in 0..columns.len() {
                let raw = row.try_get_raw(index)?;
                if raw.is_null() {
                    digest.update(b"null\0");
                    continue;
                }
                match raw.type_info().name() {
                    "INTEGER" => {
                        digest.update(b"int\0");
                        digest.update(row.try_get::<i64, _>(index)?.to_le_bytes());
                    }
                    "REAL" => {
                        digest.update(b"real\0");
                        digest.update(row.try_get::<f64, _>(index)?.to_bits().to_le_bytes());
                    }
                    "TEXT" => {
                        digest.update(b"text\0");
                        frame(&mut digest, row.try_get::<&str, _>(index)?.as_bytes());
                    }
                    "BLOB" => {
                        digest.update(b"blob\0");
                        frame(&mut digest, row.try_get::<&[u8], _>(index)?);
                    }
                    _ => return Err(Error::engine("unsupported projection storage class")),
                }
            }
            rows += 1;
        }
        digest.update(rows.to_le_bytes());
        tables.push(ProjectionTableDump {
            name,
            rows,
            sha256: hex::encode(digest.finalize()),
        });
    }
    let mut digest = Sha256::new();
    digest.update(b"native.kernel-projections.v1\0");
    digest.update(serde_json::to_vec(&tables)?);
    Ok(ProjectionDump {
        tables,
        sha256: hex::encode(digest.finalize()),
    })
}

fn frame(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}
fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
