//! The blob byte tier — SUBSTRATE, not a projection (spine decision a978c23;
//! docs/tool-surface.md §Blobs & attachments). Attachment BYTES are written
//! directly to `blobs`: routing them through the event log would bloat the
//! authoritative history, so the append-event invariant deliberately does not
//! cover this tier (and the conformance rebuild-and-diff excludes it for the
//! same reason). The RECORDS that reference blobs (`Document kind:attachment`,
//! bound via the `blob_ref` facet) go through events as normal — see
//! `crate::mcp::tools::attachments`.
//!
//! This module is the shared byte I/O every blob consumer stands on:
//! sha256/mime/size bookkeeping on write, and ranged reads that page through
//! SQLite's `substr` so a large blob is never materialized whole. The v1.1
//! sheet tools (`mcp::sheet`, tools 26–30) build on these same helpers.

use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::db::Db;
use crate::error::{Error, Result};

pub(crate) fn new_blob_meta(
    bytes: &[u8],
    mime: Option<&str>,
    original_filename: Option<&str>,
) -> BlobMeta {
    BlobMeta {
        id: Uuid::new_v4().to_string(),
        mime: mime.map(String::from),
        size_bytes: bytes.len() as i64,
        sha256: hex::encode(Sha256::digest(bytes)),
        original_filename: original_filename.map(String::from),
        storage_tier: "inline".into(),
        created_at: crate::store::now_iso(),
    }
}

/// The open facet binding an attachment record to its `blobs` row.
pub const BLOB_REF_FACET_KEY: &str = "blob_ref";

/// A `blobs` row's metadata — never the bytes.
#[derive(Debug, Clone, Serialize)]
pub struct BlobMeta {
    pub id: String,
    pub mime: Option<String>,
    pub size_bytes: i64,
    pub sha256: String,
    pub original_filename: Option<String>,
    pub storage_tier: String,
    pub created_at: String,
}

/// One page of a ranged read.
#[derive(Debug, Clone)]
pub struct BlobSlice {
    pub bytes: Vec<u8>,
    /// The byte offset this slice starts at (as requested).
    pub offset: u64,
    /// The blob's total size in bytes.
    pub total_size: u64,
    /// True iff this slice reaches the end of the blob.
    pub eof: bool,
}

/// Write bytes into the blob tier (`storage_tier='inline'`), computing
/// sha256/size here so every writer records them identically. This is a
/// DIRECT write — no event is appended, by design (module docs).
pub async fn insert_blob(
    db: &Db,
    bytes: &[u8],
    mime: Option<&str>,
    original_filename: Option<&str>,
) -> Result<BlobMeta> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let meta = insert_blob_in(&mut tx, bytes, mime, original_filename).await?;
    tx.commit().await?;
    Ok(meta)
}

/// Transaction-scoped blob insertion for attachment creation. Keeping the
/// byte row in the same transaction as authorization and the referencing
/// attachment events prevents denied or failed writes from leaving orphans.
pub(crate) async fn insert_blob_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    bytes: &[u8],
    mime: Option<&str>,
    original_filename: Option<&str>,
) -> Result<BlobMeta> {
    let meta = new_blob_meta(bytes, mime, original_filename);
    sqlx::query(
        "INSERT INTO blobs (id, bytes, mime, size_bytes, sha256, original_filename, storage_tier, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&meta.id)
    .bind(bytes)
    .bind(&meta.mime)
    .bind(meta.size_bytes)
    .bind(&meta.sha256)
    .bind(&meta.original_filename)
    .bind(&meta.storage_tier)
    .bind(&meta.created_at)
    .execute(&mut **tx)
    .await?;
    Ok(meta)
}

/// Fetch a blob's metadata. `None` if the id does not exist.
pub async fn get_meta(db: &Db, id: &str) -> Result<Option<BlobMeta>> {
    let row = sqlx::query(
        "SELECT id, mime, size_bytes, sha256, original_filename, storage_tier, created_at
            FROM blobs WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db.write_pool())
    .await?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(BlobMeta {
        id: row.try_get("id")?,
        mime: row.try_get("mime")?,
        size_bytes: row.try_get("size_bytes")?,
        sha256: row.try_get("sha256")?,
        original_filename: row.try_get("original_filename")?,
        storage_tier: row.try_get("storage_tier")?,
        created_at: row.try_get("created_at")?,
    }))
}

/// Read `length` bytes starting at byte `offset` (0-based). Pages through
/// SQLite `substr` so only the requested window crosses the connection.
/// `None` if the blob id does not exist; an offset at/past the end returns an
/// empty slice with `eof: true`.
pub async fn read_range(db: &Db, id: &str, offset: u64, length: u64) -> Result<Option<BlobSlice>> {
    let mut conn = db.write_pool().acquire().await?;
    read_range_on(&mut conn, id, offset, length).await
}

pub(crate) async fn read_range_on(
    conn: &mut sqlx::SqliteConnection,
    id: &str,
    offset: u64,
    length: u64,
) -> Result<Option<BlobSlice>> {
    if offset > i64::MAX as u64 || length > i64::MAX as u64 {
        return Err(Error::engine(format!(
            "blob range out of bounds: offset {offset}, length {length}"
        )));
    }
    let row = sqlx::query(
        // substr is 1-based; on NULL bytes it yields NULL, which we tell apart
        // from a genuinely empty window via the bytes IS NULL flag.
        "SELECT substr(bytes, ?, ?) AS chunk, size_bytes, storage_tier,
                (bytes IS NULL) AS no_bytes
            FROM blobs WHERE id = ?",
    )
    .bind((offset + 1) as i64)
    .bind(length as i64)
    .bind(id)
    .fetch_optional(conn)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let storage_tier: String = row.try_get("storage_tier")?;
    if storage_tier != "inline" {
        return Err(Error::engine(format!(
            "blob {id} is stored externally (storage_tier '{storage_tier}') — external blobs are not readable in v1"
        )));
    }
    if row.try_get::<i64, _>("no_bytes")? != 0 {
        return Err(Error::engine(format!("blob {id} has no inline bytes")));
    }
    let bytes: Vec<u8> = row.try_get("chunk")?;
    let total_size = row.try_get::<i64, _>("size_bytes")?.max(0) as u64;
    let eof = offset + bytes.len() as u64 >= total_size;
    Ok(Some(BlobSlice {
        bytes,
        offset,
        total_size,
        eof,
    }))
}
