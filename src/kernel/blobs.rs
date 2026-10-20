//! Immutable byte substrate and replayable attachment bindings. Bytes are not events.
use super::*;
use crate::blob::BlobMeta;
use sha2::{Digest, Sha256};

pub(crate) const BYTES_DDL: &str = "CREATE TABLE kernel_blobs (sha256 TEXT PRIMARY KEY, bytes BLOB NOT NULL, size_bytes INTEGER NOT NULL, mime TEXT)";
pub(crate) const HANDLES_DDL: &str = "CREATE TABLE kernel_blob_handles (handle TEXT PRIMARY KEY, sha256 TEXT NOT NULL REFERENCES kernel_blobs(sha256))";
pub(crate) const REFS_DDL: &str = "CREATE TABLE kernel_attachment_blobs (record_id TEXT PRIMARY KEY REFERENCES kernel_records(id), sha256 TEXT NOT NULL REFERENCES kernel_blobs(sha256), metadata TEXT NOT NULL)";

/// Additive admission for a pre-W2 probe database, including resumed imports.
pub(crate) async fn ensure_schema(conn: &mut SqliteConnection) -> Result<()> {
    for ddl in [BYTES_DDL, HANDLES_DDL, REFS_DDL] {
        sqlx::query(&ddl.replacen("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// Metadata belongs to the reference: identical bytes can have different filenames/MIME.
pub(crate) async fn put(conn: &mut SqliteConnection, bytes: &[u8], meta: &BlobMeta) -> Result<()> {
    ensure_schema(conn).await?;
    if meta.sha256 != hex::encode(Sha256::digest(bytes))
        || meta.size_bytes != bytes.len() as i64
        || meta.storage_tier != "inline"
    {
        return Err(Error::engine(
            "attachment blob checksum, size or storage mismatch",
        ));
    }
    sqlx::query("INSERT INTO kernel_blobs VALUES(?,?,?,?) ON CONFLICT(sha256) DO NOTHING")
        .bind(&meta.sha256)
        .bind(bytes)
        .bind(meta.size_bytes)
        .bind(&meta.mime)
        .execute(&mut *conn)
        .await?;
    let verified: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_blobs WHERE sha256=? AND bytes=? AND size_bytes=?)",
    )
    .bind(&meta.sha256)
    .bind(bytes)
    .bind(meta.size_bytes)
    .fetch_one(&mut *conn)
    .await?;
    if !verified {
        return Err(Error::engine("stored blob integrity mismatch"));
    }
    let old: Option<String> =
        sqlx::query_scalar("SELECT sha256 FROM kernel_blob_handles WHERE handle=?")
            .bind(&meta.id)
            .fetch_optional(&mut *conn)
            .await?;
    if old.as_ref().is_some_and(|old| old != &meta.sha256) {
        return Err(Error::conflict("legacy blob handle content differs"));
    }
    sqlx::query("INSERT INTO kernel_blob_handles VALUES(?,?) ON CONFLICT(handle) DO NOTHING")
        .bind(&meta.id)
        .bind(&meta.sha256)
        .execute(conn)
        .await?;
    Ok(())
}

pub(crate) async fn bind(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    actor: &str,
    id: &str,
    meta: &BlobMeta,
) -> Result<()> {
    append_in(
        db,
        tx,
        AppendSpec {
            record_id: id.into(),
            event_type: "kernel.attachment_bound.v1".into(),
            payload: serde_json::to_value(meta)?,
            actor: Some(actor.into()),
        },
        acts,
    )
    .await?;
    Ok(())
}

pub(crate) async fn admit(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if event.event_type == "kernel.facet_observed.v1" {
        let facet: FacetObservation = event_payload(event)?;
        if facet.key == "blob_ref" {
            let handle:Option<String>=sqlx::query_scalar("SELECT json_extract(metadata,'$.id') FROM kernel_attachment_blobs WHERE record_id=?").bind(&event.record_id).fetch_optional(&mut *conn).await?;
            if handle.is_none()
                || handle != facet.value
                || facet.value_num.is_some()
                || facet.vocab_ref.is_some()
            {
                return Err(Error::engine("blob_ref is engine-owned"));
            }
        }
    }
    if event.event_type != "kernel.attachment_bound.v1" {
        return Ok(());
    }
    let actor = event.actor.as_deref().unwrap_or("");
    // Engine-only event: MCP exposes no raw event append. Both producers
    // (sealed import and attach_text) store and verify bytes in this transaction.
    let host = require_import(conn, actor).await.is_ok();
    if !host {
        hq::record_edit(conn, actor, &event.record_id, None).await?;
    }
    validate(conn, event).await
}
async fn validate(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let meta: BlobMeta = event_payload(event)?;
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_blobs b WHERE b.sha256=? AND b.size_bytes=?)",
    )
    .bind(&meta.sha256)
    .bind(meta.size_bytes)
    .fetch_one(&mut *conn)
    .await?;

    // Import host is authorized by the sealed import route, not by workspace policy.
    let carrier:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records r JOIN kernel_record_fields k ON k.record_id=r.id AND k.name='v1_kind' JOIN kernel_record_fields t ON t.record_id=r.id AND t.name='v1_type' WHERE r.id=? AND r.pin_family='native.v1.record' AND r.pin_version=1 AND json_extract(k.value_json,'$')='attachment' AND json_extract(t.value_json,'$')='Document')").bind(&event.record_id).fetch_one(&mut *conn).await?;

    if !valid || !carrier || meta.storage_tier != "inline" {
        return Err(Error::engine("invalid attachment blob binding"));
    }
    let old: Option<String> =
        sqlx::query_scalar("SELECT metadata FROM kernel_attachment_blobs WHERE record_id=?")
            .bind(&event.record_id)
            .fetch_optional(conn)
            .await?;
    if old.is_some() {
        return Err(Error::conflict("attachment blob binding is immutable"));
    }
    Ok(())
}
pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    validate(conn, event).await?;
    let meta: BlobMeta = event_payload(event)?;
    let mapped: Option<String> =
        sqlx::query_scalar("SELECT sha256 FROM kernel_blob_handles WHERE handle=?")
            .bind(&meta.id)
            .fetch_optional(&mut *conn)
            .await?;
    if mapped.as_ref().is_some_and(|hash| hash != &meta.sha256) {
        return Err(Error::conflict("legacy blob handle content differs"));
    }
    sqlx::query("INSERT INTO kernel_blob_handles VALUES(?,?) ON CONFLICT(handle) DO NOTHING")
        .bind(&meta.id)
        .bind(&meta.sha256)
        .execute(&mut *conn)
        .await?;
    sqlx::query("INSERT INTO kernel_attachment_blobs VALUES(?,?,?)")
        .bind(&event.record_id)
        .bind(&meta.sha256)
        .bind(serde_json::to_string(&meta)?)
        .execute(conn)
        .await?;
    Ok(())
}
/// Always resolve through the referencing record under current policy, in one snapshot.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn metadata(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
) -> Result<BlobMeta> {
    metadata_optional(conn, actor, id)
        .await?
        .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn metadata_optional(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
) -> Result<Option<BlobMeta>> {
    if read_record_on(conn, actor, id).await?.is_none() {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    let raw: Option<String> =
        sqlx::query_scalar("SELECT metadata FROM kernel_attachment_blobs WHERE record_id=?")
            .bind(id)
            .fetch_optional(conn)
            .await?;
    raw.map(|raw| serde_json::from_str(&raw))
        .transpose()
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blob_substrate_deduplicates_checks_integrity_and_rolls_back() {
        let (db, _) = create_v2_database(":memory:", "account", "Admin", "acct:test")
            .await
            .unwrap();
        let bytes = b"same content";
        let first = crate::blob::new_blob_meta(bytes, Some("text/plain"), Some("first.txt"));
        let second =
            crate::blob::new_blob_meta(bytes, Some("application/octet-stream"), Some("second.bin"));
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        put(&mut tx, bytes, &first).await.unwrap();
        put(&mut tx, bytes, &second).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM kernel_blobs")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM kernel_blob_handles")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            2
        );
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        let fresh = crate::blob::new_blob_meta(b"rolled back", None, None);
        put(&mut tx, b"rolled back", &fresh).await.unwrap();
        tx.rollback().await.unwrap();
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        assert!(put(&mut tx, b"different", &first).await.is_err());
        tx.rollback().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM kernel_blobs")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            1
        );
    }
}
