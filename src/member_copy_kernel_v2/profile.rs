//! Probe-only native current-state member profile. No HTTP route or v1 opener
//! accepts this artifact. Selection uses the production v2 read staging, never
//! a second implementation of visibility. No canonical projections/history,
//! policy, principal directory, global frontiers or unused blobs are copied.
use super::{capture_in, file_fence, NativeMemberCut, NativeMemberSource};
use crate::{
    member_copy_transport::MemberCopyContext,
    replica_generation::{ReplicaGenerationManifest, ReplicaProfile},
};
use rusqlite::{types::Value, Connection, OpenFlags};
use sha2::{Digest, Sha256};
use sqlx::{Row, TypeInfo, ValueRef};
use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::BTreeSet,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

type Result<T> = std::result::Result<T, Refusal>;

/// Fixed errors only. SQLite errors, identifiers and content never escape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("native member profile: storage unavailable")]
    Storage,
    #[error("native member profile: identity refused")]
    Identity,
    #[error("native member profile: schema refused")]
    Schema,
    #[error("native member profile: content refused")]
    Content,
    #[error("native member profile: authorization changed")]
    Authorization,
    #[error("native member profile: range refused")]
    Range,
}
fn storage<T>(r: std::result::Result<T, impl std::fmt::Display>) -> Result<T> {
    r.map_err(|_| Refusal::Storage)
}

// A closed current-state surface, deliberately omitting history and runtime
// activity. All columns come from the compiled public SQL contract. BLOB
// affinity preserves the source storage class without coercion.
const RELATIONS: &[&str] = &[
    "records",
    "links",
    "facet_values",
    "comment_anchors",
    "bindings",
    "vocabularies",
    "vocabulary_values",
    "record_lifecycle_interpretations",
    "my_message_state",
    "messages_awaiting_reply",
    "message_reactions",
    "my_mentions",
];
fn tables() -> Vec<(String, Vec<String>)> {
    let mut tables = RELATIONS
        .iter()
        .map(|name| {
            let relation = crate::query::sql_contract::LOGICAL_RELATIONS
                .iter()
                .find(|r| r.name == *name)
                .expect("compiled relation");
            let columns = if *name == "bindings" {
                vec!["record_id", "system", "identifier", "is_canonical"]
            } else {
                relation.columns.to_vec()
            };
            (
                (*name).to_owned(),
                columns.into_iter().map(str::to_owned).collect(),
            )
        })
        .collect::<Vec<_>>();
    tables.push((
        "member_attachments".into(),
        ["record_id", "metadata", "sha256", "bytes"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    ));
    tables
}
fn quoted(columns: &[String]) -> String {
    columns
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(",")
}
fn ddl() -> Vec<String> {
    let mut result = vec![file_fence::DDL.to_owned()];
    result.extend(tables().into_iter().map(|(table, columns)| {
        format!(
            "CREATE TABLE {table} ({})",
            columns
                .iter()
                .map(|c| format!("\"{c}\" BLOB"))
                .collect::<Vec<_>>()
                .join(",")
        )
    }));
    result
}
pub fn schema_digest() -> String {
    hex::encode(Sha256::digest(ddl().join(";")))
}
fn hash(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn validate_header(manifest: &ReplicaGenerationManifest) -> Result<()> {
    let hex = |value: &str, length| {
        value.len() == length
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if manifest.materialization
        != crate::standby_snapshot::StandbyGenerationMaterialization::Snapshot
        || manifest.bytes.media_type != crate::standby_snapshot::STANDBY_SNAPSHOT_MEDIA_TYPE
        || manifest.bytes.size_bytes == 0
        || manifest.bytes.size_bytes > 512 * 1024 * 1024
        || !hex(&manifest.bytes.sha256, 64)
        || manifest.producer.name != crate::standby::kernel_v2::ENGINE
        || manifest.producer.schema_version != 0
        || !hex(&manifest.producer.source_sha, 40)
        || !hex(&manifest.producer.ddl_sha256, 64)
        || !manifest.schema_incomplete_for.is_empty()
    {
        return Err(Refusal::Schema);
    }
    Ok(())
}

// Sort encoded rows, including duplicates, rather than depending on source
// scan/insertion order. Tag every storage class; integers and reals cannot
// collide. Hash bytes themselves, never trust a claimed blob checksum.
fn digest(conn: &Connection) -> Result<String> {
    let mut all = vec![];
    let mut relations = tables();
    relations.insert(
        0,
        (
            "kernel_member_identity".into(),
            [
                "singleton",
                "engine",
                "member_schema_digest",
                "origin_database_id",
                "account_binding",
                "principal_id",
                "genesis_event_id",
                "scope_ref",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        ),
    );
    for (table, columns) in relations {
        let mut statement =
            storage(conn.prepare(&format!("SELECT {} FROM main.{table}", quoted(&columns))))?;
        let mut rows = storage(statement.query([]))?;
        let mut encoded = vec![];
        while let Some(row) = storage(rows.next())? {
            let mut cells = vec![];
            for i in 0..columns.len() {
                let value: Value = storage(row.get(i))?;
                let cell = match value {
                    Value::Null => serde_json::Value::Null,
                    Value::Integer(v) => serde_json::json!(["i", v.to_string()]),
                    Value::Real(v) if v.is_finite() => {
                        serde_json::json!(["r", v.to_bits().to_string()])
                    }
                    Value::Real(_) => return Err(Refusal::Content),
                    Value::Text(v) => serde_json::json!(["t", v]),
                    Value::Blob(v) => serde_json::json!(["b", hash(&v)]),
                };
                cells.push(cell);
            }
            encoded.push(storage(serde_jcs::to_vec(&cells))?);
        }
        encoded.sort();
        all.push((table, encoded));
    }
    Ok(hash(&storage(serde_jcs::to_vec(&(
        "member-read-kernel-v2",
        schema_digest(),
        all,
    )))?))
}

fn validate_closure(conn: &Connection) -> Result<()> {
    let invalid: bool = storage(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.records WHERE id IS NULL) OR
        (SELECT count(*) FROM main.records)!=(SELECT count(DISTINCT id) FROM main.records) OR
        EXISTS(SELECT 1 FROM main.links l WHERE NOT EXISTS(SELECT 1 FROM main.records r WHERE r.id=l.source_id) OR NOT EXISTS(SELECT 1 FROM main.records r WHERE r.id=l.target_id)) OR
        EXISTS(SELECT 1 FROM main.facet_values f WHERE NOT EXISTS(SELECT 1 FROM main.records r WHERE r.id=f.record_id)) OR
        EXISTS(SELECT 1 FROM main.member_attachments a WHERE NOT EXISTS(SELECT 1 FROM main.records r WHERE r.id=a.record_id)) OR
        EXISTS(SELECT 1 FROM main.comment_anchors a WHERE NOT EXISTS(SELECT 1 FROM main.records r WHERE r.id=a.annotation_id) OR NOT EXISTS(SELECT 1 FROM main.records r WHERE r.id=a.target_record_id))", [], |r| r.get(0)))?;
    if invalid {
        return Err(Refusal::Content);
    }
    let mut stmt =
        storage(conn.prepare("SELECT metadata,sha256,bytes FROM main.member_attachments"))?;
    let mut rows = storage(stmt.query([]))?;
    while let Some(row) = storage(rows.next())? {
        let metadata: String = storage(row.get(0))?;
        let meta: crate::blob::BlobMeta =
            serde_json::from_str(&metadata).map_err(|_| Refusal::Content)?;
        let sha: String = storage(row.get(1))?;
        let bytes: Vec<u8> = storage(row.get(2))?;
        if meta.sha256 != sha || hash(&bytes) != sha || meta.size_bytes != bytes.len() as i64 {
            return Err(Refusal::Content);
        }
    }
    Ok(())
}

fn cell(row: &sqlx::sqlite::SqliteRow, i: usize) -> Result<Value> {
    let raw = storage(row.try_get_raw(i))?;
    if raw.is_null() {
        return Ok(Value::Null);
    }
    Ok(match raw.type_info().name() {
        "INTEGER" => Value::Integer(storage(row.try_get(i))?),
        "REAL" => Value::Real(storage(row.try_get(i))?),
        "TEXT" => Value::Text(storage(row.try_get(i))?),
        "BLOB" => Value::Blob(storage(row.try_get(i))?),
        _ => return Err(Refusal::Content),
    })
}

/// A private owned file. There is no path getter, raw connection getter, Db
/// conversion, persistence, or unconditional byte-read API. Drop unlinks it.
pub struct ProducedMemberFile {
    builder: file_fence::NativeMemberFileBuilder,
    manifest: ReplicaGenerationManifest,
    cut: NativeMemberCut,
}
impl ProducedMemberFile {
    pub fn manifest(&self) -> &ReplicaGenerationManifest {
        &self.manifest
    }

    /// Server-only comparison, disclosing no private source coordinates.
    pub fn belongs_to(&self, cut: &NativeMemberCut) -> bool {
        self.cut == *cut
    }

    /// Final live workspace check for each range; never use the old production
    /// snapshot. The authenticated hosting adapter must also check its catalog
    /// fence through `catalog_check`, after the bytes are read. A refusal returns
    /// no bytes. This API is not wired to HTTP; HTTP remains Locked for review.
    pub async fn range<F, Fut>(
        &mut self,
        db: &crate::Db,
        start: u64,
        length: usize,
        catalog_check: F,
    ) -> Result<Vec<u8>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        if length == 0
            || length > 1024 * 1024
            || start
                .checked_add(length as u64)
                .is_none_or(|end| end > self.manifest.bytes.size_bytes)
        {
            return Err(Refusal::Range);
        }
        let mut file = storage(self.builder._file.reopen())?;
        storage(file.seek(SeekFrom::Start(start)))?;
        let mut bytes = vec![0; length];
        storage(file.read_exact(&mut bytes))?;
        if !catalog_check().await {
            return Err(Refusal::Authorization);
        }
        let mut tx = storage(db.pool().begin().await)?;
        let current = capture_in(
            &mut tx,
            &self.cut.origin_database_id,
            &self.cut.account_binding,
        )
        .await
        .map_err(|_| Refusal::Authorization)?;
        if !matches!(current, NativeMemberSource::Ready(current) if current == self.cut) {
            return Err(Refusal::Authorization);
        }
        storage(tx.rollback().await)?;
        Ok(bytes)
    }
}

/// Caller owns the source read transaction and must discard its physical
/// connection on every exit (TEMP staging includes private visibility state).
/// Manifest footing is supplied by the authenticated hosting composition; the
/// profile, digests, identity, byte size and generation are always overwritten.
pub async fn produce_in(
    source: &mut sqlx::SqliteConnection,
    cut: NativeMemberCut,
    directory: &Path,
    mut manifest: ReplicaGenerationManifest,
) -> Result<ProducedMemberFile> {
    manifest.profile = ReplicaProfile::MemberReadKernelV2 {
        engine: crate::standby::kernel_v2::ENGINE.into(),
        member_schema_digest: schema_digest(),
        identity: cut.profile_identity(),
    };
    manifest.content_digest = "0".repeat(64);
    manifest.frontier = None;
    manifest.schema_incomplete_for.clear();
    manifest.own_writes = crate::replica_generation::ReplicaOwnWrites::not_computed();
    manifest.materialization = crate::standby_snapshot::StandbyGenerationMaterialization::Snapshot;
    manifest.bytes.media_type = crate::standby_snapshot::STANDBY_SNAPSHOT_MEDIA_TYPE.into();
    let mut builder =
        file_fence::NativeMemberFileBuilder::new_in(directory).map_err(|_| Refusal::Storage)?;
    file_fence::initialize_in(source, &cut, &mut builder, &manifest)
        .await
        .map_err(|_| Refusal::Identity)?;
    // N1's native engine namespace uses zero for the legacy schema slot. Only
    // its static DDL digest travels; all canonical heads/counts stay private.
    {
        let coordinates = crate::standby::kernel_v2::coordinates(source)
            .await
            .map_err(|_| Refusal::Storage)?;
        manifest.producer.name = crate::standby::kernel_v2::ENGINE.into();
        manifest.producer.schema_version = 0;
        manifest.producer.ddl_sha256 = coordinates.schema_sha256;
    }
    let reads: BTreeSet<_> = tables()
        .into_iter()
        .filter(|(name, _)| name != "member_attachments")
        .flat_map(|(name, columns)| {
            columns
                .into_iter()
                .map(move |column| (name.clone(), column))
        })
        .collect();
    storage(
        sqlx::query("SAVEPOINT native_member_projection")
            .execute(&mut *source)
            .await,
    )?;
    crate::mcp::kernel_v2::sql::install(source, &cut.principal_id, &reads)
        .await
        .map_err(|_| Refusal::Storage)?;
    for sql in ddl().into_iter().skip(1) {
        storage(builder.connection.execute_batch(&sql))?;
    }
    for (name, columns) in tables()
        .into_iter()
        .filter(|(name, _)| name != "member_attachments")
    {
        let sql = format!(
            "SELECT {} FROM temp.{name} ORDER BY {}",
            quoted(&columns),
            quoted(&columns)
        );
        let rows = storage(sqlx::query(&sql).fetch_all(&mut *source).await)?;
        let insert = format!(
            "INSERT INTO main.{name} VALUES ({})",
            vec!["?"; columns.len()].join(",")
        );
        let tx = storage(builder.connection.transaction())?;
        {
            let mut stmt = storage(tx.prepare(&insert))?;
            for row in rows {
                let values = (0..columns.len())
                    .map(|i| cell(&row, i))
                    .collect::<Result<Vec<_>>>()?;
                storage(stmt.execute(rusqlite::params_from_iter(values)))?;
            }
        }
        storage(tx.commit())?;
    }
    let ids: Vec<String> = storage(sqlx::query_scalar("SELECT a.record_id FROM main.kernel_attachment_blobs a JOIN temp.records r ON r.id=a.record_id ORDER BY a.record_id").fetch_all(&mut *source).await)?;
    // Physical kernel helpers use the canonical tables. In particular the
    // logical TEMP content_events must not shadow their physical event stream.
    // Roll back only our staging, retaining the caller's original read cut.
    storage(
        sqlx::query("ROLLBACK TO native_member_projection; RELEASE native_member_projection")
            .execute(&mut *source)
            .await,
    )?;
    for id in ids {
        // Reuse the single-record live gate too, including terminal bearers.
        let meta = crate::kernel::blobs::metadata(source, &cut.principal_id, &id)
            .await
            .map_err(|_| Refusal::Authorization)?;
        let bytes: Vec<u8> = storage(
            sqlx::query_scalar("SELECT bytes FROM main.kernel_blobs WHERE sha256=?")
                .bind(&meta.sha256)
                .fetch_one(&mut *source)
                .await,
        )?;
        if hash(&bytes) != meta.sha256 || bytes.len() as i64 != meta.size_bytes {
            return Err(Refusal::Content);
        }
        storage(builder.connection.execute(
            "INSERT INTO main.member_attachments VALUES (?,?,?,?)",
            rusqlite::params![
                id,
                storage(serde_json::to_string(&meta))?,
                meta.sha256,
                bytes
            ],
        ))?;
    }
    validate_closure(&builder.connection)?;
    manifest.content_digest = digest(&builder.connection)?;
    storage(builder.connection.execute(
        "UPDATE main.kernel_member_identity SET generation_id=? WHERE singleton=1",
        [manifest.generation_id()],
    ))?;
    storage(builder._file.as_file().sync_all())?;
    if storage(builder._file.as_file().metadata())?.len() > 512 * 1024 * 1024 {
        return Err(Refusal::Content);
    }
    let bytes = storage(std::fs::read(builder._file.path()))?;
    manifest.bytes.size_bytes = bytes.len() as u64;
    manifest.bytes.sha256 = hash(&bytes);
    validate_header(&manifest)?;
    // Recheck private cut before sealing; no private fence travels in manifest.
    if !matches!(capture_in(source, &cut.origin_database_id, &cut.account_binding).await.map_err(|_| Refusal::Authorization)?, NativeMemberSource::Ready(current) if current == cut)
    {
        return Err(Refusal::Authorization);
    }
    Ok(ProducedMemberFile {
        builder,
        manifest,
        cut,
    })
}

/// Verified native read handle. Opens physically read-only, verifies immutable
/// bytes, exact closed schema, identity on that very connection and semantic
/// content. It grants no lifecycle lease or offline-serving authority.
pub struct AdmittedMemberFile {
    connection: Connection,
    expected: file_fence::ExpectedFileFence,
    _file: tempfile::NamedTempFile,
}
impl AdmittedMemberFile {
    pub fn open(
        path: &Path,
        copy_root: &Path,
        context: &MemberCopyContext,
        manifest: &ReplicaGenerationManifest,
    ) -> Result<Self> {
        // TODO(native admission wiring): check the authenticated lifecycle's
        // monotonic scope ordinal before admission. A consistent old manifest
        // and file pair must not bypass replay refusal. This verifier alone
        // grants no serving authority; native serving remains Locked.
        validate_header(manifest)?;
        let expected = file_fence::ExpectedFileFence::from_authenticated_context(context, manifest)
            .map_err(|_| Refusal::Identity)?;
        let ReplicaProfile::MemberReadKernelV2 {
            member_schema_digest,
            ..
        } = &manifest.profile
        else {
            return Err(Refusal::Schema);
        };
        if *member_schema_digest != schema_digest() {
            return Err(Refusal::Schema);
        }
        // Copy once from the opened candidate into an exclusively created
        // private snapshot. Verification and all later reads use that same
        // snapshot; replacing/modifying the offered path cannot change it.
        if manifest.bytes.size_bytes > 512 * 1024 * 1024 {
            return Err(Refusal::Content);
        }
        let mut input = storage(
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path),
        )?;
        let mut bytes = Vec::new();
        storage(
            (&mut input)
                .take(manifest.bytes.size_bytes + 1)
                .read_to_end(&mut bytes),
        )?;
        if bytes.len() as u64 != manifest.bytes.size_bytes || hash(&bytes) != manifest.bytes.sha256
        {
            return Err(Refusal::Content);
        }
        // The lifecycle enumerates root-level *.tmp files on scope/revocation
        // purge, including residue left by a crash before this handle drops.
        let mut file = storage(
            tempfile::Builder::new()
                .prefix(".native-admitted-")
                .suffix(".tmp")
                .tempfile_in(copy_root),
        )?;
        storage(std::io::Write::write_all(&mut file, &bytes))?;
        let connection = storage(Connection::open_with_flags(
            file.path(),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ))?;
        storage(connection.execute_batch("BEGIN"))?;
        file_fence::verify_on(&connection, &expected).map_err(|_| Refusal::Identity)?;
        let actual: Vec<String> = storage(
            storage(connection.prepare(
                "SELECT sql FROM main.sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY name",
            ))?
            .query_map([], |r| r.get(0)),
        )?
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| Refusal::Schema)?;
        let mut expected_ddl = ddl();
        expected_ddl.sort_by_key(|s| s.split_whitespace().nth(2).unwrap_or("").to_owned());
        if actual != expected_ddl {
            return Err(Refusal::Schema);
        }
        validate_closure(&connection)?;
        if digest(&connection)? != manifest.content_digest {
            return Err(Refusal::Content);
        }
        Ok(Self {
            connection,
            expected,
            _file: file,
        })
    }
    /// Closed relation reads only, after identity admission. No arbitrary SQL,
    /// PRAGMA, attachment, write, or connection escape hatch.
    pub fn relation(&self, name: &str) -> Result<Vec<Vec<Value>>> {
        file_fence::verify_on(&self.connection, &self.expected).map_err(|_| Refusal::Identity)?;
        let (_, columns) = tables()
            .into_iter()
            .find(|(n, _)| n == name)
            .ok_or(Refusal::Schema)?;
        let mut stmt = storage(
            self.connection
                .prepare(&format!("SELECT {} FROM main.{name}", quoted(&columns))),
        )?;
        let rows = storage(stmt.query_map([], |r| (0..columns.len()).map(|i| r.get(i)).collect()))?;
        storage(rows.collect())
    }
}

#[cfg(test)]
mod tests;
