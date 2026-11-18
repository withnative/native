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

pub(crate) mod attachments;
pub(crate) mod executor;
mod query;
mod selection;
pub(crate) mod session;
pub(crate) mod source_context;
pub(crate) mod virtual_root;

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
    "facet_times",
    "schema_config",
    "facet_keys",
    "comment_anchors",
    "bindings",
    "viewer",
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
        "member_record_metadata".into(),
        vec![
            "record_id".into(),
            "owner_id".into(),
            "custody_boundary".into(),
            "display_reference".into(),
            "native_comment".into(),
            "bears_shape".into(),
            "blob_metadata".into(),
            "native_identity".into(),
            "comment_context".into(),
            "containment_path_visible".into(),
        ],
    ));
    tables.push((
        "member_context".into(),
        vec![
            "instructions".into(),
            "schema_incomplete_for".into(),
            "principal".into(),
            "instruction_source_ids".into(),
            "virtual_root".into(),
            "source_context".into(),
        ],
    ));
    tables.push((
        "member_attachments".into(),
        ["record_id", "metadata", "sha256", "bytes"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    ));
    tables.push((
        "member_mentions".into(),
        [
            "source_id",
            "authored_reference",
            "lookup_key",
            "form",
            "span_start",
            "span_end",
        ]
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
        (SELECT count(*) FROM main.viewer)!=1 OR
        EXISTS(SELECT 1 FROM main.viewer v WHERE v.person_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM main.records r WHERE r.id=v.person_id)) OR
        EXISTS(SELECT 1 FROM main.links l WHERE NOT EXISTS(SELECT 1 FROM main.records r WHERE r.id=l.source_id) OR NOT EXISTS(SELECT 1 FROM main.records r WHERE r.id=l.target_id)) OR
        EXISTS(SELECT 1 FROM main.facet_values f WHERE NOT EXISTS(SELECT 1 FROM main.records r WHERE r.id=f.record_id)) OR
        (SELECT count(*) FROM main.member_attachments)!=(SELECT count(DISTINCT record_id) FROM main.member_attachments) OR
        EXISTS(SELECT 1 FROM main.member_attachments a WHERE NOT EXISTS(SELECT 1 FROM main.records r JOIN main.facet_values f ON f.record_id=r.id AND f.key='blob_ref' WHERE r.id=a.record_id AND r.type='Document' AND r.kind='attachment' AND r.deleted_at IS NULL AND f.value=json_extract(a.metadata,'$.id'))) OR
        (SELECT count(*) FROM main.member_record_metadata)!=(SELECT count(*) FROM main.records) OR
        (SELECT count(*) FROM main.member_record_metadata)!=(SELECT count(DISTINCT record_id) FROM main.member_record_metadata) OR
        EXISTS(SELECT 1 FROM main.member_record_metadata m WHERE NOT EXISTS(SELECT 1 FROM main.records r WHERE r.id=m.record_id) OR (m.owner_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM main.records r WHERE r.id=m.owner_id)) OR m.custody_boundary NOT IN (0,1) OR m.containment_path_visible IS NULL OR typeof(m.containment_path_visible)!='integer' OR m.containment_path_visible NOT IN (0,1) OR m.bears_shape NOT IN (0,1) OR m.native_comment NOT IN (0,1) OR (m.native_comment=1 AND NOT EXISTS(SELECT 1 FROM main.records r WHERE r.id=m.record_id AND r.type='Annotation' AND r.kind='comment')) OR (m.blob_metadata IS NOT NULL AND NOT EXISTS(SELECT 1 FROM main.member_attachments a WHERE a.record_id=m.record_id AND a.metadata=m.blob_metadata))) OR
        EXISTS(SELECT 1 FROM main.member_mentions m WHERE NOT EXISTS(SELECT 1 FROM main.records r WHERE r.id=m.source_id AND m.span_start>=0 AND m.span_end>=m.span_start AND m.span_end<=length(CAST(r.body AS BLOB)))) OR
        EXISTS(SELECT 1 FROM main.comment_anchors a WHERE NOT EXISTS(SELECT 1 FROM main.records r WHERE r.id=a.annotation_id) OR NOT EXISTS(SELECT 1 FROM main.records r WHERE r.id=a.target_record_id))", [], |r| r.get(0)))?;
    if invalid {
        return Err(Refusal::Content);
    }
    let count: i64 =
        storage(conn.query_row("SELECT COUNT(*) FROM main.member_context", [], |r| r.get(0)))?;
    if count != 1 {
        return Err(Refusal::Content);
    }
    let root: String = storage(conn.query_row(
        "SELECT virtual_root FROM main.member_context",
        [],
        |r| r.get(0),
    ))?;
    virtual_root::MemberVirtualRoot::decode(&root).map_err(|_| Refusal::Content)?;
    let selected: String = storage(conn.query_row(
        "SELECT source_context FROM main.member_context",
        [],
        |row| row.get(0),
    ))?;
    let selected = source_context::MemberSourceContext::decode(&selected)?;
    source_context::MemberSourceContext::validate_held(&selected, conn)?;
    let (principal, sources): (String, String) = storage(conn.query_row(
        "SELECT principal,instruction_source_ids FROM main.member_context",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ))?;
    let principal: serde_json::Value =
        serde_json::from_str(&principal).map_err(|_| Refusal::Content)?;
    let expected: String = storage(conn.query_row(
        "SELECT principal_id FROM main.kernel_member_identity WHERE singleton=1",
        [],
        |r| r.get(0),
    ))?;
    if principal.as_object().is_none_or(|object| object.len() != 4)
        || principal["principal_id"].as_str() != Some(expected.as_str())
        || principal["kind"].as_str().is_none()
        || principal["display_name"].as_str().is_none()
        || principal["identity_basis"] != "authenticated kernel auth_binding"
    {
        return Err(Refusal::Content);
    }
    let sources: Vec<String> = serde_json::from_str(&sources).map_err(|_| Refusal::Content)?;
    if sources.iter().collect::<BTreeSet<_>>().len() != sources.len() {
        return Err(Refusal::Content);
    }
    for id in &sources {
        let held:bool=storage(conn.query_row("SELECT EXISTS(SELECT 1 FROM main.records WHERE id=? AND deleted_at IS NULL AND archived=0)",[id],|r|r.get(0)))?;
        if !held {
            return Err(Refusal::Content);
        }
    }
    let instructions: String = storage(conn.query_row(
        "SELECT instructions FROM main.member_context",
        [],
        |r| r.get(0),
    ))?;
    let instructions: serde_json::Value =
        serde_json::from_str(&instructions).map_err(|_| Refusal::Content)?;
    for entry in instructions["entries"].as_array().ok_or(Refusal::Content)? {
        let id = entry["source"]["record_id"]
            .as_str()
            .ok_or(Refusal::Content)?;
        if !sources.iter().any(|source| source == id) {
            return Err(Refusal::Content);
        }
        let held_body: Option<String> = storage(conn.query_row(
            "SELECT body FROM main.records WHERE id=?",
            [id],
            |r| r.get(0),
        ))?;
        if entry["content"].as_str() != held_body.as_deref() {
            return Err(Refusal::Content);
        }
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
        if meta.sha256 != sha
            || hash(&bytes) != sha
            || meta.size_bytes != bytes.len() as i64
            || meta.storage_tier != "inline"
        {
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

    /// Copy the sealed artifact to registry-owned immutable storage. The
    /// registry supplies a unique pathname; never overwrite a published file.
    pub fn persist(&self, path: &Path) -> Result<()> {
        let mut source = storage(self.builder._file.reopen())?;
        storage(source.seek(SeekFrom::Start(0)))?;
        let mut output = storage(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path),
        )?;
        storage(std::io::copy(&mut source, &mut output))?;
        storage(output.sync_all())?;
        Ok(())
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
    let instructions =
        crate::mcp::kernel_v2::selected_standing_instructions_on(source, &cut.principal_id, true)
            .await
            .map_err(|_| Refusal::Authorization)?;
    let principal = crate::mcp::kernel_v2::bootstrap_principal_on(source, &cut.principal_id)
        .await
        .map_err(|_| Refusal::Authorization)?;
    let virtual_root = virtual_root::capture(source, &cut.principal_id).await?;
    // Only the sealed captured principal selects this association, before TEMP
    // staging. The shared source helper owns preparation and current View checks.
    let source_context =
        crate::kernel::v1_state::member_context::member_delivery_on(source, &cut.principal_id)
            .await
            .map_err(|_| Refusal::Authorization)?;
    let source_context = source_context::MemberSourceContext::decode(&storage(
        serde_json::to_string(&source_context),
    )?)?;
    let schema = crate::kernel::v1_state::schema_rows_on(source, &cut.principal_id)
        .await
        .map_err(|_| Refusal::Authorization)?;
    let reads: BTreeSet<_> = tables()
        .into_iter()
        .filter(|(name, _)| {
            ![
                "member_attachments",
                "member_context",
                "member_record_metadata",
                "member_mentions",
                "schema_config",
                "facet_keys",
            ]
            .contains(&name.as_str())
        })
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
    for (name, columns) in tables().into_iter().filter(|(name, _)| {
        ![
            "member_attachments",
            "member_context",
            "member_record_metadata",
            "member_mentions",
            "schema_config",
            "facet_keys",
        ]
        .contains(&name.as_str())
    }) {
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
    let shape_ids = schema
        .iter()
        .filter_map(|row| row.applies_to_collection_id.clone())
        .collect::<BTreeSet<_>>();
    manifest.schema_incomplete_for = selection::populate(
        source,
        &mut builder.connection,
        schema,
        selection::SelectedMemberContext {
            instructions: instructions.instructions,
            instruction_source_ids: instructions.source_ids,
            principal,
            virtual_root,
            source_context,
        },
    )
    .await?;
    let ids: Vec<String> = storage(sqlx::query_scalar("SELECT a.record_id FROM main.kernel_attachment_blobs a JOIN temp.records r ON r.id=a.record_id ORDER BY a.record_id").fetch_all(&mut *source).await)?;
    // Physical kernel helpers use the canonical tables. In particular the
    // logical TEMP content_events must not shadow their physical event stream.
    // Roll back only our staging, retaining the caller's original read cut.
    storage(
        sqlx::query("ROLLBACK TO native_member_projection; RELEASE native_member_projection")
            .execute(&mut *source)
            .await,
    )?;
    selection::record_metadata(
        source,
        &mut builder.connection,
        &cut.principal_id,
        &shape_ids,
    )
    .await?;
    selection::mentions(&mut builder.connection)?;
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
    principal: String,
    read_snapshots: std::sync::Arc<crate::db::ReadSnapshotCache>,
}
impl AdmittedMemberFile {
    pub fn open(
        path: &Path,
        copy_root: &Path,
        context: &MemberCopyContext,
        manifest: &ReplicaGenerationManifest,
    ) -> Result<Self> {
        // Lifecycle admission enforces rollback refusal before calling here.
        // This independent file verifier grants no serving authority.
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
        let declared: String = storage(connection.query_row(
            "SELECT schema_incomplete_for FROM main.member_context",
            [],
            |r| r.get(0),
        ))?;
        if serde_json::from_str::<Vec<String>>(&declared).map_err(|_| Refusal::Content)?
            != manifest.schema_incomplete_for
        {
            return Err(Refusal::Content);
        }
        validate_closure(&connection)?;
        if digest(&connection)? != manifest.content_digest {
            return Err(Refusal::Content);
        }
        Ok(Self {
            connection,
            read_snapshots: Default::default(),
            expected,
            _file: file,
            principal: match &manifest.profile {
                ReplicaProfile::MemberReadKernelV2 { identity, .. } => {
                    identity.principal_id.clone()
                }
                _ => return Err(Refusal::Identity),
            },
        })
    }
    /// Persist exactly the private verified bytes; never recopy an offered
    /// pathname after verification. The lifecycle owns the destination.
    pub(crate) fn copy_to(&self, path: &Path) -> Result<()> {
        let mut source = storage(self._file.reopen())?;
        storage(source.seek(SeekFrom::Start(0)))?;
        let mut target = storage(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path),
        )?;
        storage(std::io::copy(&mut source, &mut target))?;
        storage(target.sync_all())?;
        Ok(())
    }

    /// Logical rows preserve the compiled public relation column names.
    pub(crate) fn objects(&self, name: &str) -> Result<Vec<serde_json::Value>> {
        let (_, columns) = tables()
            .into_iter()
            .find(|(n, _)| n == name)
            .ok_or(Refusal::Schema)?;
        self.relation(name)?
            .into_iter()
            .map(|row| {
                let mut object = serde_json::Map::new();
                for (key, value) in columns.iter().zip(row) {
                    object.insert(key.clone(), json_cell(value)?);
                }
                Ok(serde_json::Value::Object(object))
            })
            .collect()
    }

    pub(crate) fn principal_id(&self) -> &str {
        &self.principal
    }

    pub(crate) fn query(&self, arguments: serde_json::Value) -> crate::Result<serde_json::Value> {
        query::execute(self, arguments)
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

fn json_cell(value: Value) -> Result<serde_json::Value> {
    Ok(match value {
        Value::Null => serde_json::Value::Null,
        Value::Integer(n) => n.into(),
        Value::Real(n) => serde_json::Number::from_f64(n)
            .ok_or(Refusal::Content)?
            .into(),
        Value::Text(s) => s.into(),
        Value::Blob(_) => return Err(Refusal::Content),
    })
}

#[cfg(test)]
mod tests;
