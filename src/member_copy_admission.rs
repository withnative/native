//! Member copy admission (contract c323277 rev 7 §1.3 admission core, §1.4
//! digest recompute, §3.3 rule 9, §3.4 closure self-check, §7.1 consumer
//! pipeline; slice C1).
//!
//! Consumer-side and offline. Given a delivered `member-read-v1` SQLite file
//! and its `native.replica-generation.v2` manifest, this module proves the
//! file is the one the manifest describes, that it carries no excluded table
//! or column, that its rows are internally closed, and that its content
//! digest recomputes to the manifest's. It then installs the generation under
//! the lifecycle layout, rebuilds the derived FTS indexes from the admitted
//! rows, promotes the pointer, calls
//! [`MemberCopyLifecycle::purge_superseded`] and marks the copy refreshed.
//!
//! It does **not** implement purge, the cleanup barrier, the copy-state
//! machine, read serving, the MCP surface or networking: purge and the state
//! machine are owned by [`crate::member_copy_lifecycle`], the rest are later
//! slices. Every refusal is a typed [`AdmissionError`] value; no refusal
//! message carries a workspace counter or a record id, and nothing panics.
//!
//! Only a `Ready` result of [`MemberCopyLifecycle::mark_refreshed`] means
//! admitted. A copy in `Removed`, `Locked` or `Unavailable` yields a typed
//! not-admitted outcome ([`AdmissionError::Removed`]/`Locked`/`NotAdmitted`)
//! and promotes nothing. That promotability check runs before any install or
//! copy work, so a refused admission touches nothing on disk — the previously
//! held cut survives byte-for-byte — and no failure path removes a directory
//! that the current pointer names.
//!
//! Byte safety on the way in (F3): the staged file's size and SHA-256 are
//! verified against the manifest before any install; the install writes a temp
//! file in the generation directory and atomically renames it into place; and
//! a candidate whose `generation_id` is already the promoted one is
//! short-circuited — its delivered and installed bytes are verified, the
//! refresh is completed, and nothing is reinstalled, so corrupt same-size bytes
//! can never overwrite a live generation.
//!
//! Admission is **not** atomic against a concurrent reconnect or sign-in on
//! the same copy root. [`MemberCopyLifecycle`] exposes no lock and no
//! compare-and-swap: [`MemberCopyLifecycle::status`] reads in-memory state and
//! its persisted writes are whole-file read-modify-write, so a second
//! `MemberCopyLifecycle` (another thread or process) that raises a removal
//! barrier between the promotability check and `mark_refreshed` has its state
//! silently overwritten. The lifecycle's documented quiescence obligation
//! covers the barrier, `purge_superseded` and the first sign-in, but not this
//! install/promote path. The C2c-1 refresh driver MUST therefore serialise
//! admission, reconnect and sign-in for one copy root behind a single driver
//! (one lifecycle owner, no concurrent writers). This module cannot enforce
//! it; whether the lifecycle should offer the lock is with the lifecycle owner
//! (Native 0da9bff).
//!
//! ## Trust root (contract §3.4)
//!
//! Admission proves internal closure, not eligibility. It cannot re-derive
//! E(m) offline, so it cannot detect a producer that shipped rows outside
//! E(m) (the over-shipment case). Eligibility is `producer_attested`: the
//! producer's full-evaluator fold plus authenticated transport are the trust
//! root (§0, §3.4, D2). The delivered slice is trusted to be E(m).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use sha2::Digest as _;

use crate::holding::ReplicaScope;
use crate::member_copy_lifecycle::{CopyStatus, MemberCopyLifecycle};
use crate::member_digest::content_digest;
use crate::replica_generation::{ReplicaGenerationManifest, ReplicaOrdering, ReplicaProfile};
use crate::schema::member_schema::{
    member_ddl_statements, member_schema_digest, EXTERNAL_REF_WITHHELD_COLUMN,
};
use crate::standby_snapshot::StandbyConsumerIdentity;

const CACHE_DIR_NAME: &str = "generations";
const POINTER_FILENAME: &str = "current.json";
pub(crate) const SNAPSHOT_FILENAME: &str = "snapshot.db";

/// Typed admission refusal (contract §1.3, §3.3 rule 9, §3.4). Serialised
/// with a `code` tag so a refusal payload can be scanned for counter-bearing
/// fields (§7.2 item 8). No variant carries a record id.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum AdmissionError {
    /// The manifest bytes are not a `native.replica-generation.v2` document.
    ManifestMalformed { detail: String },
    /// The manifest parses but fails shape/pairing validation (§1.3).
    ManifestRejected { detail: String },
    /// The file is not a regular file (directory, device, ...).
    NotRegularFile,
    /// The file is a symlink; admission never follows one (§1.3).
    SymlinkRefused,
    /// A SQLite sidecar (`-wal`/`-shm`/`-journal`) sits beside the file.
    SidecarPresent,
    /// The file size differs from the manifest's byte identity.
    SizeMismatch,
    /// The file SHA-256 differs from the manifest's byte identity.
    DigestMismatch,
    /// The manifest's origin database id is not the expected one.
    OriginMismatch,
    /// The manifest's member scope_ref is not the device's expected footing.
    AccountMismatch,
    /// The manifest's declared consumer identity is not this device's (§1.3
    /// "the manifest–consumer match").
    ConsumerMismatch,
    /// The manifest's declared schema digest is not this build's compiled one
    /// (§3.3 rule 9: unknown schema digest refuses admission).
    UnknownSchemaDigest,
    /// A shipped table's columns do not match the compiled member profile.
    SchemaMismatch { table: String },
    /// The file carries a table the member profile never ships (an excluded
    /// engine table or a locally derived index).
    UnexpectedTable { table: String },
    /// A shipped table is absent from the file.
    MissingTable { table: String },
    /// `PRAGMA integrity_check` did not answer `ok`.
    IntegrityCheckFailed,
    /// `PRAGMA foreign_key_check` reported rows (§3.4).
    ForeignKeyViolation,
    /// A link endpoint, annotation target, `home_id` or `owner_id` is present
    /// but unresolved (§3.4 closure).
    DanglingReference { table: String, column: String },
    /// A blob row is not reached by an included attachment (§3.4).
    BlobUnreached,
    /// An external-tier row with a NULL `external_ref` lacks the
    /// `external_ref_withheld = 1` marker (F5, §3.4).
    ExternalRefMissingMarker,
    /// The locally recomputed content digest differs from the manifest (§1.4,
    /// §3.4).
    ContentDigestMismatch,
    /// The delivered generation would roll the installed scope backwards
    /// (§1.3 ordering, F4).
    RollbackRefused,
    /// The derived index rebuild failed.
    IndexRebuildFailed { detail: String },
    /// Local filesystem failure while installing the generation.
    Io { detail: String },
    /// The lifecycle module refused promotion or purge.
    Lifecycle { detail: String },
    /// The copy is `Removed`: admission did not promote anything. The refresh
    /// driver must re-run the §4.3 reconnect check and clear the state via
    /// `sign_in(..., Replace)` before a copy can be served.
    Removed {
        cause: crate::member_copy_lifecycle::RemovedCause,
        deletion: crate::member_copy_lifecycle::DeletionState,
    },
    /// The copy is `Locked`: reconnect after sign-in. Admission did not
    /// promote anything.
    Locked,
    /// The copy is not promotable (`Unavailable` or otherwise): typed
    /// not-admitted; nothing was promoted.
    NotAdmitted,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManifestMalformed { detail } => {
                write!(f, "member copy manifest is malformed: {detail}")
            }
            Self::ManifestRejected { detail } => {
                write!(f, "member copy manifest is rejected: {detail}")
            }
            Self::NotRegularFile => write!(f, "member copy is not a regular file"),
            Self::SymlinkRefused => write!(f, "member copy is a symlink"),
            Self::SidecarPresent => write!(f, "member copy has a SQLite sidecar"),
            Self::SizeMismatch => write!(f, "member copy size does not match the manifest"),
            Self::DigestMismatch => write!(f, "member copy bytes do not match the manifest"),
            Self::OriginMismatch => write!(f, "member copy origin does not match"),
            Self::AccountMismatch => write!(f, "member copy scope does not match the account"),
            Self::ConsumerMismatch => {
                write!(f, "member copy consumer does not match this device")
            }
            Self::UnknownSchemaDigest => write!(f, "member copy schema digest is unknown"),
            Self::SchemaMismatch { table } => {
                write!(f, "member copy table {table} does not match the profile")
            }
            Self::UnexpectedTable { table } => {
                write!(f, "member copy carries an unshipped table {table}")
            }
            Self::MissingTable { table } => {
                write!(f, "member copy is missing the shipped table {table}")
            }
            Self::IntegrityCheckFailed => write!(f, "member copy failed integrity_check"),
            Self::ForeignKeyViolation => write!(f, "member copy failed foreign_key_check"),
            Self::DanglingReference { table, column } => {
                write!(f, "member copy has a dangling {table}.{column} reference")
            }
            Self::BlobUnreached => write!(f, "member copy has a blob not reached by an attachment"),
            Self::ExternalRefMissingMarker => {
                write!(f, "member copy has an unmarked external_ref")
            }
            Self::ContentDigestMismatch => {
                write!(f, "member copy content digest does not match the manifest")
            }
            Self::RollbackRefused => write!(f, "member copy would roll the scope backwards"),
            Self::IndexRebuildFailed { detail } => {
                write!(f, "member copy index rebuild failed: {detail}")
            }
            Self::Io { detail } => write!(f, "member copy install failed: {detail}"),
            Self::Lifecycle { detail } => write!(f, "member copy lifecycle refused: {detail}"),
            Self::Removed { .. } => {
                write!(f, "member copy was removed; reconnect required")
            }
            Self::Locked => write!(f, "member copy is locked; reconnect after sign-in"),
            Self::NotAdmitted => write!(f, "member copy is not admitted"),
        }
    }
}

impl std::error::Error for AdmissionError {}

/// The generation already installed for a copy root, if any. Only the fields
/// the §1.3 ordering refusal needs: identity, scope, ordinal and digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledGeneration {
    pub generation_id: String,
    pub scope_ref: String,
    pub ordinal: i64,
    pub content_digest: String,
}

/// The device's own expected footing, checked fail-closed against the
/// manifest before any file is touched (§1.3, da0a471 acceptance). `consumer`
/// is the device's declared consumer identity; the manifest's `consumer` must
/// equal it (§1.3 "the manifest–consumer match").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedFooting {
    pub origin_database_id: String,
    pub scope_ref: String,
    pub consumer: StandbyConsumerIdentity,
}

/// A validated, installed and promoted member generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedGeneration {
    pub generation_id: String,
    pub scope_ref: String,
    pub ordinal: i64,
    pub content_digest: String,
    /// The cut boundary from the manifest (`captured_at`), carried into the
    /// lifecycle as the member-facing `cut_at`.
    pub cut_at: String,
    /// §3.3 rule 6: `[]` when the exact-id gate passed everywhere,
    /// `["global"]` when a global row was withheld, otherwise the visible
    /// collection ids whose schema surfaces must refuse. C2's schema surfaces
    /// read this to refuse only where a row was withheld.
    pub schema_incomplete_for: Vec<String>,
    /// `generations/<generation_id>/` under the copy root.
    pub generation_dir: PathBuf,
}

/// Manifest facts extracted after parsing, validation and the scope/profile
/// pairing checks. Visible crate-wide so the D1 serving composition can
/// persist and re-derive the same validated facts on a fail-closed reopen
/// without duplicating the member-arm checks.
pub(crate) struct ValidatedManifest {
    pub(crate) generation_id: String,
    pub(crate) origin_database_id: String,
    pub(crate) scope_ref: String,
    pub(crate) ordinal: i64,
    pub(crate) content_digest: String,
    pub(crate) declared_schema_digest: String,
    pub(crate) consumer: StandbyConsumerIdentity,
    pub(crate) captured_at: String,
    pub(crate) schema_incomplete_for: Vec<String>,
    pub(crate) size_bytes: u64,
    pub(crate) sha256: String,
}

/// Parses and validates the manifest, then extracts the member facts admission
/// uses. Contract, shape, time order and the scope/ordering/profile pairing
/// come from [`ReplicaGenerationManifest::validate`]; this adds the explicit
/// member arm so a future wildcard cannot silently accept a non-member scope.
pub(crate) fn validate_manifest(bytes: &[u8]) -> Result<ValidatedManifest, AdmissionError> {
    let manifest: ReplicaGenerationManifest =
        serde_json::from_slice(bytes).map_err(|e| AdmissionError::ManifestMalformed {
            detail: e.to_string(),
        })?;
    manifest
        .validate()
        .map_err(|e| AdmissionError::ManifestRejected {
            detail: e.to_string(),
        })?;
    let scope_ref = match &manifest.scope {
        ReplicaScope::Member { scope_ref } => scope_ref.clone(),
        ReplicaScope::Everything => {
            return Err(AdmissionError::ManifestRejected {
                detail: "member admission needs a member scope".to_owned(),
            })
        }
    };
    let ordinal = match &manifest.ordering {
        ReplicaOrdering::Scoped { ordinal } => *ordinal,
        ReplicaOrdering::Act { .. } => {
            return Err(AdmissionError::ManifestRejected {
                detail: "member admission needs a scoped ordering".to_owned(),
            })
        }
    };
    let declared_schema_digest = match &manifest.profile {
        ReplicaProfile::MemberReadV1 {
            member_schema_digest,
        } => member_schema_digest.clone(),
        ReplicaProfile::CanonicalEngine => {
            return Err(AdmissionError::ManifestRejected {
                detail: "member admission needs the member-read-v1 profile".to_owned(),
            })
        }
    };
    Ok(ValidatedManifest {
        generation_id: manifest.generation_id(),
        origin_database_id: manifest.origin_database_id.clone(),
        scope_ref,
        ordinal,
        content_digest: manifest.content_digest.clone(),
        declared_schema_digest,
        consumer: manifest.consumer.clone(),
        captured_at: manifest.captured_at.clone(),
        schema_incomplete_for: manifest.schema_incomplete_for.clone(),
        size_bytes: manifest.bytes.size_bytes,
        sha256: manifest.bytes.sha256.clone(),
    })
}

/// §1.3 ordering (F4): a re-delivered generation for the same scope must not
/// move the ordinal backwards, and an equal ordinal must carry equal content.
/// A different scope_ref is a replace and is allowed; the lifecycle module
/// owns the old copy's purge.
fn refuse_rollback(
    installed: Option<&InstalledGeneration>,
    candidate: &ValidatedManifest,
) -> Result<(), AdmissionError> {
    let Some(installed) = installed else {
        return Ok(());
    };
    if installed.scope_ref != candidate.scope_ref {
        return Ok(());
    }
    if candidate.ordinal < installed.ordinal {
        return Err(AdmissionError::RollbackRefused);
    }
    if candidate.ordinal == installed.ordinal
        && candidate.content_digest != installed.content_digest
    {
        return Err(AdmissionError::RollbackRefused);
    }
    Ok(())
}

/// SHA-256 of a file, streamed (a member file can be large).
fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read as _;
    let mut file = File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// §1.3 admission core: regular file, no symlink.
fn check_regular_file(path: &Path) -> Result<(), AdmissionError> {
    let metadata = fs::symlink_metadata(path).map_err(|e| AdmissionError::Io {
        detail: e.to_string(),
    })?;
    if metadata.file_type().is_symlink() {
        return Err(AdmissionError::SymlinkRefused);
    }
    if !metadata.is_file() {
        return Err(AdmissionError::NotRegularFile);
    }
    Ok(())
}

/// §1.3 admission core: no SQLite sidecar may travel with the copy.
/// `symlink_metadata` so a dangling `foo-wal` symlink still counts as present
/// (L2); the sidecar suffix is unreachable through a normal file walk.
fn refuse_sidecars(path: &Path) -> Result<(), AdmissionError> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut candidate = path.as_os_str().to_os_string();
        candidate.push(suffix);
        if fs::symlink_metadata(Path::new(&candidate)).is_ok() {
            return Err(AdmissionError::SidecarPresent);
        }
    }
    Ok(())
}

/// §1.3 admission core: byte identity (size + SHA-256) against the manifest.
fn check_byte_identity(
    path: &Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(), AdmissionError> {
    let metadata = fs::metadata(path).map_err(|e| AdmissionError::Io {
        detail: e.to_string(),
    })?;
    if metadata.len() != expected_size {
        return Err(AdmissionError::SizeMismatch);
    }
    let actual = sha256_file(path).map_err(|e| AdmissionError::Io {
        detail: e.to_string(),
    })?;
    if actual != expected_sha256.to_ascii_lowercase() {
        return Err(AdmissionError::DigestMismatch);
    }
    Ok(())
}

/// Column names of one table, via `PRAGMA table_info`.
fn table_columns(conn: &Connection, table: &str) -> Result<BTreeSet<String>, AdmissionError> {
    let pragma = format!("PRAGMA table_info(\"{}\")", table.replace('"', "\"\""));
    let mut statement = conn
        .prepare(&pragma)
        .map_err(|_| AdmissionError::SchemaMismatch {
            table: table.to_owned(),
        })?;
    statement
        .query_map([], |row| row.get::<_, String>(1))
        .and_then(|rows| rows.collect::<Result<BTreeSet<_>, _>>())
        .map_err(|_| AdmissionError::SchemaMismatch {
            table: table.to_owned(),
        })
}

/// Compiled member schema: shipped table set plus per-table columns.
type CompiledMemberSchema = (BTreeSet<String>, BTreeMap<String, BTreeSet<String>>);

/// The compiled `member-read-v1` table -> columns, from the same DDL the
/// producer compiles. This is the consumer's side of the schema agreement
/// (§3.1 "a consumer whose compiled profile differs refuses admission").
fn compiled_member_schema() -> Result<CompiledMemberSchema, AdmissionError> {
    let conn = Connection::open_in_memory().map_err(|e| AdmissionError::Io {
        detail: e.to_string(),
    })?;
    conn.execute_batch(&member_ddl_statements().join(";\n"))
        .map_err(|_| AdmissionError::SchemaMismatch {
            table: "member-read-v1".to_owned(),
        })?;
    let tables = member_table_names(&conn)?;
    let mut columns = BTreeMap::new();
    for table in &tables {
        columns.insert(table.clone(), table_columns(&conn, table)?);
    }
    Ok((tables, columns))
}

/// Non-internal table names of a connection.
fn member_table_names(conn: &Connection) -> Result<BTreeSet<String>, AdmissionError> {
    let mut statement = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .map_err(|e| AdmissionError::Io {
            detail: e.to_string(),
        })?;
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .and_then(|rows| rows.collect::<Result<BTreeSet<_>, _>>())
        .map_err(|e| AdmissionError::Io {
            detail: e.to_string(),
        })
}

/// §3.4: the file must contain exactly the shipped tables, with exactly the
/// compiled columns. An excluded engine table (or a locally derived index a
/// producer should never ship) refuses; a dropped log-position column added
/// back refuses too (it would be invisible to the content digest).
fn check_file_schema(conn: &Connection) -> Result<(), AdmissionError> {
    let (expected_tables, expected_columns) = compiled_member_schema()?;
    let actual_tables = member_table_names(conn)?;
    for table in &actual_tables {
        if !expected_tables.contains(table) {
            return Err(AdmissionError::UnexpectedTable {
                table: table.clone(),
            });
        }
    }
    for table in &expected_tables {
        if !actual_tables.contains(table) {
            return Err(AdmissionError::MissingTable {
                table: table.clone(),
            });
        }
        if table_columns(conn, table)? != expected_columns[table] {
            return Err(AdmissionError::SchemaMismatch {
                table: table.clone(),
            });
        }
    }
    Ok(())
}

/// The two locally rebuilt derived indexes and their FTS5 shadow tables.
/// Exactly these names are tolerated on a reopen; a prefix allow would admit
/// `records_fts_evil`.
fn is_derived_index_table(table: &str) -> bool {
    const SHADOW_SUFFIXES: &[&str] = &["", "_data", "_idx", "_content", "_docsize", "_config"];
    ["records_fts", "records_name_idx"].iter().any(|base| {
        SHADOW_SUFFIXES
            .iter()
            .any(|suffix| table == format!("{base}{suffix}"))
    })
}

/// Reopen-time schema check. Identical to [`check_file_schema`] except that the
/// locally rebuilt derived indexes are admitted: admission appended them after
/// the shipped-table check, so an installed file always carries them and a
/// reopen must not reject a valid generation for their presence. Every shipped
/// table still needs its exact compiled columns, and any table that is neither
/// shipped nor a derived index (an excluded engine table) still refuses.
fn check_installed_file_schema(conn: &Connection) -> Result<(), AdmissionError> {
    let (expected_tables, expected_columns) = compiled_member_schema()?;
    let actual_tables = member_table_names(conn)?;
    for table in &actual_tables {
        if expected_tables.contains(table) || is_derived_index_table(table) {
            continue;
        }
        return Err(AdmissionError::UnexpectedTable {
            table: table.clone(),
        });
    }
    for table in &expected_tables {
        if !actual_tables.contains(table) {
            return Err(AdmissionError::MissingTable {
                table: table.clone(),
            });
        }
        if table_columns(conn, table)? != expected_columns[table] {
            return Err(AdmissionError::SchemaMismatch {
                table: table.clone(),
            });
        }
    }
    Ok(())
}

/// True when a `SELECT 1 ... LIMIT 1` row exists.
fn has_row(conn: &Connection, sql: &str) -> Result<bool, AdmissionError> {
    match conn.query_row(sql, [], |_| Ok(true)) {
        Ok(true) => Ok(true),
        Ok(false) | Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => Err(AdmissionError::Io {
            detail: e.to_string(),
        }),
    }
}

/// §1.3 admission core: `PRAGMA integrity_check` must answer `ok`.
fn check_integrity(conn: &Connection) -> Result<(), AdmissionError> {
    let answer: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| AdmissionError::IntegrityCheckFailed)?;
    if answer.eq_ignore_ascii_case("ok") {
        Ok(())
    } else {
        Err(AdmissionError::IntegrityCheckFailed)
    }
}

/// §1.3 admission core: `PRAGMA foreign_key_check` must be clean.
fn check_foreign_keys(conn: &Connection) -> Result<(), AdmissionError> {
    let mut statement =
        conn.prepare("PRAGMA foreign_key_check")
            .map_err(|e| AdmissionError::Io {
                detail: e.to_string(),
            })?;
    let mut rows = statement.query([]).map_err(|e| AdmissionError::Io {
        detail: e.to_string(),
    })?;
    match rows.next().map_err(|e| AdmissionError::Io {
        detail: e.to_string(),
    })? {
        Some(_) => Err(AdmissionError::ForeignKeyViolation),
        None => Ok(()),
    }
}

/// §3.4 closure: every `links` endpoint, `annotation_targets.target_record_id`,
/// `home_id` and `owner_id` is present or NULL.
fn check_dangling(conn: &Connection) -> Result<(), AdmissionError> {
    let checks: [(&str, &str, &str); 5] = [
        (
            "links",
            "source_id",
            "SELECT 1 FROM links WHERE source_id NOT IN (SELECT id FROM records) LIMIT 1",
        ),
        (
            "links",
            "target_id",
            "SELECT 1 FROM links WHERE target_id NOT IN (SELECT id FROM records) LIMIT 1",
        ),
        (
            "annotation_targets",
            "target_record_id",
            "SELECT 1 FROM annotation_targets WHERE target_record_id IS NOT NULL \
             AND target_record_id NOT IN (SELECT id FROM records) LIMIT 1",
        ),
        (
            "records",
            "home_id",
            "SELECT 1 FROM records WHERE home_id IS NOT NULL \
             AND home_id NOT IN (SELECT id FROM records) LIMIT 1",
        ),
        (
            "records",
            "owner_id",
            "SELECT 1 FROM records WHERE owner_id IS NOT NULL \
             AND owner_id NOT IN (SELECT id FROM records) LIMIT 1",
        ),
    ];
    for (table, column, sql) in checks {
        if has_row(conn, sql)? {
            return Err(AdmissionError::DanglingReference {
                table: table.to_owned(),
                column: column.to_owned(),
            });
        }
    }
    Ok(())
}

/// §3.4: every blob is reached by an included attachment, and F5's marker
/// distinguishes a gated NULL `external_ref` from a malformed external row.
///
/// Reachability mirrors the engine's `blobs` view (`src/query/sql.rs:630-651`):
/// a blob is reached when a `records` attachment (`type='Document'`,
/// `kind='attachment'`) carries a `facet_values` row `key='blob_ref'` whose
/// `value` is the blob id (`src/blob.rs:40`), and that attachment has a
/// `part_of` `links` row to a bearer record that is itself present in the file.
/// Every row in the copy is E(m), so "present in `records`" is the member-side
/// spelling of the view's `_query_sql_visible_records` joins; the producer's
/// exactly-one-bearer eligibility walk (§3.3 rule 3) already decided inclusion.
fn check_blobs(conn: &Connection) -> Result<(), AdmissionError> {
    if has_row(
        conn,
        "SELECT 1 FROM blobs b WHERE NOT EXISTS (\
           SELECT 1 FROM records attachment \
           JOIN facet_values blob_ref \
             ON blob_ref.record_id = attachment.id \
            AND blob_ref.key = 'blob_ref' \
            AND blob_ref.value = b.id \
           JOIN links bearer \
             ON bearer.source_id = attachment.id \
            AND bearer.relationship = 'part_of' \
           JOIN records bearer_record ON bearer_record.id = bearer.target_id \
           WHERE attachment.type = 'Document' AND attachment.kind = 'attachment'\
         ) LIMIT 1",
    )? {
        return Err(AdmissionError::BlobUnreached);
    }
    let marker = EXTERNAL_REF_WITHHELD_COLUMN;
    // `IS NOT 1` (not `<> 1`) so a NULL marker is treated as unmarked rather
    // than excluded from the predicate (L1).
    let unmarked = format!(
        "SELECT 1 FROM blobs WHERE storage_tier = 'external' AND external_ref IS NULL \
         AND {marker} IS NOT 1 LIMIT 1"
    );
    if has_row(conn, &unmarked)? {
        return Err(AdmissionError::ExternalRefMissingMarker);
    }
    let spurious =
        format!("SELECT 1 FROM blobs WHERE external_ref IS NOT NULL AND {marker} = 1 LIMIT 1");
    if has_row(conn, &spurious)? {
        return Err(AdmissionError::ExternalRefMissingMarker);
    }
    Ok(())
}

/// §3.4: the locally recomputed content digest equals the manifest's (§1.4).
fn check_content_digest(conn: &Connection, expected: &str) -> Result<(), AdmissionError> {
    let actual = content_digest(conn).map_err(|e| AdmissionError::Io {
        detail: e.to_string(),
    })?;
    if actual != expected {
        return Err(AdmissionError::ContentDigestMismatch);
    }
    Ok(())
}

/// §7.1: rebuild the derived FTS indexes from the admitted rows only. They are
/// never shipped (contract §3.2 "Derived, rebuilt locally"), and no triggers
/// are installed: the member copy is read-only in v1.
fn rebuild_derived_indexes(conn: &Connection) -> Result<(), AdmissionError> {
    conn.execute_batch(
        "CREATE VIRTUAL TABLE records_fts USING fts5 (\
           name, body, content='records', content_rowid='rowid', tokenize='porter unicode61');\
         CREATE VIRTUAL TABLE records_name_idx USING fts5 (\
           name, content='records', content_rowid='rowid', tokenize='unicode61');",
    )
    .map_err(|e| AdmissionError::IndexRebuildFailed {
        detail: e.to_string(),
    })?;
    conn.execute_batch(
        "INSERT INTO records_fts(records_fts) VALUES('rebuild');\
         INSERT INTO records_name_idx(records_name_idx) VALUES('rebuild');",
    )
    .map_err(|e| AdmissionError::IndexRebuildFailed {
        detail: e.to_string(),
    })?;
    Ok(())
}

fn io_error(error: std::io::Error) -> AdmissionError {
    AdmissionError::Io {
        detail: error.to_string(),
    }
}

/// §1.3 staged byte identity, checked before any install: a wrong-size or
/// corrupt download is refused here and never copied over a live generation.
fn verify_staged(staged: &Path, manifest: &ValidatedManifest) -> Result<(), AdmissionError> {
    check_regular_file(staged)?;
    refuse_sidecars(staged)?;
    check_byte_identity(staged, manifest.size_bytes, &manifest.sha256)
}

/// Verifies an already-installed generation still holds the manifest's content
/// without writing to it. The installed file cannot be compared byte-for-byte
/// (`admit_installed` appends the locally rebuilt derived indexes), so its
/// content digest is recomputed read-only instead.
fn verify_installed(path: &Path, manifest: &ValidatedManifest) -> Result<(), AdmissionError> {
    check_regular_file(path)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| AdmissionError::Io {
        detail: e.to_string(),
    })?;
    check_content_digest(&connection, &manifest.content_digest)?;
    connection.close().map_err(|(_, e)| AdmissionError::Io {
        detail: e.to_string(),
    })?;
    Ok(())
}

/// Copies the staged file into `generations/<generation_id>/snapshot.db` via a
/// temp file in the same directory and an atomic rename, so the destination is
/// never a partially written or in-place overwritten file.
fn install_staged(staged: &Path, generation_dir: &Path) -> Result<(), AdmissionError> {
    fs::create_dir_all(generation_dir).map_err(io_error)?;
    let temp = generation_dir.join(format!(".snapshot-{}.tmp", uuid::Uuid::new_v4()));
    let install = (|| -> Result<(), AdmissionError> {
        fs::copy(staged, &temp).map_err(io_error)?;
        File::open(&temp)
            .and_then(|file| file.sync_all())
            .map_err(io_error)?;
        fs::rename(&temp, generation_dir.join(SNAPSHOT_FILENAME)).map_err(io_error)?;
        File::open(generation_dir)
            .and_then(|dir| dir.sync_all())
            .map_err(io_error)?;
        Ok(())
    })();
    if install.is_err() {
        let _ = fs::remove_file(&temp);
    }
    install
}

/// Runs every §1.3/§3.4 check on the installed copy and rebuilds FTS.
fn admit_installed(path: &Path, manifest: &ValidatedManifest) -> Result<(), AdmissionError> {
    check_regular_file(path)?;
    refuse_sidecars(path)?;
    check_byte_identity(path, manifest.size_bytes, &manifest.sha256)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| AdmissionError::Io {
        detail: e.to_string(),
    })?;
    check_file_schema(&connection)?;
    check_dangling(&connection)?;
    check_blobs(&connection)?;
    check_integrity(&connection)?;
    check_foreign_keys(&connection)?;
    check_content_digest(&connection, &manifest.content_digest)?;
    rebuild_derived_indexes(&connection)?;
    connection.close().map_err(|(_, e)| AdmissionError::Io {
        detail: e.to_string(),
    })?;
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(io_error)?;
    Ok(())
}

/// Atomically writes the generation pointer the lifecycle promotes from. The
/// lifecycle reads either the raw id or `{"generation_id": "..."}`.
fn write_pointer(root: &Path, generation_id: &str) -> Result<(), AdmissionError> {
    let temp = root.join(format!(".current-{}.tmp", uuid::Uuid::new_v4()));
    let body =
        serde_jcs::to_vec(&serde_json::json!({ "generation_id": generation_id })).map_err(|e| {
            AdmissionError::Io {
                detail: e.to_string(),
            }
        })?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(io_error)?;
    file.write_all(&body).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    drop(file);
    fs::rename(&temp, root.join(POINTER_FILENAME)).map_err(io_error)?;
    File::open(root)
        .and_then(|dir| dir.sync_all())
        .map_err(io_error)?;
    Ok(())
}

/// Maps a non-`Ready` copy status to the typed not-admitted outcome (§6.1).
/// `Removed` carries its cause and deletion; `Locked` its sign-in retry;
/// anything else is the generic not-admitted.
fn not_admitted(status: &CopyStatus) -> AdmissionError {
    match status {
        CopyStatus::Removed { cause, deletion } => AdmissionError::Removed {
            cause: *cause,
            deletion: *deletion,
        },
        CopyStatus::Locked { .. } => AdmissionError::Locked,
        CopyStatus::Ready { .. } | CopyStatus::Refreshing { .. } | CopyStatus::Unavailable => {
            AdmissionError::NotAdmitted
        }
    }
}

/// Whether `current.json` names `generation_id`. Generation ids are lowercase
/// SHA-256 hex of fixed length, so one cannot be a substring of another and the
/// `contains` test cannot match the wrong generation.
fn pointer_names(copy_root: &Path, generation_id: &str) -> bool {
    fs::read(copy_root.join(POINTER_FILENAME))
        .map(|bytes| String::from_utf8_lossy(&bytes).contains(generation_id))
        .unwrap_or(false)
}

/// Removes `generation_dir` unless the current pointer names it. Called only
/// before the pointer is rewritten, so a pointer-named directory is the
/// previously held generation: a failed install of a re-delivered same-id
/// generation must not delete it.
fn remove_unless_pointed(copy_root: &Path, generation_id: &str, generation_dir: &Path) {
    if !pointer_names(copy_root, generation_id) {
        let _ = fs::remove_dir_all(generation_dir);
    }
}

/// Best-effort undo of a promotion that did not become `Ready`. If the pointer
/// names our generation, drop it first and only then remove the
/// now-unreferenced bytes, so no failure path ever removes a directory the
/// current pointer names. If the pointer names another generation, our bytes
/// are an orphan from a promotion that never took and are removed too, instead
/// of being left behind.
fn rollback_promotion(copy_root: &Path, generation_id: &str, generation_dir: &Path) {
    if pointer_names(copy_root, generation_id) {
        let _ = fs::remove_file(copy_root.join(POINTER_FILENAME));
    }
    let _ = fs::remove_dir_all(generation_dir);
}

/// Admits a delivered member copy (§1.3 admission core, §3.4 closure,
/// §7.1 consumer pipeline).
///
/// Validation, the promotability check and the staged byte-identity check all
/// happen before any install; a copy in `Removed`, `Locked` or `Unavailable` is
/// refused before the staging file is installed, so a refused admission touches
/// nothing on disk. On success the file is installed as an atomically renamed
/// `generations/<generation_id>/snapshot.db`, its derived indexes are rebuilt,
/// `current.json` names the new generation, the lifecycle purges superseded
/// generations, and the copy is marked refreshed. A failure after install
/// removes the partial generation directory and leaves the pointer untouched,
/// so the previously installed copy is unaffected; a re-delivery of the
/// currently pointed generation is short-circuited without reinstalling and
/// never has its directory removed by a failure path.
pub fn admit_member_copy(
    copy_root: &Path,
    staged_path: &Path,
    manifest_json: &[u8],
    installed: Option<&InstalledGeneration>,
    expected: &ExpectedFooting,
    lifecycle: &mut MemberCopyLifecycle,
) -> Result<AdmittedGeneration, AdmissionError> {
    let manifest = validate_manifest(manifest_json)?;

    if manifest.origin_database_id != expected.origin_database_id {
        return Err(AdmissionError::OriginMismatch);
    }
    if manifest.scope_ref != expected.scope_ref {
        return Err(AdmissionError::AccountMismatch);
    }
    if manifest.consumer != expected.consumer {
        return Err(AdmissionError::ConsumerMismatch);
    }
    if manifest.declared_schema_digest != member_schema_digest() {
        return Err(AdmissionError::UnknownSchemaDigest);
    }
    refuse_rollback(installed, &manifest)?;

    // §6.1/§7.1: only a promotable copy may be promoted, and only a `Ready`
    // result of `mark_refreshed` means admitted. `mark_refreshed` is a no-op
    // outside `Refreshing`/`Ready` (lifecycle doc), so `Removed`, `Locked` and
    // `Unavailable` must surface a typed outcome. This runs before any install
    // or copy so a refused admission touches nothing on disk — in particular
    // it never deletes the previously held cut, even when the same generation
    // id is re-delivered.
    let promotable = lifecycle.status();
    if !promotable.can_read() {
        return Err(not_admitted(&promotable));
    }

    // §1.3/F3: a re-delivery of the currently promoted generation is already
    // live. Never reinstall over its bytes: verify the delivered download and
    // the installed file both still match the manifest, complete the refresh
    // if one is running, and return the existing admission without rewriting
    // the pointer or purging. A same-size corrupt re-delivery is refused here
    // with the held bytes untouched; an already-`Ready` copy is not written to
    // at all.
    if pointer_names(copy_root, &manifest.generation_id) {
        verify_staged(staged_path, &manifest)?;
        let generation_dir = copy_root.join(CACHE_DIR_NAME).join(&manifest.generation_id);
        verify_installed(&generation_dir.join(SNAPSHOT_FILENAME), &manifest)?;
        if matches!(promotable, CopyStatus::Refreshing { .. }) {
            let status = lifecycle
                .mark_refreshed(manifest.captured_at.clone())
                .map_err(|e| AdmissionError::Lifecycle {
                    detail: e.to_string(),
                })?;
            if !matches!(status, CopyStatus::Ready { .. }) {
                return Err(not_admitted(&status));
            }
        }
        return Ok(AdmittedGeneration {
            generation_id: manifest.generation_id,
            scope_ref: manifest.scope_ref,
            ordinal: manifest.ordinal,
            content_digest: manifest.content_digest,
            cut_at: manifest.captured_at,
            schema_incomplete_for: manifest.schema_incomplete_for,
            generation_dir,
        });
    }

    // §1.3/F3: the staged byte identity is checked before any install, so a
    // wrong-size or corrupt download can never be copied over a generation.
    verify_staged(staged_path, &manifest)?;

    let generation_dir = copy_root.join(CACHE_DIR_NAME).join(&manifest.generation_id);
    install_staged(staged_path, &generation_dir)?;
    let installed_path = generation_dir.join(SNAPSHOT_FILENAME);
    if let Err(error) = admit_installed(&installed_path, &manifest) {
        // Before the pointer is rewritten, a pointer-named directory is the
        // held generation of a re-delivered same id; never delete it.
        remove_unless_pointed(copy_root, &manifest.generation_id, &generation_dir);
        return Err(error);
    }

    write_pointer(copy_root, &manifest.generation_id)?;
    lifecycle
        .purge_superseded(
            &manifest.generation_id,
            &crate::member_copy_lifecycle::NoFail,
        )
        .map_err(|e| AdmissionError::Lifecycle {
            detail: e.to_string(),
        })?;
    let status = lifecycle
        .mark_refreshed(manifest.captured_at.clone())
        .map_err(|e| AdmissionError::Lifecycle {
            detail: e.to_string(),
        })?;
    if !matches!(status, CopyStatus::Ready { .. }) {
        // Defensive: the pre-check and this call are synchronous with no
        // interleaving writer, so a non-Ready result here is a lifecycle
        // regression. Undo the promotion so nothing half-promoted is readable.
        rollback_promotion(copy_root, &manifest.generation_id, &generation_dir);
        return Err(not_admitted(&status));
    }

    Ok(AdmittedGeneration {
        generation_id: manifest.generation_id,
        scope_ref: manifest.scope_ref,
        ordinal: manifest.ordinal,
        content_digest: manifest.content_digest,
        cut_at: manifest.captured_at,
        schema_incomplete_for: manifest.schema_incomplete_for,
        generation_dir,
    })
}

/// Fail-closed reopen validation for an already-admitted generation (D1,
/// contract c323277 rev 8 "persisted validated admission").
///
/// Re-runs every §1.3/§3.4 structural and closure check against the
/// *installed* file that admission already promoted, **without** comparing it
/// to the manifest's downloaded byte identity: admission appends the locally
/// rebuilt derived FTS indexes, so the installed bytes never equal the
/// producer's SHA-256 (§1.4 excludes derived indexes from the content digest).
/// The logical content digest is recomputed instead, so a valid reopen is
/// never rejected for the byte difference, while malformed schema, excluded
/// tables, dangling rows, a wrong content digest or a symlinked/canonical file
/// still refuse.
///
/// The caller (the serving owner) is responsible for the lifecycle predicate
/// (`Ready`, pointer names the generation, nonempty `activatable_generations`)
/// and for having read the persisted manifest bytes it passes here. Nothing is
/// promoted, written or purged by this call.
pub fn revalidate_installed(
    copy_root: &Path,
    manifest_json: &[u8],
    expected: &ExpectedFooting,
) -> Result<AdmittedGeneration, AdmissionError> {
    let manifest = validate_manifest(manifest_json)?;
    if manifest.origin_database_id != expected.origin_database_id {
        return Err(AdmissionError::OriginMismatch);
    }
    if manifest.scope_ref != expected.scope_ref {
        return Err(AdmissionError::AccountMismatch);
    }
    if manifest.consumer != expected.consumer {
        return Err(AdmissionError::ConsumerMismatch);
    }
    if manifest.declared_schema_digest != member_schema_digest() {
        return Err(AdmissionError::UnknownSchemaDigest);
    }
    let generation_dir = copy_root.join(CACHE_DIR_NAME).join(&manifest.generation_id);
    let installed_path = generation_dir.join(SNAPSHOT_FILENAME);
    check_regular_file(&installed_path)?;
    refuse_sidecars(&installed_path)?;
    let connection = Connection::open_with_flags(
        &installed_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| AdmissionError::Io {
        detail: e.to_string(),
    })?;
    let structural = (|| -> Result<(), AdmissionError> {
        check_installed_file_schema(&connection)?;
        check_dangling(&connection)?;
        check_blobs(&connection)?;
        check_integrity(&connection)?;
        check_foreign_keys(&connection)?;
        check_content_digest(&connection, &manifest.content_digest)?;
        Ok(())
    })();
    let close = connection.close();
    structural?;
    close.map_err(|(_, e)| AdmissionError::Io {
        detail: e.to_string(),
    })?;
    Ok(AdmittedGeneration {
        generation_id: manifest.generation_id,
        scope_ref: manifest.scope_ref,
        ordinal: manifest.ordinal,
        content_digest: manifest.content_digest,
        cut_at: manifest.captured_at,
        schema_incomplete_for: manifest.schema_incomplete_for,
        generation_dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::holding::{HoldingDisclosureV2, HoldingWindow};
    use crate::member_copy_lifecycle::{
        CopyStatus, DeletionState, MemberCopyLifecycle, ReconnectAnswer, RemovedCause, RevokedCause,
    };
    use crate::member_offline_fixtures::assert_no_counter_fields;
    use crate::replica_generation::{
        ReplicaOwnWrites, REPLICA_GENERATION_CONTRACT, REPLICA_GENERATION_VERSION,
    };
    use crate::standby_snapshot::{
        CanonicalFrontierV1, StandbyConsumerIdentity, StandbyConsumerPlatform,
        StandbyGenerationMaterialization, StandbySnapshotBytes, StandbySnapshotEngineIdentity,
        STANDBY_CONSUMER_CONTRACT, STANDBY_FRONTIER_CONTRACT, STANDBY_SNAPSHOT_MEDIA_TYPE,
    };
    use tempfile::TempDir;

    const ORIGIN: &str = "ndb_33333333333333333333333333333333";
    const SCOPE: &str = "scope-ref-1";
    const CAPTURED: &str = "2026-09-29T00:00:00Z";

    /// Minimal valid `member-read-v1` world: a bearer note, an attachment
    /// (`Document`/`kind='attachment'`) with a `blob_ref` facet and exactly
    /// one `part_of` bearer edge, one inline blob, and display references —
    /// the engine's real attachment shape (`src/query/sql.rs:630-651`,
    /// `src/blob.rs:40`).
    const FIXTURE_SQL: &str = "
        INSERT INTO records (id, type, kind, name, body, home_id, owner_id, lifecycle,
            persistence, maturity, summary, last_activity_at, created_at, updated_at,
            deleted_at, archived)
        VALUES ('r1','Document','note','alpha','hello',NULL,NULL,'active','enduring',
            NULL,'sum','2026-09-29T00:00:00Z','2026-09-29T00:00:00Z',
            '2026-09-29T00:00:01Z',NULL,0);
        INSERT INTO records (id, type, kind, name, home_id, persistence, created_at, updated_at, archived)
        VALUES ('a1','Document','attachment','a1.txt',NULL,'enduring',
            '2026-09-29T00:00:00Z','2026-09-29T00:00:00Z',0);
        INSERT INTO links (id, source_id, target_id, relationship, note, created_at)
        VALUES ('l1','a1','r1','part_of',NULL,'2026-09-29T00:00:00Z');
        INSERT INTO blobs (id, bytes, mime, size_bytes, sha256, original_filename,
            storage_tier, external_ref, created_at, external_ref_withheld)
        VALUES ('b1', x'0102','text/plain',2,'aaa','a1.txt','inline',NULL,
            '2026-09-29T00:00:00Z',0);
        INSERT INTO facet_values (id, record_id, key, value, vocab_ref, created_at)
        VALUES ('f1','a1','blob_ref','b1',NULL,'2026-09-29T00:00:00Z');
        INSERT INTO member_display_references (record_id, display_reference)
        VALUES ('r1','a1b2'), ('a1','c3d4');";

    /// Writes a valid member file at `path` and returns its content digest.
    fn write_member_file(path: &Path) -> String {
        let connection = Connection::open(path).expect("member fixture db must open");
        connection
            .execute_batch(&member_ddl_statements().join(";\n"))
            .expect("member DDL must apply");
        connection
            .execute_batch(FIXTURE_SQL)
            .expect("member fixture must insert");
        let digest = content_digest(&connection).expect("fixture digest must compute");
        drop(connection);
        digest
    }

    /// Mutates an existing member file and returns its new content digest.
    fn mutate(path: &Path, sql: &str) -> String {
        let connection = Connection::open(path).expect("member db must reopen");
        connection.execute_batch(sql).expect("mutation must apply");
        let digest = content_digest(&connection).expect("digest must recompute");
        drop(connection);
        digest
    }

    fn sha256(bytes: &[u8]) -> String {
        hex::encode(sha2::Sha256::digest(bytes))
    }

    fn consumer_identity() -> StandbyConsumerIdentity {
        StandbyConsumerIdentity {
            contract: STANDBY_CONSUMER_CONTRACT.to_owned(),
            version: 1,
            platform: StandbyConsumerPlatform::LinuxX8664,
            source_sha: "c".repeat(40),
            artifact_sha256: "d".repeat(64),
            engine_schema_version: 1,
            ddl_sha256: "e".repeat(64),
        }
    }

    /// Builds a member manifest whose byte identity matches `path` now.
    fn manifest_for(
        path: &Path,
        content_digest: &str,
        scope_ref: &str,
        ordinal: i64,
    ) -> ReplicaGenerationManifest {
        let bytes = fs::read(path).expect("fixture bytes must read");
        ReplicaGenerationManifest {
            contract: REPLICA_GENERATION_CONTRACT.to_owned(),
            version: REPLICA_GENERATION_VERSION,
            origin_database_id: ORIGIN.to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            captured_at: CAPTURED.to_owned(),
            snapshot_completed_at: "2026-09-29T00:00:01Z".to_owned(),
            producer: StandbySnapshotEngineIdentity {
                name: "native-ce".to_owned(),
                source_sha: "a".repeat(40),
                schema_version: 1,
                ddl_sha256: "b".repeat(64),
            },
            consumer: consumer_identity(),
            bytes: StandbySnapshotBytes {
                media_type: STANDBY_SNAPSHOT_MEDIA_TYPE.to_owned(),
                size_bytes: bytes.len() as u64,
                sha256: sha256(&bytes),
            },
            materialization: StandbyGenerationMaterialization::Snapshot,
            scope: ReplicaScope::Member {
                scope_ref: scope_ref.to_owned(),
            },
            ordering: ReplicaOrdering::Scoped { ordinal },
            holding: HoldingDisclosureV2::member(scope_ref.to_owned(), ordinal),
            profile: ReplicaProfile::MemberReadV1 {
                member_schema_digest: member_schema_digest(),
            },
            content_digest: content_digest.to_owned(),
            own_writes: ReplicaOwnWrites::not_computed(),
            frontier: None,
            schema_incomplete_for: Vec::new(),
        }
    }

    /// A copy root with a staging directory and an open lifecycle.
    struct Harness {
        _dir: TempDir,
        copy_root: PathBuf,
        staged: PathBuf,
    }

    impl Harness {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let copy_root = dir.path().join("copy");
            fs::create_dir_all(copy_root.join("staging")).expect("staging dir");
            let staged = copy_root.join("staging").join("incoming.db");
            Harness {
                _dir: dir,
                copy_root,
                staged,
            }
        }

        fn expected(&self) -> ExpectedFooting {
            ExpectedFooting {
                origin_database_id: ORIGIN.to_owned(),
                scope_ref: SCOPE.to_owned(),
                consumer: consumer_identity(),
            }
        }

        fn admit_at(
            &self,
            staged: &Path,
            manifest: &ReplicaGenerationManifest,
            installed: Option<&InstalledGeneration>,
        ) -> Result<AdmittedGeneration, AdmissionError> {
            let mut lifecycle =
                MemberCopyLifecycle::open(&self.copy_root).expect("lifecycle must open");
            lifecycle
                .sign_in(
                    "acct",
                    ReconnectAnswer::Replace {
                        cut_at: CAPTURED.to_owned(),
                    },
                )
                .expect("sign-in must set refreshing");
            admit_member_copy(
                &self.copy_root,
                staged,
                &serde_json::to_vec(manifest).expect("manifest serialises"),
                installed,
                &self.expected(),
                &mut lifecycle,
            )
        }

        fn admit(
            &self,
            manifest: &ReplicaGenerationManifest,
            installed: Option<&InstalledGeneration>,
        ) -> Result<AdmittedGeneration, AdmissionError> {
            self.admit_at(&self.staged, manifest, installed)
        }

        /// Admission against a caller-prepared lifecycle, so a test can put
        /// the copy in any state first.
        fn admit_with(
            &self,
            manifest: &ReplicaGenerationManifest,
            installed: Option<&InstalledGeneration>,
            lifecycle: &mut MemberCopyLifecycle,
        ) -> Result<AdmittedGeneration, AdmissionError> {
            admit_member_copy(
                &self.copy_root,
                &self.staged,
                &serde_json::to_vec(manifest).expect("manifest serialises"),
                installed,
                &self.expected(),
                lifecycle,
            )
        }
    }

    fn assert_clean(err: &AdmissionError) {
        let value = serde_json::to_value(err).expect("refusal must serialise");
        assert_no_counter_fields(&value, "admission refusal");
    }

    #[test]
    fn happy_path_admits_promotes_and_purges() {
        let h = Harness::new();
        let digest = write_member_file(&h.staged);
        let manifest = manifest_for(&h.staged, &digest, SCOPE, 1);
        let generation_id = manifest.generation_id();

        let mut lifecycle = MemberCopyLifecycle::open(&h.copy_root).expect("lifecycle must open");
        lifecycle
            .sign_in(
                "acct",
                ReconnectAnswer::Replace {
                    cut_at: CAPTURED.to_owned(),
                },
            )
            .expect("sign-in");
        let admitted = admit_member_copy(
            &h.copy_root,
            &h.staged,
            &serde_json::to_vec(&manifest).expect("manifest serialises"),
            None,
            &h.expected(),
            &mut lifecycle,
        )
        .expect("admission must succeed");

        assert_eq!(admitted.generation_id, generation_id);
        let snapshot = admitted.generation_dir.join(SNAPSHOT_FILENAME);
        assert!(snapshot.exists(), "admitted snapshot must be installed");
        let pointer = fs::read_to_string(h.copy_root.join(POINTER_FILENAME)).expect("pointer");
        assert!(
            pointer.contains(&generation_id),
            "pointer must name the new generation"
        );
        assert_eq!(
            lifecycle.status(),
            crate::member_copy_lifecycle::CopyStatus::Ready {
                cut_at: CAPTURED.to_owned()
            }
        );
        assert_eq!(
            lifecycle.activatable_generations().expect("list"),
            vec![generation_id.clone()]
        );
        // The derived index answers a match over the admitted rows.
        let connection = Connection::open(&snapshot).expect("admitted db must open");
        let hits: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM records_fts WHERE records_fts MATCH 'alpha'",
                [],
                |row| row.get(0),
            )
            .expect("FTS must be queryable");
        assert!(hits >= 1, "admitted rows must be indexed");
        // The superseded path purged staging.
        assert!(!h.staged.exists(), "staged input must be purged");
    }

    #[test]
    fn origin_account_and_consumer_mismatch_are_refused() {
        let h = Harness::new();
        let digest = write_member_file(&h.staged);
        let manifest = manifest_for(&h.staged, &digest, SCOPE, 1);

        let mut wrong_origin = manifest.clone();
        wrong_origin.origin_database_id = format!("ndb_{}", "4".repeat(32));
        let err = h
            .admit(&wrong_origin, None)
            .expect_err("origin must refuse");
        assert_eq!(err, AdmissionError::OriginMismatch);
        assert_clean(&err);

        let mut wrong_scope = manifest.clone();
        wrong_scope.scope = ReplicaScope::Member {
            scope_ref: "other-scope".to_owned(),
        };
        wrong_scope.holding = HoldingDisclosureV2::member("other-scope".to_owned(), 1);
        let err = h.admit(&wrong_scope, None).expect_err("scope must refuse");
        assert_eq!(err, AdmissionError::AccountMismatch);
        assert_clean(&err);

        // §1.3 manifest–consumer match: a different declared platform refuses.
        let mut wrong_consumer = manifest;
        wrong_consumer.consumer.platform = StandbyConsumerPlatform::MacosArm64;
        let err = h
            .admit(&wrong_consumer, None)
            .expect_err("consumer must refuse");
        assert_eq!(err, AdmissionError::ConsumerMismatch);
        assert_clean(&err);
    }

    #[test]
    fn unknown_schema_digest_is_refused() {
        let h = Harness::new();
        let digest = write_member_file(&h.staged);
        let mut manifest = manifest_for(&h.staged, &digest, SCOPE, 1);
        manifest.profile = ReplicaProfile::MemberReadV1 {
            member_schema_digest: "0".repeat(64),
        };
        let err = h
            .admit(&manifest, None)
            .expect_err("unknown digest must refuse");
        assert_eq!(err, AdmissionError::UnknownSchemaDigest);
        assert_clean(&err);
    }

    #[test]
    fn manifest_frontier_and_act_ordering_are_refused() {
        let h = Harness::new();
        let digest = write_member_file(&h.staged);
        let manifest = manifest_for(&h.staged, &digest, SCOPE, 1);

        let mut act = manifest.clone();
        act.ordering = ReplicaOrdering::Act {
            head_act: None,
            window: HoldingWindow::CurrentStateOnly,
        };
        let err = h.admit(&act, None).expect_err("act ordering must refuse");
        assert_eq!(
            err,
            AdmissionError::ManifestRejected {
                detail: "replica generation scope, ordering and profile must pair".to_owned()
            }
        );
        assert_clean(&err);

        let mut frontier = manifest;
        frontier.frontier = Some(CanonicalFrontierV1 {
            contract: STANDBY_FRONTIER_CONTRACT.to_owned(),
            version: 1,
            content_event_seq: 0,
            policy_event_seq: 0,
            awareness_event_seq: 0,
            notification_candidate_event_seq: 0,
            binding_audit_seq: 0,
            database_identity_audit_seq: 0,
            meta_event_seq: 0,
            control_event_seq: 0,
            derivation_event_seq: 0,
            relationship_event_seq: 0,
            authorization_revision_epoch: 0,
            storage_portability_policy_revision: 0,
        });
        let err = h.admit(&frontier, None).expect_err("frontier must refuse");
        assert_eq!(
            err,
            AdmissionError::ManifestRejected {
                detail: "member generation must omit the frontier".to_owned()
            }
        );
        assert_clean(&err);
    }

    #[test]
    fn tampered_byte_and_sidecar_are_refused() {
        let h = Harness::new();
        let digest = write_member_file(&h.staged);
        let manifest = manifest_for(&h.staged, &digest, SCOPE, 1);

        let mut bytes = fs::read(&h.staged).expect("bytes");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&h.staged, &bytes).expect("tamper");
        let err = h
            .admit(&manifest, None)
            .expect_err("tampered bytes must refuse");
        assert_eq!(err, AdmissionError::DigestMismatch);
        assert_clean(&err);

        let h = Harness::new();
        let digest = write_member_file(&h.staged);
        let manifest = manifest_for(&h.staged, &digest, SCOPE, 1);
        let mut sidecar = h.staged.as_os_str().to_os_string();
        sidecar.push("-wal");
        fs::write(Path::new(&sidecar), b"wal").expect("sidecar");
        let err = h.admit(&manifest, None).expect_err("sidecar must refuse");
        assert_eq!(err, AdmissionError::SidecarPresent);
        assert_clean(&err);
    }

    #[test]
    fn excluded_table_is_refused() {
        let h = Harness::new();
        let _ = write_member_file(&h.staged);
        let digest = mutate(
            &h.staged,
            "CREATE TABLE content_events (id TEXT PRIMARY KEY, seq INTEGER);\
             INSERT INTO content_events (id, seq) VALUES ('e', 9);",
        );
        let manifest = manifest_for(&h.staged, &digest, SCOPE, 1);
        let err = h
            .admit(&manifest, None)
            .expect_err("excluded table must refuse");
        assert_eq!(
            err,
            AdmissionError::UnexpectedTable {
                table: "content_events".to_owned()
            }
        );
        assert_clean(&err);
    }

    #[test]
    fn dangling_link_endpoint_is_refused() {
        let h = Harness::new();
        let _ = write_member_file(&h.staged);
        let digest = mutate(
            &h.staged,
            "PRAGMA foreign_keys = OFF;\
             INSERT INTO links (id, source_id, target_id, relationship)\
             VALUES ('l2','r1','missing','ref');",
        );
        let manifest = manifest_for(&h.staged, &digest, SCOPE, 1);
        let err = h
            .admit(&manifest, None)
            .expect_err("dangling link must refuse");
        assert_eq!(
            err,
            AdmissionError::DanglingReference {
                table: "links".to_owned(),
                column: "target_id".to_owned()
            }
        );
        assert_clean(&err);
    }

    #[test]
    fn unreached_blob_and_external_null_marker_are_refused() {
        // A blob no attachment references at all.
        let h = Harness::new();
        let _ = write_member_file(&h.staged);
        let digest = mutate(
            &h.staged,
            "INSERT INTO blobs (id, bytes, mime, storage_tier, created_at, external_ref_withheld)\
             VALUES ('b9', x'00','application/octet-stream','inline','t',0);",
        );
        let manifest = manifest_for(&h.staged, &digest, SCOPE, 1);
        let err = h
            .admit(&manifest, None)
            .expect_err("orphan blob must refuse");
        assert_eq!(err, AdmissionError::BlobUnreached);
        assert_clean(&err);

        // A blob whose attachment has a `blob_ref` facet but no `part_of`
        // bearer edge: reachability needs the bearer walk, not just the facet.
        let h = Harness::new();
        let _ = write_member_file(&h.staged);
        let digest = mutate(
            &h.staged,
            "INSERT INTO records (id, type, kind, name, persistence, created_at, updated_at, archived)\
             VALUES ('a2','Document','attachment','a2.txt','enduring','t','t',0);\
             INSERT INTO blobs (id, bytes, mime, storage_tier, created_at, external_ref_withheld)\
             VALUES ('b2', x'00','application/octet-stream','inline','t',0);\
             INSERT INTO facet_values (id, record_id, key, value, vocab_ref, created_at)\
             VALUES ('f2','a2','blob_ref','b2',NULL,'t');",
        );
        let manifest = manifest_for(&h.staged, &digest, SCOPE, 1);
        let err = h
            .admit(&manifest, None)
            .expect_err("attachment with no bearer must refuse");
        assert_eq!(err, AdmissionError::BlobUnreached);
        assert_clean(&err);

        // An external row with a NULL external_ref and no F5 marker, reached
        // through a real attachment, is refused on the marker.
        let h = Harness::new();
        let _ = write_member_file(&h.staged);
        let digest = mutate(
            &h.staged,
            "INSERT INTO records (id, type, kind, name, persistence, created_at, updated_at, archived)\
             VALUES ('a3','Document','attachment','a3.txt','enduring','t','t',0);\
             INSERT INTO links (id, source_id, target_id, relationship, created_at)\
             VALUES ('l3','a3','r1','part_of','t');\
             INSERT INTO blobs (id, mime, storage_tier, external_ref, created_at, external_ref_withheld)\
             VALUES ('b3', NULL, 'external', NULL, 't', 0);\
             INSERT INTO facet_values (id, record_id, key, value, vocab_ref, created_at)\
             VALUES ('f3','a3','blob_ref','b3',NULL,'t');",
        );
        let manifest = manifest_for(&h.staged, &digest, SCOPE, 1);
        let err = h
            .admit(&manifest, None)
            .expect_err("unmarked external ref must refuse");
        assert_eq!(err, AdmissionError::ExternalRefMissingMarker);
        assert_clean(&err);
    }

    #[test]
    fn content_digest_mismatch_is_refused() {
        let h = Harness::new();
        let digest = write_member_file(&h.staged);
        let mut manifest = manifest_for(&h.staged, &digest, SCOPE, 1);
        manifest.content_digest = "0".repeat(64);
        let err = h.admit(&manifest, None).expect_err("digest must refuse");
        assert_eq!(err, AdmissionError::ContentDigestMismatch);
        assert_clean(&err);
    }

    #[test]
    fn schema_incomplete_for_round_trips_to_the_admitted_generation() {
        let h = Harness::new();
        let digest = write_member_file(&h.staged);
        let mut manifest = manifest_for(&h.staged, &digest, SCOPE, 1);
        manifest.schema_incomplete_for = vec!["global".to_owned()];
        let admitted = h.admit(&manifest, None).expect("gated generation admits");
        assert_eq!(admitted.schema_incomplete_for, vec!["global".to_owned()]);

        let h = Harness::new();
        let digest = write_member_file(&h.staged);
        let manifest = manifest_for(&h.staged, &digest, SCOPE, 1);
        let admitted = h
            .admit(&manifest, None)
            .expect("complete generation admits");
        assert!(
            admitted.schema_incomplete_for.is_empty(),
            "a passed gate carries an empty list"
        );
    }

    #[test]
    fn rollback_ordinals_are_refused() {
        let h = Harness::new();
        let first_digest = write_member_file(&h.staged);
        let first = manifest_for(&h.staged, &first_digest, SCOPE, 5);
        let admitted = h.admit(&first, None).expect("first install");
        let installed = InstalledGeneration {
            generation_id: admitted.generation_id.clone(),
            scope_ref: SCOPE.to_owned(),
            ordinal: 5,
            content_digest: admitted.content_digest.clone(),
        };

        let second = h.copy_root.join("staging").join("second.db");
        let _ = write_member_file(&second);
        let changed = mutate(&second, "UPDATE records SET body = 'bye' WHERE id = 'r1';");
        assert_ne!(first_digest, changed);

        let lower = manifest_for(&second, &changed, SCOPE, 4);
        let err = h
            .admit_at(&second, &lower, Some(&installed))
            .expect_err("lower ordinal must refuse");
        assert_eq!(err, AdmissionError::RollbackRefused);
        assert_clean(&err);

        let equal = manifest_for(&second, &changed, SCOPE, 5);
        let err = h
            .admit_at(&second, &equal, Some(&installed))
            .expect_err("equal ordinal with a new digest must refuse");
        assert_eq!(err, AdmissionError::RollbackRefused);
        assert_clean(&err);
    }

    fn promote_to_ready(lifecycle: &mut MemberCopyLifecycle) {
        lifecycle
            .sign_in(
                "acct",
                ReconnectAnswer::Replace {
                    cut_at: CAPTURED.to_owned(),
                },
            )
            .expect("sign in");
        lifecycle
            .mark_refreshed(CAPTURED.to_owned())
            .expect("refresh");
    }

    /// Signs in to `Ready`, admits the staged file and returns the manifest
    /// with the lifecycle now holding a real `generations/<id>/snapshot.db`
    /// that `current.json` names.
    fn seed_held_generation(h: &Harness) -> (ReplicaGenerationManifest, MemberCopyLifecycle) {
        let digest = write_member_file(&h.staged);
        let manifest = manifest_for(&h.staged, &digest, SCOPE, 1);
        let mut lifecycle = MemberCopyLifecycle::open(&h.copy_root).expect("open");
        promote_to_ready(&mut lifecycle);
        h.admit_with(&manifest, None, &mut lifecycle)
            .expect("seed admission must succeed");
        (manifest, lifecycle)
    }

    /// A same-id re-delivery of the held generation, eligible under
    /// `refuse_rollback` (equal ordinal and content digest).
    fn held_redelivery(manifest: &ReplicaGenerationManifest) -> InstalledGeneration {
        InstalledGeneration {
            generation_id: manifest.generation_id(),
            scope_ref: SCOPE.to_owned(),
            ordinal: 1,
            content_digest: manifest.content_digest.clone(),
        }
    }

    #[test]
    fn unavailable_copy_is_not_admitted_and_keeps_the_held_generation() {
        let h = Harness::new();
        let (manifest, mut lifecycle) = seed_held_generation(&h);
        let generation_id = manifest.generation_id();
        let held_dir = h.copy_root.join(CACHE_DIR_NAME).join(&generation_id);
        let held_snapshot = held_dir.join(SNAPSHOT_FILENAME);
        assert!(held_snapshot.exists(), "seed must install a held snapshot");
        let held_before = fs::read(&held_snapshot).expect("held bytes");
        let pointer_before = fs::read(h.copy_root.join(POINTER_FILENAME)).expect("held pointer");

        // Degrade to `Unavailable` while the held cut stays on disk.
        lifecycle
            .sign_in(
                "acct",
                ReconnectAnswer::Replace {
                    cut_at: CAPTURED.to_owned(),
                },
            )
            .expect("sign in");
        lifecycle.mark_refresh_failed().expect("refresh failed");
        assert_eq!(lifecycle.status(), CopyStatus::Unavailable);

        // Re-stage the identical download and re-deliver that same generation.
        // This must be refused before any install. It fails if the
        // promotability pre-check is removed: the promote/rollback path would
        // then delete the held generation and its pointer.
        let _ = write_member_file(&h.staged);
        let installed = held_redelivery(&manifest);
        let err = h
            .admit_with(&manifest, Some(&installed), &mut lifecycle)
            .expect_err("unavailable must not admit");
        assert_eq!(err, AdmissionError::NotAdmitted);
        assert_clean(&err);

        assert!(held_dir.exists(), "held generation dir must survive");
        assert_eq!(
            fs::read(&held_snapshot).expect("held bytes"),
            held_before,
            "held snapshot must be byte-for-byte untouched"
        );
        assert_eq!(
            fs::read(h.copy_root.join(POINTER_FILENAME)).expect("pointer"),
            pointer_before,
            "pointer must still name the held cut"
        );
        assert!(
            h.staged.exists(),
            "a refused admission must leave the staged download untouched"
        );
    }

    #[test]
    fn locked_copy_is_not_admitted_and_keeps_its_files() {
        let h = Harness::new();
        let (manifest, mut lifecycle) = seed_held_generation(&h);
        let generation_id = manifest.generation_id();
        let held_dir = h.copy_root.join(CACHE_DIR_NAME).join(&generation_id);
        let held_snapshot = held_dir.join(SNAPSHOT_FILENAME);
        let held_before = fs::read(&held_snapshot).expect("held bytes");
        let pointer_before = fs::read(h.copy_root.join(POINTER_FILENAME)).expect("held pointer");

        lifecycle
            .apply_reconnect(ReconnectAnswer::Locked)
            .expect("locked");
        assert!(matches!(lifecycle.status(), CopyStatus::Locked { .. }));

        let _ = write_member_file(&h.staged);
        let installed = held_redelivery(&manifest);
        let err = h
            .admit_with(&manifest, Some(&installed), &mut lifecycle)
            .expect_err("locked must not admit");
        assert_eq!(err, AdmissionError::Locked);
        assert_clean(&err);

        assert!(held_dir.exists(), "held generation dir must survive");
        assert_eq!(
            fs::read(&held_snapshot).expect("held bytes"),
            held_before,
            "held snapshot must be byte-for-byte untouched"
        );
        assert_eq!(
            fs::read(h.copy_root.join(POINTER_FILENAME)).expect("pointer"),
            pointer_before,
            "pointer must still name the held cut"
        );
        assert!(
            h.staged.exists(),
            "a refused admission must leave the staged download untouched"
        );
    }

    #[test]
    fn corrupt_same_id_redelivery_is_refused_and_leaves_the_held_bytes() {
        let h = Harness::new();
        let (manifest, mut lifecycle) = seed_held_generation(&h);
        let generation_id = manifest.generation_id();
        let held_dir = h.copy_root.join(CACHE_DIR_NAME).join(&generation_id);
        let held_snapshot = held_dir.join(SNAPSHOT_FILENAME);
        let held_before = fs::read(&held_snapshot).expect("held bytes");
        let pointer_before = fs::read(h.copy_root.join(POINTER_FILENAME)).expect("held pointer");

        // Re-stage the identical download, then corrupt one byte without
        // changing the length: the manifest still names the held generation
        // (so `refuse_rollback` permits it) and the copy is still promotable,
        // but the bytes no longer match the manifest.
        let _ = write_member_file(&h.staged);
        let mut bytes = fs::read(&h.staged).expect("staged bytes");
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xff;
        fs::write(&h.staged, &bytes).expect("write corrupt stage");
        assert_eq!(
            bytes.len() as u64,
            manifest.bytes.size_bytes,
            "the corrupt re-delivery keeps the manifest size"
        );

        let installed = held_redelivery(&manifest);
        let err = h
            .admit_with(&manifest, Some(&installed), &mut lifecycle)
            .expect_err("corrupt same-id re-delivery must refuse");
        assert_eq!(err, AdmissionError::DigestMismatch);
        assert_clean(&err);

        assert!(held_snapshot.exists(), "held snapshot must survive");
        assert_eq!(
            fs::read(&held_snapshot).expect("held bytes"),
            held_before,
            "held bytes must not be overwritten in place"
        );
        assert_eq!(
            fs::read(h.copy_root.join(POINTER_FILENAME)).expect("pointer"),
            pointer_before,
            "pointer unchanged"
        );
    }

    #[test]
    fn removed_copy_is_not_admitted_with_cause_and_promotes_nothing() {
        let h = Harness::new();
        let mut lifecycle = MemberCopyLifecycle::open(&h.copy_root).expect("open");
        promote_to_ready(&mut lifecycle);
        // The revocation barrier purges the copy root, including staging; the
        // refresh driver would stage a *new* download after the state is set.
        lifecycle
            .apply_reconnect(ReconnectAnswer::Revoked {
                cause: RevokedCause::MembershipEnded,
            })
            .expect("revoked");
        let digest = write_member_file(&h.staged);
        let manifest = manifest_for(&h.staged, &digest, SCOPE, 1);

        let err = h
            .admit_with(&manifest, None, &mut lifecycle)
            .expect_err("removed must not admit");
        assert_eq!(
            err,
            AdmissionError::Removed {
                cause: RemovedCause::MembershipEnded,
                deletion: DeletionState::Complete,
            }
        );
        assert_clean(&err);
        assert_eq!(
            lifecycle.status(),
            CopyStatus::Removed {
                cause: RemovedCause::MembershipEnded,
                deletion: DeletionState::Complete,
            }
        );
        assert!(!h.copy_root.join(POINTER_FILENAME).exists(), "no pointer");
        assert!(
            !h.copy_root
                .join(CACHE_DIR_NAME)
                .join(manifest.generation_id())
                .exists(),
            "no promoted generation"
        );
        // The refusal happens before any install or purge, so the freshly
        // staged download is untouched. This fails if the promotability
        // pre-check is removed: the promote/purge path would consume staging.
        assert!(
            h.staged.exists(),
            "a refused admission must leave the staged download untouched"
        );
    }
}
