//! Per-file identity component for the native current-state producer.
//!
//! This is deliberately NOT member admission: a match supplies neither a Db nor
//! a serving lease. The native schema/closure/content-digest verifier and reader
//! are still required. In particular the HTTP Ready path continues to hold.
//! Expected identity comes from authenticated transport footing, never SQLite.
use super::{capture_in, NativeMemberCut, NativeMemberSource};
use crate::{
    holding::ReplicaScope,
    member_copy_transport::MemberCopyContext,
    replica_generation::{NativeMemberProfileIdentity, ReplicaGenerationManifest, ReplicaProfile},
};
use rusqlite::{Connection, DatabaseName, OptionalExtension};
use sqlx::SqliteConnection;

/// A component of the eventual native member schema, not its schema digest.
/// No global head, roster, email, credential or other member binding travels.
/// Content hashing must cover this row EXCEPT generation_id (which is derived
/// from that content digest); generation_id is independently compared on open.
pub const DDL: &str = "CREATE TABLE kernel_member_identity (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 engine TEXT NOT NULL,
 member_schema_digest TEXT NOT NULL,
 origin_database_id TEXT NOT NULL,
 account_binding TEXT NOT NULL,
 principal_id TEXT NOT NULL,
 genesis_event_id TEXT NOT NULL,
 scope_ref TEXT NOT NULL,
 generation_id TEXT NOT NULL
)";

/// Fixed classes only: never disclose a candidate's identity values or SQL.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FileFenceRefusal {
    #[error("native member fence: manifest refused")]
    Manifest,
    #[error("native member fence: authenticated binding differs")]
    AuthenticatedBinding,
    #[error("native member fence: source read transaction required")]
    SourceTransaction,
    #[error("native member fence: source changed")]
    SourceChanged,
    #[error("native member fence: fresh destination required")]
    DestinationNotEmpty,
    #[error("native member fence: physical read-only connection required")]
    WritableConnection,
    #[error("native member fence: DELETE journal mode required")]
    JournalMode,
    #[error("native member fence: NKM2 marker required")]
    Marker,
    #[error("native member fence: identity schema differs")]
    Schema,
    #[error("native member fence: identity row missing or differs")]
    Identity,
    #[error("native member fence: storage unavailable")]
    Storage,
}

type Result<T> = std::result::Result<T, FileFenceRefusal>;

// No Debug/Serialize: a failed comparison must not disclose either identity.
#[derive(Eq, PartialEq)]
struct Identity {
    schema: String,
    origin: String,
    member: NativeMemberProfileIdentity,
    scope: String,
    generation: String,
}

impl Identity {
    fn from_manifest(manifest: &ReplicaGenerationManifest) -> Result<Self> {
        manifest
            .validate()
            .map_err(|_| FileFenceRefusal::Manifest)?;
        manifest
            .consumer
            .validate_declaration()
            .map_err(|_| FileFenceRefusal::Manifest)?;
        let ReplicaProfile::MemberReadKernelV2 {
            member_schema_digest,
            identity,
            ..
        } = &manifest.profile
        else {
            return Err(FileFenceRefusal::Manifest);
        };
        let ReplicaScope::Member { scope_ref } = &manifest.scope else {
            return Err(FileFenceRefusal::Manifest);
        };
        Ok(Self {
            schema: member_schema_digest.clone(),
            origin: manifest.origin_database_id.clone(),
            member: identity.clone(),
            scope: scope_ref.clone(),
            generation: manifest.generation_id(),
        })
    }
}

/// No constructor accepts origin/account/principal strings or a candidate file.
/// Only the authenticated transport context and its manifest can establish the
/// expectation. The existing transport is responsible for verifying the server
/// and installed source binding before constructing that sealed context.
/// This expectation alone is insufficient to admit or open a member Db.
pub struct ExpectedFileFence(Identity);

impl ExpectedFileFence {
    pub fn from_authenticated_context(
        context: &MemberCopyContext,
        manifest: &ReplicaGenerationManifest,
    ) -> Result<Self> {
        let identity = Identity::from_manifest(manifest)?;
        if identity.origin != context.origin_database_id()
            || identity.member.account_binding != context.account_binding()
            || identity.scope != context.scope_ref()
            || manifest.hosted_route_database_id != context.route_database_id()
            || &manifest.consumer != context.consumer()
        {
            return Err(FileFenceRefusal::AuthenticatedBinding);
        }
        Ok(Self(identity))
    }
}

#[derive(Eq, PartialEq)]
enum BuilderPhase {
    Fresh,
    Attempted,
    Initialized,
}

/// An exclusively created, private, cleanup-on-drop producer destination.
/// It cannot adopt an existing file or expose a path/Db for publication. Empty
/// schema alone would not prove freshness: dropped rows can survive in pages.
/// The future producer must add validated current-state rows and full admission
/// before introducing a sealed/publishable artifact type.
pub struct NativeMemberFileBuilder {
    phase: BuilderPhase,
    // Close SQLite before unlinking its owned temporary file.
    pub(super) connection: Connection,
    pub(super) _file: tempfile::NamedTempFile,
}

impl NativeMemberFileBuilder {
    pub fn new_in(directory: &std::path::Path) -> Result<Self> {
        let file = tempfile::Builder::new()
            .prefix(".native-member-")
            .tempfile_in(directory)
            .map_err(|_| FileFenceRefusal::Storage)?;
        let connection = Connection::open_with_flags(
            file.path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| FileFenceRefusal::Storage)?;
        Ok(Self {
            phase: BuilderPhase::Fresh,
            connection,
            _file: file,
        })
    }
}

/// Initialize ONLY a fresh producer destination. The caller owns the private
/// source read transaction spanning capture/materialize. The builder owns the
/// exclusively created temporary file; callers cannot supply an old SQLite file.
/// A cut cannot be retargeted by editing its public declaration: recapture also
/// compares its private source authorization fence before any destination write.
/// This creates an identity component, not a publishable member profile.
pub async fn initialize_in(
    source: &mut SqliteConnection,
    cut: &NativeMemberCut,
    builder: &mut NativeMemberFileBuilder,
    manifest: &ReplicaGenerationManifest,
) -> Result<()> {
    if builder.phase != BuilderPhase::Fresh {
        return Err(FileFenceRefusal::DestinationNotEmpty);
    }
    // Even a failed transaction can leave old values on free pages. Every
    // retry gets another O_EXCL file; an attempted builder is never recycled.
    builder.phase = BuilderPhase::Attempted;
    {
        let mut handle = source
            .lock_handle()
            .await
            .map_err(|_| FileFenceRefusal::Storage)?;
        // SAFETY: SQLx owns and locks this live handle throughout the call.
        if unsafe { libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) } != 0 {
            return Err(FileFenceRefusal::SourceTransaction);
        }
    }
    let identity = Identity::from_manifest(manifest)?;
    if identity.origin != cut.origin_database_id || identity.member != cut.profile_identity() {
        return Err(FileFenceRefusal::AuthenticatedBinding);
    }
    if !matches!(capture_in(source, &cut.origin_database_id, &cut.account_binding).await
        .map_err(|_| FileFenceRefusal::Storage)?, NativeMemberSource::Ready(current) if current == *cut)
    {
        return Err(FileFenceRefusal::SourceChanged);
    }
    let destination = &mut builder.connection;
    let journal: String = destination
        .pragma_query_value(Some(DatabaseName::Main), "journal_mode", |row| row.get(0))
        .map_err(|_| FileFenceRefusal::Storage)?;
    if journal != "delete" {
        return Err(FileFenceRefusal::JournalMode);
    }
    let tx = destination
        .transaction()
        .map_err(|_| FileFenceRefusal::Storage)?;
    let empty: bool = tx
        .query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE name NOT GLOB 'sqlite_*')
         AND (SELECT application_id FROM pragma_application_id)=0
         AND (SELECT user_version FROM pragma_user_version)=0",
            [],
            |row| row.get(0),
        )
        .map_err(|_| FileFenceRefusal::Storage)?;
    if !empty {
        return Err(FileFenceRefusal::DestinationNotEmpty);
    }
    tx.execute_batch(DDL)
        .map_err(|_| FileFenceRefusal::Storage)?;
    tx.execute(
        "INSERT INTO main.kernel_member_identity VALUES (1,?,?,?,?,?,?,?,?)",
        rusqlite::params![
            crate::standby::kernel_v2::ENGINE,
            identity.schema,
            identity.origin,
            identity.member.account_binding,
            identity.member.principal_id,
            identity.member.genesis_event_id,
            identity.scope,
            identity.generation
        ],
    )
    .map_err(|_| FileFenceRefusal::Storage)?;
    tx.pragma_update(None, "application_id", crate::db::V2_MEMBER_APPLICATION_ID)
        .map_err(|_| FileFenceRefusal::Storage)?;
    tx.commit().map_err(|_| FileFenceRefusal::Storage)?;
    builder.phase = BuilderPhase::Initialized;
    Ok(())
}

/// Check the marker/schema/identity ON THE ACTUAL physically read-only handle,
/// before any domain read. There is no path precheck or reopen after this test.
/// Full admission still has to validate immutable bytes, native closure and
/// digest, and bind this handle to the lifecycle/serving lease. This function
/// deliberately returns no handle, Db, admission token or serving authority.
pub fn verify_on(connection: &Connection, expected: &ExpectedFileFence) -> Result<()> {
    if !connection
        .is_readonly(DatabaseName::Main)
        .map_err(|_| FileFenceRefusal::Storage)?
    {
        return Err(FileFenceRefusal::WritableConnection);
    }
    let marker: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| FileFenceRefusal::Storage)?;
    if marker != crate::db::V2_MEMBER_APPLICATION_ID {
        return Err(FileFenceRefusal::Marker);
    }
    let journal: String = connection
        .pragma_query_value(Some(DatabaseName::Main), "journal_mode", |row| row.get(0))
        .map_err(|_| FileFenceRefusal::Storage)?;
    if journal != "delete" {
        return Err(FileFenceRefusal::JournalMode);
    }
    let version: i64 = connection
        .pragma_query_value(Some(DatabaseName::Main), "user_version", |row| row.get(0))
        .map_err(|_| FileFenceRefusal::Storage)?;
    if version != 0 {
        return Err(FileFenceRefusal::Schema);
    }
    let schema: Option<String> = connection
        .query_row(
            "SELECT sql FROM main.sqlite_schema WHERE type='table' AND name='kernel_member_identity'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| FileFenceRefusal::Storage)?;
    if schema.as_deref() != Some(DDL) {
        return Err(FileFenceRefusal::Schema);
    }
    // Exact DDL gives one possible row (singleton=1), including NOT NULLs.
    let identity = connection.query_row(
        "SELECT engine,member_schema_digest,origin_database_id,account_binding,principal_id,
                genesis_event_id,scope_ref,generation_id FROM main.kernel_member_identity WHERE singleton=1",
        [], |row| Ok((row.get::<_,String>(0)?, Identity {
            schema: row.get(1)?, origin: row.get(2)?, member: NativeMemberProfileIdentity {
                account_binding: row.get(3)?, principal_id: row.get(4)?, genesis_event_id: row.get(5)?,
            }, scope: row.get(6)?, generation: row.get(7)?,
        })),
    ).optional().map_err(|_| FileFenceRefusal::Storage)?;
    if !matches!(identity, Some((engine, identity)) if engine == crate::standby::kernel_v2::ENGINE && identity == expected.0)
    {
        return Err(FileFenceRefusal::Identity);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
