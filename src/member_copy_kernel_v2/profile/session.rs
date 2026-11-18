//! A member-only borrowed transaction over an already admitted immutable file.
//! No Db, canonical authority plane, or writable callback is constructed.
use super::*;
use crate::mcp::member_serving::MemberCopyLease;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    ConnectOptions,
};
use std::os::fd::AsRawFd;

pub(crate) struct NativeMemberReadSource {
    file: std::fs::File,
    expected: file_fence::ExpectedFileFence,
    _lease: MemberCopyLease,
    principal: String,
    read_snapshots: std::sync::Arc<crate::db::ReadSnapshotCache>,
}

impl AdmittedMemberFile {
    /// The serving owner supplies the lease only after checking the actual
    /// lifecycle read decision for this captured generation.
    pub(crate) fn borrow_member_read(
        &self,
        lease: MemberCopyLease,
    ) -> crate::Result<NativeMemberReadSource> {
        file_fence::verify_on(&self.connection, &self.expected)
            .map_err(|_| crate::Error::copy_unavailable())?;
        Ok(NativeMemberReadSource {
            file: self
                ._file
                .reopen()
                .map_err(|_| crate::Error::copy_unavailable())?,
            expected: self.expected.clone(),
            _lease: lease,
            principal: self.principal.clone(),
            read_snapshots: self.read_snapshots.clone(),
        })
    }
}

/// Only the admitted-file constructor above can create the source proof.
/// Shared member pipeline entrypoints require this token rather than a raw
/// canonical connection plus an optional/absent principal.
pub(crate) struct NativeMemberReadSession {
    tx: Option<sqlx::Transaction<'static, sqlx::Sqlite>>,
    pool: sqlx::SqlitePool,
    source: NativeMemberReadSource,
    search_indexes_ready: bool,
}
impl NativeMemberReadSource {
    pub(crate) async fn open(self) -> crate::Result<NativeMemberReadSession> {
        let options = SqliteConnectOptions::new()
            .filename(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
            .read_only(true)
            .immutable(true)
            .create_if_missing(false)
            .disable_statement_logging();
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(options)
            .await?;
        let mut tx = pool.begin().await?;
        verify(&mut tx, &self.expected).await?;
        // Fixed adapter views derive only held fields; all main tables remain
        // physically read-only. TEMP shadowing supplies the shared member
        // reader's column names without creating a canonical schema.
        for ddl in [
            "CREATE TEMP VIEW records AS SELECT r.rowid AS rowid,r.*,m.owner_id FROM main.records r JOIN main.member_record_metadata m ON m.record_id=r.id",
            // The shared native staging admits anchors only with
            // kernel_comment_anchors.source_slot='body' (kernel_v2/sql.rs).
            // Restore that proven discriminator for the existing integrity
            // fold; the public relation omits it because it is fixed.
            "CREATE TEMP VIEW annotation_targets AS SELECT a.*,'body' AS source_slot FROM main.comment_anchors a",
            "CREATE TEMP VIEW member_display_references AS SELECT record_id,display_reference FROM main.member_record_metadata WHERE display_reference IS NOT NULL",
            "CREATE TEMP VIEW record_mentions AS SELECT * FROM main.member_mentions",
        ] {
            sqlx::query(ddl).execute(&mut *tx).await?;
        }
        Ok(NativeMemberReadSession {
            tx: Some(tx),
            pool,
            source: self,
            search_indexes_ready: false,
        })
    }
}
async fn verify(
    connection: &mut sqlx::SqliteConnection,
    expected: &file_fence::ExpectedFileFence,
) -> crate::Result<()> {
    let mut handle = connection.lock_handle().await?;
    // SAFETY: SQLx locks its worker out for this guard's lifetime. The borrowed
    // rusqlite wrapper neither closes nor outlives that raw connection; all
    // verifier statements are finalized before the guard is released.
    let borrowed = unsafe { Connection::from_handle(handle.as_raw_handle().as_ptr()) }
        .map_err(|_| crate::Error::copy_unavailable())?;
    file_fence::verify_on(&borrowed, expected).map_err(|_| crate::Error::copy_unavailable())
}
impl NativeMemberReadSession {
    pub(crate) async fn virtual_root(
        &mut self,
    ) -> crate::Result<Option<super::virtual_root::MemberVirtualRoot>> {
        let raw: String = sqlx::query_scalar("SELECT virtual_root FROM main.member_context")
            .fetch_one(&mut **self.transaction())
            .await?;
        super::virtual_root::MemberVirtualRoot::decode(&raw)
            .map_err(|_| crate::Error::copy_unavailable())
    }

    /// Local derived indexes over this one admitted generation. No triggers or
    /// writes to main, no canonical authority tables, and no cross-file cache.
    pub(crate) async fn ensure_search_indexes(&mut self) -> crate::Result<()> {
        if self.search_indexes_ready {
            return Ok(());
        }
        for statement in [
            "CREATE VIRTUAL TABLE temp.records_fts USING fts5(name,body,tokenize='porter unicode61')",
            "INSERT INTO temp.records_fts(rowid,name,body) SELECT rowid,name,body FROM main.records",
            "CREATE VIRTUAL TABLE temp.records_name_idx USING fts5(name,tokenize='unicode61')",
            "INSERT INTO temp.records_name_idx(rowid,name) SELECT rowid,name FROM main.records",
        ] {
            sqlx::query(statement).execute(&mut **self.transaction()).await?;
        }
        self.search_indexes_ready = true;
        Ok(())
    }
    pub(crate) fn read_snapshots(&self) -> std::sync::Arc<crate::db::ReadSnapshotCache> {
        self.source.read_snapshots.clone()
    }
    pub(crate) fn principal(&self) -> &str {
        &self.source.principal
    }
    pub(crate) fn transaction(&mut self) -> &mut sqlx::Transaction<'static, sqlx::Sqlite> {
        self.tx.as_mut().expect("member read session remains open")
    }
    pub(crate) async fn close(mut self) -> crate::Result<()> {
        verify(
            self.tx.as_mut().expect("member read session remains open"),
            &self.source.expected,
        )
        .await?;
        self.tx
            .take()
            .expect("member read session remains open")
            .rollback()
            .await?;
        self.pool.close().await;
        Ok(())
    }
}
