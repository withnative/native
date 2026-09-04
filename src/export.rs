//! Portable SQLite export and the paged snapshot lifecycle.
//!
//! Produce a self-contained, single-file snapshot of a connected database that opens in
//! stock `sqlite3`, honouring the fidelity constraints from Native note 6c7d211:
//!
//!   - never a raw file copy: a WAL database's honest on-disk
//!     artifact is the file trio (`.db` + `-wal` + `-shm`), so the export is a
//!     `VACUUM INTO` snapshot — a fresh, WAL-free single file;
//!   - engine-specific vector-index artifacts do not round-trip to stock
//!     sqlite3; this engine keeps embeddings as plain BLOBs, and the export
//!     refuses to proceed if such artifacts ever appear in the file.
//!
//! `VACUUM INTO` reads through the WAL inside a single transaction, so the
//! snapshot is transactionally consistent even under concurrent writes.
//! This module is transport- and tenancy-agnostic: it produces and pages a file
//! on local disk. Hosted authorization, HTTP delivery, and catalog selection
//! remain in the held hosting package.

mod coordinator;

pub use coordinator::{ExportActivity, ExportCoordinator};

use std::str::FromStr;
use std::time::Duration;

use futures::future::BoxFuture;
use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};
use sqlx::{ConnectOptions, Connection, Row};
use tempfile::TempDir;

use crate::db::Db;
use crate::error::{Error, Result};
use crate::mcp::{Caller, SnapshotPage, SnapshotRequest, SnapshotSource};

/// A completed export: a self-contained `.db` file on local disk. The backing
/// temp directory is removed when this is dropped — callers stream or copy the
/// file out while holding the handle.
///
/// [`Export::cleanup`] waits for off-thread removal. Plain `drop` is
/// cancellation-safe too: on a Tokio runtime it schedules the same removal on
/// the blocking pool, which is what lets an HTTP disconnect abandon a body
/// without synchronously unlinking a database-sized file on a worker thread.
#[derive(Debug)]
pub struct Export {
    dir: ExportDir,
    file_name: String,
    size_bytes: u64,
    captured_at: String,
    snapshot_completed_at: String,
    hosted_standby_context: Option<crate::standby_snapshot::HostedStandbyManifestContext>,
}

impl Export {
    /// Path of the exported single-file database.
    pub fn path(&self) -> std::path::PathBuf {
        self.dir.path().join(&self.file_name)
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub(crate) fn snapshot_completed_at(&self) -> &str {
        &self.snapshot_completed_at
    }

    pub(crate) fn captured_at(&self) -> &str {
        &self.captured_at
    }

    /// Suggested download filename (`{db_id}.db`).
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Bind authenticated hosted route and declared consumer compatibility to
    /// this immutable export. The coordinator derives the manifest only after
    /// it has hashed the completed file.
    #[doc(hidden)]
    pub fn with_hosted_standby_context(
        mut self,
        context: crate::standby_snapshot::HostedStandbyManifestContext,
    ) -> Self {
        self.hosted_standby_context = Some(context);
        self
    }

    /// Strip disposable bookkeeping when this export is bound for a standby.
    ///
    /// A no-op for ordinary exports and backups, which must stay complete. The
    /// hosted standby context is the signal, and it is attached by
    /// `with_hosted_standby_context` *after* the snapshot is taken, so this
    /// cannot be folded into the capture itself.
    pub(crate) async fn filter_disposable_for_standby(&mut self) -> Result<()> {
        if self.hosted_standby_context.is_none() {
            return Ok(());
        }
        self.size_bytes = strip_disposable_bookkeeping(&self.path()).await?;
        Ok(())
    }

    pub(crate) fn hosted_standby_context(
        &self,
    ) -> Option<crate::standby_snapshot::HostedStandbyManifestContext> {
        self.hosted_standby_context.clone()
    }

    /// Remove the snapshot's directory on the blocking pool, and wait for it.
    ///
    /// Awaited rather than fire-and-forget: the caller that finishes with an
    /// export is the sweep, which moves straight on to the next user, and
    /// letting removals pile up behind it would trade a worker-thread stall for
    /// an unbounded set of half-deleted snapshots on the very volume the sweep
    /// protects. A leak is survivable either way — the hosted stale-export
    /// sweep reclaims by age at startup — but bounded is better than
    /// tidy-eventually.
    pub async fn cleanup(self) {
        let Export { mut dir, .. } = self;
        if let Some(dir) = dir.take() {
            remove_dir_off_thread(dir).await;
        }
    }

    #[cfg(test)]
    pub(crate) fn test_fixture(dir: TempDir, file_name: &str) -> Self {
        let size_bytes = std::fs::metadata(dir.path().join(file_name))
            .expect("test export file")
            .len();
        Self {
            dir: ExportDir::new(dir),
            file_name: file_name.to_string(),
            size_bytes,
            captured_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            snapshot_completed_at: chrono::Utc::now()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            hosted_standby_context: None,
        }
    }
}

/// Cancellation-safe ownership of an export directory.
///
/// A response body can disappear at any await point when a client disconnects.
/// `TempDir` would then synchronously unlink the database-sized snapshot on the
/// Tokio worker dropping that future. This wrapper instead schedules the unlink
/// directly on the blocking pool. Explicit cleanup still awaits the same work.
#[derive(Debug)]
struct ExportDir(Option<TempDir>);

impl ExportDir {
    fn new(dir: TempDir) -> Self {
        Self(Some(dir))
    }

    fn path(&self) -> &std::path::Path {
        self.0
            .as_ref()
            .expect("export directory already taken")
            .path()
    }

    fn take(&mut self) -> Option<TempDir> {
        self.0.take()
    }
}

impl Drop for ExportDir {
    fn drop(&mut self) {
        let Some(dir) = self.0.take() else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn_blocking(move || close_dir(dir));
        } else {
            close_dir(dir);
        }
    }
}

/// Remove a `TempDir` on the blocking pool.
///
/// `close()` rather than `drop()`: `TempDir`'s `Drop` deliberately discards
/// the `remove_dir_all` error, so dropping it here would report only a task
/// panic and stay silent about the failure that actually leaves a
/// database-sized snapshot on the volume — a permissions or I/O problem the
/// operator has no other signal for.
///
/// Both failures are logged rather than returned: the directory lives under
/// hosted `exports/` or beside the standalone database, so anything left
/// behind remains isolated as an explicitly named export directory. Nothing a
/// caller could do with the error beats reporting it, and an export that
/// succeeded must not be reported as failed because its scratch directory
/// outlived it.
async fn remove_dir_off_thread(dir: TempDir) {
    match tokio::task::spawn_blocking(move || close_dir(dir)).await {
        Ok(()) => {}
        Err(err) => eprintln!(
            "[native-ce] export cleanup task panicked ({err}); \
             the snapshot directory remains on disk and may require operator cleanup"
        ),
    }
}

fn close_dir(dir: TempDir) {
    if let Err(err) = dir.close() {
        eprintln!(
            "[native-ce] export cleanup could not remove the snapshot directory (I/O kind: {:?}); \
             it remains on disk and may require operator cleanup",
            err.kind()
        );
    }
}

/// Fail closed if the file carries engine-specific vector-index artifacts
/// (libSQL's `libsql_vector_idx` index and its shadow tables): stock sqlite3
/// cannot even parse them, so a file containing them fails `integrity_check`
/// everywhere except the engine that made it — the opposite of what an eject
/// artifact promises.
///
/// Refusing, rather than sanitising the snapshot, is deliberate. This engine
/// is stock SQLite and cannot *create* these artifacts, so in any database it
/// provisioned this check is an unreachable tripwire; the only way it fires is
/// a future engine change (native vector indexing is separately gated on
/// round-trip fidelity) or a foreign file. In both cases the right outcome is
/// a loud failure that forces the sanitise-or-sidecar decision to be made
/// against the engine that actually produced the artifacts — not a silent
/// export that drops schema objects from a file we don't fully understand.
pub(crate) async fn refuse_non_portable_artifacts(
    conn: &mut SqliteConnection,
    operation: &str,
) -> Result<()> {
    let rows = sqlx::query(
        "SELECT name FROM sqlite_master
          WHERE name LIKE 'libsql_vector%'
             OR name LIKE 'idx_%_shadow'
             OR (sql IS NOT NULL AND sql LIKE '%libsql_vector_idx%')",
    )
    .fetch_all(&mut *conn)
    .await?;
    if let Some(row) = rows.first() {
        return Err(Error::engine(format!(
            "{operation} refused: engine-specific vector-index artifact '{}' would not open in stock sqlite3 (constraint 6c7d211) — sanitise or keep vectors in a sidecar",
            row.get::<String, _>("name")
        )));
    }
    Ok(())
}

/// Validate that a staged database can cross into hosted adoption without
/// carrying engine-specific artifacts that stock SQLite cannot open.
#[doc(hidden)]
pub async fn validate_hosted_adoption_portability(conn: &mut SqliteConnection) -> Result<()> {
    refuse_non_portable_artifacts(conn, "adoption").await
}

/// Bookkeeping the standby contract declares disposable and never replays.
///
/// The ratified Milestone 1 contract says operational read-log, job, run and
/// receiver-local relationship-quarantine bookkeeping "is disposable and is
/// never replayed locally". On the production workspace that material is about
/// 98% of the database: 2,246 records and ~13 MB of canonical content in a
/// 1.63 GB image. Shipping it made the agreed 2-minute refresh cadence
/// arithmetically impossible.
///
/// This is a denylist, not an allowlist, and the asymmetry is deliberate. A new
/// bookkeeping table nobody adds here makes a standby snapshot larger than it
/// needs to be. A canonical table wrongly absent from an allowlist would make
/// the standby serve an *incomplete workspace* during an outage while reporting
/// itself healthy. Too large beats quietly wrong.
///
/// `standby_disposable_tables_are_declared_in_the_frozen_ddl` fails if any name
/// here stops existing, so a rename cannot silently disable the filter.
pub(crate) const STANDBY_DISPOSABLE_TABLES: &[&str] = &[
    "read_log_calls",
    "read_log_touches",
    "jobs",
    "agent_runs",
    "relationship_federation_quarantine",
];

/// Strip disposable bookkeeping from a completed export, in place.
///
/// Rows are deleted and the tables are kept. `consumer.ddl_sha256` pins the
/// frozen DDL against the installed standby binary, so dropping a table would
/// change schema identity and the generation would never promote. An empty
/// table preserves it exactly.
///
/// Runs before the manifest is derived, so the manifest's size and SHA-256
/// still describe precisely the bytes that are shipped and promoted. What is
/// given up is byte-identity with the source database, which the snapshot
/// contract never claimed: it requires only that the manifest be derived from
/// the completed exported image.
async fn strip_disposable_bookkeeping(target: &std::path::Path) -> Result<u64> {
    let mut conn = SqliteConnectOptions::from_str(&format!("sqlite:{}", target.to_string_lossy()))?
        .read_only(false)
        .connect()
        .await?;
    for table in STANDBY_DISPOSABLE_TABLES {
        // The table list is a compile-time constant, never caller input.
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&mut conn)
            .await?;
    }
    // Reclaim the pages the deletes freed; without this the file keeps its
    // original size and the whole exercise is pointless.
    sqlx::query("VACUUM").execute(&mut conn).await?;
    let verdict: String = sqlx::query("PRAGMA integrity_check")
        .fetch_one(&mut conn)
        .await?
        .get(0);
    conn.close().await?;
    if verdict != "ok" {
        return Err(Error::engine(format!(
            "standby export failed verification after filtering: integrity_check reported '{verdict}'"
        )));
    }
    Ok(tokio::fs::metadata(target).await?.len())
}

/// Take the snapshot at `target` and verify it, returning its size.
///
/// Split out so every way this can fail leaves the
/// caller holding the temp directory — the caller is the one that knows to
/// unlink it off-thread rather than inline.
async fn snapshot_into(conn: &mut SqliteConnection, target: &std::path::Path) -> Result<u64> {
    sqlx::query("VACUUM INTO ?")
        .bind(target.to_string_lossy().as_ref())
        .execute(&mut *conn)
        .await?;

    // Verify the artifact, not the intent: the exported file must be
    // integrity-clean on its own (a torn or non-portable file must never
    // reach the user or the backup store).
    let mut check =
        SqliteConnectOptions::from_str(&format!("sqlite:{}", target.to_string_lossy()))?
            .read_only(true)
            .connect()
            .await?;
    let verdict: String = sqlx::query("PRAGMA integrity_check")
        .fetch_one(&mut check)
        .await?
        .get(0);
    check.close().await?;
    if verdict != "ok" {
        return Err(Error::engine(format!(
            "export failed verification: integrity_check reported '{verdict}'"
        )));
    }

    Ok(tokio::fs::metadata(target).await?.len())
}

/// Materialize and verify one connection into a managed snapshot directory.
///
/// Kept private so callers cannot bypass filename validation or take on the
/// partial-directory cleanup protocol independently.
async fn export_connection_snapshot(
    conn: &mut SqliteConnection,
    export_root: Option<&std::path::Path>,
    file_name: String,
) -> Result<Export> {
    if let Some(root) = export_root {
        tokio::fs::create_dir_all(root).await?;
    }
    let temp = match export_root {
        Some(root) => tempfile::Builder::new()
            .prefix("native-ce-export-")
            .tempdir_in(root)?,
        None => tempfile::Builder::new()
            .prefix("native-ce-export-")
            .tempdir()?,
    };
    let mut dir = ExportDir::new(temp);
    // From here the directory exists and, the moment `VACUUM INTO` starts
    // writing, can hold a database-sized file. A failure must not let `dir`
    // drop inline on this worker thread; send the unlink to the blocking pool
    // exactly as `Export::cleanup` does on the success path.
    // RPO is measured from this conservative instant, immediately before the
    // consistent SQLite capture begins, never from later verification.
    let captured_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    match snapshot_into(conn, &dir.path().join(&file_name)).await {
        Ok(size_bytes) => Ok(Export {
            dir,
            file_name,
            size_bytes,
            captured_at,
            snapshot_completed_at: chrono::Utc::now()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            hosted_standby_context: None,
        }),
        Err(err) => {
            if let Some(dir) = dir.take() {
                remove_dir_off_thread(dir).await;
            }
            Err(err)
        }
    }
}

fn export_file_name(file_stem: &str) -> String {
    let safe = !file_stem.is_empty()
        && file_stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if safe {
        format!("{file_stem}.db")
    } else {
        // Catalog ids predate an explicit grammar constraint. Keep every such
        // database exportable without allowing an id to become a path: legacy
        // or manually-created ids receive a stable generic download name, and
        // the managed temp directory keeps simultaneous exports isolated.
        "native-ce-export.db".to_string()
    }
}

fn database_file_options(path: &std::path::Path) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(5))
}

/// Export one SQLite database file into a managed, verified snapshot.
///
/// This is the file-level seam for a catalog or other composition layer that
/// owns source selection but not SQLite artifact mechanics. It opens and
/// closes an independent connection, refuses engine-specific artifacts, and
/// owns partial-snapshot cleanup. A `file_stem` made only from ASCII letters,
/// digits, `-`, and `_` becomes `{file_stem}.db`; any legacy identifier outside
/// that grammar receives the safe generic name `native-ce-export.db`.
pub async fn export_database_file(
    source: &std::path::Path,
    export_root: &std::path::Path,
    file_stem: &str,
) -> Result<Export> {
    let file_name = export_file_name(file_stem);
    let mut conn = database_file_options(source).connect().await?;
    let export = async {
        refuse_non_portable_artifacts(&mut conn, "export").await?;
        export_connection_snapshot(&mut conn, Some(export_root), file_name).await
    }
    .await;

    // A close failure wins over a completed snapshot, but the successfully
    // materialized directory still needs off-thread cleanup before returning.
    match conn.close().await {
        Ok(()) => export,
        Err(err) => {
            if let Ok(export) = export {
                export.cleanup().await;
            }
            Err(err.into())
        }
    }
}

/// Export the already-connected database used by a tool call.
///
/// This has no tenant catalog to consult or router handle to evict:
/// authentication and tenant routing already happened before
/// the registry dispatched the tool. It deliberately reuses the same
/// checkpoint, `VACUUM INTO`, portability guard, verification, ownership, and
/// off-thread cleanup machinery as the HTTP export.
pub async fn export_connected_db(db: &Db, export_root: Option<&std::path::Path>) -> Result<Export> {
    let mut pooled = db.write_pool().acquire().await?;
    let conn: &mut SqliteConnection = &mut pooled;
    refuse_non_portable_artifacts(conn, "export").await?;
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_optional(&mut *conn)
        .await?;

    export_connection_snapshot(conn, export_root, "native-ce-export.db".to_string()).await
}

/// Filesystem-owned snapshot source for `mcp-stdio`.
///
/// The live WAL database is never copied raw. `export_connected_db` performs
/// the checkpoint, `VACUUM INTO`, portability check, and verification. Its
/// temporary directory is created beside the source `.db` and remains owned
/// by the paged handle until EOF, expiry, cancellation, or shutdown.
pub struct LocalSnapshotSource {
    coordinator: ExportCoordinator,
}

impl LocalSnapshotSource {
    pub fn new() -> Self {
        Self::with_coordinator(ExportCoordinator::new())
    }

    pub fn with_coordinator(coordinator: ExportCoordinator) -> Self {
        Self { coordinator }
    }
}

impl Default for LocalSnapshotSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotSource for LocalSnapshotSource {
    fn page(
        &self,
        db: Db,
        caller: Caller,
        request: SnapshotRequest,
    ) -> BoxFuture<'static, Result<SnapshotPage>> {
        let coordinator = self.coordinator.clone();
        let principal = caller.credential().to_string();
        let export_root = local_export_root(db.path());
        Box::pin(async move {
            if request.standby_consumer.is_some() {
                return Err(Error::engine(
                    "export_snapshot: standby_consumer requires an authenticated hosted source",
                ));
            }
            coordinator
                .tool_page(
                    principal,
                    request.export_id,
                    request.offset,
                    request.length,
                    move || async move { export_connected_db(&db, Some(&export_root)).await },
                )
                .await
        })
    }
}

fn local_export_root(db_path: &std::path::Path) -> std::path::PathBuf {
    db_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    /// Filtering must empty the disposable tables and touch nothing else.
    ///
    /// The tables have to survive as empty tables: `consumer.ddl_sha256` pins
    /// the frozen DDL against the installed standby binary, so a dropped table
    /// changes schema identity and the generation never promotes.
    #[tokio::test]
    async fn filtering_empties_disposable_tables_and_preserves_canonical_rows() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("filter-source.db");
        let db = crate::create_database(source.to_str().unwrap())
            .await
            .unwrap();
        let account = crate::identity::resolve_stdio_account_identity(&db, None)
            .await
            .unwrap();
        crate::store::create_record_as(
            &db,
            serde_json::json!({
                "type": "WorkItem",
                "kind": "task",
                "name": "Canonical record that must survive filtering"
            }),
            Some(&account),
        )
        .await
        .unwrap();
        let export = super::export_connected_db(&db, Some(directory.path()))
            .await
            .unwrap();
        db.close().await;

        let path = export.path();
        let before = tokio::fs::metadata(&path).await.unwrap().len();

        // Put rows in every disposable table so the filter has something to do.
        let conn = rusqlite::Connection::open(&path).unwrap();
        let records: i64 = conn
            .query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))
            .unwrap();
        assert!(records > 0, "fixture must contain canonical records");
        for table in super::STANDBY_DISPOSABLE_TABLES {
            let columns: i64 = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM pragma_table_info('{table}')"),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                columns > 0,
                "disposable table '{table}' must exist in the export"
            );
        }
        drop(conn);

        let after = super::strip_disposable_bookkeeping(&path).await.unwrap();

        let conn = rusqlite::Connection::open(&path).unwrap();
        for table in super::STANDBY_DISPOSABLE_TABLES {
            let remaining: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(remaining, 0, "'{table}' must be empty after filtering");
            let columns: i64 = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM pragma_table_info('{table}')"),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                columns > 0,
                "'{table}' must still exist: dropping it changes ddl_sha256 and blocks promotion"
            );
        }
        let survived: i64 = conn
            .query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            survived, records,
            "canonical records must survive filtering"
        );
        let verdict: String = conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(verdict, "ok");
        drop(conn);

        assert_eq!(
            after,
            tokio::fs::metadata(&path).await.unwrap().len(),
            "reported size must match the filtered file"
        );
        assert!(before > 0);
        export.cleanup().await;
    }

    /// An ordinary export or backup must keep everything.
    #[tokio::test]
    async fn filtering_is_a_no_op_without_a_hosted_standby_context() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("no-op-source.db");
        let db = crate::create_database(source.to_str().unwrap())
            .await
            .unwrap();
        let mut export = super::export_connected_db(&db, Some(directory.path()))
            .await
            .unwrap();
        db.close().await;

        let before = export.size_bytes();
        let digest_before = tokio::fs::read(&export.path()).await.unwrap();
        export.filter_disposable_for_standby().await.unwrap();
        assert_eq!(
            export.size_bytes(),
            before,
            "ordinary exports must not shrink"
        );
        assert_eq!(
            tokio::fs::read(&export.path()).await.unwrap(),
            digest_before,
            "ordinary export bytes must be untouched"
        );
        export.cleanup().await;
    }

    /// The denylist must name tables the frozen DDL actually creates.
    ///
    /// This is the guard that stops the filter rotting silently. If a
    /// disposable table is renamed or removed, the filter would quietly stop
    /// stripping it and standby snapshots would grow back toward the 1.63 GB
    /// that made the agreed refresh cadence impossible — with nothing failing.
    /// A new bookkeeping table is deliberately *not* caught here: adding one is
    /// a conscious decision for a human, and forgetting it only costs size.
    #[test]
    fn standby_disposable_tables_are_declared_in_the_frozen_ddl() {
        let ddl = crate::schema::ddl::DDL_STATEMENTS.join("\n").to_lowercase();
        for table in super::STANDBY_DISPOSABLE_TABLES {
            assert!(
                ddl.contains(&format!("create table if not exists {table} "))
                    || ddl.contains(&format!("create table {table} "))
                    || ddl.contains(&format!("create table if not exists {table}("))
                    || ddl.contains(&format!("create table {table}(")),
                "standby denylist names '{table}', which the frozen DDL does not create; \
                 the filter would silently stop stripping it"
            );
        }
    }

    use super::{export_connected_db, export_database_file, local_export_root};
    use sqlx::sqlite::SqliteConnectOptions;
    use sqlx::{ConnectOptions, Connection};

    #[test]
    fn a_bare_relative_database_path_uses_the_current_directory_as_its_parent() {
        assert_eq!(
            local_export_root(std::path::Path::new("knowledge.db")),
            std::path::Path::new(".")
        );
    }

    #[tokio::test]
    async fn connected_export_refuses_non_portable_artifacts_before_creating_scratch() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.db");
        let db = crate::create_database(&source.to_string_lossy())
            .await
            .unwrap();
        sqlx::query("CREATE TABLE libsql_vector_shadow (id INTEGER PRIMARY KEY)")
            .execute(db.write_pool())
            .await
            .unwrap();

        let error = export_connected_db(&db, Some(dir.path()))
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("engine-specific vector-index artifact"));
        assert!(!std::fs::read_dir(dir.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("native-ce-export-")
        }));
        db.close().await;
    }

    #[tokio::test]
    async fn file_export_uses_a_managed_custom_name_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.db");
        let export_root = dir.path().join("exports");
        let db = crate::create_database(&source.to_string_lossy())
            .await
            .unwrap();
        sqlx::query("CREATE TABLE export_file_marker (value TEXT NOT NULL)")
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO export_file_marker VALUES ('present')")
            .execute(db.write_pool())
            .await
            .unwrap();

        let export = export_database_file(&source, &export_root, "catalog-database")
            .await
            .unwrap();
        assert_eq!(export.file_name(), "catalog-database.db");
        assert_eq!(
            export.path().parent().unwrap().parent(),
            Some(export_root.as_path())
        );
        let exported_path = export.path();
        let mut exported = SqliteConnectOptions::new()
            .filename(&exported_path)
            .read_only(true)
            .connect()
            .await
            .unwrap();
        let marker: String = sqlx::query_scalar("SELECT value FROM export_file_marker")
            .fetch_one(&mut exported)
            .await
            .unwrap();
        assert_eq!(marker, "present");
        exported.close().await.unwrap();

        let managed_dir = exported_path.parent().unwrap().to_path_buf();
        export.cleanup().await;
        assert!(!managed_dir.exists());
        db.close().await;
    }

    #[test]
    fn file_export_sanitizes_legacy_identifiers_without_rejecting_them() {
        for file_stem in [
            "",
            ".",
            "..",
            "nested/name",
            "nested\\name",
            "/absolute",
            "trailing/",
            "already.db",
            "has space",
            "nul\0byte",
        ] {
            assert_eq!(
                super::export_file_name(file_stem),
                "native-ce-export.db",
                "unsafe legacy id was not sanitized: {file_stem:?}"
            );
        }
    }

    #[tokio::test]
    async fn file_export_refuses_non_portable_artifacts_before_creating_scratch() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.db");
        let export_root = dir.path().join("exports");
        let db = crate::create_database(&source.to_string_lossy())
            .await
            .unwrap();
        sqlx::query("CREATE TABLE libsql_vector_shadow (id INTEGER PRIMARY KEY)")
            .execute(db.write_pool())
            .await
            .unwrap();

        let error = export_database_file(&source, &export_root, "catalog-database")
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("engine-specific vector-index artifact"));
        assert!(!export_root.exists());
        db.close().await;
    }
}
