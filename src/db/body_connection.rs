//! Filename-only observation after the caller owns the raw SQLite connection.
//! No role, permission, retirement fence, body ticket or physical ACK is supplied.

use super::{Db, SqliteConnection};
use crate::managed_custody::{body_filename_footing, BodyFilenameFooting};
use crate::Result;
use std::path::{Path, PathBuf};

#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyHostAvailability {
    AvailableUnmanaged,
    KnownUnavailable,
}

pub(super) async fn actual_main_filename(
    connection: &mut SqliteConnection,
) -> sqlx::Result<PathBuf> {
    // sqlite3_db_filename is read under exclusive handle access.
    let filename = {
        let mut handle = connection.lock_handle().await?;
        let raw = unsafe {
            libsqlite3_sys::sqlite3_db_filename(handle.as_raw_handle().as_ptr(), c"main".as_ptr())
        };
        if raw.is_null() {
            return Err(sqlx::Error::Protocol(
                "SQLite main filename unavailable".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
                unsafe { std::ffi::CStr::from_ptr(raw) }.to_bytes(),
            ))
        }
        #[cfg(not(unix))]
        {
            std::path::PathBuf::from(
                unsafe { std::ffi::CStr::from_ptr(raw) }
                    .to_str()
                    .map_err(|_| sqlx::Error::Protocol("SQLite filename invalid".into()))?,
            )
        }
    };
    Ok(filename)
}

impl Db {
    /// Nonregistering observation only; H5 still atomically registers before
    /// physical startup and repeats classification on the owned raw handle.
    #[doc(hidden)]
    pub fn body_host_availability(&self) -> Result<BodyHostAvailability> {
        if !self.body_jobs.submission_available()?
            || self.read_pool.is_closed()
            || self.write_pool.is_closed()
            || self.governed_pool.is_closed()
        {
            return Ok(BodyHostAvailability::KnownUnavailable);
        }
        let options = self.governed_pool.connect_options();
        let filename = options.get_filename();
        if filename.as_os_str().is_empty() || filename == Path::new(":memory:") {
            return Ok(BodyHostAvailability::KnownUnavailable);
        }
        match body_filename_footing(filename)? {
            BodyFilenameFooting::Unmarked => Ok(BodyHostAvailability::AvailableUnmanaged),
            BodyFilenameFooting::KnownExcludedMarked => Ok(BodyHostAvailability::KnownUnavailable),
        }
    }
    /// Observe the actual owned main filename without acquiring writer custody.
    /// H5 must own/register the raw job before polling this hook. H7 still needs
    /// its same-state retirement check; this fact is not complete availability.
    pub(crate) async fn install_body_owned_guard(
        &self,
        connection: &mut SqliteConnection,
    ) -> Result<BodyHostAvailability> {
        let filename = actual_main_filename(connection).await?;
        if filename.as_os_str().is_empty() || filename == Path::new(":memory:") {
            return Ok(BodyHostAvailability::KnownUnavailable);
        }
        match body_filename_footing(&filename)? {
            BodyFilenameFooting::Unmarked => Ok(BodyHostAvailability::AvailableUnmanaged),
            BodyFilenameFooting::KnownExcludedMarked => Ok(BodyHostAvailability::KnownUnavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::{sqlite::SqliteConnectOptions, Connection};

    async fn raw_file(path: &Path, read_only: bool) -> SqliteConnection {
        SqliteConnection::connect_with(
            &SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(!read_only)
                .read_only(read_only)
                .optimize_on_close(false, None),
        )
        .await
        .unwrap()
    }

    #[cfg(unix)]
    fn reservation() -> (
        tempfile::TempDir,
        PathBuf,
        crate::managed_custody::Enrollment,
    ) {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("databases")).unwrap();
        let generation = uuid::Uuid::new_v4().to_string();
        let path = std::fs::canonicalize(root.path().join("databases"))
            .unwrap()
            .join(format!("{generation}.db"));
        let enrollment =
            crate::managed_custody::reserve_fresh_adoption(root.path(), &path, &generation)
                .unwrap();
        (root, path, enrollment)
    }

    async fn fixture_file(path: &Path) {
        let mut raw = raw_file(path, false).await;
        sqlx::query("CREATE TABLE canary(value TEXT)")
            .execute(&mut raw)
            .await
            .unwrap();
        sqlx::query("INSERT INTO canary VALUES('unchanged')")
            .execute(&mut raw)
            .await
            .unwrap();
        raw.close().await.unwrap();
    }

    #[tokio::test]
    async fn actual_nonfile_main_is_unavailable_without_db_path_fallback() {
        let db = super::super::open_database(":memory:").await.unwrap();
        let mut raw = SqliteConnection::connect(":memory:").await.unwrap();
        assert!(actual_main_filename(&mut raw)
            .await
            .unwrap()
            .as_os_str()
            .is_empty());
        assert_eq!(
            db.install_body_owned_guard(&mut raw).await.unwrap(),
            BodyHostAvailability::KnownUnavailable
        );
        raw.close().await.unwrap();
        db.close().await;
    }

    #[tokio::test]
    async fn real_unmarked_filename_is_selected_from_raw_not_db() {
        let root = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(root.path())
            .unwrap()
            .join("ordinary-é-文.db");
        fixture_file(&path).await;
        let before = std::fs::read(&path).unwrap();
        let db = super::super::open_database(":memory:").await.unwrap();
        let mut raw = raw_file(&path, true).await;
        let actual = actual_main_filename(&mut raw).await.unwrap();
        assert_eq!(actual, std::fs::canonicalize(&path).unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            assert_eq!(actual.as_os_str().as_bytes(), path.as_os_str().as_bytes());
        }
        super::super::install_enrolled_guard(&mut raw, true)
            .await
            .unwrap();
        assert_eq!(
            db.install_body_owned_guard(&mut raw).await.unwrap(),
            BodyHostAvailability::AvailableUnmanaged
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        raw.close().await.unwrap();
        db.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn genuine_pending_and_finalized_raw_main_are_excluded() {
        for finalized in [false, true] {
            let (_root, path, enrollment) = reservation();
            fixture_file(&path).await;
            if finalized {
                enrollment.finalize().unwrap();
            }
            let before = std::fs::read(&path).unwrap();
            let db = super::super::open_database(":memory:").await.unwrap();
            let mut raw = raw_file(&path, true).await;
            assert_eq!(actual_main_filename(&mut raw).await.unwrap(), path);
            assert_eq!(
                db.install_body_owned_guard(&mut raw).await.unwrap(),
                BodyHostAvailability::KnownUnavailable
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
            raw.close().await.unwrap();
            db.close().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn corrupt_and_torn_actual_main_return_error_not_unavailable() {
        for corrupt_intent in [false, true] {
            let (_root, path, _enrollment) = reservation();
            fixture_file(&path).await;
            let metadata = path
                .parent()
                .unwrap()
                .join(crate::managed_custody::METADATA_DIRECTORY);
            if corrupt_intent {
                let mut expected = path.file_name().unwrap().to_os_string();
                expected.push(".expected.json");
                std::fs::write(metadata.join(expected), b"{broken").unwrap();
            } else {
                std::fs::remove_file(metadata.join(path.file_name().unwrap()).join("owner.lock"))
                    .unwrap();
            }
            let before = std::fs::read(&path).unwrap();
            let db = super::super::open_database(":memory:").await.unwrap();
            let mut raw = raw_file(&path, true).await;
            assert_eq!(actual_main_filename(&mut raw).await.unwrap(), path);
            assert!(db.install_body_owned_guard(&mut raw).await.is_err());
            assert_eq!(std::fs::read(&path).unwrap(), before);
            raw.close().await.unwrap();
            db.close().await;
        }
    }

    #[tokio::test]
    async fn availability_uses_actual_governed_filename_and_keeps_nonfile_unavailable() {
        let db = super::super::open_database(":memory:").await.unwrap();
        let options = db.governed_pool.connect_options();
        let filename = options.get_filename();
        assert!(!filename.as_os_str().is_empty());
        assert_ne!(filename, std::path::Path::new(":memory:"));
        assert_eq!(
            db.body_host_availability().unwrap(),
            BodyHostAvailability::AvailableUnmanaged
        );
        db.close().await;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("ordinary.db");
        let db = super::super::create_database(path.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(
            db.body_host_availability().unwrap(),
            BodyHostAvailability::AvailableUnmanaged
        );
        let ticket = db.register_body_job().unwrap();
        // Registration/capacity is not a new availability or authority policy.
        assert_eq!(
            db.body_host_availability().unwrap(),
            BodyHostAvailability::AvailableUnmanaged
        );
        ticket.no_physical_started().unwrap();
        db.close().await;
    }

    #[tokio::test]
    async fn availability_fences_submission_and_each_actual_pool_close() {
        for closed in 0..4 {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("ordinary.db");
            let db = super::super::create_database(path.to_str().unwrap())
                .await
                .unwrap();
            assert_eq!(
                db.body_host_availability().unwrap(),
                BodyHostAvailability::AvailableUnmanaged
            );
            match closed {
                0 => db.body_jobs.stop_submission(),
                1 => db.read_pool.close().await,
                2 => db.write_pool.close().await,
                _ => db.governed_pool.close().await,
            }
            assert_eq!(
                db.body_host_availability().unwrap(),
                BodyHostAvailability::KnownUnavailable
            );
            db.close().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn availability_valid_marked_is_excluded_but_corrupt_marked_is_error() {
        for state in 0..3 {
            let (_root, path, enrollment) = reservation();
            fixture_file(&path).await;
            if state == 1 {
                enrollment.finalize().unwrap();
            } else if state == 2 {
                let mut name = path.file_name().unwrap().to_os_string();
                name.push(".expected.json");
                std::fs::write(
                    path.parent()
                        .unwrap()
                        .join(crate::managed_custody::METADATA_DIRECTORY)
                        .join(name),
                    b"{broken",
                )
                .unwrap();
            }
            let before = std::fs::read(&path).unwrap();
            let mut db = super::super::open_database(":memory:").await.unwrap();
            db.governed_pool.close().await;
            // Private test construction selects an ACTUAL readonly pool with
            // exact filename options. No production authority/caller stub.
            db.governed_pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(
                    SqliteConnectOptions::new()
                        .filename(&path)
                        .read_only(true)
                        .create_if_missing(false),
                )
                .await
                .unwrap();
            if state == 2 {
                assert!(db.body_host_availability().is_err());
            } else {
                assert_eq!(
                    db.body_host_availability().unwrap(),
                    BodyHostAvailability::KnownUnavailable
                );
            }
            assert_eq!(std::fs::read(&path).unwrap(), before);
            db.close().await;
        }
    }
}
