//! Test-only, connection-local SQLite work measurements.
//!
//! Use a dedicated test connection and one active trace per connection. A trace
//! counts executions (including trigger statements), not distinct SQL strings.
//! For a single-connection measurement, finish before returning it to a pool.
//! A pool-wide observer may instead hold all connections, install one trace on
//! each, release them for the measured call, then reacquire all simultaneously
//! and match each trace to its original handle before finishing. Pool cleanup
//! statements belong to that measurement too. If the test unwinds or is
//! cancelled, SQLite retains its own counter reference until a close attempt.
//! The pool sanitizer does not clear traces. An abandoned trace requires closing
//! the dedicated test pool; do not replace it or reuse the pool for another test.

use std::ffi::{c_void, CStr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use sqlx::SqliteConnection;

#[derive(Default)]
struct Counters {
    statements: AtomicUsize,
    internal_statements: AtomicUsize,
    max_bind_parameters: AtomicUsize,
    detached: AtomicBool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SqliteWork {
    pub statements: usize,
    /// SQLite marks nested execution (including trigger and virtual-table
    /// substatements) with a leading `--`. Included in `statements` too.
    pub internal_statements: usize,
    pub max_bind_parameters: usize,
}

/// Owns the observer's reference; SQLite independently owns a reference until
/// `finish` removes the callback or SQLITE_TRACE_CLOSE releases it.
pub(crate) struct SqliteTrace {
    counters: Arc<Counters>,
    connection: usize,
}

unsafe extern "C" fn trace(
    event: u32,
    context: *mut c_void,
    statement: *mut c_void,
    detail: *mut c_void,
) -> i32 {
    if event == libsqlite3_sys::SQLITE_TRACE_CLOSE as u32 {
        // SAFETY: install transferred exactly one Arc reference to SQLite.
        // Normal finish unregisters the callback before reclaiming that same
        // reference. A close trace can precede SQLITE_BUSY, leaving the database
        // open, so detach here before reclaiming too. For this event SQLite
        // supplies the live sqlite3* in the third argument, under its mutex.
        unsafe {
            libsqlite3_sys::sqlite3_trace_v2(statement.cast(), 0, None, std::ptr::null_mut());
        }
        let counters = unsafe { Arc::from_raw(context.cast::<Counters>()) };
        counters.detached.store(true, Ordering::Relaxed);
        drop(counters);
        return 0;
    }
    if event == libsqlite3_sys::SQLITE_TRACE_STMT as u32 {
        // SAFETY: SQLite retains the Arc above while the callback is installed;
        // SQLITE_TRACE_STMT supplies a live sqlite3_stmt as its third argument.
        let counters = unsafe { &*context.cast::<Counters>() };
        let binds = unsafe { libsqlite3_sys::sqlite3_bind_parameter_count(statement.cast()) };
        counters.statements.fetch_add(1, Ordering::Relaxed);
        // SAFETY: SQLITE_TRACE_STMT supplies NUL-terminated SQL text here.
        // Retain the total above: the marker is a diagnostic subdivision, not
        // permission to silently discard work from the measurement.
        if !detail.is_null()
            && unsafe { CStr::from_ptr(detail.cast()) }
                .to_bytes()
                .starts_with(b"--")
        {
            counters.internal_statements.fetch_add(1, Ordering::Relaxed);
        }
        counters
            .max_bind_parameters
            .fetch_max(binds as usize, Ordering::Relaxed);
    }
    0
}

impl SqliteTrace {
    pub(crate) async fn install(conn: &mut SqliteConnection) -> sqlx::Result<Self> {
        let mut handle = conn.lock_handle().await?;
        let connection = handle.as_raw_handle().as_ptr();
        let counters = Arc::new(Counters::default());
        let context = Arc::into_raw(Arc::clone(&counters));
        // SAFETY: lock_handle excludes concurrent SQLite use. The callback's
        // independently owned Arc outlives the observer even on cancellation.
        let status = unsafe {
            libsqlite3_sys::sqlite3_trace_v2(
                connection,
                (libsqlite3_sys::SQLITE_TRACE_STMT | libsqlite3_sys::SQLITE_TRACE_CLOSE) as u32,
                Some(trace),
                context.cast_mut().cast(),
            )
        };
        if status != libsqlite3_sys::SQLITE_OK {
            // SAFETY: installation failed, so SQLite did not take ownership.
            drop(unsafe { Arc::from_raw(context) });
            return Err(sqlx::Error::Protocol(format!(
                "SQLite trace install failed: {status}"
            )));
        }
        Ok(Self {
            counters,
            connection: connection as usize,
        })
    }

    /// Start a new measurement window while the connection is idle. For a
    /// pooled measurement, hold every observed connection before resetting.
    pub(crate) async fn reset(&self, conn: &mut SqliteConnection) -> sqlx::Result<()> {
        let mut handle = conn.lock_handle().await?;
        if handle.as_raw_handle().as_ptr() as usize != self.connection
            || self.counters.detached.load(Ordering::Relaxed)
        {
            return Err(sqlx::Error::Protocol(
                "SQLite trace reset on another connection".into(),
            ));
        }
        self.counters.statements.store(0, Ordering::Relaxed);
        self.counters
            .internal_statements
            .store(0, Ordering::Relaxed);
        self.counters
            .max_bind_parameters
            .store(0, Ordering::Relaxed);
        Ok(())
    }

    pub(crate) async fn finish(self, conn: &mut SqliteConnection) -> sqlx::Result<SqliteWork> {
        let mut handle = conn.lock_handle().await?;
        let connection = handle.as_raw_handle().as_ptr();
        if connection as usize != self.connection || self.counters.detached.load(Ordering::Relaxed)
        {
            return Err(sqlx::Error::Protocol(
                "SQLite trace finished on another connection".into(),
            ));
        }
        // SAFETY: this is the original connection under an exclusive lock.
        // Removing the callback ends its access before releasing its Arc.
        unsafe {
            libsqlite3_sys::sqlite3_trace_v2(connection, 0, None, std::ptr::null_mut());
            drop(Arc::from_raw(Arc::as_ptr(&self.counters)));
        }
        Ok(SqliteWork {
            statements: self.counters.statements.load(Ordering::Relaxed),
            internal_statements: self.counters.internal_statements.load(Ordering::Relaxed),
            max_bind_parameters: self.counters.max_bind_parameters.load(Ordering::Relaxed),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Connection;

    #[tokio::test]
    async fn counts_executions_and_binds_and_detaches_between_scopes() {
        let mut conn = SqliteConnection::connect(":memory:").await.unwrap();
        let trace = SqliteTrace::install(&mut conn).await.unwrap();
        sqlx::query("SELECT ?, ?, ?")
            .bind("warmup one")
            .bind("warmup two")
            .bind("warmup three")
            .execute(&mut conn)
            .await
            .unwrap();
        trace.reset(&mut conn).await.unwrap();
        for _ in 0..3 {
            sqlx::query("SELECT ?, ?")
                .bind("one")
                .bind("two")
                .execute(&mut conn)
                .await
                .unwrap();
        }
        let measured = trace.finish(&mut conn).await.unwrap();
        assert_eq!(measured.statements, 3);
        assert_eq!(measured.max_bind_parameters, 2);
        let trace = SqliteTrace::install(&mut conn).await.unwrap();
        sqlx::query("SELECT 1").execute(&mut conn).await.unwrap();
        let measured = trace.finish(&mut conn).await.unwrap();
        assert_eq!(measured.statements, 1);
        assert_eq!(measured.max_bind_parameters, 0);
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn reports_trigger_substatements_without_discarding_them() {
        let mut conn = SqliteConnection::connect(":memory:").await.unwrap();
        sqlx::raw_sql("CREATE TABLE input(value TEXT); CREATE TABLE audit(value TEXT);             CREATE TRIGGER log_input AFTER INSERT ON input BEGIN             INSERT INTO audit VALUES(new.value); END;")
            .execute(&mut conn).await.unwrap();
        let trace = SqliteTrace::install(&mut conn).await.unwrap();
        sqlx::query("INSERT INTO input VALUES(?)")
            .bind("entry")
            .execute(&mut conn)
            .await
            .unwrap();
        let measured = trace.finish(&mut conn).await.unwrap();
        assert_eq!(measured.statements, 3);
        assert_eq!(measured.internal_statements, 2);
        assert_eq!(measured.max_bind_parameters, 1);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(count, 1);
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn abandoned_observer_remains_owned_until_connection_close() {
        let mut conn = SqliteConnection::connect(":memory:").await.unwrap();
        let trace = SqliteTrace::install(&mut conn).await.unwrap();
        let counters = Arc::downgrade(&trace.counters);
        drop(trace);
        sqlx::query("SELECT 1").execute(&mut conn).await.unwrap();
        assert_eq!(
            counters
                .upgrade()
                .unwrap()
                .statements
                .load(Ordering::Relaxed),
            1
        );
        conn.close().await.unwrap();
        assert!(
            counters.upgrade().is_none(),
            "close releases SQLite's reference"
        );
    }

    #[tokio::test]
    async fn busy_close_detaches_before_reclaiming_callback_context() {
        let mut conn = SqliteConnection::connect(":memory:").await.unwrap();
        let trace = SqliteTrace::install(&mut conn).await.unwrap();
        // Keep the allocation live even if a regressed callback remains
        // installed after releasing SQLite's reference. The statement counter
        // then detects the regression without relying on undefined behaviour.
        let counters = Arc::clone(&trace.counters);
        drop(trace);
        let (close_status, step_status, finalize_status);
        {
            let mut handle = conn.lock_handle().await.unwrap();
            let raw = handle.as_raw_handle().as_ptr();
            let mut statement = std::ptr::null_mut();
            // SAFETY: the SQLx lock excludes concurrent handle use. This raw
            // statement deliberately remains open across sqlite3_close, which
            // must return BUSY and leave the connection alive. Finalize it
            // before releasing the lock or making assertions about the result.
            unsafe {
                let prepared = libsqlite3_sys::sqlite3_prepare_v2(
                    raw,
                    c"SELECT 1".as_ptr(),
                    -1,
                    &mut statement,
                    std::ptr::null_mut(),
                );
                assert_eq!(prepared, libsqlite3_sys::SQLITE_OK);
                close_status = libsqlite3_sys::sqlite3_close(raw);
                step_status = libsqlite3_sys::sqlite3_step(statement);
                // Test cleanup, also on an unfixed implementation: the step
                // above has already exposed any stale callback. Detach before
                // a second close can reclaim its reference again.
                libsqlite3_sys::sqlite3_trace_v2(raw, 0, None, std::ptr::null_mut());
                finalize_status = libsqlite3_sys::sqlite3_finalize(statement);
            }
        }
        assert_eq!(close_status, libsqlite3_sys::SQLITE_BUSY);
        assert_eq!(step_status, libsqlite3_sys::SQLITE_ROW);
        assert_eq!(finalize_status, libsqlite3_sys::SQLITE_OK);
        assert_eq!(
            counters.statements.load(Ordering::Relaxed),
            0,
            "the statement after a busy close must not invoke the detached callback"
        );
        assert_eq!(
            Arc::strong_count(&counters),
            1,
            "the close attempt releases SQLite's reference"
        );
        conn.close().await.unwrap();
    }
}
