//! Reuse physical SQLite connections only after caller staging is gone.
use sqlx::{pool::PoolConnection, Sqlite, SqliteConnection};
use std::ops::{Deref, DerefMut};

#[cfg(all(test, feature = "v2-kernel-probe"))]
tokio::task_local! { static FAIL_CURRENT_CLOSE_ACK: (); }
#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(super) async fn with_failed_close_ack<F: std::future::Future>(work: F) -> F::Output {
    FAIL_CURRENT_CLOSE_ACK.scope((), work).await
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
tokio::task_local! { static CURRENT_CLOSE_PROBE: std::sync::Arc<CloseProbe>; }

/// Task-scoped failure/cancellation fixture. The callback owns only the worker
/// gate and notification, never this probe, so it cannot form a release cycle.
#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(super) struct CloseProbe {
    worker: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    worker_entered: std::sync::Arc<tokio::sync::Notify>,
    close_pending: tokio::sync::Notify,
    resume_close: tokio::sync::Notify,
    acknowledged: std::sync::atomic::AtomicBool,
    handle: std::sync::atomic::AtomicUsize,
}
#[cfg(all(test, feature = "v2-kernel-probe"))]
impl CloseProbe {
    pub(super) fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            worker: std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new())),
            worker_entered: std::sync::Arc::new(tokio::sync::Notify::new()),
            close_pending: tokio::sync::Notify::new(),
            resume_close: tokio::sync::Notify::new(),
            acknowledged: std::sync::atomic::AtomicBool::new(false),
            handle: std::sync::atomic::AtomicUsize::new(0),
        })
    }
    pub(super) fn release_worker(&self) {
        let (lock, wake) = &*self.worker;
        *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        wake.notify_all();
        // The fixture's external guard also releases the continuation on panic.
        // Normal cancellation has already dropped that future; this notification
        // cannot manufacture an ACK for a cancelled reader.
        self.resume_close.notify_one();
    }
    pub(super) async fn pending(&self) {
        self.close_pending.notified().await;
    }
    pub(super) fn acknowledged(&self) -> bool {
        self.acknowledged.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub(super) fn handle(&self) -> usize {
        self.handle.load(std::sync::atomic::Ordering::SeqCst)
    }
    async fn hold_actual_worker(&self, connection: &mut SqliteConnection) -> crate::Result<()> {
        {
            let mut handle = connection.lock_handle().await?;
            self.handle.store(
                handle.as_raw_handle().as_ptr() as usize,
                std::sync::atomic::Ordering::SeqCst,
            );
            let worker = self.worker.clone();
            let entered = self.worker_entered.clone();
            handle.set_progress_handler(1, move || {
                entered.notify_one();
                let (lock, wake) = &*worker;
                let mut released = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while !*released {
                    released = wake
                        .wait(released)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                true
            });
        }
        // Real SQLite VM work is now pending in its worker. Cancellation of this
        // query releases the Rust borrow, not that worker or its physical handle.
        let mut operation = Box::pin(sqlx::query("SELECT 1").execute(&mut *connection));
        if let std::task::Poll::Ready(result) = futures::poll!(operation.as_mut()) {
            result?;
            return Err(crate::Error::engine(
                "close probe failed to hold actual SQLite worker",
            ));
        }
        self.worker_entered.notified().await;
        drop(operation);
        Ok(())
    }
}
#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(super) async fn with_close_probe<F: std::future::Future>(
    probe: std::sync::Arc<CloseProbe>,
    work: F,
) -> F::Output {
    CURRENT_CLOSE_PROBE.scope(probe, work).await
}

pub(super) struct ReadConnection {
    connection: Option<PoolConnection<Sqlite>>,
    reusable: bool,
}
impl ReadConnection {
    pub(super) fn new(connection: PoolConnection<Sqlite>) -> Self {
        Self {
            connection: Some(connection),
            reusable: false,
        }
    }

    #[cfg(all(test, feature = "v2-kernel-probe"))]
    pub(super) fn reusable_for_diagnostic(&self) -> bool {
        self.reusable
    }

    /// Consume the actual lease and acknowledge physical close before a current
    /// body reader can wait for room ops. Cancellation cannot recycle staging.
    #[cfg(feature = "v2-kernel-probe")]
    pub(super) async fn close_owned(mut self) -> crate::Result<()> {
        let mut connection = self
            .connection
            .take()
            .expect("read connection already consumed");
        connection.close_on_drop();
        #[cfg(test)]
        let probe = CURRENT_CLOSE_PROBE.try_with(std::sync::Arc::clone).ok();
        #[cfg(test)]
        if let Some(probe) = &probe {
            probe.hold_actual_worker(&mut connection).await?;
        }
        let closing = connection.close();
        tokio::pin!(closing);
        #[cfg(test)]
        if let Some(probe) = &probe {
            match futures::poll!(closing.as_mut()) {
                std::task::Poll::Pending => {
                    probe.close_pending.notify_one();
                    probe.resume_close.notified().await;
                }
                std::task::Poll::Ready(result) => {
                    result?;
                    return Err(crate::Error::engine(
                        "close probe expected actual Pending worker close",
                    ));
                }
            }
        }
        closing.await?;
        #[cfg(test)]
        if let Some(probe) = &probe {
            probe
                .acknowledged
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        #[cfg(test)]
        if FAIL_CURRENT_CLOSE_ACK.try_with(|_| ()).is_ok() {
            // Failure-only fault injection: actual physical close has completed,
            // but no usable ACK/result is exposed to the owning composition.
            return Err(crate::Error::engine(
                "injected current read close ACK failure",
            ));
        }
        Ok(())
    }

    /// Called only after the read transaction has rolled back. TEMP DDL is
    /// transactional, so rollback removes every materialized caller relation.
    /// This deliberately keeps no staging, identity or visibility across calls;
    /// only SQLite's ordinary physical connection and page cache may survive.
    /// Failure at any await, including cancellation, leaves close-on-drop armed.
    pub(super) async fn finish(&mut self) {
        {
            let Ok(mut handle) = self
                .connection
                .as_mut()
                .expect("read connection already consumed")
                .lock_handle()
                .await
            else {
                return;
            };
            handle.remove_progress_handler();
            // SAFETY: the locked SQLite handle is exclusively borrowed and live.
            if unsafe {
                libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) == 0
            } {
                return;
            }
        }
        use sqlx::Connection;
        if self
            .connection
            .as_ref()
            .expect("read connection already consumed")
            .is_in_transaction()
        {
            return;
        }
        if sqlx::query("PRAGMA query_only=OFF")
            .execute(
                &mut **self
                    .connection
                    .as_mut()
                    .expect("read connection already consumed"),
            )
            .await
            .is_err()
        {
            return;
        }
        let empty = sqlx::query_scalar::<_, bool>(
            "SELECT NOT EXISTS(SELECT 1 FROM temp.sqlite_schema WHERE name NOT GLOB 'sqlite_*')",
        )
        .fetch_one(
            &mut **self
                .connection
                .as_mut()
                .expect("read connection already consumed"),
        )
        .await;
        self.reusable = matches!(empty, Ok(true));
        // The existing governed-pool release hook independently verifies both
        // transaction states, resets limits and removes any frozen v1 contract.
    }
}
impl Deref for ReadConnection {
    type Target = SqliteConnection;
    fn deref(&self) -> &Self::Target {
        self.connection
            .as_ref()
            .expect("read connection already consumed")
    }
}
impl DerefMut for ReadConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.connection
            .as_mut()
            .expect("read connection already consumed")
    }
}
impl Drop for ReadConnection {
    fn drop(&mut self) {
        if !self.reusable {
            if let Some(connection) = self.connection.as_mut() {
                connection.close_on_drop();
            }
        }
    }
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
mod current_connection_tests {
    use super::*;
    async fn pool() -> sqlx::SqlitePool {
        sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap()
    }
    async fn marked(pool: &sqlx::SqlitePool) -> ReadConnection {
        let mut connection = ReadConnection::new(pool.acquire().await.unwrap());
        sqlx::query("PRAGMA cache_size=17123")
            .execute(&mut *connection)
            .await
            .unwrap();
        connection
    }
    async fn marker(connection: &mut SqliteConnection) -> i64 {
        sqlx::query_scalar("PRAGMA cache_size")
            .fetch_one(connection)
            .await
            .unwrap()
    }
    #[tokio::test]
    async fn legacy_finish_reuses_only_rolled_back_empty_staging() {
        let pool = pool().await;
        let mut connection = marked(&pool).await;
        sqlx::query("BEGIN; CREATE TEMP TABLE caller_identity(value TEXT); INSERT INTO caller_identity VALUES('old actor'); ROLLBACK")
            .execute(&mut *connection).await.unwrap();
        connection.finish().await;
        assert!(connection.reusable);
        drop(connection);
        let mut next = pool.acquire().await.unwrap();
        assert_eq!(marker(&mut next).await, 17123); // existing physical connection
        let staged: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM temp.sqlite_schema WHERE name='caller_identity'",
        )
        .fetch_one(&mut *next)
        .await
        .unwrap();
        assert_eq!(staged, 0);
        let query_only: i64 = sqlx::query_scalar("PRAGMA query_only")
            .fetch_one(&mut *next)
            .await
            .unwrap();
        assert_eq!(query_only, 0);
    }
    #[tokio::test]
    async fn failed_finish_and_unfinished_drop_discard_caller_staging() {
        for finish in [false, true] {
            let pool = pool().await;
            let mut connection = marked(&pool).await;
            sqlx::query("CREATE TEMP TABLE caller_identity(value TEXT)")
                .execute(&mut *connection)
                .await
                .unwrap();
            if finish {
                connection.finish().await;
                assert!(!connection.reusable);
            }
            drop(connection);
            let mut next = pool.acquire().await.unwrap();
            assert_ne!(marker(&mut next).await, 17123);
            let staged: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM temp.sqlite_schema WHERE name='caller_identity'",
            )
            .fetch_one(&mut *next)
            .await
            .unwrap();
            assert_eq!(staged, 0);
        }
    }
    #[tokio::test]
    async fn owned_close_ack_consumes_lease_and_cancel_never_recycles_staging() {
        for cancel in [false, true] {
            let pool = pool().await;
            let mut connection = marked(&pool).await;
            sqlx::query("BEGIN; CREATE TEMP TABLE caller_identity(value TEXT)")
                .execute(&mut *connection)
                .await
                .unwrap();
            let close = connection.close_owned();
            if cancel {
                // Cancellation before first poll: armed ReadConnection Drop,
                // no asynchronous ACK claimed. Composed tests cancel SQL/T3.
                drop(close);
            } else {
                close.await.unwrap(); // actual SQLx physical worker-close ACK
                assert_eq!(pool.size(), 0);
            }
            let mut next = pool.acquire().await.unwrap();
            assert_ne!(marker(&mut next).await, 17123);
            let staged: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM temp.sqlite_schema WHERE name='caller_identity'",
            )
            .fetch_one(&mut *next)
            .await
            .unwrap();
            assert_eq!(staged, 0);
        }
    }
}
