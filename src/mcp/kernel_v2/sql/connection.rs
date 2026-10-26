//! Reuse physical SQLite connections only after caller staging is gone.
use sqlx::{pool::PoolConnection, Sqlite, SqliteConnection};
use std::ops::{Deref, DerefMut};

pub(super) struct ReadConnection {
    connection: PoolConnection<Sqlite>,
    reusable: bool,
}
impl ReadConnection {
    pub(super) fn new(connection: PoolConnection<Sqlite>) -> Self {
        Self {
            connection,
            reusable: false,
        }
    }

    /// Called only after the read transaction has rolled back. TEMP DDL is
    /// transactional, so rollback removes every materialized caller relation.
    /// This deliberately keeps no staging, identity or visibility across calls;
    /// only SQLite's ordinary physical connection and page cache may survive.
    /// Failure at any await, including cancellation, leaves close-on-drop armed.
    pub(super) async fn finish(&mut self) {
        {
            let Ok(mut handle) = self.connection.lock_handle().await else {
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
        if self.connection.is_in_transaction() {
            return;
        }
        if sqlx::query("PRAGMA query_only=OFF")
            .execute(&mut *self.connection)
            .await
            .is_err()
        {
            return;
        }
        let empty = sqlx::query_scalar::<_, bool>(
            "SELECT NOT EXISTS(SELECT 1 FROM temp.sqlite_schema WHERE name NOT GLOB 'sqlite_*')",
        )
        .fetch_one(&mut *self.connection)
        .await;
        self.reusable = matches!(empty, Ok(true));
        // The existing governed-pool release hook independently verifies both
        // transaction states, resets limits and removes any frozen v1 contract.
    }
}
impl Deref for ReadConnection {
    type Target = SqliteConnection;
    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}
impl DerefMut for ReadConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}
impl Drop for ReadConnection {
    fn drop(&mut self) {
        if !self.reusable {
            self.connection.close_on_drop();
        }
    }
}
