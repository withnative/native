//! Bounded bootstrap phase diagnostics: never log caller data or database prose.
use crate::{Error, Result};
use std::{future::Future, time::Instant};

pub(super) async fn stage<T>(
    stage: &'static str,
    work: impl Future<Output = Result<T>>,
) -> Result<T> {
    let started = Instant::now();
    let result = work.await;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    match &result {
        Ok(_) => {
            tracing::debug!(target: "native_ce::bootstrap", stage, elapsed_ms, outcome = "succeeded")
        }
        Err(error) => {
            tracing::warn!(target: "native_ce::bootstrap", stage, elapsed_ms, outcome = failure_class(error), "kernel-v2 bootstrap stage failed")
        }
    }
    result
}

fn failure_class(error: &Error) -> &'static str {
    match error {
        Error::Sqlx(sqlx::Error::PoolTimedOut) => "pool_timeout",
        Error::Sqlx(sqlx::Error::Database(error)) if error.code().as_deref() == Some("9") => {
            "sqlite_interrupted"
        }
        Error::Sqlx(_) => "database_error",
        _ => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bootstrap_stage_preserves_failure_without_reexecuting() {
        let mut connection = sqlx::SqliteConnection::connect(":memory:").await.unwrap();
        connection
            .lock_handle()
            .await
            .unwrap()
            .set_progress_handler(1, || false);
        let interrupted: Error = sqlx::query("SELECT 1")
            .execute(&mut connection)
            .await
            .unwrap_err()
            .into();
        assert_eq!(failure_class(&interrupted), "sqlite_interrupted");
        let original = interrupted.to_string();
        let mut attempts = 0;
        let error = stage("root_preview", async {
            attempts += 1;
            Err::<(), _>(interrupted)
        })
        .await
        .unwrap_err();
        assert_eq!(attempts, 1);
        assert_eq!(error.to_string(), original);
        assert_eq!(
            failure_class(&Error::Sqlx(sqlx::Error::PoolTimedOut)),
            "pool_timeout"
        );
        assert_eq!(
            failure_class(&Error::engine("private caller text")),
            "error"
        );
    }

    use sqlx::Connection;
}
