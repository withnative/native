//! Backend-owned transaction lifecycle for canonical handlers.
//!
//! The shared runner chooses no isolation mode and owns no connection. A
//! backend supplies begin/commit/rollback and the canonical handler receives
//! only a mutable admitted transaction. The handler therefore cannot commit,
//! retry, or replace the transaction it was given.

use futures::future::BoxFuture;

use crate::portable_sql::{ErrorCategory, ExecutionControl, ExecutionPhase, SqlError, SqlResult};
use crate::{Error, Result};

pub(crate) trait TransactionLifecyclePort {
    type Transaction;

    fn begin<'a>(&'a mut self) -> BoxFuture<'a, Result<Self::Transaction>>;

    fn commit<'a>(&'a mut self, transaction: Self::Transaction) -> BoxFuture<'a, SqlResult<()>>;

    fn rollback<'a>(&'a mut self, transaction: Self::Transaction) -> BoxFuture<'a, Result<()>>;

    /// A backend with an external commit token may prove that an interrupted
    /// commit reached durability. SQLite deliberately returns false: once its
    /// commit future is interrupted, the request cannot distinguish outcomes.
    fn prove_interrupted_commit<'a>(&'a mut self) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async { Ok(false) })
    }
}

#[derive(Debug)]
pub(crate) enum TransactionLifecycleError {
    Domain(Error),
    Control(SqlError),
}

/// Explicit successful disposition for handlers whose result determines
/// whether an admitted write transaction actually changed durable state.
#[cfg(any(feature = "turso-local", test))]
pub(crate) enum TransactionDisposition<T> {
    Commit(T),
    Rollback(T),
}

impl TransactionLifecycleError {
    pub(crate) fn stable(self, operation: &str) -> Error {
        match self {
            Self::Domain(error) => error,
            Self::Control(error) => super::stable_storage_error(operation, &error),
        }
    }
}

/// Run one guarded write exactly once. Any validation/authorization failure or
/// statement interruption rolls back. A commit interruption is outcome-unknown
/// unless the backend can prove durability; the handler is never replayed.
pub(crate) async fn run_backend_transaction<P, C, T, H>(
    port: &mut P,
    control: &ExecutionControl,
    context: &mut C,
    handler: H,
) -> std::result::Result<T, TransactionLifecycleError>
where
    P: TransactionLifecyclePort,
    H: for<'transaction> FnOnce(
        &'transaction mut P::Transaction,
        &'transaction mut C,
    ) -> BoxFuture<'transaction, Result<T>>,
{
    let mut transaction = control
        .run_domain(ExecutionPhase::Begin, async { Ok(port.begin().await) })
        .await
        .map_err(TransactionLifecycleError::Control)?
        .map_err(TransactionLifecycleError::Domain)?;

    let handled = control
        .run_domain(ExecutionPhase::Statement, async {
            Ok(handler(&mut transaction, context).await)
        })
        .await;
    let value = match handled {
        Ok(Ok(value)) => value,
        Ok(Err(primary)) => {
            let _ = port.rollback(transaction).await;
            return Err(TransactionLifecycleError::Domain(primary));
        }
        Err(control_error) => {
            let _ = port.rollback(transaction).await;
            return Err(TransactionLifecycleError::Control(control_error));
        }
    };

    match control
        .run_domain(ExecutionPhase::Commit, port.commit(transaction))
        .await
    {
        Ok(()) => Ok(value),
        Err(mut commit_error) => {
            if matches!(
                commit_error.category,
                ErrorCategory::Cancelled | ErrorCategory::DeadlineExceeded
            ) {
                commit_error = super::commit_interruption(commit_error.category);
            }
            if commit_error.category != ErrorCategory::OutcomeUnknown {
                return Err(TransactionLifecycleError::Control(commit_error));
            }
            if port
                .prove_interrupted_commit()
                .await
                .map_err(TransactionLifecycleError::Domain)?
            {
                Ok(value)
            } else {
                Err(TransactionLifecycleError::Control(commit_error))
            }
        }
    }
}

/// Run one guarded operation whose successful handler result decides whether
/// to commit or close the transaction by rollback. This is used for
/// write-shaped operations with pure idempotent-hit paths: those paths must
/// neither advance the backend commit generation nor emit realtime wakeups.
#[cfg(any(feature = "turso-local", test))]
pub(crate) async fn run_backend_transaction_with_disposition<P, C, T, H>(
    port: &mut P,
    control: &ExecutionControl,
    context: &mut C,
    handler: H,
) -> std::result::Result<T, TransactionLifecycleError>
where
    P: TransactionLifecyclePort,
    H: for<'transaction> FnOnce(
        &'transaction mut P::Transaction,
        &'transaction mut C,
    ) -> BoxFuture<'transaction, Result<TransactionDisposition<T>>>,
{
    let mut transaction = control
        .run_domain(ExecutionPhase::Begin, async { Ok(port.begin().await) })
        .await
        .map_err(TransactionLifecycleError::Control)?
        .map_err(TransactionLifecycleError::Domain)?;

    let handled = control
        .run_domain(ExecutionPhase::Statement, async {
            Ok(handler(&mut transaction, context).await)
        })
        .await;
    let disposition = match handled {
        Ok(Ok(disposition)) => disposition,
        Ok(Err(primary)) => {
            let _ = port.rollback(transaction).await;
            return Err(TransactionLifecycleError::Domain(primary));
        }
        Err(control_error) => {
            let _ = port.rollback(transaction).await;
            return Err(TransactionLifecycleError::Control(control_error));
        }
    };

    let value = match disposition {
        TransactionDisposition::Rollback(value) => {
            port.rollback(transaction)
                .await
                .map_err(TransactionLifecycleError::Domain)?;
            return Ok(value);
        }
        TransactionDisposition::Commit(value) => value,
    };

    match control
        .run_domain(ExecutionPhase::Commit, port.commit(transaction))
        .await
    {
        Ok(()) => Ok(value),
        Err(mut commit_error) => {
            if matches!(
                commit_error.category,
                ErrorCategory::Cancelled | ErrorCategory::DeadlineExceeded
            ) {
                commit_error = super::commit_interruption(commit_error.category);
            }
            if commit_error.category != ErrorCategory::OutcomeUnknown {
                return Err(TransactionLifecycleError::Control(commit_error));
            }
            if port
                .prove_interrupted_commit()
                .await
                .map_err(TransactionLifecycleError::Domain)?
            {
                Ok(value)
            } else {
                Err(TransactionLifecycleError::Control(commit_error))
            }
        }
    }
}

/// Run one read snapshot exactly once and always close it with backend-owned
/// rollback. Primary validation/auth/storage failures are preserved when
/// cleanup also fails.
pub(crate) async fn run_backend_snapshot<P, C, T, H>(
    port: &mut P,
    control: &ExecutionControl,
    context: &mut C,
    handler: H,
) -> std::result::Result<T, TransactionLifecycleError>
where
    P: TransactionLifecyclePort,
    H: for<'transaction> FnOnce(
        &'transaction mut P::Transaction,
        &'transaction mut C,
    ) -> BoxFuture<'transaction, Result<T>>,
{
    let mut transaction = control
        .run_domain(ExecutionPhase::Begin, async { Ok(port.begin().await) })
        .await
        .map_err(TransactionLifecycleError::Control)?
        .map_err(TransactionLifecycleError::Domain)?;
    let handled = control
        .run_domain(ExecutionPhase::Statement, async {
            Ok(handler(&mut transaction, context).await)
        })
        .await;
    match handled {
        Ok(Ok(value)) => {
            port.rollback(transaction)
                .await
                .map_err(TransactionLifecycleError::Domain)?;
            Ok(value)
        }
        Ok(Err(primary)) => {
            let _ = port.rollback(transaction).await;
            Err(TransactionLifecycleError::Domain(primary))
        }
        Err(control_error) => {
            let _ = port.rollback(transaction).await;
            Err(TransactionLifecycleError::Control(control_error))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    #[derive(Default)]
    struct FakePort {
        begins: usize,
        commits: usize,
        rollbacks: usize,
        prove_commit: bool,
        block_commit: bool,
        commit_error: Option<SqlError>,
        rollback_error: bool,
    }

    impl TransactionLifecyclePort for FakePort {
        type Transaction = ();

        fn begin<'a>(&'a mut self) -> BoxFuture<'a, Result<Self::Transaction>> {
            self.begins += 1;
            Box::pin(async { Ok(()) })
        }

        fn commit<'a>(
            &'a mut self,
            _transaction: Self::Transaction,
        ) -> BoxFuture<'a, SqlResult<()>> {
            self.commits += 1;
            let block = self.block_commit;
            let commit_error = self.commit_error.clone();
            Box::pin(async move {
                if block {
                    futures::future::pending().await
                } else if let Some(error) = commit_error {
                    Err(error)
                } else {
                    Ok(())
                }
            })
        }

        fn rollback<'a>(
            &'a mut self,
            _transaction: Self::Transaction,
        ) -> BoxFuture<'a, Result<()>> {
            self.rollbacks += 1;
            let rollback_error = self.rollback_error;
            Box::pin(async move {
                if rollback_error {
                    Err(Error::engine("rollback driver detail"))
                } else {
                    Ok(())
                }
            })
        }

        fn prove_interrupted_commit<'a>(&'a mut self) -> BoxFuture<'a, Result<bool>> {
            let proved = self.prove_commit;
            Box::pin(async move { Ok(proved) })
        }
    }

    #[tokio::test]
    async fn validation_and_authorization_failures_roll_back_without_commit() {
        let mut port = FakePort {
            rollback_error: true,
            ..FakePort::default()
        };
        let error =
            run_backend_transaction(&mut port, &ExecutionControl::default(), &mut (), |_, _| {
                Box::pin(async { Err::<(), _>(Error::engine("authorization denied")) })
            })
            .await
            .unwrap_err();
        match error {
            TransactionLifecycleError::Domain(error) => {
                assert_eq!(error.to_string(), "authorization denied");
            }
            other => panic!("expected primary domain error, got {other:?}"),
        }
        assert_eq!((port.begins, port.commits, port.rollbacks), (1, 0, 1));
    }

    #[tokio::test]
    async fn successful_rollback_disposition_returns_value_without_commit() {
        let mut port = FakePort::default();
        let value = run_backend_transaction_with_disposition(
            &mut port,
            &ExecutionControl::default(),
            &mut (),
            |_, _| Box::pin(async { Ok(TransactionDisposition::Rollback("idempotent")) }),
        )
        .await
        .unwrap();
        assert_eq!(value, "idempotent");
        assert_eq!((port.begins, port.commits, port.rollbacks), (1, 0, 1));
    }

    #[tokio::test]
    async fn successful_commit_disposition_commits_once() {
        let mut port = FakePort::default();
        let value = run_backend_transaction_with_disposition(
            &mut port,
            &ExecutionControl::default(),
            &mut (),
            |_, _| Box::pin(async { Ok(TransactionDisposition::Commit("created")) }),
        )
        .await
        .unwrap();
        assert_eq!(value, "created");
        assert_eq!((port.begins, port.commits, port.rollbacks), (1, 1, 0));
    }

    #[tokio::test]
    async fn commit_driver_errors_have_one_stable_cross_engine_message() {
        for backend in [
            crate::portable_sql::Backend::Sqlite,
            crate::portable_sql::Backend::Postgres,
        ] {
            let driver_error = sqlx::Error::Protocol(format!("{backend:?} driver detail"));
            let mut port = FakePort {
                commit_error: Some(crate::portable_sql::normalize_sqlx_error(
                    backend,
                    ExecutionPhase::Commit,
                    &driver_error,
                )),
                ..FakePort::default()
            };
            let error = run_backend_transaction(
                &mut port,
                &ExecutionControl::default(),
                &mut (),
                |_, _| Box::pin(async { Ok::<_, Error>("done") }),
            )
            .await
            .unwrap_err();

            let stable = error.stable("commit attachment").to_string();
            assert_eq!(stable, "commit attachment: storage operation failed");
            assert!(!stable.contains("driver"));
            assert_eq!((port.begins, port.commits, port.rollbacks), (1, 1, 0));
        }
    }

    #[tokio::test]
    async fn statement_cancellation_poison_rolls_back_and_never_commits() {
        let mut port = FakePort::default();
        let control = ExecutionControl::default();
        let canceller = control.clone();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::clone(&entered);
        let cancel = tokio::spawn(async move {
            release.notified().await;
            canceller.cancel();
        });
        let error = run_backend_transaction(&mut port, &control, &mut (), |_, _| {
            let entered = Arc::clone(&entered);
            Box::pin(async move {
                entered.notify_one();
                futures::future::pending::<Result<()>>().await
            })
        })
        .await
        .unwrap_err();
        cancel.await.unwrap();
        assert!(matches!(
            error,
            TransactionLifecycleError::Control(SqlError {
                category: crate::portable_sql::ErrorCategory::Cancelled,
                phase: ExecutionPhase::Statement,
                ..
            })
        ));
        assert_eq!((port.begins, port.commits, port.rollbacks), (1, 0, 1));
    }

    #[tokio::test]
    async fn commit_deadline_is_outcome_unknown_unless_backend_proves_durability() {
        for proved in [false, true] {
            let mut port = FakePort {
                prove_commit: proved,
                block_commit: true,
                ..FakePort::default()
            };
            let control = ExecutionControl::with_timeout(Duration::from_millis(10));
            let result = run_backend_transaction(&mut port, &control, &mut (), |_, _| {
                Box::pin(async { Ok::<_, Error>("done") })
            })
            .await;
            if proved {
                assert_eq!(result.unwrap(), "done");
            } else {
                assert!(matches!(
                    result.unwrap_err(),
                    TransactionLifecycleError::Control(SqlError {
                        category: crate::portable_sql::ErrorCategory::OutcomeUnknown,
                        phase: ExecutionPhase::Commit,
                        ..
                    })
                ));
            }
            assert_eq!((port.begins, port.commits, port.rollbacks), (1, 1, 0));
        }
    }

    #[tokio::test]
    async fn guarded_handler_is_never_replayed() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut port = FakePort::default();
        let mut context = Arc::clone(&calls);
        run_backend_transaction(
            &mut port,
            &ExecutionControl::default(),
            &mut context,
            |_, calls| {
                let calls = Arc::clone(calls);
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, Error>(())
                })
            },
        )
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
