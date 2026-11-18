//! One dispatched local read operation sees ONE state of a copy that may be
//! advanced in place underneath it.
//!
//! Composed readers (scoped search selects scope ids, searches, then hydrates
//! placement) take several pool connections, each its own SQLite snapshot. The
//! pools hand connections to readers that cannot share one sqlx transaction,
//! so rather than rewriting every reader this guard validates the whole
//! operation at its single choke point (session dispatch): the copy's version
//! stamp is read before and after, and a result is returned only if BOTH
//! stamps were read successfully and are equal. Every in-place commit advances
//! the stamp (it moves the apply-receipt ordinal in the same transaction),
//! reads have no side effects, and a moved stamp simply re-runs the operation.
//! A stamp that cannot be read is never treated as "unchanged".
use crate::{Db, Error, Result};
use std::future::Future;

/// How often an operation is re-run when the copy moves underneath it.
pub(crate) const STABLE_READ_ATTEMPTS: usize = 3;

const RECEIPTS_TABLE: &str = "kernel_standby_apply_receipts";

/// Why a result could not be vouched for. Callers must not serve either.
#[derive(Debug)]
pub(crate) enum StableReadError<T> {
    /// The copy moved on every attempt; the last result is a mixture risk.
    Moved(T),
    /// A stamp could not be read (pool starvation, I/O, a closed pool): the
    /// result cannot be proved single-state. Retryable.
    Unstamped(Error),
}

/// `(head act, last apply-receipt ordinal)`. The receipts table is absent
/// exactly when the copy has never been advanced in place, which stamps as
/// ordinal -1; every other failure is an error.
pub(crate) async fn version_stamp(db: &Db) -> Result<(i64, i64)> {
    let mut tx = db.pool().begin().await?;
    let result = async {
        let act: i64 = sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton=1")
            .fetch_one(&mut *tx)
            .await?;
        let initialised: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?)",
        )
        .bind(RECEIPTS_TABLE)
        .fetch_one(&mut *tx)
        .await?;
        let ordinal: i64 = if initialised {
            sqlx::query_scalar(&format!(
                "SELECT COALESCE(MAX(ordinal),-1) FROM {RECEIPTS_TABLE}"
            ))
            .fetch_one(&mut *tx)
            .await?
        } else {
            -1
        };
        Ok::<_, Error>((act, ordinal))
    }
    .await;
    let _ = tx.rollback().await;
    result
}

/// Run `operation` until the copy did not move during it.
pub(crate) async fn stable<T, F, Fut>(
    db: &Db,
    mut operation: F,
) -> std::result::Result<T, StableReadError<T>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = T>,
{
    let mut last = None;
    for _ in 0..STABLE_READ_ATTEMPTS {
        let before = version_stamp(db)
            .await
            .map_err(StableReadError::Unstamped)?;
        let result = operation().await;
        let after = match version_stamp(db).await {
            Ok(after) => after,
            Err(error) => return Err(StableReadError::Unstamped(error)),
        };
        if after == before {
            return Ok(result);
        }
        last = Some(result);
    }
    Err(StableReadError::Moved(last.expect("at least one attempt")))
}
