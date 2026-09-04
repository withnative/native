//! Process-scoped persistence admission for deployment read-only transitions.
//!
//! Ordinary tool reads participate because their request lifecycle and capture
//! can persist metadata. Once freeze intent is registered, late reads switch
//! to a suppressed lifecycle while mutations fail closed. Tokio's fair
//! read/write lock drains leases admitted before the transition without
//! allowing later persistence work to barge ahead.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::{DeploymentReadOnlyOperation, Error, Result};

pub const DEPLOYMENT_READ_ONLY_ERROR: &str = "DEPLOYMENT_READ_ONLY";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationAccess {
    Read,
    Mutation,
}

#[derive(Debug)]
struct Gate {
    lock: Arc<tokio::sync::RwLock<()>>,
    freeze_waiters: AtomicUsize,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            lock: Arc::new(tokio::sync::RwLock::new(())),
            freeze_waiters: AtomicUsize::new(0),
        }
    }
}

#[derive(Debug)]
struct FreezeWaiter(Arc<Gate>);

impl Drop for FreezeWaiter {
    fn drop(&mut self) {
        self.0.freeze_waiters.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Persistence authority retained for the complete ordinary request.
#[derive(Clone, Debug)]
pub struct DeploymentPersistenceLease {
    _lease: Arc<PersistenceLease>,
}

#[derive(Debug)]
struct PersistenceLease {
    _guard: tokio::sync::OwnedRwLockReadGuard<()>,
    _gate: Arc<Gate>,
}

/// Exclusive process freeze. Dropping this internal authority reopens writes.
#[derive(Debug)]
pub struct DeploymentFreezeLease {
    _guard: tokio::sync::OwnedRwLockWriteGuard<()>,
    _gate: Arc<Gate>,
}

/// Result of classifying and admitting one registered operation.
#[derive(Debug)]
#[must_use = "dropping the admission releases its persistence lease"]
pub enum DeploymentAdmission {
    Writable(DeploymentPersistenceLease),
    FrozenRead,
}

/// One process's fair deployment mutation boundary.
#[derive(Clone, Debug, Default)]
pub struct DeploymentMutationBarrier(Arc<Gate>);

impl DeploymentMutationBarrier {
    /// Admit an operation without waiting behind a pending freeze.
    pub fn admit(
        &self,
        operation: &DeploymentReadOnlyOperation,
        access: OperationAccess,
    ) -> Result<DeploymentAdmission> {
        if self.0.freeze_waiters.load(Ordering::SeqCst) > 0 {
            return self.read_only_result(operation, access);
        }
        let guard = match self.0.lock.clone().try_read_owned() {
            Ok(guard) => guard,
            Err(_) => return self.read_only_result(operation, access),
        };
        // A freeze registered between the first check and acquisition wins.
        if self.0.freeze_waiters.load(Ordering::SeqCst) > 0 {
            drop(guard);
            return self.read_only_result(operation, access);
        }
        Ok(DeploymentAdmission::Writable(DeploymentPersistenceLease {
            _lease: Arc::new(PersistenceLease {
                _guard: guard,
                _gate: Arc::clone(&self.0),
            }),
        }))
    }

    /// Reuse authority already admitted by this exact process barrier.
    ///
    /// This is the nested-dispatch seam for an executor operation whose
    /// outer request crossed the cut before freeze intent was registered. The
    /// pointer check prevents a lease from another barrier being treated as
    /// authority here; no caller-controlled value can construct a lease.
    pub(crate) fn reuse(&self, lease: &DeploymentPersistenceLease) -> Result<DeploymentAdmission> {
        if !Arc::ptr_eq(&self.0, &lease._lease._gate) {
            return Err(Error::engine(
                "deployment persistence lease belongs to another mutation barrier",
            ));
        }
        Ok(DeploymentAdmission::Writable(lease.clone()))
    }

    fn read_only_result(
        &self,
        operation: &DeploymentReadOnlyOperation,
        access: OperationAccess,
    ) -> Result<DeploymentAdmission> {
        match access {
            OperationAccess::Read => Ok(DeploymentAdmission::FrozenRead),
            OperationAccess::Mutation => Err(Error::deployment_read_only(operation.clone())),
        }
    }

    /// Register freeze intent before waiting for all admitted persistence work.
    #[doc(hidden)]
    pub async fn freeze(&self) -> DeploymentFreezeLease {
        self.0.freeze_waiters.fetch_add(1, Ordering::SeqCst);
        let waiter = FreezeWaiter(Arc::clone(&self.0));
        let guard = self.0.lock.clone().write_owned().await;
        drop(waiter);
        DeploymentFreezeLease {
            _guard: guard,
            _gate: Arc::clone(&self.0),
        }
    }

    /// Instantaneous state used only for early refusal and observability.
    /// Correct dispatch still relies on [`Self::admit`] and its retained lease.
    pub fn is_read_only(&self) -> bool {
        self.0.freeze_waiters.load(Ordering::SeqCst) > 0
            || self.0.lock.clone().try_read_owned().is_err()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn operation(name: &'static str) -> DeploymentReadOnlyOperation {
        DeploymentReadOnlyOperation::server(name)
    }

    async fn wait_for_freeze(barrier: &DeploymentMutationBarrier) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !barrier.is_read_only() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("freeze intent was not registered");
    }

    #[tokio::test]
    async fn freeze_closes_admission_then_drains_existing_persistence() {
        let barrier = DeploymentMutationBarrier::default();
        let first = match barrier
            .admit(&operation("get_record"), OperationAccess::Read)
            .unwrap()
        {
            DeploymentAdmission::Writable(lease) => lease,
            DeploymentAdmission::FrozenRead => panic!("open barrier suppressed a read"),
        };
        let contender = barrier.clone();
        let freeze = tokio::spawn(async move { contender.freeze().await });
        wait_for_freeze(&barrier).await;

        assert!(matches!(
            barrier
                .admit(&operation("get_record"), OperationAccess::Read)
                .unwrap(),
            DeploymentAdmission::FrozenRead
        ));
        let error = barrier
            .admit(&operation("create_record"), OperationAccess::Mutation)
            .unwrap_err();
        assert_eq!(
            error.deployment_read_only_operation(),
            Some("create_record")
        );
        assert!(
            !freeze.is_finished(),
            "freeze did not drain the first lease"
        );

        drop(first);
        let frozen = tokio::time::timeout(Duration::from_secs(2), freeze)
            .await
            .expect("freeze did not acquire after drain")
            .unwrap();
        assert!(matches!(
            barrier
                .admit(&operation("ping"), OperationAccess::Read)
                .unwrap(),
            DeploymentAdmission::FrozenRead
        ));
        drop(frozen);
        assert!(matches!(
            barrier
                .admit(&operation("create_record"), OperationAccess::Mutation)
                .unwrap(),
            DeploymentAdmission::Writable(_)
        ));
    }

    #[tokio::test]
    async fn cancelling_a_queued_freeze_repairs_admission() {
        let barrier = DeploymentMutationBarrier::default();
        let first = barrier
            .admit(&operation("get_record"), OperationAccess::Read)
            .unwrap();
        let contender = barrier.clone();
        let freeze = tokio::spawn(async move { contender.freeze().await });
        wait_for_freeze(&barrier).await;
        freeze.abort();
        let _ = freeze.await;

        assert!(matches!(
            barrier
                .admit(&operation("create_record"), OperationAccess::Mutation)
                .unwrap(),
            DeploymentAdmission::Writable(_)
        ));
        drop(first);
    }

    #[tokio::test]
    async fn nested_admission_rejects_a_lease_from_another_barrier() {
        let source = DeploymentMutationBarrier::default();
        let foreign = DeploymentMutationBarrier::default();
        let lease = match source
            .admit(&operation("create_record"), OperationAccess::Mutation)
            .unwrap()
        {
            DeploymentAdmission::Writable(lease) => lease,
            DeploymentAdmission::FrozenRead => panic!("open barrier suppressed a mutation"),
        };

        let error = foreign.reuse(&lease).unwrap_err();
        assert!(error
            .to_string()
            .contains("lease belongs to another mutation barrier"));
        assert!(matches!(
            source.reuse(&lease).unwrap(),
            DeploymentAdmission::Writable(_)
        ));
    }
}
