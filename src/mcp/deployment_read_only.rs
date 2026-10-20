//! Persistence admission for fleet and durable per-database read-only transitions.
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

pub const DEPLOYMENT_DRAINING_ERROR: &str = "DEPLOYMENT_DRAINING";

/// Conservative recovery guidance for [`DEPLOYMENT_DRAINING_ERROR`]. The
/// custody write never started, but earlier effects in the same operation may
/// have committed — so unlike a pre-admission freeze refusal, this is never
/// `applied=false` and never blanket-retryable. Restart the operation from
/// its beginning rather than resending the refused request.
pub const DEPLOYMENT_DRAINING_RECOVERY: &str = "Deployment writers are paused for a freeze drain (outcome unknown). The refused write did not start, but earlier effects in this operation may have committed: verify current state before acting rather than resending this request. Never assume the operation was unapplied.";

/// Machine-readable retry interval (seconds) for [`DEPLOYMENT_READ_ONLY_ERROR`].
/// A frozen mutation was refused before execution (`applied=false`), so agents
/// poll conservatively rather than retrying hot. Transports advertise the same
/// value in-band (`retry_after_secs`) and over HTTP (`Retry-After`, via
/// [`DEPLOYMENT_READ_ONLY_RETRY_AFTER_HEADER`]).
pub const DEPLOYMENT_READ_ONLY_RETRY_AFTER_SECS: u64 = 30;

/// Header form of [`DEPLOYMENT_READ_ONLY_RETRY_AFTER_SECS`], kept paired with
/// it so the HTTP `Retry-After` header and the in-band `retry_after_secs`
/// field cannot drift apart. Hosted transports build the header from this
/// rather than their own literal.
pub const DEPLOYMENT_READ_ONLY_RETRY_AFTER_HEADER: &str = "30";

/// Conservative recovery guidance for [`DEPLOYMENT_READ_ONLY_ERROR`]. Shared
/// verbatim across MCP and HTTP so both transports carry the same wording.
pub const DEPLOYMENT_READ_ONLY_RECOVERY: &str = "This write was not applied or queued. Keep its payload and supported idempotency key. Wait at least 30 seconds before retrying, using bounded backoff and a retry budget; maintenance end time is unknown. If the plan expires or its contract changes, follow the returned repair and prepare again. Interpret any later error separately; do not assume its write was unapplied.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationAccess {
    Read,
    Mutation,
}

#[derive(Debug)]
struct Gate {
    lock: Arc<tokio::sync::RwLock<()>>,
    freeze_waiters: AtomicUsize,
    boot_frozen: bool,
    databases: Option<super::database_freeze::DatabaseFreezeStore>,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            lock: Arc::new(tokio::sync::RwLock::new(())),
            freeze_waiters: AtomicUsize::new(0),
            boot_frozen: false,
            databases: None,
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

type DatabaseLease = (String, Arc<super::database_freeze::DatabaseWriteLease>);

/// Persistence authority retained for the complete ordinary request.
#[derive(Clone, Debug)]
pub struct DeploymentPersistenceLease {
    _lease: Arc<PersistenceLease>,
    database: Option<DatabaseLease>,
}

#[derive(Debug)]
struct PersistenceLease {
    _guard: tokio::sync::OwnedRwLockReadGuard<()>,
    _gate: Arc<Gate>,
}

tokio::task_local! { static DATABASE_SCOPE: String; }

/// Scope server-selected database routing through pre-auth and nested dispatch.
/// Spawned work must explicitly carry scope or the already admitted lease.
pub async fn scope_database_persistence<F: std::future::Future>(
    id: String,
    future: F,
) -> F::Output {
    DATABASE_SCOPE.scope(id, future).await
}

tokio::task_local! { static JOB_PERSISTENCE_LEASE: Option<DeploymentPersistenceLease>; }
pub(crate) fn current_job_lease() -> Option<DeploymentPersistenceLease> {
    JOB_PERSISTENCE_LEASE.try_with(Clone::clone).ok().flatten()
}
/// Retain already admitted deployment authority across an owned execution
/// handoff. This scopes an existing unforgeable lease; it admits no new work.
#[doc(hidden)]
pub async fn scope_deployment_persistence<F: std::future::Future>(
    lease: Option<DeploymentPersistenceLease>,
    future: F,
) -> F::Output {
    JOB_PERSISTENCE_LEASE
        .scope(lease.or_else(current_job_lease), future)
        .await
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
pub struct DeploymentMutationBarrier(Arc<Gate>, DatabaseScope);

#[derive(Clone, Debug, Default)]
enum DatabaseScope {
    #[default]
    Ambient,
    Fleet,
    Database(String),
}

impl DeploymentMutationBarrier {
    /// A read-only serving process cannot thaw when a release lease expires.
    pub fn boot_frozen() -> Self {
        Self(
            Arc::new(Gate {
                boot_frozen: true,
                ..Gate::default()
            }),
            DatabaseScope::Ambient,
        )
    }

    /// Install the durable hosted database fence on a fresh barrier.
    pub fn with_database_freezes(self, data_dir: &std::path::Path) -> Self {
        Self(
            Arc::new(Gate {
                databases: Some(super::database_freeze::DatabaseFreezeStore::new(data_dir)),
                boot_frozen: self.0.boot_frozen,
                ..Gate::default()
            }),
            DatabaseScope::Ambient,
        )
    }

    pub fn for_database(&self, id: &str) -> Self {
        Self(self.0.clone(), DatabaseScope::Database(id.to_owned()))
    }

    /// Global admission only, for background work that separately retains
    /// its database fence (for example acknowledged dirty coedit text).
    pub fn for_fleet(&self) -> Self {
        Self(self.0.clone(), DatabaseScope::Fleet)
    }

    fn database_id(&self) -> Option<String> {
        match &self.1 {
            DatabaseScope::Ambient => DATABASE_SCOPE.try_with(Clone::clone).ok(),
            DatabaseScope::Fleet => None,
            DatabaseScope::Database(id) => Some(id.clone()),
        }
    }

    /// Bind a database known to the hosted catalog or verified caller. This
    /// must not be called for an unauthenticated URL parameter alone.
    pub fn register_database(&self, id: &str) -> Result<()> {
        if let Some(store) = &self.0.databases {
            if !store.is_registered(id)? {
                store.register(id)?;
            }
        }
        Ok(())
    }

    fn database_lease(&self) -> Result<Option<DatabaseLease>> {
        match (&self.0.databases, self.database_id()) {
            (Some(store), Some(id)) => {
                if matches!(self.1, DatabaseScope::Ambient) && !store.is_registered(&id)? {
                    return Ok(None); // Unknown pre-auth URLs allocate no files.
                }
                match store.admit(&id)? {
                    Some(lease) => Ok(Some((id, Arc::new(lease)))),
                    None => Err(Error::deployment_read_only(
                        DeploymentReadOnlyOperation::server("database_freeze"),
                    )),
                }
            }
            _ => Ok(None),
        }
    }

    /// Admit an operation without waiting behind a pending freeze.
    pub fn admit(
        &self,
        operation: &DeploymentReadOnlyOperation,
        access: OperationAccess,
    ) -> Result<DeploymentAdmission> {
        if self.0.boot_frozen || self.0.freeze_waiters.load(Ordering::SeqCst) > 0 {
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
        let database = match self.database_lease() {
            Ok(lease) => lease,
            Err(Error::DeploymentReadOnly(_)) => return self.read_only_result(operation, access),
            Err(_) if access == OperationAccess::Read => {
                return Ok(DeploymentAdmission::FrozenRead)
            }
            Err(error) => return Err(error),
        };
        Ok(DeploymentAdmission::Writable(DeploymentPersistenceLease {
            database,
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
    pub fn reuse(&self, lease: &DeploymentPersistenceLease) -> Result<DeploymentAdmission> {
        if !Arc::ptr_eq(&self.0, &lease._lease._gate) {
            return Err(Error::engine(
                "deployment persistence lease belongs to another mutation barrier",
            ));
        }
        if let Some(id) = self.database_id() {
            if let Some((held, _)) = &lease.database {
                if held != &id {
                    return Err(Error::engine(
                        "deployment persistence lease belongs to another database",
                    ));
                }
            } else if self.0.databases.is_some() {
                let mut scoped = lease.clone();
                scoped.database = self.database_lease()?;
                return Ok(DeploymentAdmission::Writable(scoped));
            }
        }
        Ok(DeploymentAdmission::Writable(lease.clone()))
    }

    /// A fleet/lens lease has no authority for a newly selected database.
    /// Enroll that scope, preserving frozen reads without minting authority.
    pub fn reuse_for_operation(
        &self,
        lease: &DeploymentPersistenceLease,
        operation: &DeploymentReadOnlyOperation,
        access: OperationAccess,
    ) -> Result<DeploymentAdmission> {
        match self.reuse(lease) {
            Err(Error::DeploymentReadOnly(_)) => self.read_only_result(operation, access),
            // Binding a fleet lease can encounter the same filesystem failure
            // as fresh admission. Reads must suppress persistence in both cases.
            // Scope mismatches are Engine errors checked before filesystem I/O.
            Err(Error::Io(_)) if access == OperationAccess::Read => {
                Ok(DeploymentAdmission::FrozenRead)
            }
            result => result,
        }
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

    pub fn is_database_read_only(&self) -> bool {
        self.database_id().is_some_and(|id| {
            self.0
                .databases
                .as_ref()
                .is_some_and(|store| store.is_frozen(&id).unwrap_or(true))
        })
    }

    /// Instantaneous state used only for early refusal and observability.
    /// Correct dispatch still relies on [`Self::admit`] and its retained lease.
    pub fn is_read_only(&self) -> bool {
        self.is_database_read_only()
            || self.0.boot_frozen
            || self.0.freeze_waiters.load(Ordering::SeqCst) > 0
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
    async fn boot_frozen_never_thaws_when_a_freeze_lease_drops() {
        let barrier = DeploymentMutationBarrier::boot_frozen();
        assert!(barrier.is_read_only());
        drop(barrier.freeze().await);
        assert!(matches!(
            barrier
                .admit(&operation("get_record"), OperationAccess::Read)
                .unwrap(),
            DeploymentAdmission::FrozenRead
        ));
        assert_eq!(
            barrier
                .admit(&operation("create_record"), OperationAccess::Mutation)
                .unwrap_err()
                .deployment_read_only_operation(),
            Some("create_record")
        );
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
