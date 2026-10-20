//! Durable, cross-process database freeze fence. Lock inodes are never removed.
//! Intent is fsynced before waiting for admitted writers; dropping the operator
//! or restarting the server cannot reopen admission. Only explicit thaw does.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

use crate::{Error, Result};

#[derive(Clone, Debug)]
pub struct DatabaseFreezeStore(PathBuf, Arc<CachedFences>);

#[derive(Debug, Default)]
struct CachedFences {
    writers: Mutex<BTreeMap<String, Arc<File>>>,
    watcher: OnceLock<()>,
}

impl CachedFences {
    fn writers(&self) -> MutexGuard<'_, BTreeMap<String, Arc<File>>> {
        self.writers.lock().unwrap_or_else(|poisoned| {
            let mut writers = poisoned.into_inner();
            // This map owns only idle cache references, never request authority.
            // Discarding them is safe: active requests retain their own leases.
            // Recover here for every caller so poison cannot kill the observer
            // or strand an external freeze behind idle cached shared locks.
            writers.clear();
            self.writers.clear_poison();
            writers
        })
    }
}

#[derive(Debug)]
pub struct DatabaseWriteLease {
    _file: Arc<File>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseFreezeStatus {
    Writable,
    Draining,
    Frozen,
}

impl DatabaseFreezeStore {
    pub fn new(data_dir: &Path) -> Self {
        static STORES: OnceLock<Mutex<BTreeMap<PathBuf, Weak<CachedFences>>>> = OnceLock::new();
        let path = data_dir.join("database-freezes");
        let mut stores = STORES
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stores.retain(|_, store| store.strong_count() > 0);
        let shared = stores
            .get(&path)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let shared = Arc::new(CachedFences::default());
                stores.insert(path.clone(), Arc::downgrade(&shared));
                shared
            });
        Self(path, shared)
    }

    // Cached shared locks make ordinary admission one marker stat plus an
    // Arc clone. A single observer per serving directory releases idle cached
    // fences after external freeze intent appears. Active requests retain their
    // own Arc, so the operator still drains the real in-flight work. The
    // observer only reads; it cannot clear intent or grant admission.
    fn observe_intent(&self) {
        self.1.watcher.get_or_init(|| {
            let weak = Arc::downgrade(&self.1);
            let path = self.0.clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_millis(100));
                let Some(shared) = weak.upgrade() else { break };
                let frozen = std::fs::read_dir(&path).and_then(|entries| {
                    entries
                        .map(|entry| {
                            let name = entry?.file_name();
                            Ok(name
                                .to_str()
                                .and_then(|name| name.strip_suffix(".frozen"))
                                .map(str::to_owned))
                        })
                        .collect::<std::io::Result<Vec<_>>>()
                });
                let mut writers = shared.writers();
                match frozen {
                    Ok(ids) => {
                        let ids: BTreeSet<_> = ids.into_iter().flatten().collect();
                        writers.retain(|id, _| !ids.contains(id));
                    }
                    Err(_) => writers.clear(),
                }
            });
        });
    }

    fn path(&self, id: &str, suffix: &str) -> Result<PathBuf> {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::engine("invalid database freeze id"));
        }
        Ok(self.0.join(format!("{id}.{suffix}")))
    }

    fn lock(&self, id: &str, suffix: &str) -> Result<File> {
        let path = self.path(id, suffix)?;
        if !self.0.is_dir() {
            std::fs::create_dir_all(&self.0)?;
            if let Some(parent) = self.0.parent() {
                File::open(parent)?.sync_all()?;
            }
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        Ok(options.open(path)?)
    }

    /// Register only a catalog-confirmed ID. Pre-auth URL parameters must
    /// never allocate a new file without that confirmation.
    pub fn register(&self, id: &str) -> Result<()> {
        let _file = self.lock(id, "writers")?;
        Ok(())
    }

    pub fn is_registered(&self, id: &str) -> Result<bool> {
        if self.1.writers().contains_key(id) {
            return Ok(true);
        }
        let Ok(path) = self.path(id, "writers") else {
            return Ok(false);
        };
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => Ok(metadata.is_file() && !metadata.file_type().is_symlink()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub fn is_frozen(&self, id: &str) -> Result<bool> {
        let Ok(path) = self.path(id, "frozen") else {
            // Invalid route IDs are handled by catalog/route validation, not
            // represented as a deployment freeze. Explicit admission still
            // rejects them when opening the writer fence.
            return Ok(false);
        };
        match std::fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Nonblocking admission, with a second intent check under the shared
    /// fence. None means frozen; filesystem errors fail closed separately.
    pub fn admit(&self, id: &str) -> Result<Option<DatabaseWriteLease>> {
        if self.is_frozen(id)? {
            return Ok(None);
        }
        self.observe_intent();
        let mut writers = self.1.writers();
        if let Some(file) = writers.get(id) {
            return Ok(Some(DatabaseWriteLease {
                _file: file.clone(),
            }));
        }
        let file = self.lock(id, "writers")?;
        match fs2::FileExt::try_lock_shared(&file) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        if self.is_frozen(id)? {
            return Ok(None);
        }
        let file = Arc::new(file);
        // Bound idle descriptors independently of the router's database LRU.
        // Eviction drops only the cached reference, never an active lease.
        if writers.len() >= 256 {
            let _ = writers.pop_first();
        }
        writers.insert(id.to_owned(), file.clone());
        Ok(Some(DatabaseWriteLease { _file: file }))
    }

    pub fn admit_mutation(&self, id: &str, operation: &'static str) -> Result<DatabaseWriteLease> {
        self.admit(id)?.ok_or_else(|| {
            Error::deployment_read_only(crate::DeploymentReadOnlyOperation::server(operation))
        })
    }

    /// Persist intent then drain all processes' leases. Cancellation leaves
    /// intent armed. A repeated freeze finishes any interrupted drain.
    pub async fn freeze(&self, id: &str) -> Result<DatabaseFreezeStatus> {
        let control = self.lock(id, "control")?;
        fs2::FileExt::try_lock_exclusive(&control)
            .map_err(|e| Error::engine(format!("database freeze operation already active: {e}")))?;
        // Ambient admission must discover the fence before intent is visible.
        let writers = self.lock(id, "writers")?;
        let intent = self.path(id, "frozen")?;
        if !self.is_frozen(id)? {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(intent)?;
            file.write_all(b"database-freeze-v1\n")?;
            file.sync_all()?;
            File::open(&self.0)?.sync_all()?;
        }
        self.1.writers().remove(id);
        loop {
            match fs2::FileExt::try_lock_exclusive(&writers) {
                Ok(()) => break,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(DatabaseFreezeStatus::Frozen)
    }

    pub fn unfreeze(&self, id: &str) -> Result<DatabaseFreezeStatus> {
        let control = self.lock(id, "control")?;
        fs2::FileExt::try_lock_exclusive(&control)
            .map_err(|e| Error::engine(format!("database freeze operation already active: {e}")))?;
        if !self.is_frozen(id)? {
            return Ok(DatabaseFreezeStatus::Writable);
        }
        self.1.writers().remove(id);
        let writers = self.lock(id, "writers")?;
        fs2::FileExt::try_lock_exclusive(&writers)
            .map_err(|e| Error::engine(format!("database writers have not drained: {e}")))?;
        match std::fs::remove_file(self.path(id, "frozen")?) {
            Ok(()) => File::open(&self.0)?.sync_all()?,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(DatabaseFreezeStatus::Writable)
    }

    /// Observation creates no files (including for operator dry-run).
    pub fn status(&self, id: &str) -> Result<DatabaseFreezeStatus> {
        if !self.is_frozen(id)? {
            return Ok(DatabaseFreezeStatus::Writable);
        }
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.path(id, "writers")?)
        {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(DatabaseFreezeStatus::Frozen),
            Err(e) => return Err(e.into()),
        };
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(DatabaseFreezeStatus::Frozen),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(DatabaseFreezeStatus::Draining),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::{DeploymentAdmission, DeploymentMutationBarrier, OperationAccess};
    use crate::DeploymentReadOnlyOperation;

    #[tokio::test]
    async fn cached_database_fences_release_idle_locks_on_external_intent_but_drain_active_work() {
        let dir = tempfile::tempdir().unwrap();
        let store = DatabaseFreezeStore::new(dir.path());
        let first = store.admit("db-a").unwrap().unwrap();
        let held = Arc::downgrade(&first._file);
        drop(first);
        let active = store.admit("db-a").unwrap().unwrap();
        assert!(Arc::ptr_eq(&held.upgrade().unwrap(), &active._file));
        // Simulate an operator in a separate process: it cannot clear this
        // process's cache. The observer must relinquish only its idle copy.
        let fence = store.lock("db-a", "writers").unwrap();
        std::fs::write(
            store.path("db-a", "frozen").unwrap(),
            b"database-freeze-v1\n",
        )
        .unwrap();
        assert!(store.admit("db-a").unwrap().is_none());
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while Arc::strong_count(&active._file) != 1 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(fs2::FileExt::try_lock_exclusive(&fence).is_err());
        drop(active);
        fs2::FileExt::try_lock_exclusive(&fence).unwrap();
    }

    #[tokio::test]
    async fn database_freeze_observer_recovers_poison_and_releases_idle_fences() {
        let dir = tempfile::tempdir().unwrap();
        let store = DatabaseFreezeStore::new(dir.path());
        let active = store.admit("db-a").unwrap().unwrap();
        let shared = store.1.clone();
        assert!(std::thread::spawn(move || {
            let _guard = shared.writers.lock().unwrap();
            panic!("simulate a cache owner panicking");
        })
        .join()
        .is_err());
        let fence = store.lock("db-a", "writers").unwrap();
        std::fs::write(
            store.path("db-a", "frozen").unwrap(),
            b"database-freeze-v1\n",
        )
        .unwrap();
        // Do not call the store again: only the observer can recover the cache.
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while Arc::strong_count(&active._file) != 1 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(!store.1.writers.is_poisoned());
        assert!(fs2::FileExt::try_lock_exclusive(&fence).is_err());
        drop(active);
        fs2::FileExt::try_lock_exclusive(&fence).unwrap();
        fs2::FileExt::unlock(&fence).unwrap();
        assert_eq!(store.status("db-a").unwrap(), DatabaseFreezeStatus::Frozen);
        store.unfreeze("db-a").unwrap();
        assert!(store.admit("db-a").unwrap().is_some());
    }

    #[tokio::test]
    async fn unknown_pre_auth_database_scopes_do_not_allocate_files() {
        let dir = tempfile::tempdir().unwrap();
        let store = DatabaseFreezeStore::new(dir.path());
        let barrier = DeploymentMutationBarrier::default().with_database_freezes(dir.path());
        let operation = DeploymentReadOnlyOperation::server("create_record");
        for id in ["unknown-a", "unknown-b", "../unsafe"] {
            let admission = crate::mcp::scope_database_persistence(id.to_owned(), async {
                barrier.admit(&operation, OperationAccess::Mutation)
            })
            .await
            .unwrap();
            drop(admission);
        }
        assert!(!barrier.for_database("../unsafe").is_database_read_only());
        assert!(barrier
            .for_database("../unsafe")
            .admit(&operation, OperationAccess::Mutation)
            .unwrap_err()
            .deployment_read_only_operation()
            .is_none());
        assert!(!dir.path().join("database-freezes").exists());
        barrier.register_database("known").unwrap();
        store.freeze("known").await.unwrap();
        let refusal = crate::mcp::scope_database_persistence("known".to_owned(), async {
            barrier.admit(&operation, OperationAccess::Mutation)
        })
        .await
        .unwrap_err();
        assert_eq!(
            refusal.deployment_read_only_operation(),
            Some("create_record")
        );
    }

    #[tokio::test]
    async fn database_freeze_drains_isolated_leases_and_survives_restart_until_unfreeze() {
        let dir = tempfile::tempdir().unwrap();
        let store = DatabaseFreezeStore::new(dir.path());
        let barrier = DeploymentMutationBarrier::default().with_database_freezes(dir.path());
        let a = barrier.for_database("db-a");
        let b = barrier.for_database("db-b");
        let operation = DeploymentReadOnlyOperation::server("create_record");
        let lease = a.admit(&operation, OperationAccess::Mutation).unwrap();
        let worker = store.clone();
        let freeze = tokio::spawn(async move { worker.freeze("db-a").await.unwrap() });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !store.is_frozen("db-a").unwrap() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            store.status("db-a").unwrap(),
            DatabaseFreezeStatus::Draining
        );
        assert!(!freeze.is_finished());
        assert_eq!(
            a.admit(&operation, OperationAccess::Mutation)
                .unwrap_err()
                .deployment_read_only_operation(),
            Some("create_record")
        );
        assert!(matches!(
            a.admit(&operation, OperationAccess::Read).unwrap(),
            DeploymentAdmission::FrozenRead
        ));
        assert!(matches!(
            b.admit(&operation, OperationAccess::Mutation).unwrap(),
            DeploymentAdmission::Writable(_)
        ));
        // Work admitted before intent retains authority, including nested dispatch.
        if let DeploymentAdmission::Writable(held) = &lease {
            let _nested = a.reuse(held).unwrap();
        }
        drop(lease);
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), freeze)
                .await
                .unwrap()
                .unwrap(),
            DatabaseFreezeStatus::Frozen
        );
        let DeploymentAdmission::Writable(global) = barrier
            .for_fleet()
            .admit(&operation, OperationAccess::Read)
            .unwrap()
        else {
            panic!()
        };
        assert!(matches!(
            a.reuse_for_operation(&global, &operation, OperationAccess::Read)
                .unwrap(),
            DeploymentAdmission::FrozenRead
        ));
        assert_eq!(
            a.reuse_for_operation(&global, &operation, OperationAccess::Mutation)
                .unwrap_err()
                .deployment_read_only_operation(),
            Some("create_record")
        );
        let restarted = DeploymentMutationBarrier::default().with_database_freezes(dir.path());
        assert!(restarted
            .for_database("db-a")
            .admit(&operation, OperationAccess::Mutation)
            .is_err());
        assert!(restarted
            .for_database("db-b")
            .admit(&operation, OperationAccess::Mutation)
            .is_ok());
        store.unfreeze("db-a").unwrap();
        assert!(restarted
            .for_database("db-a")
            .admit(&operation, OperationAccess::Mutation)
            .is_ok());
    }

    #[tokio::test]
    async fn cancelled_database_drain_keeps_durable_intent_and_foreign_scope_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = DatabaseFreezeStore::new(dir.path());
        assert_eq!(
            store.status("db-a").unwrap(),
            DatabaseFreezeStatus::Writable
        );
        assert!(
            !dir.path().join("database-freezes").exists(),
            "status/dry-run must not write"
        );
        let barrier = DeploymentMutationBarrier::default().with_database_freezes(dir.path());
        let a = barrier.for_database("db-a");
        let operation = DeploymentReadOnlyOperation::server("write");
        let DeploymentAdmission::Writable(held) =
            a.admit(&operation, OperationAccess::Mutation).unwrap()
        else {
            panic!()
        };
        assert!(barrier.for_database("db-b").reuse(&held).is_err());
        let worker = store.clone();
        let freeze = tokio::spawn(async move { worker.freeze("db-a").await });
        while !store.is_frozen("db-a").unwrap() {
            tokio::task::yield_now().await;
        }
        freeze.abort();
        let _ = freeze.await;
        assert!(a.admit(&operation, OperationAccess::Mutation).is_err());
        drop(held);
        assert_eq!(store.status("db-a").unwrap(), DatabaseFreezeStatus::Frozen);
        store.unfreeze("db-a").unwrap();
    }
}
