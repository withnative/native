//! Transport-neutral binary standby acquisition lifecycle.
//!
//! `start` returns an opaque handle synchronously before capture runs in an
//! independently-owned task; `poll`/`read`/`cancel` bind principal+database on
//! every lookup with one opaque missing response. Ready requires a hosted
//! standby manifest. Timeout cancel cannot abort SQL: expiry only makes the
//! handle unusable while the capture task retains the lease until completion
//! and cleanup, so `drain`/`wait_for_idle` still observe it.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use futures::FutureExt as _;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use uuid::Uuid;

use super::{Export, ExportActivity, ExportCoordinator, FinalizedExport};
use crate::error::Error;

pub const BINARY_MAX_CHUNK_BYTES: usize = 1024 * 1024;
pub(crate) const BINARY_DEFAULT_CAPACITY: usize = 32;
/// Bounds one owner even when failed handles are repeatedly polled or pending
/// captures are cancelled before their database work completes.
pub const BINARY_PER_PRINCIPAL_CAPACITY: usize = 4;
pub(crate) const BINARY_DEFAULT_IDLE_TTL: Duration = Duration::from_secs(5 * 60);
// Large workspaces need time for capture, filtering, verification and hashing.
// Pending expiry only reclaims the handle: the independently-owned SQL capture
// retains its lease until cleanup finishes. Keep a finite deadline without
// discarding a healthy capture after the former one-minute budget. This is a
// bounded acquisition allowance, not a promise of a thirty-minute refresh RPO.
pub(crate) const BINARY_DEFAULT_CAPTURE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Exact engine messages for the synchronous start refusals.
///
/// Frontends map these by equality to stable no-echo codes, so the wire never
/// carries the internal message text.
pub const BINARY_START_BUSY: &str =
    "binary export: an export is already in progress for this account and database; retry after it completes";
pub const BINARY_START_CAPACITY: &str = "binary export: too many retained exports";
pub const BINARY_START_PRINCIPAL_CAPACITY: &str =
    "binary export: too many retained exports for this account";
pub const BINARY_START_DRAINING: &str =
    "binary export: server is shutting down and no longer accepts exports";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BinaryState {
    Pending,
    Ready,
    Failed,
}

/// Stable failure codes for the public status; never echo internals.
///
/// Capture/finalize inputs may contain paths, principals, or database bytes.
/// The facility-level error is dropped after mapping to one of these codes so
/// secrets, paths, and multibyte payloads cannot leak through `poll`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BinaryFailure {
    CaptureFailed,
    FinalizeFailed,
    StandbyContextRequired,
    EmptyExport,
}

impl BinaryFailure {
    pub fn code(self) -> &'static str {
        match self {
            BinaryFailure::CaptureFailed => "capture_failed",
            BinaryFailure::FinalizeFailed => "finalize_failed",
            BinaryFailure::StandbyContextRequired => "standby_context_required",
            BinaryFailure::EmptyExport => "empty_export",
        }
    }
}

#[derive(Clone, Debug)]
pub struct BinaryStatus {
    pub handle: String,
    pub state: BinaryState,
    pub expires_at: tokio::time::Instant,
    pub size_bytes: Option<u64>,
    pub sha256: Option<String>,
    pub manifest: Option<crate::standby_snapshot::StandbySnapshotManifest>,
    pub error_code: Option<BinaryFailure>,
}

#[derive(Debug)]
pub struct BinaryChunk {
    pub handle: String,
    pub offset: u64,
    pub length: usize,
    pub size_bytes: u64,
    pub sha256: String,
    pub manifest: crate::standby_snapshot::StandbySnapshotManifest,
    pub bytes: Vec<u8>,
}

pub(crate) enum BinaryLive {
    Pending {
        principal: String,
        db_key: String,
        capture_deadline: tokio::time::Instant,
    },
    Ready {
        principal: String,
        db_key: String,
        export: Option<Box<Export>>,
        file: Option<tokio::fs::File>,
        sha256: String,
        manifest: Box<crate::standby_snapshot::StandbySnapshotManifest>,
        expires_at: tokio::time::Instant,
        activity: Option<ExportActivity>,
    },
    Failed {
        principal: String,
        db_key: String,
        code: BinaryFailure,
        expires_at: tokio::time::Instant,
    },
    /// Terminal tombstone: unlinked from the registry, no resources.
    ///
    /// Set under the slot lock *before* unlinking so a racing capture
    /// publication observes it and cleans up instead of publishing an
    /// unreachable Ready. Never holds a file, export, or lease.
    Revoked,
}

/// Registry coupling handle lookup with the single resource bound.
///
/// `outstanding` counts live handles plus detached capture tasks that outlived
/// their handle (cancelled/expired/drained while capturing). A permit is taken
/// at start and released only when the last slot reference drops, so capacity
/// bounds capture resources rather than map length. `per_principal` bounds one
/// owner's failed/ready handles and detached work separately from the global
/// capacity, so refreshing failed statuses cannot starve other owners.
pub(crate) struct BinaryRegistry {
    slots: std::collections::HashMap<String, Arc<BinarySlot>>,
    outstanding: Arc<AtomicUsize>,
    per_principal: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
}

enum CapacityRefusal {
    Global,
    Principal,
}

impl BinaryRegistry {
    pub(crate) fn new() -> Self {
        Self {
            slots: std::collections::HashMap::new(),
            outstanding: Arc::new(AtomicUsize::new(0)),
            per_principal: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Reserve one global and one principal permit for the slot's full life.
    fn acquire(&self, principal: &str, capacity: usize) -> Result<Permit, CapacityRefusal> {
        let mut counts = self
            .per_principal
            .lock()
            .expect("binary principal permits poisoned");
        if counts.get(principal).copied().unwrap_or(0) >= BINARY_PER_PRINCIPAL_CAPACITY {
            return Err(CapacityRefusal::Principal);
        }
        let previous = self.outstanding.fetch_add(1, Ordering::SeqCst);
        if previous >= capacity {
            self.outstanding.fetch_sub(1, Ordering::SeqCst);
            return Err(CapacityRefusal::Global);
        }
        *counts.entry(principal.to_owned()).or_default() += 1;
        Ok(Permit {
            outstanding: self.outstanding.clone(),
            per_principal: self.per_principal.clone(),
            principal: principal.to_owned(),
        })
    }
}

/// One binary handle: its live state, expiry signal, and capacity permit.
pub(crate) struct BinarySlot {
    live: tokio::sync::Mutex<BinaryLive>,
    /// Expiry signal: `None` stops the worker; `Some` is the current deadline.
    deadline: tokio::sync::watch::Sender<Option<tokio::time::Instant>>,
    /// Held from start until the last reference drops.
    _permit: Permit,
}

/// RAII capacity permit; releases exactly when the slot is fully dropped.
struct Permit {
    outstanding: Arc<AtomicUsize>,
    per_principal: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
    principal: String,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut counts = self
            .per_principal
            .lock()
            .expect("binary principal permits poisoned");
        let count = counts
            .get_mut(&self.principal)
            .expect("binary principal permit missing");
        *count -= 1;
        if *count == 0 {
            counts.remove(&self.principal);
        }
        drop(counts);
        self.outstanding.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Resources taken out of a Ready slot for cleanup after it is revoked.
struct ReadyResources {
    export: Option<Box<Export>>,
    file: Option<tokio::fs::File>,
    activity: Option<ExportActivity>,
}

/// Outcome of a deadline-driven expiry attempt under the slot lock.
enum ExpiryAction {
    /// The handle is now revoked; the caller cleans these (possibly empty)
    /// resources after releasing the lock.
    Revoked(Option<Box<ReadyResources>>),
    /// A concurrent read/poll refreshed the deadline first; wait again.
    StillLive,
}

impl ReadyResources {
    async fn cleanup(self) {
        drop(self.file);
        if let Some(export) = self.export {
            export.cleanup().await;
        }
        drop(self.activity);
    }
}

fn missing(handle: &str) -> Error {
    Error::engine(format!(
        "binary export {handle} does not exist or has expired"
    ))
}

impl ExportCoordinator {
    /// Register a binary acquisition and spawn its capture; returns immediately.
    pub fn start_binary_export<F, Fut>(
        &self,
        principal: String,
        db_key: String,
        create: F,
    ) -> Result<String, Error>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Export, Error>> + Send + 'static,
    {
        let permit = {
            let registry = self
                .inner
                .binary
                .lock()
                .expect("export coordinator poisoned");
            registry
                .acquire(&principal, self.inner.binary_capacity)
                .map_err(|refusal| {
                    Error::engine(match refusal {
                        CapacityRefusal::Global => BINARY_START_CAPACITY,
                        CapacityRefusal::Principal => BINARY_START_PRINCIPAL_CAPACITY,
                    })
                })?
        };
        let activity = self
            .try_begin(Self::export_lease_key(&principal, &db_key))
            .ok_or_else(|| {
                let accepting = self
                    .inner
                    .state
                    .lock()
                    .expect("export coordinator poisoned")
                    .accepting;
                Error::engine(if accepting {
                    BINARY_START_BUSY
                } else {
                    BINARY_START_DRAINING
                })
            })?;
        let handle = Uuid::new_v4().to_string();
        let capture_deadline = tokio::time::Instant::now() + self.inner.binary_capture_timeout;
        let (deadline, deadline_rx) = tokio::sync::watch::channel(Some(capture_deadline));
        let slot = Arc::new(BinarySlot {
            live: tokio::sync::Mutex::new(BinaryLive::Pending {
                principal: principal.clone(),
                db_key: db_key.clone(),
                capture_deadline,
            }),
            deadline,
            _permit: permit,
        });
        // The accepting check and the registry insert share one
        // state-lock-outer, registry-lock-inner critical section, so a drain
        // that closes admission either observes this handle or wins the check;
        // no insert can land after drain swept the registry.
        {
            let state = self
                .inner
                .state
                .lock()
                .expect("export coordinator poisoned");
            let mut registry = self
                .inner
                .binary
                .lock()
                .expect("export coordinator poisoned");
            if !state.accepting {
                drop(registry);
                drop(state);
                drop(activity);
                return Err(Error::engine(BINARY_START_DRAINING));
            }
            registry.slots.insert(handle.clone(), slot.clone());
        }
        self.spawn_binary_expiry(handle.clone(), Arc::downgrade(&slot), deadline_rx);
        let coordinator = self.clone();
        let weak = Arc::downgrade(&slot);
        let capture_handle = handle.clone();
        let capture_principal = principal.clone();
        let capture_db_key = db_key.clone();
        tokio::spawn(async move {
            let captured = AssertUnwindSafe(coordinator.run_binary_capture(
                capture_handle.clone(),
                slot,
                principal,
                db_key,
                activity,
                create,
            ))
            .catch_unwind()
            .await;
            if captured.is_err() {
                coordinator
                    .mark_binary_panicked(&capture_handle, weak, capture_principal, capture_db_key)
                    .await;
            }
        });
        Ok(handle)
    }

    async fn run_binary_capture<F, Fut>(
        &self,
        handle: String,
        slot: Arc<BinarySlot>,
        principal: String,
        db_key: String,
        activity: ExportActivity,
        create: F,
    ) where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Export, Error>> + Send + 'static,
    {
        let export = match create().await {
            Ok(export) => export,
            Err(_) => {
                self.finish_binary_failed(
                    &handle,
                    &slot,
                    principal,
                    db_key,
                    BinaryFailure::CaptureFailed,
                    activity,
                )
                .await;
                return;
            }
        };
        // An empty capture has no bytes to serve and cannot produce a standby
        // manifest; report it as a stable failure rather than publishing a
        // zero-length Ready.
        if export.size_bytes() == 0 {
            export.cleanup().await;
            self.finish_binary_failed(
                &handle,
                &slot,
                principal,
                db_key,
                BinaryFailure::EmptyExport,
                activity,
            )
            .await;
            return;
        }
        let FinalizedExport {
            export,
            mut file,
            sha256,
            manifest,
        } = match super::finalize_standby_export(export).await {
            Ok(finalized) => finalized,
            Err((export, _)) => {
                export.cleanup().await;
                self.finish_binary_failed(
                    &handle,
                    &slot,
                    principal,
                    db_key,
                    BinaryFailure::FinalizeFailed,
                    activity,
                )
                .await;
                return;
            }
        };
        let Some(manifest) = manifest else {
            drop(file);
            export.cleanup().await;
            self.finish_binary_failed(
                &handle,
                &slot,
                principal,
                db_key,
                BinaryFailure::StandbyContextRequired,
                activity,
            )
            .await;
            return;
        };
        if file.seek(std::io::SeekFrom::Start(0)).await.is_err() {
            drop(file);
            export.cleanup().await;
            self.finish_binary_failed(
                &handle,
                &slot,
                principal,
                db_key,
                BinaryFailure::FinalizeFailed,
                activity,
            )
            .await;
            return;
        }
        let expires_at = tokio::time::Instant::now() + self.inner.binary_idle_ttl;
        // Publication is serialized with cancel/drain/expiry under the slot
        // lock. If the handle was already revoked, the tombstone wins and this
        // capture closes the file, cleans the export, and releases the lease
        // here, so no unreachable Ready can retain resources for the idle TTL.
        let mut live = slot.live.lock().await;
        if matches!(&*live, BinaryLive::Pending { .. }) {
            *live = BinaryLive::Ready {
                principal,
                db_key,
                export: Some(Box::new(export)),
                file: Some(file),
                sha256,
                manifest: Box::new(manifest),
                expires_at,
                activity: Some(activity),
            };
            drop(live);
            slot.deadline.send_replace(Some(expires_at));
        } else {
            drop(live);
            drop(file);
            export.cleanup().await;
            drop(activity);
        }
    }

    /// Record a failed capture unless the handle was already revoked.
    async fn finish_binary_failed(
        &self,
        _handle: &str,
        slot: &Arc<BinarySlot>,
        principal: String,
        db_key: String,
        code: BinaryFailure,
        activity: ExportActivity,
    ) {
        let expires_at = tokio::time::Instant::now() + self.inner.binary_idle_ttl;
        let mut live = slot.live.lock().await;
        if matches!(&*live, BinaryLive::Pending { .. }) {
            *live = BinaryLive::Failed {
                principal,
                db_key,
                code,
                expires_at,
            };
            drop(live);
            drop(activity);
            slot.deadline.send_replace(Some(expires_at));
        } else {
            // Revoked: the handle is gone, so this only releases the lease;
            // the slot permit drops when this capture task's last Arc goes.
            drop(live);
            drop(activity);
        }
    }

    /// A panicked capture cannot be resumed; mark it failed if still pending.
    ///
    /// The panic may have unwound after creating an export, so the snapshot
    /// directory can leak on panic; the lease and permit still release, which
    /// keeps the bound honest. A deadline cannot abort the SQL, so panic and
    /// timeout are the only ways a capture ends without a served artifact.
    async fn mark_binary_panicked(
        &self,
        _handle: &str,
        slot: Weak<BinarySlot>,
        principal: String,
        db_key: String,
    ) {
        let Some(slot) = slot.upgrade() else {
            return;
        };
        let expires_at = tokio::time::Instant::now() + self.inner.binary_idle_ttl;
        let mut live = slot.live.lock().await;
        if matches!(&*live, BinaryLive::Pending { .. }) {
            *live = BinaryLive::Failed {
                principal,
                db_key,
                code: BinaryFailure::CaptureFailed,
                expires_at,
            };
            drop(live);
            slot.deadline.send_replace(Some(expires_at));
        }
    }

    fn lookup_binary(&self, handle: &str) -> Result<Arc<BinarySlot>, Error> {
        self.inner
            .binary
            .lock()
            .expect("export coordinator poisoned")
            .slots
            .get(handle)
            .cloned()
            .ok_or_else(|| missing(handle))
    }

    #[cfg(test)]
    fn binary_outstanding(&self) -> usize {
        self.inner
            .binary
            .lock()
            .expect("export coordinator poisoned")
            .outstanding
            .load(Ordering::SeqCst)
    }

    /// Poll handle metadata; unknown and cross-identity share one response.
    pub async fn poll_binary_export(
        &self,
        principal: &str,
        db_key: &str,
        handle: &str,
    ) -> Result<BinaryStatus, Error> {
        let slot = self.lookup_binary(handle)?;
        let mut live = slot.live.lock().await;
        let now = tokio::time::Instant::now();
        match &mut *live {
            BinaryLive::Pending {
                principal: owner,
                db_key: owner_db,
                capture_deadline,
            } => {
                if owner != principal || owner_db != db_key || now >= *capture_deadline {
                    return Err(missing(handle));
                }
                Ok(BinaryStatus {
                    handle: handle.to_string(),
                    state: BinaryState::Pending,
                    expires_at: *capture_deadline,
                    size_bytes: None,
                    sha256: None,
                    manifest: None,
                    error_code: None,
                })
            }
            BinaryLive::Ready {
                principal: owner,
                db_key: owner_db,
                export,
                sha256,
                manifest,
                expires_at,
                ..
            } => {
                if owner != principal || owner_db != db_key || now >= *expires_at {
                    return Err(missing(handle));
                }
                // Idle semantics: a successful poll refreshes the transfer
                // lifetime and wakes the expiry worker with the new deadline.
                *expires_at = now + self.inner.binary_idle_ttl;
                let refreshed = *expires_at;
                let size_bytes = export.as_ref().map(|export| export.size_bytes());
                let sha256 = sha256.clone();
                let manifest = manifest.as_ref().clone();
                drop(live);
                slot.deadline.send_replace(Some(refreshed));
                Ok(BinaryStatus {
                    handle: handle.to_string(),
                    state: BinaryState::Ready,
                    expires_at: refreshed,
                    size_bytes,
                    sha256: Some(sha256),
                    manifest: Some(manifest),
                    error_code: None,
                })
            }
            BinaryLive::Failed {
                principal: owner,
                db_key: owner_db,
                code,
                expires_at,
            } => {
                if owner != principal || owner_db != db_key || now >= *expires_at {
                    return Err(missing(handle));
                }
                *expires_at = now + self.inner.binary_idle_ttl;
                let refreshed = *expires_at;
                let code = *code;
                drop(live);
                slot.deadline.send_replace(Some(refreshed));
                Ok(BinaryStatus {
                    handle: handle.to_string(),
                    state: BinaryState::Failed,
                    expires_at: refreshed,
                    size_bytes: None,
                    sha256: None,
                    manifest: None,
                    error_code: Some(code),
                })
            }
            BinaryLive::Revoked => Err(missing(handle)),
        }
    }

    /// Read one raw chunk; validates bounds, no base64.
    pub async fn read_binary_bytes(
        &self,
        principal: &str,
        db_key: &str,
        handle: &str,
        offset: u64,
        length: usize,
    ) -> Result<BinaryChunk, Error> {
        if length == 0 {
            return Err(Error::engine(
                "binary export: length must be greater than zero",
            ));
        }
        if length > BINARY_MAX_CHUNK_BYTES {
            return Err(Error::engine(format!(
                "binary export: length {length} exceeds {BINARY_MAX_CHUNK_BYTES}-byte limit"
            )));
        }
        let slot = self.lookup_binary(handle)?;
        let mut live = slot.live.lock().await;
        let now = tokio::time::Instant::now();
        let BinaryLive::Ready {
            principal: owner,
            db_key: owner_db,
            export,
            file,
            sha256,
            manifest,
            expires_at,
            ..
        } = &mut *live
        else {
            return Err(missing(handle));
        };
        if owner != principal || owner_db != db_key || now >= *expires_at {
            return Err(missing(handle));
        }
        let export_ref = export.as_ref().ok_or_else(|| missing(handle))?;
        let size_bytes = export_ref.size_bytes();
        if offset >= size_bytes {
            return Err(Error::engine(format!(
                "binary export: offset {offset} is outside the {size_bytes}-byte snapshot"
            )));
        }
        let end = offset
            .checked_add(length as u64)
            .ok_or_else(|| Error::engine("binary export: offset plus length overflows"))?;
        let readable = (end.min(size_bytes) - offset) as usize;
        let file_ref = file.as_mut().ok_or_else(|| missing(handle))?;
        file_ref.seek(std::io::SeekFrom::Start(offset)).await?;
        let mut bytes = vec![0; readable];
        file_ref.read_exact(&mut bytes).await?;
        // A successful read refreshes the idle transfer lifetime.
        *expires_at = tokio::time::Instant::now() + self.inner.binary_idle_ttl;
        let refreshed = *expires_at;
        let sha256 = sha256.clone();
        let manifest = manifest.as_ref().clone();
        drop(live);
        slot.deadline.send_replace(Some(refreshed));
        Ok(BinaryChunk {
            handle: handle.to_string(),
            offset,
            length: readable,
            size_bytes,
            sha256,
            manifest,
            bytes,
        })
    }

    /// Make a handle unusable now; a capture still running cleans up after.
    pub async fn cancel_binary_export(
        &self,
        principal: &str,
        db_key: &str,
        handle: &str,
    ) -> Result<(), Error> {
        let slot = self.lookup_binary(handle)?;
        {
            let live = slot.live.lock().await;
            let owned = match &*live {
                BinaryLive::Pending {
                    principal: o,
                    db_key: d,
                    ..
                }
                | BinaryLive::Ready {
                    principal: o,
                    db_key: d,
                    ..
                }
                | BinaryLive::Failed {
                    principal: o,
                    db_key: d,
                    ..
                } => o == principal && d == db_key,
                BinaryLive::Revoked => false,
            };
            if !owned {
                return Err(missing(handle));
            }
        }
        // Wake the expiry worker, then revoke under the slot lock. Whichever of
        // cancel and a racing capture publication takes the lock first wins;
        // the loser observes the tombstone and cleans up exactly once.
        slot.deadline.send_replace(None);
        let resources = self.revoke_binary(handle, &slot).await;
        if let Some(resources) = resources {
            resources.cleanup().await;
        }
        Ok(())
    }

    /// Mark `slot` revoked under its lock, then unlink it.
    ///
    /// Returns Ready resources for the caller to clean up. A capture task still
    /// in flight observes the tombstone when it publishes and cleans itself up,
    /// releasing the lease and its permit.
    async fn revoke_binary(&self, handle: &str, slot: &Arc<BinarySlot>) -> Option<ReadyResources> {
        let resources = {
            let mut live = slot.live.lock().await;
            match &mut *live {
                BinaryLive::Revoked => return None,
                BinaryLive::Ready {
                    export,
                    file,
                    activity,
                    ..
                } => {
                    let resources = ReadyResources {
                        export: export.take(),
                        file: file.take(),
                        activity: activity.take(),
                    };
                    *live = BinaryLive::Revoked;
                    Some(resources)
                }
                _ => {
                    *live = BinaryLive::Revoked;
                    None
                }
            }
        };
        self.unlink_binary(handle, slot);
        resources
    }

    fn unlink_binary(&self, handle: &str, slot: &Arc<BinarySlot>) {
        let mut registry = self
            .inner
            .binary
            .lock()
            .expect("export coordinator poisoned");
        if registry
            .slots
            .get(handle)
            .is_some_and(|current| Arc::ptr_eq(current, slot))
        {
            registry.slots.remove(handle);
        }
    }

    /// Deadline-driven revocation that rechecks expiry *under the slot lock*.
    ///
    /// A poll/read can refresh the lifetime after the worker's wake but before
    /// it takes the lock; rechecking inside the lock is what stops a refreshed
    /// handle from being revoked early. Returns [`ExpiryAction::StillLive`] so
    /// the worker waits for the new deadline instead of exiting.
    async fn expire_binary(&self, handle: &str, slot: &Arc<BinarySlot>) -> ExpiryAction {
        let resources = {
            let mut live = slot.live.lock().await;
            let now = tokio::time::Instant::now();
            let expired = match &*live {
                BinaryLive::Pending {
                    capture_deadline, ..
                } => now >= *capture_deadline,
                BinaryLive::Ready { expires_at, .. } | BinaryLive::Failed { expires_at, .. } => {
                    now >= *expires_at
                }
                BinaryLive::Revoked => false,
            };
            if !expired {
                return ExpiryAction::StillLive;
            }
            match &mut *live {
                BinaryLive::Ready {
                    export,
                    file,
                    activity,
                    ..
                } => {
                    let resources = ReadyResources {
                        export: export.take(),
                        file: file.take(),
                        activity: activity.take(),
                    };
                    *live = BinaryLive::Revoked;
                    Some(resources)
                }
                _ => {
                    *live = BinaryLive::Revoked;
                    None
                }
            }
        };
        self.unlink_binary(handle, slot);
        ExpiryAction::Revoked(resources.map(Box::new))
    }

    /// One expiry worker per handle, holding the slot only weakly.
    ///
    /// It sleeps until the current deadline (refreshed through the watch
    /// channel by reads/polls), exits as soon as the deadline signal becomes
    /// `None` on cancel/drain, and returns when the slot is gone. It never
    /// keeps an inaccessible Ready alive: revocation always unlinks, so the
    /// worker's weak upgrade cannot reach an orphaned entry.
    fn spawn_binary_expiry(
        &self,
        handle: String,
        slot: Weak<BinarySlot>,
        mut deadline: tokio::sync::watch::Receiver<Option<tokio::time::Instant>>,
    ) {
        let coordinator = self.clone();
        tokio::spawn(async move {
            loop {
                let Some(due) = *deadline.borrow_and_update() else {
                    return;
                };
                tokio::select! {
                    _ = tokio::time::sleep_until(due) => {}
                    changed = deadline.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        continue;
                    }
                }
                let Some(latest) = *deadline.borrow_and_update() else {
                    return;
                };
                if latest > tokio::time::Instant::now() {
                    continue;
                }
                let Some(slot) = slot.upgrade() else {
                    return;
                };
                match coordinator.expire_binary(&handle, &slot).await {
                    ExpiryAction::Revoked(resources) => {
                        if let Some(resources) = resources {
                            resources.cleanup().await;
                        }
                        return;
                    }
                    ExpiryAction::StillLive => continue,
                }
            }
        });
    }

    pub(crate) async fn drain_binary(&self) {
        let slots: Vec<(String, Arc<BinarySlot>)> = {
            let mut registry = self
                .inner
                .binary
                .lock()
                .expect("export coordinator poisoned");
            registry.slots.drain().collect()
        };
        for (_handle, slot) in slots {
            slot.deadline.send_replace(None);
            let resources = {
                let mut live = slot.live.lock().await;
                match &mut *live {
                    BinaryLive::Ready {
                        export,
                        file,
                        activity,
                        ..
                    } => {
                        let resources = ReadyResources {
                            export: export.take(),
                            file: file.take(),
                            activity: activity.take(),
                        };
                        *live = BinaryLive::Revoked;
                        Some(resources)
                    }
                    _ => {
                        *live = BinaryLive::Revoked;
                        None
                    }
                }
            };
            if let Some(resources) = resources {
                resources.cleanup().await;
            }
        }
        // Detached captures still hold their lease and permit; the caller's
        // wait_for_idle waits for them without waiting out the idle TTL.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standby_snapshot::{
        ProducerBuildIdentity, StandbyConsumerIdentity, StandbyConsumerPlatform,
        STANDBY_CONSUMER_CONTRACT,
    };

    fn consumer() -> StandbyConsumerIdentity {
        StandbyConsumerIdentity {
            contract: STANDBY_CONSUMER_CONTRACT.into(),
            version: 1,
            platform: StandbyConsumerPlatform::LinuxX8664,
            source_sha: "b".repeat(40),
            artifact_sha256: "c".repeat(64),
            engine_schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
            ddl_sha256: crate::schema::FROZEN_DDL_SHA256.into(),
        }
    }

    fn context(db_id: &str) -> crate::standby_snapshot::HostedStandbyManifestContext {
        crate::standby_snapshot::HostedStandbyManifestContext::new_with_producer(
            db_id.into(),
            consumer(),
            ProducerBuildIdentity::new("a".repeat(40), crate::schema::FROZEN_DDL_SHA256.into())
                .unwrap(),
        )
        .unwrap()
    }

    async fn standby_export(db: &crate::Db, db_id: &str) -> Result<Export, Error> {
        Ok(crate::export::export_connected_db(db, None)
            .await?
            .with_hosted_standby_context(context(db_id)))
    }

    async fn wait_ready(
        coordinator: &ExportCoordinator,
        principal: &str,
        db_key: &str,
        handle: &str,
    ) -> BinaryStatus {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match coordinator
                    .poll_binary_export(principal, db_key, handle)
                    .await
                    .unwrap()
                {
                    status @ BinaryStatus {
                        state: BinaryState::Ready,
                        ..
                    } => return status,
                    BinaryStatus {
                        state: BinaryState::Failed,
                        ..
                    } => panic!("binary capture failed for {handle}"),
                    _ => tokio::time::sleep(Duration::from_millis(5)).await,
                }
            }
        })
        .await
        .expect("binary never became ready")
    }

    async fn wait_failed(
        coordinator: &ExportCoordinator,
        principal: &str,
        db_key: &str,
        handle: &str,
    ) -> BinaryStatus {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(status) = coordinator
                    .poll_binary_export(principal, db_key, handle)
                    .await
                {
                    if status.state == BinaryState::Failed {
                        return status;
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("binary never reported failure")
    }

    async fn wait_for_no_outstanding(coordinator: &ExportCoordinator) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while coordinator.binary_outstanding() != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("capture permit was never released");
    }

    #[tokio::test]
    async fn handle_registers_before_gated_capture_and_contends_limiter() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let db = crate::create_database(":memory:").await.unwrap();
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let gated_db = db.clone();
        let handle = coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                wait.await.unwrap();
                standby_export(&gated_db, "route-1").await
            })
            .expect("start must return a handle synchronously");
        // Handle is usable before capture completes.
        let pending = coordinator
            .poll_binary_export("user", "db", &handle)
            .await
            .unwrap();
        assert_eq!(pending.state, BinaryState::Pending);
        // Same principal+db contends on the shared limiter while gated.
        let contend_db = db.clone();
        assert!(coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                standby_export(&contend_db, "route-1").await
            })
            .is_err());
        release.send(()).unwrap();
        let ready = wait_ready(&coordinator, "user", "db", &handle).await;
        assert!(ready.sha256.unwrap().len() == 64);
        assert!(ready.manifest.is_some());
        db.close().await;
    }

    #[tokio::test]
    async fn cross_identity_shares_one_missing_response() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let db = crate::create_database(":memory:").await.unwrap();
        let owned_db = db.clone();
        let handle = coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                standby_export(&owned_db, "route-1").await
            })
            .unwrap();
        wait_ready(&coordinator, "user", "db", &handle).await;
        let unknown = coordinator
            .poll_binary_export("user", "db", "missing")
            .await
            .unwrap_err()
            .to_string();
        let wrong_user = coordinator
            .poll_binary_export("intruder", "db", &handle)
            .await
            .unwrap_err()
            .to_string();
        let wrong_db = coordinator
            .poll_binary_export("user", "other", &handle)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(wrong_user, unknown.replace("missing", &handle));
        assert_eq!(wrong_db, unknown.replace("missing", &handle));
        db.close().await;
    }

    #[tokio::test]
    async fn ready_reads_bytes_and_validates_bounds_ordinary_requires_manifest() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let db = crate::create_database(":memory:").await.unwrap();
        let owned_db = db.clone();
        let handle = coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                standby_export(&owned_db, "route-1").await
            })
            .unwrap();
        let ready = wait_ready(&coordinator, "user", "db", &handle).await;
        let size = ready.size_bytes.unwrap();
        let chunk = coordinator
            .read_binary_bytes("user", "db", &handle, 0, 64)
            .await
            .unwrap();
        assert_eq!(chunk.size_bytes, size);
        assert_eq!(chunk.sha256, ready.sha256.unwrap());
        assert_eq!(chunk.bytes.len(), 64.min(size as usize));
        assert!(coordinator
            .read_binary_bytes("user", "db", &handle, 0, 0)
            .await
            .is_err());
        assert!(coordinator
            .read_binary_bytes("user", "db", &handle, 0, BINARY_MAX_CHUNK_BYTES + 1)
            .await
            .is_err());
        assert!(coordinator
            .read_binary_bytes("user", "db", &handle, size, 1)
            .await
            .is_err());
        assert!(coordinator
            .read_binary_bytes("user", "db", &handle, u64::MAX, 1)
            .await
            .is_err());
        // Ordinary no-context export is not silently valid standby.
        let plain_db = db.clone();
        let plain = coordinator
            .start_binary_export("plain".into(), "db".into(), move || async move {
                crate::export::export_connected_db(&plain_db, None).await
            })
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if matches!(
                    coordinator
                        .poll_binary_export("plain", "db", &plain)
                        .await
                        .unwrap()
                        .state,
                    BinaryState::Failed
                ) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("ordinary export must fail this API");
        db.close().await;
    }

    #[tokio::test]
    async fn cancel_and_expiry_release_after_capture_cleanup() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_millis(40),
            Duration::from_secs(5),
        );
        let db = crate::create_database(":memory:").await.unwrap();
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let gated_db = db.clone();
        let handle = coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                wait.await.unwrap();
                standby_export(&gated_db, "route-1").await
            })
            .unwrap();
        coordinator
            .cancel_binary_export("user", "db", &handle)
            .await
            .unwrap();
        let missing = coordinator
            .poll_binary_export("user", "db", &handle)
            .await
            .unwrap_err()
            .to_string();
        assert!(missing.contains("does not exist or has expired"));
        // Lease is retained by the capture task until cleanup completes.
        assert!(coordinator.try_begin("user:db".into()).is_none());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), coordinator.wait_for_idle())
            .await
            .expect("cancel left capture or cleanup stranded");
        assert!(coordinator.try_begin("user:db".into()).is_some());
        // Idle expiry makes a ready handle unusable and cleans its file.
        let owned_db = db.clone();
        let ready_handle = coordinator
            .start_binary_export("idle".into(), "db".into(), move || async move {
                standby_export(&owned_db, "route-1").await
            })
            .unwrap();
        wait_ready(&coordinator, "idle", "db", &ready_handle).await;
        // Sleep past the idle TTL without polling; a poll would refresh it.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(coordinator
            .poll_binary_export("idle", "db", &ready_handle)
            .await
            .is_err());
        wait_for_no_outstanding(&coordinator).await;
        db.close().await;
    }

    #[tokio::test]
    async fn capacity_bound_and_drain_race_keep_cleanup_owned() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            1,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let db = crate::create_database(":memory:").await.unwrap();
        let first_db = db.clone();
        let first = coordinator
            .start_binary_export("a".into(), "db".into(), move || async move {
                standby_export(&first_db, "route-1").await
            })
            .unwrap();
        wait_ready(&coordinator, "a", "db", &first).await;
        // Strict bound counts ready handles.
        let second_db = db.clone();
        assert!(coordinator
            .start_binary_export("b".into(), "db".into(), move || async move {
                standby_export(&second_db, "route-1").await
            })
            .is_err());
        coordinator.drain().await;
        assert!(coordinator
            .poll_binary_export("a", "db", &first)
            .await
            .is_err());
        // Drain closed admission atomically for late starts.
        let late_db = db.clone();
        assert!(coordinator
            .start_binary_export("late".into(), "db".into(), move || async move {
                standby_export(&late_db, "route-1").await
            })
            .is_err());
        db.close().await;
    }

    #[tokio::test]
    async fn binary_shares_canonical_user_db_singleflight_with_tool() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        // A held frontend lease on the canonical key blocks binary start.
        let held = coordinator.try_begin("user:db".into()).expect("lease");
        let db = crate::create_database(":memory:").await.unwrap();
        let blocked_db = db.clone();
        assert!(coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                standby_export(&blocked_db, "route-1").await
            })
            .is_err());
        drop(held);
        // A gated binary capture blocks the canonical key and the tool page
        // addressed to the same principal.
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let gated_db = db.clone();
        let handle = coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                wait.await.unwrap();
                standby_export(&gated_db, "route-1").await
            })
            .unwrap();
        assert!(coordinator.try_begin("user:db".into()).is_none());
        let tool_db = db.clone();
        let tool_err = coordinator
            .tool_page("user:db".into(), None, 0, 1024, move || async move {
                crate::export::export_connected_db(&tool_db, None).await
            })
            .await
            .unwrap_err()
            .to_string();
        assert!(tool_err.contains("already in progress"));
        release.send(()).unwrap();
        wait_ready(&coordinator, "user", "db", &handle).await;
        db.close().await;
    }

    #[tokio::test]
    async fn failure_codes_never_echo_secret_paths_or_multibyte() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let secret = format!("sentinel-secret-/etc/shadow-{}", "é".repeat(600));
        let handle = coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                Err::<Export, Error>(Error::engine(secret.clone()))
            })
            .unwrap();
        let failed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = coordinator
                    .poll_binary_export("user", "db", &handle)
                    .await
                    .unwrap();
                if status.state == BinaryState::Failed {
                    return status;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("capture failure must surface without panicking on multibyte input");
        assert_eq!(failed.error_code, Some(BinaryFailure::CaptureFailed));
        // Lease is released after the failure is retained.
        assert!(coordinator.try_begin("user:db".into()).is_some());
    }

    #[tokio::test]
    async fn ready_then_cancel_closes_file_and_releases_lease_promptly() {
        // Idle TTL is long: only correct revocation can finish inside 2s.
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(30),
            Duration::from_secs(5),
        );
        let db = crate::create_database(":memory:").await.unwrap();
        let path_slot = Arc::new(std::sync::Mutex::new(None::<std::path::PathBuf>));
        let record = path_slot.clone();
        let owned_db = db.clone();
        let handle = coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                let export = standby_export(&owned_db, "route-1").await?;
                *record.lock().unwrap() = Some(export.path());
                Ok(export)
            })
            .unwrap();
        wait_ready(&coordinator, "user", "db", &handle).await;
        let path = path_slot.lock().unwrap().clone().expect("recorded path");
        assert!(path.exists());
        assert!(coordinator.try_begin("user:db".into()).is_none());

        coordinator
            .cancel_binary_export("user", "db", &handle)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while path.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("cancel did not remove the snapshot promptly");
        tokio::time::timeout(Duration::from_secs(2), coordinator.wait_for_idle())
            .await
            .expect("cancel did not release the lease promptly");
        wait_for_no_outstanding(&coordinator).await;
        assert!(coordinator.try_begin("user:db".into()).is_some());
        db.close().await;
    }

    #[tokio::test]
    async fn drain_closes_ready_promptly_without_waiting_idle_ttl() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(30),
            Duration::from_secs(5),
        );
        let db = crate::create_database(":memory:").await.unwrap();
        let path_slot = Arc::new(std::sync::Mutex::new(None::<std::path::PathBuf>));
        let record = path_slot.clone();
        let owned_db = db.clone();
        let handle = coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                let export = standby_export(&owned_db, "route-1").await?;
                *record.lock().unwrap() = Some(export.path());
                Ok(export)
            })
            .unwrap();
        wait_ready(&coordinator, "user", "db", &handle).await;
        let path = path_slot.lock().unwrap().clone().expect("recorded path");
        tokio::time::timeout(Duration::from_secs(2), coordinator.drain())
            .await
            .expect("drain waited on the idle TTL");
        assert!(!path.exists());
        assert!(coordinator
            .poll_binary_export("user", "db", &handle)
            .await
            .is_err());
        assert_eq!(coordinator.active_lease_len(), 0);
        db.close().await;
    }

    #[tokio::test]
    async fn pending_expiry_revokes_before_late_ready_publication() {
        // Short capture deadline forces pending expiry while the capture gate
        // is still held; publication must then observe the tombstone.
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(30),
            Duration::from_millis(60),
        );
        let db = crate::create_database(":memory:").await.unwrap();
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let gated_db = db.clone();
        let handle = coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                wait.await.unwrap();
                standby_export(&gated_db, "route-1").await
            })
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(coordinator
            .poll_binary_export("user", "db", &handle)
            .await
            .is_err());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), coordinator.wait_for_idle())
            .await
            .expect("revoked capture did not release its lease");
        wait_for_no_outstanding(&coordinator).await;
        assert!(coordinator
            .poll_binary_export("user", "db", &handle)
            .await
            .is_err());
        assert!(coordinator.try_begin("user:db".into()).is_some());
        db.close().await;
    }

    #[tokio::test]
    async fn capacity_retained_by_detached_capture_blocks_other_principals() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            1,
            Duration::from_secs(30),
            Duration::from_secs(30),
        );
        let db = crate::create_database(":memory:").await.unwrap();
        // Build the database fixture outside the bounded cleanup assertion.
        // The gated future still owns a pending capture after cancellation;
        // VACUUM/verification speed is not the resource-permit contract.
        let captured = standby_export(&db, "route-1").await.unwrap();
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let handle = coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                wait.await.unwrap();
                Ok(captured)
            })
            .unwrap();
        coordinator
            .cancel_binary_export("user", "db", &handle)
            .await
            .unwrap();
        // A different principal cannot start while the cancelled capture's
        // resource permit is still held.
        let other_db = db.clone();
        assert!(coordinator
            .start_binary_export("other".into(), "db".into(), move || async move {
                standby_export(&other_db, "route-1").await
            })
            .is_err());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), coordinator.wait_for_idle())
            .await
            .expect("detached capture did not finish");
        wait_for_no_outstanding(&coordinator).await;
        // The permit is released only after the capture completed cleanup.
        let again_db = db.clone();
        let again = coordinator
            .start_binary_export("other".into(), "db".into(), move || async move {
                standby_export(&again_db, "route-1").await
            })
            .expect("capacity not restored after capture cleanup");
        wait_ready(&coordinator, "other", "db", &again).await;
        coordinator
            .cancel_binary_export("other", "db", &again)
            .await
            .unwrap();
        db.close().await;
    }

    #[tokio::test]
    async fn failed_status_churn_is_bounded_per_principal_without_starving_others() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(30),
            Duration::from_secs(30),
        );
        let mut handles = Vec::new();
        for _ in 0..BINARY_PER_PRINCIPAL_CAPACITY {
            let handle = coordinator
                .start_binary_export("owner".into(), "db".into(), || async {
                    Err(Error::engine("capture path sentinel"))
                })
                .unwrap();
            let status = wait_failed(&coordinator, "owner", "db", &handle).await;
            assert_eq!(status.error_code, Some(BinaryFailure::CaptureFailed));
            handles.push(handle);
        }
        // Repeated failed polls extend tombstone TTL but cannot acquire more
        // permits for the same principal.
        for handle in &handles {
            coordinator
                .poll_binary_export("owner", "db", handle)
                .await
                .unwrap();
        }
        assert!(matches!(
            coordinator.start_binary_export("owner".into(), "db".into(), || async {
                Err(Error::engine("unexpected capture"))
            }),
            Err(Error::Engine(message)) if message == BINARY_START_PRINCIPAL_CAPACITY
        ));
        assert_eq!(
            coordinator.binary_outstanding(),
            BINARY_PER_PRINCIPAL_CAPACITY
        );

        let other = coordinator
            .start_binary_export("other".into(), "db".into(), || async {
                Err(Error::engine("other capture"))
            })
            .expect("another principal must retain global capacity");
        wait_failed(&coordinator, "other", "db", &other).await;
        for handle in handles {
            coordinator
                .cancel_binary_export("owner", "db", &handle)
                .await
                .unwrap();
        }
        coordinator
            .cancel_binary_export("other", "db", &other)
            .await
            .unwrap();
        wait_for_no_outstanding(&coordinator).await;
    }

    #[tokio::test]
    async fn cancelled_in_flight_captures_still_count_against_principal_limit() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(30),
            Duration::from_secs(30),
        );
        let mut releases = Vec::new();
        for index in 0..BINARY_PER_PRINCIPAL_CAPACITY {
            let db_key = format!("db-{index}");
            let (release, wait) = tokio::sync::oneshot::channel::<()>();
            let handle = coordinator
                .start_binary_export("owner".into(), db_key.clone(), move || async move {
                    wait.await.unwrap();
                    Err(Error::engine("detached capture finished"))
                })
                .unwrap();
            coordinator
                .cancel_binary_export("owner", &db_key, &handle)
                .await
                .unwrap();
            releases.push(release);
        }
        assert_eq!(
            coordinator.binary_outstanding(),
            BINARY_PER_PRINCIPAL_CAPACITY
        );
        assert!(matches!(
            coordinator.start_binary_export("owner".into(), "new-db".into(), || async {
                Err(Error::engine("unexpected capture"))
            }),
            Err(Error::Engine(message)) if message == BINARY_START_PRINCIPAL_CAPACITY
        ));
        let other = coordinator
            .start_binary_export("other".into(), "db".into(), || async {
                Err(Error::engine("other capture"))
            })
            .expect("detached owner captures must leave permits for another principal");
        wait_failed(&coordinator, "other", "db", &other).await;
        for release in releases {
            release.send(()).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(3), coordinator.wait_for_idle())
            .await
            .expect("detached captures did not finish");
        coordinator
            .cancel_binary_export("other", "db", &other)
            .await
            .unwrap();
        wait_for_no_outstanding(&coordinator).await;
    }

    #[tokio::test]
    async fn successful_poll_refreshes_ready_idle_lifetime() {
        let ttl = Duration::from_millis(200);
        let coordinator =
            ExportCoordinator::with_binary_test_bounds(8, ttl, Duration::from_secs(5));
        let db = crate::create_database(":memory:").await.unwrap();
        let owned_db = db.clone();
        let handle = coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                standby_export(&owned_db, "route-1").await
            })
            .unwrap();
        wait_ready(&coordinator, "user", "db", &handle).await;
        // Poll past the original TTL, refreshing each time.
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(80)).await;
            let status = coordinator
                .poll_binary_export("user", "db", &handle)
                .await
                .expect("refreshed handle expired early");
            assert_eq!(status.state, BinaryState::Ready);
        }
        // Stop refreshing: the idle TTL now expires it. Sleep past the TTL
        // without polling (a poll would refresh the lifetime), then confirm.
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert!(coordinator
            .poll_binary_export("user", "db", &handle)
            .await
            .is_err());
        wait_for_no_outstanding(&coordinator).await;
        db.close().await;
    }

    #[tokio::test]
    async fn empty_export_reports_stable_code_and_releases_lease() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("snapshot.db"), b"").unwrap();
        let handle = coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                Ok(Export::test_fixture(dir, "snapshot.db"))
            })
            .unwrap();
        let status = wait_failed(&coordinator, "user", "db", &handle).await;
        assert_eq!(status.error_code, Some(BinaryFailure::EmptyExport));
        assert!(coordinator.try_begin("user:db".into()).is_some());
    }

    #[tokio::test]
    async fn stable_failure_codes_for_context_and_finalize() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let db = crate::create_database(":memory:").await.unwrap();
        // Ordinary export without a hosted standby context.
        let plain_db = db.clone();
        let plain = coordinator
            .start_binary_export("plain".into(), "db".into(), move || async move {
                crate::export::export_connected_db(&plain_db, None).await
            })
            .unwrap();
        let status = wait_failed(&coordinator, "plain", "db", &plain).await;
        assert_eq!(
            status.error_code,
            Some(BinaryFailure::StandbyContextRequired)
        );
        assert!(coordinator.try_begin("plain:db".into()).is_some());
        // Hosted context over a non-database file fails finalization.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("snapshot.db"), b"not a database").unwrap();
        let broken = coordinator
            .start_binary_export("broken".into(), "db".into(), move || async move {
                Ok(Export::test_fixture(dir, "snapshot.db")
                    .with_hosted_standby_context(context("route-1")))
            })
            .unwrap();
        let status = wait_failed(&coordinator, "broken", "db", &broken).await;
        assert_eq!(status.error_code, Some(BinaryFailure::FinalizeFailed));
        db.close().await;
    }
}
