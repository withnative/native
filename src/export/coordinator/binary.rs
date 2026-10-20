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
/// Capture refusal for an authority act delta above the spool ceiling. The
/// capture closure returns this exact engine message so the registry maps it to
/// [`BinaryFailure::DeltaTooLarge`] rather than a generic capture failure.
pub const BINARY_DELTA_TOO_LARGE: &str =
    "binary export: authority act delta exceeds the spool ceiling";

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
    /// The exact authority cut is above the spool ceiling; the client takes a
    /// whole snapshot rather than retrying the same cut.
    DeltaTooLarge,
}

impl BinaryFailure {
    pub fn code(self) -> &'static str {
        match self {
            BinaryFailure::CaptureFailed => "capture_failed",
            BinaryFailure::FinalizeFailed => "finalize_failed",
            BinaryFailure::StandbyContextRequired => "standby_context_required",
            BinaryFailure::EmptyExport => "empty_export",
            BinaryFailure::DeltaTooLarge => "delta_too_large",
        }
    }
}

/// Which wire family a handle belongs to. Both share one registry, its permits,
/// idle TTL and drain, but a handle is only ever served by its own routes.
/// `SnapshotGzip` shares the snapshot single-flight lease (no duplicate
/// database-sized captures) and is still kind-separated at lookup.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum BinaryKind {
    Snapshot,
    SnapshotGzip,
    AuthorityActDelta,
}

/// Coordinates the authority itself observed for a captured delta cut.
///
/// Set by the capture closure, never by a client: `to_inclusive_act` is the
/// head read in the same transaction as the cut rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryDeltaMeta {
    pub route_database_id: String,
    pub origin_database_id: String,
    pub from_exclusive_act: i64,
    pub to_inclusive_act: i64,
    pub content_sha256: String,
    pub outer_sha256: String,
}

/// The kind-specific description a Ready handle carries. The gzip variant
/// keeps the unchanged decoded manifest; encoded identity travels beside it.
#[derive(Clone, Debug)]
pub(crate) enum BinaryReadyMeta {
    Snapshot(Box<crate::standby_snapshot::StandbySnapshotManifest>),
    SnapshotGzip(Box<crate::standby_snapshot::StandbySnapshotManifest>),
    Delta(Box<BinaryDeltaMeta>),
}

/// What a capture closure produced, before the registry finalizes it.
pub(crate) enum BinaryCaptured {
    Snapshot(Export),
    Delta(Export, BinaryDeltaMeta),
}

#[derive(Clone, Debug)]
pub struct BinaryStatus {
    pub handle: String,
    pub state: BinaryState,
    pub expires_at: tokio::time::Instant,
    pub size_bytes: Option<u64>,
    pub sha256: Option<String>,
    pub manifest: Option<crate::standby_snapshot::StandbySnapshotManifest>,
    pub delta: Option<BinaryDeltaMeta>,
    pub error_code: Option<BinaryFailure>,
    /// Encoded identity for gzip handles only; `None` on v1 and delta.
    /// `size_bytes`/`sha256`/`manifest` stay decoded (canonical admission).
    pub encoded_size_bytes: Option<u64>,
    pub encoded_sha256: Option<String>,
}

#[derive(Debug)]
pub struct BinaryChunk {
    pub handle: String,
    pub offset: u64,
    pub length: usize,
    pub size_bytes: u64,
    pub sha256: String,
    pub manifest: Option<crate::standby_snapshot::StandbySnapshotManifest>,
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
        meta: BinaryReadyMeta,
        expires_at: tokio::time::Instant,
        activity: Option<ExportActivity>,
        /// Private gzip spool for `SnapshotGzip` handles: encoded bytes in a
        /// sibling file inside the decoded export's directory, so one export
        /// cleanup removes both. `None` for v1 and delta handles.
        encoded: Option<Box<EncodedSpool>>,
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
    kind: BinaryKind,
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
    encoded_file: Option<tokio::fs::File>,
}

/// Private gzip spool: the encoded sibling's open handle plus its identity.
/// The bytes live inside the decoded export's directory, so dropping the file
/// handle here and cleaning the export removes both spools together.
pub(crate) struct EncodedSpool {
    file: tokio::fs::File,
    size_bytes: u64,
    sha256: String,
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
        drop(self.encoded_file);
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

/// Encode one finalized snapshot to a gzip sibling with streaming I/O.
///
/// Both the copy and the digest stream in bounded steps, so no
/// whole-snapshot buffer ever exists. Level 1 favours host CPU over bytes;
/// the encoded file is a sibling inside the decoded export's directory, so
/// the export cleanup removes both spools together.
async fn encode_snapshot_gzip(
    decoded_path: &std::path::Path,
) -> Result<(std::path::PathBuf, u64, String, tokio::fs::File), Error> {
    let mut sibling_name = decoded_path
        .file_name()
        .map(|name| name.to_owned())
        .ok_or_else(|| Error::engine("binary export: snapshot path has no file name"))?;
    sibling_name.push(".gz");
    let encoded_path = decoded_path.with_file_name(sibling_name);
    let source = decoded_path.to_path_buf();
    let target = encoded_path.clone();
    let copied = tokio::task::spawn_blocking(move || -> Result<(), Error> {
        let mut input = std::fs::File::open(&source)?;
        let output = std::fs::File::create(&target)?;
        let mut encoder = flate2::write::GzEncoder::new(output, flate2::Compression::new(1));
        std::io::copy(&mut input, &mut encoder)?;
        encoder.finish()?;
        Ok(())
    })
    .await
    .map_err(|_| Error::engine("binary export: gzip encode task stopped"))?;
    copied?;
    let mut file = tokio::fs::File::open(&encoded_path).await?;
    let sha256 = super::sha256_file(&mut file).await?;
    file.seek(std::io::SeekFrom::Start(0)).await?;
    let size_bytes = file.metadata().await?.len();
    Ok((encoded_path, size_bytes, sha256, file))
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
        let lease_key = Self::export_lease_key(&principal, &db_key);
        self.start_binary(
            BinaryKind::Snapshot,
            lease_key,
            principal,
            db_key,
            move || async move { create().await.map(BinaryCaptured::Snapshot) },
        )
    }

    /// Register a gzip snapshot acquisition sharing the snapshot lease.
    ///
    /// The lease key is identical to [`Self::start_binary_export`], so one
    /// account+database cannot run concurrent snapshot captures across the v1
    /// and v2 wire families. Global/per-principal permits, idle TTL, capture
    /// timeout and drain are shared through the same registry; only the handle
    /// kind (and its routes) differs.
    pub fn start_binary_gzip_export<F, Fut>(
        &self,
        principal: String,
        db_key: String,
        create: F,
    ) -> Result<String, Error>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Export, Error>> + Send + 'static,
    {
        let lease_key = Self::export_lease_key(&principal, &db_key);
        self.start_binary(
            BinaryKind::SnapshotGzip,
            lease_key,
            principal,
            db_key,
            move || async move { create().await.map(BinaryCaptured::Snapshot) },
        )
    }

    /// Register an authority act-delta acquisition. It draws on the same global
    /// and per-principal permits, idle TTL and drain as a snapshot handle, but
    /// holds a distinct lease key so neither can block the other for one
    /// account and database.
    pub fn start_binary_delta_export<F, Fut>(
        &self,
        principal: String,
        db_key: String,
        create: F,
    ) -> Result<String, Error>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(Export, BinaryDeltaMeta), Error>> + Send + 'static,
    {
        let lease_key = format!(
            "standby-delta:{}",
            Self::export_lease_key(&principal, &db_key)
        );
        self.start_binary(
            BinaryKind::AuthorityActDelta,
            lease_key,
            principal,
            db_key,
            move || async move {
                create()
                    .await
                    .map(|(export, meta)| BinaryCaptured::Delta(export, meta))
            },
        )
    }

    fn start_binary<F, Fut>(
        &self,
        kind: BinaryKind,
        lease_key: String,
        principal: String,
        db_key: String,
        create: F,
    ) -> Result<String, Error>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<BinaryCaptured, Error>> + Send + 'static,
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
        let activity = self.try_begin(lease_key).ok_or_else(|| {
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
            kind,
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
        Fut: Future<Output = Result<BinaryCaptured, Error>> + Send + 'static,
    {
        let captured = match create().await {
            Ok(captured) => captured,
            Err(error) => {
                let code = match &error {
                    Error::Engine(message) if message.as_str() == BINARY_DELTA_TOO_LARGE => {
                        BinaryFailure::DeltaTooLarge
                    }
                    _ => BinaryFailure::CaptureFailed,
                };
                self.finish_binary_failed(&handle, &slot, principal, db_key, code, activity)
                    .await;
                return;
            }
        };
        // An empty capture has no bytes to serve and cannot produce a standby
        // manifest; report it as a stable failure rather than publishing a
        // zero-length Ready.
        let export_ref = match &captured {
            BinaryCaptured::Snapshot(export) | BinaryCaptured::Delta(export, _) => export,
        };
        if export_ref.size_bytes() == 0 {
            match captured {
                BinaryCaptured::Snapshot(export) | BinaryCaptured::Delta(export, _) => {
                    export.cleanup().await
                }
            }
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
        let want_gzip = slot.kind == BinaryKind::SnapshotGzip;
        let (export, mut file, sha256, meta, encoded) = match captured {
            BinaryCaptured::Snapshot(export) => {
                let FinalizedExport {
                    export,
                    file,
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
                if !want_gzip {
                    (
                        export,
                        file,
                        sha256,
                        BinaryReadyMeta::Snapshot(Box::new(manifest)),
                        None,
                    )
                } else {
                    // Canonical capture, filter, finalize and admission all
                    // ran before this point; compression is a representation
                    // of the admitted bytes, never a second capture.
                    let decoded_path = export.path();
                    match encode_snapshot_gzip(&decoded_path).await {
                        Ok((_, encoded_size, encoded_sha, encoded_file)) => (
                            export,
                            file,
                            sha256,
                            BinaryReadyMeta::SnapshotGzip(Box::new(manifest)),
                            Some(Box::new(EncodedSpool {
                                file: encoded_file,
                                size_bytes: encoded_size,
                                sha256: encoded_sha,
                            })),
                        ),
                        Err(_) => {
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
                    }
                }
            }
            BinaryCaptured::Delta(export, meta) => {
                // The spooled bytes must still be the bytes the authority
                // validated and digested at capture.
                let hashed = match tokio::fs::File::open(export.path()).await {
                    Ok(mut file) => super::sha256_file(&mut file).await.map(|sha| (file, sha)),
                    Err(error) => Err(error.into()),
                };
                match hashed {
                    Ok((file, sha256)) if sha256 == meta.outer_sha256 => (
                        export,
                        file,
                        sha256,
                        BinaryReadyMeta::Delta(Box::new(meta)),
                        None,
                    ),
                    _ => {
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
                }
            }
        };
        if file.seek(std::io::SeekFrom::Start(0)).await.is_err() {
            drop(file);
            drop(encoded);
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
                meta,
                expires_at,
                activity: Some(activity),
                encoded,
            };
            drop(live);
            slot.deadline.send_replace(Some(expires_at));
        } else {
            drop(live);
            drop(file);
            drop(encoded);
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

    /// A handle is only visible to the routes of its own kind, so a snapshot
    /// handle can never be polled, read or cancelled as a delta (or back).
    fn lookup_binary(&self, handle: &str, kind: BinaryKind) -> Result<Arc<BinarySlot>, Error> {
        self.inner
            .binary
            .lock()
            .expect("export coordinator poisoned")
            .slots
            .get(handle)
            .filter(|slot| slot.kind == kind)
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
        self.poll_binary(BinaryKind::Snapshot, principal, db_key, handle)
            .await
    }

    /// Poll a gzip snapshot handle; kind-separated from v1 and delta.
    pub async fn poll_binary_gzip_export(
        &self,
        principal: &str,
        db_key: &str,
        handle: &str,
    ) -> Result<BinaryStatus, Error> {
        self.poll_binary(BinaryKind::SnapshotGzip, principal, db_key, handle)
            .await
    }

    /// Poll an authority act-delta handle; same opaque missing response.
    pub async fn poll_binary_delta_export(
        &self,
        principal: &str,
        db_key: &str,
        handle: &str,
    ) -> Result<BinaryStatus, Error> {
        self.poll_binary(BinaryKind::AuthorityActDelta, principal, db_key, handle)
            .await
    }

    async fn poll_binary(
        &self,
        kind: BinaryKind,
        principal: &str,
        db_key: &str,
        handle: &str,
    ) -> Result<BinaryStatus, Error> {
        let slot = self.lookup_binary(handle, kind)?;
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
                    delta: None,
                    error_code: None,
                    encoded_size_bytes: None,
                    encoded_sha256: None,
                })
            }
            BinaryLive::Ready {
                principal: owner,
                db_key: owner_db,
                export,
                sha256,
                meta,
                expires_at,
                encoded,
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
                let (manifest, delta, encoded_size_bytes, encoded_sha256) = match (meta, encoded) {
                    (BinaryReadyMeta::Snapshot(manifest), _) => {
                        (Some(manifest.as_ref().clone()), None, None, None)
                    }
                    (BinaryReadyMeta::SnapshotGzip(manifest), Some(spool)) => (
                        Some(manifest.as_ref().clone()),
                        None,
                        Some(spool.size_bytes),
                        Some(spool.sha256.clone()),
                    ),
                    (BinaryReadyMeta::SnapshotGzip(_), None) => return Err(missing(handle)),
                    (BinaryReadyMeta::Delta(delta), _) => {
                        (None, Some(delta.as_ref().clone()), None, None)
                    }
                };
                drop(live);
                slot.deadline.send_replace(Some(refreshed));
                Ok(BinaryStatus {
                    handle: handle.to_string(),
                    state: BinaryState::Ready,
                    expires_at: refreshed,
                    size_bytes,
                    sha256: Some(sha256),
                    manifest,
                    delta,
                    error_code: None,
                    encoded_size_bytes,
                    encoded_sha256,
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
                    delta: None,
                    error_code: Some(code),
                    encoded_size_bytes: None,
                    encoded_sha256: None,
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
        self.read_binary(
            BinaryKind::Snapshot,
            principal,
            db_key,
            handle,
            offset,
            length,
        )
        .await
    }

    /// Read one gzip chunk of a ready v2 snapshot spool.
    ///
    /// Offsets address the encoded bytes; the returned digest and length are
    /// the encoded identity, while the manifest stays the decoded one.
    pub async fn read_binary_gzip_bytes(
        &self,
        principal: &str,
        db_key: &str,
        handle: &str,
        offset: u64,
        length: usize,
    ) -> Result<BinaryChunk, Error> {
        self.read_binary(
            BinaryKind::SnapshotGzip,
            principal,
            db_key,
            handle,
            offset,
            length,
        )
        .await
    }

    /// Read one raw chunk of a ready authority act-delta spool.
    pub async fn read_binary_delta_bytes(
        &self,
        principal: &str,
        db_key: &str,
        handle: &str,
        offset: u64,
        length: usize,
    ) -> Result<BinaryChunk, Error> {
        self.read_binary(
            BinaryKind::AuthorityActDelta,
            principal,
            db_key,
            handle,
            offset,
            length,
        )
        .await
    }

    async fn read_binary(
        &self,
        kind: BinaryKind,
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
        let slot = self.lookup_binary(handle, kind)?;
        let mut live = slot.live.lock().await;
        let now = tokio::time::Instant::now();
        let BinaryLive::Ready {
            principal: owner,
            db_key: owner_db,
            export,
            file,
            sha256,
            meta,
            expires_at,
            encoded,
            ..
        } = &mut *live
        else {
            return Err(missing(handle));
        };
        if owner != principal || owner_db != db_key || now >= *expires_at {
            return Err(missing(handle));
        }
        // Gzip handles address the encoded spool and report the encoded
        // identity; the decoded manifest stays canonical for admission.
        let (size_bytes, digest, file_ref): (u64, String, &mut tokio::fs::File) =
            if kind == BinaryKind::SnapshotGzip {
                if !matches!(meta, BinaryReadyMeta::SnapshotGzip(_)) {
                    return Err(missing(handle));
                }
                let Some(spool) = encoded.as_mut() else {
                    return Err(missing(handle));
                };
                (spool.size_bytes, spool.sha256.clone(), &mut spool.file)
            } else {
                let export_ref = export.as_ref().ok_or_else(|| missing(handle))?;
                let file_ref = file.as_mut().ok_or_else(|| missing(handle))?;
                (export_ref.size_bytes(), sha256.clone(), file_ref)
            };
        if offset >= size_bytes {
            return Err(Error::engine(format!(
                "binary export: offset {offset} is outside the {size_bytes}-byte snapshot"
            )));
        }
        let end = offset
            .checked_add(length as u64)
            .ok_or_else(|| Error::engine("binary export: offset plus length overflows"))?;
        let readable = (end.min(size_bytes) - offset) as usize;
        file_ref.seek(std::io::SeekFrom::Start(offset)).await?;
        let mut bytes = vec![0; readable];
        file_ref.read_exact(&mut bytes).await?;
        // A successful read refreshes the idle transfer lifetime.
        *expires_at = tokio::time::Instant::now() + self.inner.binary_idle_ttl;
        let refreshed = *expires_at;
        let sha256 = digest;
        let manifest = match meta {
            BinaryReadyMeta::Snapshot(manifest) => Some(manifest.as_ref().clone()),
            BinaryReadyMeta::SnapshotGzip(manifest) => Some(manifest.as_ref().clone()),
            BinaryReadyMeta::Delta(_) => None,
        };
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
        self.cancel_binary(BinaryKind::Snapshot, principal, db_key, handle)
            .await
    }

    /// Cancel a gzip snapshot handle and remove both spools immediately.
    pub async fn cancel_binary_gzip_export(
        &self,
        principal: &str,
        db_key: &str,
        handle: &str,
    ) -> Result<(), Error> {
        self.cancel_binary(BinaryKind::SnapshotGzip, principal, db_key, handle)
            .await
    }

    /// Cancel an authority act-delta handle and remove its spool.
    pub async fn cancel_binary_delta_export(
        &self,
        principal: &str,
        db_key: &str,
        handle: &str,
    ) -> Result<(), Error> {
        self.cancel_binary(BinaryKind::AuthorityActDelta, principal, db_key, handle)
            .await
    }

    async fn cancel_binary(
        &self,
        kind: BinaryKind,
        principal: &str,
        db_key: &str,
        handle: &str,
    ) -> Result<(), Error> {
        let slot = self.lookup_binary(handle, kind)?;
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
                    encoded,
                    ..
                } => {
                    let resources = ReadyResources {
                        export: export.take(),
                        file: file.take(),
                        activity: activity.take(),
                        encoded_file: encoded.take().map(|spool| spool.file),
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
                    encoded,
                    ..
                } => {
                    let resources = ReadyResources {
                        export: export.take(),
                        file: file.take(),
                        activity: activity.take(),
                        encoded_file: encoded.take().map(|spool| spool.file),
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
                        encoded,
                        ..
                    } => {
                        let resources = ReadyResources {
                            export: export.take(),
                            file: file.take(),
                            activity: activity.take(),
                            encoded_file: encoded.take().map(|spool| spool.file),
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

    async fn wait_gzip_ready(
        coordinator: &ExportCoordinator,
        principal: &str,
        db_key: &str,
        handle: &str,
    ) -> BinaryStatus {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match coordinator
                    .poll_binary_gzip_export(principal, db_key, handle)
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
                    } => panic!("gzip capture failed for {handle}"),
                    _ => tokio::time::sleep(Duration::from_millis(5)).await,
                }
            }
        })
        .await
        .expect("gzip never became ready")
    }

    async fn compressible_standby_db() -> crate::Db {
        let db = crate::create_database(":memory:").await.unwrap();
        sqlx::query(
            "INSERT INTO blobs
             (id, bytes, size_bytes, storage_tier, created_at)
             VALUES ('gzip-padding', zeroblob(100000), 100000, 'inline', '2026-07-31T00:00:00Z')",
        )
        .execute(db.write_pool())
        .await
        .unwrap();
        db
    }

    #[tokio::test]
    async fn gzip_roundtrip_preserves_decoded_identity_and_reports_encoded() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let db = compressible_standby_db().await;
        let owned_db = db.clone();
        let handle = coordinator
            .start_binary_gzip_export("user".into(), "db".into(), move || async move {
                standby_export(&owned_db, "route-1").await
            })
            .unwrap();
        let ready = wait_gzip_ready(&coordinator, "user", "db", &handle).await;
        let decoded_size = ready.size_bytes.unwrap();
        let decoded_sha = ready.sha256.clone().unwrap();
        let manifest = ready.manifest.clone().unwrap();
        assert_eq!(manifest.snapshot.size_bytes, decoded_size);
        assert_eq!(manifest.snapshot.sha256, decoded_sha);
        let encoded_size = ready.encoded_size_bytes.unwrap();
        let encoded_sha = ready.encoded_sha256.clone().unwrap();
        assert!(encoded_size < decoded_size);
        assert_ne!(encoded_sha, decoded_sha);
        let mut encoded = Vec::new();
        let mut offset = 0u64;
        while offset < encoded_size {
            let length = (encoded_size - offset).min(BINARY_MAX_CHUNK_BYTES as u64) as usize;
            let chunk = coordinator
                .read_binary_gzip_bytes("user", "db", &handle, offset, length)
                .await
                .unwrap();
            assert_eq!(chunk.size_bytes, encoded_size);
            assert_eq!(chunk.sha256, encoded_sha);
            assert_eq!(chunk.manifest.clone().unwrap(), manifest);
            encoded.extend_from_slice(&chunk.bytes);
            offset += chunk.length as u64;
        }
        assert_eq!(encoded.len() as u64, encoded_size);
        use sha2::Digest as _;
        assert_eq!(hex::encode(sha2::Sha256::digest(&encoded)), encoded_sha);
        let mut decoder = flate2::read::GzDecoder::new(&encoded[..]);
        let mut decoded = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut decoded).unwrap();
        assert_eq!(decoded.len() as u64, decoded_size);
        assert_eq!(hex::encode(sha2::Sha256::digest(&decoded)), decoded_sha);
        db.close().await;
    }

    #[tokio::test]
    async fn gzip_shares_snapshot_singleflight_in_both_directions() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let db = crate::create_database(":memory:").await.unwrap();
        // A held canonical lease blocks a gzip start: no duplicate capture.
        let held = coordinator.try_begin("user:db".into()).expect("lease");
        let blocked_db = db.clone();
        let refused = coordinator
            .start_binary_gzip_export("user".into(), "db".into(), move || async move {
                standby_export(&blocked_db, "route-1").await
            })
            .unwrap_err()
            .to_string();
        assert!(refused.contains("already in progress"));
        drop(held);
        // A gated v1 capture blocks a gzip start on the same key.
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let gated_db = db.clone();
        let first = coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                wait.await.unwrap();
                standby_export(&gated_db, "route-1").await
            })
            .unwrap();
        let contend_db = db.clone();
        assert!(coordinator
            .start_binary_gzip_export("user".into(), "db".into(), move || async move {
                standby_export(&contend_db, "route-1").await
            })
            .is_err());
        release.send(()).unwrap();
        wait_ready(&coordinator, "user", "db", &first).await;
        coordinator
            .cancel_binary_export("user", "db", &first)
            .await
            .unwrap();
        // A gated gzip capture blocks a v1 start on the same key.
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let gated_db = db.clone();
        let gz = coordinator
            .start_binary_gzip_export("user".into(), "db".into(), move || async move {
                wait.await.unwrap();
                standby_export(&gated_db, "route-1").await
            })
            .unwrap();
        let contend_db = db.clone();
        assert!(coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                standby_export(&contend_db, "route-1").await
            })
            .is_err());
        release.send(()).unwrap();
        wait_gzip_ready(&coordinator, "user", "db", &gz).await;
        db.close().await;
    }

    #[tokio::test]
    async fn gzip_handles_are_kind_separated_from_v1() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let db = crate::create_database(":memory:").await.unwrap();
        let v1_db = db.clone();
        let v1 = coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                standby_export(&v1_db, "route-1").await
            })
            .unwrap();
        wait_ready(&coordinator, "user", "db", &v1).await;
        // A v1 handle is invisible to every gzip verb.
        assert!(coordinator
            .poll_binary_gzip_export("user", "db", &v1)
            .await
            .is_err());
        assert!(coordinator
            .read_binary_gzip_bytes("user", "db", &v1, 0, 64)
            .await
            .is_err());
        assert!(coordinator
            .cancel_binary_gzip_export("user", "db", &v1)
            .await
            .is_err());
        coordinator
            .cancel_binary_export("user", "db", &v1)
            .await
            .unwrap();
        let gz_db = db.clone();
        let gz = coordinator
            .start_binary_gzip_export("user".into(), "db".into(), move || async move {
                standby_export(&gz_db, "route-1").await
            })
            .unwrap();
        wait_gzip_ready(&coordinator, "user", "db", &gz).await;
        // A gzip handle is invisible to every v1 verb.
        assert!(coordinator
            .poll_binary_export("user", "db", &gz)
            .await
            .is_err());
        assert!(coordinator
            .read_binary_bytes("user", "db", &gz, 0, 64)
            .await
            .is_err());
        assert!(coordinator
            .cancel_binary_export("user", "db", &gz)
            .await
            .is_err());
        coordinator
            .cancel_binary_gzip_export("user", "db", &gz)
            .await
            .unwrap();
        db.close().await;
    }

    #[tokio::test]
    async fn gzip_cancel_removes_both_spools_and_releases_lease() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(30),
            Duration::from_secs(5),
        );
        let db = compressible_standby_db().await;
        let path_slot = Arc::new(std::sync::Mutex::new(None::<std::path::PathBuf>));
        let record = path_slot.clone();
        let owned_db = db.clone();
        let handle = coordinator
            .start_binary_gzip_export("user".into(), "db".into(), move || async move {
                let export = standby_export(&owned_db, "route-1").await?;
                *record.lock().unwrap() = Some(export.path());
                Ok(export)
            })
            .unwrap();
        wait_gzip_ready(&coordinator, "user", "db", &handle).await;
        let decoded_path = path_slot.lock().unwrap().clone().expect("recorded path");
        let encoded_path = decoded_path.with_file_name(format!(
            "{}.gz",
            decoded_path.file_name().unwrap().to_str().unwrap()
        ));
        assert!(decoded_path.exists());
        assert!(encoded_path.exists());
        assert!(coordinator.try_begin("user:db".into()).is_none());
        coordinator
            .cancel_binary_gzip_export("user", "db", &handle)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while decoded_path.exists() || encoded_path.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("cancel did not remove both spools promptly");
        tokio::time::timeout(Duration::from_secs(2), coordinator.wait_for_idle())
            .await
            .expect("cancel did not release the lease promptly");
        wait_for_no_outstanding(&coordinator).await;
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

    // ---- authority act-delta handle family -------------------------------

    async fn delta_capture(bytes: &[u8]) -> Result<(Export, BinaryDeltaMeta), Error> {
        use sha2::{Digest, Sha256};
        let export = crate::export::spool_bytes_export(None, "delta.json", bytes).await?;
        let digest = hex::encode(Sha256::digest(bytes));
        Ok((
            export,
            BinaryDeltaMeta {
                route_database_id: "route-1".into(),
                origin_database_id: "ndb_0123456789abcdef0123456789abcdef".into(),
                from_exclusive_act: 3,
                to_inclusive_act: 9,
                content_sha256: "c".repeat(64),
                outer_sha256: digest,
            },
        ))
    }

    async fn wait_delta_ready(
        coordinator: &ExportCoordinator,
        principal: &str,
        db_key: &str,
        handle: &str,
    ) -> BinaryStatus {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = coordinator
                    .poll_binary_delta_export(principal, db_key, handle)
                    .await
                    .unwrap();
                match status.state {
                    BinaryState::Ready => return status,
                    BinaryState::Failed => panic!("delta capture failed"),
                    BinaryState::Pending => tokio::time::sleep(Duration::from_millis(5)).await,
                }
            }
        })
        .await
        .expect("delta never became ready")
    }

    #[tokio::test]
    async fn delta_handle_serves_ranges_and_reports_the_cut_the_authority_observed() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let bytes: Vec<u8> = (0..2_500_000_u32).map(|n| (n % 253) as u8).collect();
        let owned = bytes.clone();
        let handle = coordinator
            .start_binary_delta_export("user".into(), "db".into(), move || async move {
                delta_capture(&owned).await
            })
            .unwrap();
        let ready = wait_delta_ready(&coordinator, "user", "db", &handle).await;
        assert_eq!(ready.size_bytes, Some(bytes.len() as u64));
        assert!(ready.manifest.is_none());
        let delta = ready.delta.expect("cut metadata");
        assert_eq!((delta.from_exclusive_act, delta.to_inclusive_act), (3, 9));

        let mut assembled = Vec::new();
        let mut offset = 0_u64;
        while offset < bytes.len() as u64 {
            let chunk = coordinator
                .read_binary_delta_bytes("user", "db", &handle, offset, BINARY_MAX_CHUNK_BYTES)
                .await
                .unwrap();
            assert_eq!(chunk.sha256, delta.outer_sha256, "ETag source");
            assert!(chunk.manifest.is_none());
            offset += chunk.length as u64;
            assembled.extend_from_slice(&chunk.bytes);
        }
        assert_eq!(assembled, bytes);
        assert!(coordinator
            .read_binary_delta_bytes("user", "db", &handle, bytes.len() as u64, 1)
            .await
            .is_err());
        assert!(coordinator
            .read_binary_delta_bytes("user", "db", &handle, 0, BINARY_MAX_CHUNK_BYTES + 1)
            .await
            .is_err());

        coordinator
            .cancel_binary_delta_export("user", "db", &handle)
            .await
            .unwrap();
        assert!(coordinator
            .poll_binary_delta_export("user", "db", &handle)
            .await
            .is_err());
        coordinator.wait_for_idle().await;
        wait_for_no_outstanding(&coordinator).await;
    }

    #[tokio::test]
    async fn delta_handle_expires_after_the_idle_ttl() {
        // Direct handle-expiry coverage for the delta family: a ready delta
        // handle whose idle deadline passes expires like a snapshot handle.
        // Afterwards polls, reads, and cancels all miss the registry — the
        // wire layer answers each of those as `handle_not_found`. The expiry
        // is forced through the real worker path (past `expires_at` under
        // the slot lock plus a past watch deadline to wake the worker), so
        // no short real TTL can flake under a loaded scheduler.
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(30),
            Duration::from_secs(5),
        );
        let bytes = b"{\"contract\":\"native.standby-authority-act-delta.v1\"}".to_vec();
        let owned = bytes.clone();
        let handle = coordinator
            .start_binary_delta_export("user".into(), "db".into(), move || async move {
                delta_capture(&owned).await
            })
            .unwrap();
        wait_delta_ready(&coordinator, "user", "db", &handle).await;
        let slot = coordinator
            .inner
            .binary
            .lock()
            .expect("export coordinator poisoned")
            .slots
            .get(&handle)
            .cloned()
            .expect("delta slot registered");
        let past = tokio::time::Instant::now() - Duration::from_secs(1);
        {
            let mut live = slot.live.lock().await;
            match &mut *live {
                BinaryLive::Ready { expires_at, .. } => *expires_at = past,
                _ => panic!("delta handle not ready"),
            }
        }
        slot.deadline.send_replace(Some(past));
        drop(slot);
        // Wait for the expiry worker itself to revoke and unlink the slot:
        // polling alone would refuse via the past `expires_at` without
        // proving the worker path ran.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let linked = coordinator
                    .inner
                    .binary
                    .lock()
                    .expect("export coordinator poisoned")
                    .slots
                    .contains_key(&handle);
                if !linked {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("forced delta expiry did not revoke the handle");
        assert!(
            coordinator
                .read_binary_delta_bytes("user", "db", &handle, 0, 8)
                .await
                .is_err(),
            "expired delta handle still serves bytes"
        );
        assert!(
            coordinator
                .cancel_binary_delta_export("user", "db", &handle)
                .await
                .is_err(),
            "expired delta handle still cancels"
        );
        wait_for_no_outstanding(&coordinator).await;
    }

    #[tokio::test]
    async fn a_handle_is_only_visible_to_its_own_wire_family() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let db = crate::create_database(":memory:").await.unwrap();
        let snapshot_db = db.clone();
        let snapshot = coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                standby_export(&snapshot_db, "route-1").await
            })
            .unwrap();
        let delta = coordinator
            .start_binary_delta_export("user".into(), "db".into(), || async {
                delta_capture(b"{}").await
            })
            .unwrap();
        wait_ready(&coordinator, "user", "db", &snapshot).await;
        wait_delta_ready(&coordinator, "user", "db", &delta).await;

        assert!(coordinator
            .poll_binary_delta_export("user", "db", &snapshot)
            .await
            .is_err());
        assert!(coordinator
            .read_binary_delta_bytes("user", "db", &snapshot, 0, 1)
            .await
            .is_err());
        assert!(coordinator
            .cancel_binary_delta_export("user", "db", &snapshot)
            .await
            .is_err());
        assert!(coordinator
            .poll_binary_export("user", "db", &delta)
            .await
            .is_err());
        assert!(coordinator
            .read_binary_bytes("user", "db", &delta, 0, 1)
            .await
            .is_err());
        assert!(coordinator
            .cancel_binary_export("user", "db", &delta)
            .await
            .is_err());
        // Neither refused cancel touched the other family's live handle.
        wait_ready(&coordinator, "user", "db", &snapshot).await;
        wait_delta_ready(&coordinator, "user", "db", &delta).await;
        // Identity binding still applies within the family.
        assert!(coordinator
            .poll_binary_delta_export("other", "db", &delta)
            .await
            .is_err());
        assert!(coordinator
            .poll_binary_delta_export("user", "other-db", &delta)
            .await
            .is_err());
        db.close().await;
    }

    #[tokio::test]
    async fn delta_and_snapshot_do_not_contend_for_one_account_but_share_its_permits() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            16,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let db = crate::create_database(":memory:").await.unwrap();
        // A gated snapshot capture holds the canonical lease for user:db.
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let gated_db = db.clone();
        let snapshot = coordinator
            .start_binary_export("user".into(), "db".into(), move || async move {
                wait.await.unwrap();
                standby_export(&gated_db, "route-1").await
            })
            .unwrap();
        assert!(coordinator.try_begin("user:db".into()).is_none());
        // The delta capture is not blocked by it...
        let delta = coordinator
            .start_binary_delta_export("user".into(), "db".into(), || async {
                delta_capture(b"{}").await
            })
            .expect("a delta capture is independent of the snapshot lease");
        wait_delta_ready(&coordinator, "user", "db", &delta).await;
        // ...and holds its own lease, so a second delta for the same account
        // and database is busy, while the snapshot lease is still the snapshot's.
        let busy = coordinator
            .start_binary_delta_export("user".into(), "db".into(), || async {
                delta_capture(b"{}").await
            })
            .unwrap_err();
        assert!(busy.to_string().contains("already in progress"), "{busy}");
        assert!(coordinator.try_begin("user:db".into()).is_none());
        release.send(()).unwrap();
        wait_ready(&coordinator, "user", "db", &snapshot).await;

        // The per-principal bound counts both families: one snapshot and one
        // delta are held, so two more handles on other databases fill it.
        for index in 0..BINARY_PER_PRINCIPAL_CAPACITY - 2 {
            coordinator
                .start_binary_delta_export("user".into(), format!("db-{index}"), || async {
                    delta_capture(b"{}").await
                })
                .unwrap();
        }
        let refused = coordinator
            .start_binary_delta_export("user".into(), "db-over".into(), || async {
                delta_capture(b"{}").await
            })
            .unwrap_err();
        assert_eq!(
            refused.to_string(),
            Error::engine(BINARY_START_PRINCIPAL_CAPACITY).to_string()
        );
        // Another principal is unaffected.
        coordinator
            .start_binary_delta_export("someone-else".into(), "db".into(), || async {
                delta_capture(b"{}").await
            })
            .unwrap();
        db.close().await;
    }

    #[tokio::test]
    async fn delta_above_the_spool_ceiling_reports_its_stable_code() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let handle = coordinator
            .start_binary_delta_export("user".into(), "db".into(), || async {
                Err::<(Export, BinaryDeltaMeta), _>(Error::engine(BINARY_DELTA_TOO_LARGE))
            })
            .unwrap();
        let failed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = coordinator
                    .poll_binary_delta_export("user", "db", &handle)
                    .await
                    .unwrap();
                if status.state != BinaryState::Pending {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(failed.state, BinaryState::Failed);
        assert_eq!(failed.error_code.unwrap().code(), "delta_too_large");
        // Any other capture error stays a generic, non-echoing failure.
        let other = coordinator
            .start_binary_delta_export("user".into(), "db2".into(), || async {
                Err::<(Export, BinaryDeltaMeta), _>(Error::engine("secret /tmp/path"))
            })
            .unwrap();
        let failed = loop {
            let status = coordinator
                .poll_binary_delta_export("user", "db2", &other)
                .await
                .unwrap();
            if status.state != BinaryState::Pending {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert_eq!(failed.error_code.unwrap().code(), "capture_failed");
    }

    #[tokio::test]
    async fn delta_spool_that_no_longer_matches_its_digest_is_not_published() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let handle = coordinator
            .start_binary_delta_export("user".into(), "db".into(), || async {
                let (export, mut meta) = delta_capture(b"{\"a\":1}").await?;
                meta.outer_sha256 = "0".repeat(64);
                Ok((export, meta))
            })
            .unwrap();
        let status = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = coordinator
                    .poll_binary_delta_export("user", "db", &handle)
                    .await
                    .unwrap();
                if status.state != BinaryState::Pending {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(status.error_code.unwrap().code(), "finalize_failed");
        coordinator.wait_for_idle().await;
    }

    #[tokio::test]
    async fn drain_removes_a_ready_delta_spool_promptly() {
        let coordinator = ExportCoordinator::with_binary_test_bounds(
            8,
            Duration::from_secs(30),
            Duration::from_secs(5),
        );
        let path_slot = Arc::new(std::sync::Mutex::new(None::<std::path::PathBuf>));
        let record = path_slot.clone();
        let handle = coordinator
            .start_binary_delta_export("user".into(), "db".into(), move || async move {
                let (export, meta) = delta_capture(b"{}").await?;
                *record.lock().unwrap() = Some(export.path());
                Ok((export, meta))
            })
            .unwrap();
        wait_delta_ready(&coordinator, "user", "db", &handle).await;
        let path = path_slot.lock().unwrap().clone().expect("recorded path");
        assert!(path.exists());
        tokio::time::timeout(Duration::from_secs(2), coordinator.drain())
            .await
            .expect("drain waited on the idle TTL");
        assert!(!path.exists());
        assert!(coordinator
            .poll_binary_delta_export("user", "db", &handle)
            .await
            .is_err());
        assert_eq!(coordinator.active_lease_len(), 0);
        assert!(coordinator
            .start_binary_delta_export("user".into(), "db".into(), || async {
                delta_capture(b"{}").await
            })
            .is_err());
    }
}
