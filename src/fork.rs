//! The engine's disposable speculative-execution fork, used by the hosted
//! maintenance outbox today and intended for the local node.
//!
//! No ingress, router, journal, scheduler or public receipt is installed here.
//! The caller must already be authenticated by frozen hosted ingress. A fork
//! is disposable; only journaled calls may be used to reconstruct it.

mod rebase;

#[cfg(feature = "v2-kernel-probe")]
pub(crate) mod working_v2;

#[cfg(all(test, feature = "v2-kernel-probe"))]
mod kernel_v2_tests;

use crate::db::DatabaseOpenMode;
use crate::mcp::{register_surface_tools, Caller, ToolRegistry};
use crate::{Db, Error};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;

/// Internal categories for the future ingress coordinator. Infrastructure and
/// post-dispatch failures are never reported as domain refusals.
#[derive(Debug)]
pub enum ForkError {
    RetryableNotReady(String),
    RefusedInvalid(Error),
    RefusedUnsupported(String),
    Uncertain(Error),
}

impl std::fmt::Display for ForkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RetryableNotReady(reason) | Self::RefusedUnsupported(reason) => {
                f.write_str(reason)
            }
            Self::RefusedInvalid(error) | Self::Uncertain(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for ForkError {}
impl From<Error> for ForkError {
    fn from(error: Error) -> Self {
        Self::Uncertain(error)
    }
}
impl From<sqlx::Error> for ForkError {
    fn from(error: sqlx::Error) -> Self {
        Self::Uncertain(error.into())
    }
}
impl From<std::io::Error> for ForkError {
    fn from(error: std::io::Error) -> Self {
        Self::Uncertain(error.into())
    }
}
impl From<serde_json::Error> for ForkError {
    fn from(error: serde_json::Error) -> Self {
        Self::Uncertain(error.into())
    }
}
pub type ForkResult<T> = std::result::Result<T, ForkError>;
type Result<T> = ForkResult<T>;

fn refuse(message: &str) -> ForkError {
    ForkError::RefusedInvalid(Error::engine(format!("hosted outbox fork: {message}")))
}
fn unsupported(message: &str) -> ForkError {
    ForkError::RefusedUnsupported(message.into())
}
fn not_ready(message: &str) -> ForkError {
    ForkError::RetryableNotReady(message.into())
}

// Operator diagnostics never render an error's message, paths or caller data.
fn diagnostic_error(error: &ForkError) -> (&'static str, Option<i32>) {
    match error {
        ForkError::Uncertain(Error::Io(error)) => ("io", error.raw_os_error()),
        ForkError::Uncertain(Error::Sqlx(sqlx::Error::Database(error))) => {
            ("database", error.code().and_then(|code| code.parse().ok()))
        }
        ForkError::Uncertain(Error::Sqlx(sqlx::Error::PoolTimedOut)) => ("pool_timeout", None),
        ForkError::Uncertain(_) => ("uncertain", None),
        ForkError::RefusedInvalid(_) => ("invalid", None),
        ForkError::RefusedUnsupported(_) => ("unsupported", None),
        ForkError::RetryableNotReady(_) => ("not_ready", None),
    }
}

/// One speculative workspace generation per window. Values never form paths.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ForkKey {
    pub window_id: String,
    pub workspace_id: String,
}

#[derive(Clone, Debug)]
pub struct ForkLimits {
    pub copy_workers: usize,
    pub max_forks: usize,
    pub max_reserved_bytes: u64,
    /// Fixed growth allowance on top of twice the base's allocated page size.
    pub growth_bytes: u64,
    pub max_call_bytes: usize,
}

impl Default for ForkLimits {
    fn default() -> Self {
        Self {
            copy_workers: 1,
            max_forks: 32,
            max_reserved_bytes: 4 * 1024 * 1024 * 1024,
            growth_bytes: 16 * 1024 * 1024,
            max_call_bytes: 1024 * 1024,
        }
    }
}

/// A trusted, private data directory capability, not an arbitrary fork path.
/// Canonical locations must be outside its hosted-outbox/forks subtree. The
/// directory tree must be controlled by the service UID; checks detect path
/// replacement between operations, not hostile concurrent writes by that UID.
pub struct ForkArea {
    root: PathBuf,
    identity: FileIdentity,
    _lock: std::fs::File,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity(u64, u64);

#[cfg(unix)]
fn identity(path: &Path, directory: bool) -> Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || metadata.is_dir() != directory
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
    {
        return Err(ForkError::Uncertain(Error::engine(
            "symlink, hardlink or unexpected file type",
        )));
    }
    Ok(FileIdentity(metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn identity(_path: &Path, _directory: bool) -> Result<FileIdentity> {
    Err(refuse(
        "private fork paths require Unix filesystem identity",
    ))
}

fn no_symlink_components(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(refuse("data directory must be absolute"));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(refuse("parent path components are not permitted"));
        }
        current.push(component);
        if std::fs::symlink_metadata(&current)?
            .file_type()
            .is_symlink()
        {
            return Err(refuse("symlink path component"));
        }
    }
    Ok(())
}

fn directory(path: &Path, private: bool) -> Result<()> {
    use std::fs::DirBuilder;
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    no_symlink_components(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if private && std::fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            return Err(refuse("fork area must be private to the service UID"));
        }
    }
    identity(path, true)?;
    Ok(())
}

impl ForkArea {
    pub fn new(data_directory: &Path, canonical_files: &[PathBuf]) -> Result<Self> {
        no_symlink_components(data_directory)?;
        let root = data_directory.join("hosted-outbox").join("forks");
        // Check before creating anything. Missing canonical files are refused,
        // rather than guessed from an unverified lexical spelling.
        for path in canonical_files {
            let canonical = std::fs::canonicalize(path)?;
            if canonical.starts_with(&root) || path.starts_with(&root) {
                return Err(refuse("canonical file is inside the fork area"));
            }
        }
        directory(&data_directory.join("hosted-outbox"), false)?;
        directory(&root, true)?;
        let lock = std::fs::File::open(&root)?;
        fs2::FileExt::try_lock_exclusive(&lock)
            .map_err(|_| not_ready("fork area already has a manager"))?;
        // A restart never trusts old speculative files. Only this manager owns
        // the locked subtree; the sibling journal is outside it and untouched.
        for entry in std::fs::read_dir(&root)? {
            let entry = entry?;
            if Uuid::parse_str(&entry.file_name().to_string_lossy()).is_err() {
                return Err(refuse("unexpected entry in private fork area"));
            }
            identity(&entry.path(), true)?;
            for file in std::fs::read_dir(entry.path())? {
                let file = file?;
                let name = file.file_name();
                if !matches!(
                    name.to_str(),
                    Some(
                        "partial.sqlite"
                            | "partial.sqlite-wal"
                            | "partial.sqlite-shm"
                            | "partial.sqlite-journal"
                            | "fork.sqlite"
                            | "fork.sqlite-wal"
                            | "fork.sqlite-shm"
                            | "fork.sqlite-journal"
                            | "rebase-in-progress"
                            | "pending-binding"
                            | "pending-binding-next"
                    )
                ) {
                    return Err(refuse("unexpected file in stale fork directory"));
                }
                identity(&file.path(), false)?;
            }
            std::fs::remove_dir_all(entry.path())?;
        }
        Ok(Self {
            identity: identity(&root, true)?,
            root,
            _lock: lock,
        })
    }

    /// Reopen a named retained subtree without examining or deleting siblings.
    /// Acquiring this lock never implies that a different live owner is dead.
    #[cfg(feature = "v2-kernel-probe")]
    pub(super) fn open_retained(
        data_directory: &Path,
        canonical_files: &[PathBuf],
    ) -> Result<Self> {
        no_symlink_components(data_directory)?;
        let root = data_directory.join("hosted-outbox").join("forks");
        for path in canonical_files {
            let canonical = std::fs::canonicalize(path)?;
            if canonical.starts_with(&root) || path.starts_with(&root) {
                return Err(refuse("canonical file is inside the fork area"));
            }
        }
        for path in [
            data_directory.to_path_buf(),
            data_directory.join("hosted-outbox"),
            root.clone(),
        ] {
            identity(&path, true)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                let meta = std::fs::symlink_metadata(&path)?;
                if meta.uid() != crate::node::current_uid()
                    || meta.permissions().mode() & 0o077 != 0
                {
                    return Err(refuse("retained working directory ownership differs"));
                }
            }
        }
        let lock = std::fs::File::open(&root)?;
        fs2::FileExt::try_lock_exclusive(&lock)
            .map_err(|_| not_ready("fork area still has an owner"))?;
        Ok(Self {
            identity: identity(&root, true)?,
            root,
            _lock: lock,
        })
    }

    fn check(&self) -> Result<()> {
        no_symlink_components(&self.root)?;
        if identity(&self.root, true)? != self.identity {
            return Err(ForkError::Uncertain(Error::engine(
                "fork area was substituted",
            )));
        }
        Ok(())
    }
}

/// A normalized call suitable for journaling *before* dispatch. Deserializing
/// journal rows does not grant execution: every field is revalidated below.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedCall {
    operation: String,
    arguments: Value,
    #[serde(default)]
    create_id: Option<String>,
    /// In-process authority, never deserialized from journal payloads.
    #[serde(skip)]
    caller: Option<Caller>,
}

impl PreparedCall {
    pub fn with_caller(mut self, caller: Caller) -> Self {
        self.caller = Some(caller);
        self
    }

    pub fn publication_key(&self) -> String {
        publication_key(
            self.caller.as_ref().map_or("", Caller::credential),
            &self.operation,
            self.idempotency_key(),
        )
    }
    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn arguments(&self) -> &Value {
        &self.arguments
    }
    pub fn idempotency_key(&self) -> &str {
        self.arguments["idempotency_key"].as_str().unwrap_or("")
    }
    pub fn create_id(&self) -> Option<&str> {
        self.create_id.as_deref().or_else(|| {
            (self.operation == "create_record")
                .then(|| self.arguments["id"].as_str())
                .flatten()
        })
    }
}

/// The journal reserves client keys per principal and operation.
pub fn publication_key(principal: &str, operation: &str, key: &str) -> String {
    serde_json::to_string(&(principal, operation, key)).expect("string tuple")
}

/// Journal adapters return only the ordered, currently retained calls for this
/// workspace/window. No dependency on the journal worker's store.
pub trait OrderedJournaledCalls: Send + Sync {
    fn ordered_calls<'a>(
        &'a self,
        key: &'a ForkKey,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::Result<Vec<PreparedCall>>> + Send + 'a>,
    >;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForkState {
    Absent,
    Preparing,
    Ready,
    Dirty,
    Failed,
}

/// Internal validation evidence. Deliberately has no handler receipt, event
/// pin, attestation, canonical version or public success framing.
#[derive(Clone, Debug)]
pub struct ForkOutcome {
    pub idempotency_key: String,
    pub create_id: Option<String>,
    pub touched_record_ids: Vec<String>,
    pub frontier: i64,
    /// Journal confirmation must return this token before another dispatch.
    confirmation: Uuid,
    publication_key: String,
}

struct ForkHandle {
    db: Db,
    registry: ToolRegistry,
    directory: PathBuf,
    directory_identity: FileIdentity,
    file_identity: FileIdentity,
    base_frontier: i64,
    capture: Option<rebase::Capture>,
}

impl ForkHandle {
    fn check(&self, area: &ForkArea) -> Result<()> {
        area.check()?;
        if identity(&self.directory, true)? != self.directory_identity
            || identity(self.db.path(), false)? != self.file_identity
        {
            return Err(ForkError::Uncertain(Error::engine(
                "fork path was substituted",
            )));
        }
        Ok(())
    }

    async fn touched(&self) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            "SELECT DISTINCT record_id FROM content_events WHERE seq>? ORDER BY record_id",
        )
        .bind(self.base_frontier)
        .fetch_all(self.db.pool())
        .await?)
    }

    /// Domain touched IDs for the private KernelV2 engine: content events
    /// minus internal kernel streams (notably `kernel:mcp-write-receipts`,
    /// the event-backed keyed-receipt bookkeeping). Those rows are engine
    /// internals, not pending user content, and must never surface as
    /// touched records.
    #[cfg(feature = "v2-kernel-probe")]
    async fn touched_domain(&self) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            "SELECT DISTINCT record_id FROM content_events WHERE seq>? AND record_id NOT LIKE 'kernel:%' ORDER BY record_id",
        )
        .bind(self.base_frontier)
        .fetch_all(self.db.pool())
        .await?)
    }
}

struct Entry {
    handle: Option<ForkHandle>,
    pending_confirmation: Option<Uuid>,
    published_keys: Vec<String>,
}

struct EntrySlot {
    #[cfg(feature = "v2-kernel-probe")]
    changed: tokio::sync::Notify,
    // State has its own short synchronous lock: status never waits for SQLite.
    state: std::sync::Mutex<ForkState>,
    base: Db,
    reservation: u64,
    speculative: std::sync::atomic::AtomicBool,
    inner: Arc<Mutex<Entry>>,
}
impl EntrySlot {
    fn state(&self) -> ForkState {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn set_state(&self, state: ForkState) {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = state;
        #[cfg(feature = "v2-kernel-probe")]
        self.changed.notify_waiters();
    }
}

// A panic in a detached rebuild must not leave it preparing forever.
struct Rebuilding(Arc<EntrySlot>);
impl Drop for Rebuilding {
    fn drop(&mut self) {
        if self.0.state() == ForkState::Preparing {
            self.0.set_state(ForkState::Dirty);
        }
    }
}

#[derive(Default)]
struct Entries {
    items: HashMap<ForkKey, Arc<EntrySlot>>,
    reserved: u64,
    prewarm_closed: bool,
}

/// Test-only hook installed on the reclaim path immediately before unlink:
/// signals arrival, waits for release, then optionally fails instead of
/// unlinking. Lets tests prove map availability during cleanup and failure
/// atomicity without timing assumptions.
#[cfg(test)]
pub(super) struct ReclaimUnlinkHook {
    pub reached: Option<tokio::sync::oneshot::Sender<()>>,
    pub release: std::sync::Arc<tokio::sync::Notify>,
    /// Fires after unlink completes, before the final map lock: lets tests
    /// park a reclaimer with its slot Dirty and its reservation charged.
    pub settled: Option<tokio::sync::oneshot::Sender<()>>,
    pub fail_unlink: bool,
}

/// Test-only hook for proving bounded waits survive a contended fork map:
/// holds the global map lock until dropped. Dropping never disturbs the map;
/// it only releases the lock.
#[cfg(any(test, feature = "body-read-test-support"))]
#[doc(hidden)]
pub struct MapLockHold<'a> {
    _guard: tokio::sync::MutexGuard<'a, Entries>,
}

pub struct ForkManager {
    #[cfg(test)]
    copy_count: std::sync::atomic::AtomicU64,
    area: ForkArea,
    limits: ForkLimits,
    workers: Arc<Semaphore>,
    entries: Mutex<Entries>,
    validators: HashMap<String, jsonschema::Validator>,
    presentation: ToolRegistry,
    /// True for the private KernelV2 working engine. The v1 hosted-outbox
    /// path keeps `false`; every existing v1 behaviour is unchanged.
    #[cfg(feature = "v2-kernel-probe")]
    kernel_v2: bool,
    /// Test-only pre-unlink gate for deterministic reclaim tests.
    #[cfg(test)]
    unlink_hook: Mutex<Option<ReclaimUnlinkHook>>,
}

impl ForkManager {
    pub fn new(area: ForkArea, limits: ForkLimits) -> Result<Arc<Self>> {
        Self::new_with_presentation(area, limits, &ToolRegistry::new())
    }

    /// Use the live deployment's URL annotations on disposable fork reads.
    pub fn new_with_presentation(
        area: ForkArea,
        limits: ForkLimits,
        source: &ToolRegistry,
    ) -> Result<Arc<Self>> {
        if limits.copy_workers == 0 || limits.max_forks == 0 || limits.max_call_bytes == 0 {
            return Err(refuse("zero capacity"));
        }
        area.check()?;
        let mut contracts = ToolRegistry::new();
        register_surface_tools(&mut contracts)?;
        let mut validators = HashMap::new();
        for operation in ["create_record", "update_record"] {
            let spec = contracts
                .get(operation)
                .ok_or_else(|| refuse("missing ordinary tool contract"))?;
            let validator = jsonschema::validator_for(&spec.input_schema)
                .map_err(|error| refuse(&format!("invalid ordinary contract: {error}")))?;
            validators.insert(operation.into(), validator);
        }
        let mut presentation = ToolRegistry::new();
        presentation.copy_presentation_from(source);
        Ok(Arc::new(Self {
            #[cfg(test)]
            copy_count: std::sync::atomic::AtomicU64::new(0),
            presentation,
            workers: Arc::new(Semaphore::new(limits.copy_workers)),
            area,
            limits,
            entries: Mutex::new(Entries::default()),
            validators,
            #[cfg(feature = "v2-kernel-probe")]
            kernel_v2: false,
            #[cfg(test)]
            unlink_hook: Mutex::new(None),
        }))
    }

    /// Private KernelV2 working engine: the same fork machinery (area, copy,
    /// slots, journal gating) dispatching through the actual KernelV2
    /// handlers. No v1 hosted-outbox behaviour changes; v1 managers keep
    /// `kernel_v2 == false` and never reach the v2 methods below.
    #[cfg(feature = "v2-kernel-probe")]
    pub fn new_kernel_v2(area: ForkArea, limits: ForkLimits) -> Result<Arc<Self>> {
        Self::new_kernel_v2_with_presentation(area, limits, &ToolRegistry::new())
    }

    /// Use the live deployment's URL annotations on disposable fork reads.
    #[cfg(feature = "v2-kernel-probe")]
    pub fn new_kernel_v2_with_presentation(
        area: ForkArea,
        limits: ForkLimits,
        source: &ToolRegistry,
    ) -> Result<Arc<Self>> {
        if limits.copy_workers == 0 || limits.max_forks == 0 || limits.max_call_bytes == 0 {
            return Err(refuse("zero capacity"));
        }
        area.check()?;
        let mut presentation = ToolRegistry::new();
        presentation.copy_presentation_from(source);
        Ok(Arc::new(Self {
            #[cfg(test)]
            copy_count: std::sync::atomic::AtomicU64::new(0),
            presentation,
            workers: Arc::new(Semaphore::new(limits.copy_workers)),
            area,
            limits,
            entries: Mutex::new(Entries::default()),
            validators: HashMap::new(),
            kernel_v2: true,
            #[cfg(test)]
            unlink_hook: Mutex::new(None),
        }))
    }

    /// Install (or clear with None) the reclaim pre-unlink test hook.
    #[cfg(test)]
    pub(super) async fn set_unlink_hook_for_tests(&self, hook: Option<ReclaimUnlinkHook>) {
        *self.unlink_hook.lock().await = hook;
    }

    /// Normalize once, retain the returned call/key even when preparing, and
    /// journal these same arguments. Id-less keyed retries derive the same id.
    pub async fn prepare_call(
        &self,
        key: &ForkKey,
        caller: &Caller,
        operation: &str,
        mut arguments: Value,
    ) -> Result<PreparedCall> {
        check_binding(key, caller)?;
        validate_shape(operation, &arguments, false, self.limits.max_call_bytes)?;
        self.validate_contract(operation, &arguments)?;
        let object = arguments
            .as_object_mut()
            .ok_or_else(|| refuse("expected object"))?;
        if !object.contains_key("idempotency_key") {
            object.insert(
                "idempotency_key".into(),
                Value::String(Uuid::new_v4().to_string()),
            );
        }
        let trimmed = object["idempotency_key"]
            .as_str()
            .expect("validated key")
            .trim()
            .to_owned();
        object.insert("idempotency_key".into(), Value::String(trimmed));
        let mut create_id = None;
        if operation == "create_record" && !object.contains_key("id") {
            let slot = self.entry(key).await?;
            if let Some((id, replay_arguments)) =
                crate::provenance::existing_create_replay_arguments(
                    &slot.base,
                    caller.credential(),
                    &arguments,
                    &crate::provenance::CommandAppContext::no_app(),
                )
                .await
                .map_err(classify_preflight)?
            {
                // Preserve the original digest, including whether id was absent.
                arguments = replay_arguments;
                create_id = Some(id);
            } else {
                let object = arguments.as_object_mut().expect("validated object");
                let bytes = serde_json::to_vec(&(
                    caller.credential(),
                    operation,
                    &object["idempotency_key"],
                ))
                .map_err(|_| refuse("cannot normalize key"))?;
                let hash = Sha256::digest(bytes);
                let mut bytes = [0; 16];
                bytes.copy_from_slice(&hash[..16]);
                // Stable RFC variant UUID with the caller-supported v4 spelling.
                bytes[6] = (bytes[6] & 0x0f) | 0x40;
                bytes[8] = (bytes[8] & 0x3f) | 0x80;
                object.insert(
                    "id".into(),
                    Value::String(Uuid::from_bytes(bytes).to_string()),
                );
            }
        }
        self.validate_contract(operation, &arguments)?;
        validate_shape(operation, &arguments, false, self.limits.max_call_bytes)?;
        Ok(PreparedCall {
            operation: operation.into(),
            arguments,
            create_id,
            caller: Some(caller.clone()),
        })
    }

    /// Background entry point on first write or preview recovery. It reserves
    /// count/bytes before enqueueing, and never accepts a call.
    /// Repeated preparation is idempotent for the same base handle.
    pub async fn prepare(self: &Arc<Self>, key: ForkKey, base: Db) -> Result<ForkState> {
        self.prepare_inner(key, base, false).await
    }

    /// Test-only gate for pinning a copy in flight: holds one copy-worker
    /// permit so a prepared slot stays Preparing until the permit is dropped.
    /// Lets a bounded waiter be exercised without any timing dependence.
    #[cfg(any(test, feature = "body-read-test-support"))]
    #[doc(hidden)]
    pub async fn hold_copy_worker_for_tests(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.workers
            .clone()
            .acquire_owned()
            .await
            .expect("copy worker semaphore stays open")
    }

    /// Acquire the global fork-map lock and hold it until the returned guard
    /// is dropped, so a state lookup blocks exactly like a multi-GB reclaim
    /// holding the lock across unlink.
    #[cfg(any(test, feature = "body-read-test-support"))]
    #[doc(hidden)]
    pub async fn hold_map_lock_for_tests(&self) -> MapLockHold<'_> {
        MapLockHold {
            _guard: self.entries.lock().await,
        }
    }

    /// Best effort: never queue a speculative copy ahead of demand. Unclaimed
    /// completed prewarms may be reclaimed when demand needs their reservation.
    pub async fn prewarm(self: &Arc<Self>, key: ForkKey, base: Db) -> Result<ForkState> {
        self.prepare_inner(key, base, true).await
    }

    async fn prepare_inner(
        self: &Arc<Self>,
        key: ForkKey,
        base: Db,
        speculative: bool,
    ) -> Result<ForkState> {
        self.area.check()?;
        if key.window_id.trim().is_empty() || key.workspace_id.trim().is_empty() {
            return Err(refuse("window/workspace binding required"));
        }
        if base.open_mode() != DatabaseOpenMode::StandbyReadOnly {
            return Err(refuse("base must be physically read-only"));
        }
        let canonical = std::fs::canonicalize(base.path())?;
        if canonical.starts_with(&self.area.root) {
            return Err(refuse("canonical base cannot be a fork"));
        }
        // Idempotent status lookup must not touch a pool a rebuild is using.
        let existing = {
            let mut entries = self.entries.lock().await;
            if speculative && entries.prewarm_closed {
                return Err(not_ready("prewarm stopped after on-demand preparation"));
            }
            if !speculative {
                entries.prewarm_closed = true;
            }
            let existing = entries.items.get(&key).cloned();
            if let Some(slot) = &existing {
                if !speculative {
                    slot.speculative
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                }
            }
            existing
        };
        if let Some(existing) = existing {
            if existing.base.handle_id() != base.handle_id() {
                return Err(refuse("window base changed"));
            }
            return Ok(existing.state());
        }
        let pages: i64 = sqlx::query_scalar("PRAGMA page_count")
            .fetch_one(base.pool())
            .await?;
        let page_size: i64 = sqlx::query_scalar("PRAGMA page_size")
            .fetch_one(base.pool())
            .await?;
        let reservation = (pages as u64)
            .checked_mul(page_size as u64)
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(self.limits.growth_bytes))
            .ok_or_else(|| refuse("copy size overflow"))?;
        let mut entries = self.entries.lock().await;
        if let Some(entry) = entries.items.get(&key).cloned() {
            if entry.base.handle_id() != base.handle_id() {
                return Err(refuse("window base changed"));
            }
            if !speculative {
                entry
                    .speculative
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            }
            return Ok(entry.state());
        }
        if speculative && entries.prewarm_closed {
            return Err(not_ready("prewarm stopped after on-demand preparation"));
        }
        let fits = |entries: &Entries| {
            entries.items.len() < self.limits.max_forks
                && reservation
                    <= self
                        .limits
                        .max_reserved_bytes
                        .saturating_sub(entries.reserved)
        };
        if !speculative && !fits(&entries) {
            let candidates: Vec<_> = entries
                .items
                .iter()
                .filter(|(_, slot)| {
                    slot.speculative.load(std::sync::atomic::Ordering::Relaxed)
                        && slot.state() != ForkState::Preparing
                })
                .map(|(key, slot)| (key.clone(), slot.clone()))
                .collect();
            // Release the map before the expensive part: reclaim holds only
            // each slot's own lock across check/close/release/unlink. The
            // tombstoned slot stays in the map with its reservation charged,
            // so no same-key replacement can be created and no bytes go
            // unreserved while cleanup runs. Cancellation or errors leave
            // the same Dirty, retained state for rebuild.
            drop(entries);
            for (candidate, slot) in candidates {
                if !slot.speculative.load(std::sync::atomic::Ordering::Relaxed)
                    || slot.state() == ForkState::Preparing
                {
                    continue;
                }
                let Ok(mut inner) = slot.inner.try_lock() else {
                    continue;
                };
                {
                    let map = self.entries.lock().await;
                    // Only retire the exact slot vetted above: a concurrent
                    // demand may have claimed it (clearing speculative) while
                    // the map was unlocked.
                    let eligible = map.items.get(&candidate).is_some_and(|live| {
                        Arc::ptr_eq(live, &slot)
                            && live.speculative.load(std::sync::atomic::Ordering::Relaxed)
                            && live.state() != ForkState::Preparing
                    });
                    if !eligible {
                        continue;
                    }
                    slot.set_state(ForkState::Dirty);
                }
                if let Some(handle) = inner.handle.as_ref() {
                    handle.check(&self.area)?;
                    handle.db.close().await;
                    crate::coedit::live::release_idle_database(&handle.db);
                    // Deterministic test seam (no-op in production builds):
                    // fail injection happens before any mutation; reaching the
                    // unlink gate only waits when the test armed a oneshot.
                    #[cfg(test)]
                    {
                        let mut hook = self.unlink_hook.lock().await;
                        if let Some(hook) = hook.as_mut() {
                            if hook.fail_unlink {
                                return Err(
                                    std::io::Error::other("test-injected unlink failure").into()
                                );
                            }
                            if let Some(reached) = hook.reached.take() {
                                let _ = reached.send(());
                                hook.release.notified().await;
                            }
                        }
                    }
                    std::fs::remove_dir_all(&handle.directory)?;
                }
                inner.handle = None;
                // Keep Dirty across the final map wait: publishing Absent
                // happens atomically with deduction and removal below, so
                // cancellation can never strand a charged Absent slot that no
                // rebuild path accepts.
                #[cfg(test)]
                {
                    let mut hook = self.unlink_hook.lock().await;
                    if let Some(hook) = hook.as_mut() {
                        if let Some(settled) = hook.settled.take() {
                            let _ = settled.send(());
                            hook.release.notified().await;
                        }
                    }
                }
                {
                    let mut map = self.entries.lock().await;
                    // Publish Absent together with deduction and removal: no
                    // await can intervene, so cancellation cannot strand a
                    // charged Absent slot that rebuild refuses. A failure
                    // above leaves Dirty (with or without a handle) plus
                    // the reservation for rebuild.
                    if map
                        .items
                        .get(&candidate)
                        .is_some_and(|live| Arc::ptr_eq(live, &slot))
                    {
                        slot.set_state(ForkState::Absent);
                        map.reserved -= slot.reservation;
                        map.items.remove(&candidate);
                    }
                }
                {
                    let map = self.entries.lock().await;
                    if fits(&map) {
                        break;
                    }
                }
            }
            // Re-acquire the same binding for the capacity check and
            // insertion below (assignment drops nothing: the old guard
            // was released before the loop).
            entries = self.entries.lock().await;
            // A concurrent prepare may have created the requested key while
            // the map was unlocked: reuse it with the identical base-handle
            // validation and demand claiming as the pre-reclaim check, instead
            // of replacing it (double charge, orphaned copy) or refusing a
            // slot that now exists.
            if let Some(entry) = entries.items.get(&key).cloned() {
                if entry.base.handle_id() != base.handle_id() {
                    return Err(refuse("window base changed"));
                }
                if !speculative {
                    entry
                        .speculative
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                }
                return Ok(entry.state());
            }
        }
        if !fits(&entries) {
            eprintln!("[native-ce-outbox-fork] capacity_refused required_bytes={reservation} available_bytes={} slots={} max_slots={}", self.limits.max_reserved_bytes.saturating_sub(entries.reserved), entries.items.len(), self.limits.max_forks);
            return Err(not_ready("copy capacity exhausted; not accepted"));
        }
        let permit = if speculative {
            Some(
                self.workers
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| not_ready("prewarm copy worker busy; skipped"))?,
            )
        } else {
            None
        };
        let entry = Arc::new(EntrySlot {
            #[cfg(feature = "v2-kernel-probe")]
            changed: tokio::sync::Notify::new(),
            state: std::sync::Mutex::new(ForkState::Preparing),
            base,
            reservation,
            speculative: std::sync::atomic::AtomicBool::new(speculative),
            inner: Arc::new(Mutex::new(Entry {
                handle: None,
                pending_confirmation: None,
                published_keys: vec![],
            })),
        });
        entries.reserved += reservation;
        entries.items.insert(key.clone(), entry.clone());
        drop(entries);
        let manager = self.clone();
        tokio::spawn(async move {
            let _state_guard = Rebuilding(entry.clone());
            let _permit = match permit {
                Some(permit) => permit,
                None => manager
                    .workers
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("manager semaphore stays open"),
            };
            // Do not hold the entry lock during copying: status must say Preparing.
            let base = entry.base.clone();
            let prepared = manager.copy(&base).await;
            let mut state = entry.inner.lock().await;
            match prepared {
                Ok(handle) => {
                    let fits =
                        footprint(&handle.directory).is_ok_and(|bytes| bytes <= entry.reservation);
                    state.handle = Some(handle);
                    entry.set_state(if fits {
                        ForkState::Ready
                    } else {
                        ForkState::Failed
                    });
                    eprintln!("[native-ce-outbox-fork] footprint_checked fits={fits} reservation_bytes={}", entry.reservation);
                }
                Err(_) => {
                    entry.set_state(ForkState::Failed);
                }
            }
        });
        Ok(ForkState::Preparing)
    }

    fn validate_contract(&self, operation: &str, arguments: &Value) -> Result<()> {
        // Bound input before traversing the ordinary JSON Schema.
        if arguments.to_string().len() > self.limits.max_call_bytes {
            return Err(refuse("call too large"));
        }
        let validator = self
            .validators
            .get(operation)
            .ok_or_else(|| unsupported("unsupported operation"))?;
        validator
            .validate(arguments)
            .map_err(|error| refuse(&format!("ordinary contract refused: {error}")))
    }

    async fn entry(&self, key: &ForkKey) -> Result<Arc<EntrySlot>> {
        self.entries
            .lock()
            .await
            .items
            .get(key)
            .cloned()
            .ok_or_else(|| not_ready("fork absent"))
    }

    pub async fn state(&self, key: &ForkKey) -> ForkState {
        match self.entry(key).await {
            Ok(entry) => entry.state(),
            Err(_) => ForkState::Absent,
        }
    }

    async fn copy(&self, base: &Db) -> Result<ForkHandle> {
        let started = std::time::Instant::now();
        let mut stage = "area";
        eprintln!("[native-ce-outbox-fork] preparation_started");
        let result = self.copy_with_diagnostics(base, &mut stage).await;
        match &result {
            Ok(_) => eprintln!(
                "[native-ce-outbox-fork] preparation_finished elapsed_ms={}",
                started.elapsed().as_millis()
            ),
            Err(error) => {
                let (category, code) = diagnostic_error(error);
                eprintln!("[native-ce-outbox-fork] preparation_failed stage={stage} category={category} code={code:?} elapsed_ms={}", started.elapsed().as_millis());
            }
        }
        result
    }

    async fn copy_with_diagnostics(
        &self,
        base: &Db,
        stage: &mut &'static str,
    ) -> Result<ForkHandle> {
        self.area.check()?;
        // The unique private directory is the path capability. Tool arguments
        // and catalog locators never participate in generating these paths.
        let directory = self.area.root.join(Uuid::new_v4().to_string());
        *stage = "directory";
        self::directory(&directory, true)?;
        let directory_identity = identity(&directory, true)?;
        let partial = directory.join("partial.sqlite");
        let path = directory.join("fork.sqlite");
        let result = async {
            *stage = "frontier";
            let frontier = frontier(base).await?;
            *stage = "vacuum";
            #[cfg(test)]
            self.copy_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            eprintln!("[native-ce-outbox-fork] preparation_stage stage=vacuum");
            // SQLite's default 0644 output depends on the process umask.
            // Precreate ONLY this new v2 destination before SQLite opens it;
            // subsequent WAL/SHM files inherit the private main-file mode.
            #[cfg(all(unix, feature = "v2-kernel-probe"))]
            let private_output = if self.kernel_v2 {
                use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&partial)?;
                let meta = file.metadata()?;
                let expected = FileIdentity(meta.dev(), meta.ino());
                if identity(&partial, false)? != expected {
                    return Err(ForkError::Uncertain(Error::engine(
                        "private fork destination substituted",
                    )));
                }
                Some((file, expected))
            } else {
                None
            };
            sqlx::query("VACUUM INTO ?")
                .bind(partial.to_str().ok_or_else(|| refuse("non-UTF8 path"))?)
                .execute(base.pool())
                .await?;
            *stage = "identity";
            self.area.check()?;
            if identity(&directory, true)? != directory_identity {
                return Err(ForkError::Uncertain(Error::engine(
                    "preparing directory substituted",
                )));
            }
            identity(&partial, false)?;
            #[cfg(all(unix, feature = "v2-kernel-probe"))]
            if let Some((file, expected)) = private_output {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                let meta = file.metadata()?;
                if identity(&partial, false)? != expected
                    || FileIdentity(meta.dev(), meta.ino()) != expected
                    || meta.nlink() != 1
                    || meta.uid() != crate::node::current_uid()
                    || meta.permissions().mode() & 0o777 != 0o600
                {
                    return Err(ForkError::Uncertain(Error::engine(
                        "private fork destination identity or mode changed",
                    )));
                }
                file.sync_all()?;
            }
            // Verify with the normal opener, drain/close before rename (including
            // WAL/capture pools), then reopen the published filename directly.
            *stage = "verify_partial";
            eprintln!("[native-ce-outbox-fork] preparation_stage stage=verify_partial");
            #[cfg(feature = "v2-kernel-probe")]
            let verified = if self.kernel_v2 {
                crate::db::open_existing_v2_file(
                    partial.to_str().ok_or_else(|| refuse("non-UTF8 path"))?,
                )
                .await?
            } else {
                crate::db::open_receiver_fork_at(&partial).await?
            };
            #[cfg(not(feature = "v2-kernel-probe"))]
            let verified = crate::db::open_receiver_fork_at(&partial).await?;
            *stage = "close_partial";
            verified.close().await;
            *stage = "publish";
            std::fs::rename(&partial, &path)?;
            *stage = "open_published";
            eprintln!("[native-ce-outbox-fork] preparation_stage stage=open_published");
            #[cfg(feature = "v2-kernel-probe")]
            let db = if self.kernel_v2 {
                crate::db::open_existing_v2_file(
                    path.to_str().ok_or_else(|| refuse("non-UTF8 path"))?,
                )
                .await?
            } else {
                crate::db::open_receiver_fork_at(&path).await?
            };
            #[cfg(not(feature = "v2-kernel-probe"))]
            let db = crate::db::open_receiver_fork_at(&path).await?;
            *stage = "registry";
            let mut registry = ToolRegistry::new();
            registry.copy_presentation_from(&self.presentation);
            #[cfg(feature = "v2-kernel-probe")]
            let registered = if self.kernel_v2 {
                // Mirror the established v2 registry assembly: builtin and
                // surface descriptors first, then the KernelV2 handlers.
                crate::mcp::register_builtin_tools(&mut registry)
                    .and_then(|_| register_surface_tools(&mut registry))
                    .and_then(|_| crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry))
            } else {
                register_surface_tools(&mut registry)
            };
            #[cfg(not(feature = "v2-kernel-probe"))]
            let registered = register_surface_tools(&mut registry);
            if let Err(error) = registered {
                db.close().await;
                return Err(error.into());
            }
            Ok(ForkHandle {
                file_identity: identity(&path, false)?,
                db,
                registry,
                directory: directory.clone(),
                directory_identity,
                base_frontier: frontier,
                capture: None,
            })
        }
        .await;
        if result.is_err() && identity(&directory, true).ok() == Some(directory_identity) {
            let _ = std::fs::remove_dir_all(&directory);
        }
        result
    }

    /// Serial speculative execution. The fork is dirty before the handler can
    /// commit. Clean domain refusals with an unchanged frontier restore Ready;
    /// uncertain errors/cancellation retain Dirty, including post-commit rendering errors. The returned evidence is not a public acceptance acknowledgement.
    pub async fn dispatch(
        &self,
        key: &ForkKey,
        caller: &Caller,
        call: &PreparedCall,
    ) -> Result<ForkOutcome> {
        check_binding(key, caller)?;
        validate_shape(
            &call.operation,
            &call.arguments,
            false,
            self.limits.max_call_bytes,
        )?;
        self.validate_contract(&call.operation, &call.arguments)?;
        let slot = self.entry(key).await?;
        let mut entry = slot.inner.try_lock().map_err(|_| not_ready("fork busy"))?;
        require_ready(&slot)?;
        if call
            .caller
            .as_ref()
            .is_some_and(|author| author.credential() != caller.credential())
        {
            return Err(refuse("prepared author changed"));
        }
        self.validate_prepared(&slot, caller, call).await?;
        let handle = entry
            .handle
            .as_ref()
            .ok_or_else(|| refuse("missing fork handle"))?;
        if let Err(error) = handle.check(&self.area) {
            slot.set_state(ForkState::Dirty);
            return Err(error);
        }
        validate_target(handle, call).await?;
        slot.set_state(ForkState::Dirty);
        entry.pending_confirmation = None;
        let handle = entry.handle.as_ref().expect("checked handle");
        let before = frontier(&handle.db).await?;
        // No caller-supplied Db/registry; dispatch uses the manager's bound
        // handle and this write's authenticated caller.
        let result = handle
            .registry
            .call(
                handle.db.clone(),
                caller.clone(),
                &call.operation,
                call.arguments.clone(),
            )
            .await;
        if handle.capture.is_some() {
            handle.db.drain_captures().await;
        }
        handle.check(&self.area)?;
        if let Err(error) = result {
            // The allowlist uses one transactional content write. Only typed
            // domain refusals with no new content may restore Ready; failed
            // rendering after commit, SQL/I/O failures and cancellation stay dirty.
            if clean_domain_refusal(&error)
                && frontier(&handle.db).await? == before
                && footprint(&handle.directory)? <= slot.reservation
            {
                slot.set_state(ForkState::Ready);
                return Err(ForkError::RefusedInvalid(error));
            }
            return Err(ForkError::Uncertain(error));
        }
        if footprint(&handle.directory)? > slot.reservation {
            return Err(ForkError::Uncertain(Error::engine(
                "fork exceeded byte reservation; rebuild required",
            )));
        }
        let outcome = ForkOutcome {
            idempotency_key: call.idempotency_key().into(),
            create_id: call.create_id().map(str::to_owned),
            touched_record_ids: handle.touched().await?,
            frontier: frontier(&handle.db).await?,
            confirmation: Uuid::new_v4(),
            publication_key: publication_key(
                caller.credential(),
                &call.operation,
                call.idempotency_key(),
            ),
        };
        entry.pending_confirmation = Some(outcome.confirmation);
        Ok(outcome)
    }

    /// Call only after the matching prepared call is durably in the journal.
    /// A lost outcome/token cannot publish an uncertain fork; rebuild instead.
    pub async fn confirm_journaled(&self, key: &ForkKey, outcome: &ForkOutcome) -> Result<()> {
        let slot = self.entry(key).await?;
        let mut entry = slot.inner.try_lock().map_err(|_| not_ready("fork busy"))?;
        if slot.state() != ForkState::Dirty
            || entry.pending_confirmation != Some(outcome.confirmation)
        {
            return Err(refuse("stale journal confirmation"));
        }
        entry
            .handle
            .as_ref()
            .ok_or_else(|| refuse("missing handle"))?
            .check(&self.area)?;
        entry.pending_confirmation = None;
        entry.published_keys.push(outcome.publication_key.clone());
        slot.set_state(ForkState::Ready);
        Ok(())
    }

    /// Read only a published generation, under the same lock as speculative
    /// dispatch. No unjournaled or rebuilding content can escape this boundary.
    pub async fn get_record(
        &self,
        key: &ForkKey,
        caller: &Caller,
        arguments: Value,
    ) -> Result<(Value, Vec<String>, Vec<String>)> {
        self.preview_read(key, caller, "get_record", arguments)
            .await
    }

    /// Ordinary read against the same published workspace generation as get_record.
    pub async fn preview_read(
        &self,
        key: &ForkKey,
        caller: &Caller,
        operation: &str,
        arguments: Value,
    ) -> Result<(Value, Vec<String>, Vec<String>)> {
        if !matches!(operation, "get_record" | "search") {
            return Err(refuse("unsupported preview read"));
        }
        check_binding(key, caller)?;
        let slot = self.entry(key).await?;
        let entry = slot.inner.try_lock().map_err(|_| not_ready("fork busy"))?;
        require_ready(&slot)?;
        let handle = entry
            .handle
            .as_ref()
            .ok_or_else(|| not_ready("missing handle"))?;
        handle.check(&self.area)?;
        let value = handle
            .registry
            .call(handle.db.clone(), caller.clone(), operation, arguments)
            .await
            .map_err(classify_preflight)?;
        Ok((value, handle.touched().await?, entry.published_keys.clone()))
    }

    pub async fn published_keys(&self, key: &ForkKey) -> Result<Vec<String>> {
        let slot = self.entry(key).await?;
        let entry = slot.inner.try_lock().map_err(|_| not_ready("fork busy"))?;
        require_ready(&slot)?;
        Ok(entry.published_keys.clone())
    }

    pub async fn touched_record_ids(&self, key: &ForkKey) -> Result<Vec<String>> {
        let slot = self.entry(key).await?;
        let entry = slot.inner.try_lock().map_err(|_| not_ready("fork busy"))?;
        require_ready(&slot)?;
        let handle = entry
            .handle
            .as_ref()
            .ok_or_else(|| refuse("missing handle"))?;
        handle.check(&self.area)?;
        handle.touched().await
    }

    /// Opt-in node admission, before any speculative dispatch. Other fork
    /// consumers retain the existing copy/rebuild machinery unchanged.
    pub(crate) async fn enable_rebase(&self, key: &ForkKey) -> Result<()> {
        let slot = self.entry(key).await?;
        let mut entry = slot.inner.lock().await;
        require_ready(&slot)?;
        let handle = entry
            .handle
            .as_mut()
            .ok_or_else(|| refuse("missing fork"))?;
        if handle.capture.is_none() {
            handle.db.constrain_pending_writer().await?;
            handle.capture = Some(rebase::Capture::install(&handle.db).await?);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn copy_count_for_test(&self) -> u64 {
        self.copy_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) async fn test_working_db(&self, key: &ForkKey) -> Result<Db> {
        let slot = self.entry(key).await?;
        let entry = slot.inner.lock().await;
        Ok(entry
            .handle
            .as_ref()
            .ok_or_else(|| refuse("missing fork"))?
            .db
            .clone())
    }

    /// Called by the node owner with refresh's original transport-trusted
    /// object after the accepted commit. This touches only private bytes. On
    /// ANY error the owner discards the slot and invokes its original full-copy path.
    pub(crate) async fn rebase_accepted(
        &self,
        key: &ForkKey,
        delta: &crate::standby::act_materialise::TrustedAuthorityActDelta,
        journal_revision: &str,
    ) -> Result<()> {
        let slot = self.entry(key).await?;
        let mut entry = slot.inner.lock().await;
        require_ready(&slot)?;
        slot.set_state(ForkState::Dirty);
        let handle = entry
            .handle
            .as_mut()
            .ok_or_else(|| refuse("missing fork"))?;
        handle.check(&self.area)?;
        handle.db.drain_captures().await;
        handle.db.invalidate_pending_caches().await?;
        let capture = handle
            .capture
            .as_ref()
            .ok_or_else(|| refuse("capture gap"))?;
        let (schema, epoch) = capture.binding();
        let marker = handle.directory.join("rebase-in-progress");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)?;
        use std::io::Write;
        file.write_all(
            serde_json::to_string(&serde_json::json!({
                "key":key,"from":delta.from_exclusive_act(),"to":delta.to_inclusive_act(),
                "schema":schema,"capture_epoch":epoch,"journal_revision":journal_binding(journal_revision),
            }))?
            .as_bytes(),
        )?;
        file.sync_all()?;
        std::fs::File::open(&handle.directory)?.sync_all()?;
        capture.undo().await?;
        crate::standby::act_materialise::apply_authority_act_delta_and_finalize_head(
            &handle.db, delta,
        )
        .await?;
        handle.base_frontier = frontier(&handle.db).await?;
        handle.db.invalidate_pending_caches().await?;
        capture.rearm().await?;
        entry.pending_confirmation = None;
        entry.published_keys.clear();
        // The node serializes replay and read publication under its owner lock.
        // The marker remains until its new journal snapshot has been persisted.
        slot.set_state(ForkState::Ready);
        Ok(())
    }

    pub(crate) async fn finish_rebase(
        &self,
        key: &ForkKey,
        head: i64,
        snapshot: &str,
    ) -> Result<()> {
        let slot = self.entry(key).await?;
        let entry = slot.inner.lock().await;
        require_ready(&slot)?;
        let handle = entry
            .handle
            .as_ref()
            .ok_or_else(|| refuse("missing fork"))?;
        handle.check(&self.area)?;
        handle.db.drain_captures().await;
        if let Some(capture) = &handle.capture {
            capture.verify().await?;
            let (schema, epoch) = capture.binding();
            let path = handle.directory.join("pending-binding");
            let next = handle.directory.join("pending-binding-next");
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&next)?;
            use std::io::Write;
            file.write_all(serde_json::to_string(&serde_json::json!({"key":key,"head":head,"journal":journal_binding(snapshot),"schema":schema,"capture_epoch":epoch}))?.as_bytes())?;
            file.sync_all()?;
            std::fs::rename(next, path)?;
            // The replacement's directory entry must be durable BEFORE marker
            // removal, even if the process/power fails between those steps.
            std::fs::File::open(&handle.directory)?.sync_all()?;
            if footprint(&handle.directory)? > slot.reservation {
                return Err(ForkError::Uncertain(Error::engine(
                    "pending binding exceeds reservation",
                )));
            }
            let marker = handle.directory.join("rebase-in-progress");
            if marker.exists() {
                std::fs::remove_file(marker)?;
            }
            std::fs::File::open(&handle.directory)?.sync_all()?;
        }
        Ok(())
    }

    /// Drop all speculative state, then replay only supplied durable calls in
    /// order. Failure leaves the fork Dirty and unavailable. Restarts never adopt
    /// files from disk: construct a manager, prepare and rebuild from the journal.
    pub async fn rebuild(
        self: &Arc<Self>,
        key: &ForkKey,
        journal: &dyn OrderedJournaledCalls,
    ) -> Result<Vec<String>> {
        let slot = self.entry(key).await?;
        // Journal acquisition is cancellable before changing any fork state.
        let calls = journal.ordered_calls(key).await?;
        let entry = slot
            .inner
            .clone()
            .try_lock_owned()
            .map_err(|_| not_ready("fork busy"))?;
        if matches!(slot.state(), ForkState::Preparing | ForkState::Absent) {
            return Err(not_ready("copy preparing or fork discarded"));
        }
        slot.set_state(ForkState::Preparing);
        let manager = self.clone();
        let key_for_rebuild = key.clone();
        // Detach work from the requesting future. Cancellation cannot abandon a
        // VACUUM file or its reservation; this task owns them until completion.
        tokio::spawn(async move {
            let _state_guard = Rebuilding(slot.clone());
            let mut entry = entry;
            entry.pending_confirmation = None;
            if let Some(old) = entry.handle.as_ref() {
                old.check(&manager.area)?;
                old.db.close().await;
                crate::coedit::live::release_idle_database(&old.db);
                std::fs::remove_dir_all(&old.directory)?;
            }
            entry.handle = None;
            {
                let _permit = manager
                    .workers
                    .acquire()
                    .await
                    .map_err(|_| not_ready("copy worker closed"))?;
                entry.handle = Some(manager.copy(&slot.base).await?);
            }
            let handle = entry.handle.as_ref().expect("new copy");
            let published_keys = calls.iter().map(PreparedCall::publication_key).collect();
            for call in calls {
                let caller = call
                    .caller
                    .as_ref()
                    .ok_or_else(|| refuse("journal caller not verified"))?;
                check_binding(&key_for_rebuild, caller)?;
                manager.validate_prepared(&slot, caller, &call).await?;
                validate_target(handle, &call).await?;
                handle
                    .registry
                    .call(
                        handle.db.clone(),
                        caller.clone(),
                        &call.operation,
                        call.arguments,
                    )
                    .await?;
            }
            handle.check(&manager.area)?;
            if footprint(&handle.directory)? > slot.reservation {
                return Err(ForkError::Uncertain(Error::engine(
                    "rebuilt fork exceeds reservation",
                )));
            }
            let touched = handle.touched().await?;
            entry.published_keys = published_keys;
            slot.set_state(ForkState::Ready);
            Ok(touched)
        })
        .await
        .map_err(|error| ForkError::Uncertain(Error::engine(error.to_string())))?
    }

    async fn validate_prepared(
        &self,
        slot: &EntrySlot,
        caller: &Caller,
        call: &PreparedCall,
    ) -> Result<()> {
        validate_shape(
            &call.operation,
            &call.arguments,
            false,
            self.limits.max_call_bytes,
        )?;
        self.validate_contract(&call.operation, &call.arguments)?;
        if matches!(
            (call.create_id.as_deref(), call.arguments.get("id").and_then(Value::as_str)),
            (Some(metadata), Some(argument)) if metadata != argument
        ) {
            return Err(refuse("prepared create id mismatch"));
        }
        string(
            call.arguments.as_object().expect("validated object"),
            "idempotency_key",
        )?;
        if call.operation == "create_record" && call.arguments.get("id").is_none() {
            let replay = crate::provenance::existing_create_replay_arguments(
                &slot.base,
                caller.credential(),
                &call.arguments,
                &crate::provenance::CommandAppContext::no_app(),
            )
            .await
            .map_err(classify_preflight)?;
            if !replay.is_some_and(|(id, arguments)| {
                call.create_id() == Some(id.as_str()) && call.arguments == arguments
            }) {
                return Err(refuse(
                    "id-less prepared create must replay a frozen-base command",
                ));
            }
        }
        let run = call.arguments["run_key"]
            .as_str()
            .ok_or_else(|| refuse("existing run required"))?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM agent_runs WHERE run_key=? AND account_id=?)",
        )
        .bind(run)
        .bind(caller.credential())
        .fetch_one(slot.base.pool())
        .await?;
        if !exists {
            return Err(refuse("run must exist in the frozen base for this author"));
        }
        Ok(())
    }

    /// Drain one key without holding the manager map lock. Keep its slot in the
    /// map until drainage completes so another prepare cannot race its cleanup.
    pub async fn discard(&self, key: &ForkKey) -> Result<()> {
        let slot = self.entries.lock().await.items.get(key).cloned();
        if let Some(slot) = slot {
            let mut entry = slot.inner.try_lock().map_err(|_| not_ready("fork busy"))?;
            if slot.state() == ForkState::Preparing {
                return Err(not_ready("copy still preparing"));
            }
            slot.set_state(ForkState::Dirty);
            if let Some(handle) = entry.handle.as_ref() {
                handle.check(&self.area)?;
                if let Some(capture) = &handle.capture {
                    capture.drain().await;
                }
                handle.db.close().await;
                crate::coedit::live::release_idle_database(&handle.db);
                std::fs::remove_dir_all(&handle.directory)?;
            }
            entry.handle = None;
            slot.set_state(ForkState::Absent);
            let mut entries = self.entries.lock().await;
            entries.reserved -= slot.reservation;
            entries.items.remove(key);
        }
        Ok(())
    }
}

/// Private KernelV2 working engine (see docs/node-v2-pending-engine.md).
///
/// The same fork machinery as the v1 hosted-outbox path — [`ForkArea`], copy
/// workers, slot lifecycle, [`ForkManager::confirm_journaled`] gating — but
/// dispatching through the actual KernelV2 handlers with
/// [`EngineHandle::KernelV2`]. Scope is plain note create/read/append only.
/// No routing, no flags, no deployment, no copy-free rebase: reconstruction
/// copies once per rebuild and must not become the ordinary refresh loop.
#[cfg(feature = "v2-kernel-probe")]
impl ForkManager {
    /// Key helper for the private engine: the window carries the exact
    /// account credential the engine was prepared for, so a different
    /// account can never address the same slot.
    pub fn kernel_v2_key(credential: &str, workspace: &str) -> ForkKey {
        ForkKey {
            window_id: format!("v2-working:{}", credential.trim()),
            workspace_id: workspace.into(),
        }
    }

    fn require_kernel_v2(&self) -> Result<()> {
        if self.kernel_v2 {
            Ok(())
        } else {
            Err(refuse("kernel-v2 call on a v1 fork manager"))
        }
    }

    /// Normalize once and retain the key; the durable journal must hold these
    /// same arguments before dispatch. Unlike the v1 path this mints no
    /// record IDs: ordinary v2 create rejects caller-supplied IDs, so the
    /// kernel mints private IDs at dispatch. `create_id` stays `None`.
    /// Device-minted final IDs (ratified `a85e61a`) arrive via the
    /// verified-ID seam, never via provisional mapping (see the design note).
    pub async fn prepare_call_kernel_v2(
        &self,
        key: &ForkKey,
        caller: &Caller,
        operation: &str,
        mut arguments: Value,
    ) -> Result<PreparedCall> {
        self.require_kernel_v2()?;
        check_binding_kernel_v2(key, caller)?;
        if matches!(operation, "get_record" | "search") {
            return Err(refuse("reads are not prepared calls"));
        }
        validate_shape_kernel_v2(operation, &arguments, self.limits.max_call_bytes)?;
        let object = arguments
            .as_object_mut()
            .ok_or_else(|| refuse("expected object"))?;
        if !object.contains_key("idempotency_key") {
            object.insert(
                "idempotency_key".into(),
                Value::String(Uuid::new_v4().to_string()),
            );
        }
        let trimmed = object["idempotency_key"]
            .as_str()
            .expect("validated key")
            .trim()
            .to_owned();
        object.insert("idempotency_key".into(), Value::String(trimmed));
        // Resolve the caller against the accepted base through the real v2
        // account/principal binding: no advisory fork identity, no minted grants.
        let slot = self.entry(key).await?;
        crate::mcp::kernel_v2::principal(&slot.base, caller)
            .await
            .map_err(classify_preflight)?;
        Ok(PreparedCall {
            operation: operation.into(),
            arguments,
            create_id: None,
            caller: Some(caller.clone()),
        })
    }

    /// Serial speculative execution on the private working copy. Same
    /// Dirty-before-commit discipline as the v1 path: clean domain refusals
    /// with an unchanged frontier restore Ready, everything else stays Dirty.
    /// Keyed replays are answered by v2's event-backed receipts inside the
    /// working copy; no other receipt ledger exists.
    pub async fn dispatch_kernel_v2(
        &self,
        key: &ForkKey,
        caller: &Caller,
        call: &PreparedCall,
    ) -> Result<ForkOutcome> {
        self.require_kernel_v2()?;
        check_binding_kernel_v2(key, caller)?;
        validate_shape_kernel_v2(&call.operation, &call.arguments, self.limits.max_call_bytes)?;
        let slot = self.entry(key).await?;
        let mut entry = slot.inner.try_lock().map_err(|_| not_ready("fork busy"))?;
        require_ready(&slot)?;
        if call
            .caller
            .as_ref()
            .is_some_and(|author| author.credential() != caller.credential())
        {
            return Err(refuse("prepared author changed"));
        }
        self.validate_prepared_kernel_v2(&slot, caller, call)
            .await?;
        let handle = entry
            .handle
            .as_ref()
            .ok_or_else(|| refuse("missing fork handle"))?;
        if let Err(error) = handle.check(&self.area) {
            slot.set_state(ForkState::Dirty);
            return Err(error);
        }
        // The plain-note append scope is enforced here, before anything is
        // dirtied: a refused target leaves the slot Ready. Handler
        // capability checks remain authoritative beyond this gate.
        validate_target_kernel_v2(handle, caller, call).await?;
        slot.set_state(ForkState::Dirty);
        entry.pending_confirmation = None;
        let handle = entry.handle.as_ref().expect("checked handle");
        let before = frontier(&handle.db).await?;
        // No caller-supplied Db/registry: dispatch uses the manager's bound
        // handle and this write's authenticated caller.
        let result = handle
            .registry
            .call_engine(
                crate::mcp::EngineHandle::KernelV2(handle.db.clone()),
                caller.clone(),
                &call.operation,
                call.arguments.clone(),
            )
            .await;
        handle.check(&self.area)?;
        if let Err(error) = result {
            if clean_domain_refusal(&error)
                && frontier(&handle.db).await? == before
                && footprint(&handle.directory)? <= slot.reservation
            {
                slot.set_state(ForkState::Ready);
                return Err(ForkError::RefusedInvalid(error));
            }
            return Err(ForkError::Uncertain(error));
        }
        if footprint(&handle.directory)? > slot.reservation {
            return Err(ForkError::Uncertain(Error::engine(
                "fork exceeded byte reservation; rebuild required",
            )));
        }
        let outcome = ForkOutcome {
            idempotency_key: call.idempotency_key().into(),
            create_id: None,
            touched_record_ids: handle.touched_domain().await?,
            frontier: frontier(&handle.db).await?,
            confirmation: Uuid::new_v4(),
            publication_key: publication_key(
                caller.credential(),
                &call.operation,
                call.idempotency_key(),
            ),
        };
        entry.pending_confirmation = Some(outcome.confirmation);
        Ok(outcome)
    }

    /// Read the private working copy only. This never falls back to the
    /// accepted base: it returns `NotReady` while rebuilding, so a pending
    /// note can never silently vanish into an accepted-only view here (see
    /// the continuity requirement in docs/node-v2-pending-engine.md).
    pub async fn preview_read_kernel_v2(
        &self,
        key: &ForkKey,
        caller: &Caller,
        operation: &str,
        arguments: Value,
    ) -> Result<(Value, Vec<String>, Vec<String>)> {
        self.require_kernel_v2()?;
        if !matches!(operation, "get_record" | "search") {
            return Err(refuse("unsupported preview read"));
        }
        check_binding_kernel_v2(key, caller)?;
        validate_shape_kernel_v2(operation, &arguments, self.limits.max_call_bytes)?;
        let slot = self.entry(key).await?;
        let entry = slot.inner.try_lock().map_err(|_| not_ready("fork busy"))?;
        require_ready(&slot)?;
        let handle = entry
            .handle
            .as_ref()
            .ok_or_else(|| not_ready("missing handle"))?;
        handle.check(&self.area)?;
        let value = handle
            .registry
            .call_engine(
                crate::mcp::EngineHandle::KernelV2(handle.db.clone()),
                caller.clone(),
                operation,
                arguments,
            )
            .await
            .map_err(classify_preflight)?;
        Ok((
            value,
            handle.touched_domain().await?,
            entry.published_keys.clone(),
        ))
    }

    /// Drop speculative state, copy once from the current base, then replay
    /// only the supplied durable calls in order. Failure leaves the fork
    /// Dirty and unavailable. Restarts never adopt files from disk: construct
    /// a manager, prepare and rebuild from the journal.
    pub async fn rebuild_kernel_v2(
        self: &Arc<Self>,
        key: &ForkKey,
        journal: &dyn OrderedJournaledCalls,
    ) -> Result<Vec<String>> {
        self.require_kernel_v2()?;
        // Journal acquisition is cancellable before changing any fork state.
        let calls = journal.ordered_calls(key).await?;
        for call in &calls {
            let caller = call
                .caller
                .as_ref()
                .ok_or_else(|| refuse("journal caller not verified"))?;
            check_binding_kernel_v2(key, caller)?;
            validate_shape_kernel_v2(
                call.operation(),
                call.arguments(),
                self.limits.max_call_bytes,
            )?;
        }
        let slot = self.entry(key).await?;
        let entry = slot
            .inner
            .clone()
            .try_lock_owned()
            .map_err(|_| not_ready("fork busy"))?;
        if matches!(slot.state(), ForkState::Preparing | ForkState::Absent) {
            return Err(not_ready("copy preparing or fork discarded"));
        }
        slot.set_state(ForkState::Preparing);
        let manager = self.clone();
        let key_for_rebuild = key.clone();
        // Detach work from the requesting future. Cancellation cannot abandon a
        // VACUUM file or its reservation; this task owns them until completion.
        tokio::spawn(async move {
            let _state_guard = Rebuilding(slot.clone());
            let mut entry = entry;
            entry.pending_confirmation = None;
            if let Some(old) = entry.handle.as_ref() {
                old.check(&manager.area)?;
                old.db.close().await;
                crate::coedit::live::release_idle_database(&old.db);
                std::fs::remove_dir_all(&old.directory)?;
            }
            entry.handle = None;
            {
                let _permit = manager
                    .workers
                    .acquire()
                    .await
                    .map_err(|_| not_ready("copy worker closed"))?;
                entry.handle = Some(manager.copy(&slot.base).await?);
            }
            let handle = entry.handle.as_ref().expect("new copy");
            let published_keys = calls.iter().map(PreparedCall::publication_key).collect();
            for call in calls {
                let caller = call
                    .caller
                    .as_ref()
                    .ok_or_else(|| refuse("journal caller not verified"))?;
                check_binding_kernel_v2(&key_for_rebuild, caller)?;
                manager
                    .validate_prepared_kernel_v2(&slot, caller, &call)
                    .await?;
                validate_target_kernel_v2(handle, caller, &call).await?;
                handle
                    .registry
                    .call_engine(
                        crate::mcp::EngineHandle::KernelV2(handle.db.clone()),
                        caller.clone(),
                        call.operation(),
                        call.arguments().clone(),
                    )
                    .await?;
            }
            handle.check(&manager.area)?;
            if footprint(&handle.directory)? > slot.reservation {
                return Err(ForkError::Uncertain(Error::engine(
                    "rebuilt fork exceeds reservation",
                )));
            }
            let touched = handle.touched_domain().await?;
            entry.published_keys = published_keys;
            slot.set_state(ForkState::Ready);
            Ok(touched)
        })
        .await
        .map_err(|error| ForkError::Uncertain(Error::engine(error.to_string())))?
    }

    async fn validate_prepared_kernel_v2(
        &self,
        slot: &EntrySlot,
        caller: &Caller,
        call: &PreparedCall,
    ) -> Result<()> {
        validate_shape_kernel_v2(
            call.operation(),
            call.arguments(),
            self.limits.max_call_bytes,
        )?;
        if call.create_id().is_some() {
            return Err(refuse("v2 prepared creates carry no client id"));
        }
        string(
            call.arguments.as_object().expect("validated object"),
            "idempotency_key",
        )?;
        // The caller must still resolve on the accepted base through the real
        // v2 binding. Local speculation never mints authority.
        crate::mcp::kernel_v2::principal(&slot.base, caller)
            .await
            .map_err(classify_preflight)?;
        Ok(())
    }
}

/// Append-target scope for the private KernelV2 engine: the target must be
/// an existing plain Document/note. Existence and kind are read from the
/// working copy, so privately created notes are addressable while internal
/// streams and other kinds are refused before anything is dirtied. Caller
/// visibility is checked first through the same engine access semantics as
/// the handlers, with a uniform missing-or-hidden outcome: a refused caller
/// learns nothing about whether the target exists, what kind it is, or who
/// else can see it. Only visible targets reach the kind diagnostics. Handler
/// capability checks remain authoritative beyond this gate.
#[cfg(feature = "v2-kernel-probe")]
async fn validate_target_kernel_v2(
    handle: &ForkHandle,
    caller: &Caller,
    call: &PreparedCall,
) -> Result<()> {
    if call.operation() != "update_record" {
        return Ok(());
    }
    let id = call
        .arguments
        .get("id")
        .or_else(|| call.arguments.get("record_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| refuse("single record id required"))?;
    if Uuid::parse_str(id).is_err() {
        return Err(unsupported(
            "append requires a full UUID; short references and aliases are unsupported",
        ));
    }
    // Visibility first, with the engine's own uniform outcome: missing and
    // hidden are indistinguishable here, exactly as in handler reads.
    let actor = crate::mcp::kernel_v2::principal(&handle.db, caller)
        .await
        .map_err(classify_preflight)?;
    let visible = crate::kernel::read_record_as(&handle.db, &actor, id)
        .await
        .map_err(classify_preflight)?
        .is_some();
    if !visible {
        return Err(ForkError::RefusedInvalid(Error::engine(
            crate::kernel::HIDDEN_OR_MISSING,
        )));
    }
    type FormatRow = (Option<String>, Option<String>, Option<String>, Option<i64>);
    let row: Option<FormatRow> = sqlx::query_as(
        "SELECT primary_type,kind,pin_family,pin_version FROM kernel_records WHERE id=?",
    )
    .bind(id)
    .fetch_optional(handle.db.pool())
    .await?;
    let Some((record_type, kind, family, pin_version)) = row else {
        // Unreachable when the visibility gate above passed, kept uniform.
        return Err(ForkError::RefusedInvalid(Error::engine(
            crate::kernel::HIDDEN_OR_MISSING,
        )));
    };
    // No family pin means no claimed kind: fail closed rather than admit
    // untyped rows outside the two supported families.
    if family.is_none() {
        return Err(unsupported("append target must be a plain Document/note"));
    }
    if family.as_deref() == Some(crate::v2_standard::DOCUMENT_FAMILY) {
        if record_type.as_deref() == Some("Document") && kind.as_deref() == Some("note") {
            return Ok(());
        }
        return Err(unsupported("append target must be a plain Document/note"));
    }
    if pin_version != Some(1) || family.as_deref() != Some(crate::v2_standard::v1_compat::FAMILY) {
        return Err(unsupported("append target must be a plain Document/note"));
    }
    // v1-imported records resolve through their v1_type/v1_kind fields,
    // falling back to the row values (mirroring the publications surface).
    let fields: Vec<(String, String)> = sqlx::query_as(
        "SELECT name,value_json FROM kernel_record_fields WHERE record_id=? AND name IN ('v1_type','v1_kind')",
    )
    .bind(id)
    .fetch_all(handle.db.pool())
    .await?;
    let field = |key: &str| {
        fields
            .iter()
            .find(|(name, _)| name == key)
            .and_then(|(_, value)| serde_json::from_str::<String>(value).ok())
    };
    let record_type = field("v1_type").or(record_type);
    let kind = field("v1_kind").or(kind);
    if matches!(
        (record_type.as_deref(), kind.as_deref()),
        (Some("Document"), Some("note"))
    ) {
        Ok(())
    } else {
        Err(unsupported("append target must be a plain Document/note"))
    }
}

/// Author/workspace binding for the private KernelV2 engine. The window
/// carries the exact account credential prepared for this slot; any other
/// credential — including another valid account — is refused before dispatch.
#[cfg(feature = "v2-kernel-probe")]
fn check_binding_kernel_v2(key: &ForkKey, caller: &Caller) -> Result<()> {
    if key.workspace_id.trim().is_empty() {
        return Err(refuse("workspace binding required"));
    }
    if caller.credential().trim().is_empty() {
        return Err(refuse("author/workspace binding mismatch"));
    }
    if key.window_id != format!("v2-working:{}", caller.credential()) {
        return Err(refuse("author/workspace binding mismatch"));
    }
    Ok(())
}

/// Minimal shape gate for the private-engine increment: plain notes only.
/// The KernelV2 handlers remain the authority beyond this gate.
#[cfg(feature = "v2-kernel-probe")]
/// Installed working create admission is distinct from the legacy speculative
/// fork API, whose caller-ID refusal remains unchanged.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) fn validate_working_shape_kernel_v2(
    operation: &str,
    args: &Value,
    max_bytes: usize,
) -> Result<()> {
    if operation != "create_record" {
        return validate_shape_kernel_v2(operation, args, max_bytes);
    }
    if args.to_string().len() > max_bytes {
        return Err(refuse("call too large"));
    }
    let mut source = args.clone();
    let object = source
        .as_object_mut()
        .ok_or_else(|| refuse("expected argument object"))?;
    object.remove("id");
    object.remove("id_nonce");
    crate::mcp::kernel_v2::writes::replay::validate_first_party_create_source(&source)
        .map_err(|e| refuse(&e.to_string()))?;
    let id = args
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| refuse("provider final id missing"))?;
    if uuid::Uuid::parse_str(id).is_err() || args.get("id_nonce").and_then(Value::as_str).is_none()
    {
        return Err(refuse("provider final id proof missing"));
    }
    Ok(())
}

pub fn validate_shape_kernel_v2(
    operation: &str,
    arguments: &Value,
    max_bytes: usize,
) -> Result<()> {
    if arguments.to_string().len() > max_bytes {
        return Err(refuse("call too large"));
    }
    let object = arguments
        .as_object()
        .ok_or_else(|| refuse("expected argument object"))?;
    match operation {
        "create_record" => {
            for field in object.keys() {
                if ![
                    "type",
                    "kind",
                    // `id` is listed only so the dedicated refusal below fires
                    // with the canonical-authority message; it is never accepted.
                    "id",
                    "name",
                    "body",
                    "summary",
                    "home_id",
                    "reason",
                    "idempotency_key",
                    "response_mode",
                ]
                .contains(&field.as_str())
                {
                    return Err(unsupported(&format!("unsupported field {field}")));
                }
            }
            if object.get("type").and_then(Value::as_str) != Some("Document")
                || object.get("kind").and_then(Value::as_str) != Some("note")
            {
                return Err(unsupported(
                    "private engine creates plain Document/note only",
                ));
            }
            // Canonical ID authority is unchanged: ordinary v2 create mints
            // the record ID. The kernel handler enforces this; the gate
            // refuses early so a provisional ID can never be smuggled in.
            if object.get("id").is_some() {
                return Err(refuse(
                    "v2 create mints private IDs; caller-supplied id rejected",
                ));
            }
        }
        "update_record" => {
            for field in object.keys() {
                if !KERNEL_V2_APPEND_FIELDS.contains(&field.as_str()) {
                    return Err(unsupported(&format!("unsupported field {field}")));
                }
            }
            if object.contains_key("id") == object.contains_key("record_id") {
                return Err(refuse("exactly one id required"));
            }
            string(
                object,
                if object.contains_key("id") {
                    "id"
                } else {
                    "record_id"
                },
            )?;
            // This increment covers the existing-record append path. Other
            // update shapes are refused here; the handlers stay authoritative.
            string(object, "body_append")?;
        }
        "get_record" | "search" => {}
        _ => return Err(unsupported("unsupported operation")),
    }
    if let Some(mode) = object.get("response_mode") {
        if mode != "summary" && mode != "verbose" && mode != "full" {
            return Err(unsupported("unsupported response mode"));
        }
    }
    if let Some(key) = object.get("idempotency_key") {
        if key
            .as_str()
            .is_none_or(|key| key.trim().is_empty() || key.chars().count() > 200)
        {
            return Err(refuse("key too long"));
        }
    }
    Ok(())
}

// Persist only a content address and bounded metadata, never note bodies.
fn journal_binding(snapshot: &str) -> Value {
    let entries = serde_json::from_str::<Value>(snapshot)
        .ok()
        .and_then(|value| value.as_array().map(Vec::len));
    serde_json::json!({"sha256":hex::encode(Sha256::digest(snapshot.as_bytes())),
        "bytes":snapshot.len(), "entries":entries})
}

fn check_binding(key: &ForkKey, caller: &Caller) -> Result<()> {
    if key.window_id.trim().is_empty()
        || caller.hosting_principal().is_none()
        || caller.hosting_database() != Some(key.workspace_id.as_str())
        || caller.credential() == Caller::local().credential()
    {
        return Err(refuse("author/workspace binding mismatch"));
    }
    Ok(())
}

async fn frontier(db: &Db) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
            .fetch_one(db.pool())
            .await?,
    )
}

fn footprint(directory: &Path) -> Result<u64> {
    let mut bytes = 0u64;
    for file in std::fs::read_dir(directory)? {
        let file = file?;
        identity(&file.path(), false)?;
        bytes = bytes
            .checked_add(file.metadata()?.len())
            .ok_or_else(|| refuse("size overflow"))?;
    }
    Ok(bytes)
}

fn string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| refuse(&format!("nonempty {field} required")))
}

/// Scope shared by KernelV2 callers that may retain an ordinary append.
/// The authoritative operation contract and target permissions still apply.
pub fn kernel_v2_plain_append_target(arguments: &Value) -> Option<&str> {
    let fields = arguments.as_object()?;
    if !fields
        .keys()
        .all(|field| KERNEL_V2_APPEND_FIELDS.contains(&field.as_str()))
        || fields
            .get("body_append")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return None;
    }
    let target = match (fields.get("id"), fields.get("record_id")) {
        (Some(id), None) | (None, Some(id)) => id.as_str()?,
        _ => return None,
    };
    Uuid::parse_str(target)
        .is_ok_and(|id| id.to_string() == target)
        .then_some(target)
}

const KERNEL_V2_APPEND_FIELDS: &[&str] = &[
    "id",
    "record_id",
    "body_append",
    "reason",
    "idempotency_key",
    "response_mode",
];

pub fn validate_shape(
    operation: &str,
    arguments: &Value,
    prepared: bool,
    max_bytes: usize,
) -> Result<()> {
    if arguments.to_string().len() > max_bytes {
        return Err(refuse("call too large"));
    }
    let object = arguments
        .as_object()
        .ok_or_else(|| refuse("expected argument object"))?;
    let common = [
        "reason",
        "run_key",
        "parent_key",
        "idempotency_key",
        "response_mode",
        "sources",
    ];
    let fields: &[&str] = match operation {
        "create_record" => &[
            "id", "type", "kind", "name", "body", "home_id", "summary", "confirm",
        ],
        "update_record" => &["id", "record_id", "body_append"],
        _ => return Err(unsupported("unsupported operation")),
    };
    for field in object.keys() {
        if !common.contains(&field.as_str()) && !fields.contains(&field.as_str()) {
            return Err(unsupported(&format!("unsupported field {field}")));
        }
    }
    string(object, "reason")?;
    string(object, "run_key")?;
    if (prepared || object.contains_key("idempotency_key"))
        && string(object, "idempotency_key")?.chars().count() > 200
    {
        return Err(refuse("key too long"));
    }
    if let Some(mode) = object.get("response_mode") {
        if mode != "summary" && mode != "verbose" {
            return Err(unsupported("unsupported response mode"));
        }
    }
    // Pinned sources and structured source features are deferred. Empty source
    // declarations are safe and preserve declared-none versus undeclared.
    if object
        .get("sources")
        .is_some_and(|v| v != &Value::Array(vec![]))
    {
        return Err(unsupported("nonempty sources are not supported yet"));
    }
    match operation {
        "create_record" => {
            if object.get("confirm").is_some_and(|v| !v.is_boolean()) {
                return Err(refuse("confirm must be a boolean"));
            }
            let record_type = string(object, "type")?;
            let kind = string(object, "kind")?;
            if !matches!(
                (record_type, kind),
                ("Document", "note") | ("WorkItem", "task")
            ) {
                return Err(unsupported("create supports only plain note/task"));
            }
            for field in ["name", "body", "home_id", "summary"] {
                if object.get(field).is_some_and(|v| !v.is_string()) {
                    return Err(refuse("expected plain text fields"));
                }
            }
            if prepared || object.contains_key("id") {
                let id = string(object, "id")?;
                let _ = id; // UUID syntax was checked by the ordinary registered schema.
            }
        }
        "update_record" => {
            if object.contains_key("id") == object.contains_key("record_id") {
                return Err(refuse("exactly one id required"));
            }
            string(
                object,
                if object.contains_key("id") {
                    "id"
                } else {
                    "record_id"
                },
            )?;
            string(object, "body_append")?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

async fn validate_target(handle: &ForkHandle, call: &PreparedCall) -> Result<()> {
    if call.operation == "update_record" {
        let id = call
            .arguments
            .get("id")
            .or_else(|| call.arguments.get("record_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| refuse("single record id required"))?;
        if Uuid::parse_str(id).is_err() {
            return Err(unsupported(
                "append requires a full UUID; short references and aliases are unsupported",
            ));
        }
        let kind: Option<(String, String)> =
            sqlx::query_as("SELECT type,kind FROM records WHERE id=?")
                .bind(id)
                .fetch_optional(handle.db.pool())
                .await?;
        let Some((record_type, kind)) = kind else {
            return Err(refuse("append target does not exist"));
        };
        let instruction: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM instruction_bindings WHERE source_record_id=?)",
        )
        .bind(id)
        .fetch_one(handle.db.pool())
        .await?;
        if !matches!(
            (record_type.as_str(), kind.as_str()),
            ("Document", "note") | ("WorkItem", "task")
        ) || instruction
        {
            return Err(unsupported(
                "append target must be a plain note/task, not an instruction source",
            ));
        }
    }
    Ok(())
}

fn require_ready(slot: &EntrySlot) -> Result<()> {
    match slot.state() {
        ForkState::Ready => Ok(()),
        ForkState::Absent | ForkState::Preparing => Err(not_ready("fork absent or preparing")),
        ForkState::Dirty | ForkState::Failed => {
            Err(ForkError::Uncertain(Error::engine("fork requires rebuild")))
        }
    }
}
fn clean_domain_refusal(error: &Error) -> bool {
    matches!(
        error,
        Error::Engine(_) | Error::Conflict(_) | Error::Auth(_)
    )
}
fn classify_preflight(error: Error) -> ForkError {
    if clean_domain_refusal(&error) {
        ForkError::RefusedInvalid(error)
    } else {
        ForkError::Uncertain(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct Harness {
        _directory: tempfile::TempDir,
        base: Db,
        manager: Arc<ForkManager>,
    }

    /// Component qualification of the existing v1 outbox/pending-fork path.
    /// This is not installed admission or authority to execute95 arguments.
    #[tokio::test]
    async fn receiver_real95_v1_fork_replays_ordinary94_calls_without_touching_base() {
        use serde_json::json;
        use sqlx::Connection as _;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("private-preparation95.db");
        let output = std::process::Command::new("gzip")
            .args(["-cd"])
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/receiver-shapes/v1-base95.sqlite.gz"),
            )
            .output()
            .unwrap();
        assert!(output.status.success());
        std::fs::write(&source, output.stdout).unwrap();
        // Only this owned setup copy is writable. Mint the fixture identity
        // and note through ordinary APIs before publishing the immutable base.
        let setup = crate::db::open_receiver_fork_at(&source).await.unwrap();
        let account = crate::identity::resolve_stdio_account_identity(&setup, None)
            .await
            .unwrap();
        let caller = Caller::for_node_pending_fork(account, "receiver95".into());
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).unwrap();
        registry
            .call(
                setup.clone(),
                caller.clone(),
                "set_intent",
                json!({"run_key":"scout-chair-k748b2","intent":"Private95 fork qualification"}),
            )
            .await
            .unwrap();
        let id = Uuid::new_v4().to_string();
        registry.call(setup.clone(), caller.clone(), "create_record", json!({"id":id,"type":"Document","kind":"note","body":"accepted","reason":"Private fixture setup","run_key":"scout-chair-k748b2","idempotency_key":"receiver95-setup"})).await.unwrap();
        let accepted = dir.path().join("accepted95.db");
        sqlx::query("VACUUM INTO ?")
            .bind(accepted.to_str().unwrap())
            .execute(setup.pool())
            .await
            .unwrap();
        setup.close().await;
        let base = crate::db::open_existing_database_standby_read_only(accepted.to_str().unwrap())
            .await
            .unwrap();
        let bytes = std::fs::read(&accepted).unwrap();
        let seq: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
            .fetch_one(base.pool())
            .await
            .unwrap();
        async fn prefix(db: &Db, seq: i64) -> Vec<String> {
            sqlx::query_scalar("SELECT json_array(seq,id,record_id,type,payload,actor,run_key,created_at,act,observed_act,observed_basis,caller_write_ordinal) FROM content_events WHERE seq<=? ORDER BY seq")
                .bind(seq).fetch_all(db.pool()).await.unwrap()
        }
        let canonical = prefix(&base, seq).await;
        let observed: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM content_events WHERE caller_write_ordinal IS NOT NULL",
        )
        .fetch_one(base.pool())
        .await
        .unwrap();
        assert!(observed > 0, "actual795 producer metadata must be present");
        let local_sql = registry
            .call(
                base.clone(),
                caller.clone(),
                "query_sql",
                json!({"sql":"SELECT * FROM content_events LIMIT 1"}),
            )
            .await
            .unwrap()
            .to_string();
        for name in ["observed_act", "observed_basis", "caller_write_ordinal"] {
            assert!(
                !local_sql.contains(name),
                "v1 local SQL must keep the94 view"
            );
        }
        let manager = ForkManager::new(
            ForkArea::new(dir.path(), std::slice::from_ref(&accepted)).unwrap(),
            ForkLimits::default(),
        )
        .unwrap();
        let key = ForkKey {
            window_id: "receiver95-window".into(),
            workspace_id: "receiver95".into(),
        };
        manager.prepare(key.clone(), base.clone()).await.unwrap();
        until_ready(&manager, &key).await;
        manager.enable_rebase(&key).await.unwrap();
        let args = json!({"id":id,"body_append":" pending","reason":"Ordinary94 private replay","run_key":"scout-chair-k748b2","idempotency_key":"receiver95-append"});
        for field in ["observed", "observed_act", "observed_basis"] {
            let mut future = args.clone();
            future[field] = Value::Null;
            assert!(manager
                .prepare_call(&key, &caller, "update_record", future)
                .await
                .is_err());
        }
        let call = manager
            .prepare_call(&key, &caller, "update_record", args.clone())
            .await
            .unwrap();
        let original = serde_json::to_vec(&call).unwrap();
        assert_eq!(call.arguments(), &args);
        for _ in 0..2 {
            let outcome = manager.dispatch(&key, &caller, &call).await.unwrap();
            assert_eq!(outcome.idempotency_key, "receiver95-append");
            manager.confirm_journaled(&key, &outcome).await.unwrap();
        }
        struct Calls(Vec<PreparedCall>);
        impl OrderedJournaledCalls for Calls {
            fn ordered_calls<'a>(
                &'a self,
                _: &'a ForkKey,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = crate::Result<Vec<PreparedCall>>> + Send + 'a>,
            > {
                Box::pin(async move { Ok(self.0.clone()) })
            }
        }
        manager
            .rebuild(&key, &Calls(vec![call.clone(), call.clone()]))
            .await
            .unwrap();
        let work = manager.test_working_db(&key).await.unwrap();
        let body: String = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
            .bind(&id)
            .fetch_one(work.pool())
            .await
            .unwrap();
        assert_eq!(body, "accepted pending", "retry and replay have one effect");
        assert_eq!(
            prefix(&work, seq).await,
            canonical,
            "preserve original95 facts, timestamps, provenance and metadata"
        );
        let added_metadata: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events WHERE seq>? AND (observed_act IS NOT NULL OR observed_basis IS NOT NULL OR caller_write_ordinal IS NOT NULL)")
            .bind(seq).fetch_one(work.pool()).await.unwrap();
        assert_eq!(added_metadata, 0, "ordinary94 replay adds no95 metadata");
        assert_eq!(serde_json::to_vec(&call).unwrap(), original);
        assert_eq!(
            std::fs::read(&accepted).unwrap(),
            bytes,
            "source copy stays untouched"
        );
        manager.discard(&key).await.unwrap();
        base.close().await;
        let unknown = dir.path().join("unknown96.db");
        std::fs::write(&unknown, &bytes).unwrap();
        let mut raw = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new().filename(&unknown),
        )
        .await
        .unwrap();
        sqlx::query("PRAGMA user_version=96")
            .execute(&mut raw)
            .await
            .unwrap();
        raw.close().await.unwrap();
        let bytes96 = std::fs::read(&unknown).unwrap();
        assert!(crate::db::open_receiver_fork_at(&unknown).await.is_err());
        assert_eq!(std::fs::read(&unknown).unwrap(), bytes96);
    }

    async fn harness(limits: ForkLimits) -> Harness {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("canonical.sqlite");
        let db = crate::create_database(path.to_str().unwrap())
            .await
            .unwrap();
        db.close().await;
        // Checkpoint the WAL into the main file (as the shared fixtures do)
        // so the read-only open sees a plain database file.
        let standalone = sqlx::pool::PoolOptions::<sqlx::Sqlite>::new()
            .max_connections(1)
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&path)
                    .journal_mode(sqlx::sqlite::SqliteJournalMode::Delete),
            )
            .await
            .unwrap();
        standalone.close().await;
        let base = crate::db::open_current_database_wal_read_only_at(&path)
            .await
            .unwrap();
        assert_eq!(
            base.open_mode(),
            crate::db::DatabaseOpenMode::StandbyReadOnly
        );
        let area = ForkArea::new(directory.path(), std::slice::from_ref(&path)).unwrap();
        let manager = ForkManager::new(area, limits).unwrap();
        Harness {
            _directory: directory,
            base,
            manager,
        }
    }

    fn key(workspace: &str) -> ForkKey {
        ForkKey {
            window_id: "window:test".into(),
            workspace_id: workspace.into(),
        }
    }

    fn slot_limits() -> ForkLimits {
        ForkLimits {
            copy_workers: 1,
            max_forks: 1,
            ..Default::default()
        }
    }

    async fn until_ready(manager: &Arc<ForkManager>, key: &ForkKey) {
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                match manager.state(key).await {
                    ForkState::Ready => break,
                    ForkState::Preparing => tokio::time::sleep(Duration::from_millis(10)).await,
                    other => panic!("unexpected fork state: {other:?}"),
                }
            }
        })
        .await
        .expect("fork became ready");
    }

    #[tokio::test]
    async fn reclaim_keeps_map_usable_and_reservation_charged_until_unlink() {
        let f = harness(slot_limits()).await;
        // Slot A: speculative prewarm, completed and Ready.
        assert_eq!(
            f.manager
                .prewarm(key("ws-a"), f.base.clone())
                .await
                .unwrap(),
            ForkState::Preparing
        );
        until_ready(&f.manager, &key("ws-a")).await;
        let reserved_a = {
            let map = f.manager.entries.lock().await;
            assert_eq!(map.items.len(), 1);
            map.reserved
        };
        assert!(reserved_a > 0);
        // Gate the unlink: signal arrival, then wait for release.
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        f.manager
            .set_unlink_hook_for_tests(Some(ReclaimUnlinkHook {
                reached: Some(reached_tx),
                release: release.clone(),
                settled: None,
                fail_unlink: false,
            }))
            .await;
        // B on-demand: over the one-slot budget, so it reclaims A and parks.
        let b = tokio::spawn({
            let manager = f.manager.clone();
            let base = f.base.clone();
            async move { manager.prepare(key("ws-b"), base).await }
        });
        tokio::time::timeout(Duration::from_secs(30), reached_rx)
            .await
            .expect("reclaim reaches unlink")
            .unwrap();
        // The map is not held by the unlink: status resolves the tombstone
        // instead of blocking, and a same-key prepare observes it instead of
        // creating a replacement (no duplicate reservation).
        let st = tokio::time::timeout(Duration::from_secs(30), f.manager.state(&key("ws-a")))
            .await
            .expect("state lookup is not blocked by unlink");
        assert_eq!(st, ForkState::Dirty);
        let again = tokio::time::timeout(
            Duration::from_secs(30),
            f.manager.prepare(key("ws-a"), f.base.clone()),
        )
        .await
        .expect("same-key prepare is not blocked by unlink");
        assert_eq!(again.unwrap(), ForkState::Dirty);
        {
            let map = f.manager.entries.lock().await;
            assert_eq!(map.items.len(), 1, "no replacement slot during cleanup");
            assert_eq!(map.reserved, reserved_a, "reservation stays charged");
        }
        // Release: B completes, A removed, reservation transferred exactly once.
        release.notify_waiters();
        let b_state = tokio::time::timeout(Duration::from_secs(120), b)
            .await
            .expect("reclaim finishes")
            .unwrap()
            .unwrap();
        assert_eq!(b_state, ForkState::Preparing);
        until_ready(&f.manager, &key("ws-b")).await;
        {
            let map = f.manager.entries.lock().await;
            assert!(!map.items.contains_key(&key("ws-a")));
            assert!(map.items.contains_key(&key("ws-b")));
            let kept = map.items.get(&key("ws-b")).unwrap().reservation;
            assert_eq!(map.reserved, kept, "exactly one reservation charged");
        }
        // The slot budget is still enforced afterwards.
        assert!(f
            .manager
            .prepare(key("ws-c"), f.base.clone())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn failed_reclaim_keeps_slot_and_charge_for_recovery() {
        let f = harness(slot_limits()).await;
        assert_eq!(
            f.manager
                .prewarm(key("ws-a"), f.base.clone())
                .await
                .unwrap(),
            ForkState::Preparing
        );
        until_ready(&f.manager, &key("ws-a")).await;
        let reserved_a = f.manager.entries.lock().await.reserved;
        // Fail the unlink deterministically instead of relying on filesystem
        // behavior, which varies across platforms.
        f.manager
            .set_unlink_hook_for_tests(Some(ReclaimUnlinkHook {
                reached: None,
                release: std::sync::Arc::new(tokio::sync::Notify::new()),
                settled: None,
                fail_unlink: true,
            }))
            .await;
        let failed = f.manager.prepare(key("ws-b"), f.base.clone()).await;
        assert!(failed.is_err(), "injected unlink failure must propagate");
        // Slot, handle and reservation are retained for recovery.
        {
            let map = f.manager.entries.lock().await;
            assert!(map.items.contains_key(&key("ws-a")));
            assert!(!map.items.contains_key(&key("ws-b")));
            assert_eq!(map.reserved, reserved_a);
        }
        assert_eq!(f.manager.state(&key("ws-a")).await, ForkState::Dirty);
        // Discard still recovers the failed slot; a fresh prepare then works.
        f.manager.discard(&key("ws-a")).await.unwrap();
        {
            let map = f.manager.entries.lock().await;
            assert!(map.items.is_empty());
            assert_eq!(map.reserved, 0);
        }
        f.manager.set_unlink_hook_for_tests(None).await;
        assert_eq!(
            f.manager
                .prepare(key("ws-b"), f.base.clone())
                .await
                .unwrap(),
            ForkState::Preparing
        );
        until_ready(&f.manager, &key("ws-b")).await;
    }

    async fn sized_base(dir: &std::path::Path, name: &str, pad_mib: usize) -> (crate::Db, u64) {
        use crate::blob::insert_blob;
        let path = dir.join(name);
        let db = crate::create_database(path.to_str().unwrap())
            .await
            .unwrap();
        for _ in 0..pad_mib {
            insert_blob(&db, &vec![0x5a; 1024 * 1024], None, None)
                .await
                .unwrap();
        }
        db.close().await;
        let standalone = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&path)
                    .journal_mode(sqlx::sqlite::SqliteJournalMode::Delete),
            )
            .await
            .unwrap();
        standalone.close().await;
        let base = crate::db::open_current_database_wal_read_only_at(&path)
            .await
            .unwrap();
        let pages: i64 = sqlx::query_scalar("PRAGMA page_count")
            .fetch_one(base.pool())
            .await
            .unwrap();
        let page_size: i64 = sqlx::query_scalar("PRAGMA page_size")
            .fetch_one(base.pool())
            .await
            .unwrap();
        let reservation = (pages as u64) * (page_size as u64) * 2 + 1024 * 1024;
        (base, reservation)
    }

    #[tokio::test]
    async fn reclaim_rereads_requested_key_before_inserting() {
        // Heterogeneous budgets force the exact race: the reclaiming demand
        // holds no map lock across cleanup, so a concurrent prepare for the
        // same key can insert first. The recheck must adopt the existing slot
        // (same base) or refuse a base mismatch instead of replacing the Arc
        // and double-charging (or orphaning a copy).
        let directory = tempfile::tempdir().unwrap();
        let (big, big_res) = sized_base(directory.path(), "big.sqlite", 4).await;
        let (small, small_res) = sized_base(directory.path(), "small.sqlite", 0).await;
        // A retained + B(big) does not fit; A retained + B(small) does; and a
        // completed small B plus big still fits, so the recheck (not capacity)
        // decides the outcome.
        let max = big_res + small_res + 4096;
        assert!(
            big_res + big_res > max,
            "reclaim must trigger for the big base"
        );
        assert!(
            small_res + big_res <= max,
            "small insert plus big retry must fit"
        );
        let area = ForkArea::new(directory.path(), &[]).unwrap();
        let manager = ForkManager::new(
            area,
            ForkLimits {
                copy_workers: 1,
                max_forks: 8,
                max_reserved_bytes: max,
                growth_bytes: 1024 * 1024,
                max_call_bytes: 1024 * 1024,
            },
        )
        .unwrap();
        let key_a = ForkKey {
            window_id: "window:test".into(),
            workspace_id: "ws-a".into(),
        };
        let key_b = ForkKey {
            window_id: "window:test".into(),
            workspace_id: "ws-b".into(),
        };
        // Slot A is speculative and Ready; B prepares on the big base.
        assert_eq!(
            manager.prewarm(key_a.clone(), big.clone()).await.unwrap(),
            ForkState::Preparing
        );
        until_ready(&manager, &key_a).await;
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        manager
            .set_unlink_hook_for_tests(Some(ReclaimUnlinkHook {
                reached: Some(reached_tx),
                release: release.clone(),
                settled: None,
                fail_unlink: false,
            }))
            .await;
        let parked = tokio::spawn({
            let manager = manager.clone();
            let big = big.clone();
            let key_b = key_b.clone();
            async move { manager.prepare(key_b, big).await }
        });
        tokio::time::timeout(Duration::from_secs(30), reached_rx)
            .await
            .expect("reclaim reaches unlink")
            .unwrap();
        // While A is being unlinked (still charged, still mapped), a
        // concurrent demand for B on the small base fits and is accepted.
        let inserted = manager.prepare(key_b.clone(), small.clone()).await.unwrap();
        assert!(matches!(inserted, ForkState::Preparing | ForkState::Ready));
        until_ready(&manager, &key_b).await;
        let before = {
            let map = manager.entries.lock().await;
            assert!(map.items.contains_key(&key_a));
            assert!(map.items.contains_key(&key_b));
            let incumbent = Arc::as_ptr(map.items.get(&key_b).unwrap());
            (incumbent as usize, map.reserved)
        };
        // Release the gate: the parked demand must adopt the existing slot
        // (same key, different base) as a refusal, not replace it.
        release.notify_waiters();
        let parked = tokio::time::timeout(Duration::from_secs(60), parked)
            .await
            .expect("parked prepare finishes after release")
            .unwrap();
        let error = parked.expect_err("base mismatch must refuse, not replace");
        assert!(
            error.to_string().contains("window base changed"),
            "unexpected refusal: {error}"
        );
        // Exactly one slot, single charge, identical Arc: no replacement, no
        // duplicate reservation, no orphaned copy.
        {
            let map = manager.entries.lock().await;
            assert_eq!(map.items.len(), 1, "only the small-base slot survives");
            assert!(map.items.contains_key(&key_b));
            assert_eq!(map.reserved, small_res);
            assert_eq!(
                Arc::as_ptr(map.items.get(&key_b).unwrap()) as usize,
                before.0,
                "same Arc: no replacement happened during reclaim"
            );
        }
        // Re-preparing the same key and base finds the existing slot instead
        // of erroring on capacity.
        let again = manager.prepare(key_b.clone(), small.clone()).await.unwrap();
        assert_eq!(again, ForkState::Ready);
        {
            let map = manager.entries.lock().await;
            assert_eq!(map.items.len(), 1);
            assert_eq!(map.reserved, small_res);
        }
        manager.set_unlink_hook_for_tests(None).await;
    }

    struct EmptyJournal;

    impl OrderedJournaledCalls for EmptyJournal {
        fn ordered_calls<'a>(
            &'a self,
            _key: &'a ForkKey,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = crate::Result<Vec<PreparedCall>>> + Send + 'a>,
        > {
            Box::pin(async move { Ok(vec![]) })
        }
    }

    #[tokio::test]
    async fn cancelled_reclaim_before_commit_stays_recoverable() {
        let f = harness(slot_limits()).await;
        assert_eq!(
            f.manager
                .prewarm(key("ws-a"), f.base.clone())
                .await
                .unwrap(),
            ForkState::Preparing
        );
        until_ready(&f.manager, &key("ws-a")).await;
        let reserved_a = f.manager.entries.lock().await.reserved;
        // Park the reclaimer after unlink but before the final map lock:
        // no slot state may be published and no charge may move.
        let (settled_tx, settled_rx) = tokio::sync::oneshot::channel();
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        f.manager
            .set_unlink_hook_for_tests(Some(ReclaimUnlinkHook {
                reached: None,
                release,
                settled: Some(settled_tx),
                fail_unlink: false,
            }))
            .await;
        let mut reclaimer = tokio::spawn({
            let manager = f.manager.clone();
            let base = f.base.clone();
            async move { manager.prepare(key("ws-b"), base).await }
        });
        tokio::time::timeout(Duration::from_secs(30), settled_rx)
            .await
            .expect("reclaim reaches post-unlink gate")
            .unwrap();
        // Cancel while parked: the slot must stay Dirty with no handle and a
        // retained charge — never a stranded Absent slot that rebuild refuses.
        reclaimer.abort();
        assert!(
            tokio::time::timeout(Duration::from_secs(30), &mut reclaimer)
                .await
                .expect("aborted reclaim task finishes being cancelled")
                .unwrap_err()
                .is_cancelled()
        );
        {
            let map = f.manager.entries.lock().await;
            let slot = map.items.get(&key("ws-a")).expect("slot retained");
            assert_eq!(slot.state(), ForkState::Dirty);
            assert!(slot.inner.try_lock().is_ok());
            assert_eq!(map.reserved, reserved_a);
        }
        // A demand sees Dirty (not Absent) and claims the slot; the ordinary
        // rebuild path then recovers it to Ready with the charge intact.
        assert_eq!(
            f.manager
                .prepare(key("ws-a"), f.base.clone())
                .await
                .unwrap(),
            ForkState::Dirty
        );
        f.manager
            .rebuild(&key("ws-a"), &EmptyJournal)
            .await
            .expect("rebuild recovers the cancelled slot");
        assert_eq!(f.manager.state(&key("ws-a")).await, ForkState::Ready);
        {
            let map = f.manager.entries.lock().await;
            assert!(map.items.contains_key(&key("ws-a")));
            assert_eq!(map.reserved, reserved_a);
        }
        f.manager.set_unlink_hook_for_tests(None).await;
    }

    #[tokio::test]
    async fn same_base_reclaim_rereads_requested_key() {
        // Parked reclaimer plus a concurrent demand for the same base: the
        // recheck must adopt the existing slot instead of replacing it.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("canonical.sqlite");
        let db = crate::create_database(path.to_str().unwrap())
            .await
            .unwrap();
        db.close().await;
        let standalone = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&path)
                    .journal_mode(sqlx::sqlite::SqliteJournalMode::Delete),
            )
            .await
            .unwrap();
        standalone.close().await;
        let base = crate::db::open_current_database_wal_read_only_at(&path)
            .await
            .unwrap();
        let area = ForkArea::new(directory.path(), &[path]).unwrap();
        let manager = ForkManager::new(
            area,
            ForkLimits {
                copy_workers: 1,
                max_forks: 2,
                max_reserved_bytes: u64::MAX,
                growth_bytes: 1024 * 1024,
                max_call_bytes: 1024 * 1024,
            },
        )
        .unwrap();
        // Two speculative slots fill the two-slot budget.
        for key in [key("ws-a"), key("ws-c")] {
            assert_eq!(
                manager.prewarm(key.clone(), base.clone()).await.unwrap(),
                ForkState::Preparing
            );
            until_ready(&manager, &key).await;
        }
        // Demand-claim C so only A is reclaimable, then park a reclaimer on A.
        assert_eq!(
            manager.prepare(key("ws-c"), base.clone()).await.unwrap(),
            ForkState::Ready
        );
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        manager
            .set_unlink_hook_for_tests(Some(ReclaimUnlinkHook {
                reached: Some(reached_tx),
                release: release.clone(),
                settled: None,
                fail_unlink: false,
            }))
            .await;
        // A concurrent demand for B cannot fit while both slots are charged.
        let mut first = tokio::spawn({
            let manager = manager.clone();
            let base = base.clone();
            async move { manager.prepare(key("ws-b"), base).await }
        });
        tokio::time::timeout(Duration::from_secs(30), reached_rx)
            .await
            .expect("reclaim reaches unlink gate")
            .unwrap();
        // Discard C to free a slot, then demand B: it inserts cleanly.
        manager.discard(&key("ws-c")).await.unwrap();
        assert_eq!(
            manager.prepare(key("ws-b"), base.clone()).await.unwrap(),
            ForkState::Preparing
        );
        until_ready(&manager, &key("ws-b")).await;
        let incumbent = {
            let map = manager.entries.lock().await;
            assert!(map.items.contains_key(&key("ws-a")));
            assert!(map.items.contains_key(&key("ws-b")));
            Arc::as_ptr(map.items.get(&key("ws-b")).unwrap()) as usize
        };
        // Release the parked reclaim: with A gone and B present it must adopt
        // the existing same-base slot instead of replacing it or erroring.
        release.notify_waiters();
        let adopted = tokio::time::timeout(Duration::from_secs(60), &mut first)
            .await
            .expect("parked prepare completes after release")
            .expect("no panic in parked prepare");
        assert_eq!(adopted.unwrap(), ForkState::Ready);
        {
            let map = manager.entries.lock().await;
            assert_eq!(map.items.len(), 1, "no duplicate slot was created");
            assert!(map.items.contains_key(&key("ws-b")));
            assert_eq!(
                Arc::as_ptr(map.items.get(&key("ws-b")).unwrap()) as usize,
                incumbent,
                "same Arc: the parked task adopted instead of replacing"
            );
        }
        manager.set_unlink_hook_for_tests(None).await;
    }

    #[tokio::test]
    async fn full_capacity_returns_existing_slot() {
        // With the single slot occupied, preparing the same key must return
        // the existing slot rather than erroring on capacity.
        let f = harness(slot_limits()).await;
        assert_eq!(
            f.manager
                .prepare(key("ws-a"), f.base.clone())
                .await
                .unwrap(),
            ForkState::Preparing
        );
        until_ready(&f.manager, &key("ws-a")).await;
        let again = f
            .manager
            .prepare(key("ws-a"), f.base.clone())
            .await
            .unwrap();
        assert_eq!(again, ForkState::Ready);
        {
            let map = f.manager.entries.lock().await;
            assert_eq!(map.items.len(), 1);
        }
    }
}
