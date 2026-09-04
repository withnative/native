//! Transport-neutral lifecycle for paged SQLite exports.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use uuid::Uuid;

use crate::error::Error;
use crate::mcp::{SnapshotPage, SNAPSHOT_COMPLETED_CACHE_CAP};

use super::Export;

const STREAM_CHUNK_BYTES: usize = 64 * 1024;
const SQLITE_MEDIA_TYPE: &str = "application/vnd.sqlite3";
const TOOL_EXPORT_IDLE_TTL: Duration = Duration::from_secs(5 * 60);

/// Tracks export generation, delivery, and cleanup for concurrency limiting
/// and bounded server shutdown.
#[derive(Clone)]
pub struct ExportCoordinator {
    inner: Arc<ExportCoordinatorInner>,
}

struct ExportCoordinatorInner {
    state: Mutex<ExportCoordinatorState>,
    tool_exports: Mutex<HashMap<String, Arc<tokio::sync::Mutex<Option<ToolExport>>>>>,
    completed_tool_exports: Mutex<CompletedToolExportCache>,
    completed_cache_changed: tokio::sync::Notify,
    changes: tokio::sync::watch::Sender<u64>,
    tool_export_idle_ttl: Duration,
    tool_expiry_workers: Arc<AtomicUsize>,
    completed_cache_workers: Arc<AtomicUsize>,
}

struct ExportCoordinatorState {
    active: HashSet<String>,
    accepting: bool,
}

impl ExportCoordinator {
    pub fn new() -> Self {
        Self::with_options(TOOL_EXPORT_IDLE_TTL)
    }

    fn with_options(tool_export_idle_ttl: Duration) -> Self {
        Self {
            inner: Arc::new(ExportCoordinatorInner {
                state: Mutex::new(ExportCoordinatorState {
                    active: HashSet::new(),
                    accepting: true,
                }),
                tool_exports: Mutex::new(HashMap::new()),
                completed_tool_exports: Mutex::new(CompletedToolExportCache::default()),
                completed_cache_changed: tokio::sync::Notify::new(),
                changes: tokio::sync::watch::channel(0).0,
                tool_export_idle_ttl,
                tool_expiry_workers: Arc::new(AtomicUsize::new(0)),
                completed_cache_workers: Arc::new(AtomicUsize::new(0)),
            }),
        }
    }

    #[cfg(test)]
    fn with_tool_export_idle_ttl(tool_export_idle_ttl: Duration) -> Self {
        Self::with_options(tool_export_idle_ttl)
    }

    /// Wait until every export has finished generation, delivery, and cleanup.
    ///
    /// Production calls this after Axum's request drain, when no new export can
    /// begin. The subscription is created before checking the set, so a final
    /// release cannot race between the check and the wait.
    pub async fn wait_for_idle(&self) {
        let mut changes = self.inner.changes.subscribe();
        loop {
            if self
                .inner
                .state
                .lock()
                .expect("export coordinator poisoned")
                .active
                .is_empty()
            {
                return;
            }
            if changes.changed().await.is_err() {
                return;
            }
        }
    }

    /// Stop accepting new export work, then wait for every current lifecycle.
    pub async fn drain(&self) {
        self.inner
            .state
            .lock()
            .expect("export coordinator poisoned")
            .accepting = false;

        // A paged tool export deliberately remains live between calls. On
        // shutdown there will be no next call, so take every retained snapshot
        // and clean it before waiting on the shared generation counter.
        let transfers: Vec<_> = self
            .inner
            .tool_exports
            .lock()
            .expect("export coordinator poisoned")
            .drain()
            .map(|(_, transfer)| transfer)
            .collect();
        self.inner
            .completed_tool_exports
            .lock()
            .expect("export coordinator poisoned")
            .clear();
        self.inner.completed_cache_changed.notify_one();
        for transfer in transfers {
            if let Some(export) = transfer.lock().await.take() {
                export.cleanup().await;
            }
        }
        self.wait_for_idle().await;
    }

    /// Begin one account's export lifecycle.
    ///
    /// The standard HTTP route uses this internally. It is exposed only so
    /// another export frontend can join the same concurrency and shutdown
    /// lifecycle; normal HTTP callers should use the hosted router
    /// constructors.
    #[doc(hidden)]
    pub fn try_begin(&self, principal: String) -> Option<ExportActivity> {
        let acquired = {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("export coordinator poisoned");
            state.accepting && state.active.insert(principal.clone())
        };
        if acquired {
            Some(ExportActivity {
                coordinator: Arc::downgrade(&self.inner),
                principal,
            })
        } else {
            None
        }
    }

    /// Produce one page of a tool-owned export, starting a new consistent
    /// snapshot when `export_id` is absent and continuing one otherwise.
    ///
    /// Each call runs in an independently-owned task. Dropping the MCP/HTTP
    /// request future therefore cannot interrupt generation, final cleanup, or
    /// lease release. An abandoned multi-page transfer is reclaimed after a
    /// bounded idle period; [`drain`](Self::drain) reclaims it immediately.
    pub async fn tool_page<F, Fut>(
        &self,
        principal: String,
        export_id: Option<String>,
        offset: u64,
        length: usize,
        create: F,
    ) -> Result<SnapshotPage, Error>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Export, Error>> + Send + 'static,
    {
        let coordinator = self.clone();
        let (send, receive) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = match export_id {
                Some(export_id) => {
                    coordinator
                        .read_tool_page(&principal, &export_id, offset, length)
                        .await
                }
                None => {
                    coordinator
                        .start_tool_export(principal, offset, length, create)
                        .await
                }
            };
            let _ = send.send(result);
        });
        receive.await.map_err(|_| {
            Error::engine("export_snapshot task stopped before producing a response")
        })?
    }

    async fn start_tool_export<F, Fut>(
        &self,
        principal: String,
        offset: u64,
        length: usize,
        create: F,
    ) -> Result<SnapshotPage, Error>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Export, Error>>,
    {
        let activity = self.try_begin(principal.clone()).ok_or_else(|| {
            Error::engine(
                "export_snapshot: an export is already in progress for this account; retry after it completes",
            )
        })?;
        let mut export = create().await?;
        // Filter before the file is opened, hashed or described: the manifest
        // must cover exactly the bytes that ship.
        if let Err(err) = export.filter_disposable_for_standby().await {
            export.cleanup().await;
            drop(activity);
            return Err(err);
        }
        let mut file = match tokio::fs::File::open(export.path()).await {
            Ok(file) => file,
            Err(err) => {
                export.cleanup().await;
                drop(activity);
                return Err(err.into());
            }
        };
        let sha256 = match sha256_file(&mut file).await {
            Ok(sha256) => sha256,
            Err(err) => {
                drop(file);
                export.cleanup().await;
                drop(activity);
                return Err(err);
            }
        };
        let manifest = match export.hosted_standby_context() {
            Some(context) => match crate::standby_snapshot::manifest_from_completed_export(
                &export.path(),
                export.size_bytes(),
                sha256.clone(),
                export.captured_at().to_string(),
                export.snapshot_completed_at().to_string(),
                context,
            )
            .await
            {
                Ok(manifest) => Some(manifest),
                Err(err) => {
                    drop(file);
                    export.cleanup().await;
                    drop(activity);
                    return Err(err);
                }
            },
            None => None,
        };
        if let Err(err) = file.seek(std::io::SeekFrom::Start(0)).await {
            drop(file);
            export.cleanup().await;
            drop(activity);
            return Err(err.into());
        }
        let export_id = Uuid::new_v4().to_string();
        let deadline = tokio::time::Instant::now() + self.inner.tool_export_idle_ttl;
        let (idle_deadline, idle_deadlines) = tokio::sync::watch::channel(deadline);
        let transfer = Arc::new(tokio::sync::Mutex::new(Some(ToolExport {
            principal,
            file,
            export,
            activity,
            sha256,
            manifest,
            idle_deadline,
        })));

        // A shutdown may begin while VACUUM/verification is running. Refuse to
        // retain a fresh handle after drain closed admission.
        let inserted = {
            let state = self
                .inner
                .state
                .lock()
                .expect("export coordinator poisoned");
            if state.accepting {
                self.inner
                    .tool_exports
                    .lock()
                    .expect("export coordinator poisoned")
                    .insert(export_id.clone(), transfer.clone());
            }
            state.accepting
        };
        if !inserted {
            if let Some(export) = transfer.lock().await.take() {
                export.cleanup().await;
            }
            return Err(Error::engine(
                "export_snapshot: server is shutting down and no longer accepts exports",
            ));
        }
        // Exactly one expiry worker owns this handle's mutable deadline. Page
        // reads move the deadline through the watch channel; they never spawn
        // another sleeper, so retries and tiny pages cannot grow task count.
        self.spawn_tool_expiry_worker(export_id.clone(), Arc::downgrade(&transfer), idle_deadlines);
        self.read_tool_page_from(transfer, &export_id, offset, length)
            .await
    }

    async fn read_tool_page(
        &self,
        principal: &str,
        export_id: &str,
        offset: u64,
        length: usize,
    ) -> Result<SnapshotPage, Error> {
        let transfer = self
            .inner
            .tool_exports
            .lock()
            .expect("export coordinator poisoned")
            .get(export_id)
            .cloned();
        let Some(transfer) = transfer else {
            let completed = self
                .inner
                .completed_tool_exports
                .lock()
                .expect("export coordinator poisoned")
                .get(export_id, tokio::time::Instant::now());
            if let Some(completed) = completed {
                if completed.principal != principal {
                    return Err(Error::Auth(
                        "export_snapshot: export handle belongs to another account".into(),
                    ));
                }
                if completed.page.offset != offset || completed.page.length > length {
                    return Err(Error::engine(format!(
                        "export_snapshot: completed export {export_id} only retains its final page at offset {} with length {}",
                        completed.page.offset, completed.page.length
                    )));
                }
                return Ok(completed.page);
            }
            return Err(Error::engine(format!(
                "export_snapshot: export_id {export_id} does not exist or has expired"
            )));
        };
        {
            let guard = transfer.lock().await;
            let export = guard.as_ref().ok_or_else(|| {
                Error::engine(format!(
                    "export_snapshot: export_id {export_id} is no longer available"
                ))
            })?;
            if export.principal != principal {
                return Err(Error::Auth(
                    "export_snapshot: export handle belongs to another account".into(),
                ));
            }
        }
        self.read_tool_page_from(transfer, export_id, offset, length)
            .await
    }

    async fn read_tool_page_from(
        &self,
        transfer: Arc<tokio::sync::Mutex<Option<ToolExport>>>,
        export_id: &str,
        offset: u64,
        length: usize,
    ) -> Result<SnapshotPage, Error> {
        let mut guard = transfer.lock().await;
        let export = guard.as_mut().ok_or_else(|| {
            Error::engine(format!(
                "export_snapshot: export_id {export_id} is no longer available"
            ))
        })?;
        let size_bytes = export.export.size_bytes();
        if offset >= size_bytes {
            return Err(Error::engine(format!(
                "export_snapshot: offset {offset} is outside the {size_bytes}-byte snapshot"
            )));
        }
        export.file.seek(std::io::SeekFrom::Start(offset)).await?;
        let available = size_bytes.saturating_sub(offset).min(length as u64) as usize;
        let mut bytes = vec![0; available];
        export.file.read_exact(&mut bytes).await?;
        let eof = offset + available as u64 == size_bytes;
        let page = SnapshotPage {
            export_id: export_id.to_string(),
            file_name: "native-ce-export.db".into(),
            media_type: SQLITE_MEDIA_TYPE.into(),
            size_bytes,
            sha256: export.sha256.clone(),
            offset,
            length: available,
            eof,
            data_base64: base64_encode(&bytes),
            expires_in_seconds: self.inner.tool_export_idle_ttl.as_secs(),
            manifest: export.manifest.clone(),
        };

        if eof {
            let export = guard.take().expect("tool export exists");
            let principal = export.principal.clone();
            drop(guard);
            self.remove_tool_transfer(export_id, &transfer);
            let accepting = self
                .inner
                .state
                .lock()
                .expect("export coordinator poisoned")
                .accepting;
            if accepting {
                self.cache_completed_tool_export(
                    export_id.to_string(),
                    CompletedToolExport {
                        principal,
                        page: page.clone(),
                        expires_at: tokio::time::Instant::now() + self.inner.tool_export_idle_ttl,
                    },
                );
            }
            export.cleanup().await;
        } else {
            export
                .idle_deadline
                .send_replace(tokio::time::Instant::now() + self.inner.tool_export_idle_ttl);
            drop(guard);
        }
        Ok(page)
    }

    fn remove_tool_transfer(
        &self,
        export_id: &str,
        expected: &Arc<tokio::sync::Mutex<Option<ToolExport>>>,
    ) {
        let mut transfers = self
            .inner
            .tool_exports
            .lock()
            .expect("export coordinator poisoned");
        if transfers
            .get(export_id)
            .is_some_and(|current| Arc::ptr_eq(current, expected))
        {
            transfers.remove(export_id);
        }
    }

    fn spawn_tool_expiry_worker(
        &self,
        export_id: String,
        transfer: std::sync::Weak<tokio::sync::Mutex<Option<ToolExport>>>,
        mut deadlines: tokio::sync::watch::Receiver<tokio::time::Instant>,
    ) {
        let coordinator = Arc::downgrade(&self.inner);
        let worker_count = self.inner.tool_expiry_workers.clone();
        worker_count.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let _worker = WorkerCountGuard(worker_count);
            loop {
                let deadline = *deadlines.borrow_and_update();
                tokio::select! {
                    changed = deadlines.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        continue;
                    }
                    _ = tokio::time::sleep_until(deadline) => {}
                }

                // A deadline update can race the timer becoming ready. Read
                // the latest value again, and only expire when it too is due.
                if *deadlines.borrow_and_update() > tokio::time::Instant::now() {
                    continue;
                }
                let Some(transfer) = transfer.upgrade() else {
                    return;
                };
                let mut guard = transfer.lock().await;
                if *deadlines.borrow() > tokio::time::Instant::now() {
                    continue;
                }
                let Some(export) = guard.take() else {
                    return;
                };
                drop(guard);
                let Some(inner) = coordinator.upgrade() else {
                    export.cleanup().await;
                    return;
                };
                let coordinator = ExportCoordinator { inner };
                coordinator.remove_tool_transfer(&export_id, &transfer);
                export.cleanup().await;
                return;
            }
        });
    }

    fn cache_completed_tool_export(&self, export_id: String, export: CompletedToolExport) {
        let start_worker = self
            .inner
            .completed_tool_exports
            .lock()
            .expect("export coordinator poisoned")
            .insert(export_id, export);
        self.inner.completed_cache_changed.notify_one();
        if start_worker {
            self.spawn_completed_cache_worker();
        }
    }

    fn spawn_completed_cache_worker(&self) {
        let coordinator = Arc::downgrade(&self.inner);
        let worker_count = self.inner.completed_cache_workers.clone();
        worker_count.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let _worker = WorkerCountGuard(worker_count);
            loop {
                let Some(inner) = coordinator.upgrade() else {
                    return;
                };
                let deadline = {
                    let mut cache = inner
                        .completed_tool_exports
                        .lock()
                        .expect("export coordinator poisoned");
                    cache.purge_expired(tokio::time::Instant::now());
                    match cache.next_expiry() {
                        Some(deadline) => deadline,
                        None => {
                            cache.worker_running = false;
                            return;
                        }
                    }
                };
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => {}
                    _ = inner.completed_cache_changed.notified() => {}
                }
            }
        });
    }

    #[cfg(test)]
    fn tool_expiry_worker_count(&self) -> usize {
        self.inner.tool_expiry_workers.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn completed_cache_worker_count(&self) -> usize {
        self.inner.completed_cache_workers.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn completed_cache_len(&self) -> usize {
        self.inner
            .completed_tool_exports
            .lock()
            .expect("export coordinator poisoned")
            .entries
            .len()
    }
}

impl Default for ExportCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Ownership token for a complete export lifecycle.
#[doc(hidden)]
pub struct ExportActivity {
    coordinator: std::sync::Weak<ExportCoordinatorInner>,
    principal: String,
}

impl Drop for ExportActivity {
    fn drop(&mut self) {
        let Some(coordinator) = self.coordinator.upgrade() else {
            return;
        };
        let removed = coordinator
            .state
            .lock()
            .expect("export coordinator poisoned")
            .active
            .remove(&self.principal);
        if removed {
            coordinator
                .changes
                .send_modify(|generation| *generation = generation.wrapping_add(1));
        }
    }
}

#[derive(Clone)]
struct CompletedToolExport {
    principal: String,
    page: SnapshotPage,
    expires_at: tokio::time::Instant,
}

#[derive(Default)]
struct CompletedToolExportCache {
    entries: HashMap<String, CompletedToolExport>,
    insertion_order: VecDeque<String>,
    worker_running: bool,
}

impl CompletedToolExportCache {
    fn insert(&mut self, export_id: String, export: CompletedToolExport) -> bool {
        self.purge_expired(tokio::time::Instant::now());
        if let Some(previous) = self
            .entries
            .iter()
            .find_map(|(id, existing)| (existing.principal == export.principal).then(|| id.clone()))
        {
            self.remove(&previous);
        }
        self.entries.insert(export_id.clone(), export);
        self.insertion_order.push_back(export_id);
        while self.entries.len() > SNAPSHOT_COMPLETED_CACHE_CAP {
            if let Some(oldest) = self.insertion_order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        let start_worker = !self.worker_running;
        self.worker_running = true;
        start_worker
    }

    fn get(&mut self, export_id: &str, now: tokio::time::Instant) -> Option<CompletedToolExport> {
        self.purge_expired(now);
        self.entries.get(export_id).cloned()
    }

    fn remove(&mut self, export_id: &str) {
        self.entries.remove(export_id);
        self.insertion_order.retain(|id| id != export_id);
    }

    fn purge_expired(&mut self, now: tokio::time::Instant) {
        self.entries.retain(|_, export| export.expires_at > now);
        self.insertion_order
            .retain(|id| self.entries.contains_key(id));
    }

    fn next_expiry(&self) -> Option<tokio::time::Instant> {
        self.entries.values().map(|export| export.expires_at).min()
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.insertion_order.clear();
    }
}

struct WorkerCountGuard(Arc<AtomicUsize>);

impl Drop for WorkerCountGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct ToolExport {
    principal: String,
    file: tokio::fs::File,
    export: Export,
    activity: ExportActivity,
    sha256: String,
    manifest: Option<crate::standby_snapshot::StandbySnapshotManifest>,
    idle_deadline: tokio::sync::watch::Sender<tokio::time::Instant>,
}

impl ToolExport {
    async fn cleanup(self) {
        drop(self.file);
        self.export.cleanup().await;
        drop(self.activity);
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

async fn sha256_file(file: &mut tokio::fs::File) -> Result<String, Error> {
    let mut digest = Sha256::new();
    let mut buffer = vec![0; STREAM_CHUNK_BYTES];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            return Ok(hex::encode(digest.finalize()));
        }
        digest.update(&buffer[..read]);
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    async fn paged_tool_db() -> crate::Db {
        let db = crate::create_database(":memory:").await.unwrap();
        // Keep this fixture larger than the 1 KiB pagination cases but safely
        // below SNAPSHOT_MAX_PAGE_BYTES after fresh-schema seed metadata.
        sqlx::query(
            "INSERT INTO blobs
             (id, bytes, size_bytes, storage_tier, created_at)
             VALUES ('padding', zeroblob(100000), 100000, 'inline', '2026-07-31T00:00:00Z')",
        )
        .execute(db.write_pool())
        .await
        .unwrap();
        db
    }

    fn export_factory(
        db: crate::Db,
    ) -> impl FnOnce() -> std::pin::Pin<Box<dyn Future<Output = Result<Export, Error>> + Send>> + Send
    {
        let root = db.path().parent().map(std::path::Path::to_path_buf);
        move || {
            Box::pin(async move { crate::export::export_connected_db(&db, root.as_deref()).await })
        }
    }

    fn tiny_export_factory(
    ) -> impl FnOnce() -> std::pin::Pin<Box<dyn Future<Output = Result<Export, Error>> + Send>> + Send
    {
        move || {
            Box::pin(async move {
                let dir = tempfile::tempdir().unwrap();
                std::fs::write(dir.path().join("snapshot.db"), b"tiny export fixture").unwrap();
                Ok(Export::test_fixture(dir, "snapshot.db"))
            })
        }
    }

    #[tokio::test]
    async fn abandoned_tool_handle_expires_and_releases_after_cleanup() {
        let db = paged_tool_db().await;
        let coordinator = ExportCoordinator::with_tool_export_idle_ttl(Duration::from_millis(30));
        let page = coordinator
            .tool_page("user".into(), None, 0, 1024, export_factory(db.clone()))
            .await
            .unwrap();
        assert!(!page.eof);
        assert!(coordinator.try_begin("user".into()).is_none());

        tokio::time::timeout(Duration::from_secs(2), coordinator.wait_for_idle())
            .await
            .expect("idle timeout did not reclaim abandoned tool export");
        assert!(coordinator
            .tool_page(
                "user".into(),
                Some(page.export_id),
                page.length as u64,
                1024,
                export_factory(db.clone()),
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("does not exist or has expired"));
        let _reacquired = coordinator
            .try_begin("user".into())
            .expect("idle expiry did not release principal lease");
        db.close().await;
    }

    #[tokio::test]
    async fn repeated_page_reads_keep_one_expiry_worker_per_handle() {
        let db = paged_tool_db().await;
        let coordinator = ExportCoordinator::with_tool_export_idle_ttl(Duration::from_millis(250));
        let first = coordinator
            .tool_page("user".into(), None, 0, 1024, export_factory(db.clone()))
            .await
            .unwrap();
        assert!(!first.eof);
        assert_eq!(coordinator.tool_expiry_worker_count(), 1);

        for _ in 0..100 {
            let retry = coordinator
                .tool_page(
                    "user".into(),
                    Some(first.export_id.clone()),
                    0,
                    1024,
                    export_factory(db.clone()),
                )
                .await
                .unwrap();
            assert_eq!(retry.data_base64, first.data_base64);
            assert_eq!(coordinator.tool_expiry_worker_count(), 1);
        }

        coordinator.drain().await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while coordinator.tool_expiry_worker_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("handle expiry worker did not stop after drain");
        db.close().await;
    }

    #[tokio::test]
    async fn completed_page_cache_is_principal_bounded_and_globally_capped() {
        // This test is about completed-handle cache ownership, not the exact
        // size of the evolving engine schema. Use a tiny synthetic export so a
        // max-size page remains one request as the database schema grows.
        let coordinator = ExportCoordinator::new();
        let mut pages = Vec::new();

        for index in 0..(SNAPSHOT_COMPLETED_CACHE_CAP + 2) {
            let principal = format!("user-{index}");
            let page = coordinator
                .tool_page(
                    principal.clone(),
                    None,
                    0,
                    crate::mcp::SNAPSHOT_MAX_PAGE_BYTES,
                    tiny_export_factory(),
                )
                .await
                .unwrap();
            assert!(page.eof);
            pages.push((principal, page));
        }

        assert_eq!(
            coordinator.completed_cache_len(),
            SNAPSHOT_COMPLETED_CACHE_CAP
        );
        assert_eq!(coordinator.completed_cache_worker_count(), 1);

        let (oldest_principal, oldest) = &pages[0];
        let evicted = coordinator
            .tool_page(
                oldest_principal.clone(),
                Some(oldest.export_id.clone()),
                oldest.offset,
                crate::mcp::SNAPSHOT_MAX_PAGE_BYTES,
                tiny_export_factory(),
            )
            .await
            .unwrap_err();
        assert!(evicted
            .to_string()
            .contains("does not exist or has expired"));

        let (replacement_principal, previous) = pages.last().unwrap();
        let replacement = coordinator
            .tool_page(
                replacement_principal.clone(),
                None,
                0,
                crate::mcp::SNAPSHOT_MAX_PAGE_BYTES,
                tiny_export_factory(),
            )
            .await
            .unwrap();
        assert!(replacement.eof);
        assert_eq!(
            coordinator.completed_cache_len(),
            SNAPSHOT_COMPLETED_CACHE_CAP
        );
        assert_eq!(coordinator.completed_cache_worker_count(), 1);

        let wrong_principal = coordinator
            .tool_page(
                "intruder".into(),
                Some(replacement.export_id.clone()),
                replacement.offset,
                crate::mcp::SNAPSHOT_MAX_PAGE_BYTES,
                tiny_export_factory(),
            )
            .await
            .unwrap_err();
        assert!(matches!(wrong_principal, Error::Auth(_)));

        let replaced = coordinator
            .tool_page(
                replacement_principal.clone(),
                Some(previous.export_id.clone()),
                previous.offset,
                crate::mcp::SNAPSHOT_MAX_PAGE_BYTES,
                tiny_export_factory(),
            )
            .await
            .unwrap_err();
        assert!(replaced
            .to_string()
            .contains("does not exist or has expired"));
        let retry = coordinator
            .tool_page(
                replacement_principal.clone(),
                Some(replacement.export_id.clone()),
                replacement.offset,
                crate::mcp::SNAPSHOT_MAX_PAGE_BYTES,
                tiny_export_factory(),
            )
            .await
            .unwrap();
        assert_eq!(retry.data_base64, replacement.data_base64);

        coordinator.drain().await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while coordinator.completed_cache_worker_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed-cache worker did not stop after drain");
    }

    #[tokio::test]
    async fn an_older_cache_deadline_cannot_evict_its_principals_replacement() {
        let coordinator = ExportCoordinator::with_tool_export_idle_ttl(Duration::from_millis(500));
        let first = coordinator
            .tool_page(
                "user".into(),
                None,
                0,
                crate::mcp::SNAPSHOT_MAX_PAGE_BYTES,
                tiny_export_factory(),
            )
            .await
            .unwrap();
        assert!(first.eof);

        tokio::time::sleep(Duration::from_millis(300)).await;
        let replacement = coordinator
            .tool_page(
                "user".into(),
                None,
                0,
                crate::mcp::SNAPSHOT_MAX_PAGE_BYTES,
                tiny_export_factory(),
            )
            .await
            .unwrap();
        assert!(replacement.eof);
        assert_ne!(replacement.export_id, first.export_id);

        // The first entry's deadline has passed, while the replacement still
        // has time remaining. A stale per-entry sleeper would wrongly remove
        // the replacement here.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let retry = coordinator
            .tool_page(
                "user".into(),
                Some(replacement.export_id.clone()),
                replacement.offset,
                crate::mcp::SNAPSHOT_MAX_PAGE_BYTES,
                tiny_export_factory(),
            )
            .await
            .unwrap();
        assert_eq!(retry.data_base64, replacement.data_base64);

        tokio::time::timeout(Duration::from_secs(2), async {
            while coordinator.completed_cache_len() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("replacement cache entry did not expire");
    }

    #[tokio::test]
    async fn cancelled_tool_request_cannot_cancel_generation_or_cleanup() {
        let db = paged_tool_db().await;
        let coordinator = ExportCoordinator::with_tool_export_idle_ttl(Duration::from_millis(30));
        let request_coordinator = coordinator.clone();
        let request_db = db.clone();
        let request = tokio::spawn(async move {
            request_coordinator
                .tool_page("user".into(), None, 0, 1024, export_factory(request_db))
                .await
        });

        let mut observed_active = false;
        for _ in 0..100 {
            if coordinator.try_begin("user".into()).is_none() {
                observed_active = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(observed_active, "tool generation never acquired its lease");
        request.abort();
        let _ = request.await;
        assert!(
            coordinator.try_begin("user".into()).is_none(),
            "cancelled request released its independently-owned export task"
        );
        tokio::time::timeout(Duration::from_secs(2), coordinator.wait_for_idle())
            .await
            .expect("cancelled request left generation or cleanup stranded");
        let _reacquired = coordinator
            .try_begin("user".into())
            .expect("cleanup did not release cancelled request's lease");
        db.close().await;
    }

    #[tokio::test]
    async fn cancelled_tool_request_keeps_a_blocked_generation_owned_until_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("snapshot.db"), b"gated export fixture").unwrap();
        let path = dir.path().join("snapshot.db");
        let export = Export::test_fixture(dir, "snapshot.db");
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let coordinator = ExportCoordinator::new();
        let request_coordinator = coordinator.clone();
        let request = tokio::spawn(async move {
            request_coordinator
                .tool_page("user".into(), None, 0, 1024, move || async move {
                    wait.await.unwrap();
                    Ok(export)
                })
                .await
        });

        for _ in 0..100 {
            if coordinator.try_begin("user".into()).is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(coordinator.try_begin("user".into()).is_none());
        request.abort();
        let _ = request.await;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), coordinator.wait_for_idle())
                .await
                .is_err(),
            "cancelled request made blocked generation invisible"
        );

        release.send(()).unwrap();
        coordinator.wait_for_idle().await;
        assert!(!path.exists(), "lease released before snapshot cleanup");
        let _reacquired = coordinator
            .try_begin("user".into())
            .expect("cleanup did not release cancelled request's lease");
    }

    #[tokio::test]
    async fn drain_during_generation_cleans_the_unpublished_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("snapshot.db"), b"gated export fixture").unwrap();
        let path = dir.path().join("snapshot.db");
        let export = Export::test_fixture(dir, "snapshot.db");
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let coordinator = ExportCoordinator::new();
        let request_coordinator = coordinator.clone();
        let request = tokio::spawn(async move {
            request_coordinator
                .tool_page("user".into(), None, 0, 1024, move || async move {
                    wait.await.unwrap();
                    Ok(export)
                })
                .await
        });

        for _ in 0..100 {
            if coordinator.try_begin("user".into()).is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(coordinator.try_begin("user".into()).is_none());
        let drain_coordinator = coordinator.clone();
        let drain = tokio::spawn(async move { drain_coordinator.drain().await });
        let mut observed_closed_admission = false;
        for _ in 0..100 {
            if coordinator.try_begin("late".into()).is_none() {
                observed_closed_admission = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            observed_closed_admission,
            "drain never closed export admission"
        );
        release.send(()).unwrap();

        let error = request.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("shutting down"));
        drain.await.unwrap();
        assert!(!path.exists(), "drain completed before snapshot cleanup");
        assert!(coordinator.try_begin("late".into()).is_none());
    }
}
