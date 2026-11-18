//! Opt-in proof: a disposable engine fork of the accepted v1 generation.
//! The durable node journal is the only reconstruction input. Hosted custody,
//! forwarding, validation and replay are owned by the existing gate.
use super::*;
use crate::fork::{
    ForkArea, ForkKey, ForkLimits, ForkManager, ForkState, OrderedJournaledCalls, PreparedCall,
};
use crate::mcp::Caller;
use futures::FutureExt;
use std::sync::atomic::Ordering;
use tokio::sync::Mutex;

#[cfg(test)]
type PreviewPause = (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>);

#[derive(Default)]
pub(super) struct PendingFork {
    inner: Mutex<Option<Active>>,
    wake: tokio::sync::Notify,
    handoff: std::sync::atomic::AtomicUsize,
    notices: DeltaQueue,
    gap: std::sync::atomic::AtomicBool,
    unsupported: Mutex<Option<(ForkKey, String)>>,
    stopping: std::sync::atomic::AtomicBool,
    worker: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    #[cfg(test)]
    pub(super) prepare_delay_ms: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    pub(super) prepare_attempts: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    pub(super) fail_prepare: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    pub(super) fail_enable: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    pub(super) panic_rebase: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    mismatch_head: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    pub(super) pause_rebase: std::sync::Mutex<Option<PreviewPause>>,
    #[cfg(test)]
    pub(super) pause_replay: std::sync::Mutex<Option<PreviewPause>>,
    #[cfg(test)]
    pub(super) pause_preview: std::sync::Mutex<Option<PreviewPause>>,
}
struct Active {
    manager: Arc<ForkManager>,
    key: ForkKey,
    fingerprint: String,
    calls: Vec<PreparedCall>,
    snapshot: String,
    payloads: Vec<(String, String, Value)>,
    // Holds the serving pool/reader lease until discard has completed.
    _base: crate::mcp::standby_stdio::PendingForkBase,
}
struct DeltaNotice {
    generation: String,
    delta: crate::standby::act_materialise::TrustedAuthorityActDelta,
}
struct DeltaQueue {
    sender: tokio::sync::mpsc::Sender<DeltaNotice>,
    receiver: std::sync::Mutex<tokio::sync::mpsc::Receiver<DeltaNotice>>,
}
impl Default for DeltaQueue {
    fn default() -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        Self {
            sender,
            receiver: std::sync::Mutex::new(receiver),
        }
    }
}
struct DeltaObserver {
    owner: std::sync::Weak<PendingFork>,
}
impl crate::standby::AcceptedDeltaObserver for DeltaObserver {
    fn begin(&self) {
        if let Some(owner) = self.owner.upgrade() {
            owner.handoff.fetch_add(1, Ordering::AcqRel);
        }
    }
    fn finish(&self) {
        if let Some(owner) = self.owner.upgrade() {
            // Publication failed before enqueue. The next owner check must not
            // adopt a head for which it never received the trusted delta.
            owner.gap.store(true, Ordering::Release);
            owner.handoff.fetch_sub(1, Ordering::AcqRel);
            owner.wake();
        }
    }
    fn committed(
        &self,
        generation: String,
        delta: crate::standby::act_materialise::TrustedAuthorityActDelta,
    ) {
        if let Some(owner) = self.owner.upgrade() {
            if owner
                .notices
                .sender
                .try_send(DeltaNotice { generation, delta })
                .is_err()
            {
                owner.gap.store(true, Ordering::Release);
                owner.handoff.fetch_sub(1, Ordering::AcqRel);
            }
            owner.wake();
        }
    }
}

struct Calls(Vec<PreparedCall>);
impl OrderedJournaledCalls for Calls {
    fn ordered_calls<'a>(
        &'a self,
        _: &'a ForkKey,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<PreparedCall>>> + Send + 'a>>
    {
        Box::pin(async { Ok(self.0.clone()) })
    }
}
fn error(e: impl std::fmt::Display) -> Error {
    Error::engine(format!("node pending fork: {e}"))
}

fn transient(error: &Error) -> bool {
    let message = error.to_string();
    [
        "base advanced during preview",
        "headroom",
        "journal changed",
    ]
    .iter()
    .any(|s| message.contains(s))
}
fn unsupported(message: &str) -> bool {
    [
        "unsupported",
        "no such table: sqlite_sequence",
        "no such function",
        "unknown function",
        "no such collation",
    ]
    .iter()
    .any(|s| message.contains(s))
}
async fn schema_fingerprint(db: &crate::Db) -> Result<String> {
    use sha2::{Digest, Sha256};
    let rows: Vec<(String, String, Option<String>)> =
        sqlx::query_as("SELECT type,name,sql FROM sqlite_schema ORDER BY type,name")
            .fetch_all(db.pool())
            .await?;
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&rows)?)))
}

/// Use the engine's locked stale-file cleanup before any headroom check.
/// A disabled proof must not strand a previous process's multi-GB copy.
pub(super) fn cleanup_stale_area(directory: &std::path::Path) {
    if directory.join("hosted-outbox/forks").exists() {
        if let Err(error) = ForkArea::new(directory, &[]) {
            tracing::warn!(%error, "could not clean stale pending fork area");
        }
    }
}

async fn reservation(db: &crate::Db) -> Result<u64> {
    let pages: i64 = sqlx::query_scalar("PRAGMA page_count")
        .fetch_one(db.pool())
        .await?;
    let size: i64 = sqlx::query_scalar("PRAGMA page_size")
        .fetch_one(db.pool())
        .await?;
    Ok((pages as u64)
        .saturating_mul(size as u64)
        .saturating_mul(2)
        .saturating_add(128 * 1024 * 1024))
}

fn retry_delay(failures: u32) -> Duration {
    Duration::from_secs(1u64 << failures.saturating_sub(1).min(6)).min(Duration::from_secs(60))
}

pub(super) fn previewable(entry: &super::journal::Entry) -> bool {
    if entry.version != 1 || entry.custody_compatibility.is_some() {
        return false;
    }
    let Some(mut args) = entry.arguments.clone().or(entry.fork_arguments.clone()) else {
        return false;
    };
    // Journal arguments exclude the executor envelope. Shape validation needs
    // the same run/parent reconstruction used by actual fork dispatch.
    if let Some(run) = entry.fork_run_key.as_ref().or(entry.run_key.as_ref()) {
        args["run_key"] = json!(run);
    }
    if let Some(parent) = &entry.parent_key {
        args["parent_key"] = json!(parent);
    }
    entry.executor == "records_write"
        && (entry.operation != "create_record"
            || (args["type"] == "Document" && args["kind"] == "note"))
        && crate::fork::validate_shape(&entry.operation, &args, true, 1024 * 1024).is_ok()
}

impl PendingFork {
    pub(super) fn observe(self: &Arc<Self>, hints: &crate::standby::RefreshHints) {
        hints.observe_accepted_deltas(Arc::new(DeltaObserver {
            owner: Arc::downgrade(self),
        }));
    }
    pub(super) fn start(
        self: &Arc<Self>,
        dispatcher: crate::mcp::standby_stdio::StandbyDispatcher,
        config: NodeConfig,
        gate: Arc<WriteGate>,
        hints: Option<&crate::standby::RefreshHints>,
    ) {
        if let Some(hints) = hints {
            self.observe(hints);
        }
        let weak = Arc::downgrade(self);
        let worker = tokio::spawn(async move {
            let mut failures = 0u32;
            let mut retry_at = tokio::time::Instant::now();
            let mut previous_base = None;
            loop {
                let Some(this) = weak.upgrade() else { break };
                if this.stopping.load(std::sync::atomic::Ordering::Acquire) {
                    break;
                }
                this.process_notices().await;
                let context = dispatcher.serving_context();
                let base = context.as_ref().map(|c| c.serving_generation_id.clone());
                let changed = base != previous_base;
                // Release a superseded lease even during negative-cache cooldown.
                if changed || !gate.preview_space(0) {
                    if let Err(error) = this.discard().await {
                        tracing::warn!(%error, "pending fork discard failed");
                    }
                }
                if changed {
                    failures = 0;
                    retry_at = tokio::time::Instant::now();
                }
                previous_base = base;
                if tokio::time::Instant::now() >= retry_at {
                    let result = std::panic::AssertUnwindSafe(this.read_or_sync(
                        &dispatcher,
                        &config,
                        &gate,
                        None,
                    ))
                    .catch_unwind()
                    .await
                    .unwrap_or_else(|_| Err(error("pending replay panicked")));
                    if let Err(error) = result {
                        if !transient(&error) {
                            let _ = this.discard().await;
                        }
                        failures = failures.saturating_add(1);
                        retry_at = tokio::time::Instant::now() + retry_delay(failures);
                        tracing::warn!(%error, failures, "pending fork unavailable; normal routing continues");
                    } else {
                        failures = 0;
                    }
                }
                // No strong owner while idle; dropping the router does not leak a worker.
                let notified = this.wake.notified();
                tokio::select! { _ = notified => {}, _ = tokio::time::sleep(Duration::from_millis(100)) => {} }
                drop(this);
            }
        });
        *self.worker.lock().unwrap_or_else(|e| e.into_inner()) = Some(worker);
    }
    #[cfg(test)]
    pub(super) async fn copy_count_for_test(&self) -> u64 {
        self.inner
            .lock()
            .await
            .as_ref()
            .map_or(0, |active| active.manager.copy_count_for_test())
    }
    #[cfg(test)]
    pub(super) async fn unsupported_for_test(&self) -> bool {
        self.unsupported.lock().await.is_some()
    }
    #[cfg(test)]
    pub(super) async fn mismatch_head_for_test(&self) {
        self.mismatch_head.store(true, Ordering::Release);
    }

    // This runs exclusively on the node runtime. Refresh only pushes to the
    // bounded queue; it never locks inner or awaits filesystem/engine work.
    async fn process_notices(&self) {
        loop {
            if self.gap.swap(false, Ordering::AcqRel) {
                let _ = self.discard().await;
            }
            let notice = self
                .notices
                .receiver
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .try_recv()
                .ok();
            let Some(notice) = notice else { break };
            if self.stopping.load(Ordering::Acquire) {
                self.handoff.fetch_sub(1, Ordering::AcqRel);
                continue;
            }
            let outcome = tokio::time::timeout(
                Duration::from_secs(120),
                std::panic::AssertUnwindSafe(self.apply_notice(notice)).catch_unwind(),
            )
            .await;
            if !matches!(outcome, Ok(Ok(Ok(())))) {
                tracing::warn!("pending rebase failed, panicked or exceeded 120s; rebuilding");
                // Discard drains any raw inverse job which outlived cancellation
                // before closing/unlinking its private database.
                let _ = self.discard().await;
            }
            self.handoff.fetch_sub(1, Ordering::AcqRel);
        }
    }
    async fn apply_notice(&self, notice: DeltaNotice) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let Some(active) = inner.as_mut() else {
            return Ok(());
        };
        #[cfg(test)]
        {
            let pause = self
                .pause_rebase
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some((entered, resume)) = pause {
                entered.notify_one();
                resume.notified().await;
            }
            assert!(
                !self.panic_rebase.swap(false, Ordering::AcqRel),
                "injected rebase panic"
            );
        }
        #[cfg(test)]
        if self.mismatch_head.swap(false, Ordering::AcqRel) {
            active._base.context.serving_head_act = Some(-1);
        }
        if active._base.context.serving_generation_id.as_deref() != Some(&notice.generation)
            || active._base.context.serving_head_act != Some(notice.delta.from_exclusive_act())
        {
            return Err(error("missing or out-of-order delta"));
        }
        if active.snapshot == "[]" {
            // A preceding accepted advance has not replayed yet. Seal that
            // empty interval before starting the next marker. Otherwise keep
            // its marker throughout replay until journal publication finishes.
            active
                .manager
                .finish_rebase(
                    &active.key,
                    notice.delta.from_exclusive_act(),
                    &active.snapshot,
                )
                .await
                .map_err(error)?;
        }
        let result = active
            .manager
            .rebase_accepted(&active.key, &notice.delta, &active.snapshot)
            .await;
        if let Err(failure) = result {
            if unsupported(&failure.to_string()) {
                *self.unsupported.lock().await = Some((
                    active.key.clone(),
                    schema_fingerprint(&active._base.db).await?,
                ));
            }
            return Err(error(failure));
        }
        active._base.context.serving_head_act = Some(notice.delta.to_inclusive_act());
        active.fingerprint.clear();
        active.calls.clear();
        active.payloads.clear();
        active.snapshot = "[]".into();
        // Keep the marker through replay. A following queued delta seals the
        // empty interval above before creating its own marker.
        Ok(())
    }
    pub(super) fn wake(&self) {
        self.wake.notify_one();
    }
    async fn discard(&self) -> Result<()> {
        let active = self.inner.lock().await.take();
        if let Some(active) = active {
            active.manager.discard(&active.key).await.map_err(error)?;
        }
        Ok(())
    }
    /// Release the base lease before the standby supervisor drains generations.
    pub(super) async fn shutdown(&self) -> Result<()> {
        self.stopping
            .store(true, std::sync::atomic::Ordering::Release);
        self.wake();
        let worker = self.worker.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(worker) = worker {
            let _ = worker.await;
        }
        self.discard().await
    }

    /// Serialises preview admission with rebuild and reads. A missed trusted
    /// handoff falls back to the original full-copy admission path.
    pub(super) async fn read_or_sync(
        &self,
        dispatcher: &crate::mcp::standby_stdio::StandbyDispatcher,
        config: &NodeConfig,
        gate: &WriteGate,
        read: Option<(&str, Value)>,
    ) -> Result<Option<Value>> {
        if let Some(read) = read {
            return self.read_ready(dispatcher, gate, read).await;
        }
        if self.handoff.load(Ordering::Acquire) != 0 || self.gap.load(Ordering::Acquire) {
            return Ok(None);
        }
        let base = dispatcher
            .pending_fork_base()
            .ok_or_else(|| error("no serving v1 generation"))?;
        let act = base
            .context
            .serving_head_act
            .ok_or_else(|| error("base act unavailable"))?;
        // The persisted head disclosure can lag an in-place commit. Compare
        // SQLite's own accepted act as well, so VACUUM never straddles cuts.
        let database_act: i64 =
            sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton=1")
                .fetch_one(base.db.pool())
                .await?;
        if database_act != act {
            // Refresh has committed bytes but has not published its head yet.
            // Preserve a successfully rebased owner during this handoff window.
            return Ok(None);
        }
        let generation = base
            .context
            .serving_generation_id
            .clone()
            .ok_or_else(|| error("generation unavailable"))?;
        if config
            .account_id
            .as_deref()
            .is_some_and(|account| account != base.account)
        {
            return Err(error("account binding differs from serving copy"));
        }
        let key = ForkKey {
            window_id: format!("node-{generation}-{}", base.account),
            workspace_id: config.db_id.clone(),
        };
        let caller = Caller::for_node_pending_fork(base.account.clone(), config.db_id.clone());
        gate.journal.retire_fork_payloads(Some(act))?;
        let entries = gate.fork_entries(act)?;
        let journal_snapshot = serde_json::to_string(&entries)?;
        let mut payloads = Vec::new();
        for entry in entries {
            let Some(mut args) = entry.fork_arguments.clone().or(entry.arguments.clone()) else {
                continue;
            };
            // Preserve the calling run from the executor envelope. Do not invent
            // runs or import them into the accepted base to pass fork validation.
            if let Some(run) = entry.fork_run_key.as_ref().or(entry.run_key.as_ref()) {
                args["run_key"] = json!(run);
            }
            if let Some(parent) = &entry.parent_key {
                args["parent_key"] = json!(parent);
            }
            if previewable(&entry)
                && entry.executor == "records_write"
                && (entry.operation != "create_record"
                    || (args["type"] == "Document" && args["kind"] == "note"))
                && crate::fork::validate_shape(&entry.operation, &args, true, 1024 * 1024).is_ok()
            {
                payloads.push((entry.id, entry.operation, args));
            }
        }
        let fingerprint = serde_json::to_string(&payloads)?;
        let mut inner = self.inner.lock().await;
        if self.handoff.load(Ordering::Acquire) != 0 || self.gap.load(Ordering::Acquire) {
            return Ok(None);
        }
        if inner
            .as_ref()
            .is_some_and(|a| a.key != key || a._base.context.serving_head_act != Some(act))
        {
            let active = inner.as_ref().unwrap();
            active.manager.discard(&active.key).await.map_err(error)?;
            *inner = None;
        }
        if payloads.is_empty() {
            if let Some(active) = inner.as_ref() {
                active.manager.discard(&active.key).await.map_err(error)?;
                *inner = None;
            }
            return Ok(None);
        }
        if inner.is_none() {
            let schema = schema_fingerprint(&base.db).await?;
            if self.unsupported.lock().await.as_ref() == Some(&(key.clone(), schema.clone())) {
                return Err(error("unsupported pending schema (cached)"));
            }
            let reserve = reservation(&base.db).await?;
            if reserve > 16 * 1024 * 1024 * 1024 || !gate.preview_space(reserve) {
                return Err(error(
                    "insufficient preview headroom; journal holds take priority",
                ));
            }
            #[cfg(test)]
            {
                self.prepare_attempts
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(
                    self.prepare_delay_ms
                        .load(std::sync::atomic::Ordering::Relaxed),
                ))
                .await;
                if self.fail_prepare.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(error("injected prepare failure"));
                }
            }
            let area = ForkArea::new(&config.socket_directory, &[base.db.path().to_path_buf()])
                .map_err(error)?;
            let limits = ForkLimits {
                max_forks: 1,
                max_reserved_bytes: 16 * 1024 * 1024 * 1024,
                growth_bytes: 128 * 1024 * 1024,
                ..ForkLimits::default()
            };
            let manager = ForkManager::new(area, limits).map_err(error)?;
            manager
                .prepare(key.clone(), base.db.clone())
                .await
                .map_err(error)?;
            // Preparation is manager-owned; cancellation never adopts a partial file.
            while manager.state(&key).await == ForkState::Preparing {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if manager.state(&key).await != ForkState::Ready {
                let _ = manager.discard(&key).await;
                return Err(error("fork preparation failed"));
            }
            #[cfg(test)]
            if self.fail_enable.load(Ordering::Acquire) {
                let db = manager.test_working_db(&key).await.map_err(error)?;
                sqlx::query("CREATE VIRTUAL TABLE unsupported_capture USING fts5(body)")
                    .execute(db.write_pool())
                    .await?;
            }
            if let Err(failure) = manager.enable_rebase(&key).await {
                let _ = manager.discard(&key).await;
                if unsupported(&failure.to_string()) {
                    *self.unsupported.lock().await = Some((key.clone(), schema));
                }
                return Err(error(failure));
            }
            *inner = Some(Active {
                manager,
                key: key.clone(),
                fingerprint: String::new(),
                calls: vec![],
                snapshot: "[]".into(),
                payloads: vec![],
                _base: base,
            });
        }
        let active = inner.as_mut().unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        if active.fingerprint != fingerprint || active.manager.state(&key).await != ForkState::Ready
        {
            let mut calls = Vec::new();
            for (_, operation, args) in &payloads {
                let prepared = tokio::time::timeout_at(
                    deadline,
                    active
                        .manager
                        .prepare_call(&key, &caller, operation, args.clone()),
                )
                .await
                .map_err(|_| error("pending replay preflight exceeded 120s"))?;
                match prepared {
                    Ok(call) => calls.push(call),
                    Err(
                        failure @ (crate::fork::ForkError::RefusedInvalid(_)
                        | crate::fork::ForkError::RefusedUnsupported(_)),
                    ) => {
                        tracing::warn!(%failure, %operation, "excluding invalid pending preview entry")
                    }
                    Err(failure) => return Err(error(failure)),
                }
            }
            // A pure tail addition can dispatch directly. Removal, settlement,
            // uncertainty or a changed prefix requires discard/copy/replay.
            let prefix =
                active.calls.len() <= calls.len()
                    && active.calls.iter().zip(&calls).all(|(a, b)| {
                        a.operation() == b.operation() && a.arguments() == b.arguments()
                    });
            let start = if prefix && active.manager.state(&key).await == ForkState::Ready {
                active.calls.len()
            } else {
                if !gate.preview_space(reservation(&active._base.db).await?) {
                    return Err(error(
                        "insufficient rebuild headroom; journal holds take priority",
                    ));
                }
                active
                    .manager
                    .rebuild(&key, &Calls(vec![]))
                    .await
                    .map_err(error)?;
                if let Err(failure) = active.manager.enable_rebase(&key).await {
                    if unsupported(&failure.to_string()) {
                        *self.unsupported.lock().await =
                            Some((key.clone(), schema_fingerprint(&active._base.db).await?));
                    }
                    return Err(error(failure));
                }
                active.calls.clear();
                0
            };
            #[cfg(test)]
            {
                let pause = self
                    .pause_replay
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                if let Some((entered, resume)) = pause {
                    entered.notify_one();
                    resume.notified().await;
                }
            }
            for call in calls.iter().skip(start) {
                let outcome =
                    tokio::time::timeout_at(deadline, active.manager.dispatch(&key, &caller, call))
                        .await
                        .map_err(|_| error("pending replay exceeded 120s"))?;
                match outcome {
                    Ok(outcome) => {
                        active
                            .manager
                            .confirm_journaled(&key, &outcome)
                            .await
                            .map_err(error)?;
                        active.calls.push(call.clone());
                    }
                    Err(error) if active.manager.state(&key).await == ForkState::Ready => {
                        tracing::warn!(%error, operation = call.operation(), "excluding refused pending preview entry");
                    }
                    Err(failure) => return Err(error(failure)),
                }
            }
            active.fingerprint = fingerprint;
            active.payloads = payloads
                .into_iter()
                .filter(|(_, operation, args)| {
                    active
                        .calls
                        .iter()
                        .any(|call| call.operation() == operation && call.arguments() == args)
                })
                .collect();
        }
        if active.snapshot != journal_snapshot {
            tokio::time::timeout_at(
                deadline,
                active.manager.finish_rebase(&key, act, &journal_snapshot),
            )
            .await
            .map_err(|_| error("pending replay publication exceeded 120s"))?
            .map_err(error)?;
            active.snapshot = journal_snapshot;
        }
        let now = dispatcher
            .serving_context()
            .ok_or_else(|| error("base retired"))?;
        let database_act: i64 =
            sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton=1")
                .fetch_one(active._base.db.pool())
                .await?;
        if now.serving_generation_id != active._base.context.serving_generation_id
            || now.serving_head_act != Some(act)
            || database_act != act
        {
            // The accepted source can advance during VACUUM/replay. Do not label
            // a copy with an act different from the captured source boundary.
            return Err(error("base advanced during preview preparation; retry"));
        }
        Ok(None)
    }

    /// Never wait for copy/replay. A ready fork must match both current base
    /// and journal before it can supply a response.
    async fn read_ready(
        &self,
        dispatcher: &crate::mcp::standby_stdio::StandbyDispatcher,
        gate: &WriteGate,
        (operation, arguments): (&str, Value),
    ) -> Result<Option<Value>> {
        if self.handoff.load(Ordering::Acquire) != 0 || self.gap.load(Ordering::Acquire) {
            return Ok(None);
        }
        let Ok(inner) = self.inner.try_lock() else {
            return Ok(None);
        };
        let Some(active) = inner.as_ref() else {
            return Ok(None);
        };
        let Some(now) = dispatcher.serving_context() else {
            return Ok(None);
        };
        let act = active._base.context.serving_head_act.unwrap();
        if now.serving_generation_id != active._base.context.serving_generation_id
            || now.serving_head_act != Some(act)
            || !gate.preview_space(0)
            || active.manager.state(&active.key).await != ForkState::Ready
            || serde_json::to_string(&gate.fork_entries(act)?)? != active.snapshot
        {
            return Ok(None);
        }
        let key = &active.key;
        let caller =
            Caller::for_node_pending_fork(active._base.account.clone(), key.workspace_id.clone());
        let payloads = &active.payloads;
        let (mut value, touched, _) = active
            .manager
            .preview_read(key, &caller, operation, arguments)
            .await
            .map_err(error)?;
        if operation == "get_record"
            && !value["records"].as_array().is_some_and(|items| {
                items.iter().any(|item| {
                    item["id"]
                        .as_str()
                        .is_some_and(|id| touched.iter().any(|t| t == id))
                })
            })
        {
            return Ok(None);
        }
        if serde_json::to_string(&gate.fork_entries(act)?)? != active.snapshot {
            return Err(error("journal changed during preview; retry"));
        }
        let database_act: i64 =
            sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton=1")
                .fetch_one(active._base.db.pool())
                .await?;
        if database_act != act
            || dispatcher.serving_context().is_none_or(|context| {
                context.serving_generation_id != now.serving_generation_id
                    || context.serving_head_act != Some(act)
            })
        {
            return Ok(None);
        }
        let flags: std::collections::HashMap<String, Vec<String>> = touched
            .iter()
            .map(|id| {
                let entry_ids = payloads
                    .iter()
                    .filter(|(_, _, args)| {
                        args.get("id")
                            .or_else(|| args.get("record_id"))
                            .and_then(Value::as_str)
                            == Some(id.as_str())
                    })
                    .map(|(entry, _, _)| entry.clone())
                    .collect();
                (id.clone(), entry_ids)
            })
            .collect();
        decorate(&mut value, operation, &flags, &key.window_id);
        value["standby_context"] = serde_json::to_value(now)?;
        #[cfg(test)]
        {
            let pause = self.pause_preview.lock().unwrap().take();
            if let Some((entered, resume)) = pause {
                entered.notify_one();
                resume.notified().await;
            }
        }
        // A typed save may be parked behind this create, in flight, or awaiting
        // result recovery. Do not present a partial same-record ordering as a
        // complete preview. Fall back for the whole response, including search.
        if gate.journal.fork_blocked_by_merge(&touched) {
            return Ok(None);
        }
        Ok(Some(value))
    }
}

fn decorate_item(
    item: &mut Value,
    flags: &std::collections::HashMap<String, Vec<String>>,
    window: &str,
) {
    if let Some(entries) = item["id"].as_str().and_then(|id| flags.get(id)) {
        if let Some(object) = item.as_object_mut() {
            for field in [
                "version",
                "body_digest",
                "updated_at",
                "created_at",
                "last_activity_at",
                "contribution",
                "history_summary",
                "provenance",
                "source_event_id",
                "action_attestation_ids",
            ] {
                object.remove(field);
            }
            object.insert(
                "node_pending_preview".into(),
                json!({"state":"pending","canonical":false,"window_id":window,"entry_ids":entries}),
            );
        }
    }
    for field in ["children", "ancestors", "mentions_in", "mentions_out"] {
        if let Some(items) = item[field].as_array_mut() {
            for item in items {
                decorate_item(item, flags, window);
            }
        }
    }
}
fn decorate(
    value: &mut Value,
    operation: &str,
    flags: &std::collections::HashMap<String, Vec<String>>,
    window: &str,
) {
    let paths: &[&str] = if operation == "search" {
        &[
            "/hits",
            "/near_misses/name_prefix",
            "/near_misses/name_infix",
            "/near_misses/tree_siblings",
        ]
    } else {
        &["/records"]
    };
    for path in paths {
        if let Some(items) = value.pointer_mut(path).and_then(Value::as_array_mut) {
            for item in items {
                decorate_item(item, flags, window);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn startup_cleans_stale_copies_without_creating_a_disabled_area() {
        let directory = tempfile::tempdir().unwrap();
        super::cleanup_stale_area(directory.path());
        let root = directory.path().join("hosted-outbox/forks");
        assert!(!root.exists());
        drop(ForkArea::new(directory.path(), &[]).unwrap());
        let stale = root.join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir(&stale).unwrap();
        std::fs::write(stale.join("fork.sqlite"), b"stale disposable copy").unwrap();
        std::fs::write(stale.join("rebase-in-progress"), b"interrupted rebase").unwrap();
        super::cleanup_stale_area(directory.path());
        assert!(std::fs::read_dir(root).unwrap().next().is_none());
    }

    #[test]
    fn failed_prepare_backoff_is_exponential_and_bounded() {
        let actual: Vec<_> = (1..10).map(|n| super::retry_delay(n).as_secs()).collect();
        assert_eq!(actual, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
    }

    use super::*;
    use crate::db::{open_current_database_wal_read_only_at, open_existing_database_at};
    use crate::mcp::{register_surface_tools, ToolRegistry};
    use std::time::Instant;

    /// Run explicitly with NATIVE_NODE_FORK_BENCH_DB pointing at an already
    /// copied generation. This test makes another private copy before opening
    /// SQLite, so no supplied source path is ever opened as a database.
    #[tokio::test]
    #[ignore = "explicit large-database fork cost measurement"]
    async fn pending_fork_generation_costs() {
        let source = PathBuf::from(
            std::env::var("NATIVE_NODE_FORK_BENCH_DB").expect("path to a copied v1 generation"),
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("base.sqlite");
        let started = Instant::now();
        std::fs::copy(&source, &path).unwrap();
        let file_copy = started.elapsed();
        let size = std::fs::metadata(&path).unwrap().len();
        let db = open_existing_database_at(&path).await.unwrap();
        let selected = std::env::var("NATIVE_NODE_FORK_BENCH_ACCOUNT").ok();
        let account =
            crate::mcp::standby_stdio::resolve_standby_account_identity(&db, selected.as_deref())
                .await
                .unwrap();
        let caller = Caller::for_node_pending_fork(account, "node-bench".into());
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).unwrap();
        registry.call(db.clone(), caller.clone(), "set_intent", json!({"run_key":"scout-chair-k748b2", "intent":"Measure disposable node fork cost on a private copy"})).await.unwrap();
        crate::db::checkpoint_and_close_hosted_adoption_database(db)
            .await
            .unwrap();
        // Match the hosted fork fixture: a closed WAL-mode file can have no
        // sidecars, which the WAL-aware read-only opener correctly refuses.
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
        let base = open_current_database_wal_read_only_at(&path).await.unwrap();
        let vacuum_path = dir.path().join("vacuum-only.sqlite");
        let started = Instant::now();
        sqlx::query("VACUUM INTO ?")
            .bind(vacuum_path.to_str().unwrap())
            .execute(base.pool())
            .await
            .unwrap();
        let vacuum = started.elapsed();
        std::fs::remove_file(vacuum_path).unwrap();
        let manager = ForkManager::new(
            ForkArea::new(dir.path(), std::slice::from_ref(&path)).unwrap(),
            ForkLimits {
                max_forks: 1,
                max_reserved_bytes: 16 * 1024 * 1024 * 1024,
                growth_bytes: 128 * 1024 * 1024,
                ..Default::default()
            },
        )
        .unwrap();
        let key = ForkKey {
            window_id: "node-bench".into(),
            workspace_id: "node-bench".into(),
        };
        let started = Instant::now();
        manager.prepare(key.clone(), base.clone()).await.unwrap();
        while manager.state(&key).await == ForkState::Preparing {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(manager.state(&key).await, ForkState::Ready);
        let prepare = started.elapsed();
        let mut calls = Vec::new();
        for n in 0..100 {
            calls.push(manager.prepare_call(&key, &caller, "create_record", json!({"id":uuid::Uuid::new_v4().to_string(),"type":"Document","kind":"note","name":format!("Fork timing {n}"),"body":"Disposable pending note timing","reason":"Measure fork replay","run_key":"scout-chair-k748b2","idempotency_key":format!("node-fork-bench-{n}")})).await.unwrap());
        }
        let started = Instant::now();
        let outcome = manager.dispatch(&key, &caller, &calls[0]).await.unwrap();
        let dispatch = started.elapsed();
        manager.confirm_journaled(&key, &outcome).await.unwrap();
        eprintln!("NODE_FORK_BENCH bytes={size} file_copy_ms={} vacuum_ms={} prepare_ms={} dispatch_ms={:.3}", file_copy.as_millis(), vacuum.as_millis(), prepare.as_millis(), dispatch.as_secs_f64()*1000.);
        for n in [1, 10, 100] {
            let started = Instant::now();
            manager
                .rebuild(&key, &Calls(calls[..n].to_vec()))
                .await
                .unwrap();
            eprintln!(
                "NODE_FORK_BENCH rebuild_n={n} elapsed_ms={}",
                started.elapsed().as_millis()
            );
            assert_eq!(manager.touched_record_ids(&key).await.unwrap().len(), n);
        }
        manager.discard(&key).await.unwrap();
        base.close().await;
    }
}
