//! Network-independent standby handoff. Capture one coherent Arc under a brief
//! lock, then retain its database, frozen status, caller and protected lease
//! through dispatch. No member revocation policy applies to owner standby reads.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use sqlx::Row;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use super::protocol;
use super::stdio::dispatch_engine_message;
use super::{
    Caller, EngineHandle, ExperimentalExecutors, ExposureProfile, McpSurfaceMode,
    StatusOnlyStdioServer, ToolRegistry,
};
use crate::error::{Error, Result};
use crate::export::{ExportCoordinator, LocalSnapshotSource};
use crate::standby::{
    ActivatedGeneration, GenerationStore, StandbyRuntimeConfig, StandbyStartupOutcome,
    StandbyStatusOnly, StandbyStatusProvider,
};
use crate::standby_snapshot::ObservedInstalledConsumerIdentity;

/// Database-less status while readiness is pending, or the recovery path's
/// actual refusal reason and candidate counts when no generation is usable.
pub fn standby_startup_status(startup: &StandbyStartupOutcome) -> StandbyStatusOnly {
    match startup {
        StandbyStartupOutcome::Serving(_) => StandbyStatusOnly {
            reason: "startup_readiness_pending".into(),
            candidate_count: 0,
            unusable_candidate_count: 0,
        },
        StandbyStartupOutcome::StatusOnly(status) => StandbyStatusOnly {
            reason: status.reason.into(),
            candidate_count: status.candidate_count,
            unusable_candidate_count: status.unusable_candidate_count,
        },
    }
}

/// Fixed composition configuration, shared by startup and every hot candidate.
pub struct StandbySessionConfig {
    pub runtime: StandbyRuntimeConfig,
    pub store: GenerationStore,
    pub observed: ObservedInstalledConsumerIdentity,
    pub surface: McpSurfaceMode,
    pub profile: ExposureProfile,
    pub experimental: ExperimentalExecutors,
    pub selected_account: Option<String>,
    pub refresh_configured: bool,
    pub refresh_available: bool,
}

#[derive(Default)]
struct Retirements {
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    pending: Mutex<Vec<(crate::Db, Arc<ActivatedGeneration>)>>,
    owner: Mutex<Option<tokio::runtime::Handle>>,
    live: std::sync::atomic::AtomicUsize,
    retired: tokio::sync::Notify,
}

impl Retirements {
    fn retire(self: &Arc<Self>, db: crate::Db, active: Arc<ActivatedGeneration>) {
        let owner = self.owner.lock().expect("standby retirement owner");
        if let Some(owner) = owner.as_ref() {
            self.spawn_retirement(owner, db, active);
        } else {
            // Startup preparation may fail before the worker exists. Preserve
            // the lease in a queue; never entrust cleanup to the transport's
            // runtime, which can disappear when its future is aborted.
            self.pending
                .lock()
                .expect("standby pending retirement")
                .push((db, active));
        }
    }

    fn spawn_retirement(
        self: &Arc<Self>,
        owner: &tokio::runtime::Handle,
        db: crate::Db,
        active: Arc<ActivatedGeneration>,
    ) {
        let mut tasks = self.tasks.lock().expect("standby retirement lock");
        tasks.retain(|task| !task.is_finished());
        let retirement = self.clone();
        tasks.push(owner.spawn(async move {
            // Only the final request/reference can retire this bundle. Keep the
            // pathname lease until all pool checkouts and background jobs drain.
            db.close().await;
            drop(active);
            retirement
                .live
                .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            retirement.retired.notify_one();
        }));
    }

    fn own_runtime(self: &Arc<Self>, runtime: tokio::runtime::Handle) {
        let mut owner = self.owner.lock().expect("standby retirement owner");
        *owner = Some(runtime.clone());
        for (db, active) in
            std::mem::take(&mut *self.pending.lock().expect("standby pending retirement"))
        {
            self.spawn_retirement(&runtime, db, active);
        }
    }

    async fn drain(self: &Arc<Self>) {
        // Explicit drain also supports database-less/manual library fixtures
        // that have no transport worker. Connected sessions use its runtime.
        {
            let owner = self.owner.lock().expect("standby retirement owner");
            let runtime = owner
                .clone()
                .unwrap_or_else(tokio::runtime::Handle::current);
            for (db, active) in
                std::mem::take(&mut *self.pending.lock().expect("standby pending retirement"))
            {
                self.spawn_retirement(&runtime, db, active);
            }
        }
        let tasks = std::mem::take(&mut *self.tasks.lock().expect("standby retirement lock"));
        for task in tasks {
            let _ = task.await;
        }
    }

    async fn drain_all(self: &Arc<Self>) {
        loop {
            let retired = self.retired.notified();
            if self.live.load(std::sync::atomic::Ordering::Acquire) == 0 {
                break;
            }
            retired.await;
        }
        self.drain().await;
    }
}

/// Cancellation cannot depend on reaching the async transport's tail. The
/// worker owns cleanup and its runtime until every captured resource retires.
struct WorkerShutdown {
    session: Arc<StandbyStdioSession>,
    cancellation: Arc<std::sync::atomic::AtomicBool>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl WorkerShutdown {
    fn cancel(&self) {
        // Serialize cancellation with publication, never with verification.
        let _state = self
            .session
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.cancellation
            .store(true, std::sync::atomic::Ordering::Release);
        let _ = self.shutdown.send(true);
    }
}

impl Drop for WorkerShutdown {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Owns verification, observation and retirement independently of connections.
/// Start one supervisor per session/workspace. Keep it for the owner's lifetime;
/// dropping it requests cancellation, while `shutdown` also waits for drain.
/// `start_with_startup` also runs cold recovery before watching hot candidates.
pub struct StandbySupervisor {
    stop: WorkerShutdown,
    stopped: tokio::sync::oneshot::Receiver<()>,
    worker: std::thread::JoinHandle<std::io::Result<()>>,
}

impl StandbySupervisor {
    pub fn start(session: Arc<StandbyStdioSession>) -> Result<Self> {
        Self::start_inner(session, false, None)
    }

    /// Return a dispatcher immediately; recover and activate on the worker's
    /// runtime, which owns opened pools and their retirement through shutdown.
    pub fn start_with_startup(session: Arc<StandbyStdioSession>) -> Result<Self> {
        Self::start_inner(session, true, None)
    }

    /// Internal node seam: notify refresh after cold recovery has completed,
    /// including status-only outcomes that need a first usable generation.
    pub(crate) fn start_with_startup_notifier(
        session: Arc<StandbyStdioSession>,
        startup_ready: tokio::sync::oneshot::Sender<()>,
    ) -> Result<Self> {
        Self::start_inner(session, true, Some(startup_ready))
    }

    fn start_inner(
        session: Arc<StandbyStdioSession>,
        recover_startup: bool,
        startup_ready: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Result<Self> {
        let (shutdown, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let cancellation = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_cancellation = cancellation.clone();
        let (stopped, stopped_rx) = tokio::sync::oneshot::channel();
        let stop = WorkerShutdown {
            session: session.clone(),
            cancellation,
            shutdown,
        };
        let worker_session = session.clone();
        // mcp-stdio uses a current-thread runtime. Full byte hashing and
        // rebuilding must never run on its dispatch thread, even via spawn.
        // This dedicated runtime also stays alive through pool retirement.
        let worker = std::thread::Builder::new()
            .name("standby-handoff".into())
            // Full debug verifier/catalogue futures exceed Rust's default
            // worker stack. Reserve the same bound used by repository tests.
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                crate::standby::generation_store::with_verification_cancellation(
                    worker_cancellation,
                    || {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;
                        worker_session
                            .retirements
                            .own_runtime(runtime.handle().clone());
                        runtime.block_on(async {
                            if recover_startup && worker_session.recover_startup().await.is_err() {
                                tracing::warn!(target: "native_ce::standby::verification",
                                    "standby startup recovery failed; retaining status-only");
                            }
                            if let Some(startup_ready) = startup_ready {
                                let _ = startup_ready.send(());
                            }
                            // Never drop a pinned full-verification future at
                            // an arbitrary SQL await: finish its current phase
                            // and cleanup before releasing its pathname lease.
                            let vault_shutdown = shutdown_rx.clone();
                            tokio::join!(
                                worker_session.watch_accepted(&mut shutdown_rx),
                                worker_session.project_vault(vault_shutdown)
                            );
                            worker_session.retire_serving();
                            // This supervisor survives a dropped serve future.
                            // Keep driving cleanup until the final request Arc
                            // and candidate pool have actually retired.
                            worker_session.retirements.drain_all().await;
                        });
                        *worker_session
                            .retirements
                            .owner
                            .lock()
                            .expect("standby retirement owner") = None;
                        runtime.shutdown_timeout(Duration::from_secs(5));
                        let _ = stopped.send(());
                        Ok::<_, std::io::Error>(())
                    },
                )
            })?;
        Ok(Self {
            stop,
            stopped: stopped_rx,
            worker,
        })
    }

    /// Clones share request state, but never own cancellation or retirement.
    pub fn dispatcher(&self) -> StandbyDispatcher {
        StandbyDispatcher {
            session: self.stop.session.clone(),
        }
    }

    /// Stop observation and drain all captured requests and candidate pools.
    /// Dropping this future still signals cancellation; the worker owns cleanup.
    pub async fn shutdown(self) -> Result<()> {
        self.stop.cancel();
        let _ = self.stopped.await;
        tokio::task::spawn_blocking(move || self.worker.join())
            .await
            .map_err(|_| Error::engine("standby handoff worker join failed"))?
            .map_err(|_| Error::engine("standby handoff worker panicked"))??;
        Ok(())
    }
}

/// A connection-independent request handle. Dropping a clone or finishing a
/// connection does not stop the supervisor or retire its serving generation.
#[derive(Clone)]
pub struct StandbyDispatcher {
    session: Arc<StandbyStdioSession>,
}

impl StandbyDispatcher {
    pub(crate) fn serving_kernel_v2(&self) -> bool {
        match self.session.capture() {
            SessionSnapshot::Serving(served) => served
                .resources
                .active
                .generation
                .manifest
                .kernel_v2
                .is_some(),
            SessionSnapshot::StatusOnly(_) => false,
        }
    }
    pub async fn handle_message(&self, message: Value) -> Option<Value> {
        self.session.handle_message(message).await
    }

    /// Internal node-only outage composition. The override is scoped to one
    /// bootstrap and never changes the caller of the shared serving generation.
    pub(crate) async fn handle_outage_bootstrap(&self, message: Value) -> Option<Value> {
        self.session.handle_message_with_outage(message, true).await
    }

    /// Serve one newline-framed connection without owning supervisor shutdown.
    pub async fn serve_connection<R, W>(&self, reader: R, writer: W) -> Result<()>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        self.session.transport(reader, writer).await
    }
}

/// Also guards preparation failures/cancellation after a pool has opened.
struct GenerationResources {
    db: crate::Db,
    active: Arc<ActivatedGeneration>,
    retirements: Arc<Retirements>,
}

impl GenerationResources {
    fn engine(&self) -> EngineHandle {
        #[cfg(feature = "v2-kernel-probe")]
        if self.active.generation.manifest.kernel_v2.is_some() {
            return EngineHandle::KernelV2(self.db.clone());
        }
        EngineHandle::Sqlite(self.db.clone())
    }
}

impl Drop for GenerationResources {
    fn drop(&mut self) {
        self.retirements
            .retire(self.db.clone(), self.active.clone());
    }
}

enum ServedDispatcher {
    Legacy {
        registry: Arc<ToolRegistry>,
        caller: Caller,
    },
    #[cfg(feature = "mcp-executor-prototype")]
    Executor {
        server: Box<super::ExecutorPrototypeStdioServer>,
        diagnostic_registry: Arc<ToolRegistry>,
        caller: Caller,
    },
}

struct ServedGeneration {
    resources: GenerationResources,
    account: String,
    dispatcher: ServedDispatcher,
    status: StandbyStatusProvider,
    /// Shared `.reader.lock`, held while this generation is served so that
    /// deltas can tell the build marker belongs to a live reader.
    reader_lock: Option<std::fs::File>,
    #[cfg(test)]
    dispatch_pause: Option<DispatchPause>,
}

impl ServedGeneration {
    async fn dispatch(&self, message: Value, outage_bootstrap: bool) -> Option<Value> {
        #[cfg(test)]
        if let Some((id, entered, resume)) = &self.dispatch_pause {
            if message["id"].as_i64() == Some(*id) {
                entered.notify_one();
                resume.notified().await;
            }
        }
        let outage_bootstrap = outage_bootstrap
            && protocol::method_and_name(&message) == (Some("tools/call"), Some("bootstrap"));
        match &self.dispatcher {
            ServedDispatcher::Legacy { registry, caller } => {
                dispatch_engine_message(
                    registry.clone(),
                    self.resources.engine(),
                    if outage_bootstrap {
                        caller.clone().with_outage_bootstrap()
                    } else {
                        caller.clone()
                    },
                    message,
                )
                .await
            }
            #[cfg(feature = "mcp-executor-prototype")]
            ServedDispatcher::Executor {
                server,
                diagnostic_registry,
                caller,
            } => {
                if protocol::method_and_name(&message)
                    == (Some("tools/call"), Some("standby_status"))
                {
                    dispatch_engine_message(
                        diagnostic_registry.clone(),
                        self.resources.engine(),
                        caller.clone(),
                        message,
                    )
                    .await
                } else if outage_bootstrap {
                    server
                        .handle_bootstrap_with_caller(
                            message,
                            caller.clone().with_outage_bootstrap(),
                        )
                        .await
                } else {
                    server.handle_message(message).await
                }
            }
        }
    }
}

#[derive(Clone)]
enum SessionSnapshot {
    StatusOnly(Arc<StatusOnlyStdioServer>),
    Serving(Arc<ServedGeneration>),
}

#[cfg(test)]
type WarmupHook = Arc<dyn Fn() -> Result<Option<Arc<tokio::sync::Notify>>> + Send + Sync>;

#[cfg(test)]
type DispatchPause = (i64, Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>);

/// A single-writer session. Its watcher prepares one pinned candidate at a time;
/// newer hints are coalesced by rereading the accepted descriptor afterwards.
pub struct StandbyStdioSession {
    config: StandbySessionConfig,
    #[cfg(unix)]
    markdown_folder: Option<std::path::PathBuf>,
    #[cfg(all(test, unix))]
    vault_tick_interval: Duration,
    state: Mutex<SessionSnapshot>,
    retirements: Arc<Retirements>,
    catalogue: Vec<Value>,
    #[cfg(feature = "mcp-executor-prototype")]
    catalogue_meta: Option<Value>,
    #[cfg(test)]
    warmup_hook: Mutex<Option<WarmupHook>>,
    #[cfg(test)]
    dispatch_pause: Mutex<Option<DispatchPause>>,
}

impl StandbyStdioSession {
    #[cfg(not(unix))]
    async fn project_vault(&self, _shutdown: tokio::sync::watch::Receiver<bool>) {}
    #[cfg(unix)]
    pub(crate) fn with_markdown_folder(mut self, path: Option<std::path::PathBuf>) -> Self {
        self.markdown_folder = path;
        self
    }

    #[cfg(unix)]
    async fn project_vault(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let Some(path) = &self.markdown_folder else {
            return;
        };
        let vault_path = path.clone();
        // First-write notice: a fresh vault has no ownership state yet, so a
        // successful open below creates the directory. Say so once, with the
        // off switch, before the publisher takes the writer lock.
        let fresh = !vault_path.join(".native").join("state.json").exists();
        let publisher = match tokio::task::spawn_blocking(move || {
            crate::markdown_vault::Publisher::open(&vault_path)
        })
        .await
        .expect("vault initialization worker")
        {
            Ok(p) => p,
            Err(error) => {
                tracing::error!(target: "native_ce::standby::vault", error = %crate::markdown_vault::diag_field(&error, crate::markdown_vault::DIAG_ERROR_MAX),"vault initialization failed");
                return;
            }
        };
        if fresh {
            tracing::info!(
                target: "native_ce::standby::vault",
                path = %crate::markdown_vault::diag_field(&path.display(), crate::markdown_vault::DIAG_PATH_MAX),
                "created read-only markdown vault; to turn it off set \"markdown_folder\": false in node.json",
            );
        }
        let mut publisher = Some(publisher);
        let mut last: Option<crate::markdown_vault::SourceSnapshot> = None;
        let mut conflicts = Vec::new();
        let mut last_check = std::time::Instant::now();
        #[cfg(test)]
        let tick_interval = self.vault_tick_interval;
        #[cfg(not(test))]
        let tick_interval = Duration::from_secs(5);
        let mut interval = tokio::time::interval(tick_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {_=shutdown.changed()=>break,_=interval.tick()=>{}}
            let snapshot = self.state.lock().expect("standby state").clone();
            let SessionSnapshot::Serving(served) = snapshot else {
                let mut writer = publisher.take().unwrap();
                let (writer, result) = tokio::task::spawn_blocking(move || {
                    let result = writer.unavailable("no authorized serving generation");
                    (writer, result)
                })
                .await
                .expect("vault status worker");
                publisher = Some(writer);
                if let Err(error) = result {
                    tracing::warn!(target: "native_ce::standby::vault", error = %crate::markdown_vault::diag_field(&error, crate::markdown_vault::DIAG_ERROR_MAX),"vault update failed");
                }
                continue;
            };
            let result: Result<()> = async {
                let db = &served.resources.db;
                let mut connection = db.pool().acquire().await?;
                let head = crate::act::current_act(&mut connection).await?;
                drop(connection);
                if !crate::markdown_vault::needs_projection(
                    last.as_ref(),
                    head,
                    &served.resources.active.generation.id,
                    last_check.elapsed(),
                ) {
                    let source = last.as_mut().unwrap();
                    source.freshness = serde_json::to_value(served.status.status().await)?;
                    let mut writer = publisher.take().unwrap();
                    let source_copy = source.status_only();
                    let issues = conflicts.clone();
                    let (writer, result) = tokio::task::spawn_blocking(move || {
                        let result = writer.status(&source_copy, &issues);
                        (writer, result)
                    })
                    .await
                    .map_err(|_| Error::engine("vault publisher worker failed"))?;
                    publisher = Some(writer);
                    result?;
                } else {
                    let caller = match &served.dispatcher {
                        ServedDispatcher::Legacy { caller, .. } => caller,
                        #[cfg(feature = "mcp-executor-prototype")]
                        ServedDispatcher::Executor { caller, .. } => caller,
                    };
                    let started = std::time::Instant::now();
                    let mut source =
                        crate::query::sql::projection_snapshot(db, caller.into()).await?;
                    tracing::debug!(
                        snapshot_millis = started.elapsed().as_millis(),
                        "vault source transaction released"
                    );
                    source.origin = served
                        .resources
                        .active
                        .generation
                        .manifest
                        .origin_database_id
                        .clone();
                    source.generation = served.resources.active.generation.id.clone();
                    let mut writer = publisher.take().unwrap();
                    let runtime = tokio::runtime::Handle::current();
                    let status_provider = served.status.clone();
                    let (writer, source, result) = tokio::task::spawn_blocking(move || {
                        let result = writer.cycle_with_freshness(&source, || {
                            Ok(serde_json::to_value(
                                runtime.block_on(status_provider.status()),
                            )?)
                        });
                        (writer, source.status_only(), result)
                    })
                    .await
                    .map_err(|_| Error::engine("vault publisher worker failed"))?;
                    publisher = Some(writer);
                    conflicts = result?;
                    last = Some(source);
                    last_check = std::time::Instant::now();
                }
                Ok(())
            }
            .await;
            if publisher.is_none() {
                tracing::warn!(target: "native_ce::standby::vault", error = %"vault publisher worker terminated","vault update failed");
                return;
            }
            if let Err(error) = result {
                tracing::warn!(target: "native_ce::standby::vault", error = %crate::markdown_vault::diag_field(&error, crate::markdown_vault::DIAG_ERROR_MAX),"vault update failed");
                let mut writer = publisher.take().unwrap();
                let (writer, result) = tokio::task::spawn_blocking(move || {
                    let result = writer.unavailable("cycle failed; inspect node diagnostics");
                    (writer, result)
                })
                .await
                .expect("vault failure status worker");
                publisher = Some(writer);
                if let Err(error) = result {
                    tracing::warn!(target: "native_ce::standby::vault", error = %crate::markdown_vault::diag_field(&error, crate::markdown_vault::DIAG_ERROR_MAX),"vault update failed");
                }
            }
        }
    }

    /// Shared cold-start path for stdio and the node. Recovery repairs an
    /// interrupted promotion and selects an accepted generation before open
    /// and authorised-read readiness. No request can see an unchecked reader.
    pub async fn recover_startup(&self) -> Result<()> {
        match self
            .config
            .store
            .activate_for_startup(&self.config.observed)
            .await
        {
            Ok(startup) => {
                self.install_startup_outcome(startup).await;
                Ok(())
            }
            Err(error) => {
                self.publish_startup_status(StandbyStatusOnly {
                    reason: "startup_recovery_failed".into(),
                    candidate_count: 0,
                    unusable_candidate_count: 0,
                });
                Err(error)
            }
        }
    }

    /// Apply the cold recovery result using the same publication and refusal
    /// semantics on both stdio and the node's dedicated supervisor runtime.
    pub async fn install_startup_outcome(&self, startup: StandbyStartupOutcome) {
        match startup {
            StandbyStartupOutcome::Serving(active) => {
                if active.startup_reason.is_some() {
                    tracing::info!(target: "native_ce::standby::verification",
                        "standby startup recovered with a fallback");
                }
                if !active.retention_warnings.is_empty() {
                    tracing::warn!(target: "native_ce::standby::verification",
                        "standby retention warnings present");
                }
                if self.install_startup(*active).await.is_err() {
                    self.publish_startup_status(StandbyStatusOnly {
                        reason: "startup_readiness_unavailable".into(),
                        candidate_count: 0,
                        unusable_candidate_count: 0,
                    });
                    tracing::warn!(target: "native_ce::standby::verification",
                        "standby startup readiness unavailable; retaining status-only");
                }
            }
            StandbyStartupOutcome::StatusOnly(status) => {
                self.publish_startup_status(standby_startup_status(
                    &StandbyStartupOutcome::StatusOnly(status),
                ));
            }
        }
    }

    fn publish_startup_status(&self, status: StandbyStatusOnly) {
        let provider = StandbyStatusProvider::for_status_only_reason(
            self.config.runtime.clone(),
            self.config.store.clone(),
            Some(self.config.observed.clone()),
            status,
            self.config.refresh_configured,
            self.config.refresh_available,
        )
        .with_connected_handoff();
        *self.state.lock().expect("standby state lock") =
            SessionSnapshot::StatusOnly(Arc::new(StatusOnlyStdioServer::with_provider(provider)));
    }

    #[cfg(feature = "mcp-executor-prototype")]
    pub(crate) fn operation_rows(&self, provider: StandbyStatusProvider) -> Result<Value> {
        let registry = Self::registry(&self.config, provider)?;
        super::executor_prototype::standby_operation_rows(&registry)
    }
    pub fn new(mut config: StandbySessionConfig, provider: StandbyStatusProvider) -> Result<Self> {
        // The standby read-only projection is unchanged by the lean surface:
        // lean narrows the writable ordinary catalogue only, so a standby
        // configured `lean` serves exactly the executor standby projection.
        if config.surface == McpSurfaceMode::Lean {
            config.surface = McpSurfaceMode::Executor;
        }
        let registry = Self::registry(&config, provider.clone().with_connected_handoff())?;
        let mut catalogue: Vec<Value> = match config.surface {
            McpSurfaceMode::Legacy => registry
                .descriptor_projection(config.profile)
                .into_iter()
                .map(|tool| tool.descriptor)
                .collect(),
            McpSurfaceMode::Executor | McpSurfaceMode::Lean => {
                #[cfg(feature = "mcp-executor-prototype")]
                {
                    super::executor_prototype::standby_read_only_descriptors(&registry)?
                }
                #[cfg(not(feature = "mcp-executor-prototype"))]
                {
                    return Err(Error::engine("executor surface is unavailable"));
                }
            }
        };
        // Preserve the database-less diagnostic entry point on both surfaces.
        if !catalogue
            .iter()
            .any(|tool| tool["name"] == "standby_status")
        {
            catalogue.push(
                registry
                    .descriptor_projection(config.profile)
                    .into_iter()
                    .find(|tool| tool.name == "standby_status")
                    .ok_or_else(|| Error::engine("standby diagnostic descriptor unavailable"))?
                    .descriptor,
            );
        }
        for descriptor in &mut catalogue {
            let description = descriptor["description"].as_str().unwrap_or("");
            descriptor["description"] = Value::String(format!("{description} Local standby calls return STANDBY_STATUS_ONLY while no fully verified authorised reader is ready; discovery alone does not imply workspace data is available."));
        }
        if serde_json::to_vec(&catalogue)?.len() > config.profile.max_descriptor_bytes() {
            return Err(Error::engine(
                "standby catalogue exceeds configured discovery budget",
            ));
        }
        #[cfg(feature = "mcp-executor-prototype")]
        let catalogue_meta = if config.surface == McpSurfaceMode::Executor {
            Some(super::executor_prototype::standby_discovery_meta(
                &catalogue,
            )?)
        } else {
            None
        };
        Ok(Self {
            config,
            #[cfg(unix)]
            markdown_folder: None,
            #[cfg(all(test, unix))]
            vault_tick_interval: Duration::from_secs(5),
            state: Mutex::new(SessionSnapshot::StatusOnly(Arc::new(
                StatusOnlyStdioServer::with_provider(provider.with_connected_handoff()),
            ))),
            retirements: Arc::new(Retirements::default()),
            catalogue,
            #[cfg(feature = "mcp-executor-prototype")]
            catalogue_meta,
            #[cfg(test)]
            warmup_hook: Mutex::new(None),
            #[cfg(test)]
            dispatch_pause: Mutex::new(None),
        })
    }

    fn registry(
        config: &StandbySessionConfig,
        provider: StandbyStatusProvider,
    ) -> Result<Arc<ToolRegistry>> {
        let exports = ExportCoordinator::new();
        let mut registry = ToolRegistry::new();
        registry.set_standby_status_provider(provider.clone());
        registry.set_exposure_profile(config.profile);
        super::register_builtin_tools(&mut registry)?;
        super::register_surface_tools(&mut registry)?;
        #[cfg(feature = "v2-kernel-probe")]
        super::kernel_v2::register_hosted_kernel_v2_tools(&mut registry)?;
        super::register_build_enabled_experimental_tools(&mut registry)?;
        super::register_allowlisted_experimental_tools(&mut registry, &config.experimental)?;
        super::register_snapshot_tool(
            &mut registry,
            Arc::new(LocalSnapshotSource::with_coordinator(exports)),
        )?;
        super::register_standby_status_tool(&mut registry, provider)?;
        registry.validate_profile_budgets()?;
        Ok(Arc::new(registry))
    }

    fn capture(&self) -> SessionSnapshot {
        self.state.lock().expect("standby state lock").clone()
    }

    fn prepare<'a>(
        &'a self,
        active: ActivatedGeneration,
        account: Option<&'a str>,
    ) -> impl std::future::Future<Output = Result<ServedGeneration>> + 'a {
        // Readiness constructs an executor and dispatches authorised reads.
        // Keep that state off startup, refresh and publication callers' stacks.
        Box::pin(self.prepare_inner(active, account))
    }

    async fn prepare_inner(
        &self,
        active: ActivatedGeneration,
        account: Option<&str>,
    ) -> Result<ServedGeneration> {
        crate::standby::generation_store::check_verification_cancellation()?;
        let active = Arc::new(active);
        let path = active
            .generation
            .snapshot_path
            .to_str()
            .ok_or_else(|| Error::engine("invalid standby snapshot path"))?;
        let kernel_v2 = active.generation.manifest.kernel_v2.is_some();
        let db = if kernel_v2 {
            #[cfg(feature = "v2-kernel-probe")]
            {
                crate::db::open_kernel_v2_standby_read_only(path).await?
            }
            #[cfg(not(feature = "v2-kernel-probe"))]
            return Err(Error::engine("kernel-v2 standby requires v2-kernel-probe"));
        } else {
            crate::db::open_existing_database_standby_read_only(path).await?
        };
        self.retirements
            .live
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let resources = GenerationResources {
            db,
            active,
            retirements: self.retirements.clone(),
        };
        let account = if kernel_v2 {
            #[cfg(feature = "v2-kernel-probe")]
            {
                resolve_kernel_account(&resources.db, account).await?
            }
            #[cfg(not(feature = "v2-kernel-probe"))]
            return Err(Error::engine("kernel-v2 standby requires v2-kernel-probe"));
        } else {
            resolve_standby_account_identity(&resources.db, account).await?
        };
        #[cfg(feature = "v2-kernel-probe")]
        if kernel_v2 {
            let principal =
                crate::kernel::resolve_caller_principal_by_binding(&resources.db, &account)
                    .await?
                    .ok_or_else(|| Error::engine("standby kernel principal unavailable"))?
                    .0;
            let mut snapshot = resources.db.pool().begin().await?;
            crate::kernel::kernel_require(
                &mut snapshot,
                &principal,
                crate::events::KERNEL_ROOT_ID,
                crate::authorization::Capability::View,
            )
            .await?;
            snapshot.rollback().await?;
        }
        #[cfg(test)]
        {
            let hook = self.warmup_hook.lock().unwrap().clone();
            if let Some(hook) = hook {
                if let Some(resume) = hook()? {
                    // A fixture may hold readiness without freezing this
                    // runtime's real pool retirement or cancellation work.
                    let resumed = resume.notified();
                    tokio::pin!(resumed);
                    loop {
                        crate::standby::generation_store::check_verification_cancellation()?;
                        tokio::select! {
                            _ = &mut resumed => break,
                            _ = tokio::time::sleep(Duration::from_millis(20)) => {},
                        }
                    }
                }
            }
        }
        let provider = StandbyStatusProvider::for_serving(
            self.config.runtime.clone(),
            self.config.store.clone(),
            self.config.observed.clone(),
            &resources.active,
            self.config.refresh_configured,
            self.config.refresh_available,
        )
        .with_connected_handoff();
        let registry = Self::registry(&self.config, provider.clone())?;
        let caller = standby_owner_caller(account.clone());
        let dispatcher = match self.config.surface {
            McpSurfaceMode::Legacy => ServedDispatcher::Legacy { registry, caller },
            // `new` normalised Lean to Executor; both serve the standby projection.
            McpSurfaceMode::Executor | McpSurfaceMode::Lean => {
                #[cfg(feature = "mcp-executor-prototype")]
                {
                    ServedDispatcher::Executor {
                        server: Box::new(
                            super::ExecutorPrototypeStdioServer::new_standby_read_only(
                                registry.clone(),
                                resources.engine(),
                                caller.clone(),
                            )
                            .await?
                            .with_connected_standby_discovery(&self.catalogue)?,
                        ),
                        diagnostic_registry: registry,
                        caller,
                    }
                }
                #[cfg(not(feature = "mcp-executor-prototype"))]
                {
                    return Err(Error::engine("executor surface is unavailable"));
                }
            }
        };
        let prepared = ServedGeneration {
            resources,
            account,
            dispatcher,
            status: provider,
            reader_lock: None,
            #[cfg(test)]
            dispatch_pause: self.dispatch_pause.lock().unwrap().clone(),
        };
        // Readiness uses the actual authenticated production dispatch path.
        // A readable SQLite file or built catalogue alone proves no authorised
        // kernel root can be served by this exact candidate/caller.
        let (name, arguments) = if kernel_v2 {
            ("bootstrap", serde_json::json!({"format":"json"}))
        } else {
            match &prepared.dispatcher {
                ServedDispatcher::Legacy { .. } => (
                    "get_record",
                    serde_json::json!({"ids":["native:root"],"format":"json"}),
                ),
                #[cfg(feature = "mcp-executor-prototype")]
                ServedDispatcher::Executor { .. } => (
                    "records_read",
                    serde_json::json!({"operation":"get_record","arguments":{"ids":["native:root"]},"format":"json"}),
                ),
            }
        };
        let response = prepared.dispatch(serde_json::json!({"jsonrpc":"2.0","id":0,"method":"tools/call","params":{"name":name,"arguments":arguments}}), false).await
            .ok_or_else(|| Error::engine("standby authorised readiness unavailable"))?;
        let value = &response["result"]["structuredContent"];
        let context = &value["standby_context"];
        let ready_root = if kernel_v2 {
            value["workspace"]["primary_workspace"]["id"] == "kernel:root"
                && value["run"]["read_only"] == true
        } else {
            value["records"].as_array().is_some_and(|records| {
                records
                    .iter()
                    .any(|record| record["id"] == "native:root" && record["status"] == "found")
            })
        };
        if response["result"]["isError"] != false
            || !ready_root
            || context["mode"] != "standby"
            || context["serving_generation_id"] != prepared.resources.active.generation.id
            || context["status_scope"] != "serving_generation_freshness_only"
            || context["canonical_authority"] != "hosted"
            || context["read_only"] != true
            || context["writes_supported"] != false
        {
            return Err(Error::engine("standby authorised readiness refused"));
        }
        Ok(prepared)
    }

    /// Startup has already run the complete existing recovery/acceptance path.
    /// A failed open/catalogue leaves the database-less status surface usable.
    pub async fn install_startup(&self, active: ActivatedGeneration) -> Result<()> {
        let prepared = self
            .prepare(active, self.config.selected_account.as_deref())
            .await?;
        self.publish(prepared)
    }

    fn publish(&self, mut prepared: ServedGeneration) -> Result<()> {
        // Deltas are refused until this build is serving the generation: an
        // older build would read the file as immutable while deltas rewrite
        // it. The lock is taken before the swap and the marker written after
        // it, so a cancelled or crashed publish leaves no marker for a reader
        // that is not serving. A missing lock or marker only defers deltas, so
        // it never blocks serving.
        let generation_id = prepared.resources.active.generation.id.clone();
        prepared.reader_lock = self.config.store.hold_serving_reader(&generation_id).ok();
        let old = {
            let mut state = self.state.lock().expect("standby state lock");
            crate::standby::generation_store::check_verification_cancellation()?;
            std::mem::replace(&mut *state, SessionSnapshot::Serving(Arc::new(prepared)))
        };
        if self
            .config
            .store
            .record_serving_reader(&generation_id, &self.config.observed)
            .is_err()
        {
            tracing::warn!(target: "native_ce::standby::verification",
                "standby serving build marker unavailable; deltas stay deferred");
        }
        // Dropping outside the request lock may enqueue pool retirement, but
        // never closes the shared pool of an in-flight captured generation.
        drop(old);
        self.config
            .store
            .schedule_maintenance(&self.config.observed);
        Ok(())
    }

    pub async fn handle_message(&self, message: Value) -> Option<Value> {
        self.handle_message_with_outage(message, false).await
    }

    async fn handle_message_with_outage(
        &self,
        message: Value,
        outage_bootstrap: bool,
    ) -> Option<Value> {
        let snapshot = self.capture();
        let listing = message["method"] == "tools/list";
        let orientation = matches!(
            message["method"].as_str(),
            Some("server/discover" | "initialize")
        );
        let mut response = match &snapshot {
            SessionSnapshot::StatusOnly(server) => server.handle_message(message).await,
            SessionSnapshot::Serving(served) => served.dispatch(message, outage_bootstrap).await,
        };
        // Executor mutations can refuse before delegating to the registry.
        // Bind those refusals to the captured bundle too, without an audit.
        if let SessionSnapshot::Serving(served) = &snapshot {
            if let Some(body) = response
                .as_mut()
                .filter(|body| body["result"]["isError"] == true)
            {
                if let Some(content) = body["result"]["structuredContent"].as_object_mut() {
                    content.insert(
                        "standby_context".into(),
                        serde_json::to_value(served.status.response_context())
                            .expect("standby context is serializable"),
                    );
                }
            }
        }
        if listing {
            if let Some(body) = response
                .as_mut()
                .filter(|body| body.get("result").is_some())
            {
                // The same callable schemas survive status-only -> serving;
                // cached discovery never needs a notification or a manual list.
                body["result"]["tools"] = Value::Array(self.catalogue.clone());
            }
        }
        if orientation {
            if let Some(body) = response
                .as_mut()
                .filter(|body| body.get("result").is_some())
            {
                body["result"]["instructions"] = Value::String("This read-only standby has a stable callable catalogue. Workspace calls return STANDBY_STATUS_ONLY until a fully verified authorised reader is ready; inspect each call's actual serving context and availability.".into());
            }
        }
        #[cfg(feature = "mcp-executor-prototype")]
        if let Some(meta) = &self.catalogue_meta {
            if let Some(body) = response
                .as_mut()
                .filter(|body| body.get("result").is_some())
            {
                body["result"]["_meta"]["nativeExecutor"] = meta.clone();
            }
        }
        response
    }

    async fn watch_accepted(&self, shutdown: &mut tokio::sync::watch::Receiver<bool>) {
        let mut retries = std::collections::HashMap::<
            String,
            (
                crate::standby::AcceptedGenerationHint,
                u32,
                tokio::time::Instant,
            ),
        >::new();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {},
                _ = shutdown.changed() => return,
            }
            if crate::standby::generation_store::check_verification_cancellation().is_err() {
                return;
            }
            let snapshot = self.capture();
            let serving = match &snapshot {
                SessionSnapshot::Serving(served) => Some(served),
                SessionSnapshot::StatusOnly(_) => None,
            };
            let hints = match self.config.store.handoff_candidates_hint() {
                Ok(hints) => hints,
                Err(_) => continue,
            };
            retries.retain(|_, (hint, _, _)| hints.contains(hint));
            let now = tokio::time::Instant::now();
            let hint = match hints.into_iter().find(|hint| {
                serving.is_none_or(|served| {
                    served.resources.active.generation.id != hint.generation_id()
                }) && retries
                    .get(hint.generation_id())
                    .is_none_or(|(_, attempts, retry_at)| *attempts < 3 && now >= *retry_at)
            }) {
                Some(hint) => hint,
                None => continue,
            };
            // Three attempts per unchanged hint, coalesced independently. A bad
            // orphan must not hide another full-verifiable durable successor.
            let retry =
                retries
                    .entry(hint.generation_id().to_owned())
                    .or_insert((hint.clone(), 0, now));
            retry.1 += 1;
            let attempt = retry.1;
            let predecessor = serving.map(|served| served.resources.active.as_ref());
            let account = serving
                .map(|served| served.account.as_str())
                .or(self.config.selected_account.as_deref());
            let result = async {
                let active = self
                    .config
                    .store
                    .activate_accepted(&hint, &self.config.observed, predecessor)
                    .await?;
                let prepared = self.prepare(active, account).await?;
                crate::standby::generation_store::check_verification_cancellation()?;
                self.config
                    .store
                    .confirm_handoff(&prepared.resources.active)?;
                self.publish(prepared)
            }
            .await;
            let ready = result.is_ok();
            tracing::info!(target: "native_ce::standby::verification", ready, attempt,
                "standby connected handoff finished");
            if let Some(retry) = retries.get_mut(hint.generation_id()) {
                retry.2 = tokio::time::Instant::now() + Duration::from_secs(1 << attempt);
            }
        }
    }

    pub async fn serve_stdio(self: &Arc<Self>) -> Result<()> {
        self.serve(BufReader::new(tokio::io::stdin()), tokio::io::stdout())
            .await
    }

    /// EOF cancels unpublished verification/warmup, stops observation, and
    /// drains pool retirement before the final protected lease is released.
    pub async fn serve<R, W>(self: &Arc<Self>, reader: R, writer: W) -> Result<()>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let supervisor = StandbySupervisor::start(self.clone())?;
        let outcome = supervisor
            .dispatcher()
            .serve_connection(reader, writer)
            .await;
        supervisor.shutdown().await?;
        outcome
    }

    fn retire_serving(&self) {
        // Called by the worker even if the transport future was dropped.
        let fallback = StandbyStatusProvider::for_status_only_reason(
            self.config.runtime.clone(),
            self.config.store.clone(),
            Some(self.config.observed.clone()),
            crate::standby::StandbyStatusOnly {
                reason: "connection_closed".into(),
                candidate_count: 0,
                unusable_candidate_count: 0,
            },
            self.config.refresh_configured,
            self.config.refresh_available,
        )
        .with_connected_handoff();
        let old = std::mem::replace(
            &mut *self.state.lock().expect("standby state lock"),
            SessionSnapshot::StatusOnly(Arc::new(StatusOnlyStdioServer::with_provider(fallback))),
        );
        drop(old);
    }

    async fn transport<R, W>(&self, mut reader: R, mut writer: W) -> Result<()>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                return Ok(());
            }
            if line.trim().is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<Value>(&line) {
                Ok(message) => self.handle_message(message).await,
                Err(error) => Some(protocol::error_response(
                    Value::Null,
                    protocol::PARSE_ERROR,
                    &format!("parse error: {error}"),
                )),
            };
            if let Some(response) = response {
                let mut bytes = serde_json::to_vec(&response)?;
                bytes.push(b'\n');
                writer.write_all(&bytes).await?;
                writer.flush().await?;
            }
        }
    }
}
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn resolve_kernel_account(
    db: &crate::Db,
    selected: Option<&str>,
) -> Result<String> {
    let mut conn = db.pool().acquire().await?;
    Ok(
        crate::standby::kernel_v2::resolve_account_on(&mut conn, selected)
            .await?
            .0,
    )
}

pub async fn resolve_standby_account_identity(
    db: &crate::Db,
    selected_account: Option<&str>,
) -> crate::Result<String> {
    let rows = sqlx::query(
        "SELECT bindings.record_id, bindings.identifier,
                records.type, records.kind, records.deleted_at
         FROM bindings
         LEFT JOIN records ON records.id = bindings.record_id
         WHERE bindings.system = 'account' AND bindings.is_canonical = 1
         ORDER BY bindings.identifier",
    )
    .fetch_all(db.pool())
    .await?;

    let mut accounts = Vec::with_capacity(rows.len());
    let mut record_ids = std::collections::HashSet::with_capacity(rows.len());
    for row in rows {
        let record_id = row.try_get::<String, _>("record_id")?;
        let account = row.try_get::<String, _>("identifier")?;
        let record_type = row.try_get::<Option<String>, _>("type")?;
        let kind = row.try_get::<Option<String>, _>("kind")?;
        let deleted_at = row.try_get::<Option<String>, _>("deleted_at")?;
        let token_is_valid = account.len() == 37
            && account.starts_with("acct_")
            && account[5..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !token_is_valid
            || record_type.as_deref() != Some("Entity")
            || kind.as_deref() != Some("person")
            || deleted_at.is_some()
            || !record_ids.insert(record_id)
        {
            return Err(crate::Error::engine(
                "standby account bindings do not form a valid canonical identity set",
            ));
        }
        accounts.push(account);
    }

    match selected_account {
        Some(selected) if accounts.iter().any(|account| account == selected) => {
            Ok(selected.to_string())
        }
        Some(selected) => {
            let detail = if selected.len() == 37
                && selected.starts_with("acct_")
                && selected[5..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                "selected account is not available"
            } else {
                "selected account token is malformed"
            };
            Err(crate::Error::engine(format!(
                "standby account selection failed: {detail}"
            )))
        }
        None if accounts.len() == 1 => Ok(accounts.remove(0)),
        None if accounts.is_empty() => Err(crate::Error::engine(
            "standby account selection failed: no canonical account is present",
        )),
        None => Err(crate::Error::engine(
            "standby account selection failed: multiple accounts are present; pass --account <token> or set NATIVE_CE_ACCOUNT",
        )),
    }
}

/// The caller for the owner standby. The standby is the owner's own copy of
/// their database, inside the owner's trust boundary (design 1e5d802), so it
/// carries the narrow local-owner marker (owner counter footing only); it is
/// not `trusted_local`.
fn standby_owner_caller(account: String) -> Caller {
    Caller::local_owner(account).with_channel(crate::provenance::Channel::Mcp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standby::generation_store::tests::{observed, stage};
    use crate::standby::{StandbyStartupOutcome, StandbyStatusOnly};
    use serde_json::json;
    use tokio::io::AsyncWriteExt;

    const RECORD: &str = "70110000-0000-4000-8000-000000000001";

    #[test]
    fn owner_standby_caller_keeps_owner_counter_footing_without_trusted_local() {
        let caller = standby_owner_caller("acct:owner".to_string());
        assert!(caller.counter_footing().is_owner());
        assert!(!caller.is_member_copy());
        assert_eq!(caller.credential(), "acct:owner");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn supervisor_markdown_vault_opt_in_tracks_serving_generations_and_drains() {
        fn find(root: &std::path::Path, needle: &str) -> Option<std::path::PathBuf> {
            for entry in std::fs::read_dir(root).ok()? {
                let path = entry.ok()?.path();
                if path.is_dir() {
                    if let Some(found) = find(&path, needle) {
                        return Some(found);
                    }
                } else if std::fs::read_to_string(&path).is_ok_and(|text| text.contains(needle)) {
                    return Some(path);
                }
            }
            None
        }
        async fn wait(root: &std::path::Path, needle: &str) -> std::path::PathBuf {
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    if let Some(path) = find(root, needle) {
                        return path;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("vault did not publish {needle}"))
        }
        let (dir, db, session) = fixture_for_surface(McpSurfaceMode::Executor).await;
        let mut session = Arc::try_unwrap(session).unwrap_or_else(|_| panic!("unshared fixture"));
        let vault = std::fs::canonicalize(dir.path()).unwrap().join("vault");
        session.markdown_folder = Some(vault.clone());
        session.vault_tick_interval = Duration::from_millis(25);
        let session = Arc::new(session);
        crate::store::update_record(&db, RECORD, json!({"body":"vault smoke first"}))
            .await
            .unwrap();
        let first = accept(&session, &db, "vault-first").await;
        session
            .install_startup(activate(&session).await)
            .await
            .unwrap();
        let supervisor = StandbySupervisor::start(session.clone()).unwrap();
        let first_path = wait(&vault, "vault smoke first").await;
        wait(&vault, &format!("Generation: {first}")).await;
        crate::store::update_record(
            &db,
            RECORD,
            json!({"name":"second","body":"vault smoke second"}),
        )
        .await
        .unwrap();
        let second = accept(&session, &db, "vault-second").await;
        let second_path = wait(&vault, "vault smoke second").await;
        wait(&vault, &format!("Generation: {second}")).await;
        assert_ne!(first_path, second_path);
        assert!(!first_path.exists());
        let served_db = match session.capture() {
            SessionSnapshot::Serving(served) => served.resources.db.clone(),
            _ => panic!("serving"),
        };
        tokio::time::timeout(Duration::from_secs(10), supervisor.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert!(served_db.pool().is_closed());
        // Shutdown released the publisher lock as well as the engine bundle.
        drop(crate::markdown_vault::Publisher::open(&vault).unwrap());
    }

    async fn fixture() -> (tempfile::TempDir, crate::Db, Arc<StandbyStdioSession>) {
        fixture_for_surface(McpSurfaceMode::Legacy).await
    }

    async fn fixture_for_surface(
        surface: McpSurfaceMode,
    ) -> (tempfile::TempDir, crate::Db, Arc<StandbyStdioSession>) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let account = crate::identity::resolve_stdio_account_identity(&db, None)
            .await
            .unwrap();
        crate::store::create_record_as(
            &db,
            json!({"id": RECORD, "type":"Document", "kind":"note", "name":"first"}),
            Some(&account),
        )
        .await
        .unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap().join("replica");
        let store = GenerationStore::open(&root, "route-1", Some(origin.clone())).unwrap();
        let runtime = StandbyRuntimeConfig {
            replica_root: root,
            hosted_route_database_id: "route-1".into(),
            origin_database_id: origin,
        };
        let provider = StandbyStatusProvider::for_status_only_reason(
            runtime.clone(),
            store.clone(),
            Some(observed()),
            StandbyStatusOnly {
                reason: "no_usable_generation".into(),
                candidate_count: 0,
                unusable_candidate_count: 0,
            },
            false,
            false,
        );
        let session = Arc::new(
            StandbyStdioSession::new(
                StandbySessionConfig {
                    runtime,
                    store,
                    observed: observed(),
                    surface,
                    profile: ExposureProfile::Complete,
                    experimental: ExperimentalExecutors::empty(),
                    selected_account: Some(account),
                    refresh_configured: false,
                    refresh_available: false,
                },
                provider,
            )
            .unwrap(),
        );
        (dir, db, session)
    }

    async fn accept(session: &StandbyStdioSession, db: &crate::Db, stem: &str) -> String {
        let (snapshot, manifest) = stage(&session.config.store, db, stem).await;
        session
            .config
            .store
            .install_staged(&snapshot, &manifest, &observed())
            .await
            .unwrap()
            .id
    }

    async fn activate(session: &StandbyStdioSession) -> ActivatedGeneration {
        let snapshot = session.capture();
        let predecessor = match &snapshot {
            SessionSnapshot::Serving(served) => Some(served.resources.active.as_ref()),
            _ => None,
        };
        let hint = session
            .config
            .store
            .accepted_identity_hint()
            .unwrap()
            .unwrap();
        session
            .config
            .store
            .activate_accepted(&hint, &observed(), predecessor)
            .await
            .unwrap()
    }

    fn read(id: i64) -> Value {
        json!({"jsonrpc":"2.0", "id":id,"method":"tools/call", "params":{"name":"get_record","arguments":{"ids":[RECORD],"format":"json"}}})
    }

    fn surface_read(surface: McpSurfaceMode, id: i64) -> Value {
        match surface {
            McpSurfaceMode::Legacy => read(id),
            McpSurfaceMode::Executor | McpSurfaceMode::Lean => {
                json!({"jsonrpc":"2.0", "id":id,"method":"tools/call", "params":{"name":"records_read","arguments":{"operation":"get_record","arguments":{"ids":[RECORD]},"format":"json"}}})
            }
        }
    }

    async fn install_app(db: &crate::Db, account: &str) -> String {
        use crate::control::{
            append_control_event, AlphaTabAdoptPayload, AlphaTabStatePayload, ControlEventPayload,
            NewControlEvent,
        };
        let declaration = json!({"contract":"native.app.v2","needs":[],"effects":[]});
        let pin = AlphaTabStatePayload {
            account_id: account.into(),
            package: "offline.test".into(),
            version: "1".into(),
            digest: format!("sha256:{}", "a".repeat(64)),
            artifact_id: RECORD.into(),
            consented_source_revision: "source-1".into(),
            declaration_digest: crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(
                &declaration,
            )
            .unwrap(),
            consented_declaration: declaration,
            adoption: "caller_asserted".into(),
            request: None,
            previous_event_id: None,
        };
        let installed = append_control_event(
            db,
            NewControlEvent::authored(
                uuid::Uuid::new_v4().to_string(),
                crate::control::alpha_tab_aggregate_id(account, "offline.test"),
                account,
                None,
                "offline app fixture",
                ControlEventPayload::AlphaTabInstalled(pin.clone()),
            )
            .unwrap(),
        )
        .await
        .unwrap()
        .id;
        append_control_event(
            db,
            NewControlEvent::authored(
                uuid::Uuid::new_v4().to_string(),
                crate::control::alpha_tab_aggregate_id(account, "offline.test"),
                account,
                None,
                "offline app adoption fixture",
                ControlEventPayload::AlphaTabAdopted(AlphaTabAdoptPayload {
                    account_id: pin.account_id,
                    package: pin.package,
                    version: pin.version,
                    digest: pin.digest,
                    artifact_id: pin.artifact_id,
                    consented_source_revision: pin.consented_source_revision,
                    declaration_digest: pin.declaration_digest,
                    consented_declaration: pin.consented_declaration,
                    adoption: "shell_adopt.v1".into(),
                    previous_event_id: installed,
                    receipt_id: Some("receipt".into()),
                    preview_session: Some("session".into()),
                    launch_id: None,
                    authored_run_key: None,
                    request: None,
                }),
            )
            .unwrap(),
        )
        .await
        .unwrap()
        .id
    }

    #[tokio::test(flavor = "current_thread")]
    async fn app_carrier_preserves_installed_user_reads_and_standby_refusals() {
        let mut surfaces = vec![McpSurfaceMode::Legacy];
        #[cfg(feature = "mcp-executor-prototype")]
        surfaces.push(McpSurfaceMode::Executor);
        for (surface, modern_era) in surfaces
            .into_iter()
            .flat_map(|surface| [(surface, false), (surface, true)])
        {
            let (_dir, db, session) = fixture_for_surface(surface).await;
            let account = crate::identity::resolve_stdio_account_identity(&db, None)
                .await
                .unwrap();
            let install = install_app(&db, &account).await;
            let foreign_install = install_app(&db, "acct_foreign").await;
            accept(&session, &db, "app").await;
            session
                .install_startup(activate(&session).await)
                .await
                .unwrap();
            let mut read = surface_read(surface, 1);
            read["params"]["_meta"] = if modern_era {
                json!({"io.modelcontextprotocol/protocolVersion":protocol::PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities":{},
                    "io.modelcontextprotocol/clientInfo":{"name":"desktop-test","version":"1"}})
            } else {
                json!({})
            };
            let plain = session.handle_message(read.clone()).await.unwrap();
            let mut attributed = read;
            attributed["params"]["_meta"]["native/app"] =
                json!(format!("offline.test@1; install={install}"));
            let admitted = session.handle_message(attributed.clone()).await.unwrap();
            assert_eq!(admitted["result"]["isError"], false, "{admitted}");
            // The two reads are taken moments apart, so a whole-second
            // freshness age can tick between them; compare everything else.
            fn without_age(mut value: Value) -> Value {
                match &mut value {
                    Value::Object(map) => {
                        map.remove("age_seconds");
                        for child in map.values_mut() {
                            *child = without_age(child.take());
                        }
                    }
                    Value::Array(items) => {
                        for child in items.iter_mut() {
                            *child = without_age(child.take());
                        }
                    }
                    _ => {}
                }
                value
            }
            assert_eq!(
                without_age(admitted["result"]["structuredContent"].clone()),
                without_age(plain["result"]["structuredContent"].clone())
            );
            for identity in [
                format!("offline.test@2; install={install}"),
                "offline.test@1; install=missing".into(),
                format!("foreign.app@1; install={install}"),
                format!("offline.test@1; install={foreign_install}"),
            ] {
                attributed["params"]["_meta"]["native/app"] = json!(identity);
                let refused = session.handle_message(attributed.clone()).await.unwrap();
                assert_eq!(refused["result"]["isError"], true, "{refused}");
                assert!(
                    refused.get("error").is_none(),
                    "install refusal is a tool result: {refused}"
                );
                assert!(
                    refused["result"]["structuredContent"]["error"]
                        .as_str()
                        .unwrap()
                        .contains("app_install_unknown"),
                    "{refused}"
                );
            }
            attributed["params"]["_meta"]["native/app"] =
                json!(format!("offline.test@1; install={install}"));
            let sql = |sql: &str| match surface {
                McpSurfaceMode::Legacy => {
                    json!({"name":"query_sql","arguments":{"sql":sql,"format":"json"}})
                }
                _ => {
                    json!({"name":"sql_read","arguments":{"operation":"query_sql","arguments":{"sql":sql},"format":"json"}})
                }
            };
            for (query, succeeds) in [
                ("SELECT id FROM records LIMIT 1", true),
                ("SELECT * FROM alpha_tab_installs", false),
            ] {
                let mut request = attributed.clone();
                let meta = request["params"]["_meta"].clone();
                request["params"] = sql(query);
                request["params"]["_meta"] = meta;
                let result = session.handle_message(request).await.unwrap();
                assert_eq!(result["result"]["isError"], !succeeds, "{result}");
            }
            for (tool, args, expected) in [
                (
                    "create_record",
                    json!({"type":"Document","name":"never"}),
                    "STANDBY_READ_ONLY",
                ),
                (
                    "manage_alpha_tabs",
                    json!({"action":"list"}),
                    "app_operation_refused",
                ),
            ] {
                let mut request = attributed.clone();
                if surface == McpSurfaceMode::Legacy {
                    request["params"]["name"] = json!(tool);
                    request["params"]["arguments"] = args;
                } else {
                    request["params"]["name"] = json!(if tool == "create_record" {
                        "records_write"
                    } else {
                        "artifacts_read"
                    });
                    request["params"]["arguments"] = json!({"operation":if tool == "create_record" { "create_record" } else { "manage_alpha_tabs.list" },"arguments":if tool == "create_record" { args } else { json!({}) }});
                }
                let refused = session.handle_message(request).await.unwrap();
                assert_eq!(refused["result"]["isError"], true, "{refused}");
                assert!(refused.get("error").is_none(), "{refused}");
                let structured = &refused["result"]["structuredContent"];
                if tool == "create_record" {
                    assert_eq!(structured["error_code"], expected, "{refused}");
                    assert!(structured["error"].is_string(), "{refused}");
                } else {
                    assert!(
                        structured["error"].as_str().unwrap().contains(expected),
                        "{refused}"
                    );
                }
                if tool == "manage_alpha_tabs" {
                    // The launcher's first-party registry read is available;
                    // app approval remains refused even for action=list.
                    let mut registry_read = attributed.clone();
                    registry_read["params"]["name"] = json!(if surface == McpSurfaceMode::Legacy {
                        "manage_alpha_tabs"
                    } else {
                        "artifacts_read"
                    });
                    registry_read["params"]["arguments"] = if surface == McpSurfaceMode::Legacy {
                        json!({"action":"list"})
                    } else {
                        json!({"operation":"manage_alpha_tabs.list","arguments":{}})
                    };
                    registry_read["params"]["_meta"]
                        .as_object_mut()
                        .unwrap()
                        .remove("native/app");
                    let listed = session.handle_message(registry_read).await.unwrap();
                    assert_eq!(listed["result"]["isError"], false, "{listed}");
                    assert!(
                        listed["result"]["structuredContent"]
                            .to_string()
                            .contains("offline.test"),
                        "{listed}"
                    );
                }
            }
            let mut preferences = attributed;
            preferences["params"]["_meta"]
                .as_object_mut()
                .unwrap()
                .remove("native/app");
            preferences["params"]["name"] = json!(if surface == McpSurfaceMode::Legacy {
                "manage_account_config"
            } else {
                "records_read"
            });
            preferences["params"]["arguments"] = if surface == McpSurfaceMode::Legacy {
                json!({"action":"inspect","kind":"focus_preferences"})
            } else {
                json!({"operation":"manage_account_config.inspect","arguments":{"kind":"focus_preferences"}})
            };
            let unavailable = session.handle_message(preferences).await.unwrap();
            assert_eq!(unavailable["result"]["isError"], true, "{unavailable}");
            assert!(
                unavailable.to_string().contains("unavailable_offline"),
                "{unavailable}"
            );
            db.close().await;
        }
    }

    fn lease(session: &StandbyStdioSession, generation: &str) -> std::fs::File {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(
                session
                    .config
                    .runtime
                    .replica_root
                    .join("accepted/leases")
                    .join(format!("{generation}.lock")),
            )
            .unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn watcher_handoff_retains_real_transport_read_through_refusal_and_concurrent_pruning() {
        let mut surfaces = vec![McpSurfaceMode::Legacy];
        #[cfg(feature = "mcp-executor-prototype")]
        surfaces.push(McpSurfaceMode::Executor);
        for surface in surfaces {
            let (_dir, db, session) = fixture_for_surface(surface).await;
            let first = accept(&session, &db, "first").await;
            let entered = Arc::new(tokio::sync::Notify::new());
            let resume = Arc::new(tokio::sync::Notify::new());
            *session.dispatch_pause.lock().unwrap() = Some((1, entered.clone(), resume.clone()));
            session
                .install_startup(activate(&session).await)
                .await
                .unwrap();
            *session.dispatch_pause.lock().unwrap() = None;
            let old_db = match session.capture() {
                SessionSnapshot::Serving(served) => served.resources.db.clone(),
                _ => panic!("serving"),
            };
            let mut old_checkout = old_db.pool().acquire().await.unwrap();
            let (client, server) = tokio::io::duplex(65536);
            let (receive, mut send) = tokio::io::split(client);
            let (receive_server, send_server) = tokio::io::split(server);
            let live = session.clone();
            let transport = tokio::spawn(async move {
                live.serve(BufReader::new(receive_server), send_server)
                    .await
            });
            let mut responses = BufReader::new(receive).lines();
            send.write_all(format!("{}\n", surface_read(surface, 1)).as_bytes())
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), entered.notified())
                .await
                .unwrap();
            let (warming, waiting) = std::sync::mpsc::channel();
            let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
            let hook_gate = gate.clone();
            *session.warmup_hook.lock().unwrap() = Some(Arc::new(move || {
                let attempt = attempts.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                warming.send(attempt).unwrap();
                if attempt == 0 {
                    return Err(Error::engine("injected pinned warmup refusal"));
                }
                if attempt > 1 {
                    // Newer externally accepted generations make G1 eligible
                    // for retention. Keep their preparation pinned until EOF,
                    // so this transport still proves the intended G1/G2 reads.
                    return Ok(Some(Arc::new(tokio::sync::Notify::new())));
                }
                let (open, timeout) = hook_gate
                    .1
                    .wait_timeout_while(
                        hook_gate.0.lock().unwrap(),
                        Duration::from_secs(180),
                        |open| !*open,
                    )
                    .unwrap();
                assert!(
                    *open && !timeout.timed_out(),
                    "test must release pinned warmup"
                );
                Ok(None)
            }));
            crate::store::update_record(&db, RECORD, json!({"name":"second"}))
                .await
                .unwrap();
            let second = accept(&session, &db, "second").await;
            let waiting = tokio::task::spawn_blocking(move || {
                assert_eq!(waiting.recv_timeout(Duration::from_secs(180)).unwrap(), 0);
                assert_eq!(waiting.recv_timeout(Duration::from_secs(180)).unwrap(), 1);
                waiting
            });
            let waiting = waiting.await.unwrap();
            // The first pinned warmup actually refused; the bounded retry is
            // now pinned but unpublished. Neither old nor candidate can prune.
            assert!(
                matches!(session.capture(), SessionSnapshot::Serving(served) if served.resources.active.generation.id == first)
            );
            let old_lease = lease(&session, &first);
            let candidate_lease = lease(&session, &second);
            assert!(fs2::FileExt::try_lock_exclusive(&old_lease).is_err());
            assert!(fs2::FileExt::try_lock_exclusive(&candidate_lease).is_err());
            let store = session.config.store.clone();
            let pruning = tokio::task::spawn_blocking(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(store.prune_retention(&observed()))
                    .unwrap()
            });
            // Two generations need no retention checks. Pruning must finish
            // while warmup is pinned, rather than holding promotion across a
            // device check. Polling for that old long-held lock misses the
            // short discovery section and waits forever for obsolete behavior.
            assert!(tokio::time::timeout(Duration::from_secs(120), pruning)
                .await
                .unwrap()
                .unwrap()
                .is_empty());
            *gate.0.lock().unwrap() = true;
            gate.1.notify_all();
            tokio::time::timeout(Duration::from_secs(120), async {
                loop {
                    if matches!(session.capture(), SessionSnapshot::Serving(served) if served.resources.active.generation.id == second) { break; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.unwrap();
            assert!(!old_db.pool().is_closed());
            assert!(
                fs2::FileExt::try_lock_exclusive(&old_lease).is_err(),
                "held real request retains G1 lease after watcher publishes G2"
            );
            let mut newer = Vec::new();
            for name in ["third", "fourth"] {
                crate::store::update_record(&db, RECORD, json!({"name":name}))
                    .await
                    .unwrap();
                newer.push(accept(&session, &db, name).await);
            }
            tokio::task::spawn_blocking(move || {
                assert_eq!(waiting.recv_timeout(Duration::from_secs(180)).unwrap(), 2);
            })
            .await
            .unwrap();
            let generations = session
                .config
                .runtime
                .replica_root
                .join("accepted/generations");
            let old_path = generations.join(&first);
            assert_eq!(
                session
                    .config
                    .store
                    .accepted_identity_hint()
                    .unwrap()
                    .unwrap()
                    .generation_id(),
                newer[1]
            );
            // G4 is current and G3/G2 are the two retained predecessors. G1
            // is now actually deletion-eligible, but acceptance's pruning must
            // leave its real held request and checkout readable.
            assert!(old_path.is_dir());
            assert!(fs2::FileExt::try_lock_exclusive(&old_lease).is_err());
            resume.notify_one();
            let old: Value =
                serde_json::from_str(&responses.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(generation(&old), first);
            assert_eq!(
                old["result"]["structuredContent"]["records"][0]["name"],
                "first"
            );
            send.write_all(format!("{}\n", surface_read(surface, 2)).as_bytes())
                .await
                .unwrap();
            let fresh: Value =
                serde_json::from_str(&responses.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(generation(&fresh), second);
            assert_eq!(
                fresh["result"]["structuredContent"]["records"][0]["name"],
                "second"
            );
            // A real checkout can outlive dispatch. Retirement must still
            // protect its pathname until SQLite work and both pools drain.
            tokio::time::timeout(Duration::from_secs(10), async {
                while !old_db.pool().is_closed() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert!(fs2::FileExt::try_lock_exclusive(&old_lease).is_err());
            let old_name: String = sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
                .bind(RECORD)
                .fetch_one(&mut *old_checkout)
                .await
                .unwrap();
            assert_eq!(old_name, "first");
            let store = session.config.store.clone();
            assert!(tokio::task::spawn_blocking(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(store.prune_retention(&observed()))
                    .unwrap()
            })
            .await
            .unwrap()
            .is_empty());
            assert!(
                old_path.is_dir(),
                "eligible G1 survives physical pool drain"
            );
            assert!(fs2::FileExt::try_lock_exclusive(&old_lease).is_err());
            // Physical retirement releases the serving lease, not leases held
            // by a concurrent retention verifier. Force that permitted overlap
            // instead of relying on background maintenance's scheduling.
            let verifier_lease = lease(&session, &first);
            fs2::FileExt::lock_shared(&verifier_lease).unwrap();
            drop(old_checkout);
            session.retirements.drain().await;
            assert!(old_db.pool().is_closed());
            assert_eq!(
                fs2::FileExt::try_lock_exclusive(&old_lease)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::WouldBlock,
            );
            let store = session.config.store.clone();
            assert!(tokio::task::spawn_blocking(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(store.prune_retention(&observed()))
                    .unwrap()
            })
            .await
            .unwrap()
            .is_empty());
            assert!(
                old_path.is_dir(),
                "a verifier lease still protects drained G1"
            );
            drop(verifier_lease);
            // publish() schedules independent background retention. A single
            // explicit prune may skip a candidate leased by that worker even
            // after Retirements::drain has completed. Join it before requiring
            // deletion, without changing any lease or retained-floor check.
            tokio::time::timeout(
                Duration::from_secs(120),
                session.config.store.maintenance_idle(),
            )
            .await
            .expect("background retention finishes before unleased deletion");
            fs2::FileExt::try_lock_exclusive(&old_lease).unwrap();
            fs2::FileExt::unlock(&old_lease).unwrap();
            let store = session.config.store.clone();
            assert!(tokio::task::spawn_blocking(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(store.prune_retention(&observed()))
                    .unwrap()
            })
            .await
            .unwrap()
            .is_empty());
            assert!(
                !old_path.exists(),
                "eligible G1 prunes after physical drain"
            );
            for retained in [&second, &newer[0], &newer[1]] {
                assert!(generations.join(retained).is_dir());
            }
            send.write_all(format!("{}\n", surface_read(surface, 3)).as_bytes())
                .await
                .unwrap();
            let fresh: Value =
                serde_json::from_str(&responses.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(generation(&fresh), second);
            assert_eq!(
                fresh["result"]["structuredContent"]["records"][0]["name"],
                "second"
            );
            *session.warmup_hook.lock().unwrap() = None;
            send.shutdown().await.unwrap();
            tokio::time::timeout(Duration::from_secs(10), transport)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            db.close().await;
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn abort_during_pinned_warmup_drains_fragmented_input_or_captured_dispatch() {
        let mut cases = vec![(McpSurfaceMode::Legacy, false)];
        #[cfg(feature = "mcp-executor-prototype")]
        cases.push((McpSurfaceMode::Executor, true));
        for (surface, dispatching) in cases {
            let (_dir, db, session) = fixture_for_surface(surface).await;
            let first = accept(&session, &db, "first").await;
            let entered = Arc::new(tokio::sync::Notify::new());
            let resume = Arc::new(tokio::sync::Notify::new());
            if dispatching {
                *session.dispatch_pause.lock().unwrap() = Some((1, entered.clone(), resume));
            }
            session
                .install_startup(activate(&session).await)
                .await
                .unwrap();
            let old_db = match session.capture() {
                SessionSnapshot::Serving(served) => served.resources.db.clone(),
                _ => panic!("serving"),
            };
            let (warming, waiting) = std::sync::mpsc::channel();
            *session.warmup_hook.lock().unwrap() = Some(Arc::new(move || {
                warming.send(()).unwrap();
                for _ in 0..15000 {
                    crate::standby::generation_store::check_verification_cancellation()?;
                    std::thread::sleep(Duration::from_millis(2));
                }
                panic!("aborting serve must cooperatively cancel pinned preparation");
            }));
            crate::store::update_record(&db, RECORD, json!({"name":"second"}))
                .await
                .unwrap();
            let second = accept(&session, &db, "second").await;
            let (client, server) = tokio::io::duplex(65536);
            let (receive, mut send) = tokio::io::split(client);
            let (receive_server, send_server) = tokio::io::split(server);
            let live = session.clone();
            let transport = tokio::spawn(async move {
                live.serve(BufReader::new(receive_server), send_server)
                    .await
            });
            if dispatching {
                send.write_all(format!("{}\n", surface_read(surface, 1)).as_bytes())
                    .await
                    .unwrap();
                tokio::time::timeout(Duration::from_secs(5), entered.notified())
                    .await
                    .unwrap();
            } else {
                send.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":")
                    .await
                    .unwrap();
            }
            tokio::task::spawn_blocking(move || {
                waiting.recv_timeout(Duration::from_secs(180)).unwrap()
            })
            .await
            .unwrap();
            let candidate_lease = lease(&session, &second);
            assert!(fs2::FileExt::try_lock_exclusive(&candidate_lease).is_err());
            transport.abort();
            assert!(transport.await.unwrap_err().is_cancelled());
            tokio::time::timeout(Duration::from_secs(10), async {
                while Arc::strong_count(&session) != 1 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert!(old_db.pool().is_closed());
            assert_eq!(
                session
                    .retirements
                    .live
                    .load(std::sync::atomic::Ordering::Acquire),
                0
            );
            assert!(matches!(session.capture(), SessionSnapshot::StatusOnly(_)));
            assert_eq!(
                session
                    .config
                    .store
                    .accepted_identity_hint()
                    .unwrap()
                    .unwrap()
                    .generation_id(),
                second
            );
            assert_eq!(
                BufReader::new(receive).lines().next_line().await.unwrap(),
                None
            );
            for generation in [&first, &second] {
                let retired = lease(&session, generation);
                fs2::FileExt::try_lock_exclusive(&retired).unwrap();
                fs2::FileExt::unlock(&retired).unwrap();
            }
            db.close().await;
        }
    }

    fn generation(response: &Value) -> &str {
        response["result"]["structuredContent"]["standby_context"]["serving_generation_id"]
            .as_str()
            .unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shared_supervisor_connection_eof_preserves_other_dispatcher_generation() {
        let mut surfaces = vec![McpSurfaceMode::Legacy];
        #[cfg(feature = "mcp-executor-prototype")]
        surfaces.push(McpSurfaceMode::Executor);
        for surface in surfaces {
            let (_dir, db, session) = fixture_for_surface(surface).await;
            let first = accept(&session, &db, "first").await;
            let entered = Arc::new(tokio::sync::Notify::new());
            let resume = Arc::new(tokio::sync::Notify::new());
            *session.dispatch_pause.lock().unwrap() = Some((1, entered.clone(), resume.clone()));
            session
                .install_startup(activate(&session).await)
                .await
                .unwrap();
            let served_db = match session.capture() {
                SessionSnapshot::Serving(served) => served.resources.db.clone(),
                _ => panic!("serving"),
            };
            let protected = lease(&session, &first);
            let supervisor = StandbySupervisor::start(session.clone()).unwrap();
            let held_dispatcher = supervisor.dispatcher();
            let finishing_dispatcher = held_dispatcher.clone();
            let (held_client, held_server) = tokio::io::duplex(65536);
            let (held_receive, mut held_send) = tokio::io::split(held_client);
            let (held_reader, held_writer) = tokio::io::split(held_server);
            let held = tokio::spawn(async move {
                held_dispatcher
                    .serve_connection(BufReader::new(held_reader), held_writer)
                    .await
            });
            held_send
                .write_all(format!("{}\n", surface_read(surface, 1)).as_bytes())
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), entered.notified())
                .await
                .unwrap();

            let (client, server) = tokio::io::duplex(65536);
            let (receive, mut send) = tokio::io::split(client);
            let (reader, writer) = tokio::io::split(server);
            let finishing = tokio::spawn(async move {
                finishing_dispatcher
                    .serve_connection(BufReader::new(reader), writer)
                    .await
            });
            send.write_all(format!("{}\n", surface_read(surface, 2)).as_bytes())
                .await
                .unwrap();
            send.shutdown().await.unwrap();
            let response = BufReader::new(receive)
                .lines()
                .next_line()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                generation(&serde_json::from_str::<Value>(&response).unwrap()),
                first
            );
            finishing.await.unwrap().unwrap();
            // EOF dropped one dispatcher while the other retained its bundle.
            assert!(!held.is_finished());
            assert!(!served_db.pool().is_closed());
            assert!(fs2::FileExt::try_lock_exclusive(&protected).is_err());
            assert!(matches!(session.capture(), SessionSnapshot::Serving(served)
                if served.resources.active.generation.id == first));
            let fresh = supervisor
                .dispatcher()
                .handle_message(surface_read(surface, 3))
                .await
                .unwrap();
            assert_eq!(generation(&fresh), first);
            assert_eq!(fresh["result"]["isError"], false);

            // Owner shutdown removes serving state but waits for captured work.
            let shutdown = tokio::spawn(supervisor.shutdown());
            tokio::time::timeout(Duration::from_secs(5), async {
                while matches!(session.capture(), SessionSnapshot::Serving(_)) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(!shutdown.is_finished());
            assert!(!served_db.pool().is_closed());
            assert!(fs2::FileExt::try_lock_exclusive(&protected).is_err());
            resume.notify_one();
            let response = BufReader::new(held_receive)
                .lines()
                .next_line()
                .await
                .unwrap()
                .unwrap();
            let response: Value = serde_json::from_str(&response).unwrap();
            assert_eq!(generation(&response), first);
            assert_eq!(response["result"]["isError"], false);
            held_send.shutdown().await.unwrap();
            held.await.unwrap().unwrap();
            tokio::time::timeout(Duration::from_secs(10), shutdown)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(served_db.pool().is_closed());
            fs2::FileExt::try_lock_exclusive(&protected).unwrap();
            fs2::FileExt::unlock(&protected).unwrap();
            db.close().await;
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn captured_dispatch_keeps_old_context_pool_and_lease_until_completion() {
        let (_dir, db, session) = fixture().await;
        let first = accept(&session, &db, "first").await;
        let StandbyStartupOutcome::Serving(active) = session
            .config
            .store
            .activate_for_startup(&observed())
            .await
            .unwrap()
        else {
            panic!("startup")
        };
        let mut prepared = session
            .prepare(*active, session.config.selected_account.as_deref())
            .await
            .unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        prepared.dispatch_pause = Some((1, entered.clone(), resume.clone()));
        session.publish(prepared).unwrap();
        let live = session.clone();
        let held = tokio::spawn(async move { live.handle_message(read(1)).await.unwrap() });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        crate::store::update_record(&db, RECORD, json!({"name":"second"}))
            .await
            .unwrap();
        let second = accept(&session, &db, "second").await;
        let candidate = activate(&session).await;
        session
            .publish(
                session
                    .prepare(candidate, session.config.selected_account.as_deref())
                    .await
                    .unwrap(),
            )
            .unwrap();
        let fresh = session.handle_message(read(2)).await.unwrap();
        assert_eq!(generation(&fresh), second);
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(
                session
                    .config
                    .runtime
                    .replica_root
                    .join("accepted/leases")
                    .join(format!("{first}.lock")),
            )
            .unwrap();
        assert!(
            fs2::FileExt::try_lock_exclusive(&lease).is_err(),
            "in-flight generation must stay protected"
        );
        resume.notify_one();
        let old = held.await.unwrap();
        assert_eq!(
            old["result"]["structuredContent"]["records"][0]["name"],
            "first"
        );
        assert_eq!(generation(&old), first);
        session.retirements.drain().await;
        fs2::FileExt::try_lock_exclusive(&lease).unwrap();
        fs2::FileExt::unlock(&lease).unwrap();
        db.close().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejected_identity_owner_and_hot_rollback_preserve_serving() {
        let (_dir, db, session) = fixture().await;
        let first = accept(&session, &db, "first").await;
        let first_pointer = std::fs::read(
            session
                .config
                .runtime
                .replica_root
                .join("accepted/current.json"),
        )
        .unwrap();
        session
            .install_startup(activate(&session).await)
            .await
            .unwrap();
        crate::store::update_record(&db, RECORD, json!({"name":"second"}))
            .await
            .unwrap();
        let second = accept(&session, &db, "second").await;
        let candidate = activate(&session).await;
        assert!(session
            .prepare(candidate, Some("acct_00000000000000000000000000000000"))
            .await
            .is_err());
        assert_eq!(
            generation(&session.handle_message(read(1)).await.unwrap()),
            first
        );
        let hint = session
            .config
            .store
            .accepted_identity_hint()
            .unwrap()
            .unwrap();
        let mut wrong_consumer = observed();
        // A same-format artifact change is now eligible for re-admission;
        // this refusal must exercise an incompatible consumer instead.
        wrong_consumer.ddl_sha256 = "d".repeat(64);
        assert!(session
            .config
            .store
            .activate_accepted(&hint, &wrong_consumer, None)
            .await
            .is_err());
        assert_eq!(
            generation(&session.handle_message(read(2)).await.unwrap()),
            first
        );
        session
            .publish(
                session
                    .prepare(
                        activate(&session).await,
                        session.config.selected_account.as_deref(),
                    )
                    .await
                    .unwrap(),
            )
            .unwrap();
        std::fs::write(
            session
                .config
                .runtime
                .replica_root
                .join("accepted/current.json"),
            first_pointer,
        )
        .unwrap();
        let rollback = session
            .config
            .store
            .accepted_identity_hint()
            .unwrap()
            .unwrap();
        let snapshot = session.capture();
        let SessionSnapshot::Serving(served) = &snapshot else {
            panic!("serving")
        };
        assert!(session
            .config
            .store
            .activate_accepted(&rollback, &observed(), Some(&served.resources.active))
            .await
            .is_err());
        assert_eq!(
            generation(&session.handle_message(read(3)).await.unwrap()),
            second
        );
        crate::authorization::replace_explicit_policy(
            &db,
            session.config.selected_account.as_deref().unwrap(),
            "native:root",
            vec![],
        )
        .await
        .unwrap();
        // The owner floor survives policy removal. Use the real event API to
        // remove that floor too; never corrupt a projection or repair a marker.
        crate::store::unset_facet(&db, "native:root", "owner")
            .await
            .unwrap();
        assert_eq!(
            crate::authorization::effective_capability(
                &db,
                crate::authorization::Principal::bound(
                    session.config.selected_account.as_deref().unwrap(),
                    true
                ),
                "native:root",
            )
            .await
            .unwrap(),
            crate::authorization::Capability::None
        );
        accept(&session, &db, "root-unavailable").await;
        let candidate = activate(&session).await;
        let refused = session
            .prepare(candidate, session.config.selected_account.as_deref())
            .await;
        assert!(
            matches!(refused, Err(ref error) if error.to_string().contains("authorised readiness refused")),
            "device-valid candidate must refuse at actual authorised root readiness"
        );
        assert_eq!(
            generation(&session.handle_message(read(4)).await.unwrap()),
            second
        );
        session.retirements.drain().await;
        db.close().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_or_cancelled_publication_cannot_seed_candidate_proof_reuse() {
        use crate::standby::generation_store::{test_diagnostics, with_verification_cancellation};
        use tracing::instrument::WithSubscriber;
        let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
        let (_dir, db, session) = fixture().await;
        let first = accept(&session, &db, "first").await;
        session
            .install_startup(activate(&session).await)
            .await
            .unwrap();
        crate::store::update_record(&db, RECORD, json!({"name":"second"}))
            .await
            .unwrap();
        let second = accept(&session, &db, "second").await;
        *session.warmup_hook.lock().unwrap() =
            Some(Arc::new(|| Err(Error::engine("fixture warmup failure"))));
        let logs = test_diagnostics::Capture::default();
        let result = async {
            let active = activate(&session).await;
            session.install_startup(active).await
        }
        .with_subscriber(logs.subscriber())
        .await;
        assert!(result.is_err());
        assert_eq!(
            generation(&session.handle_message(read(1)).await.unwrap()),
            first
        );
        // Device verification ran (not skipped): no conformance suite, and
        // the candidate snapshot check finished successfully.
        assert_eq!(
            logs.output()
                .lines()
                .filter(|line| line.contains("standby suite started"))
                .count(),
            0
        );
        assert!(
            logs.output().lines().any(|line| line
                .contains("phase=\"startup-snapshot\"")
                && line.contains("ok=true")),
            "failed warmup still device-verified the candidate"
        );
        *session.warmup_hook.lock().unwrap() = None;

        // Device verification succeeded, but cancellation under the publication lock must
        // drop the prepared serving state rather than attach it to serving.
        let logs = test_diagnostics::Capture::default();
        let prepared = async {
            let active = activate(&session).await;
            session
                .prepare(active, session.config.selected_account.as_deref())
                .await
                .unwrap()
        }
        .with_subscriber(logs.subscriber())
        .await;
        assert_eq!(
            logs.output()
                .lines()
                .filter(|line| line.contains("standby suite started"))
                .count(),
            0,
            "failed preparation did not cache the candidate"
        );
        assert!(
            logs.output().lines().any(|line| line
                .contains("phase=\"startup-snapshot\"")
                && line.contains("ok=true")),
            "failed preparation still device-verified the candidate"
        );
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
        assert!(with_verification_cancellation(flag, || session.publish(prepared)).is_err());
        assert_eq!(
            generation(&session.handle_message(read(2)).await.unwrap()),
            first
        );

        let logs = test_diagnostics::Capture::default();
        async {
            let active = activate(&session).await;
            session.install_startup(active).await.unwrap();
        }
        .with_subscriber(logs.subscriber())
        .await;
        assert_eq!(
            logs.output()
                .lines()
                .filter(|line| line.contains("standby suite started"))
                .count(),
            0,
            "cancelled publication did not cache the candidate"
        );
        assert!(
            logs.output().lines().any(|line| line
                .contains("phase=\"startup-snapshot\"")
                && line.contains("ok=true")),
            "post-cancellation activation re-verified the candidate"
        );
        assert_eq!(
            generation(&session.handle_message(read(3)).await.unwrap()),
            second
        );
        session.retire_serving();
        session.retirements.drain().await;
        db.close().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dedicated_warmup_cannot_block_stdio_and_refusal_or_eof_keeps_old_reads() {
        let (_dir, db, session) = fixture().await;
        let first = accept(&session, &db, "first").await;
        session
            .install_startup(activate(&session).await)
            .await
            .unwrap();
        let (client, server) = tokio::io::duplex(65536);
        let (receive, mut send) = tokio::io::split(client);
        let (receive_server, send_server) = tokio::io::split(server);
        let mut responses = BufReader::new(receive).lines();
        let (entered, waiting) = std::sync::mpsc::channel();
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let hook_gate = gate.clone();
        *session.warmup_hook.lock().unwrap() = Some(Arc::new(move || {
            entered
                .send(std::thread::current().name().map(str::to_owned))
                .unwrap();
            let (lock, ready) = &*hook_gate;
            let (open, timeout) = ready
                .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(10), |open| !*open)
                .unwrap();
            assert!(*open && !timeout.timed_out(), "test must release warmup");
            Err(Error::engine("injected warmup refusal"))
        }));
        crate::store::update_record(&db, RECORD, json!({"name":"second"}))
            .await
            .unwrap();
        accept(&session, &db, "second").await;
        // Start the bounded warmup hook after producer fsyncs complete. Slow
        // fixture publication must not spend the hook's dispatch/EOF budget.
        let live = session.clone();
        let transport = tokio::spawn(async move {
            live.serve(BufReader::new(receive_server), send_server)
                .await
        });
        let thread_name = tokio::task::spawn_blocking(move || {
            waiting.recv_timeout(Duration::from_secs(120)).unwrap()
        })
        .await
        .unwrap();
        assert_eq!(thread_name.as_deref(), Some("standby-handoff"));
        send.write_all(format!("{}\n", read(1)).as_bytes())
            .await
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), responses.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            generation(&serde_json::from_str::<Value>(&response).unwrap()),
            first
        );
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        *session.warmup_hook.lock().unwrap() = None;
        // EOF while a refused candidate is awaiting retry must drain cleanly.
        send.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), transport)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        db.close().await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn eof_cancels_unpublished_warmup_and_drains_candidate_without_retiring_capture() {
        let (_dir, db, session) = fixture().await;
        let first = accept(&session, &db, "first").await;
        session
            .install_startup(activate(&session).await)
            .await
            .unwrap();
        let captured = session.capture();
        let (client, server) = tokio::io::duplex(65536);
        let (receive, mut send) = tokio::io::split(client);
        let (receive_server, send_server) = tokio::io::split(server);
        let _receive = receive;
        let (entered, waiting) = std::sync::mpsc::channel();
        *session.warmup_hook.lock().unwrap() = Some(Arc::new(move || {
            entered.send(()).unwrap();
            for _ in 0..5000 {
                crate::standby::generation_store::check_verification_cancellation()?;
                std::thread::sleep(Duration::from_millis(2));
            }
            panic!("EOF must cooperatively cancel preparation");
        }));
        crate::store::update_record(&db, RECORD, json!({"name":"second"}))
            .await
            .unwrap();
        let second = accept(&session, &db, "second").await;
        let live = session.clone();
        let transport = tokio::spawn(async move {
            live.serve(BufReader::new(receive_server), send_server)
                .await
        });
        tokio::task::spawn_blocking(move || {
            waiting.recv_timeout(Duration::from_secs(120)).unwrap()
        })
        .await
        .unwrap();
        let warming_lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(
                session
                    .config
                    .runtime
                    .replica_root
                    .join("accepted/leases")
                    .join(format!("{second}.lock")),
            )
            .unwrap();
        assert!(
            fs2::FileExt::try_lock_exclusive(&warming_lease).is_err(),
            "pinned warmup must exclude pruning"
        );
        send.shutdown().await.unwrap();
        let SessionSnapshot::Serving(old) = &captured else {
            panic!("captured generation")
        };
        assert_eq!(
            generation(&old.dispatch(read(1), false).await.unwrap()),
            first
        );
        drop(captured);
        tokio::time::timeout(Duration::from_secs(10), transport)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(
                session
                    .config
                    .runtime
                    .replica_root
                    .join("accepted/leases")
                    .join(format!("{second}.lock")),
            )
            .unwrap();
        fs2::FileExt::try_lock_exclusive(&lease).unwrap();
        fs2::FileExt::unlock(&lease).unwrap();
        session.retirements.drain().await;
        db.close().await;
    }
}
