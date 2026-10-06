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
    ActivatedGeneration, GenerationStore, StandbyRuntimeConfig, StandbyStatusProvider,
};
use crate::standby_snapshot::ObservedInstalledConsumerIdentity;

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

/// Also guards preparation failures/cancellation after a pool has opened.
struct GenerationResources {
    db: crate::Db,
    active: Arc<ActivatedGeneration>,
    retirements: Arc<Retirements>,
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
    #[cfg(test)]
    dispatch_pause: Option<DispatchPause>,
}

impl ServedGeneration {
    async fn dispatch(&self, message: Value) -> Option<Value> {
        #[cfg(test)]
        if let Some((id, entered, resume)) = &self.dispatch_pause {
            if message["id"].as_i64() == Some(*id) {
                entered.notify_one();
                resume.notified().await;
            }
        }
        match &self.dispatcher {
            ServedDispatcher::Legacy { registry, caller } => {
                dispatch_engine_message(
                    registry.clone(),
                    EngineHandle::Sqlite(self.resources.db.clone()),
                    caller.clone(),
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
                        EngineHandle::Sqlite(self.resources.db.clone()),
                        caller.clone(),
                        message,
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
    pub fn new(config: StandbySessionConfig, provider: StandbyStatusProvider) -> Result<Self> {
        let registry = Self::registry(&config, provider.clone().with_connected_handoff())?;
        let mut catalogue: Vec<Value> = match config.surface {
            McpSurfaceMode::Legacy => registry
                .descriptor_projection(config.profile)
                .into_iter()
                .map(|tool| tool.descriptor)
                .collect(),
            McpSurfaceMode::Executor => {
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

    async fn prepare(
        &self,
        active: ActivatedGeneration,
        account: Option<&str>,
    ) -> Result<ServedGeneration> {
        crate::standby::generation_store::check_verification_cancellation()?;
        let active = Arc::new(active);
        let db = crate::db::open_existing_database_standby_read_only(
            active
                .generation
                .snapshot_path
                .to_str()
                .ok_or_else(|| Error::engine("invalid standby snapshot path"))?,
        )
        .await?;
        self.retirements
            .live
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let resources = GenerationResources {
            db,
            active,
            retirements: self.retirements.clone(),
        };
        let account = resolve_standby_account_identity(&resources.db, account).await?;
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
        let caller =
            Caller::authenticated(account.clone()).with_channel(crate::provenance::Channel::Mcp);
        let dispatcher = match self.config.surface {
            McpSurfaceMode::Legacy => ServedDispatcher::Legacy { registry, caller },
            McpSurfaceMode::Executor => {
                #[cfg(feature = "mcp-executor-prototype")]
                {
                    ServedDispatcher::Executor {
                        server: Box::new(
                            super::ExecutorPrototypeStdioServer::new_standby_read_only(
                                registry.clone(),
                                resources.db.clone(),
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
            #[cfg(test)]
            dispatch_pause: self.dispatch_pause.lock().unwrap().clone(),
        };
        // Readiness uses the actual authenticated production dispatch path.
        // A readable SQLite file or built catalogue alone proves no authorised
        // kernel root can be served by this exact candidate/caller.
        let (name, arguments) = match &prepared.dispatcher {
            ServedDispatcher::Legacy { .. } => (
                "get_record",
                serde_json::json!({"ids":["native:root"],"format":"json"}),
            ),
            #[cfg(feature = "mcp-executor-prototype")]
            ServedDispatcher::Executor { .. } => (
                "records_read",
                serde_json::json!({"operation":"get_record","arguments":{"ids":["native:root"]},"format":"json"}),
            ),
        };
        let response = prepared.dispatch(serde_json::json!({"jsonrpc":"2.0","id":0,"method":"tools/call","params":{"name":name,"arguments":arguments}})).await
            .ok_or_else(|| Error::engine("standby authorised readiness unavailable"))?;
        let value = &response["result"]["structuredContent"];
        let context = &value["standby_context"];
        if response["result"]["isError"] != false
            || !value["records"].as_array().is_some_and(|records| {
                records
                    .iter()
                    .any(|record| record["id"] == "native:root" && record["status"] == "found")
            })
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

    fn publish(&self, prepared: ServedGeneration) -> Result<()> {
        let old = {
            let mut state = self.state.lock().expect("standby state lock");
            crate::standby::generation_store::check_verification_cancellation()?;
            std::mem::replace(&mut *state, SessionSnapshot::Serving(Arc::new(prepared)))
        };
        // Dropping outside the request lock may enqueue pool retirement, but
        // never closes the shared pool of an in-flight captured generation.
        drop(old);
        Ok(())
    }

    pub async fn handle_message(&self, message: Value) -> Option<Value> {
        let snapshot = self.capture();
        let listing = message["method"] == "tools/list";
        let orientation = matches!(
            message["method"].as_str(),
            Some("server/discover" | "initialize")
        );
        let mut response = match &snapshot {
            SessionSnapshot::StatusOnly(server) => server.handle_message(message).await,
            SessionSnapshot::Serving(served) => served.dispatch(message).await,
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
        let (shutdown, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let cancellation = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_cancellation = cancellation.clone();
        let (stopped, stopped_rx) = tokio::sync::oneshot::channel();
        let stop = WorkerShutdown {
            session: self.clone(),
            cancellation,
            shutdown,
        };
        let session = self.clone();
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
                        session.retirements.own_runtime(runtime.handle().clone());
                        runtime.block_on(async {
                            // Never drop a pinned full-verification future at
                            // an arbitrary SQL await: finish its current phase
                            // and cleanup before releasing its pathname lease.
                            session.watch_accepted(&mut shutdown_rx).await;
                            session.retire_serving();
                            // This supervisor survives a dropped serve future.
                            // Keep driving cleanup until the final request Arc
                            // and candidate pool have actually retired.
                            session.retirements.drain_all().await;
                        });
                        *session
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
        let outcome = self.transport(reader, writer).await;
        stop.cancel();
        let _ = stopped_rx.await;
        tokio::task::spawn_blocking(move || worker.join())
            .await
            .map_err(|_| Error::engine("standby handoff worker join failed"))?
            .map_err(|_| Error::engine("standby handoff worker panicked"))??;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standby::generation_store::tests::{observed, stage};
    use crate::standby::{StandbyStartupOutcome, StandbyStatusOnly};
    use serde_json::json;
    use tokio::io::AsyncWriteExt;

    const RECORD: &str = "70110000-0000-4000-8000-000000000001";

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
            McpSurfaceMode::Executor => {
                json!({"jsonrpc":"2.0", "id":id,"method":"tools/call", "params":{"name":"records_read","arguments":{"operation":"get_record","arguments":{"ids":[RECORD]},"format":"json"}}})
            }
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
            let promotion = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(
                    session
                        .config
                        .runtime
                        .replica_root
                        .join("accepted/promotion.lock"),
                )
                .unwrap();
            tokio::time::timeout(Duration::from_secs(120), async {
                loop {
                    if fs2::FileExt::try_lock_exclusive(&promotion).is_err() {
                        break;
                    }
                    fs2::FileExt::unlock(&promotion).unwrap();
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
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
            assert!(pruning.await.unwrap().is_empty());
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
            drop(old_checkout);
            session.retirements.drain().await;
            assert!(old_db.pool().is_closed());
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
        wrong_consumer.artifact_sha256 = "d".repeat(64);
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
            "full-valid candidate must refuse at actual authorised root readiness"
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
        assert_eq!(
            logs.output()
                .lines()
                .filter(|line| line.contains("standby suite started"))
                .count(),
            1
        );
        *session.warmup_hook.lock().unwrap() = None;

        // FULL succeeded, but cancellation under the publication lock must
        // drop the private prepared witness rather than attach it to serving.
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
            1,
            "failed preparation did not cache the candidate"
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
            1,
            "cancelled publication did not cache the candidate"
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
        assert_eq!(generation(&old.dispatch(read(1)).await.unwrap()), first);
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
