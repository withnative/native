//! Failover policy and owner-only persisted discovery / own-write state.
use super::*;
use crate::mcp::standby_stdio::{
    StandbyDispatcher, StandbySessionConfig, StandbyStdioSession, StandbySupervisor,
};
use crate::mcp::{ExperimentalExecutors, ExposureProfile, McpSurfaceMode};
use crate::standby::delta_transport::{
    AuthorityActHttpClient, AuthorityActTransport, AuthorityCallFuture,
};
use crate::standby::{
    observe_installed_consumer_identity, start_background_refresh_after_startup, BackgroundRefresh,
    GenerationStore, RefreshCause, RefreshHints, StandbyRuntimeConfig, StandbyStatusOnly,
    StandbyStatusProvider,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Health {
    Reachable,
    Unreachable,
    AuthRefused,
    ProtocolFailed,
    /// Hosted is reachable but authors an interchange revision this build
    /// cannot read. Forwarding continues; following pauses and local reads
    /// are stale until the node is upgraded.
    RevisionUnsupported,
}
impl Health {
    /// Hosted counts as down only when it is actually unreachable. A
    /// reachable hosted that answers malformedly (`ProtocolFailed`), refuses
    /// credentials (`AuthRefused`) or authors an unreadable revision
    /// (`RevisionUnsupported`) still receives forwarded requests; local reads
    /// are marked stale instead of silently substituting.
    fn offline(self) -> bool {
        matches!(self, Self::Unreachable)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Binding {
    home: String,
    route: String,
    origin: String,
    account: String,
    endpoint: String,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Discovery {
    tools: Option<Value>,
    operations: Vec<Value>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Floor {
    act: Option<i64>,
    pending: u64,
    unresolved: bool,
    #[serde(skip)]
    active_writes: u64,
}
impl Floor {
    fn begin_write(&mut self) {
        self.pending += 1;
        self.active_writes += 1;
        self.unresolved = true;
    }
    fn finish_write(&mut self, may_commit: bool) {
        self.active_writes -= 1;
        if may_commit {
            self.pending += 1;
            self.unresolved = true;
        }
    }
    fn observe(&mut self, started_at: u64, act: i64) {
        self.act = Some(self.act.map_or(act, |old| old.max(act)));
        if started_at == self.pending && self.active_writes == 0 {
            self.unresolved = false;
        }
    }
    fn label(&self, serving: Option<i64>) -> Option<String> {
        if self.unresolved || self.act.is_none() || serving.is_none() || serving < self.act {
            Some(match self.act {
                Some(act) => format!("this copy may be missing writes acknowledged by hosted (up to at least act {act})"),
                None => "this copy may be missing writes acknowledged by hosted (hosted act floor unknown)".into(),
            })
        } else {
            None
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Persisted {
    binding: Binding,
    floor: Floor,
    discovery: BTreeMap<String, Discovery>,
}
struct State {
    persisted: Persisted,
    health: Health,
    persistence_failed: bool,
    health_epoch: u64,
    /// Sticky revision-compatibility flag, separate from connectivity.
    /// Set when a validated probe shows hosted authoring an unreadable
    /// interchange revision; retained through later outages and cleared
    /// only by a compatible validated head. Memory-only: it re-derives on
    /// every probe after a restart.
    revision_unsupported: bool,
}

/// No secret is stored here. Binding is still checked both in the filename and
/// payload: replaced origins and accounts cannot inherit a cache or floor.
struct StateFile {
    path: PathBuf,
}
impl StateFile {
    fn open(directory: &Path, binding: Binding) -> Result<(Self, Persisted)> {
        let directory = directory.join("state");
        validate_credential_path(&directory, "node state directory")?;
        match fs::symlink_metadata(&directory) {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(Error::engine("invalid node state directory"));
                }
                check_owned(&meta, 0o700)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(&directory)?;
            }
            Err(e) => return Err(e.into()),
        }
        let key = hex::encode(Sha256::digest(serde_json::to_vec(&binding)?));
        let file = Self {
            path: directory.join(format!("{key}.json")),
        };
        let state = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&file.path)
        {
            Ok(mut input) => {
                let meta = input.metadata()?;
                check_owned(&meta, 0o600)?;
                if !meta.is_file() || meta.nlink() != 1 || meta.len() > MAX_FRAME as u64 * 2 {
                    return Err(Error::engine("invalid node state file"));
                }
                let mut bytes = Vec::new();
                input.read_to_end(&mut bytes)?;
                let state: Persisted = serde_json::from_slice(&bytes)?;
                if state.binding != binding {
                    return Err(Error::engine("node state binding mismatch"));
                }
                state
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Persisted {
                binding,
                floor: Floor::default(),
                discovery: BTreeMap::new(),
            },
            Err(e) => return Err(e.into()),
        };
        Ok((file, state))
    }
    fn save(&self, state: &Persisted) -> Result<()> {
        let temporary = self
            .path
            .with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            let bytes = serde_json::to_vec(state)?;
            if bytes.len() > MAX_FRAME * 2 {
                return Err(Error::engine("node state exceeds bound"));
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            output.write_all(&bytes)?;
            output.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            File::open(self.path.parent().expect("state parent"))?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

pub(super) struct Failover {
    upstream: Arc<Upstream>,
    discovery_upstream: Upstream,
    dispatcher: StandbyDispatcher,
    local: Vec<Value>,
    state: Mutex<State>,
    file: StateFile,
    probe_lock: Mutex<()>,
    probe_needed: tokio::sync::Notify,
    probe_client: reqwest::Client,
    refresh_hints: Option<RefreshHints>,
    gate: Option<Arc<WriteGate>>,
}

pub(super) struct NodeStandby {
    pub(super) supervisor: StandbySupervisor,
    pub(super) local: Vec<Value>,
    pub(super) origin: String,
    pub(super) refresh: Option<BackgroundRefresh>,
    /// The local copy; its size sets the free-disk floor for held writes.
    pub(super) replica_root: PathBuf,
}

impl NodeStandby {
    pub(super) async fn shutdown(self) -> Result<()> {
        if let Some(refresh) = self.refresh {
            refresh.stop().await;
        }
        self.supervisor.shutdown().await
    }
}

/// Default vault location: a `vault/` sibling of the standby `replica_root`.
/// `replica_root` is validated as an absolute path with at least one normal
/// component, so it always has a parent. Comparison is lexical: symlinks are
/// never canonicalised (Native Desktop relies on `<node root>/vault`).
/// Returns `None` (vault off) when the derived path would equal or sit inside
/// `replica_root` (e.g. a `replica_root` that itself ends in `vault`), or when
/// the parent is the filesystem root (`/replica` would give `/vault`).
pub(super) fn default_vault_path(replica_root: &Path) -> Option<PathBuf> {
    let parent = replica_root.parent()?;
    if parent == Path::new("/") {
        return None;
    }
    let vault = parent.join("vault");
    if vault == replica_root || vault.starts_with(replica_root) {
        return None;
    }
    Some(vault)
}

/// Resolve the vault setting against the standby copy. `None` means off:
/// no standby copy means off without an error, and `false` means off even
/// with one. Only an explicit path without a standby copy errors.
fn resolve_vault_path(
    setting: &Option<MarkdownFolder>,
    replica_root: Option<&Path>,
) -> Result<Option<PathBuf>> {
    match (setting, replica_root) {
        (Some(MarkdownFolder::Explicit(path)), Some(_)) => Ok(Some(path.clone())),
        (Some(MarkdownFolder::Explicit(_)), None) => Err(Error::engine(
            "node refresh_config and markdown_folder require standby_config",
        )),
        (Some(MarkdownFolder::Disabled), _) => Ok(None),
        (None, Some(root)) => match default_vault_path(root) {
            Some(path) => Ok(Some(path)),
            None => {
                tracing::warn!(
                    target: "native_ce::standby::vault",
                    replica_root = %crate::markdown_vault::diag_field(&root.display(), crate::markdown_vault::DIAG_ROOT_MAX),
                    "markdown vault default beside the local copy is unsafe; vault is off - set \"markdown_folder\" to an explicit path to enable it",
                );
                Ok(None)
            }
        },
        (None, None) => Ok(None),
    }
}

pub(super) fn start_standby(config: &NodeConfig) -> Result<Option<NodeStandby>> {
    if config.standby_config.is_none() {
        if config.refresh_config.is_some()
            || matches!(config.markdown_folder, Some(MarkdownFolder::Explicit(_)))
        {
            return Err(Error::engine(
                "node refresh_config and markdown_folder require standby_config",
            ));
        }
        return Ok(None);
    }
    start_standby_with_identity(config, observe_installed_consumer_identity()?)
}

fn start_standby_with_identity(
    config: &NodeConfig,
    observed: crate::standby_snapshot::ObservedInstalledConsumerIdentity,
) -> Result<Option<NodeStandby>> {
    let Some(path) = &config.standby_config else {
        return Ok(None);
    };
    let account = config
        .account_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::engine("node standby requires an explicit canonical account_id"))?;
    let runtime = StandbyRuntimeConfig::from_json(&fs::read(path)?)?;
    if runtime.hosted_route_database_id != config.db_id {
        return Err(Error::engine("node and standby workspace routes differ"));
    }
    let origin = runtime.origin_database_id.clone();
    let replica_root = runtime.replica_root.clone();
    let vault_path = resolve_vault_path(&config.markdown_folder, Some(&replica_root))?;
    let store = GenerationStore::open(
        &runtime.replica_root,
        &runtime.hosted_route_database_id,
        Some(origin.clone()),
    )?;
    let (startup_ready, ready) = tokio::sync::oneshot::channel();
    let refresh_configured = config.refresh_config.is_some();
    let refresh = if let Some(path) = &config.refresh_config {
        match start_background_refresh_after_startup(
            &runtime,
            &observed,
            path,
            ready,
            store.clone(),
        ) {
            Ok(refresh) => Some(refresh),
            Err(_) => {
                tracing::warn!(target: "native_ce::standby::verification", "node standby refresh is unavailable");
                None
            }
        }
    } else {
        None
    };
    let refresh_available = refresh.is_some();
    let provider = StandbyStatusProvider::for_status_only_reason(
        runtime.clone(),
        store.clone(),
        Some(observed.clone()),
        StandbyStatusOnly {
            reason: "startup_readiness_pending".into(),
            candidate_count: 0,
            unusable_candidate_count: 0,
        },
        refresh_configured,
        refresh_available,
    );
    let session = Arc::new(
        StandbyStdioSession::new(
            StandbySessionConfig {
                runtime,
                store,
                observed,
                surface: McpSurfaceMode::Executor,
                profile: ExposureProfile::Complete,
                experimental: ExperimentalExecutors::empty(),
                selected_account: Some(account.into()),
                refresh_configured,
                refresh_available,
            },
            provider.clone(),
        )?
        .with_markdown_folder(vault_path),
    );
    let local = session
        .operation_rows(provider)?
        .as_array()
        .cloned()
        .ok_or_else(|| Error::engine("invalid local operation catalogue"))?;
    // Cold recovery, activation and later verification all belong to the
    // supervisor runtime; the listener can forward hosted calls immediately.
    Ok(Some(NodeStandby {
        supervisor: StandbySupervisor::start_with_startup_notifier(session, startup_ready)?,
        local,
        origin,
        refresh,
        replica_root,
    }))
}

impl Failover {
    pub(super) fn new(
        upstream: Arc<Upstream>,
        dispatcher: StandbyDispatcher,
        local: Vec<Value>,
        origin: String,
    ) -> Result<Self> {
        let config = &upstream.config;
        let binding = Binding {
            home: config.home_id.clone(),
            route: config.db_id.clone(),
            origin,
            account: config
                .account_id
                .clone()
                .ok_or_else(|| Error::engine("node account binding missing"))?,
            endpoint: upstream.endpoint.to_string(),
        };
        // Validate the authenticated head transport's origin/route binding before
        // starting the listener. HTTP is allowed only for loopback. The HTTP
        // seam sends to the separately pinned node endpoint, retaining prefixes.
        AuthorityActTransport::new(
            &upstream.endpoint.origin().ascii_serialization(),
            &config.db_id,
            &binding.origin,
            "validation-only",
        )?;
        let (file, persisted) = StateFile::open(&config.socket_directory, binding)?;
        let probe_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| Error::engine("cannot build node probe client"))?;
        let discovery_upstream = Upstream {
            config: upstream.config.clone(),
            endpoint: upstream.endpoint.clone(),
            client: probe_client.clone(),
            // Discovery and head probes never renew; the renewal loop keeps
            // `credential_file` fresh and they re-read it on every use.
            oauth: None,
        };
        Ok(Self {
            upstream,
            discovery_upstream,
            dispatcher,
            local,
            state: Mutex::new(State {
                persisted,
                health: Health::Reachable,
                persistence_failed: false,
                health_epoch: 0,
                revision_unsupported: false,
            }),
            file,
            probe_lock: Mutex::new(()),
            probe_needed: tokio::sync::Notify::new(),
            probe_client,
            refresh_hints: None,
            gate: None,
        })
    }
    pub(super) fn with_gate(mut self, gate: Option<Arc<WriteGate>>) -> Self {
        self.gate = gate;
        self
    }
    pub(super) fn with_refresh_hints(mut self, hints: Option<RefreshHints>) -> Self {
        self.refresh_hints = hints;
        self
    }

    fn hint_refresh(&self, cause: RefreshCause) {
        if let Some(hints) = &self.refresh_hints {
            hints.request(cause);
        }
    }

    fn persist(&self, state: &mut State) -> bool {
        let ok = self.file.save(&state.persisted).is_ok();
        state.persistence_failed = !ok;
        if !ok {
            state.persisted.floor.unresolved = true;
        }
        ok
    }
    pub(super) async fn monitor(self: Arc<Self>) {
        self.probe().await;
        self.refresh_discovery().await;
        let mut timer = tokio::time::interval(Duration::from_secs(30));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        timer.tick().await;
        loop {
            tokio::select! {
                _ = timer.tick() => {},
                _ = self.probe_needed.notified() => {},
            }
            self.probe().await;
        }
    }
    async fn probe(&self) {
        self.probe_observed().await;
    }

    /// Whether hosted is confirmed unreachable, for deciding to hold a write.
    ///
    /// A single failed forward already marks `health` unreachable, which is
    /// right for reads. Holding a write is a bigger step, so it needs a second,
    /// independent failure: a fresh head probe, started after the failed
    /// forward, that also cannot reach hosted. Only a transport or gateway
    /// failure counts. A refused credential, a malformed answer or an
    /// unreadable interchange revision means hosted answered, so none of them
    /// confirms an outage.
    pub(super) async fn confirm_down(&self) -> bool {
        self.probe_observed().await == Health::Unreachable
    }

    /// Run one head probe, update health as the monitor always has, and say
    /// what this probe itself saw (independent of the health epoch).
    async fn probe_observed(&self) -> Health {
        let _serial = self.probe_lock.lock().await;
        let (pending, binding, epoch) = {
            let s = self.state.lock().await;
            (
                s.persisted.floor.pending,
                s.persisted.binding.clone(),
                s.health_epoch,
            )
        };
        let classification = Arc::new(std::sync::Mutex::new(Health::ProtocolFailed));
        let result = async {
            let token = read_guarded_credential(&self.upstream.config.credential_file, "node")
                .inspect_err(|_| {
                    *classification.lock().expect("probe classification") = Health::AuthRefused;
                })?;
            let client = Arc::new(ProbeHttp {
                client: self.probe_client.clone(),
                endpoint: self.upstream.endpoint.clone(),
                classification: classification.clone(),
            });
            let transport = AuthorityActTransport::with_client(
                &self.upstream.endpoint.origin().ascii_serialization(),
                &binding.route,
                &binding.origin,
                std::str::from_utf8(&token).expect("guarded UTF-8"),
                client,
            )?;
            transport.head().await
        }
        .await;
        let mut state = self.state.lock().await;
        match result {
            Ok(head) => {
                if state.health_epoch == epoch {
                    if state.health != Health::Reachable {
                        self.hint_refresh(RefreshCause::NetworkRecovery);
                    }
                    state.health = Health::Reachable;
                    // Hosted answers: held writes can go.
                    if let Some(gate) = &self.gate {
                        gate.wake_queue();
                    }
                }
                // A compatible validated head clears the sticky revision flag.
                state.revision_unsupported = false;
                state
                    .persisted
                    .floor
                    .observe(pending, head.head().head_act());
                self.persist(&mut state);
                Health::Reachable
            }
            Err(error) => {
                let observed = if crate::standby::is_revision_unsupported(&error) {
                    Health::RevisionUnsupported
                } else {
                    *classification.lock().expect("probe classification")
                };
                if state.health_epoch == epoch {
                    state.health = observed;
                    if observed == Health::RevisionUnsupported {
                        state.revision_unsupported = true;
                    }
                }
                observed
            }
        }
    }
    async fn refresh_discovery(&self) {
        let message = json!({"jsonrpc":"2.0","id":"node-discovery","method":"tools/list","params":{"_meta":probe_meta()}});
        let reply = self
            .discovery_upstream
            .send(&message.to_string(), &message, None, message.get("id"))
            .await;
        if let Some(result) = reply
            .as_deref()
            .and_then(|r| serde_json::from_str::<Value>(r).ok())
            .and_then(|r| r.get("result").cloned())
            .filter(|r| r["tools"].is_array())
        {
            let mut state = self.state.lock().await;
            state
                .persisted
                .discovery
                .entry(crate::mcp::PROTOCOL_VERSION.into())
                .or_default()
                .tools = Some(result);
            self.persist(&mut state);
        }
        self.refresh_catalogue(crate::mcp::PROTOCOL_VERSION, None)
            .await;
    }
    async fn refresh_catalogue(&self, protocol: &str, meta: Option<&Value>) {
        let mut rows = Vec::new();
        loop {
            let mut message = json!({"jsonrpc":"2.0","id":"node-catalogue","method":"tools/call","params":{"name":"sql_read","arguments":{"operation":"query_sql","arguments":{"sql":format!("SELECT * FROM catalog_operations ORDER BY executor, operation LIMIT 1000 OFFSET {}", rows.len())},"format":"json"}}});
            if let Some(meta) = meta {
                message["params"]["_meta"] = meta.clone();
            } else if protocol == crate::mcp::PROTOCOL_VERSION {
                message["params"]["_meta"] = probe_meta();
            }
            let reply = self
                .discovery_upstream
                .send(
                    &message.to_string(),
                    &message,
                    Some(protocol),
                    message.get("id"),
                )
                .await;
            let Some(reply) = reply.and_then(|r| serde_json::from_str::<Value>(&r).ok()) else {
                return;
            };
            if reply.pointer("/result/isError") == Some(&Value::Bool(true))
                || reply
                    .pointer("/result/resultType")
                    .is_some_and(|v| v != "complete")
            {
                return;
            }
            let Some(page) = reply
                .pointer("/result/structuredContent/rows")
                .and_then(Value::as_array)
            else {
                return;
            };
            if page.iter().any(|r| {
                ["executor", "operation", "contract_digest"]
                    .iter()
                    .any(|key| r.get(key).and_then(Value::as_str).is_none())
            }) {
                return;
            }
            rows.extend(page.iter().cloned());
            if rows.len() > 10000 {
                return;
            }
            if page.len() < 1000 {
                break;
            }
        }
        let mut state = self.state.lock().await;
        state
            .persisted
            .discovery
            .entry(protocol.into())
            .or_default()
            .operations = rows;
        self.persist(&mut state);
    }
    fn local_row(&self, executor: &str, operation: &str) -> Option<&Value> {
        self.local
            .iter()
            .find(|r| r["executor"] == executor && r["operation"] == operation)
    }
    fn supported(&self, discovery: Option<&Discovery>, executor: &str, operation: &str) -> bool {
        let Some(local) = self.local_row(executor, operation) else {
            return false;
        };
        if executor == "bootstrap"
            || local["access"] != "read"
            || local["offline_advertised"] != true
            || operation.starts_with("manage_account_config.")
        {
            return false;
        }
        match discovery {
            Some(cache) => cache.operations.iter().any(|r| {
                r["executor"] == executor
                    && r["operation"] == operation
                    && r["access"] == "read"
                    && r["contract_digest"] == local["contract_digest"]
            }),
            // Explicit cold-start exception: use the standby's own direct shape.
            None => true,
        }
    }
    pub(super) async fn route(
        self: &Arc<Self>,
        body: &str,
        mut message: Value,
        revision: Option<&str>,
        direct: &std::sync::atomic::AtomicBool,
        caller: &Caller,
    ) -> Option<String> {
        // Resolve the constraint before any forwarding, floor mutation or
        // write gate. The ordinary outage path owns all local read policy.
        let local = match local_route(&message) {
            Ok(local) => local,
            Err(reason) => return route_refusal(&message, reason),
        };
        let protocol = message
            .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .and_then(Value::as_str)
            .or(revision)
            .unwrap_or(crate::mcp::PROTOCOL_VERSION)
            .to_owned();
        let (health, revision_unsupported) = {
            let state = self.state.lock().await;
            (state.health, state.revision_unsupported)
        };
        let target = target(&message);
        if target
            .as_ref()
            .is_some_and(|(executor, _, _)| executor == "standby_status")
        {
            let response = self.dispatcher.handle_message(message).await;
            return response.map(|r| {
                let mut value = r;
                bind_status_account(&mut value, self.upstream.config.account_id.as_deref());
                if revision_unsupported {
                    add_text(
                        &mut value,
                        "Hosted uses a newer interchange revision this node cannot read; local copy is stale. Upgrade the node to resume following.",
                    );
                    annotate_revision_status(&mut value);
                }
                value.to_string()
            });
        }
        // A manual route constraint cannot bypass a known authentication
        // refusal. Status remains inspectable above; data cannot use the
        // standby path while the current health is AuthRefused.
        if local && health == Health::AuthRefused {
            return frame_error(
                message.get("id"),
                "Hosted authentication refused; local data request was not sent",
                json!({"outcome":"not_sent","reason":"auth_refused"}),
            );
        }
        if local {
            return self.offline(message, &protocol, direct).await;
        }
        // Reads use offline routing while hosted is marked unreachable. A
        // write the node may hold, and a keyed repeat of one it already holds,
        // still go through the gate: otherwise only the first write of an
        // outage would be held, and its keyed repeat could not get its pending
        // answer. When health is already Unreachable, a fresh failed probe
        // lets the gate hold before forwarding. Otherwise it needs a failed
        // forward and a failed probe; the stale health flag alone cannot hold.
        if health.offline() {
            let may_hold = self.gate.is_some()
                && target
                    .as_ref()
                    .is_some_and(|(executor, operation, envelope)| {
                        hold::is_holdable(
                            executor,
                            operation,
                            envelope.get("arguments").unwrap_or(&Value::Null),
                        )
                    });
            if !may_hold {
                return self.offline(message, &protocol, direct).await;
            }
        }
        let original = message.clone();
        if direct.load(std::sync::atomic::Ordering::Acquire) {
            wrap_direct(&mut message);
        }
        let adapted_body = if original == message {
            body.to_owned()
        } else {
            message.to_string()
        };
        let mutation = target.as_ref().is_some_and(|(executor, operation, _)| {
            if executor == "bootstrap" || executor == "describe_operation" {
                return false;
            }
            self.local_row(executor, operation)
                .is_none_or(|r| r["access"] != "read")
        });
        if mutation {
            let mut state = self.state.lock().await;
            state.persisted.floor.begin_write();
            if !self.persist(&mut state) {
                state.persisted.floor.finish_write(false);
                return frame_error(
                    message.get("id"),
                    "Cannot persist own-write floor; nothing was sent",
                    json!({"outcome":"not_sent"}),
                );
            }
        }
        let sent = match (&self.gate, mutation) {
            // Boxed to keep this large future out of `route`'s own frame.
            (Some(gate), true) => {
                Box::pin(gate.forward(
                    &self.upstream,
                    &gate::WriteRequest {
                        body: &adapted_body,
                        message: &message,
                        revision,
                        caller,
                        outage: Some(&**self),
                        // Failover-routed caller traffic may be held; only
                        // the session saver opts out (S3).
                        no_hold: false,
                    },
                    true,
                ))
                .await
            }
            _ => {
                self.upstream
                    .send_classified(&adapted_body, &message, revision, message.get("id"))
                    .await
            }
        };
        if mutation {
            let may_commit = may_have_committed(sent.reply.as_deref());
            let mut state = self.state.lock().await;
            state.persisted.floor.finish_write(may_commit);
            self.persist(&mut state);
            if may_commit {
                self.hint_refresh(RefreshCause::AfterAdmittedWrite);
            }
        }
        if let Some(failure) = sent.failure {
            let mut state = self.state.lock().await;
            state.health = failure;
            state.health_epoch += 1;
        }
        let read = target.as_ref().is_some_and(|(e, o, _)| {
            e != "bootstrap" && self.local_row(e, o).is_some_and(|r| r["access"] == "read")
        });
        if sent.failure == Some(Health::Unreachable)
            && (read
                || message["method"] == "tools/list"
                || message["method"] == "initialize"
                || message["method"] == "server/discover")
        {
            let reply = self.offline(message, &protocol, direct).await;
            self.probe_needed.notify_one();
            return reply;
        }
        if mutation || sent.failure.is_some() {
            self.probe_needed.notify_one();
        }
        if message["method"] == "tools/list" && sent.failure.is_none() {
            if let Some(result) = sent
                .reply
                .as_deref()
                .and_then(|r| serde_json::from_str::<Value>(r).ok())
                .and_then(|r| r.get("result").cloned())
                .filter(|r| r["tools"].is_array())
            {
                let mut state = self.state.lock().await;
                state
                    .persisted
                    .discovery
                    .entry(protocol.clone())
                    .or_default()
                    .tools = Some(result);
                self.persist(&mut state);
                drop(state);
                self.refresh_catalogue(&protocol, message.pointer("/params/_meta"))
                    .await;
            }
        }
        sent.reply
    }
    async fn offline(
        &self,
        mut message: Value,
        protocol: &str,
        direct: &std::sync::atomic::AtomicBool,
    ) -> Option<String> {
        let (cache, health) = {
            let state = self.state.lock().await;
            (
                state.persisted.discovery.get(protocol).cloned(),
                state.health,
            )
        };
        if message["method"] == "tools/list" {
            if let Some(tools) = cache.as_ref().and_then(|c| c.tools.as_ref()) {
                return rpc_result(message.get("id"), tools.clone());
            }
            direct.store(true, std::sync::atomic::Ordering::Release);
            return self
                .dispatcher
                .handle_message(message)
                .await
                .map(|r| r.to_string());
        }
        if message["method"] == "initialize" || message["method"] == "server/discover" {
            direct.store(
                cache.as_ref().and_then(|c| c.tools.as_ref()).is_none(),
                std::sync::atomic::Ordering::Release,
            );
            let mut reply = self.dispatcher.handle_message(message).await?;
            if let Some(tools) = cache.as_ref().and_then(|c| c.tools.as_ref()) {
                if reply["result"]["tools"].is_array() {
                    reply["result"]["tools"] = tools["tools"].clone();
                }
            }
            return Some(reply.to_string());
        }
        let Some((executor, operation, envelope)) = target(&message) else {
            return unavailable(&message, "unknown", "unknown", false);
        };
        if executor == "bootstrap" {
            let response = self.dispatcher.handle_outage_bootstrap(message).await?;
            return self
                .offline_response(response, health, &executor, &operation)
                .await;
        }
        let (supported_executor, supported_operation) = if executor == "describe_operation" {
            (
                envelope["executor"].as_str().unwrap_or(""),
                envelope["operation"].as_str().unwrap_or(""),
            )
        } else {
            (executor.as_str(), operation.as_str())
        };
        let discovery = cache
            .as_ref()
            .filter(|c| c.tools.is_some() || !c.operations.is_empty());
        if !self.supported(discovery, supported_executor, supported_operation) {
            let mutation = self
                .local_row(&executor, &operation)
                .is_some_and(|r| r["access"] == "mutation");
            return unavailable(&message, &executor, &operation, mutation);
        }
        if message.pointer("/params/name") == Some(&json!("call_executor")) {
            message["params"]["name"] = json!(executor);
            message["params"]["arguments"] = envelope;
        }
        let supported_rows = self
            .local
            .iter()
            .filter(|r| {
                self.supported(
                    discovery,
                    r["executor"].as_str().unwrap_or(""),
                    r["operation"].as_str().unwrap_or(""),
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        let snapshot = serde_json::from_value::<Vec<crate::query::principal::CatalogOperationRow>>(
            json!(supported_rows),
        )
        .ok()?;
        let response = crate::mcp::executor_prototype::with_standby_catalogue(
            Arc::new(snapshot),
            self.dispatcher.handle_message(message),
        )
        .await?;
        self.offline_response(response, health, &executor, &operation)
            .await
    }

    /// Apply the same own-write and protocol disclosure to every outage read,
    /// including the bounded bootstrap orientation.
    async fn offline_response(
        &self,
        mut response: Value,
        health: Health,
        executor: &str,
        operation: &str,
    ) -> Option<String> {
        if health == Health::ProtocolFailed {
            add_text(
                &mut response,
                "Hosted MCP protocol failed; this answer is from the local standby.",
            );
        }
        // The sticky flag, not the transient health: a later outage must
        // not drop the revision incompatibility from local answers.
        let revision_unsupported = self.state.lock().await.revision_unsupported;
        if revision_unsupported {
            add_text(
                &mut response,
                "Hosted uses a newer interchange revision this node cannot read; this local answer is stale. Upgrade the node to resume following.",
            );
            annotate_revision_status(&mut response);
        }
        if response.pointer("/result/isError") == Some(&Value::Bool(true)) {
            // Preserve genuine status-only and read-only engine refusals.
            return Some(response.to_string());
        }
        if executor == "describe_operation" || (executor == "sql_read" && operation == "query_sql")
        {
            add_text(&mut response, "Availability: served locally; catalog_operations describes only the supported offline surface. Hosted may advertise additional operations.");
        }
        // Include writes that completed while this read was executing. A floor
        // captured before dispatch could miss an acknowledgement racing it.
        let (floor, persistence_failed) = {
            let state = self.state.lock().await;
            (state.persisted.floor.clone(), state.persistence_failed)
        };
        let serving = response
            .pointer("/result/structuredContent/standby_context/serving_head_act")
            .and_then(Value::as_i64);
        if let Some(label) = floor.label(serving) {
            add_text(&mut response, &label);
        }
        if persistence_failed {
            add_text(
                &mut response,
                "Own-write floor persistence failed; the retained floor is unresolved.",
            );
        }
        Some(response.to_string())
    }
}

impl gate::Outage for Failover {
    fn known_unreachable(&self) -> gate::Ready<'_, bool> {
        Box::pin(async { self.state.lock().await.health == Health::Unreachable })
    }

    fn contract_digest<'a>(
        &'a self,
        executor: &'a str,
        operation: &'a str,
        protocol: Option<&'a str>,
    ) -> gate::Ready<'a, Option<String>> {
        Box::pin(async move {
            self.state
                .lock()
                .await
                .persisted
                .discovery
                .get(protocol.unwrap_or(crate::mcp::PROTOCOL_VERSION))?
                .operations
                .iter()
                .find(|row| {
                    row["executor"] == executor
                        && row["operation"] == operation
                        && row["access"] == "mutation"
                })?
                .get("contract_digest")?
                .as_str()
                .map(str::to_owned)
        })
    }

    fn confirm_down(&self) -> gate::Ready<'_, bool> {
        Box::pin(Failover::confirm_down(self))
    }

    /// A queue send is a write like any other: it is recorded in the own-write
    /// floor before it goes out, and counted after if it may have committed.
    fn before_send(&self) -> gate::Ready<'_, bool> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            state.persisted.floor.begin_write();
            if self.persist(&mut state) {
                true
            } else {
                state.persisted.floor.finish_write(false);
                false
            }
        })
    }

    fn after_send(&self, may_commit: bool) -> gate::Ready<'_, ()> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            state.persisted.floor.finish_write(may_commit);
            self.persist(&mut state);
            drop(state);
            if may_commit {
                self.hint_refresh(RefreshCause::AfterAdmittedWrite);
            }
            self.probe_needed.notify_one();
        })
    }
}

pub(super) fn probe_meta() -> Value {
    json!({"io.modelcontextprotocol/protocolVersion":crate::mcp::PROTOCOL_VERSION,"io.modelcontextprotocol/clientInfo":{"name":"native-node","version":crate::engine_version_string()},"io.modelcontextprotocol/clientCapabilities":{}})
}
fn rpc_result(id: Option<&Value>, result: Value) -> Option<String> {
    id.map(|id| json!({"jsonrpc":"2.0","id":id,"result":result}).to_string())
}
pub(super) fn target(message: &Value) -> Option<(String, String, Value)> {
    if message["method"] != "tools/call" {
        return None;
    }
    let executor = message.pointer("/params/name")?.as_str()?;
    let arguments = message
        .pointer("/params/arguments")
        .cloned()
        .unwrap_or(json!({}));
    let (executor, arguments) = if executor == "call_executor" {
        crate::mcp::executor_prototype::unwrap_envelope(&arguments).ok()?
    } else {
        (executor.into(), arguments)
    };
    let operation = arguments["operation"].as_str().unwrap_or("").to_string();
    Some((executor, operation, arguments))
}
fn wrap_direct(message: &mut Value) {
    if message["method"] != "tools/call" {
        return;
    }
    let Some(name) = message
        .pointer("/params/name")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return;
    };
    if [
        "bootstrap",
        "describe_operation",
        "call_executor",
        "standby_status",
    ]
    .contains(&name.as_str())
    {
        return;
    }
    if let Some(envelope) = message
        .pointer_mut("/params/arguments")
        .and_then(Value::as_object_mut)
    {
        envelope.insert("executor".into(), json!(name));
        message["params"]["name"] = json!("call_executor");
    }
}
fn unavailable(message: &Value, executor: &str, operation: &str, mutation: bool) -> Option<String> {
    frame_error(
        message.get("id"),
        match (local_route(message) == Ok(true), mutation) {
            (true, true) => "Local route is read-only; nothing saved",
            (true, false) => "Operation unavailable on local route",
            (false, true) => "Hosted unreachable; nothing saved",
            (false, false) => "Operation unavailable offline",
        },
        json!({"outcome":if mutation {"not_sent"} else {"unavailable_offline"},"executor":executor,"operation":operation}),
    )
}
/// Project only the configured canonical account, never an OAuth credential.
fn bind_status_account(response: &mut Value, account: Option<&str>) {
    if response.pointer("/result/isError") == Some(&json!(true)) {
        return;
    }
    if let Some(status) = response.pointer_mut("/result/structuredContent") {
        status["account_id"] = json!(account);
        if let Some(account) = account {
            add_text(response, &format!("Bound account_id: {account}"));
        }
    }
}

fn may_have_committed(reply: Option<&str>) -> bool {
    let Some(reply) = reply.and_then(|r| serde_json::from_str::<Value>(r).ok()) else {
        return true;
    };
    // A write the node is holding has not reached hosted, unless an earlier
    // attempt of it was in flight.
    if reply.pointer("/result/structuredContent/outcome") == Some(&json!("accepted_pending")) {
        return reply
            .pointer("/result/structuredContent/may_already_be_applied")
            .and_then(Value::as_bool)
            .unwrap_or(true);
    }
    let outcome = reply
        .pointer("/error/data/outcome")
        .or_else(|| reply.pointer("/result/structuredContent/outcome"))
        .and_then(Value::as_str);
    !matches!(outcome, Some("not_sent" | "refused"))
}
fn add_text(response: &mut Value, text: &str) {
    if let Some(result) = response.get_mut("result").and_then(Value::as_object_mut) {
        if let Some(content) = result
            .entry("content")
            .or_insert_with(|| json!([]))
            .as_array_mut()
        {
            content.push(json!({"type":"text","text":text}));
        }
    }
}

/// Machine-readable revision-compatibility attachment for local answers.
/// Structured readers must not infer freshness from age fields alone while
/// following is paused: `local_reads_stale` carries the staleness and
/// `degraded_reasons` the cause, while every age field keeps its actual
/// value. All strings are static; nothing here reflects hosted content.
fn annotate_revision_status(response: &mut Value) {
    const NEXT_STEP: &str = "Upgrade the node software to a build that reads the hosted interchange revision, then resume following.";
    if let Some(structured) = response
        .pointer_mut("/result/structuredContent")
        .and_then(Value::as_object_mut)
    {
        structured.insert(
            "node_health".into(),
            json!({
                "state": "revision_unsupported",
                "local_reads_stale": true,
                "next_step": NEXT_STEP,
            }),
        );
        if let Some(reasons) = structured
            .get_mut("degraded_reasons")
            .and_then(Value::as_array_mut)
        {
            if !reasons
                .iter()
                .any(|reason| reason == "revision_unsupported")
            {
                reasons.push(json!("revision_unsupported"));
            }
        }
        if let Some(degraded) = structured.get_mut("degraded") {
            if degraded.is_boolean() {
                *degraded = json!(true);
            }
        }
    }
}

struct ProbeHttp {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    classification: Arc<std::sync::Mutex<Health>>,
}
impl AuthorityActHttpClient for ProbeHttp {
    fn call(&self, _endpoint: String, bearer: String, body: Value) -> AuthorityCallFuture {
        let client = self.client.clone();
        let endpoint = self.endpoint.clone();
        let classification = self.classification.clone();
        Box::pin(async move {
            let mut response = client
                .post(endpoint)
                .bearer_auth(bearer)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .json(&body)
                .send()
                .await
                .map_err(|_| {
                    *classification.lock().expect("probe classification") = Health::Unreachable;
                    Error::engine("node probe transport failed")
                })?;
            let status = response.status().as_u16();
            if matches!(status, 401 | 403) {
                *classification.lock().expect("probe classification") = Health::AuthRefused;
                return Err(Error::auth("node probe credential refused"));
            }
            if matches!(status, 502..=504) {
                *classification.lock().expect("probe classification") = Health::Unreachable;
                return Err(Error::engine("node probe gateway failed"));
            }
            if !response.status().is_success() {
                return Err(Error::engine("node probe HTTP protocol failure"));
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| {
                *classification.lock().expect("probe classification") = Health::Unreachable;
                Error::engine("node probe reply lost")
            })? {
                if bytes.len().saturating_add(chunk.len()) > 2 * 1024 * 1024 {
                    return Err(Error::engine("node probe response too large"));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        })
    }
}

#[cfg(test)]
mod tests;
