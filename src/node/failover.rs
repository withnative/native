//! Failover policy and owner-only persisted discovery / own-write state.
#[cfg(feature = "v2-kernel-probe")]
mod working_append;
use super::*;
use crate::mcp::executor_prototype::NodeHoldingContract;
use crate::mcp::standby_stdio::{
    StandbyDispatcher, StandbyLocalDispatcher, StandbySessionConfig, StandbyStdioSession,
    StandbySupervisor,
};
use crate::mcp::{ExperimentalExecutors, ExposureProfile, McpSurfaceMode};
use crate::standby::delta_transport::{
    AuthorityActHttpClient, AuthorityActTransport, AuthorityCallFuture, SelectedCallFuture,
    SelectedResponse,
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
    /// The word `node_status` reports for this health.
    fn as_str(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::Unreachable => "unreachable",
            Self::AuthRefused => "auth_refused",
            Self::ProtocolFailed => "protocol_failed",
            Self::RevisionUnsupported => "revision_unsupported",
        }
    }

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
    /// Last-known authenticated evidence; canonical replay revalidates it.
    /// Bound by Persisted.binding, this protocol key, and the checked principal.
    #[serde(default)]
    holding_contracts: Vec<CachedHoldingContract>,
    #[serde(default)]
    holding_catalog_credential: Option<[u8; 32]>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
struct CachedHoldingContract {
    credential_digest: [u8; 32],
    contract: NodeHoldingContract,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Floor {
    act: Option<i64>,
    pending: u64,
    unresolved: bool,
    /// The hosted act lineage `act` was last anchored in (see
    /// [`act_lineage`]); `None` for a floor persisted before lineage was
    /// tracked. Act numbers are only comparable within one lineage.
    #[serde(default)]
    lineage: Option<String>,
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
    /// Raise the floor to at least `act` (a hosted write receipt). Monotonic:
    /// never lowers it, and never touches `unresolved`; only the head probe
    /// resolves that.
    fn raise(&mut self, act: i64) {
        if act > 0 {
            self.act = Some(self.act.map_or(act, |old| old.max(act)));
        }
    }
    /// Fold in a validated hosted head observed by a probe that started when
    /// `pending` was `started_at`. Within one act lineage this is monotonic: a
    /// lower head never lowers the floor.
    ///
    /// Across known lineages act numbers are not comparable. The v1 to kernel-v2
    /// cutover kept the same route and origin but renumbered acts, so a v1
    /// floor (68739 on the VM node) stayed above every v2 head (about 66400)
    /// and silently disabled online local reads. A restore or re-cut inside
    /// v2 replaces the genesis and would do the same. When the head's lineage
    /// differs from the floor's, re-anchor to the observed head. The legacy
    /// follow-head policy also re-anchors a pre-lineage floor above a v2 head;
    /// default routing retains that unknown lineage as requiring migration. Only when
    /// quiescent: every node write bumps `pending`, and barrier captures share
    /// the probe lock, so no acknowledgement newer than this head is dropped.
    /// Otherwise keep the floor and let a later quiescent probe re-anchor.
    fn observe(&mut self, started_at: u64, act: i64, lineage: String) {
        self.observe_head(started_at, act, lineage, true);
    }

    /// In local-by-default mode, a head probe settles uncertain writes and
    /// re-anchors foreign lineages, but unrelated hosted traffic does not
    /// raise the acknowledged-write floor. Existing persisted floors remain
    /// conservative; this never lowers one within its lineage.
    fn observe_head(&mut self, started_at: u64, act: i64, lineage: String, follow_head: bool) {
        // Unknown migrated numbering is opaque in the default policy. A
        // reachable head cannot prove which history produced that old floor.
        if !follow_head && self.act.is_some() && self.lineage.is_none() {
            return;
        }
        let quiescent = started_at == self.pending && self.active_writes == 0;
        let foreign = match (self.act, self.lineage.as_deref()) {
            (None, _) => false,
            (Some(_), Some(known)) => known != lineage,
            (Some(old), None) => follow_head && lineage.starts_with("v2:") && old > act,
        };
        if foreign {
            if !quiescent {
                return;
            }
            tracing::warn!(
                target: "native_ce::node",
                floor_act = self.act,
                hosted_head_act = act,
                "own-write floor came from another hosted act lineage; re-anchored to the hosted head"
            );
            self.act = Some(act);
        } else {
            if quiescent && self.act.is_some_and(|old| old > act) {
                // Same lineage, yet above hosted's own head with nothing in
                // flight. Kept (a head may lag), but never silent: online local
                // reads stay on hosted until hosted passes this floor.
                tracing::warn!(
                    target: "native_ce::node",
                    floor_act = self.act,
                    hosted_head_act = act,
                    "own-write floor is above the observed hosted head"
                );
            }
            if follow_head || self.unresolved {
                self.act = Some(self.act.map_or(act, |old| old.max(act)));
            }
        }
        self.lineage = Some(lineage);
        if quiescent {
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
// Bump before changing saved-state semantics or shape: older builds must not
// reinterpret or erase new custody/floor/account evidence. Unversioned is v1.
const STATE_VERSION: u64 = 1;
pub(super) fn runtime_declaration() -> Value {
    json!({"family":"node_failover_state","version":STATE_VERSION,
        "source":"src/node/failover.rs#StateFile",
        "decoder_compiled":true,"fresh_writer":"production","retained_entry_rewrite":true,
        "required_features":["mcp-executor-prototype"],
        "missing_version":"legacy_default_1","unknown_fields":"ignored_not_round_tripped_on_rewrite",
        "unknown_format":"future_payload_preserved_opaque_saving_disabled_not_usable_cached_authority",
        "continuation_conditions":["owned_bounded_file","exact_binding","floor_and_account_evidence"]})
}

fn legacy_state_version() -> u64 {
    1
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Persisted {
    #[serde(default = "legacy_state_version")]
    version: u64,
    #[serde(default)]
    kernel_v2: bool,
    binding: Binding,
    floor: Floor,
    /// Following signal only, never a read admission fence.
    #[serde(default)]
    observed_hosted_head: Option<(i64, String)>,
    discovery: BTreeMap<String, Discovery>,
    /// Confirmed account mismatch, scoped by this file's origin/account binding.
    /// Only a conclusive match clears it, including after a restart or renewal.
    #[serde(default)]
    account_mismatch: bool,
    /// A conclusive account check for these exact credential bytes. The state
    /// file already binds account, route, origin and endpoint. Never a bearer.
    #[serde(default)]
    verified_custody_credential: Option<[u8; 32]>,
}
struct State {
    persisted: Persisted,
    /// Diagnostic only: unknown after restart until this process probes.
    observed_hosted_head_at: Option<String>,
    health: Health,
    persistence_failed: bool,
    /// Opaque newer state cannot establish whether an account mismatch was
    /// recorded. This is doubt, not a confirmed account switch.
    account_unconfirmed: bool,
    health_epoch: u64,
    /// A probe (or a failed forward) has settled `health` at least once. Before
    /// that, `Reachable` is only the optimistic starting value.
    checked: bool,
    /// Sticky revision-compatibility flag, separate from connectivity.
    /// Set when a validated probe shows hosted authoring an unreadable
    /// interchange revision; retained through later outages and cleared
    /// only by a compatible validated head. Memory-only: it re-derives on
    /// every probe after a restart.
    revision_unsupported: bool,
    /// A readable hosted head belongs to an incompatible engine family.
    head_engine_mismatch: bool,
    discovery_retry: BTreeMap<String, (u32, std::time::Instant)>,
    /// Digest of the credential last checked, when, and whether the check
    /// was conclusive. An inconclusive check is retried at most every 5 min.
    account_check: Option<([u8; 32], std::time::Instant, bool)>,
    /// Principal checks are numbered when they start; a result is applied
    /// only if no later-started check has already applied, so two checks of
    /// the same credential finishing out of order cannot let an older
    /// observation overwrite a newer one.
    account_check_started: u64,
    account_check_applied: u64,
}

/// No secret is stored here. Supported state checks binding in filename and
/// payload; opaque versions inherit no cache/floor/account evidence and require
/// fresh hosted account confirmation. Replaced bindings cannot inherit custody.
struct StateFile {
    path: PathBuf,
    newer_version: Option<u64>,
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
        let mut file = Self {
            path: directory.join(format!("{key}.json")),
            newer_version: None,
        };
        let empty = |binding| Persisted {
            version: STATE_VERSION,
            kernel_v2: false,
            binding,
            floor: Floor::default(),
            observed_hosted_head: None,
            discovery: BTreeMap::new(),
            account_mismatch: false,
            verified_custody_credential: None,
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
                // Parse only the stable envelope first. A future payload may have
                // changed types or removed fields; it is opaque to this build.
                #[derive(Deserialize)]
                struct Header {
                    #[serde(default = "legacy_state_version")]
                    version: u64,
                }
                let header: Header = serde_json::from_slice(&bytes)?;
                if header.version > STATE_VERSION {
                    file.newer_version = Some(header.version);
                    let mut state = empty(binding);
                    state.version = header.version;
                    state.floor.unresolved = true;
                    return Ok((file, state));
                }
                if header.version == 0 {
                    return Err(Error::engine("invalid node state version 0"));
                }
                let mut state: Persisted = serde_json::from_slice(&bytes)?;
                if state.binding != binding {
                    return Err(Error::engine("node state binding mismatch"));
                }
                // Any supported migration is saved under this build's format,
                // including when a later version reads a legacy file.
                state.version = STATE_VERSION;
                state
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => empty(binding),
            Err(e) => return Err(e.into()),
        };
        Ok((file, state))
    }
    fn save(&self, state: &Persisted) -> Result<()> {
        if self.newer_version.is_some() {
            return Err(Error::engine(
                "node state was saved by a newer build; file preserved, saving disabled",
            ));
        }
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

/// What one node connection's own writes require of a read it makes. The node
/// keeps one persisted, node-wide floor (every acknowledged write, from every
/// session), but only the session that wrote has a read-your-writes claim on
/// it: other agents' writes are ordinary staleness, disclosed rather than
/// refused (Richard, 10 Nov 2026; Native task 3f3120c). Memory-only and
/// dropped with the connection: a reconnecting client keeps the persisted
/// node-wide floor as disclosure but no longer gets its own-write guarantee.
#[derive(Clone, Copy, Debug, Default)]
struct SessionWrites {
    /// Highest receipt act this session's writes were acknowledged at.
    act: i64,
    /// Writes of this session currently in flight.
    active: u32,
    /// A write of this session may have committed without a receipt act.
    uncertain: bool,
}

/// The connection whose write is in flight.
type SessionWrite = Option<u64>;

/// The own-write requirement a particular read carries.
#[derive(Clone, Copy, Debug)]
struct OwnWrites {
    /// The copy must hold at least this act (0 = no requirement).
    act: i64,
    /// A write that may have committed has no known act yet.
    unresolved: bool,
}

/// Who is reading, and how strictly the route is pinned.
#[derive(Clone, Copy, Debug)]
struct ReadCtx {
    session: Option<u64>,
    /// An explicit `native/route: local` is a caller-owned constraint: it is
    /// never answered by hosted.
    local: bool,
}

/// Position and act numbering of the exact dispatcher that answers a read.
struct ReadPosition {
    act: i64,
    lineage: Option<String>,
}

/// How a default-routed read was settled.
enum DefaultRead {
    /// Not a default-local read (a write, or nothing to decide): carry on.
    Pass,
    /// Answer (or error) for the caller.
    Reply(String),
    /// Hosted can answer this read: forward it exactly as with the option off.
    /// The reason is disclosed on the hosted answer.
    Forward(&'static str),
}

/// How a local answer stands against what this node knows hosted holds.
/// Pure data, computed under the state lock so the disclosure matches the
/// final fence.
#[derive(Clone, Debug, Default)]
struct Standing {
    serving_head_act: Option<i64>,
    /// Highest comparable act known to be on hosted (own-write floor or the
    /// last probed head).
    known_hosted_head_act: Option<i64>,
    last_successful_hosted_check_at: Option<String>,
    /// `None` when the copy's act numbering cannot be compared with the
    /// floor's (unknown or different lineage).
    behind_known_write: Option<bool>,
    own_write_floor_act: Option<i64>,
    own_write_unresolved: bool,
    /// Why hosted could not simply answer instead.
    fallback_reason: Option<&'static str>,
}

#[cfg(test)]
struct DefaultReadPause {
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

pub(super) struct Failover {
    upstream: Arc<Upstream>,
    discovery_upstream: Upstream,
    dispatcher: StandbyDispatcher,
    // Baseline access classification for hosted forwarding only. Local-read
    // admission uses the catalogue pinned to the current serving generation.
    local: Vec<Value>,
    state: Mutex<State>,
    /// Per-connection own-write records; see [`SessionWrites`].
    sessions: std::sync::Mutex<BTreeMap<u64, SessionWrites>>,
    file: StateFile,
    probe_lock: Mutex<()>,
    holding_refresh: Mutex<()>,
    holding_refresh_cursor: std::sync::atomic::AtomicUsize,
    probe_needed: tokio::sync::Notify,
    probe_client: reqwest::Client,
    refresh_hints: Option<RefreshHints>,
    /// Present only when the hosted change stream is configured.
    events: Option<Arc<super::hosted_events::EventStatus>>,
    gate: Option<Arc<WriteGate>>,
    pub(super) changes: Arc<super::changes::Broker>,
    changes_sample: Mutex<()>,
    pending_fork: Arc<super::pending_fork::PendingFork>,
    #[cfg(feature = "v2-kernel-probe")]
    working: working_append::WorkingCopies,
    #[cfg(test)]
    read_pause: std::sync::Mutex<Option<Arc<DefaultReadPause>>>,
    #[cfg(test)]
    final_read_pause: std::sync::Mutex<Option<Arc<DefaultReadPause>>>,
    #[cfg(test)]
    offline_pin_pause: std::sync::Mutex<Option<Arc<DefaultReadPause>>>,
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

pub(super) fn start_standby(
    config: &NodeConfig,
    install_key: Option<crate::node_credential::InstallKey>,
) -> Result<Option<NodeStandby>> {
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
    #[cfg(test)]
    if let Some(identity) = TEST_CONSUMER_IDENTITY.lock().unwrap().clone() {
        return start_standby_with_identity(config, identity, install_key);
    }
    start_standby_with_identity(config, observe_installed_consumer_identity()?, install_key)
}

/// Test seam: a local build is stamped `dev` and cannot serve a standby
/// generation, so a test that runs the whole `serve` path names the consumer
/// identity to use. Only `serve` with a standby config consults it.
#[cfg(test)]
pub(crate) static TEST_CONSUMER_IDENTITY: std::sync::Mutex<
    Option<crate::standby_snapshot::ObservedInstalledConsumerIdentity>,
> = std::sync::Mutex::new(None);

fn start_standby_with_identity(
    config: &NodeConfig,
    observed: crate::standby_snapshot::ObservedInstalledConsumerIdentity,
    install_key: Option<crate::node_credential::InstallKey>,
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
            install_key,
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
    /// How the node last found hosted, for `node_status`: the connectivity
    /// health (reachable / unreachable / auth_refused / protocol_failed /
    /// revision_unsupported) and the sticky interchange-revision flag. Last
    /// observed, not a fresh probe.
    pub(super) async fn hosted_summary(&self) -> Value {
        let state = self.state.lock().await;
        let mut summary = json!({
            "health": state.health.as_str(),
            // False until the first probe (or failed forward) has settled it:
            // `reachable` before that is only the starting assumption.
            "checked": state.checked,
            "revision_unsupported": state.revision_unsupported,
            "head_engine_mismatch":state.head_engine_mismatch,
            "saved_state": {
                "newer_version": self.file.newer_version,
                "supported_version": STATE_VERSION,
                "account_unconfirmed": state.account_unconfirmed,
                "message": self.file.newer_version.map(|_| {
                    let mut message = "Saved state is from a newer build. The file is preserved; writes use an in-memory floor and default online reads use hosted. After a restart, local reads stay unavailable until hosted can be reached once to confirm the account; upgrading to a compatible node removes this restriction.".to_owned();
                    if state.account_unconfirmed {
                        message.push_str(" The shim socket binding is unavailable until confirmation.");
                    }
                    message
                }),
            },
            "local_read_migration_required":self.upstream.config.local_reads_by_default && state.persisted.floor.act.is_some() && state.persisted.floor.lineage.is_none(),
        });
        if let Some(hints) = &self.refresh_hints {
            summary["replication_compatibility"] = hints.compatibility().status();
        }
        // Informational only; never an input to `health`.
        if let Some(events) = &self.events {
            summary["events"] = events.summary();
        }
        summary
    }

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
            compatibility: upstream.compatibility.clone(),
            config: upstream.config.clone(),
            endpoint: upstream.endpoint.clone(),
            client: probe_client.clone(),
            // Discovery and head probes never renew; the renewal loop keeps
            // `credential_file` fresh and they re-read it on every use.
            oauth: None,
            install_key: upstream.install_key.clone(),
        };
        let changes = super::changes::Broker::new(
            persisted.binding.account.clone(),
            persisted.binding.origin.clone(),
            super::changes::Floor {
                act: persisted.floor.act,
                pending: persisted.floor.pending,
                unresolved: persisted.floor.unresolved,
                persistence_failed: file.newer_version.is_some(),
            },
        );
        let head_engine_mismatch = upstream.config.local_reads_by_default
            && persisted
                .observed_hosted_head
                .as_ref()
                .is_some_and(|(_, lineage)| lineage.starts_with("v1:"));
        Ok(Self {
            changes,
            changes_sample: Mutex::new(()),
            pending_fork: Default::default(),
            #[cfg(feature = "v2-kernel-probe")]
            working: Default::default(),
            #[cfg(test)]
            read_pause: Default::default(),
            #[cfg(test)]
            final_read_pause: Default::default(),
            #[cfg(test)]
            offline_pin_pause: Default::default(),
            upstream,
            discovery_upstream,
            dispatcher,
            local,
            state: Mutex::new(State {
                persisted,
                observed_hosted_head_at: None,
                health: Health::Reachable,
                persistence_failed: file.newer_version.is_some(),
                account_unconfirmed: file.newer_version.is_some(),
                health_epoch: 0,
                checked: false,
                revision_unsupported: false,
                head_engine_mismatch,
                discovery_retry: Default::default(),
                account_check: None,
                account_check_started: 0,
                account_check_applied: 0,
            }),
            sessions: Default::default(),
            file,
            probe_lock: Mutex::new(()),
            holding_refresh: Mutex::new(()),
            holding_refresh_cursor: Default::default(),
            probe_needed: tokio::sync::Notify::new(),
            probe_client,
            refresh_hints: None,
            events: None,
            gate: None,
        })
    }
    pub(super) async fn shutdown_pending_fork(&self) -> Result<()> {
        self.pending_fork.shutdown().await
    }
    pub(super) fn with_gate(mut self, gate: Option<Arc<WriteGate>>) -> Self {
        if let Some(gate) = &gate {
            super::pending_fork::cleanup_stale_area(&self.upstream.config.socket_directory);
            gate.set_kernel_v2_upstream(
                self.state.get_mut().persisted.kernel_v2
                    || self.upstream.config.local_reads_by_default,
            );
            if self.upstream.config.pending_fork_reads {
                gate.enable_pending_fork();
                self.pending_fork.start(
                    self.dispatcher.clone(),
                    self.upstream.config.clone(),
                    gate.clone(),
                    self.refresh_hints.as_ref(),
                );
            } else {
                gate.disable_pending_fork();
            }
        }
        self.gate = gate;
        self
    }
    pub(super) fn with_refresh_hints(mut self, hints: Option<RefreshHints>) -> Self {
        #[cfg(feature = "v2-kernel-probe")]
        if self.upstream.config.working_note_appends {
            if let Some(hints) = &hints {
                self.working.observe(hints);
            }
        }
        self.refresh_hints = hints;
        self
    }

    pub(super) fn with_events(
        mut self,
        events: Option<Arc<super::hosted_events::EventStatus>>,
    ) -> Self {
        self.events = events;
        self
    }

    fn hint_refresh(&self, cause: RefreshCause) {
        if let Some(hints) = &self.refresh_hints {
            hints.request(cause);
        }
    }

    /// Capture only the active reader's bounded response context: small serving
    /// sidecars/header and audit standing, never full status, hashing or scans.
    /// No serving I/O occurs under the failover state lock.
    pub(super) async fn sample_changes(&self) {
        let _serial = self.changes_sample.lock().await;
        let context = self.dispatcher.serving_context();
        let authority = {
            let state = self.state.lock().await;
            super::changes::Authority {
                hosted: if state.checked {
                    state.health.as_str()
                } else {
                    "not_checked"
                }
                .into(),
                checked: state.checked,
                revision_unsupported: state.revision_unsupported,
            }
        };
        let serving = context
            .map(|context| super::changes::Serving {
                generation_id: context.serving_generation_id,
                applied_act: context.serving_head_act,
                freshness: match context.freshness.state {
                    crate::standby::StandbyFreshnessState::Fresh => "fresh",
                    crate::standby::StandbyFreshnessState::BeyondRpo => "beyond_rpo",
                    crate::standby::StandbyFreshnessState::Unavailable => "unavailable",
                }
                .into(),
                degraded_reasons: context
                    .degraded_reasons
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            })
            .unwrap_or_default();
        self.changes.observe(serving, authority);
    }

    /// One observer per node, with no reader I/O while there are no followers.
    /// This is a bounded initial cadence, not a UI latency promise.
    pub(super) async fn observe_changes(self: Arc<Self>) {
        let mut timer = tokio::time::interval(Duration::from_secs(1));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            timer.tick().await;
            if self.changes.has_followers() {
                self.sample_changes().await;
            }
        }
    }

    /// Admit floor-dependent sends. True means durable for supported files,
    /// or deliberately memory-only for opaque newer state; barriers must check
    /// the latter separately before claiming floor_persisted.
    fn persist(&self, state: &mut State) -> bool {
        let ok = self.file.save(&state.persisted).is_ok();
        state.persistence_failed = !ok;
        if !ok {
            state.persisted.floor.unresolved = true;
        }
        // Compact, non-reentrant publication AFTER the persistence outcome.
        // Broker publication performs no I/O and never acquires this state lock.
        // It does not capture serving state or advance the applied act.
        self.changes.note_floor(super::changes::Floor {
            act: state.persisted.floor.act,
            pending: state.persisted.floor.pending,
            unresolved: state.persisted.floor.unresolved,
            persistence_failed: state.persistence_failed,
        });
        // A newer file durably records that this build cannot know the floor.
        // Keep receipts in memory and force reads to hosted. Restart restores
        // the same conservative state, so sending does not require rewriting it.
        ok || self.file.newer_version.is_some()
    }
    pub(super) async fn monitor(self: Arc<Self>) {
        self.probe().await;
        self.refresh_discovery().await;
        for protocol in self.discovery_protocols() {
            self.refresh_holding_contracts(protocol).await;
        }
        let mut timer = tokio::time::interval(Duration::from_secs(30));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        timer.tick().await;
        loop {
            tokio::select! {
                _ = timer.tick() => {},
                _ = self.probe_needed.notified() => {},
            }
            self.probe().await;
            if self.upstream.config.local_reads_by_default {
                self.refresh_needed_discovery().await;
            }
            for protocol in self.discovery_protocols() {
                self.refresh_holding_contracts(protocol).await;
            }
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
        let checked_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let result = async {
            let token = read_guarded_credential(&self.upstream.config.credential_file, "node")
                .inspect_err(|_| {
                    *classification.lock().expect("probe classification") = Health::AuthRefused;
                })?;
            let client = Arc::new(ProbeHttp {
                compatibility: self.upstream.compatibility.clone(),
                client: self.probe_client.clone(),
                endpoint: self.upstream.endpoint.clone(),
                classification: classification.clone(),
                install_key: self.upstream.install_key.clone(),
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
        state.checked = true;
        let local_kernel_v2 = self.dispatcher.serving_kernel_v2();
        if local_kernel_v2 && !state.persisted.kernel_v2 {
            state.persisted.kernel_v2 = true;
            if let Some(gate) = &self.gate {
                gate.set_kernel_v2_upstream(true);
            }
            self.persist(&mut state);
        }
        let observed_health = match result {
            Ok(head) => {
                state.persisted.kernel_v2 = head.head().is_kernel_v2()
                    || local_kernel_v2
                    || self.upstream.config.local_reads_by_default;
                if let Some(gate) = &self.gate {
                    gate.set_kernel_v2_upstream(state.persisted.kernel_v2);
                }
                if state.health_epoch == epoch {
                    if state.health != Health::Reachable {
                        self.hint_refresh(RefreshCause::NetworkRecovery);
                        state.discovery_retry.clear();
                    }
                    state.health = Health::Reachable;
                    // Hosted answers: held writes can go.
                    if let Some(gate) = &self.gate {
                        gate.wake_queue();
                    }
                }
                // A compatible validated head clears the sticky revision flag.
                state.revision_unsupported = false;
                state.head_engine_mismatch =
                    self.upstream.config.local_reads_by_default && !head.head().is_kernel_v2();
                state.persisted.observed_hosted_head =
                    Some((head.head().head_act(), act_lineage(head.head())));
                state.observed_hosted_head_at = Some(checked_at);
                if self.upstream.config.local_reads_by_default {
                    state.persisted.floor.observe_head(
                        pending,
                        head.head().head_act(),
                        act_lineage(head.head()),
                        false,
                    );
                } else {
                    state.persisted.floor.observe(
                        pending,
                        head.head().head_act(),
                        act_lineage(head.head()),
                    );
                }
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
        };
        drop(state);
        // Hosted could not be asked while it is down; any other answer can be.
        if observed_health != Health::Unreachable {
            self.verify_account_if_credential_changed().await;
        }
        #[cfg(feature = "v2-kernel-probe")]
        if observed_health == Health::Reachable
            && self.upstream.install_key.is_some()
            && self.upstream.config.working_note_appends
        {
            self.verify_enrolled_queue().await;
        }
        observed_health
    }

    #[cfg(feature = "v2-kernel-probe")]
    async fn verify_enrolled_queue(&self) {
        let Some(gate) = &self.gate else { return };
        let Some(scope) = gate::Outage::custody_binding(self).await else {
            return;
        };
        let Some(credential) = gate::Outage::custody_credential(self).await else {
            return;
        };
        let Ok(scoped) = gate.scoped_v2_gate(&scope) else {
            return;
        };
        if scoped
            .verify_enrolled_custody(&self.upstream, credential)
            .await
            .is_ok()
        {
            gate.wake_queue();
        }
    }

    /// When the credential is new to this node (first probe, `native login`,
    /// OAuth rotation), ask hosted who it now authenticates and compare with
    /// the account the node is bound to. Cheap: one `current_principal()`
    /// query per credential change, retried only every 5 minutes while
    /// inconclusive. A confirmed different account, or opaque newer saved
    /// evidence awaiting confirmation, keeps the local account boundary.
    async fn verify_account_if_credential_changed(&self) {
        self.verify_account_against(self.upstream.config.account_id.as_deref())
            .await;
    }

    async fn verify_account_against(&self, bound: Option<&str>) {
        let Ok(token) = read_guarded_credential(&self.upstream.config.credential_file, "node")
        else {
            return;
        };
        let digest: [u8; 32] = Sha256::digest(&*token).into();
        let started = {
            let mut state = self.state.lock().await;
            if let Some((seen, at, conclusive)) = state.account_check {
                // While a mismatch is established, an inconclusive check must
                // not delay the next attempt: confirming the bound account is
                // the only way back to local reads, so retry on every probe.
                let backoff = !state.persisted.account_mismatch
                    && !state.account_unconfirmed
                    && at.elapsed() < Duration::from_secs(300);
                if seen == digest && (conclusive || backoff) {
                    if state.persistence_failed {
                        self.persist(&mut state);
                    }
                    return;
                }
            }
            state.account_check_started += 1;
            state.account_check_started
        };
        let Ok(bearer) = std::str::from_utf8(&token) else {
            return;
        };
        let origin = self.upstream.config.hosted_base_url.trim_end_matches('/');
        let principal = crate::native_cli::setup::canonical_account_for_node(
            &self.probe_client,
            origin,
            &self.upstream.config.db_id,
            bearer,
            &self.upstream.compatibility,
            self.upstream.install_key.as_ref(),
        )
        .await
        .ok();
        let verdict = account_verdict(bound, principal.as_deref());
        let mut state = self.state.lock().await;
        // Login or renewal may have replaced the credential during the HTTP
        // request. Evidence about the old credential cannot govern this one.
        if self.credential_digest() != Some(digest) {
            return;
        }
        // Only conclusive verdicts advance the watermark: a newer inconclusive
        // check finishing first must not discard older conclusive evidence
        // about the same credential, and never overwrites a conclusive record.
        if started <= state.account_check_applied {
            return;
        }
        let Some(same) = verdict else {
            let conclusive_here =
                matches!(state.account_check, Some((seen, _, true)) if seen == digest);
            if !conclusive_here {
                state.account_check = Some((digest, std::time::Instant::now(), false));
            }
            return;
        };
        state.account_unconfirmed = false;
        state.account_check_applied = started;
        state.account_check = Some((digest, std::time::Instant::now(), true));
        // Renewal can rotate a mismatched account's token during an outage.
        // Doubt must never erase that established boundary. Only conclusive
        // confirmation of the bound account permits local data again.
        let changed = state.persisted.account_mismatch != !same;
        state.persisted.account_mismatch = !same;
        let witness = same.then_some(digest);
        let witness_changed = state.persisted.verified_custody_credential != witness;
        state.persisted.verified_custody_credential = witness;
        if changed || witness_changed || state.persistence_failed {
            self.persist(&mut state);
        }
        if verdict == Some(false) {
            tracing::warn!(
                target: "native_ce::node",
                "the signed-in account differs from the account this node is bound to; local reads are refused until it is signed in again"
            );
        }
        drop(state);
        #[cfg(feature = "v2-kernel-probe")]
        if verdict == Some(false) {
            self.working.close_account_switch();
        }
    }

    fn credential_digest(&self) -> Option<[u8; 32]> {
        read_guarded_credential(&self.upstream.config.credential_file, "node")
            .ok()
            .map(|token| Sha256::digest(&*token).into())
    }

    /// A confirmed mismatch survives token replacement and unreadability.
    /// Otherwise only confirmation of the current credential is trusted;
    /// replacement, unreadability and inconclusive checks are doubt.
    /// This is a bounded local credential read, never a hosted request.
    fn current_account_verdict(&self, state: &State) -> Option<bool> {
        if state.persisted.account_mismatch {
            return Some(false);
        }
        let digest = self.credential_digest()?;
        let (checked, _, conclusive) = state.account_check?;
        (checked == digest && conclusive).then_some(!state.persisted.account_mismatch)
    }
    fn discovery_needs_refresh(&self, cache: Option<&Discovery>) -> bool {
        let Some(cache) = cache else { return true };
        cache.tools.is_none()
            || cache.operations.is_empty()
            || self
                .dispatcher
                .local_dispatcher()
                .is_some_and(|dispatcher| {
                    dispatcher.operation_rows().iter().any(|local| {
                        local["access"] == "read"
                            && local["offline_advertised"] == true
                            && !cache.operations.iter().any(|hosted| {
                                hosted["executor"] == local["executor"]
                                    && hosted["operation"] == local["operation"]
                                    && hosted["contract_digest"] == local["contract_digest"]
                            })
                    })
                })
    }

    async fn refresh_needed_discovery(&self) {
        for protocol in self.discovery_protocols() {
            let due = {
                let state = self.state.lock().await;
                state.health == Health::Reachable
                    && self.discovery_needs_refresh(state.persisted.discovery.get(protocol))
                    && state
                        .discovery_retry
                        .get(protocol)
                        .is_none_or(|(_, due)| std::time::Instant::now() >= *due)
            };
            if due {
                self.refresh_discovery_for(protocol).await;
            }
        }
    }
    async fn refresh_discovery(&self) {
        for protocol in self.discovery_protocols() {
            if self.upstream.config.local_reads_by_default
                && self.state.lock().await.health == Health::AuthRefused
            {
                break;
            }
            self.refresh_discovery_for(protocol).await;
        }
    }
    fn discovery_protocols(&self) -> Vec<&'static str> {
        let mut protocols = vec![crate::mcp::PROTOCOL_VERSION];
        if self.upstream.config.local_reads_by_default {
            protocols.extend(crate::mcp::LEGACY_SUPPORTED_PROTOCOL_VERSIONS);
        }
        protocols
    }
    async fn discovery_request(&self, message: &Value, protocol: &str) -> Option<String> {
        self.discovery_report(message, protocol).await.reply
    }
    async fn discovery_report(&self, message: &Value, protocol: &str) -> SendReport {
        let epoch = self.state.lock().await.health_epoch;
        let report = self
            .discovery_upstream
            .send_classified(
                &message.to_string(),
                message,
                Some(protocol),
                message.get("id"),
            )
            .await;
        if self.upstream.config.local_reads_by_default
            && report.failure == Some(Health::AuthRefused)
        {
            let mut state = self.state.lock().await;
            if state.health_epoch == epoch {
                state.health = Health::AuthRefused;
                state.health_epoch += 1;
                state.checked = true;
            }
        }
        // A failed or unsupported protocol is not a global connectivity or
        // credential verdict. Only a classified authentication refusal is.
        report
    }
    async fn refresh_discovery_for(&self, protocol: &str) {
        let mut message =
            json!({"jsonrpc":"2.0","id":"node-discovery","method":"tools/list","params":{}});
        if protocol == crate::mcp::PROTOCOL_VERSION {
            message["params"]["_meta"] = probe_meta();
        }
        let reply = self.discovery_request(&message, protocol).await;
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
                .entry(protocol.into())
                .or_default()
                .tools = Some(result);
            self.persist(&mut state);
        }
        self.refresh_catalogue(protocol, None).await;
        let mut state = self.state.lock().await;
        let failed = self.discovery_needs_refresh(state.persisted.discovery.get(protocol));
        let attempts = if failed {
            state
                .discovery_retry
                .get(protocol)
                .map_or(1, |(n, _)| n.saturating_add(1))
        } else {
            0
        };
        let seconds = 30u64.saturating_mul(1u64 << attempts.min(5)).min(900);
        state.discovery_retry.insert(
            protocol.into(),
            (
                attempts,
                std::time::Instant::now() + Duration::from_secs(seconds),
            ),
        );
    }
    async fn refresh_catalogue(&self, protocol: &str, meta: Option<&Value>) {
        let mut rows = Vec::new();
        let mut custody_answered = true;
        let catalog_credential = self.credential_digest();
        loop {
            let mut message = json!({"jsonrpc":"2.0","id":"node-catalogue","method":"tools/call","params":{"name":"sql_read","arguments":{"operation":"query_sql","arguments":{"sql":format!("SELECT * FROM catalog_operations ORDER BY executor, operation LIMIT 1000 OFFSET {}", rows.len())},"format":"json"}}});
            if let Some(meta) = meta {
                message["params"]["_meta"] = meta.clone();
            } else if protocol == crate::mcp::PROTOCOL_VERSION {
                message["params"]["_meta"] = probe_meta();
            }
            let report = self.discovery_report(&message, protocol).await;
            custody_answered &= report.failure.is_none()
                && report.attempt == Attempt::Answered
                && report
                    .status
                    .is_some_and(|status| (200..300).contains(&status));
            let Some(reply) = report
                .reply
                .and_then(|r| serde_json::from_str::<Value>(&r).ok())
            else {
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
        // Collecting six descriptions is monitor work, never part of the
        // tools/list response path that also refreshes this catalog.
        let mut holding_contracts: Vec<CachedHoldingContract> = Vec::new();
        let mut state = self.state.lock().await;
        let verified_credential =
            if custody_answered && catalog_credential == self.credential_digest() {
                catalog_credential
            } else {
                None
            };
        let discovery = state
            .persisted
            .discovery
            .entry(protocol.into())
            .or_default();
        discovery.holding_catalog_credential = verified_credential.or_else(|| {
            (discovery.operations == rows)
                .then_some(discovery.holding_catalog_credential)
                .flatten()
        });
        // A failed description refresh is not evidence of incompatibility.
        // Preserve last-known evidence only while the newly observed catalog
        // still agrees on digest, routing and all separately declared policy.
        for prior in &discovery.holding_contracts {
            let description = &prior.contract.description;
            let replaced = holding_contracts.iter().any(|fresh| {
                fresh.contract.description["executor"] == description["executor"]
                    && fresh.contract.description["operation"] == description["operation"]
            });
            if !replaced
                && rows
                    .iter()
                    .filter(|row| {
                        row["executor"] == description["executor"]
                            && row["operation"] == description["operation"]
                    })
                    .any(|row| {
                        NodeHoldingContract::from_hosted(description.clone(), row).as_ref()
                            == Some(&prior.contract)
                    })
            {
                holding_contracts.push(prior.clone());
            }
        }
        discovery.operations = rows;
        discovery.holding_contracts = holding_contracts;
        self.persist(&mut state);
    }

    /// Background-only, nonoverlapping and bounded as a whole. A stalled
    /// description cannot hold up tools/list or grow one timeout per operation.
    fn holding_discovery_operations(&self) -> Vec<(&'static str, &'static str)> {
        let mut operations = hold::HOLDABLE.to_vec();
        // Evidence acquisition is not ordinary holding eligibility. Only the
        // explicit working pilot can admit these additional native families.
        if self.upstream.config.working_note_appends {
            operations.extend([
                ("records_lifecycle", "archive_record"),
                ("records_write", "manage_links.remove"),
            ]);
        }
        operations
    }

    async fn refresh_holding_contracts(&self, protocol: &str) {
        let Ok(_turn) = self.holding_refresh.try_lock() else {
            return;
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let repair_catalog = {
            let state = self.state.lock().await;
            if state.health != Health::Reachable
                || self.current_account_verdict(&state) != Some(true)
            {
                return;
            }
            state
                .persisted
                .discovery
                .get(protocol)
                .is_none_or(|discovery| {
                    discovery.holding_catalog_credential != self.credential_digest()
                })
        };
        if repair_catalog
            && tokio::time::timeout_at(deadline, self.refresh_catalogue(protocol, None))
                .await
                .is_err()
        {
            return;
        }
        let rows = {
            let state = self.state.lock().await;
            if state.health != Health::Reachable
                || self.current_account_verdict(&state) != Some(true)
            {
                return;
            }
            let Some(discovery) = state.persisted.discovery.get(protocol) else {
                return;
            };
            // The same bearer must have fetched these rows and now be
            // confirmed for the bound principal before descriptions are joined.
            if discovery.holding_catalog_credential != self.credential_digest() {
                return;
            }
            // Probe wakeups also follow writes. A complete, coherent cache
            // needs no repeated description reads on those wakeups.
            let missing = discovery.operations.iter().any(|row| {
                let (Some(executor), Some(operation)) =
                    (row["executor"].as_str(), row["operation"].as_str())
                else {
                    return false;
                };
                self.holding_discovery_operations()
                    .contains(&(executor, operation))
                    && !discovery.holding_contracts.iter().any(|cached| {
                        NodeHoldingContract::from_hosted(cached.contract.description.clone(), row)
                            .as_ref()
                            == Some(&cached.contract)
                    })
            });
            if !missing {
                return;
            }
            discovery.operations.clone()
        };
        let fresh = self
            .discover_holding_contracts(protocol, &rows, deadline)
            .await;
        let mut state = self.state.lock().await;
        if self.current_account_verdict(&state) != Some(true)
            || fresh
                .iter()
                .any(|contract| Some(contract.credential_digest) != self.credential_digest())
        {
            return;
        }
        let Some(discovery) = state.persisted.discovery.get_mut(protocol) else {
            return;
        };
        if discovery.operations != rows {
            return;
        }
        for contract in fresh {
            discovery.holding_contracts.retain(|old| {
                old.contract.description["executor"] != contract.contract.description["executor"]
                    || old.contract.description["operation"]
                        != contract.contract.description["operation"]
            });
            discovery.holding_contracts.push(contract);
        }
        self.persist(&mut state);
    }

    /// Bounded to the existing held set, outside the write path. A token swap
    /// or an unconfirmed principal never creates durable compatibility evidence.
    async fn discover_holding_contracts(
        &self,
        protocol: &str,
        rows: &[Value],
        deadline: tokio::time::Instant,
    ) -> Vec<CachedHoldingContract> {
        let Some(credential_digest) = self.credential_digest() else {
            return vec![];
        };
        if self.current_account_verdict(&*self.state.lock().await) != Some(true) {
            return vec![];
        }
        let cached = self
            .state
            .lock()
            .await
            .persisted
            .discovery
            .get(protocol)
            .map(|discovery| discovery.holding_contracts.clone())
            .unwrap_or_default();
        let mut contracts = Vec::new();
        // Rotate partial scans so repeated timeouts cannot starve the tail.
        let offset = self
            .holding_refresh_cursor
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let operations = self.holding_discovery_operations();
        for index in 0..operations.len() {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let (executor, operation) = operations[(offset + index) % operations.len()];
            let Some(row) = rows
                .iter()
                .find(|row| row["executor"] == executor && row["operation"] == operation)
            else {
                continue;
            };
            if cached.iter().any(|cached| {
                NodeHoldingContract::from_hosted(cached.contract.description.clone(), row).as_ref()
                    == Some(&cached.contract)
            }) {
                continue;
            }
            let mut message = json!({"jsonrpc":"2.0", "id":"node-holding-contract", "method":"tools/call",
                "params":{"name":"describe_operation","arguments":{"executor":executor,"operation":operation}}});
            if protocol == crate::mcp::PROTOCOL_VERSION {
                message["params"]["_meta"] = probe_meta();
            }
            let attempt_deadline =
                deadline.min(tokio::time::Instant::now() + Duration::from_secs(1));
            let Ok(report) = tokio::time::timeout_at(
                attempt_deadline,
                self.discovery_report(&message, protocol),
            )
            .await
            else {
                continue;
            };
            let description = (report.failure.is_none()
                && report.attempt == Attempt::Answered
                && report
                    .status
                    .is_some_and(|status| (200..300).contains(&status)))
            .then_some(report.reply)
            .flatten()
            .and_then(|reply| serde_json::from_str::<Value>(&reply).ok())
            .filter(|reply| {
                reply.pointer("/result/isError") != Some(&Value::Bool(true))
                    && reply
                        .pointer("/result/resultType")
                        .is_none_or(|kind| kind == "complete")
            })
            .and_then(|reply| reply.pointer("/result/structuredContent").cloned());
            if let Some(contract) = description
                .and_then(|description| NodeHoldingContract::from_hosted(description, row))
            {
                contracts.push(CachedHoldingContract {
                    credential_digest,
                    contract,
                });
            }
        }
        let state = self.state.lock().await;
        if self.credential_digest() != Some(credential_digest)
            || self.current_account_verdict(&state) != Some(true)
            || state.health == Health::AuthRefused
        {
            return vec![];
        }
        contracts
    }
    fn local_row(&self, executor: &str, operation: &str) -> Option<&Value> {
        self.local
            .iter()
            .find(|r| r["executor"] == executor && r["operation"] == operation)
    }
    fn supported(&self, discovery: Option<&Discovery>, executor: &str, operation: &str) -> bool {
        let Some(dispatcher) = self.dispatcher.local_dispatcher() else {
            return false;
        };
        Self::supported_in(dispatcher.operation_rows(), discovery, executor, operation)
    }
    fn supported_in(
        rows: &[Value],
        discovery: Option<&Discovery>,
        executor: &str,
        operation: &str,
    ) -> bool {
        let Some(local) = rows
            .iter()
            .find(|r| r["executor"] == executor && r["operation"] == operation)
        else {
            return false;
        };
        if executor == "bootstrap"
            || local["access"] != "read"
            || local["offline_advertised"] != true
            || operation.starts_with("manage_account_config.")
            || operation.starts_with("manage_saved_tabs.")
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
    /// An ordered cut observation, not HTTP settlement or reader advancement.
    /// The lock is acquired before issuing a NEW request; periodic probes are
    /// never reused. Existing unresolved writes remain unresolved.
    pub(super) async fn capture_read_barrier(
        &self,
        expected: &super::app_proof::Binding,
    ) -> std::result::Result<i64, &'static str> {
        let _serial = self.probe_lock.lock().await;
        if !self.upstream.config.tracks_local_reads()
            || self.app_proof_binding().await.as_ref() != Some(expected)
        {
            return Err("barrier_unavailable");
        }
        if self.file.newer_version.is_some() {
            return Err("saved_state_newer");
        }
        if self.upstream.config.local_reads_by_default {
            let state = self.state.lock().await;
            if state.persisted.floor.act.is_some() && state.persisted.floor.lineage.is_none() {
                return Err("migration_unsettled");
            }
        }
        let binding = self.state.lock().await.persisted.binding.clone();
        let token = read_guarded_credential(&self.upstream.config.credential_file, "node")
            .map_err(|_| "barrier_unavailable")?;
        let transport = AuthorityActTransport::with_client(
            &self.upstream.endpoint.origin().ascii_serialization(),
            &binding.route,
            &binding.origin,
            std::str::from_utf8(&token).map_err(|_| "barrier_unavailable")?,
            Arc::new(ProbeHttp {
                compatibility: self.upstream.compatibility.clone(),
                client: self.probe_client.clone(),
                endpoint: self.upstream.endpoint.clone(),
                classification: Arc::new(std::sync::Mutex::new(Health::ProtocolFailed)),
                install_key: self.upstream.install_key.clone(),
            }),
        )
        .map_err(|_| "barrier_unavailable")?;
        let head = transport.head().await.map_err(|_| "barrier_unavailable")?;
        let act = head.head().head_act();
        if act < 0 {
            return Err("barrier_unavailable");
        }
        let mut state = self.state.lock().await;
        if self.upstream.config.local_reads_by_default {
            let lineage = act_lineage(head.head());
            if state.persisted.floor.act.is_some()
                && state.persisted.floor.lineage.as_deref() != Some(lineage.as_str())
            {
                return Err("barrier_unavailable");
            }
            state.persisted.floor.lineage = Some(lineage);
        }
        state.persisted.floor.act = Some(state.persisted.floor.act.map_or(act, |old| old.max(act)));
        let persisted = self.persist(&mut state);
        drop(state);
        self.hint_refresh(RefreshCause::AfterAdmittedWrite);
        if !persisted {
            return Err("barrier_persistence_failed");
        }
        Ok(act)
    }
    /// Constrains a socket to the already-admitted owner and immutable served route.
    /// Reuses the existing account verdict; does not grant freshness or bypass refusal.
    pub(super) async fn connection_scope(&self) -> Option<super::connection_binding::Scope> {
        let state = self.state.lock().await;
        let binding = &state.persisted.binding;
        if state.account_unconfirmed
            || self.current_account_verdict(&state) == Some(false)
            || binding.account.is_empty()
            || binding.origin.is_empty()
            || self.upstream.config.account_id.as_deref() != Some(binding.account.as_str())
            || self.upstream.config.db_id != binding.route
        {
            return None;
        }
        Some(super::connection_binding::Scope {
            account_id: binding.account.clone(),
            database_id: binding.route.clone(),
            hosted_origin: self.upstream.endpoint.origin().ascii_serialization(),
        })
    }
    pub(super) async fn app_proof_binding(&self) -> Option<super::app_proof::Binding> {
        let state = self.state.lock().await;
        let b = &state.persisted.binding;
        let resource_origin = super::app_proof::resource_origin(&self.upstream.config)?;
        (!b.account.is_empty() && !b.origin.is_empty()).then(|| super::app_proof::Binding {
            account_id: b.account.clone(),
            hosted_db_id: b.route.clone(),
            origin_database_id: b.origin.clone(),
            resource_origin,
            forwarding_origin: self.upstream.endpoint.origin().ascii_serialization(),
        })
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
        let (health, revision_unsupported, checked, account_changed) = {
            let state = self.state.lock().await;
            (
                state.health,
                state.revision_unsupported,
                state.checked,
                self.current_account_verdict(&state) == Some(false),
            )
        };
        let target = target(&message);
        if target
            .as_ref()
            .is_some_and(|(executor, _, _)| executor == "standby_status")
        {
            let dispatcher = self.dispatcher.local_dispatcher();
            let response = match &dispatcher {
                Some(dispatcher) => dispatcher.handle_message(message).await,
                None => self.dispatcher.handle_message(message).await,
            };
            let (migration, head_engine_mismatch, standing) = {
                let state = self.state.lock().await;
                let serving = response
                    .as_ref()
                    .and_then(|r| {
                        r.pointer("/result/structuredContent/serving_generation/head_act")
                    })
                    .and_then(Value::as_i64);
                (
                    self.upstream.config.local_reads_by_default
                        && state.persisted.floor.act.is_some()
                        && state.persisted.floor.lineage.is_none(),
                    state.head_engine_mismatch,
                    standing_in(
                        &state,
                        serving,
                        dispatcher.as_ref().and_then(|d| d.act_lineage()).as_deref(),
                        None,
                    ),
                )
            };
            return response.map(|r| {
                let mut value = r;
                annotate_node_routing_with(&mut value, health, checked, "local_status", Some(&standing), false, None, true);
                bind_status_account(&mut value, self.upstream.config.account_id.as_deref());
                if migration || head_engine_mismatch {
                    let reason = if migration { "migration_unsettled" } else { "hosted_engine_mismatch" };
                    if let Some(status) = value.pointer_mut("/result/structuredContent").and_then(Value::as_object_mut) {
                        status.insert("node_local_read_admission".into(), json!({"state":reason,"next_safe_action":if migration {"Requires a recorded migration with provenance establishing the retained floor's history. No automatic re-anchor or state deletion."} else {"Hosted head is not kernel-v2; restore a compatible engine family before using this accepted-only v2 policy."}}));
                    }
                    add_text(&mut value, reason);
                }
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
        if local && self.state.lock().await.account_unconfirmed {
            return account_unconfirmed_refusal(&message);
        }
        #[cfg(feature = "v2-kernel-probe")]
        // Keep the working-append future out of the connection task's inline
        // layout: downstream binaries otherwise exceed rustc's query depth.
        if let Some(reply) =
            Box::pin(self.try_working_route(&message, Some(&protocol), caller)).await
        {
            return Some(reply);
        }
        // A confirmed account change is a definite boundary (not doubt): the
        // node's copy is another account's. Status stays inspectable above.
        if local && account_changed {
            return account_changed_refusal(&message);
        }
        // Hosted authentication trouble is doubt, not a definite answer: a
        // local read (explicit or default) is still served, with a disclosure
        // whose next step is to re-authenticate. Writes are unchanged.
        let mut forward_reason = None;
        if self.upstream.config.local_reads_by_default {
            match Box::pin(self.try_default_local(
                &message,
                &protocol,
                caller,
                local,
                account_changed,
            ))
            .await
            {
                DefaultRead::Reply(reply) => return Some(reply),
                DefaultRead::Forward(reason) => forward_reason = Some(reason),
                DefaultRead::Pass => {}
            }
        }
        // An explicit `native/route: local` is a caller-owned constraint, like
        // an offline read: it is SERVED, and the response's standby disclosure
        // carries the required audit's standing (`serving_audit`, and a
        // degraded reason `audit_overdue`, `audit_unaudited` or `audit_failed`)
        // for the caller to weigh. The 2N bound below gates only the
        // default-routed online path (`online_local_reads`).
        if !super::app_proof::attributed(&message)
            && self.upstream.config.pending_fork_reads
            && health != Health::AuthRefused
            && (local
                || health.offline()
                || target.as_ref().is_some_and(|(_, op, _)| op == "get_record"))
        {
            if let Some(reply) = self.try_pending_read(&message, &protocol).await {
                return Some(reply);
            }
        }
        if local {
            return self.offline(message, &protocol, direct, None).await;
        }
        if let Some(online) = self
            .upstream
            .config
            .online_local_reads
            .filter(|_| !self.upstream.config.local_reads_by_default)
        {
            if health == Health::Reachable && !revision_unsupported {
                // Boxed, like the gate call below, to keep this large future
                // out of `route`'s own frame.
                if let Some(reply) =
                    Box::pin(self.try_online_local(&message, &protocol, online.max_age_seconds))
                        .await
                {
                    return Some(reply);
                }
            }
        }
        // Automatic app traffic is online-only. Eligible fresh reads already
        // had their local opportunity above; never serve a stale fallback
        // behind an own-write floor. Explicit local routing returned earlier
        // and retains its established read-only standby contract.
        if super::app_proof::attributed(&message) && health.offline() {
            return frame_error(
                message.get("id"),
                "Hosted is unreachable; online app request was not sent",
                json!({"outcome":"not_sent","reason":"app_online_required"}),
            );
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
                return self.offline(message, &protocol, direct, None).await;
            }
        }
        if super::app_proof::attributed(&message)
            && super::app_proof::header(&self.upstream.config, &message, Some(&caller.context))
                .is_err()
        {
            return super::app_proof::refusal(&message);
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
            if executor == "bootstrap"
                || executor == "describe_operation"
                || (executor == "system_read" && operation == "ping")
            {
                return false;
            }
            self.local_row(executor, operation)
                .is_none_or(|r| r["access"] != "read")
        });
        let mut session_write = None;
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
            drop(state);
            session_write = self.session_begin_write(caller.session);
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
                        no_hold: super::app_proof::attributed(&message),
                    },
                    true,
                ))
                .await
            }
            _ => {
                self.upstream
                    .send_classified_context(
                        &adapted_body,
                        &message,
                        revision,
                        message.get("id"),
                        &caller.context,
                    )
                    .await
            }
        };
        if mutation {
            self.settle_write(sent.reply.as_deref(), session_write)
                .await;
            self.pending_fork.wake();
        }

        let read = target.as_ref().is_some_and(|(e, o, _)| {
            e != "bootstrap"
                && ((e == "system_read" && o == "ping")
                    || self.local_row(e, o).is_some_and(|r| r["access"] == "read"))
        });
        let default_read = self.upstream.config.local_reads_by_default
            && !mutation
            && (read
                || target.as_ref().is_some_and(|(executor, _, _)| {
                    matches!(executor.as_str(), "describe_operation" | "bootstrap")
                }));
        // A credential the node could not use never left the node, so no
        // failure was classified. For a default-policy read that is still
        // authentication doubt: serve the verified copy, do not return it.
        let mut sent = sent;
        if default_read
            && sent.reply_kind == super::ReplyKind::ExplicitRefusal
            && sent.failure == Some(Health::ProtocolFailed)
        {
            // An unframed 2xx is a protocol failure for transport/retry
            // purposes, but an explicit request refusal still answered this
            // read. Keep mutation classification and generic auth doubt intact.
            sent.failure = None;
        }
        if sent.update_required().is_some()
            && sent.failure != Some(Health::AuthRefused)
            && (read || default_read)
        {
            sent.failure = Some(Health::ProtocolFailed);
        }
        if sent.failure.is_none() && default_read {
            sent.failure = credential_preflight_failure(sent.reply.as_deref()).or_else(|| {
                // Read continuity is independent of a mutation's possibly-applied
                // outcome and retry classification. A reachable server can fail
                // this read, including with a correctly framed internal error.
                default_read_server_failure(&sent)
            });
        }
        if let Some(failure) = sent.failure {
            let mut state = self.state.lock().await;
            state.health = failure;
            state.health_epoch += 1;
            state.checked = true;
        }
        // A read hosted could not answer is served from the local copy with a
        // disclosure, never refused (continuity over freshness). The offline
        // path labels a metadata answer as the reduced local catalogue, so it
        // cannot masquerade as the canonical one.
        let default_read_failed = default_read && sent.failure.is_some();
        if (sent.failure == Some(Health::Unreachable)
            || default_read_failed
            || (read && sent.update_required().is_some()))
            && !super::app_proof::attributed(&message)
            && (read
                || default_read_failed
                || message["method"] == "tools/list"
                || message["method"] == "initialize"
                || message["method"] == "server/discover")
        {
            let reply = self.offline(message, &protocol, direct, None).await;
            self.probe_needed.notify_one();
            return reply.map(|reply| {
                if default_read_failed {
                    annotate_failed_hosted_read(reply, &sent)
                } else {
                    reply
                }
            });
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
                self.probe_needed.notify_one();
            }
        }
        // Hosted bootstrap is deliberately never served by the online local
        // read path. Give its orientation the same explicit write routing.
        if sent.failure.is_none()
            && target.as_ref().is_some_and(|(executor, operation, _)| {
                executor == "bootstrap" || (executor == "system_read" && operation == "ping")
            })
        {
            if let Some(mut response) = sent
                .reply
                .as_deref()
                .and_then(|reply| serde_json::from_str::<Value>(reply).ok())
            {
                annotate_node_routing(&mut response, Health::Reachable, true, "hosted", true);
                annotate_hosted_fallback(&mut response, forward_reason);
                return Some(response.to_string());
            }
        }
        if self.upstream.config.local_reads_by_default
            && sent.failure.is_none()
            && (read
                || target
                    .as_ref()
                    .is_some_and(|(executor, _, _)| executor == "describe_operation"))
        {
            if let Some(mut response) = sent
                .reply
                .as_deref()
                .and_then(|reply| serde_json::from_str::<Value>(reply).ok())
            {
                annotate_node_routing(&mut response, Health::Reachable, true, "hosted", false);
                match forward_reason {
                    Some(reason) if reason != "metadata_requires_hosted" => {
                        annotate_hosted_fallback(&mut response, Some(reason));
                    }
                    _ => add_text(
                        &mut response,
                        "This operation requires the canonical hosted catalogue.",
                    ),
                }
                return Some(response.to_string());
            }
        }
        sent.reply
    }
    async fn try_pending_read(&self, message: &Value, protocol: &str) -> Option<String> {
        if super::app_proof::attributed(message) {
            return None;
        }
        let (executor, operation, envelope) = target(message)?;
        if executor != "records_read" || !matches!(operation.as_str(), "get_record" | "search") {
            return None;
        }
        let args = envelope.get("arguments").cloned().unwrap_or(json!({}));
        if args.get("as_of").is_some()
            || args.get("include_history_summary") == Some(&json!(true))
            || args.get("include_interpretation") == Some(&json!(true))
        {
            return None;
        }
        let state = self.state.lock().await;
        if state.revision_unsupported
            || !self.supported(
                state.persisted.discovery.get(protocol),
                &executor,
                &operation,
            )
        {
            return None;
        }
        let health = state.health;
        drop(state);
        let value = self.pending_preview(&operation, args).await?;
        let text = format!(
            "{}\nPending node previews may be refused by hosted; they are not canonical receipts.",
            serde_json::to_string(&value).ok()?
        );
        let response = json!({"jsonrpc":"2.0","id":message.get("id")?,"result":{"isError":false,"structuredContent":value,"content":[{"type":"text","text":text}]}});
        self.offline_response(response, health, &executor, &operation, false)
            .await
    }

    /// A preview is speculative, but its accepted base must cover every known
    /// canonical floor, including an ordered reads/barrier capture. Unresolved
    /// pending writes remain unresolved; a preview never claims read readiness.
    async fn pending_preview(&self, operation: &str, arguments: Value) -> Option<Value> {
        let act = self.dispatcher.serving_context()?.serving_head_act?;
        {
            let state = self.state.lock().await;
            if state.persistence_failed
                || state.persisted.floor.act.is_some_and(|floor| act < floor)
            {
                return None;
            }
        }
        let value = self
            .pending_fork
            .read_or_sync(
                &self.dispatcher,
                &self.upstream.config,
                self.gate.as_ref()?,
                Some((operation, arguments)),
            )
            .await
            .ok()??;
        let act = value
            .pointer("/standby_context/serving_head_act")?
            .as_i64()?;
        let state = self.state.lock().await;
        if state.persistence_failed || state.persisted.floor.act.is_some_and(|floor| act < floor) {
            return None;
        }
        Some(value)
    }

    async fn offline(
        &self,
        message: Value,
        protocol: &str,
        direct: &std::sync::atomic::AtomicBool,
        fallback: Option<&'static str>,
    ) -> Option<String> {
        let (cache, health, account_changed) = {
            let state = self.state.lock().await;
            (
                state.persisted.discovery.get(protocol).cloned(),
                state.health,
                self.current_account_verdict(&state) == Some(false),
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
        // Opaque saved account evidence needs hosted confirmation before any
        // local account data can be served; doubt is not an account switch.
        if self.state.lock().await.account_unconfirmed {
            return account_unconfirmed_refusal(&message);
        }
        // A confirmed account change is a definite boundary: this node's copy
        // belongs to another account and is never served to this sign-in.
        if account_changed {
            return account_changed_refusal(&message);
        }
        let reply_to = json!({"id": message.get("id")});
        if executor == "bootstrap" {
            // Default policy: judge the serving copy before it answers.
            let pinned = match self.pin_default_copy(&reply_to).await {
                Ok(pinned) => pinned,
                Err(refusal) => return refusal,
            };
            #[cfg(test)]
            self.pause_offline_pin().await;
            let response = match &pinned {
                Some((copy, _)) => copy.handle_outage_bootstrap(message).await?,
                None => self.dispatcher.handle_outage_bootstrap(message).await?,
            };
            if let Some((copy, position)) = &pinned {
                if default_read_act(&copy.serving_context(), position.act).is_none() {
                    return self
                        .local_read_unavailable(&reply_to, "generation_or_integrity")
                        .await;
                }
            }
            // Boxed: keeps this large future out of `offline`'s (and `route`'s) frame.
            return Box::pin(self.offline_response_with(
                response,
                health,
                &executor,
                &operation,
                true,
                Some((fallback, pinned.map(|(_, position)| position))),
            ))
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
        // Every default-policy local answer, including a fallback after hosted
        // failed, pins its serving copy, requires it to pass the default
        // integrity checks before the query and again after it, and is
        // disclosed from the position it was read at, never the current one.
        let pinned = match self.pin_default_copy(&reply_to).await {
            Ok(pinned) => pinned,
            Err(refusal) => return refusal,
        };
        #[cfg(test)]
        self.pause_offline_pin().await;
        let response = Box::pin(self.dispatch_local_pinned(
            pinned.as_ref().map(|(copy, _)| copy),
            message,
            discovery,
            &executor,
            envelope,
        ))
        .await?;
        if let Some((copy, position)) = &pinned {
            if default_read_act(&copy.serving_context(), position.act).is_none() {
                return self
                    .local_read_unavailable(&reply_to, "generation_or_integrity")
                    .await;
            }
        }
        Box::pin(self.offline_response_with(
            response,
            health,
            &executor,
            &operation,
            true,
            Some((fallback, pinned.map(|(_, position)| position))),
        ))
        .await
    }

    /// Default policy only: pin the serving copy and return the act it is at
    /// BEFORE any query (a lower bound on what the answer holds, since a copy
    /// only advances), after requiring it to pass the default integrity checks.
    /// `Ok(None)` outside the default policy; `Err` is the explicit error
    /// (with a next step) when no trustworthy copy can be shown.
    async fn pin_default_copy(
        &self,
        reply_to: &Value,
    ) -> std::result::Result<Option<(StandbyLocalDispatcher, ReadPosition)>, Option<String>> {
        if !self.upstream.config.local_reads_by_default {
            return Ok(None);
        }
        let Some(copy) = self.dispatcher.local_dispatcher() else {
            return Err(self.local_read_unavailable(reply_to, "generation").await);
        };
        match default_read_act(&copy.serving_context(), 0) {
            Some(act) => {
                let lineage = copy.act_lineage();
                Ok(Some((copy, ReadPosition { act, lineage })))
            }
            None => Err(self
                .local_read_unavailable(reply_to, "generation_or_integrity")
                .await),
        }
    }

    #[cfg(test)]
    async fn pause_offline_pin(&self) {
        let pause = self.offline_pin_pause.lock().unwrap().clone();
        if let Some(pause) = pause {
            pause.entered.notify_one();
            pause.resume.notified().await;
        }
    }

    /// Run one supported read against the local copy and return the engine's
    /// response before any disclosure is added. The caller has already
    /// checked `supported`.
    /// Settle the own-write floor after a node-originated write: raise it
    /// from a receipt act, close the write (`finish_write`), persist, and hint
    /// a refresh if it may have committed.
    async fn settle_write(&self, reply: Option<&str>, write: SessionWrite) {
        let may_commit = may_have_committed(reply);
        let receipt = receipt_act(reply);
        let mut state = self.state.lock().await;
        if let Some(act) = receipt {
            state.persisted.floor.raise(act);
        }
        state.persisted.floor.finish_write(may_commit);
        self.persist(&mut state);
        drop(state);
        self.session_settle_write(write, receipt, may_commit);
        if may_commit {
            self.hint_refresh(RefreshCause::AfterAdmittedWrite);
        }
    }

    /// A write by `session` is about to leave the node.
    fn session_begin_write(&self, session: Option<u64>) -> SessionWrite {
        let id = session?;
        let mut sessions = self.sessions.lock().expect("session writes");
        sessions.entry(id).or_default().active += 1;
        Some(id)
    }

    /// A write by a session finished. A receipt act is the definite commit
    /// position of that write. A possible commit without one leaves the
    /// session uncertain. No receipt clears uncertainty: even a later request
    /// can replay an old receipt. Only a resolved node-wide floor can bound it.
    fn session_settle_write(&self, write: SessionWrite, receipt: Option<i64>, may_commit: bool) {
        let Some(id) = write else { return };
        let mut sessions = self.sessions.lock().expect("session writes");
        let writes = sessions.entry(id).or_default();
        writes.active = writes.active.saturating_sub(1);
        match receipt {
            Some(act) => {
                writes.act = writes.act.max(act);
            }
            None if may_commit => {
                writes.uncertain = true;
            }
            None => {}
        }
    }

    /// Drop a closed connection's own-write record.
    pub(super) fn forget_session(&self, session: u64) {
        self.sessions
            .lock()
            .expect("session writes")
            .remove(&session);
    }

    /// What the reader's own writes require. Another session's writes are
    /// ordinary staleness (disclosed, not enforced); a caller with no session
    /// identity is held to the node-wide floor.
    fn own_writes(&self, session: Option<u64>, floor: &Floor) -> OwnWrites {
        let node = OwnWrites {
            act: floor.act.unwrap_or(0),
            unresolved: floor.unresolved,
        };
        let Some(id) = session else { return node };
        let mut sessions = self.sessions.lock().expect("session writes");
        let Some(writes) = sessions.get_mut(&id) else {
            return OwnWrites {
                act: 0,
                unresolved: false,
            };
        };
        if writes.uncertain && writes.active == 0 && !floor.unresolved {
            if let Some(act) = floor.act.filter(|act| *act >= writes.act) {
                writes.act = act;
                writes.uncertain = false;
            }
        }
        if writes.active > 0 || writes.uncertain {
            // This session may have written something with no known act: only
            // the node-wide floor, once resolved, can bound it.
            OwnWrites {
                act: writes.act.max(node.act),
                unresolved: node.unresolved || floor.act.is_none() || writes.uncertain,
            }
        } else {
            OwnWrites {
                act: writes.act,
                unresolved: false,
            }
        }
    }

    async fn dispatch_local(
        &self,
        message: Value,
        discovery: Option<&Discovery>,
        executor: &str,
        envelope: Value,
    ) -> Option<Value> {
        self.dispatch_local_pinned(None, message, discovery, executor, envelope)
            .await
    }

    /// `pinned`: run against exactly this captured generation rather than the
    /// current one, so the caller's pre-read judgement (act, lineage,
    /// integrity) is about the very copy that answers.
    async fn dispatch_local_pinned(
        &self,
        pinned: Option<&StandbyLocalDispatcher>,
        mut message: Value,
        discovery: Option<&Discovery>,
        executor: &str,
        envelope: Value,
    ) -> Option<Value> {
        // Recheck admission against the same captured generation that executes
        // the call; publication may have changed since the outer route check.
        let (supported_executor, supported_operation) = if executor == "describe_operation" {
            (
                envelope["executor"].as_str()?,
                envelope["operation"].as_str()?,
            )
        } else {
            (executor, envelope["operation"].as_str()?)
        };
        let current;
        let dispatcher = match pinned {
            Some(dispatcher) => dispatcher,
            None => {
                current = self.dispatcher.local_dispatcher();
                match current.as_ref() {
                    Some(dispatcher) => dispatcher,
                    None => {
                        return unavailable(
                            &message,
                            supported_executor,
                            supported_operation,
                            false,
                        )
                        .and_then(|response| serde_json::from_str(&response).ok());
                    }
                }
            }
        };
        if !Self::supported_in(
            dispatcher.operation_rows(),
            discovery,
            supported_executor,
            supported_operation,
        ) {
            return unavailable(&message, supported_executor, supported_operation, false)
                .and_then(|response| serde_json::from_str(&response).ok());
        }
        if !super::app_proof::attributed(&message)
            && self.upstream.config.pending_fork_reads
            && executor == "records_read"
        {
            let operation = envelope["operation"].as_str().unwrap_or("");
            let args = envelope.get("arguments").cloned().unwrap_or(json!({}));
            if matches!(operation, "get_record" | "search")
                && args.get("as_of").is_none()
                && args.get("include_history_summary") != Some(&json!(true))
                && args.get("include_interpretation") != Some(&json!(true))
            {
                if let Some(value) = self.pending_preview(operation, args).await {
                    return Some(
                        json!({"jsonrpc":"2.0","id":message.get("id"),"result":{"isError":false,"structuredContent":value,"content":[{"type":"text","text":value.to_string()}]}}),
                    );
                }
            }
        }
        if message.pointer("/params/name") == Some(&json!("call_executor")) {
            message["params"]["name"] = json!(executor);
            message["params"]["arguments"] = envelope;
        }
        let supported_rows = dispatcher
            .operation_rows()
            .iter()
            .filter(|r| {
                Self::supported_in(
                    dispatcher.operation_rows(),
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
        crate::mcp::executor_prototype::with_standby_catalogue(
            Arc::new(snapshot),
            dispatcher.handle_message(message),
        )
        .await
    }

    /// Task 960f47f item D, run-key option B (Richard, 9 Nov 2026): answer
    /// `bootstrap` from the local copy whenever it is as eligible as any online
    /// local read, and issue the run key here. Hosted `open_run_as` creates the
    /// run for an unseen valid key on the first call that needs one
    /// (`set_intent`, claims, `close_run`); ordinary reads and writes do not
    /// require it. Many agents starting at once then cost hosted nothing. The
    /// key is a correlation handle, never authority: hosted refuses a key that
    /// belongs to another principal or to imported history. `None` forwards
    /// to hosted exactly as before.
    async fn try_online_local_bootstrap(
        &self,
        message: &Value,
        protocol: &str,
        max_age_seconds: u64,
        local_by_default: bool,
        ctx: ReadCtx,
    ) -> Option<DefaultRead> {
        let (cache, floor, persistence_failed, checked) = {
            let state = self.state.lock().await;
            if !local_by_default && self.current_account_verdict(&state) == Some(false) {
                return None;
            }
            (
                state.persisted.discovery.get(protocol).cloned(),
                state.persisted.floor.clone(),
                state.persistence_failed,
                state.checked,
            )
        };
        // The default policy judges own writes at the final fence, where the
        // outcome is "answer from hosted" or "disclose", never "refuse".
        if (!checked || floor.unresolved || persistence_failed) && !local_by_default {
            return None;
        }
        let floor_act = if local_by_default { 0 } else { floor.act? };
        // The hosted catalogue must be known: bootstrap advertises tools.
        cache.as_ref().filter(|c| !c.operations.is_empty())?;
        let arguments = message
            .pointer("/params/arguments")
            .cloned()
            .unwrap_or(json!({}));
        let (key, issued) = match arguments.get("run_key").and_then(Value::as_str) {
            None | Some("new") => (
                crate::runkey::mint_fresh_agent_run(&Default::default()).ok()?,
                true,
            ),
            Some(key)
                if matches!(
                    crate::runkey::validate_full(Some(key)),
                    crate::runkey::KeyOutcome::Valid(_)
                ) =>
            {
                (key.to_owned(), false)
            }
            // Agent-key sentinels and malformed keys keep hosted semantics.
            Some(_) => return None,
        };
        let wants_json = arguments.get("format").and_then(Value::as_str) == Some("json");
        // Pin one generation first; judge eligibility on exactly that copy.
        let dispatcher = self.dispatcher.local_dispatcher()?;
        let context = dispatcher.serving_context();
        let before_act = if local_by_default {
            default_read_act(&context, floor_act)?
        } else {
            pre_read_act(&context, floor_act, max_age_seconds)?
        };
        let mut local = message.clone();
        local["params"]["arguments"]["run_key"] = json!(key);
        local["params"]["arguments"]["format"] = json!("json");
        let mut response = dispatcher.handle_message(local).await?;
        if response.get("error").is_some()
            || response.pointer("/result/isError") == Some(&Value::Bool(true))
        {
            return None;
        }
        {
            let state = self.state.lock().await;
            let floor = &state.persisted.floor;
            if !local_by_default
                && (floor.unresolved
                    || state.persistence_failed
                    || floor.act.is_none_or(|act| before_act < act))
            {
                return None;
            }
        }
        let structured = response.pointer_mut("/result/structuredContent")?;
        // Serve only a complete bootstrap: the kernel-v2 engine's own answer,
        // with standing instructions resolved and an explicit readiness contract.
        // Onboarding is not a completeness signal. A reduced member copy cannot
        // claim the kernel-v2 contract, so hosted answers when reachable.
        let complete = structured.pointer("/engine/name") == Some(&json!("kernel-v2"))
            && structured.pointer("/instructions/status") == Some(&json!("ready"))
            && structured.pointer("/bootstrap_readiness/contract")
                == Some(&json!(crate::instructions::BOOTSTRAP_CONTRACT))
            && structured.pointer("/bootstrap_readiness/status") == Some(&json!("complete"));
        if !complete {
            return None;
        }
        // The standby session's runtime block says read-only/no writes, which is
        // true of the copy, not of this session: writes go to hosted (see
        // node_routing). Hosted's own bootstrap carries no such block.
        if let Some(exposure) = structured
            .get_mut("tool_exposure")
            .and_then(Value::as_object_mut)
        {
            exposure.remove("runtime");
        }
        // The local engine answers read-only: `durable` means the copy already
        // holds this caller's run for the key.
        let known = structured.pointer("/run/durable") == Some(&Value::Bool(true));
        if !issued && !known && !local_by_default {
            // A carried key the copy does not hold may be new, or may be a run
            // hosted has since opened or closed. Hosted's answer is authoritative.
            return None;
        }
        let closed = known && structured.pointer("/run/closed") == Some(&Value::Bool(true));
        let status = if !issued && !known {
            "unknown"
        } else if !known {
            "pending_on_hosted"
        } else if closed {
            "closed"
        } else {
            "open"
        };
        let guidance = if !issued && !known {
            "This copy does not know this carried run key. It is echoed for correlation only; its ownership and open/closed status require canonical verification on first use.".to_owned()
        } else if closed {
            "This run is closed. Its key is retained for correlation; writes requiring an open run will fail run_closed. Use set_intent with run_key='new' to start a new run; retain the returned key.".to_owned()
        } else if known {
            crate::instructions::RUN_CONTINUATION_GUIDANCE.to_owned()
        } else {
            format!("{} If hosted refuses the key, use set_intent with run_key='new'; retain the returned key.", crate::instructions::RUN_CONTINUATION_GUIDANCE)
        };
        // Rebuild in continuation-first order even when an older local engine
        // supplied the original object. preserve_order keeps this order on the wire.
        let mut fields = std::mem::take(structured.as_object_mut()?);
        fields.shift_remove("run");
        fields.shift_remove("session");
        *structured = json!({
            "run":{"run_key":key,"closed":if known {json!(closed)} else {Value::Null},
                "status":status,"read_only":false,"durable":known,
                "issued_by":if issued {"node"} else {"caller"}},
            "session":{"run_key":key,"reuse_required":!closed,"guidance":guidance}
        });
        structured.as_object_mut()?.extend(fields);
        // Bootstrap results carry no standby_context of their own; disclose the
        // pinned copy like every other local answer.
        structured["standby_context"] = serde_json::to_value(&context).ok()?;
        let snapshot = structured.clone();
        let text = if wants_json {
            snapshot.to_string()
        } else {
            crate::mcp::render::render("bootstrap", &snapshot)
                .unwrap_or_else(|| snapshot.to_string())
        };
        response["result"]["content"] = json!([{"type":"text","text":text}]);
        let health = self.state.lock().await.health;
        let mut response: Value = serde_json::from_str(
            &self
                .offline_response(response, health, "bootstrap", "", false)
                .await?,
        )
        .ok()?;
        if !wants_json && !local_by_default {
            // Like hosted text answers: no structuredContent, so clients that
            // prefer it cannot hide the rendered text and run key (deb2b566).
            if let Some(result) = response.get_mut("result").and_then(Value::as_object_mut) {
                result.remove("structuredContent");
            }
        }
        let response = response.to_string();
        if local_by_default {
            Some(
                self.finalize_default_read(message, response, before_act, &dispatcher, ctx)
                    .await,
            )
        } else {
            Some(DefaultRead::Reply(response))
        }
    }

    fn local_read_unavailable_in(
        message: &Value,
        reason: &str,
        state: &State,
        mut context: Value,
    ) -> Option<String> {
        scope_local_copy_status(&mut context);
        let (writes, _) = write_routing(state.health, state.checked);
        frame_error(
            Some(message.get("id").unwrap_or(&Value::Null)),
            "Local read is unavailable",
            json!({
                "outcome":"local_unavailable", "reason":reason,
                "floor_act":state.persisted.floor.act,
                "own_write_unresolved":state.persisted.floor.unresolved,
                "observed_hosted_head":state.persisted.observed_hosted_head,
                "standby_context":context,
                "node_routing":{"read_source":"local_unavailable", "hosted_health":if state.checked {state.health.as_str()} else {"not_checked"},
                    "canonical_writes":writes, "local_copy_writes":"unsupported"},
                "next_step": UNAVAILABLE_NEXT_STEP,
                "next_safe_action": UNAVAILABLE_NEXT_STEP,
            }),
        )
    }
    /// Reached only when hosted cannot answer AND this node holds no verified
    /// copy it may show (nothing serving, or the copy failed verification):
    /// wrong data is never an acceptable substitute for an error.
    async fn local_read_unavailable(&self, message: &Value, reason: &str) -> Option<String> {
        let context =
            serde_json::to_value(self.dispatcher.serving_context()).unwrap_or(Value::Null);
        let state = self.state.lock().await;
        Self::local_read_unavailable_in(message, reason, &state, context)
    }

    /// Settle a default read that the local copy cannot answer as a clean
    /// current local read. Hosted answers it when reachable (exactly the
    /// option-off path); otherwise the last verified local copy answers with
    /// a disclosure (`local_ok`); only with neither is an error returned, and
    /// it carries a next step.
    async fn default_fallback(
        &self,
        message: &Value,
        protocol: &str,
        reason: &'static str,
        ctx: ReadCtx,
        local_ok: bool,
    ) -> DefaultRead {
        let health = self.state.lock().await.health;
        if !ctx.local && hosted_forwardable(health) {
            return DefaultRead::Forward(reason);
        }
        if local_ok {
            let direct = std::sync::atomic::AtomicBool::new(false);
            if let Some(reply) = self
                .offline(message.clone(), protocol, &direct, Some(reason))
                .await
            {
                return DefaultRead::Reply(with_next_step(reply));
            }
        }
        match self.local_read_unavailable(message, reason).await {
            Some(reply) => DefaultRead::Reply(reply),
            None => DefaultRead::Pass,
        }
    }

    /// No await separates the final account/receipt/lineage fence from the
    /// answer. The account check reads only the bounded local credential file.
    async fn finalize_default_read(
        &self,
        message: &Value,
        response: String,
        before_act: i64,
        dispatcher: &StandbyLocalDispatcher,
        ctx: ReadCtx,
    ) -> DefaultRead {
        #[cfg(test)]
        {
            let pause = self.final_read_pause.lock().unwrap().clone();
            if let Some(pause) = pause {
                pause.entered.notify_one();
                pause.resume.notified().await;
            }
        }
        let pinned_context = dispatcher.serving_context();
        let lineage = dispatcher.act_lineage();
        let context = serde_json::to_value(&pinned_context).unwrap_or(Value::Null);
        let mut response: Value = match serde_json::from_str(&response) {
            Ok(response) => response,
            Err(_) => {
                let health = self.state.lock().await.health;
                if !ctx.local && hosted_forwardable(health) {
                    return DefaultRead::Forward("response_encoding");
                }
                return DefaultRead::Reply(
                    self.local_read_unavailable(message, "response_encoding")
                        .await
                        .unwrap_or_default(),
                );
            }
        };
        let state = self.state.lock().await;
        let account = self.current_account_verdict(&state);
        if state.account_unconfirmed {
            return if !ctx.local && hosted_forwardable(state.health) {
                DefaultRead::Forward("account_unconfirmed")
            } else {
                DefaultRead::Reply(account_unconfirmed_refusal(message).unwrap_or_default())
            };
        }
        if account == Some(false) {
            return if !ctx.local && hosted_forwardable(state.health) {
                DefaultRead::Forward("account_changed")
            } else {
                DefaultRead::Reply(account_changed_refusal(message).unwrap_or_default())
            };
        }
        let own = self.own_writes(ctx.session, &state.persisted.floor);
        let behind = needs_hosted(&state, own, before_act, lineage.as_deref());
        if let Some(reason) = behind {
            if !ctx.local && hosted_forwardable(state.health) {
                return DefaultRead::Forward(reason);
            }
        }
        if default_read_act(&pinned_context, before_act).is_none() {
            if !ctx.local && hosted_forwardable(state.health) {
                return DefaultRead::Forward("generation_or_integrity");
            }
            return DefaultRead::Reply(
                Self::local_read_unavailable_in(
                    message,
                    "generation_or_integrity",
                    &state,
                    context,
                )
                .unwrap_or_default(),
            );
        }
        let bootstrap = target(message).is_some_and(|(executor, _, _)| executor == "bootstrap");
        // Pure response construction under the final lock, never I/O. Health
        // affects disclosure, not the engine selected for a supported read.
        if let Some(content) = response
            .pointer_mut("/result/content")
            .and_then(Value::as_array_mut)
        {
            content.retain(|item| {
                !item["text"].as_str().is_some_and(|text| {
                    text.starts_with("Node routing:")
                        || (bootstrap && text.starts_with("Read source: "))
                })
            });
        }
        // Disclose the position the query was read at (`before_act`, taken
        // before it ran), not the pinned copy's current act: an in-place delta
        // may have advanced the copy since, and the answer does not hold it.
        let standing = standing_in(&state, Some(before_act), lineage.as_deref(), behind);
        // Keep the answering snapshot's captured age. A delta may have advanced
        // the pinned generation since this query, which must not make the old
        // answer appear newly synchronized.
        let bootstrap_context = bootstrap
            .then(|| {
                response
                    .pointer("/result/structuredContent/standby_context")
                    .cloned()
            })
            .flatten();
        annotate_node_routing_with(
            &mut response,
            state.health,
            state.checked,
            "local_copy",
            Some(&standing),
            self.upstream.config.account_id.is_some() && account.is_none(),
            bootstrap.then_some(bootstrap_context.as_ref().unwrap_or(&context)),
            states_write_routing(message),
        );
        if bootstrap && message.pointer("/params/arguments/format") != Some(&json!("json")) {
            // Carry the structured facts through the final fence internally,
            // then return plain text alone (deb2b566).
            if let Some(result) = response.get_mut("result").and_then(Value::as_object_mut) {
                result.remove("structuredContent");
            }
        }
        DefaultRead::Reply(response.to_string())
    }

    /// Default-policy reads never refuse. Hosted answers when it can (so a
    /// reader always sees its own writes); otherwise the local copy answers
    /// with a disclosure of how it stands. Only a read hosted cannot answer
    /// and no verified copy can serve is an error, and it names a next step.
    /// Richard, 10 Nov 2026 (Native task 3f3120c): "I really am not sure we
    /// should EVER be blocking reads."
    async fn try_default_local(
        &self,
        message: &Value,
        protocol: &str,
        caller: &Caller,
        local: bool,
        account_changed: bool,
    ) -> DefaultRead {
        let ctx = ReadCtx {
            session: caller.session,
            local,
        };
        let Some((executor, operation, envelope)) = target(message) else {
            return DefaultRead::Pass;
        };
        let (cache, persistence_failed, revision_unsupported, head_engine_mismatch) = {
            let state = self.state.lock().await;
            (
                state.persisted.discovery.get(protocol).cloned(),
                state.persistence_failed,
                state.revision_unsupported,
                state.head_engine_mismatch,
            )
        };
        let metadata = if executor == "describe_operation"
            || (executor == "system_read" && operation == "ping")
        {
            true
        } else if executor == "sql_read" && operation == "query_sql" {
            let dependencies = envelope
                .pointer("/arguments/sql")
                .and_then(Value::as_str)
                .and_then(|sql| {
                    crate::query::sql::validated_relation_dependencies_ad_hoc(sql).ok()
                });
            let Some(dependencies) = dependencies else {
                // The local engine returns its own validation answer.
                return self
                    .default_fallback(message, protocol, "unsupported_query", ctx, true)
                    .await;
            };
            dependencies.iter().any(|name| name.starts_with("catalog_"))
        } else {
            false
        };
        if metadata {
            return self
                .default_fallback(message, protocol, "metadata_requires_hosted", ctx, true)
                .await;
        }
        let read = executor == "bootstrap"
            || executor.ends_with("_read")
            || self
                .local_row(&executor, &operation)
                .is_some_and(|row| row["access"] == "read")
            || cache.as_ref().is_some_and(|cache| {
                cache.operations.iter().any(|row| {
                    row["executor"] == executor
                        && row["operation"] == operation
                        && row["access"] == "read"
                })
            });
        if !read {
            return DefaultRead::Pass;
        }
        let (account_unconfirmed, health) = {
            let state = self.state.lock().await;
            (state.account_unconfirmed, state.health)
        };
        if account_unconfirmed {
            if !ctx.local && hosted_forwardable(health) {
                return DefaultRead::Forward("account_unconfirmed");
            }
            return match account_unconfirmed_refusal(message) {
                Some(reply) => DefaultRead::Reply(reply),
                None => DefaultRead::Pass,
            };
        }
        // Never answered from this node's copy while the signed-in account is
        // confirmed different. Hosted answers as the new account; if it
        // cannot, the read is refused, not served from the old account's copy.
        if account_changed {
            let health = self.state.lock().await.health;
            if !ctx.local && hosted_forwardable(health) {
                return DefaultRead::Forward("account_changed");
            }
            return match account_changed_refusal(message) {
                Some(reply) => DefaultRead::Reply(reply),
                None => DefaultRead::Pass,
            };
        }
        if revision_unsupported {
            return self
                .default_fallback(message, protocol, "consumer_revision", ctx, true)
                .await;
        }
        if head_engine_mismatch {
            return self
                .default_fallback(message, protocol, "hosted_engine_mismatch", ctx, true)
                .await;
        }
        if persistence_failed {
            return self
                .default_fallback(message, protocol, "persistence_failed", ctx, true)
                .await;
        }
        if !self.dispatcher.serving_kernel_v2() {
            return self
                .default_fallback(message, protocol, "generation", ctx, false)
                .await;
        }
        if executor == "bootstrap" {
            return match Box::pin(self.try_online_local_bootstrap(message, protocol, 0, true, ctx))
                .await
            {
                Some(read) => read,
                None => {
                    self.default_fallback(message, protocol, "bootstrap_not_ready", ctx, true)
                        .await
                }
            };
        }
        let Some(discovery) = cache.as_ref().filter(|cache| !cache.operations.is_empty()) else {
            return self
                .default_fallback(message, protocol, "catalogue", ctx, true)
                .await;
        };
        if !self.supported(Some(discovery), &executor, &operation) {
            return self
                .default_fallback(message, protocol, "unsupported_contract", ctx, true)
                .await;
        }
        // One retry for a generation swapping under the read; then hosted, or
        // (hosted unreachable) a fresh disclosed local read.
        let mut attempt = 0;
        let (response, before_act, dispatcher) = loop {
            let Some(dispatcher) = self.dispatcher.local_dispatcher() else {
                return self
                    .default_fallback(message, protocol, "generation", ctx, false)
                    .await;
            };
            let before = dispatcher.serving_context();
            let lineage = dispatcher.act_lineage();
            let Some(before_act) = default_read_act(&before, 0) else {
                return self
                    .default_fallback(message, protocol, "generation_or_integrity", ctx, false)
                    .await;
            };
            // A copy behind this reader's own writes cannot answer while
            // hosted can: skip the local query entirely.
            {
                let state = self.state.lock().await;
                let own = self.own_writes(ctx.session, &state.persisted.floor);
                if let Some(reason) = needs_hosted(&state, own, before_act, lineage.as_deref()) {
                    if !ctx.local && hosted_forwardable(state.health) {
                        return DefaultRead::Forward(reason);
                    }
                }
            }
            let generation = before.serving_generation_id.as_deref();
            let Some(response) = self
                .dispatch_local_pinned(
                    Some(&dispatcher),
                    message.clone(),
                    Some(discovery),
                    &executor,
                    envelope.clone(),
                )
                .await
            else {
                return self
                    .default_fallback(message, protocol, "generation", ctx, false)
                    .await;
            };
            #[cfg(test)]
            if attempt == 0 {
                let pause = self.read_pause.lock().unwrap().clone();
                if let Some(pause) = pause {
                    pause.entered.notify_one();
                    pause.resume.notified().await;
                }
            }
            // The query ran on the pinned generation, so this is a backstop. A
            // text-format answer carries no structuredContent (an audited
            // rendering omits the duplicate): absence is not a mismatch. It
            // once was, which refused every text read while JSON was served.
            // Keep genuine engine validation/refusal results; they are not a
            // cue to retry a possibly different query against hosted.
            let answered = response
                .pointer("/result/structuredContent/standby_context/serving_generation_id")
                .and_then(Value::as_str);
            if response.pointer("/result/isError") != Some(&Value::Bool(true))
                && (generation.is_none() || answered.is_some_and(|id| Some(id) != generation))
            {
                attempt += 1;
                if attempt < 2 {
                    continue;
                }
                return self
                    .default_fallback(message, protocol, "generation_changed", ctx, true)
                    .await;
            }
            break (response, before_act, dispatcher);
        };
        let health = self.state.lock().await.health;
        let Some(response) = self
            .offline_response(response, health, &executor, &operation, false)
            .await
        else {
            return DefaultRead::Pass;
        };
        self.finalize_default_read(message, response, before_act, &dispatcher, ctx)
            .await
    }

    /// Opt-in everyday local read (`online_local_reads`). Only for a read the
    /// explicit `native/route: local` rules would serve (advertised locally,
    /// read-only, contract digest matching the hosted catalogue cache), and
    /// only when the copy provably holds every write this node has seen
    /// acknowledged (`serving_head_act >= floor.act`, nothing pending or
    /// unresolved) and is no older than the bound. `None` means "forward to
    /// hosted exactly as without the option"; nothing is shown to the caller.
    async fn try_online_local(
        &self,
        message: &Value,
        protocol: &str,
        max_age_seconds: u64,
    ) -> Option<String> {
        let (executor, operation, envelope) = target(message)?;
        if executor == "bootstrap" {
            return match Box::pin(self.try_online_local_bootstrap(
                message,
                protocol,
                max_age_seconds,
                false,
                ReadCtx {
                    session: None,
                    local: false,
                },
            ))
            .await
            {
                Some(DefaultRead::Reply(reply)) => Some(reply),
                _ => None,
            };
        }
        if matches!(executor.as_str(), "describe_operation" | "standby_status") {
            return None;
        }
        let (cache, floor, persistence_failed, checked) = {
            let state = self.state.lock().await;
            if self.current_account_verdict(&state) == Some(false) {
                return None;
            }
            (
                state.persisted.discovery.get(protocol).cloned(),
                state.persisted.floor.clone(),
                state.persistence_failed,
                state.checked,
            )
        };
        // `Reachable` before the first settled probe is only the optimistic
        // starting value (the credential may have been revoked meanwhile).
        if !checked || floor.unresolved || persistence_failed {
            return None;
        }
        let floor_act = floor.act?;
        // Unlike the explicit route, no cold-start exception: the hosted
        // contract digest must be known and must match.
        let discovery = cache.as_ref().filter(|c| !c.operations.is_empty())?;
        if !self.supported(Some(discovery), &executor, &operation) {
            return None;
        }
        if executor == "sql_read" {
            // Local SQL receives the offline catalogue. Admit only individually
            // understood data queries, leaving real catalogue reads hosted.
            // Preparing against the logical schema distinguishes dependencies
            // from comments, literals and same-named CTEs. Column-less staged
            // catalogue reads that inspection refuses also stay hosted.
            // Unknown/named-view forms stay hosted; the normal dispatcher still
            // owns validation, app admission and engine-specific support.
            if operation != "query_sql" {
                return None;
            }
            let sql = envelope.pointer("/arguments/sql")?.as_str()?;
            let dependencies =
                crate::query::sql::validated_relation_dependencies_ad_hoc(sql).ok()?;
            if dependencies.contains("catalog_operations") {
                return None;
            }
        }
        // Read the copy's state BEFORE the query. The copy only advances, so
        // this is a lower bound on what the query sees; the context the
        // response carries is attached afterwards and could overstate it.
        let before = self.dispatcher.serving_context()?;
        let before_act = pre_read_act(&before, floor_act, max_age_seconds)?;
        let before_generation = before.serving_generation_id.clone()?;
        let response = self
            .dispatch_local(message.clone(), Some(discovery), &executor, envelope)
            .await?;
        if response.pointer("/result/isError") == Some(&Value::Bool(true)) {
            return None;
        }
        // The answer must come from the generation the check was made on.
        if response
            .pointer("/result/structuredContent/standby_context/serving_generation_id")
            .and_then(Value::as_str)
            != Some(before_generation.as_str())
        {
            return None;
        }
        // A write acknowledged while the read ran must still count.
        let (floor, persistence_failed) = {
            let state = self.state.lock().await;
            (state.persisted.floor.clone(), state.persistence_failed)
        };
        if floor.unresolved || persistence_failed || floor.act.is_none_or(|act| before_act < act) {
            return None;
        }
        self.offline_response(response, Health::Reachable, &executor, &operation, false)
            .await
    }

    /// Apply the same own-write and protocol disclosure to every outage read,
    /// including the bounded bootstrap orientation.
    async fn offline_response(
        &self,
        response: Value,
        health: Health,
        executor: &str,
        operation: &str,
        include_catalogue_disclosure: bool,
    ) -> Option<String> {
        self.offline_response_with(
            response,
            health,
            executor,
            operation,
            include_catalogue_disclosure,
            None,
        )
        .await
    }

    /// `standing`: `Some((reason, position))` also discloses how the answer stands
    /// against the known hosted head (default policy only; `reason` is why
    /// hosted did not answer, `position` captures the answering copy's act and lineage). Default-routed reads pass `None` and take the same
    /// disclosure from their final fence.
    async fn offline_response_with(
        &self,
        mut response: Value,
        health: Health,
        executor: &str,
        operation: &str,
        include_catalogue_disclosure: bool,
        standing: Option<(Option<&'static str>, Option<ReadPosition>)>,
    ) -> Option<String> {
        #[cfg(test)]
        if standing.is_some() {
            let pause = self.final_read_pause.lock().unwrap().clone();
            if let Some(pause) = pause {
                pause.entered.notify_one();
                pause.resume.notified().await;
            }
        }
        // Final fence for every offline/local answer, including legacy and
        // outage bootstrap. No await follows it before returning the answer.
        let state = self.state.lock().await;
        let account = self.current_account_verdict(&state);
        if state.account_unconfirmed {
            return account_unconfirmed_refusal(&response);
        }
        if account == Some(false) {
            return account_changed_refusal(&response);
        }
        let checked = state.checked;
        let source = if response.pointer("/result/structuredContent/standby_context/mode")
            == Some(&json!("status_only"))
            || response.pointer("/result/structuredContent/mode") == Some(&json!("status_only"))
        {
            "local_status"
        } else {
            "local_copy"
        };
        let standing = match standing {
            Some((reason, Some(position)))
                if self.upstream.config.local_reads_by_default && source == "local_copy" =>
            {
                // Never combine this answer's act with another generation's
                // numbering after a concurrent publication.
                Some(standing_in(
                    &state,
                    Some(position.act),
                    position.lineage.as_deref(),
                    reason,
                ))
            }
            _ => None,
        };
        let bootstrap_context = (executor == "bootstrap")
            .then(|| {
                response
                    .pointer("/result/structuredContent/standby_context")
                    .cloned()
            })
            .flatten();
        annotate_node_routing_with(
            &mut response,
            health,
            checked,
            source,
            standing.as_ref(),
            self.upstream.config.account_id.is_some() && account.is_none(),
            bootstrap_context.as_ref(),
            executor == "bootstrap" || (executor == "system_read" && operation == "ping"),
        );
        if health == Health::ProtocolFailed {
            add_text(
                &mut response,
                "Hosted MCP protocol failed; this answer is from the local standby.",
            );
        }
        // The sticky flag, not the transient health: a later outage must
        // not drop the revision incompatibility from local answers.
        let revision_unsupported = state.revision_unsupported;
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
        if include_catalogue_disclosure
            && (executor == "describe_operation"
                || (executor == "sql_read" && operation == "query_sql"))
        {
            add_text(&mut response, "Availability: served locally; catalog_operations describes only the supported offline surface. Hosted may advertise additional operations.");
        }
        // Include writes that completed while this read was executing. A floor
        // captured before dispatch could miss an acknowledgement racing it.
        let floor = &state.persisted.floor;
        let persistence_failed = state.persistence_failed;
        let serving = response
            .pointer("/result/structuredContent/standby_context/serving_head_act")
            .and_then(Value::as_i64);
        if !self.upstream.config.local_reads_by_default {
            if let Some(label) = floor.label(serving) {
                add_text(&mut response, &label);
            }
        }
        if persistence_failed {
            add_text(
                &mut response,
                if self.file.newer_version.is_some() {
                    "Saved state is from a newer build; the write floor is kept in memory and this copy cannot be compared with the saved floor."
                } else {
                    "Own-write floor persistence failed; the retained floor is unresolved."
                },
            );
        }
        Some(response.to_string())
    }
}

impl gate::Outage for Failover {
    fn held_replay_allowed(&self) -> gate::Ready<'_, bool> {
        Box::pin(async {
            if self.dispatcher.serving_kernel_v2() || self.upstream.config.local_reads_by_default {
                let mut state = self.state.lock().await;
                state.persisted.kernel_v2 = true;
                if let Some(gate) = &self.gate {
                    gate.set_kernel_v2_upstream(true);
                }
                self.persist(&mut state);
                return false;
            }
            !self.state.lock().await.persisted.kernel_v2
        })
    }

    #[cfg(feature = "v2-kernel-probe")]
    fn working_published<'a>(
        &'a self,
        scope: &'a super::journal::CustodyBinding,
        ordinal: i64,
    ) -> gate::Ready<'a, bool> {
        Box::pin(async move { self.working_published(scope, ordinal).await })
    }
    #[cfg(feature = "v2-kernel-probe")]
    fn working_dispatch_exclusions<'a>(
        &'a self,
        scope: &'a super::journal::CustodyBinding,
    ) -> gate::Ready<'a, Option<Vec<String>>> {
        Box::pin(async move { self.working_dispatch_exclusions(scope).await })
    }
    #[cfg(feature = "v2-kernel-probe")]
    fn working_canonical_changed<'a>(
        &'a self,
        scope: &'a super::journal::CustodyBinding,
    ) -> gate::Ready<'a, ()> {
        Box::pin(async move {
            self.working_canonical_changed(scope);
        })
    }
    fn custody_binding(&self) -> gate::Ready<'_, Option<super::journal::CustodyBinding>> {
        Box::pin(async {
            let state = self.state.lock().await;
            // Opaque state cannot supply evidence. Fresh account/head evidence
            // collected in this process can still bind queued sends; a genuine
            // failure saving supported state retains its existing refusal.
            if (state.persistence_failed && self.file.newer_version.is_none())
                || state.persisted.account_mismatch
                || state.account_unconfirmed
                || !state.persisted.kernel_v2
                || state.head_engine_mismatch
                || self.credential_digest() != state.persisted.verified_custody_credential
                || state.persisted.verified_custody_credential.is_none()
            {
                return None;
            }
            let binding = &state.persisted.binding;
            let selected = self.upstream.config.account_id.as_deref()?;
            if selected != binding.account || self.upstream.config.db_id != binding.route {
                return None;
            }
            let history = state.persisted.observed_hosted_head.as_ref()?.1.clone();
            if !history.starts_with("v2:") {
                return None;
            }
            let custody = super::journal::CustodyBinding {
                account_id: binding.account.clone(),
                database_id: binding.route.clone(),
                origin_database_id: binding.origin.clone(),
                history_lineage: history,
                install_id: self.upstream.install_key.as_ref().map(|key| key.id()),
                resource_origin: self
                    .upstream
                    .config
                    .hosted_base_url
                    .trim_end_matches('/')
                    .to_owned(),
            };
            custody.valid().then_some(custody)
        })
    }

    fn custody_credential(&self) -> gate::Ready<'_, Option<[u8; 32]>> {
        Box::pin(async {
            gate::Outage::custody_binding(self).await?;
            let state = self.state.lock().await;
            if state.persisted.account_mismatch
                || state.account_unconfirmed
                || (state.persistence_failed && self.file.newer_version.is_none())
            {
                return None;
            }
            state.persisted.verified_custody_credential
        })
    }

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

    fn holding_contract<'a>(
        &'a self,
        executor: &'a str,
        operation: &'a str,
        protocol: Option<&'a str>,
    ) -> gate::Ready<'a, Option<NodeHoldingContract>> {
        Box::pin(async move {
            let state = self.state.lock().await;
            if (state.persistence_failed && self.file.newer_version.is_none())
                || state.account_unconfirmed
                || state.health == Health::AuthRefused
                || self.current_account_verdict(&state) == Some(false)
            {
                return None;
            }
            let discovery = state
                .persisted
                .discovery
                .get(protocol.unwrap_or(crate::mcp::PROTOCOL_VERSION))?;
            let cached = discovery.holding_contracts.iter().find(|cached| {
                cached.contract.description["executor"] == executor
                    && cached.contract.description["operation"] == operation
            })?;
            // After restart, the same credential retains its confirmed account
            // evidence. A different credential must first confirm this account.
            if self.credential_digest() != Some(cached.credential_digest)
                && self.current_account_verdict(&state) != Some(true)
            {
                return None;
            }
            let row = discovery
                .operations
                .iter()
                .find(|row| row["executor"] == executor && row["operation"] == operation)?;
            let coherent =
                NodeHoldingContract::from_hosted(cached.contract.description.clone(), row)?;
            (coherent == cached.contract).then_some(coherent)
        })
    }

    fn holding_operation_absent<'a>(
        &'a self,
        executor: &'a str,
        operation: &'a str,
        protocol: Option<&'a str>,
    ) -> gate::Ready<'a, bool> {
        Box::pin(async move {
            let state = self.state.lock().await;
            let Some(credential) = self.credential_digest() else {
                return false;
            };
            let account = self.current_account_verdict(&state);
            let account_confirmed = account == Some(true)
                || (account.is_none()
                    && state.persisted.verified_custody_credential == Some(credential));
            if (state.persistence_failed && self.file.newer_version.is_none())
                || state.account_unconfirmed
                || state.health == Health::AuthRefused
                || !account_confirmed
            {
                return false;
            }
            let Some(discovery) = state
                .persisted
                .discovery
                .get(protocol.unwrap_or(crate::mcp::PROTOCOL_VERSION))
            else {
                return false;
            };
            // This witness is retained only after the complete catalogue fetch
            // answered successfully under this credential. Empty can be genuine.
            discovery.holding_catalog_credential == Some(credential)
                && !discovery
                    .operations
                    .iter()
                    .any(|row| row["executor"] == executor && row["operation"] == operation)
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

    fn after_write<'a>(&'a self, reply: Option<&'a str>) -> gate::Ready<'a, ()> {
        Box::pin(async move {
            self.settle_write(reply, None).await;
            self.probe_needed.notify_one();
        })
    }

    fn note_receipt<'a>(&'a self, reply: Option<&'a str>) -> gate::Ready<'a, ()> {
        Box::pin(async move {
            if let Some(act) = receipt_act(reply) {
                let mut state = self.state.lock().await;
                state.persisted.floor.raise(act);
                self.persist(&mut state);
            }
            self.probe_needed.notify_one();
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

/// The act a copy is provably at, from its context read BEFORE a local
/// query, if that copy may answer an online read: serving, fresh (inside the
/// RPO, not degraded), no older than the bound, and at or past the floor.
pub(crate) fn pre_read_act(
    context: &crate::standby::StandbyResponseContext,
    floor_act: i64,
    max_age_seconds: u64,
) -> Option<i64> {
    use crate::standby::{StandbyFreshnessState, StandbyStatusMode};
    if context.mode != StandbyStatusMode::Standby
        || context.freshness.state != StandbyFreshnessState::Fresh
        || context.freshness_degraded
        || !context.degraded_reasons.is_empty()
        || context.freshness.age_seconds? > max_age_seconds
    {
        return None;
    }
    // A copy advanced in place must have been re-judged against its receipts
    // within twice the audit interval (design record 5065900 §5): a stalled,
    // failed or absent audit forwards the read to hosted, which is canonical.
    // Evaluated on every request, from a context read just before the query.
    if context
        .serving_audit
        .as_ref()
        .is_some_and(|audit| audit.state != "current")
    {
        return None;
    }
    context.serving_head_act.filter(|act| *act >= floor_act)
}

/// Next step on the one error a default read can still return.
const UNAVAILABLE_NEXT_STEP: &str = "This node has no verified local copy it can show right now and hosted Native did not answer. Retry in a minute; if it keeps failing, run `native status` on this machine or read from hosted Native directly.";

/// Hosted can be asked to answer a read unless it is known to be down or to
/// be refusing this node's credentials (which would only fail the same way).
fn hosted_forwardable(health: Health) -> bool {
    !matches!(health, Health::Unreachable | Health::AuthRefused)
}

/// A canonical tool refusal or JSON-RPC request error is an answer, even if
/// accompanied by a server status. Do not replace validation/access decisions
/// with potentially older local data. Internal errors and otherwise unusable
/// server responses, on the other hand, did not answer the read.
fn default_read_server_failure(sent: &super::SendReport) -> Option<Health> {
    match sent.reply_kind {
        super::ReplyKind::ExplicitRefusal => None,
        super::ReplyKind::CanonicalRpc => {
            let reply = sent
                .reply
                .as_deref()
                .and_then(|reply| serde_json::from_str::<Value>(reply).ok())?;
            // All canonical results (including tool refusals) answered the
            // read. Only JSON-RPC's internal error establishes server failure.
            (reply.pointer("/error/code").and_then(Value::as_i64) == Some(-32603))
                .then_some(Health::ProtocolFailed)
        }
        super::ReplyKind::Node => sent
            .status
            .filter(|status| (500..600).contains(status))
            .map(|_| Health::ProtocolFailed),
    }
}

/// Retain only small transport facts, never hosted error bodies. Text-format
/// answers get the same JSON disclosure without inventing structuredContent.
fn annotate_failed_hosted_read(reply: String, sent: &super::SendReport) -> String {
    let Ok(mut response) = serde_json::from_str::<Value>(&reply) else {
        return reply;
    };
    if response.get("result").is_none()
        || response.pointer("/result/isError") == Some(&Value::Bool(true))
    {
        return reply;
    }
    let mut failure = json!({});
    if sent.update_required().is_some() {
        failure["error_code"] = json!(crate::client_compatibility::UPDATE_REQUIRED);
        failure["updater"] = json!("unavailable");
    }

    if let Some(status) = sent.status {
        failure["http_status"] = json!(status);
    }
    if sent.reply_kind == super::ReplyKind::CanonicalRpc {
        if let Some(code) = sent
            .reply
            .as_deref()
            .and_then(|reply| serde_json::from_str::<Value>(reply).ok())
            .and_then(|reply| reply.pointer("/error/code").and_then(Value::as_i64))
        {
            failure["rpc_error_code"] = json!(code);
        }
    }
    if failure.as_object().is_none_or(|facts| facts.is_empty()) {
        return reply;
    }
    if let Some(structured) = response.pointer_mut("/result/structuredContent") {
        let original = structured.clone();
        structured["node_routing"]["hosted_read_failure"] = failure.clone();
        let replacement = structured.to_string();
        if let Some(content) = response
            .pointer_mut("/result/content")
            .and_then(Value::as_array_mut)
        {
            for item in content {
                if item["type"] == "text"
                    && item["text"].as_str().is_some_and(|text| {
                        serde_json::from_str::<Value>(text).ok().as_ref() == Some(&original)
                    })
                {
                    item["text"] = json!(replacement);
                }
            }
        }
    }
    add_text(&mut response, &format!("Hosted could not answer this read ({failure}); this answer is from the retained local copy."));
    response.to_string()
}

/// Why hosted should answer this read instead of the local copy, if it
/// should. Never a reason to refuse: with hosted unavailable the local copy
/// answers with a disclosure. Authentication trouble is deliberately absent:
/// it is doubt about hosted, not evidence about the copy.
fn needs_hosted(
    state: &State,
    own: OwnWrites,
    before_act: i64,
    lineage: Option<&str>,
) -> Option<&'static str> {
    let floor = &state.persisted.floor;
    if state.revision_unsupported {
        Some("consumer_revision")
    } else if state.head_engine_mismatch {
        Some("hosted_engine_mismatch")
    } else if state.persisted.version > STATE_VERSION && (own.act > 0 || own.unresolved) {
        Some("migration_unsettled")
    } else if state.persistence_failed {
        Some("persistence_failed")
    } else if own.unresolved {
        Some("own_write")
    } else if own.act > 0 && floor.lineage.is_none() {
        Some("migration_unsettled")
    } else if own.act > 0 && floor.lineage.as_deref() != lineage {
        Some("own_write_lineage")
    } else if before_act < own.act {
        Some("own_write")
    } else {
        None
    }
}

/// How a local answer stands against what the node knows hosted holds.
fn standing_in(
    state: &State,
    serving: Option<i64>,
    lineage: Option<&str>,
    fallback_reason: Option<&'static str>,
) -> Standing {
    let floor = &state.persisted.floor;
    let mut known: Option<i64> = None;
    let mut incomparable = false;
    if let Some(act) = floor.act {
        if lineage.is_some() && floor.lineage.as_deref() == lineage {
            known = Some(known.map_or(act, |old| old.max(act)));
        } else {
            incomparable = true;
        }
    }
    if let Some((act, observed)) = &state.persisted.observed_hosted_head {
        if lineage == Some(observed.as_str()) {
            known = Some(known.map_or(*act, |old| old.max(*act)));
        } else {
            incomparable = true;
        }
    }
    let behind_known_write = match (serving, known) {
        _ if state.persisted.version > STATE_VERSION => None,
        (Some(serving), Some(known)) if serving < known => Some(true),
        (None, _) => None,
        _ if incomparable => None,
        _ => Some(false),
    };
    Standing {
        serving_head_act: serving,
        known_hosted_head_act: known,
        last_successful_hosted_check_at: state
            .observed_hosted_head_at
            .clone()
            .filter(|at| chrono::DateTime::parse_from_rfc3339(at).is_ok()),
        behind_known_write,
        own_write_floor_act: floor.act,
        own_write_unresolved: floor.unresolved || state.persistence_failed,
        fallback_reason,
    }
}

/// Freshness is a disclosure, never a refusal: a verified copy whose age is
/// beyond RPO or unknown (`snapshot_age_unavailable`) still answers, with its
/// standing disclosed. Failed verification and every unrecognised
/// degradation still refuse (Richard, 10 Nov 2026; task 3f3120c G-N2).
fn default_read_act(
    context: &crate::standby::StandbyResponseContext,
    floor_act: i64,
) -> Option<i64> {
    use crate::standby::StandbyStatusMode;
    if context.mode != StandbyStatusMode::Standby
        || context.degraded_reasons.iter().any(|reason| {
            !matches!(
                *reason,
                "snapshot_beyond_rpo"
                    | "snapshot_age_unavailable"
                    | "audit_overdue"
                    | "audit_unaudited"
                    | "restart_recheck_pending"
            )
        })
        || context
            .serving_audit
            .as_ref()
            .is_some_and(|audit| !matches!(audit.state, "current" | "overdue" | "unaudited"))
        || (context.freshness_degraded && context.degraded_reasons.is_empty())
    {
        return None;
    }
    context.serving_head_act.filter(|act| *act >= floor_act)
}

/// Is the signed-in principal the account this node is bound to? `Some(true)`
/// same, `Some(false)` CONFIRMED different, `None` cannot tell. Both sides must
/// be well-formed canonical `acct_...` ids: a configured id in some other
/// shape, or a principal that could not be read (hosted refusing the new
/// credential, offline), is doubt, never a refusal.
fn account_verdict(bound: Option<&str>, principal: Option<&str>) -> Option<bool> {
    let canonical = |id: &str| {
        id.starts_with("acct_")
            && id.len() > 5
            && id.len() <= 256
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
    };
    let (bound, principal) = (bound?, principal?);
    (canonical(bound) && canonical(principal)).then(|| bound == principal)
}

fn account_unconfirmed_refusal(message: &Value) -> Option<String> {
    frame_error(
        message.get("id"),
        "Local account data is waiting for hosted account confirmation after opening newer saved state",
        json!({"outcome":"not_sent", "reason":"account_unconfirmed",
            "next_step":"Reconnect to hosted so the node can confirm this account, or upgrade to a node that can read the saved state."}),
    )
}

fn account_changed_refusal(message: &Value) -> Option<String> {
    frame_error(
        message.get("id"),
        "The signed-in account is not the account this node is set up for; local data request was not sent",
        json!({
            "outcome":"not_sent","reason":"account_changed",
            "next_step":"Sign in again with the account this node is set up for (`native login`), or run `native setup` to move the node to the new account.",
        }),
    )
}

/// The node's own credential refusals (unreadable credential file, failed
/// renewal or preflight) are answered before anything is sent, so they carry
/// no classified failure. They are authentication trouble all the same.
fn credential_preflight_failure(reply: Option<&str>) -> Option<Health> {
    let reply = serde_json::from_str::<Value>(reply?).ok()?;
    let data = reply.pointer("/error/data")?;
    (data.get("outcome").and_then(Value::as_str) == Some("not_sent")
        && matches!(
            data.get("reason").and_then(Value::as_str),
            Some("credential_refused" | "credential_renewal_failed")
        ))
    .then_some(Health::AuthRefused)
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
/// The highest act a successful hosted write receipt reports, if any. Reads
/// only the engine's receipt positions (the ones `withhold_receipt_acts`
/// names): top-level `act`, `acts[]` (integers or `{act}` objects, as
/// `create_many` emits), `results[].record.act` and `refresh.record.act`.
/// Caller-authored `metadata.act` is deliberately ignored. Errors, refusals
/// and held writes yield `None`.
pub(super) fn receipt_act(reply: Option<&str>) -> Option<i64> {
    let reply = serde_json::from_str::<Value>(reply?).ok()?;
    if reply.get("error").is_some() || reply.pointer("/result/isError") == Some(&json!(true)) {
        return None;
    }
    let receipt = reply.pointer("/result/structuredContent")?;
    if matches!(
        receipt.get("outcome").and_then(Value::as_str),
        Some("not_sent" | "refused" | "accepted_pending")
    ) {
        return None;
    }
    let act_of = |v: &Value| v.as_i64().or_else(|| v.get("act").and_then(Value::as_i64));
    let mut acts = Vec::new();
    acts.extend(receipt.get("act").and_then(Value::as_i64));
    if let Some(list) = receipt.get("acts").and_then(Value::as_array) {
        acts.extend(list.iter().filter_map(act_of));
    }
    if let Some(list) = receipt.get("results").and_then(Value::as_array) {
        acts.extend(
            list.iter()
                .filter_map(|r| r.pointer("/record/act").and_then(Value::as_i64)),
        );
    }
    acts.extend(
        receipt
            .pointer("/refresh/record/act")
            .and_then(Value::as_i64),
    );
    acts.into_iter().filter(|a| *a > 0).max()
}
/// Copy capabilities are not session capabilities: an online node forwards
/// mutations to hosted even when it answers a read from this read-only copy.
fn scope_local_copy_status(value: &mut Value) {
    if let Some(object) = value.as_object_mut() {
        let read_only = object.remove("read_only");
        let writes_supported = object.remove("writes_supported");
        if read_only.is_some() || writes_supported.is_some() {
            object.insert(
                "local_copy".into(),
                json!({"read_only":read_only,"writes_supported":writes_supported}),
            );
        }
        // This node-only tool is not in the hosted executor contract exposed
        // to connected agents. Do not direct them to an uncallable operation.
        object.remove("full_status_tool");
    }
}

fn annotate_node_routing(
    response: &mut Value,
    health: Health,
    checked: bool,
    source: &str,
    states_write_routing: bool,
) {
    annotate_node_routing_with(
        response,
        health,
        checked,
        source,
        None,
        false,
        None,
        states_write_routing,
    );
}

/// One short, plain line saying how a local answer stands, or `None` when
/// there is nothing to say. Internal outcome words stay in the machine fields.
fn standing_sentence(standing: &Standing) -> Option<String> {
    let mut parts = Vec::new();
    match (
        standing.behind_known_write,
        standing.serving_head_act,
        standing.known_hosted_head_act,
    ) {
        (Some(true), Some(serving), Some(known)) => parts.push(format!(
            "This answer is from the node's local copy at act {serving}; hosted is known to be at act {known}, so recent writes may be missing."
        )),
        (None, ..) if standing.own_write_floor_act.is_some() => parts.push(
            "This answer is from the node's local copy; whether it holds every recent write could not be checked."
                .to_owned(),
        ),
        _ if standing.own_write_unresolved => {
            parts.push("A recent write may not be in this copy yet.".to_owned());
        }
        _ => {}
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// Bootstrap and ping are where an agent orients, so their routing line states
/// ordinary write routing; other reads leave it to them.
fn states_write_routing(message: &Value) -> bool {
    target(message).is_some_and(|(executor, operation, _)| {
        executor == "bootstrap" || (executor == "system_read" && operation == "ping")
    })
}

/// Disclose, on an answer hosted gave in place of the local copy, that and why.
fn annotate_hosted_fallback(response: &mut Value, reason: Option<&'static str>) {
    let Some(reason) = reason else { return };
    if let Some(routing) = response
        .pointer_mut("/result/structuredContent/node_routing")
        .and_then(Value::as_object_mut)
    {
        routing.insert("read_fallback_reason".into(), json!(reason));
    }
    let why = match reason {
        "own_write" | "own_write_lineage" | "migration_unsettled" | "persistence_failed" => {
            "this node's local copy might not yet include your own recent writes"
        }
        _ => "this node's local copy could not safely answer this read",
    };
    add_text(
        response,
        &format!("This answer comes from hosted Native because {why}."),
    );
}

/// A plain next step on an error the node returns in place of a read.
fn with_next_step(reply: String) -> String {
    const STEP: &str = "Next step: retry shortly, or read from hosted Native when it is reachable; `native status` shows the state of this node's local copy.";
    let Ok(mut value) = serde_json::from_str::<Value>(&reply) else {
        return reply;
    };
    if let Some(data) = value
        .pointer_mut("/error/data")
        .and_then(Value::as_object_mut)
    {
        if !data.contains_key("next_step") {
            data.insert("next_step".into(), json!(STEP));
        }
    } else if value.pointer("/result/isError") == Some(&json!(true)) {
        add_text(&mut value, STEP);
    } else {
        return reply;
    }
    value.to_string()
}

#[allow(clippy::too_many_arguments)]
fn annotate_node_routing_with(
    response: &mut Value,
    health: Health,
    checked: bool,
    source: &str,
    standing: Option<&Standing>,
    account_unverified: bool,
    bootstrap_context: Option<&Value>,
    states_write_routing: bool,
) {
    let Some(result) = response.get_mut("result").and_then(Value::as_object_mut) else {
        return;
    };
    let (writes, explanation) = write_routing(health, checked);
    let mut line = if let Some(context) = bootstrap_context {
        let age = context
            .pointer("/freshness/age_seconds")
            .and_then(Value::as_u64);
        let age = age
            .map(|age| format!("last matching hosted check/snapshot capture {age}s ago"))
            .unwrap_or_else(|| "matching hosted check age unknown".into());
        let writes = if checked && health == Health::Reachable {
            "Writes go to hosted Native; the local copy accepts no writes."
        } else {
            explanation
        };
        format!("Read source: {source}; {age}. {writes}")
    } else if writes == "forwarded_to_hosted" && !states_write_routing {
        // Ordinary write routing is stated where an agent orients (bootstrap
        // and ping). Repeating it on every read only costs tokens; the unusual
        // cases below still say why writes are unavailable.
        format!("Node routing: reads from {source}.")
    } else {
        format!("Node routing: reads from {source}. {explanation}")
    };
    if let Some(standing) = standing {
        let sentence = if bootstrap_context.is_some() {
            if standing.behind_known_write == Some(true) {
                Some("Hosted has newer changes; their time lag is unknown.".to_owned())
            } else if standing.own_write_unresolved {
                Some("A recent write is not yet confirmed in this copy.".to_owned())
            } else if standing.behind_known_write.is_none()
                && standing.own_write_floor_act.is_some()
            {
                Some("Whether this copy includes your prior writes is unknown.".to_owned())
            } else {
                match (standing.serving_head_act, standing.known_hosted_head_act) {
                    (Some(local), Some(known))
                        if local == known && standing.behind_known_write == Some(false) =>
                    {
                        Some("Local copy matches the latest known hosted revision.".to_owned())
                    }
                    _ => None,
                }
            }
        } else {
            standing_sentence(standing)
        };
        if let Some(sentence) = sentence {
            line.push(' ');
            line.push_str(&sentence);
        }
        if bootstrap_context.is_some() {
            if let Some(at) = &standing.last_successful_hosted_check_at {
                line.push_str(&format!(" Last successful hosted head check: {at}."));
            }
            if !checked || health != Health::Reachable {
                line.push_str(" Current hosted comparison is unavailable; any additional missing changes are unknown.");
            }
        }
    }
    if let Some(context) = bootstrap_context {
        let age = context
            .pointer("/freshness/age_seconds")
            .and_then(Value::as_u64);
        let target = context
            .pointer("/freshness/target_rpo_seconds")
            .and_then(Value::as_u64);
        if age.zip(target).is_some_and(|(age, target)| age > target)
            || context.pointer("/freshness/state") == Some(&json!("stale"))
        {
            line.push_str(
                " Check age exceeds the refresh target; elapsed age alone does not establish missing changes.",
            );
        }
        let reasons: Vec<_> = context
            .get("degraded_reasons")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if !reasons.is_empty() {
            line.push_str(&format!(
                " Copy refresh is degraded: {}. See `native status` for diagnostics.",
                reasons.join(", ")
            ));
        } else if context.get("freshness_degraded") == Some(&json!(true)) {
            line.push_str(" Copy refresh is degraded; see `native status` for diagnostics.");
        }
    }
    let account_unverified = account_unverified && source == "local_copy";
    let reauthenticate = health == Health::AuthRefused && source == "local_copy";
    if account_unverified {
        line.push_str(" The account for the current sign-in has not been verified; this answer is from the node's previously verified copy.");
    }
    if reauthenticate {
        line.push_str(" Hosted sign-in needs attention, so this copy may be out of date. Next step: run `native login` on this machine to re-authenticate, then retry.");
    }
    // The rendered local-copy header never asserts `fresh` (see
    // `render_standby_context`), so a copy behind a known hosted head needs
    // no text correction: the standing sentence in this routing line says
    // hosted is ahead, and the JSON payload carries `behind_hosted_head`.
    // A text-format answer deliberately carries no structuredContent. Do not
    // invent one: MCP clients that prefer structuredContent would then show
    // only node_routing and hide the real text, including bootstrap's run key.
    let Some(structured) = result
        .get_mut("structuredContent")
        .filter(|structured| structured.is_object())
    else {
        add_routing_text(response, &line, bootstrap_context.is_some());
        return;
    };
    let original = structured.clone();
    if let Some(context) = structured.get_mut("standby_context") {
        scope_local_copy_status(context);
    }
    if source == "local_status" {
        scope_local_copy_status(structured);
    }
    structured["node_routing"] = json!({
        "read_source":source,
        "hosted_health":if checked {health.as_str()} else {"not_checked"},
        "canonical_writes":writes,
        "local_copy_writes":"unsupported",
    });
    if account_unverified {
        structured["node_routing"]["account_verified"] = json!(false);
    }
    if reauthenticate {
        structured["node_routing"]["reauthenticate"] = json!(true);
        structured["node_routing"]["next_step"] =
            json!("Run `native login` on this machine to re-authenticate the node, then retry.");
    }
    if let Some(standing) = standing {
        if let Some(routing) = structured
            .get_mut("node_routing")
            .and_then(Value::as_object_mut)
        {
            routing.insert("serving_head_act".into(), json!(standing.serving_head_act));
            routing.insert(
                "known_hosted_head_act".into(),
                json!(standing.known_hosted_head_act),
            );
            let comparable = standing.behind_known_write.is_some();
            let pair = standing
                .serving_head_act
                .zip(standing.known_hosted_head_act)
                .filter(|_| comparable);
            routing.insert(
                "revision_comparison".into(),
                json!({
                    "state": match pair {
                        Some((local, known)) if local < known => "behind_latest_known",
                        Some((local, known)) if local == known => "matches_latest_known",
                        Some(_) => "ahead_of_latest_known",
                        None => "unknown",
                    },
                    "known_lag_acts": pair.map(|(local, known)| known.saturating_sub(local).max(0)),
                    "last_successful_hosted_check_at": standing.last_successful_hosted_check_at,
                    "time_lag_seconds": Value::Null,
                    "current_lag_known": false,
                }),
            );
            routing.insert(
                "behind_known_write".into(),
                json!(standing.behind_known_write),
            );
            routing.insert(
                "own_write_floor_act".into(),
                json!(standing.own_write_floor_act),
            );
            routing.insert(
                "own_write_unresolved".into(),
                json!(standing.own_write_unresolved),
            );
            if let Some(reason) = standing.fallback_reason {
                routing.insert("read_fallback_reason".into(), json!(reason));
            }
        }
        // A copy below a head this node already knows is not "fresh", whatever
        // its age says.
        if standing.behind_known_write == Some(true) {
            if let Some(state) = structured.pointer_mut("/standby_context/freshness/state") {
                if state == "fresh" {
                    *state = json!("behind_hosted_head");
                }
            }
        }
    }
    // JSON format carries the same payload both as text and structuredContent.
    // Keep them consistent instead of leaving the misleading fields in text.
    let replacement = structured.to_string();
    if let Some(content) = result.get_mut("content").and_then(Value::as_array_mut) {
        for item in content {
            if item["type"] == "text"
                && item["text"].as_str().is_some_and(|text| {
                    serde_json::from_str::<Value>(text).ok().as_ref() == Some(&original)
                })
            {
                item["text"] = json!(replacement);
            }
        }
    }
    add_routing_text(response, &line, bootstrap_context.is_some());
}

/// Identity of the act numbering a hosted head belongs to. v2 heads carry the
/// genesis event, which a restore or re-cut replaces; v1 heads do not, so v1
/// is keyed by origin alone.
fn act_lineage(head: &crate::standby::delta_transport::AuthorityHead) -> String {
    match head {
        crate::standby::delta_transport::AuthorityHead::KernelV2(h) => format!(
            "v2:{}:{}",
            head.origin_database_id(),
            h.generation.genesis_event_id
        ),
        crate::standby::delta_transport::AuthorityHead::V1(_) => {
            format!("v1:{}", head.origin_database_id())
        }
    }
}

fn write_routing(health: Health, checked: bool) -> (&'static str, &'static str) {
    match (checked, health) {
        (true, Health::Unreachable) => (
            "unavailable",
            "Hosted is unreachable; canonical writes are unavailable. Nothing can write to the local copy. Any separately accepted pending write is not a canonical commit.",
        ),
        (true, Health::AuthRefused) => (
            "authentication_refused",
            "Hosted authentication was refused; writes require restored authentication. Nothing can write to the local copy.",
        ),
        (true, Health::ProtocolFailed) => (
            "forwarded_to_hosted_protocol_failed",
            "Writes route to hosted, but the hosted protocol failed; write availability is not established. Nothing can write to the local copy.",
        ),
        _ => (
            "forwarded_to_hosted",
            "Writes are forwarded to hosted Native, subject to hosted authorization and availability. The local copy's read-only status does not make this session read-only.",
        ),
    }
}

/// Keep bootstrap source/age/warnings beside the continuation key, ahead of
/// potentially long policy bodies. Only replace our generated second line;
/// never search or rewrite the exact instruction content below it.
fn add_routing_text(response: &mut Value, line: &str, bootstrap: bool) {
    if bootstrap {
        if let Some(value) = response.pointer_mut("/result/content/0/text") {
            if let Some((key, body)) = value
                .as_str()
                .and_then(|text| text.split_once('\n'))
                .filter(|(key, _)| key.starts_with("Run key: "))
            {
                let body = if body.starts_with("Read source: ") {
                    body.split_once('\n').map(|(_, rest)| rest).unwrap_or("")
                } else {
                    body
                };
                *value = json!(format!("{key}\n{line}\n{body}"));
                return;
            }
        }
    }
    add_text(response, line);
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
    compatibility: crate::client_compatibility::Monitor,
    client: reqwest::Client,
    endpoint: reqwest::Url,
    classification: Arc<std::sync::Mutex<Health>>,
    install_key: Option<crate::node_credential::InstallKey>,
}
impl AuthorityActHttpClient for ProbeHttp {
    fn call(&self, endpoint: String, bearer: String, body: Value) -> AuthorityCallFuture {
        let call = self.call_with_shape(endpoint, bearer, body);
        Box::pin(async move { Ok(call.await?.into_bytes()) })
    }

    fn call_with_shape(
        &self,
        _endpoint: String,
        bearer: String,
        body: Value,
    ) -> SelectedCallFuture {
        let client = self.client.clone();
        let compatibility = self.compatibility.clone();
        let endpoint = self.endpoint.clone();
        let classification = self.classification.clone();
        let install_key = self.install_key.clone();
        Box::pin(async move {
            let request = client
                .post(endpoint)
                .header(
                    crate::standby::shapes::ACCEPTED_SHAPES_HEADER,
                    crate::standby::shapes::advertisement(),
                )
                .header(
                    crate::client_compatibility::HEADER,
                    crate::client_compatibility::advertisement(),
                )
                .bearer_auth(bearer)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .json(&body);
            let mut response =
                crate::node_credential::send_request(&client, request, install_key.as_ref())
                    .await
                    .map_err(|_| {
                        *classification.lock().expect("probe classification") = Health::Unreachable;
                        Error::engine("node probe transport failed")
                    })?;
            let (family, operation) = super::compatibility_target(&body);
            response =
                crate::client_compatibility::inspect(response, &compatibility, &family, &operation)
                    .await?;
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
            if response
                .headers()
                .get("x-native-read-only")
                .is_some_and(|value| value == "true")
            {
                return Err(Error::engine(
                    crate::standby::delta_transport::MAINTENANCE_SNAPSHOT_ERROR,
                ));
            }
            let selected = crate::standby::delta_transport::selected_header(response.headers())?;
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
            Ok(SelectedResponse::new(bytes, selected))
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(in crate::node) fn enrollment_before_active_for_test(
    control: &crate::fork::working_v2::manager::WorkingControl,
    completed: Option<crate::standby::AcceptedKernelDelta>,
) {
    working_append::enrollment_before_active_for_test(control, completed);
}
