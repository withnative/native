//! Owner-local hosted MCP transport and conservative standby failover.

mod accept;
mod app_proof;
mod connection_binding;
mod maintenance;
pub mod oauth;
mod read_barrier;
mod shim;

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fs2::FileExt;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;

use crate::credential_file::{read_guarded_credential, validate_credential_path};
use crate::error::{Error, Result};

pub(crate) mod agent_sessions;
pub(crate) mod daemon_client;
// S3 seam: the persistence slice is the in-crate consumer of the curator.
// Until it lands, the whole module would read as dead code.
#[cfg(feature = "mcp-executor-prototype")]
mod changes;
#[cfg(feature = "mcp-executor-prototype")]
mod failover;
#[cfg(all(test, feature = "mcp-executor-prototype", feature = "v2-kernel-probe"))]
pub(crate) use failover::pre_read_act;
#[cfg(feature = "mcp-executor-prototype")]
mod gate;
#[cfg(feature = "mcp-executor-prototype")]
mod hold;
#[cfg(feature = "mcp-executor-prototype")]
mod hosted_events;
#[cfg(feature = "mcp-executor-prototype")]
mod journal;
#[cfg(all(feature = "mcp-executor-prototype", feature = "v2-kernel-probe"))]
pub(crate) use journal::working_v2;
#[cfg(feature = "mcp-executor-prototype")]
mod lineage;
#[cfg(feature = "mcp-executor-prototype")]
mod pending_fork;
#[allow(dead_code)]
pub(crate) mod session_persist;
#[cfg(feature = "mcp-executor-prototype")]
mod unmerged;
// S2 seam: the curator is consumed by the S3 persistence slice (fingerprint
// reuse today, full curation in S3b). Until then it would read as dead code.
#[allow(dead_code)]
pub(crate) mod session_projection;
pub(crate) mod session_quotes;
pub(crate) mod session_saver;
#[allow(dead_code)]
pub(crate) mod session_writer;
// Source catch-up preparation; daemon activation follows its admission.
#[allow(dead_code)]
pub(crate) mod session_actor;
#[allow(dead_code)]
pub(crate) mod session_catchup;
#[allow(dead_code)]
pub(crate) mod session_control;
#[allow(dead_code)]
pub(crate) mod session_hosted;
#[allow(dead_code)]
pub(crate) mod session_identity;
#[allow(dead_code)]
pub(crate) mod session_stream;
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) mod session_supervisor;
#[cfg(feature = "mcp-executor-prototype")]
use failover::{Failover, Health};

#[cfg(feature = "mcp-executor-prototype")]
use gate::WriteGate;
#[cfg(not(feature = "mcp-executor-prototype"))]
struct WriteGate;

#[cfg(not(feature = "mcp-executor-prototype"))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Health {
    Unreachable,
    AuthRefused,
    ProtocolFailed,
}

/// Transport provenance for read fallback; never a mutation retry decision.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum ReplyKind {
    #[default]
    Node,
    CanonicalRpc,
    ExplicitRefusal,
}

struct SendReport {
    reply: Option<String>,
    failure: Option<Health>,
    attempt: Attempt,
    /// The HTTP status hosted answered with, apart from whatever body came
    /// back (a framed JSON-RPC error body carries no status of its own).
    status: Option<u16>,
    reply_kind: ReplyKind,
}

impl SendReport {
    fn update_required(&self) -> Option<crate::client_compatibility::UpdateRequired> {
        crate::client_compatibility::classify(self.status, self.reply.as_deref()?.as_bytes())
    }
}

/// The time and cancellation bounds on one attempt of a retried write. One
/// absolute `deadline` covers everything the attempt does before and during
/// the send: OAuth renewal and its lock wait, then the request itself.
#[derive(Clone)]
struct Limits {
    deadline: std::time::Instant,
    attempt_timeout: Duration,
    /// Do not start a send with less than this left.
    min_attempt: Duration,
    cancel: Option<Cancel>,
    /// Scoped pending writes must use the credential whose account was verified,
    /// including after an OAuth renewal or filesystem replacement.
    custody_credential_sha256: Option<[u8; 32]>,
}

/// How one send ended, for a caller deciding whether a keyed write may be
/// sent again. Only `NotSent` and `Lost` are retryable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attempt {
    /// Hosted answered; the reply is passed through unchanged (including
    /// refusals, `DEPLOYMENT_READ_ONLY`, replay-bound and partial receipts).
    Answered,
    /// The connection failed before anything was sent.
    NotSent,
    /// A timeout, a dropped connection, a lost reply or a bare 502/503/504:
    /// the write may or may not have been applied.
    Lost,
    /// Outcome unknown, but not a condition worth retrying (a 2xx the node
    /// cannot read, an unexplained 5xx).
    Unclear,
    /// Nothing was sent and sending again will not help (credentials).
    Stopped,
}

/// Caller cancellation or disconnect. Stops further attempts; an attempt
/// already on the wire still finishes so the journal can record its outcome.
#[derive(Clone)]
struct Cancel(Arc<tokio::sync::watch::Sender<bool>>);

impl Cancel {
    fn new() -> Self {
        Self(Arc::new(tokio::sync::watch::channel(false).0))
    }
    fn cancel(&self) {
        self.0.send_replace(true);
    }
    fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }
    async fn cancelled(&self) {
        let mut receiver = self.0.subscribe();
        let _ = receiver.wait_for(|cancelled| *cancelled).await;
    }
}

/// What the node knows about who is calling, for the write journal.
struct Caller {
    client_info: Option<Value>,
    cancel: Cancel,
    /// When the request's frame arrived. A write's whole time budget runs from
    /// here, so time spent waiting for capacity counts against it.
    received: std::time::Instant,
    context: app_proof::RequestContext,
    /// The node connection this request arrived on. Reads use it to scope the
    /// own-write floor to the session that wrote (see `Failover::sessions`);
    /// `None` (internal callers) is treated as the node-wide floor.
    session: Option<u64>,
}

impl Caller {
    fn new(client_info: Option<Value>, cancel: Cancel) -> Self {
        Self {
            client_info,
            cancel,
            received: std::time::Instant::now(),
            context: Default::default(),
            session: None,
        }
    }
}

/// Process-unique id for one node connection.
fn next_session_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Requests tracked on one connection, so `notifications/cancelled` and a
/// dropped connection can stop a write's retries. One lock covers the cancel
/// flag, the registration and the connection's closed state, so "was it
/// cancelled?" and "stop tracking it" happen together, and anything
/// registered after the connection closed is cancelled from the start.
#[derive(Default)]
struct InFlight(std::sync::Mutex<InFlightState>);

#[derive(Default)]
struct InFlightState {
    closed: bool,
    next_anonymous: u64,
    requests: std::collections::HashMap<String, Cancel>,
}

impl InFlight {
    /// Track a request (notifications get an anonymous key). Returns the key
    /// to `finish` with and the request's cancel handle.
    fn register(&self, id: Option<&Value>) -> (String, Cancel) {
        let mut state = self.0.lock().expect("in-flight requests");
        let key = match id {
            Some(id) => id.to_string(),
            None => {
                state.next_anonymous += 1;
                format!("anonymous:{}", state.next_anonymous)
            }
        };
        let cancel = Cancel::new();
        if state.closed {
            cancel.cancel();
        }
        state.requests.insert(key.clone(), cancel.clone());
        (key, cancel)
    }
    /// Stop tracking a request; true if it had been cancelled by then.
    fn finish(&self, key: &str) -> bool {
        self.0
            .lock()
            .expect("in-flight requests")
            .requests
            .remove(key)
            .is_some_and(|cancel| cancel.is_cancelled())
    }
    fn cancel(&self, id: &Value) {
        if let Some(cancel) = self
            .0
            .lock()
            .expect("in-flight requests")
            .requests
            .get(&id.to_string())
        {
            cancel.cancel();
        }
    }
    /// The connection is gone: cancel everything tracked and everything
    /// registered from now on.
    fn close(&self) {
        let mut state = self.0.lock().expect("in-flight requests");
        state.closed = true;
        for cancel in state.requests.values() {
            cancel.cancel();
        }
    }
}

/// Node-wide limits on requests waiting for a connection's capacity. The
/// reader never waits for capacity: a request that cannot start is queued
/// within these limits, or refused at once as not sent. Nothing queued can
/// outlive its time budget, which runs from arrival.
struct Admission {
    restart: Option<Arc<tokio::sync::Notify>>,
    instance_id: String,
    max_queued: usize,
    max_queued_bytes: usize,
    /// How long a queued request may wait: the request budget less the
    /// shortest useful attempt.
    queue_wait: Duration,
    queued: std::sync::atomic::AtomicUsize,
    queued_bytes: std::sync::atomic::AtomicUsize,
}

impl Admission {
    fn new() -> Self {
        Self::with_limits(
            MAX_QUEUED,
            MAX_QUEUED_BYTES,
            REQUEST_BUDGET.saturating_sub(MIN_ATTEMPT),
        )
    }
    fn with_limits(max_queued: usize, max_queued_bytes: usize, queue_wait: Duration) -> Self {
        Self {
            restart: None,
            instance_id: uuid::Uuid::new_v4().to_string(),
            max_queued,
            max_queued_bytes,
            queue_wait,
            queued: Default::default(),
            queued_bytes: Default::default(),
        }
    }
    /// Reserve a queue place for a request of `bytes`, or None if either
    /// limit would be exceeded.
    fn reserve(self: &Arc<Self>, bytes: usize) -> Option<QueueSlot> {
        use std::sync::atomic::Ordering::AcqRel;
        let count = self.queued.fetch_add(1, AcqRel) + 1;
        let total = self.queued_bytes.fetch_add(bytes, AcqRel) + bytes;
        let slot = QueueSlot {
            admission: self.clone(),
            bytes,
        };
        // Dropping `slot` gives the reservation back when over a limit.
        (count <= self.max_queued && total <= self.max_queued_bytes).then_some(slot)
    }
}

struct QueueSlot {
    admission: Arc<Admission>,
    bytes: usize,
}

impl Drop for QueueSlot {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering::AcqRel;
        self.admission.queued.fetch_sub(1, AcqRel);
        self.admission.queued_bytes.fetch_sub(self.bytes, AcqRel);
    }
}

const SOCKET_NAME: &str = "node.sock";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_FRAME: usize = 8 * 1024 * 1024;
const MAX_IN_FLIGHT: usize = 64;
/// A request waits for capacity only within these node-wide limits (at most
/// 4 maximum-size frames), and never past its time budget.
const MAX_QUEUED: usize = 64;
const MAX_QUEUED_BYTES: usize = 32 * 1024 * 1024;
/// A write's whole time budget, from the arrival of its frame to its reply,
/// and the shortest attempt worth starting inside it. See `gate.rs` for why
/// 40 s: the shortest harness tool timeout is 60 s.
const REQUEST_BUDGET: Duration = Duration::from_secs(40);
const MIN_ATTEMPT: Duration = Duration::from_secs(2);
const DISCONNECT_POLL: Duration = Duration::from_millis(250);

/// One explicit (home, workspace) binding. Increment 1 serves exactly one.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub hosted_base_url: String,
    pub home_id: String,
    pub db_id: String,
    pub credential_file: PathBuf,
    pub socket_directory: PathBuf,
    /// Optional OAuth grant file for in-node renewal (increment 3a).
    /// When set, the node renews the bearer into `credential_file`.
    #[serde(default)]
    pub oauth_auth_file: Option<PathBuf>,
    /// Dedicated enrollment is explicit and stays in a separate credential
    /// directory. The legacy node does not load or send an install proof.
    #[serde(default)]
    pub node_install_key_file: Option<PathBuf>,
    /// The expected public key of an enrolled writer's durable install.
    #[serde(default)]
    pub node_install_id: Option<String>,
    #[serde(default)]
    pub standby_config: Option<PathBuf>,
    #[serde(default)]
    pub account_id: Option<String>,
    /// Same refresh configuration used by stdio standby; requires standby_config.
    #[serde(default)]
    pub refresh_config: Option<PathBuf>,
    /// Free-disk floor for holding writes, in bytes. Below the larger of this
    /// and twice the local copy's size the node refuses new writes it would
    /// otherwise hold. Defaults to 10 GiB.
    #[serde(default)]
    pub disk_floor_bytes: Option<u64>,
    /// Read-only vault, on by default next to the authorized local copy.
    /// Absent, null or `true` means the default `vault/` sibling of the
    /// standby `replica_root`. A string path overrides it. `false` turns it
    /// off. An explicit path still requires `standby_config`.
    #[serde(default, deserialize_with = "deserialize_markdown_folder")]
    pub markdown_folder: Option<MarkdownFolder>,
    /// Opt-in: while hosted is healthy, serve eligible reads from the local
    /// copy when it is provably at least as new as every write this node has
    /// seen acknowledged and no older than `max_age_seconds`. Absent means off
    /// and the node behaves exactly as without the option.
    #[serde(default)]
    pub online_local_reads: Option<OnlineLocalReads>,
    /// Accepted-only kernel-v2 reads use the local engine regardless of hosted
    /// reachability or RPO age. Unsafe/unavailable reads refuse explicitly;
    /// writes still require canonical admission. The legacy fresh preference
    /// remains available for a staged rollout.
    #[serde(default)]
    pub local_reads_by_default: bool,
    /// Preparation only: connection-bound desktop proof forwarding, off by default.
    #[serde(default)]
    pub desktop_app_proof_transport: bool,
    /// Explicit canonical MCP/OAuth resource origin; never inferred from forwarding.
    #[serde(default)]
    pub desktop_app_proof_resource_origin: Option<String>,
    /// Experimental, disposable pending-note previews. Absent/false is off.
    #[serde(default)]
    pub pending_fork_reads: bool,
    /// Off-default installed v2 plain-note append/Get proof. Pinned base only;
    /// canonical reconciliation pauses further acknowledgements until undo is qualified.
    #[serde(default)]
    pub working_note_appends: bool,
    /// Qualify install-scoped refusal recovery on a private working copy.
    #[serde(default)]
    pub working_refusal_drafts: bool,
    /// Operator declaration that hosted runs the kernel-v2 engine, for a node
    /// without `standby_config` (the hosted-only pass-through). Only the
    /// standby router's head probe observes the engine, so a routerless node
    /// otherwise treats hosted as v1: creates become holdable and the gate
    /// derives a record `id`, which kernel-v2 hosted refuses. The declaration
    /// can only turn holding and ID derivation off (fail closed) and grants
    /// nothing; a router's own observation replaces it. Absent or false keeps
    /// v1 semantics.
    #[serde(default)]
    pub hosted_kernel_v2: bool,
}

/// Offline declarations from the compiled codecs; no config is loaded here.
pub(crate) fn runtime_declarations() -> Value {
    #[cfg(feature = "mcp-executor-prototype")]
    let journal = journal::runtime_declaration();
    #[cfg(not(feature = "mcp-executor-prototype"))]
    let journal = json!({"family":"node_journal","decoder_compiled":false,
        "fresh_writer":"unavailable","retained_entry_rewrite":false,
        "required_features":["mcp-executor-prototype"]});
    #[cfg(feature = "mcp-executor-prototype")]
    let failover = failover::runtime_declaration();
    #[cfg(not(feature = "mcp-executor-prototype"))]
    let failover = json!({"family":"node_failover_state","decoder_compiled":false,
        "required_features":["mcp-executor-prototype"]});
    json!({"journal":journal,"failover_state":failover,
        "session":session_persist::runtime_declaration(),
        "connection_binding":connection_binding::runtime_declaration(),
        "configuration":{"reader":"NodeConfig","source":"src/node/mod.rs#NodeConfig",
            "envelope":"unversioned","unknown_fields":"reject",
            "compatibility":"new_optional_fields_can_break_older_strict_readers"}})
}

/// Shared vocabulary used by the codec owners, without a central version table.
fn format_declaration(
    family: &str,
    variant: &str,
    version: u64,
    decoder_compiled: bool,
    writers: (&str, bool),
    required_features: &[&str],
    continuation_conditions: &[&str],
) -> Value {
    json!({"family":family,"variant":variant,"version":version,
        "decoder_compiled":decoder_compiled,"fresh_writer":writers.0,
        "retained_entry_rewrite":writers.1,
        "required_features":required_features,"continuation_conditions":continuation_conditions})
}

/// `node.json` `online_local_reads` setting; presence turns the policy on.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OnlineLocalReads {
    /// Largest local-copy age, in seconds, that may answer a read online.
    pub max_age_seconds: u64,
}

/// `node.json` vault setting. `None` at the `NodeConfig` level means the
/// default path; `Some(Disabled)` is the off switch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MarkdownFolder {
    Disabled,
    Explicit(PathBuf),
}

fn deserialize_markdown_folder<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<MarkdownFolder>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    let value = Option::<Value>::deserialize(deserializer)?;
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(false)) => Ok(Some(MarkdownFolder::Disabled)),
        Some(Value::Bool(true)) => Ok(None),
        Some(Value::String(path)) => {
            if path.is_empty() {
                return Err(D::Error::custom(
                    "node markdown_folder must be an absolute path, got an empty string",
                ));
            }
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(D::Error::custom(format!(
                    "node markdown_folder must be an absolute path, got {}",
                    path.display()
                )));
            }
            Ok(Some(MarkdownFolder::Explicit(path)))
        }
        Some(Value::Number(_)) => Err(D::Error::custom(
            "node markdown_folder must be a path string, true, false or null, got a number",
        )),
        Some(Value::Array(_)) => Err(D::Error::custom(
            "node markdown_folder must be a path string, true, false or null, got an array",
        )),
        Some(Value::Object(_)) => Err(D::Error::custom(
            "node markdown_folder must be a path string, true, false or null, got an object",
        )),
    }
}

/// Apply the operator's engine declaration to a freshly opened gate. Called on
/// every start (the declaration is configuration, not persisted gate state);
/// a router constructed afterwards sets the flag from its own observation.
#[cfg(feature = "mcp-executor-prototype")]
fn apply_declared_upstream(gate: &gate::WriteGate, config: &NodeConfig) {
    if config.hosted_kernel_v2 {
        gate.declare_kernel_v2_upstream();
        // Kernel-v2 upstream drains only body merges, so writes held earlier
        // under v1 semantics are not sent while it is declared. Removing the
        // declaration on a kernel-v2 hosted is not a drain: they would be
        // resent with v1 derived ids, which v2 refuses.
        let pending = gate.journal.pending_count();
        if pending > 0 {
            tracing::warn!(
                target: "native_ce::node",
                pending,
                "hosted_kernel_v2 is declared while held writes are pending (body merges still drain). Other held writes are not sent while it stays set, and removing it on a kernel-v2 hosted would resend them with v1 derived ids that v2 refuses. Inspect them with node_status and settle them by hand; declare only when queue.pending is 0"
            );
        }
    }
}

/// The only way `serve` obtains its write gate: open it and apply the engine
/// declaration in one step, so no request can ever reach an undeclared gate.
#[cfg(feature = "mcp-executor-prototype")]
fn open_gate(config: &NodeConfig) -> Result<Arc<WriteGate>> {
    let gate = WriteGate::open(
        &config.socket_directory,
        gate::GateConfig {
            disk_floor_bytes: config.disk_floor_bytes.unwrap_or(gate::DEFAULT_DISK_FLOOR),
            record_url_base: Some(config.hosted_base_url.trim_end_matches('/').to_owned()),
            account_binding: Some(
                json!({"account_id":config.account_id,"database_id":config.db_id,
                "origin":config.hosted_base_url.trim_end_matches('/')}),
            ),
            ..gate::GateConfig::default()
        },
    )?;
    apply_declared_upstream(&gate, config);
    Ok(Arc::new(gate))
}

impl NodeConfig {
    pub(super) fn tracks_local_reads(&self) -> bool {
        self.local_reads_by_default || self.online_local_reads.is_some()
    }

    pub fn socket_path(&self) -> PathBuf {
        self.socket_directory.join(SOCKET_NAME)
    }

    fn endpoint(&self) -> Result<reqwest::Url> {
        if self.node_install_key_file.is_some()
            && (!cfg!(all(
                feature = "v2-kernel-probe",
                feature = "mcp-executor-prototype"
            )) || !self.hosted_kernel_v2
                || self.oauth_auth_file.is_none()
                || self.desktop_app_proof_transport)
        {
            return Err(Error::engine(
                "dedicated enrolled nodes require KernelV2 and an OAuth renewal grant",
            ));
        }
        if self.node_install_key_file.is_some()
            && self.working_note_appends
            && self.node_install_id.is_none()
        {
            return Err(Error::engine(
                "enrolled writes require the verified install id in node.json",
            ));
        }
        if self.node_install_id.is_some() && self.node_install_key_file.is_none() {
            return Err(Error::engine("enrolled install id has no configured key"));
        }
        if self.working_refusal_drafts
            && (!self.working_note_appends || self.node_install_id.is_none())
        {
            return Err(Error::engine(
                "working_refusal_drafts requires an enrolled working node",
            ));
        }
        if self.working_note_appends
            && (!cfg!(feature = "v2-kernel-probe")
                || self.standby_config.is_none()
                || !self.hosted_kernel_v2
                || self.pending_fork_reads)
        {
            return Err(Error::engine("working_note_appends needs v2-kernel-probe, a verified v2 standby, hosted_kernel_v2 and pending_fork_reads=false"));
        }
        if self.local_reads_by_default
            && (!cfg!(feature = "mcp-executor-prototype")
                || self.standby_config.is_none()
                || !self.hosted_kernel_v2
                || self.pending_fork_reads)
        {
            return Err(Error::engine(
                "local_reads_by_default requires a standby, hosted_kernel_v2 and pending_fork_reads=false",
            ));
        }
        if let Some(online) = self.online_local_reads {
            if online.max_age_seconds == 0
                || online.max_age_seconds > crate::standby::STANDBY_RPO_SECONDS
            {
                return Err(Error::engine(format!(
                    "node online_local_reads.max_age_seconds must be between 1 and {} (the standby RPO)",
                    crate::standby::STANDBY_RPO_SECONDS
                )));
            }
        }
        if self.home_id.trim().is_empty() || self.db_id.trim().is_empty() {
            return Err(Error::engine("node home_id and db_id must be nonempty"));
        }
        if self.db_id == "." || self.db_id == ".." || self.db_id.contains(['/', '\\']) {
            return Err(Error::engine(
                "node db_id must be one unambiguous route segment",
            ));
        }
        let mut url = reqwest::Url::parse(&self.hosted_base_url)
            .map_err(|_| Error::engine("invalid node hosted_base_url"))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::engine(
                "node requires an HTTP(S) base URL without credentials, query or fragment",
            ));
        }
        if self.node_install_key_file.is_some()
            && url.scheme() != "https"
            && !matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
        {
            return Err(Error::engine("enrolled node requests require HTTPS"));
        }
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| Error::engine("invalid node base URL path"))?;
            if self.node_install_key_file.is_some() {
                path.clear()
                    .extend(["internal", "node", "databases", &self.db_id, "mcp"]);
            } else {
                path.pop_if_empty().push("mcp").push(&self.db_id);
            }
        }
        Ok(url)
    }
}

struct Upstream {
    compatibility: crate::client_compatibility::Monitor,
    // This configuration is the state key: (home_id, db_id), N = 1.
    config: NodeConfig,
    endpoint: reqwest::Url,
    client: reqwest::Client,
    oauth: Option<std::sync::Arc<oauth::OAuthRenewer>>,
    install_key: Option<crate::node_credential::InstallKey>,
}

impl Upstream {
    fn new(config: NodeConfig, timeout: Duration) -> Result<Self> {
        let endpoint = config.endpoint()?;
        let install_key = config
            .node_install_key_file
            .as_deref()
            .map(crate::node_credential::InstallKey::load)
            .transpose()?;
        if let Some(expected) = &config.node_install_id {
            if install_key.as_ref().map(|key| key.id()).as_ref() != Some(expected) {
                return Err(Error::engine(
                    "configured install key changed; journal retained",
                ));
            }
        }
        read_guarded_credential(&config.credential_file, "node")?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(timeout)
            .build()
            .map_err(|_| Error::engine("cannot build node HTTP client"))?;
        let oauth = match &config.oauth_auth_file {
            Some(auth_path) => {
                oauth::check_install_grant(
                    auth_path,
                    oauth::TOKEN_ENDPOINT,
                    &endpoint.origin(),
                    install_key.is_some(),
                )?;
                let renew_client = oauth::renew_client()?;
                Some(std::sync::Arc::new(oauth::OAuthRenewer::new(
                    auth_path.clone(),
                    config.credential_file.clone(),
                    oauth::TOKEN_ENDPOINT.to_owned(),
                    renew_client,
                )))
            }
            None => None,
        };
        Ok(Self {
            compatibility: Default::default(),
            config,
            endpoint,
            client,
            oauth,
            install_key,
        })
    }

    #[cfg(test)]
    async fn send(
        &self,
        body: &str,
        message: &Value,
        revision: Option<&str>,
        id: Option<&Value>,
    ) -> Option<String> {
        self.send_classified(body, message, revision, id)
            .await
            .reply
    }

    async fn send_classified(
        &self,
        body: &str,
        message: &Value,
        revision: Option<&str>,
        id: Option<&Value>,
    ) -> SendReport {
        self.send_attempt(body, message, revision, id, None).await
    }

    /// One send. `limits` bounds it below the client default and makes it
    /// give up cleanly (nothing sent) at the deadline or on cancellation.
    async fn send_attempt(
        &self,
        body: &str,
        message: &Value,
        revision: Option<&str>,
        id: Option<&Value>,
        limits: Option<&Limits>,
    ) -> SendReport {
        self.send_attempt_context(body, message, revision, id, limits, None)
            .await
    }

    async fn send_classified_context(
        &self,
        body: &str,
        message: &Value,
        revision: Option<&str>,
        id: Option<&Value>,
        context: &app_proof::RequestContext,
    ) -> SendReport {
        self.send_attempt_context(body, message, revision, id, None, Some(context))
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_attempt_context(
        &self,
        body: &str,
        message: &Value,
        revision: Option<&str>,
        id: Option<&Value>,
        limits: Option<&Limits>,
        context: Option<&app_proof::RequestContext>,
    ) -> SendReport {
        if app_proof::header(&self.config, message, context).is_err() {
            return SendReport {
                reply: app_proof::refusal(message),
                failure: None,
                attempt: Attempt::Stopped,
                status: None,
                reply_kind: Default::default(),
            };
        }
        let mut failure = None;
        let mut attempt = Attempt::Answered;
        let mut status = None;
        let mut reply_kind = ReplyKind::Node;
        // Boxed: `send_inner`'s future is large and sits under `Failover::route`.
        let reply = Box::pin(self.send_inner(
            body,
            message,
            revision,
            id,
            limits,
            &mut failure,
            &mut attempt,
            &mut status,
            &mut reply_kind,
            context,
        ))
        .await;
        SendReport {
            reply,
            failure,
            attempt,
            status,
            reply_kind,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_inner(
        &self,
        body: &str,
        message: &Value,
        revision: Option<&str>,
        id: Option<&Value>,
        limits: Option<&Limits>,
        failure: &mut Option<Health>,
        attempt: &mut Attempt,
        answered_status: &mut Option<u16>,
        reply_kind: &mut ReplyKind,
        context: Option<&app_proof::RequestContext>,
    ) -> Option<String> {
        // Renewal happens only before a send, never as a retry: at-most-once.
        // A renewal failure is a credential problem, not an outage: report
        // not_sent and leave `failure` unset so failover is not triggered.
        if let Some(oauth) = &self.oauth {
            let renewal = match limits {
                Some(limits) => bounded(oauth.ensure_fresh_before_send(), limits).await,
                None => Ok(oauth.ensure_fresh_before_send().await),
            };
            match renewal {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    *attempt = Attempt::Stopped;
                    return frame_error(
                        id,
                        "OAuth grant rejected; request was not sent",
                        json!({"outcome":"not_sent","reason":"credential_refused","detail":error.to_string()}),
                    );
                }
                Err(reason) => {
                    *attempt = Attempt::Stopped;
                    return frame_error(
                        id,
                        &format!("Credential renewal {reason}; request was not sent"),
                        json!({"outcome":"not_sent","reason":"credential_renewal_failed"}),
                    );
                }
            }
        }
        // Read on every send: atomic replacement and in-place renewal both become
        // visible, and the guarded reader revalidates permissions each time.
        let token = match read_guarded_credential(&self.config.credential_file, "node") {
            Ok(token) => token,
            Err(_) => {
                *attempt = Attempt::Stopped;
                return frame_error(
                    id,
                    "Credential unavailable; request was not sent",
                    json!({"outcome":"not_sent","reason":"credential_refused"}),
                );
            }
        };
        if let Some(expected) = limits.and_then(|limits| limits.custody_credential_sha256) {
            use sha2::Digest;
            let actual: [u8; 32] = sha2::Sha256::digest(&*token).into();
            if actual != expected {
                *attempt = Attempt::Stopped;
                return frame_error(
                    id,
                    "Credential changed since its account was verified; pending write was not sent",
                    json!({"outcome":"not_sent","reason":"custody_credential_changed"}),
                );
            }
        }
        // Recompute what is left now, after any renewal and lock wait.
        let timeout = match limits {
            Some(limits) => {
                let left = limits
                    .deadline
                    .saturating_duration_since(std::time::Instant::now());
                if limits.cancel.as_ref().is_some_and(Cancel::is_cancelled) {
                    *attempt = Attempt::Stopped;
                    return frame_error(
                        id,
                        "Request cancelled; request was not sent",
                        json!({"outcome":"not_sent"}),
                    );
                }
                if left < limits.min_attempt {
                    *attempt = Attempt::Stopped;
                    return frame_error(
                        id,
                        "Retry budget exhausted before sending; request was not sent",
                        json!({"outcome":"not_sent"}),
                    );
                }
                Some(limits.attempt_timeout.min(left))
            }
            None => None,
        };
        // Check again after OAuth/queue waits; a hint never admits a call locally.
        let proof = match app_proof::header(&self.config, message, context) {
            Ok(proof) => proof,
            Err(()) => {
                *attempt = Attempt::Stopped;
                return app_proof::refusal(message);
            }
        };
        let mut request = self
            .client
            .post(self.endpoint.clone())
            .header(
                crate::client_compatibility::HEADER,
                crate::client_compatibility::advertisement(),
            )
            .bearer_auth(std::str::from_utf8(&token).expect("guarded UTF-8"))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .body(body.to_owned());
        if let Some(proof) = proof {
            request = request.header(app_proof::HEADER, proof);
        }
        if !crate::mcp::is_modern_request(message) {
            if let Some(revision) = revision {
                request = request.header("MCP-Protocol-Version", revision);
            }
        }
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let response = match crate::node_credential::send_request(
            &self.client,
            request,
            self.install_key.as_ref(),
        )
        .await
        {
            Ok(response) => response,
            Err(crate::node_credential::SendError::Proof) => {
                *attempt = Attempt::Stopped;
                return frame_error(
                    id,
                    "Node install proof unavailable; request was not sent",
                    json!({"outcome":"not_sent"}),
                );
            }
            Err(crate::node_credential::SendError::Http(error)) => {
                *failure = Some(Health::Unreachable);
                let outcome = if error.is_connect() || error.is_builder() {
                    "not_sent"
                } else {
                    "unknown"
                };
                *attempt = if error.is_builder() {
                    Attempt::Stopped
                } else if error.is_connect() {
                    Attempt::NotSent
                } else {
                    Attempt::Lost
                };
                return frame_error(
                    id,
                    if outcome == "not_sent" {
                        "Hosted connection failed before sending; nothing was sent"
                    } else {
                        "Hosted outcome unknown; check against hosted before retrying"
                    },
                    json!({"outcome":outcome}),
                );
            }
        };
        let status = response.status().as_u16();
        *answered_status = Some(status);
        if matches!(status, 401 | 403) {
            *failure = Some(Health::AuthRefused);
        }
        let bytes = match response.bytes().await {
            Ok(bytes) => bytes,
            Err(_) => {
                if (400..500).contains(&status) {
                    // A 4xx is hosted refusing the request (401/403 already
                    // marked auth above); losing its body does not make the
                    // write possibly-applied, so it is not retried.
                    *attempt = Attempt::Answered;
                    return frame_error(
                        id,
                        "Hosted refused the request; its reply body was lost",
                        json!({"http_status":status,"outcome":"refused"}),
                    );
                }
                if failure.is_none() {
                    *failure = Some(Health::Unreachable);
                }
                // A reply lost mid-body on a 2xx or gateway status is the
                // dropped connection a retry exists for; any other 5xx is not.
                *attempt = if (200..300).contains(&status) || matches!(status, 502..=504) {
                    Attempt::Lost
                } else {
                    Attempt::Unclear
                };
                return frame_error(
                    id,
                    "Hosted reply lost; check against hosted before retrying",
                    json!({"http_status":status,"outcome":"unknown"}),
                );
            }
        };
        let text = std::str::from_utf8(&bytes).ok();
        let reply = text.and_then(decode_reply);
        let observed_bytes = reply
            .as_ref()
            .map(|(raw, _)| raw.as_bytes())
            .unwrap_or(&bytes);
        let (family, operation) = compatibility_target(message);
        if let Some(mut update) = self
            .compatibility
            .observe(&family, &operation, Some(status), observed_bytes)
            .or_else(|| {
                // decode_reply already parsed the ordinary response. A known
                // update code outside the small refusal envelope may record
                // uncertainty, but cannot prove this mutation was unapplied.
                if !matches!(status, 401 | 403)
                    && reply
                        .as_ref()
                        .is_some_and(|(_, v)| crate::client_compatibility::is_candidate(v))
                {
                    self.compatibility.observe(
                        &family,
                        &operation,
                        Some(status),
                        br#"{"error_code":"client_update_required","outcome":"unknown"}"#,
                    )
                } else {
                    None
                }
            })
        {
            if reply
                .as_ref()
                .is_some_and(|(_, value)| value.get("jsonrpc").is_some() && value.get("id") != id)
            {
                update.definitely_unapplied = false;
            }
            *failure = None;
            *attempt = if update.definitely_unapplied {
                Attempt::Answered
            } else {
                Attempt::Unclear
            };
            *reply_kind = ReplyKind::ExplicitRefusal;
            return frame_error(
                id,
                "Client update demand recorded; updater unavailable",
                json!({
                    "error_code":crate::client_compatibility::UPDATE_REQUIRED,
                    "outcome":if update.definitely_unapplied {"refused"} else {"unknown"},
                    "applied":if update.definitely_unapplied {Value::Bool(false)} else {Value::Null},
                    "updater":"unavailable"
                }),
            );
        }
        if status == 202 && bytes.is_empty() && id.is_none() {
            return None;
        }
        if let Some((raw, value)) = reply {
            if is_rpc_reply(&value) {
                *reply_kind = ReplyKind::CanonicalRpc;
                // Compact only when framing demands it; already single-line replies
                // retain their exact bytes (including spaces and field ordering).
                return id.map(|_| {
                    let raw = raw.trim_end_matches(['\n', '\r']);
                    if raw.contains(['\n', '\r']) {
                        value.to_string()
                    } else {
                        raw.to_owned()
                    }
                });
            }
            // The explicit refusal contract is stronger than a semantic error
            // shape. Internal/transient errors may also carry error_code, so
            // that field alone never establishes a refusal.
            if value.get("outcome").and_then(Value::as_str) == Some("refused")
                && value.get("applied") == Some(&Value::Bool(false))
                && value
                    .get("error_code")
                    .and_then(Value::as_str)
                    .is_some_and(|code| !code.is_empty())
            {
                *reply_kind = ReplyKind::ExplicitRefusal;
            }
            let semantic = is_native_envelope(&value);
            *attempt = classify_unframed(status, semantic);
            if failure.is_none() {
                *failure = if matches!(status, 502..=504) && !semantic {
                    Some(Health::Unreachable)
                } else if (200..300).contains(&status) {
                    Some(Health::ProtocolFailed)
                } else {
                    None
                };
            }
            let mut data = match value.as_object() {
                Some(object) => object.clone(),
                None => serde_json::Map::new(),
            };
            // Preserve the complete body as well as exposing Native fields at the
            // data root for both {error: string, ...} and {error: {code, ...}}.
            data.insert("upstream_body".into(), value.clone());
            if let Some(error) = value.get("error").and_then(Value::as_object) {
                data.extend(error.clone());
            }
            data.insert("http_status".into(), json!(status));
            // Only a typed, definitely unapplied maintenance answer establishes
            // refusal. A gateway status or a contradictory partial/unknown body
            // cannot establish what happened to this write.
            let maintenance_refusal = status == 503
                && [Some(&value), value.get("error")]
                    .into_iter()
                    .flatten()
                    .any(|body| {
                        body.get("error_code")
                            .or_else(|| body.get("code"))
                            .and_then(Value::as_str)
                            == Some("DEPLOYMENT_READ_ONLY")
                    })
                && data.get("applied") == Some(&Value::Bool(false))
                && [Some(&value), value.get("error")]
                    .into_iter()
                    .flatten()
                    .all(|body| {
                        !has_uncertain_outcome(body)
                            && body.get("applied").is_none_or(|v| v == &Value::Bool(false))
                    });
            if maintenance_refusal {
                *reply_kind = ReplyKind::ExplicitRefusal;
                data.insert("outcome".into(), json!("refused"));
                return frame_error(
                    id,
                    "Hosted is temporarily read-only for maintenance; this attempt was not applied or queued",
                    Value::Object(data),
                );
            }
            data.entry("outcome").or_insert(json!("unknown"));
            return frame_error(id, "Hosted returned an HTTP error; check against hosted before retrying if outcome is unknown", Value::Object(data));
        }
        *attempt = classify_unframed(status, false);
        if failure.is_none() {
            *failure = if matches!(status, 502..=504) {
                Some(Health::Unreachable)
            } else if (200..300).contains(&status) {
                Some(Health::ProtocolFailed)
            } else {
                None
            };
        }
        frame_error(
            id,
            "Unrecognised hosted reply; check against hosted before retrying",
            json!({"http_status":status,"outcome":"unknown"}),
        )
    }
}

/// Positive evidence of an incomplete or unknown outcome, before interpreting
/// a refusal field elsewhere in the same hosted reply.
fn has_uncertain_outcome(body: &Value) -> bool {
    let conflicting_applied = body
        .get("applied")
        .and_then(Value::as_bool)
        .zip(body.pointer("/error/applied").and_then(Value::as_bool))
        .is_some_and(|(outer, inner)| outer != inner);
    conflicting_applied
        || body.get("partial") == Some(&Value::Bool(true))
        || body
            .get("applied")
            .is_some_and(|v| !v.is_boolean() && !v.is_null())
        || matches!(
            body.get("outcome").and_then(Value::as_str),
            Some("unknown" | "uncertain" | "partial")
        )
}

/// Whether a non-JSON-RPC body is Native's own answer, so that a gateway
/// status on it is hosted speaking rather than a proxy. Keyed to the fields
/// only Native's envelopes carry: `outcome`, `applied`, `partial`,
/// `error_code`, `recovery`, `retryable`. A bare `code` or `error` is not
/// enough: proxies and load balancers send `{"code":"ServiceUnavailable"}`
/// too, and treating that as an answer would stop retries on a plain outage.
fn is_native_envelope(value: &Value) -> bool {
    [value, value.get("error").unwrap_or(&Value::Null)]
        .iter()
        .any(|body| {
            body.get("outcome").is_some_and(Value::is_string)
                || body.get("applied").is_some_and(|value| !value.is_null())
                || body.get("partial").is_some_and(Value::is_boolean)
                || body.get("error_code").is_some_and(Value::is_string)
                || body.get("recovery").is_some_and(|v| !v.is_null())
                || body.get("retryable").is_some_and(Value::is_boolean)
        })
}

/// Run `work` inside the attempt's remaining time and cancellation. `Err`
/// carries why it did not finish.
async fn bounded<T>(
    work: impl std::future::Future<Output = T>,
    limits: &Limits,
) -> std::result::Result<T, &'static str> {
    let left = limits
        .deadline
        .saturating_duration_since(std::time::Instant::now());
    if let Some(cancel) = &limits.cancel {
        return tokio::select! {
            biased;
            _ = cancel.cancelled() => Err("cancelled"),
            done = tokio::time::timeout(left, work) => done.map_err(|_| "exceeded the retry budget"),
        };
    }
    tokio::time::timeout(left, work)
        .await
        .map_err(|_| "exceeded the retry budget")
}

/// Classify a reply that is not a JSON-RPC message. A Native-shaped body is
/// an answer whatever its status; otherwise 502/503/504 are the gateway
/// signals the node retries, 4xx is a refusal, and anything else is unclear.
fn classify_unframed(status: u16, native_shaped: bool) -> Attempt {
    if native_shaped || (400..500).contains(&status) {
        Attempt::Answered
    } else if matches!(status, 502..=504) {
        Attempt::Lost
    } else {
        Attempt::Unclear
    }
}

fn frame_error(id: Option<&Value>, message: &str, data: Value) -> Option<String> {
    id.map(|id| {
        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":message,"data":data}})
            .to_string()
    })
}

/// Frame node-built tool results through the same era-specific helper as hosted.
/// JSON-RPC errors and forwarded hosted replies retain their own envelopes.
#[cfg(feature = "mcp-executor-prototype")]
fn tool_reply(id: Option<&Value>, mut result: Value, modern: bool) -> Option<String> {
    if modern {
        crate::mcp::hosted_protocol::add_modern_result_fields(&mut result);
    }
    id.map(|id| json!({"jsonrpc":"2.0","id":id,"result":result}).to_string())
}

fn is_rpc_reply(value: &Value) -> bool {
    value.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && value
            .get("id")
            .is_some_and(|id| id.is_string() || id.is_i64() || id.is_u64() || id.is_null())
        && (value.get("result").is_some() ^ value.get("error").is_some())
        && value.get("error").is_none_or(|error| {
            error.get("code").is_some_and(|code| code.is_i64())
                && error.get("message").is_some_and(Value::is_string)
        })
}

fn decode_reply(text: &str) -> Option<(String, Value)> {
    if let Ok(value) = serde_json::from_str(text) {
        return Some((text.to_owned(), value));
    }
    // Defensively accept exactly one SSE message, including multiline data.
    let mut messages = Vec::new();
    let mut data = Vec::new();
    for line in text.lines().chain(std::iter::once("")) {
        if line.is_empty() {
            if !data.is_empty() {
                messages.push(data.join("\n"));
                data.clear();
            }
        } else if let Some(line) = line.strip_prefix("data:") {
            data.push(line.strip_prefix(' ').unwrap_or(line));
        } else if !line.starts_with(':')
            && !line.starts_with("event:")
            && !line.starts_with("id:")
            && !line.starts_with("retry:")
        {
            return None;
        }
    }
    if messages.len() != 1 {
        return None;
    }
    let raw = messages.pop()?;
    let value = serde_json::from_str(&raw).ok()?;
    Some((raw, value))
}

/// Held for the listener lifetime; flock serialises stale-socket removal/bind.
struct SocketGuard {
    path: PathBuf,
    identity: (u64, u64),
    _lock: File,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            if metadata.file_type().is_socket() && (metadata.dev(), metadata.ino()) == self.identity
            {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

fn owner_uid() -> u32 {
    // SAFETY: geteuid has no preconditions or pointer arguments.
    unsafe { libc::geteuid() }
}

fn check_owned(metadata: &fs::Metadata, mode: u32) -> Result<()> {
    if metadata.uid() != owner_uid() || metadata.permissions().mode() & 0o777 != mode {
        return Err(Error::engine(
            "node path must be owner-owned with restrictive permissions",
        ));
    }
    Ok(())
}

/// What the node demands of its socket directory when it already exists: a
/// real (non-symlinked) directory owned by this user with mode exactly 0700.
/// `Ok(false)` means it does not exist yet. `native setup` asks the same
/// question before it hands the directory to the node.
pub(crate) fn check_socket_directory(directory: &Path) -> Result<bool> {
    validate_credential_path(directory, "node socket directory")?;
    match fs::symlink_metadata(directory) {
        Ok(metadata) => {
            if !metadata.is_dir() {
                return Err(Error::engine("node socket directory is not a directory"));
            }
            check_owned(&metadata, 0o700)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

async fn bind_socket(config: &NodeConfig) -> Result<(UnixListener, SocketGuard)> {
    if !check_socket_directory(&config.socket_directory)? {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&config.socket_directory)?;
        fs::set_permissions(&config.socket_directory, fs::Permissions::from_mode(0o700))?;
    }
    let lock_path = config.socket_directory.join("node.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)?;
    let metadata = lock.metadata()?;
    check_owned(&metadata, 0o600)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(Error::engine("invalid node lock file"));
    }
    lock.try_lock_exclusive()
        .map_err(|_| Error::engine("a node already owns this socket directory"))?;
    let path = config.socket_path();
    let existing = match fs::symlink_metadata(&path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if let Some(metadata) = existing {
        if !metadata.file_type().is_socket() {
            return Err(Error::engine("refusing to remove a non-socket node path"));
        }
        check_owned(&metadata, 0o600)?;
        match UnixStream::connect(&path).await {
            Ok(_) => return Err(Error::engine("a live node already answers on this socket")),
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                let current = fs::symlink_metadata(&path)?;
                if (current.dev(), current.ino()) != (metadata.dev(), metadata.ino()) {
                    return Err(Error::engine("node socket changed during stale check"));
                }
                fs::remove_file(&path)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let metadata = fs::symlink_metadata(&path)?;
    let guard = SocketGuard {
        path,
        identity: (metadata.dev(), metadata.ino()),
        _lock: lock,
    };
    Ok((listener, guard))
}

async fn write_reply(
    writer: &Mutex<tokio::net::unix::OwnedWriteHalf>,
    reply: Option<String>,
) -> io::Result<()> {
    if let Some(reply) = reply {
        let mut writer = writer.lock().await;
        writer.write_all(reply.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }
    Ok(())
}

#[cfg(test)]
async fn serve_connection(stream: UnixStream, upstream: Arc<Upstream>) -> Result<()> {
    serve_connection_with_broker(stream, upstream, None).await
}

#[cfg(test)]
async fn serve_connection_with_broker(
    stream: UnixStream,
    upstream: Arc<Upstream>,
    broker: Option<Arc<agent_sessions::broker::AgentSessionsBroker>>,
) -> Result<()> {
    serve_routed_connection(
        stream,
        upstream,
        None,
        None,
        broker,
        Arc::new(Admission::new()),
    )
    .await
}

#[cfg(feature = "mcp-executor-prototype")]
type Router = Arc<Failover>;
#[cfg(not(feature = "mcp-executor-prototype"))]
type Router = ();

/// Saver writes join the own-write floor only when `online_local_reads` is
/// configured; otherwise they behave exactly as before that option existed.
#[cfg(feature = "mcp-executor-prototype")]
fn saver_floor(
    config: &NodeConfig,
    outage: Option<Arc<dyn gate::Outage>>,
) -> Option<Arc<dyn gate::Outage>> {
    config.tracks_local_reads().then_some(outage).flatten()
}

/// A present routing hint is a constraint, never a best-effort preference.
/// Refuse unknown values rather than accidentally forwarding a local request.
fn local_route(message: &Value) -> std::result::Result<bool, &'static str> {
    match message.pointer("/params/_meta/native~1route") {
        None => Ok(false),
        Some(Value::String(route)) if route == "local" => Ok(true),
        Some(_) => Err("Unsupported native/route; request was not sent"),
    }
}

fn route_refusal(message: &Value, reason: &'static str) -> Option<String> {
    frame_error(
        message.get("id"),
        reason,
        json!({"outcome":"not_sent","reason":"local_route_refused"}),
    )
}

/// Writes are journaled by the gate; without it (or its feature) the node
/// forwards exactly as slice 1 did.
#[allow(clippy::too_many_arguments)]
async fn route_message(
    upstream: &Upstream,
    router: Option<&Router>,
    gate: Option<&Arc<WriteGate>>,
    broker: Option<&Arc<agent_sessions::broker::AgentSessionsBroker>>,
    follow_ctx: &agent_sessions::routing::FollowCtx,
    body: &str,
    message: Value,
    revision: Option<&str>,
    direct: &std::sync::atomic::AtomicBool,
    caller: &Caller,
) -> (Option<String>, Option<agent_sessions::routing::PushRelease>) {
    // A batch carrying an agent-sessions call is refused whole: the
    // per-request push and slot accounting below only hold for single calls.
    // Other batches pass through untouched.
    if let Some(batch) = message.as_array() {
        let carries_session_tool = batch.iter().any(|item| {
            item.get("method").and_then(Value::as_str) == Some("tools/call")
                && item
                    .pointer("/params/name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| {
                        agent_sessions::is_agent_sessions_tool(name) || body_merge_local_tool(name)
                    })
        });
        if carries_session_tool {
            return (
                frame_error(
                    Some(&Value::Null),
                    "Local node controls do not accept batches; request was not sent",
                    json!({"outcome":"not_sent","reason":"batch_refused"}),
                ),
                None,
            );
        }
    }
    let local = match local_route(&message) {
        Ok(local) => local,
        Err(reason) => return (route_refusal(&message, reason), None),
    };
    // Agent-sessions tools are answered locally, like `node_status`, and are
    // never forwarded upstream — configured or not. The route check above
    // still applies: a refused route value refuses even these.
    if message.get("method").and_then(Value::as_str) == Some("tools/call") {
        if let Some(name) = message.pointer("/params/name").and_then(Value::as_str) {
            if body_merge_local_tool(name) {
                if app_proof::attributed(&message) {
                    return (
                        frame_error(
                            message.get("id"),
                            "Private recovery is available only to the device owner",
                            json!({"outcome":"not_sent","reason":"owner_only"}),
                        ),
                        None,
                    );
                }
                #[cfg(feature = "mcp-executor-prototype")]
                if let Some(gate) = gate {
                    return (gate.body_merge_control(&message).await, None);
                }
                return (
                    frame_error(
                        message.get("id"),
                        "Body-merge recovery is unavailable on this node",
                        json!({"outcome":"not_sent","reason":"node_unavailable"}),
                    ),
                    None,
                );
            }
            if agent_sessions::is_agent_sessions_tool(name) {
                let (reply, release) = agent_sessions::routing::handle_agent_sessions_tool(
                    broker,
                    follow_ctx,
                    &message,
                    crate::mcp::is_modern_request(&message),
                )
                .await;
                return (reply, release);
            }
        }
    }
    #[cfg(feature = "mcp-executor-prototype")]
    {
        if let Some(gate) = gate {
            if message.pointer("/params/name") == Some(&json!("node_status"))
                && message["method"] == "tools/call"
            {
                let filter = status_filter(message.pointer("/params/arguments"));
                let mut status = gate
                    .scoped_status(
                        &filter,
                        router.map(|router| router.as_ref() as &dyn gate::Outage),
                    )
                    .await;
                status["account_id"] = json!(upstream.config.account_id);
                status["client_compatibility"] = upstream.compatibility.status();
                status["desktop_app_proof_transport"] = caller.context.capability(&upstream.config);
                if let Some(router) = router {
                    status["hosted"] = router.hosted_summary().await;
                }
                return (
                    node_status_reply(
                        message.get("id"),
                        status,
                        crate::mcp::is_modern_request(&message),
                    ),
                    None,
                );
            }
            // Every bootstrap hears about the account backlog, including a
            // fresh conversation that does not have a run key yet.
            let bootstrap_run = failover::target(&message)
                .filter(|(executor, _, _)| executor == "bootstrap")
                .map(|(_, _, arguments)| {
                    arguments
                        .get("run_key")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .unwrap_or_default()
                });
            if let Some(run) = bootstrap_run {
                let reply = route_unnoted(
                    upstream,
                    router,
                    Some(gate),
                    body,
                    message,
                    revision,
                    direct,
                    caller,
                    local,
                )
                .await;
                let scoped = if let Some(router) = router {
                    gate::Outage::custody_binding(router.as_ref())
                        .await
                        .and_then(|binding| gate.scoped_v2_gate(&binding).ok())
                } else {
                    None
                };
                return (
                    reply.map(|reply| {
                        let mut gates: Vec<&gate::WriteGate> = vec![gate];
                        gates.extend(scoped.as_deref());
                        gate::WriteGate::note_held_writes_across(&gates, &reply, &run)
                    }),
                    None,
                );
            }
        }
    }
    (
        route_unnoted(
            upstream, router, gate, body, message, revision, direct, caller, local,
        )
        .await,
        None,
    )
}

fn body_merge_local_tool(name: &str) -> bool {
    #[cfg(feature = "mcp-executor-prototype")]
    {
        gate::body_merge_controls::is_tool(name)
    }
    #[cfg(not(feature = "mcp-executor-prototype"))]
    {
        matches!(
            name,
            "node_unmerged"
                | "node_unmerged_dismiss"
                | "node_lineage_retire"
                | "node_body_merge_forget"
        )
    }
}

#[allow(clippy::too_many_arguments)]
async fn route_unnoted(
    upstream: &Upstream,
    router: Option<&Router>,
    gate: Option<&Arc<WriteGate>>,
    body: &str,
    message: Value,
    revision: Option<&str>,
    direct: &std::sync::atomic::AtomicBool,
    caller: &Caller,
    local: bool,
) -> Option<String> {
    #[cfg(feature = "mcp-executor-prototype")]
    {
        if let Some(router) = router {
            return router.route(body, message, revision, direct, caller).await;
        }
        if local {
            return route_refusal(&message, "Local reader unavailable; request was not sent");
        }
        if let Some(gate) = gate {
            return Box::pin(gate.forward(
                upstream,
                &gate::WriteRequest {
                    body,
                    message: &message,
                    revision,
                    caller,
                    outage: None,
                    // App calls are online-only; never accept node custody.
                    no_hold: app_proof::attributed(&message),
                },
                false,
            ))
            .await
            .reply;
        }
    }
    #[cfg(not(feature = "mcp-executor-prototype"))]
    let _ = (router, gate, direct, caller);
    if local {
        return route_refusal(&message, "Local reader unavailable; request was not sent");
    }
    upstream
        .send_classified_context(body, &message, revision, message.get("id"), &caller.context)
        .await
        .reply
}

/// What a `node_status` call asks for: `run`, `parent_run`, `state` (one name
/// or a list) and `limit`. Not `run_key`: that is the caller's own run, which
/// every call carries.
#[cfg(feature = "mcp-executor-prototype")]
fn status_filter(arguments: Option<&Value>) -> journal::StatusFilter {
    let text = |field: &str| {
        arguments
            .and_then(|a| a.get(field))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let states = match arguments.and_then(|a| a.get("state")) {
        Some(Value::String(state)) => vec![state.clone()],
        Some(Value::Array(states)) => states
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    journal::StatusFilter {
        run: text("run"),
        parent_run: text("parent_run"),
        states,
        limit: arguments
            .and_then(|a| a.get("limit"))
            .and_then(Value::as_u64)
            .map_or(100, |n| n.min(500) as usize),
        newest_first: text("order").as_deref() == Some("newest_first"),
    }
}

#[cfg(feature = "mcp-executor-prototype")]
fn node_status_reply(id: Option<&Value>, status: Value, modern: bool) -> Option<String> {
    let text = serde_json::to_string_pretty(&status).unwrap_or_default();
    tool_reply(
        id,
        json!({
            "content":[{"type":"text","text":text}],
            "structuredContent":status,
            "isError":false,
        }),
        modern,
    )
}

/// Client identity for the journal: the connection's `initialize`
/// `clientInfo`, or the per-request `_meta` of stateless protocol revisions.
fn client_info_of(message: &Value, connection: &Option<Value>) -> Option<Value> {
    message
        .pointer("/params/_meta/io.modelcontextprotocol~1clientInfo")
        .cloned()
        .or_else(|| connection.clone())
}

async fn serve_routed_connection(
    stream: UnixStream,
    upstream: Arc<Upstream>,
    router: Option<Router>,
    gate: Option<Arc<WriteGate>>,
    broker: Option<Arc<agent_sessions::broker::AgentSessionsBroker>>,
    admission: Arc<Admission>,
) -> Result<()> {
    if stream.peer_cred()?.uid() != owner_uid() {
        return Err(Error::engine("node peer UID rejected"));
    }
    // A second handle on the same socket, only to notice the peer going away.
    // A half-close (the shim at stdin EOF) leaves the connection open and
    // waiting for replies; only a full close or reset raises POLLHUP.
    let std_stream = stream.into_std()?;
    let probe = std_stream.try_clone()?;
    let stream = UnixStream::from_std(std_stream)?;
    #[cfg(feature = "mcp-executor-prototype")]
    let proof_binding = match router.as_ref() {
        Some(router) => router.app_proof_binding().await,
        None => None,
    };
    #[cfg(not(feature = "mcp-executor-prototype"))]
    let proof_binding = None;
    let proof_connection = app_proof::Connection::new(proof_binding);
    let in_flight = Arc::new(InFlight::default());
    let session = next_session_id();
    let watcher = tokio::spawn({
        let in_flight = in_flight.clone();
        let proof_context = proof_connection.context();
        async move {
            use std::os::fd::AsRawFd;
            loop {
                tokio::time::sleep(DISCONNECT_POLL).await;
                let mut poll = libc::pollfd {
                    fd: probe.as_raw_fd(),
                    events: 0,
                    revents: 0,
                };
                // SAFETY: one valid pollfd, zero timeout; the fd outlives the call.
                let ready = unsafe { libc::poll(&mut poll, 1, 0) };
                if ready > 0 && poll.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                    proof_context.clear();
                    in_flight.close();
                    return;
                }
            }
        }
    });
    #[cfg(feature = "mcp-executor-prototype")]
    let session_router = router.clone();
    let result = serve_split_connection(
        stream,
        upstream,
        router,
        gate,
        broker,
        admission,
        in_flight.clone(),
        proof_connection,
        session,
    )
    .await;
    // Whatever ended the connection, nobody is waiting for retries any more.
    in_flight.close();
    #[cfg(feature = "mcp-executor-prototype")]
    if let Some(router) = session_router {
        router.forget_session(session);
    }
    watcher.abort();
    result
}

// Keep proof ownership explicit here so it ends with this socket's lifetime.
#[allow(clippy::too_many_arguments)]
async fn serve_split_connection(
    stream: UnixStream,
    upstream: Arc<Upstream>,
    router: Option<Router>,
    gate: Option<Arc<WriteGate>>,
    broker: Option<Arc<agent_sessions::broker::AgentSessionsBroker>>,
    admission: Arc<Admission>,
    in_flight: Arc<InFlight>,
    proof_connection: app_proof::Connection,
    session: u64,
) -> Result<()> {
    let peer_pid = stream.peer_cred()?.pid();
    let (read, write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let writer = Arc::new(Mutex::new(write));
    let follow_ctx = agent_sessions::routing::FollowCtx {
        writer: writer.clone(),
        follows: Arc::new(std::sync::Mutex::new(Vec::new())),
    };
    #[cfg(feature = "mcp-executor-prototype")]
    let mut changes_connection = changes::Connection::default();
    let barrier_permit = Arc::new(Semaphore::new(1));
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut tasks = JoinSet::new();
    let mut revision: Option<String> = None;
    let mut client_info: Option<Value> = None;
    let mut pinned_scope = None;
    let direct = Arc::new(std::sync::atomic::AtomicBool::new(false));
    loop {
        // Reap completed controls too, including streams containing no tool calls.
        while let Some(result) = tasks.try_join_next() {
            result.map_err(|_| Error::engine("node request task failed"))??;
        }
        // Bound a single frame without losing partial reads.
        let mut bytes = Vec::new();
        let read = (&mut reader).take((MAX_FRAME + 1) as u64);
        tokio::pin!(read);
        #[cfg(feature = "mcp-executor-prototype")]
        let count = tokio::select! {
            count = read.read_until(b'\n', &mut bytes) => count?,
            _ = changes_connection.failed() => return Err(Error::engine("node changes consumer disconnected or timed out")),
        };
        #[cfg(not(feature = "mcp-executor-prototype"))]
        let count = read.read_until(b'\n', &mut bytes).await?;
        if count == 0 {
            break;
        }
        if count > MAX_FRAME {
            return Err(Error::engine("node request frame exceeded bound"));
        }
        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        let body = match String::from_utf8(bytes) {
            Ok(body) => body,
            Err(_) => {
                write_reply(
                    &writer,
                    frame_error(
                        Some(&Value::Null),
                        "Invalid JSON",
                        json!({"outcome":"not_sent"}),
                    ),
                )
                .await?;
                continue;
            }
        };
        let message: Value = match serde_json::from_str(&body) {
            Ok(message) => message,
            Err(_) => {
                write_reply(
                    &writer,
                    frame_error(
                        Some(&Value::Null),
                        "Invalid JSON",
                        json!({"outcome":"not_sent"}),
                    ),
                )
                .await?;
                continue;
            }
        };
        if connection_binding::is_control(&message) {
            let actual = connection_binding::served_scope(&upstream, router.as_ref()).await;
            let result = connection_binding::dispatch(&message, actual, &mut pinned_scope);
            write_reply(&writer, result.reply).await?;
            if !result.accepted {
                break;
            }
            continue;
        }
        let scope_matches = match &pinned_scope {
            None => true,
            Some(expected) => {
                connection_binding::served_scope(&upstream, router.as_ref())
                    .await
                    .as_ref()
                    == Some(expected)
            }
        };
        if !scope_matches {
            write_reply(&writer, connection_binding::refusal(&message)).await?;
            break;
        }
        if let Some(method) = message
            .get("method")
            .and_then(Value::as_str)
            .filter(|method| method.starts_with("native/node/"))
        {
            let valid = message.get("jsonrpc") == Some(&json!("2.0"))
                && message
                    .get("id")
                    .is_some_and(|id| id.is_string() || id.is_number())
                && message
                    .get("params")
                    .is_none_or(|params| params == &json!({}));
            let result = if valid && method == "native/node/diagnostics" {
                Some(
                    json!({"contract":"native.node-diagnostics.v1", "pid":std::process::id(),
                    "instance_id":admission.instance_id,
                    "async_tasks":crate::async_diagnostics::snapshot(),
                    "restart_supported":admission.restart.is_some()}),
                )
            } else if valid && method == "native/node/restart" && admission.restart.is_some() {
                Some(json!({"contract":"native.node-restart.v1", "accepted":true,
                    "pid":std::process::id(), "instance_id":admission.instance_id, "connections_will_close":true}))
            } else {
                None
            };
            let restart = valid && method == "native/node/restart" && result.is_some();
            let reply = match result {
                Some(result) => {
                    Some(json!({"jsonrpc":"2.0", "id":message["id"], "result":result}).to_string())
                }
                None => frame_error(
                    message.get("id"),
                    "Local node control is unavailable or invalid",
                    json!({"outcome":"not_sent"}),
                ),
            };
            write_reply(&writer, reply).await?;
            if restart {
                if let Some(restart) = &admission.restart {
                    restart.notify_one();
                }
                break;
            }
            continue;
        }
        if read_barrier::is_control(&message) {
            if !read_barrier::valid(&message) {
                write_reply(
                    &writer,
                    read_barrier::error(&message, "barrier_unavailable"),
                )
                .await?;
                continue;
            }
            let permit = match barrier_permit.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    write_reply(&writer, read_barrier::error(&message, "barrier_busy")).await?;
                    continue;
                }
            };
            let deadline = tokio::time::Instant::now() + read_barrier::TIMEOUT;
            let (key, cancel) = in_flight.register(message.get("id"));
            let tracking = read_barrier::Tracking(in_flight.clone(), key);
            let context = proof_connection.context();
            let router = router.clone();
            let upstream = upstream.clone();
            let writer = writer.clone();
            tasks.spawn(async move {
                let _permit = permit;
                let _tracking = tracking;
                let reply = read_barrier::dispatch(
                    router.as_ref(),
                    &upstream.config,
                    &context,
                    &message,
                    &cancel,
                    deadline,
                )
                .await;
                // A blocked consumer cannot retain the control task indefinitely.
                tokio::time::timeout(Duration::from_secs(5), write_reply(&writer, reply))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "node barrier response timed out")
                    })?
            });
            continue;
        }
        if app_proof::is_control(&message) {
            write_reply(
                &writer,
                proof_connection.dispatch(&upstream.config, &message),
            )
            .await?;
            continue;
        }
        // Node-local extensions never enter upstream MCP, even in a batch.
        let changes_control = |item: &Value| {
            item.get("method")
                .and_then(Value::as_str)
                .is_some_and(|method| method.starts_with("native/changes/"))
        };
        if message
            .as_array()
            .is_some_and(|batch| batch.iter().any(changes_control))
        {
            write_reply(
                &writer,
                frame_error(
                    Some(&Value::Null),
                    "Node changes controls do not accept batches",
                    json!({"reason":"batch_refused","outcome":"not_sent"}),
                ),
            )
            .await?;
            continue;
        }
        if changes_control(&message) {
            #[cfg(feature = "mcp-executor-prototype")]
            changes_connection
                .dispatch(router.as_ref(), &writer, &message)
                .await?;
            #[cfg(not(feature = "mcp-executor-prototype"))]
            write_reply(
                &writer,
                frame_error(
                    message.get("id"),
                    "Node changes are unavailable",
                    json!({"reason":"changes_unavailable","outcome":"not_sent"}),
                ),
            )
            .await?;
            continue;
        }
        if message
            .get("method")
            .and_then(Value::as_str)
            .is_some_and(|method| method.starts_with(maintenance::PREFIX))
        {
            write_reply(
                &writer,
                maintenance::dispatch(gate.as_ref(), router.as_ref(), &message, peer_pid).await,
            )
            .await?;
            continue;
        }
        if message.get("method").and_then(Value::as_str) == Some("initialize") {
            client_info = message.pointer("/params/clientInfo").cloned();
            let mut caller = Caller::new(client_info.clone(), Cancel::new());
            caller.context = proof_connection.context();
            caller.session = Some(session);
            let (reply, _release) = route_message(
                &upstream,
                router.as_ref(),
                gate.as_ref(),
                broker.as_ref(),
                &follow_ctx,
                &body,
                message.clone(),
                revision.as_deref(),
                &direct,
                &caller,
            )
            .await;
            if let Some(value) = reply
                .as_deref()
                .and_then(|reply| serde_json::from_str::<Value>(reply).ok())
            {
                if let Some(negotiated) = value
                    .pointer("/result/protocolVersion")
                    .and_then(Value::as_str)
                {
                    revision = Some(negotiated.to_owned());
                }
            }
            write_reply(&writer, reply).await?;
            continue;
        }
        // The caller can withdraw a request it is still waiting on. That
        // stops a write's retries; it does not recall an attempt on the wire.
        if message.get("method").and_then(Value::as_str) == Some("notifications/cancelled") {
            if let Some(request_id) = message.pointer("/params/requestId") {
                in_flight.cancel(request_id);
            }
        }
        // The reader never waits for capacity, so a later
        // `notifications/cancelled` is always read. A request with no permit
        // free is queued within the node-wide limits and its time budget
        // (which runs from now), or refused immediately as not sent.
        let arrived = std::time::Instant::now();
        let request_id = message.get("id").cloned();
        let (permit, slot) = match permits.clone().try_acquire_owned() {
            Ok(permit) => (Some(permit), None),
            Err(tokio::sync::TryAcquireError::NoPermits) => match admission.reserve(body.len()) {
                Some(slot) => (None, Some(slot)),
                None => {
                    write_reply(
                        &writer,
                        frame_error(
                            request_id.as_ref(),
                            "Node busy: too many requests waiting; request was not sent",
                            json!({"outcome":"not_sent","reason":"node_busy"}),
                        ),
                    )
                    .await?;
                    continue;
                }
            },
            Err(_) => return Err(Error::engine("node shutting down")),
        };
        let (track, cancel) = in_flight.register(request_id.as_ref());
        let caller = Caller {
            client_info: client_info_of(&message, &client_info),
            cancel,
            received: arrived,
            context: proof_connection.context(),
            session: Some(session),
        };
        let upstream = upstream.clone();
        let writer = writer.clone();
        let revision = revision.clone();
        let router = router.clone();
        let gate = gate.clone();
        let broker = broker.clone();
        let follow_ctx = follow_ctx.clone();
        let direct = direct.clone();
        let in_flight = in_flight.clone();
        let permits = permits.clone();
        let queue_wait = admission.queue_wait;
        tasks.spawn(async move {
            let permit = match (permit, slot) {
                (Some(permit), _) => permit,
                (None, slot) => {
                    let waited = tokio::select! {
                        biased;
                        _ = caller.cancel.cancelled() => Err(true),
                        permit = permits.acquire_owned() => permit.map_err(|_| false),
                        _ = tokio::time::sleep_until((arrived + queue_wait).into()) => Err(false),
                    };
                    drop(slot);
                    match waited {
                        Ok(permit) => permit,
                        Err(cancelled) => {
                            // Never ran. Cancelled: no reply. Out of time: say so.
                            let cancelled = in_flight.finish(&track) || cancelled;
                            if cancelled {
                                return Ok(());
                            }
                            return write_reply(
                                &writer,
                                frame_error(
                                    request_id.as_ref(),
                                    "Node busy: waited too long for capacity; request was not sent",
                                    json!({"outcome":"not_sent","reason":"queue_timeout"}),
                                ),
                            )
                            .await;
                        }
                    }
                }
            };
            let _permit = permit;
            let (reply, release) = route_message(
                &upstream,
                router.as_ref(),
                gate.as_ref(),
                broker.as_ref(),
                &follow_ctx,
                &body,
                message.clone(),
                revision.as_deref(),
                &direct,
                &caller,
            )
            .await;
            // MCP: a cancelled request gets no reply.
            if in_flight.finish(&track) {
                // The reply is never written: dropping the release tears
                // the orphaned follow down without pushing anything.
                drop(release);
                return Ok(());
            }
            let outcome = write_reply(&writer, reply).await;
            // The follow reply is on the wire: pushes may flow now. A
            // dropped sender (cancelled write path above) cleans up instead.
            if let Some(release) = release {
                release.fire();
            }
            outcome
        });
        while let Some(result) = tasks.try_join_next() {
            result.map_err(|_| Error::engine("node request task failed"))??;
        }
    }
    #[cfg(feature = "mcp-executor-prototype")]
    drop(changes_connection);
    // EOF does not cancel an already sent request or cause a resend.
    while let Some(result) = tasks.join_next().await {
        result.map_err(|_| Error::engine("node request task failed"))??;
    }
    // Connection close ends its follows and frees their buffers.
    agent_sessions::routing::close_connection_follows(broker.as_ref(), &follow_ctx).await;
    Ok(())
}

/// Serve until SIGINT/SIGTERM. Shutdown never retries outstanding requests.
pub async fn serve(config: NodeConfig) -> Result<()> {
    serve_inner(config, None).await.map(|_| ())
}

async fn serve_inner(
    config: NodeConfig,
    restart: Option<Arc<tokio::sync::Notify>>,
) -> Result<bool> {
    let upstream = Arc::new(Upstream::new(config.clone(), REQUEST_TIMEOUT)?);
    let _install_lock = upstream
        .install_key
        .as_ref()
        .map(lock_install)
        .transpose()?;
    let (listener, _guard) = bind_socket(&config).await?;
    let mut listener = accept::Listener::new(listener)?;
    // Optional in-node renewal loop (increment 3a). When `oauth_auth_file`
    // is set, poll about every 45 s and renew when within 90 s of expiry.
    // The loop keeps `credential_file` fresh; the failover probe keeps
    // reading that file each time and needs no renewal of its own.
    if let Some(oauth) = upstream.oauth.clone() {
        tokio::spawn(oauth::renewal_loop(oauth));
    }
    // Saved-before-sent journal for forwarded writes. Opening it also turns
    // anything a previous process left in flight into an `uncertain` entry.
    #[cfg(feature = "mcp-executor-prototype")]
    let gate = Some(open_gate(&config)?);
    #[cfg(not(feature = "mcp-executor-prototype"))]
    let gate: Option<Arc<WriteGate>> = None;
    #[cfg(feature = "mcp-executor-prototype")]
    let housekeeping = gate.as_ref().map(|gate| {
        pending_fork::cleanup_stale_area(&config.socket_directory);
        if !config.pending_fork_reads {
            gate.disable_pending_fork();
        }
        WriteGate::spawn_housekeeping(gate)
    });
    #[cfg(feature = "mcp-executor-prototype")]
    let standby = failover::start_standby(&config, upstream.install_key.clone())?;
    #[cfg(feature = "mcp-executor-prototype")]
    if let (Some(gate), Some(standby)) = (&gate, &standby) {
        gate.set_copy_root(standby.replica_root.clone());
    }
    // Online local reads only: one SSE signal connection to hosted that asks
    // the refresh controller for a delta. Built here, spawned once the router
    // (which validates the endpoint) exists.
    #[cfg(feature = "mcp-executor-prototype")]
    let event_stream = standby
        .as_ref()
        .filter(|_| upstream.install_key.is_none())
        .and_then(|standby| standby.refresh.as_ref())
        .and_then(|refresh| hosted_events::EventStream::for_config(&upstream, refresh.hints()));
    #[cfg(feature = "mcp-executor-prototype")]
    let router = standby
        .as_ref()
        .map(|standby| {
            Failover::new(
                upstream.clone(),
                standby.supervisor.dispatcher(),
                standby.local.clone(),
                standby.origin.clone(),
            )
            .map(|router| {
                Arc::new(
                    router
                        .with_refresh_hints(standby.refresh.as_ref().map(|r| r.hints()))
                        .with_events(event_stream.as_ref().map(|stream| stream.status()))
                        .with_gate(gate.clone()),
                )
            })
        })
        .transpose()?;
    #[cfg(not(feature = "mcp-executor-prototype"))]
    let router: Option<Router> =
        if config.standby_config.is_some() || config.refresh_config.is_some() {
            return Err(Error::engine(
                "node standby requires mcp-executor-prototype",
            ));
        } else {
            None
        };
    #[cfg(feature = "mcp-executor-prototype")]
    let queue = gate.as_ref().map(|gate| {
        gate.spawn_queue(
            upstream.clone(),
            router.clone().map(|router| router as Arc<dyn gate::Outage>),
        )
    });
    #[cfg(feature = "mcp-executor-prototype")]
    let monitor = router.as_ref().map(|router| {
        tokio::spawn(crate::async_diagnostics::track(
            "node.hosted_monitor",
            router.clone().monitor(),
        ))
    });
    #[cfg(feature = "mcp-executor-prototype")]
    let events = router.as_ref().and(event_stream).map(|stream| {
        tokio::spawn(crate::async_diagnostics::track(
            "node.hosted_events",
            stream.run(),
        ))
    });
    #[cfg(feature = "mcp-executor-prototype")]
    let changes_observer = router.as_ref().map(|router| {
        tokio::spawn(crate::async_diagnostics::track(
            "node.observe_changes",
            router.clone().observe_changes(),
        ))
    });
    // Session saver: optional sibling `sessions.json` in the
    // node's working directory. Absent means off. Present but invalid, or
    // present without the gate machinery, fails serve visibly.
    let saver = session_saver::load_session_saver(&config.socket_directory)?
        .map(|loaded| {
            let account = config.account_id.as_deref().ok_or_else(|| {
                Error::engine("session saver requires an explicit node account_id")
            })?;
            #[cfg(feature = "mcp-executor-prototype")]
            let backend = session_saver::SaverBackend::hosted(
                &loaded,
                account,
                &config.db_id,
                Arc::new(
                    session_writer::GateSink::new(
                        upstream.clone(),
                        gate.as_ref()
                            .ok_or_else(|| Error::engine("session saver requires its write gate"))?
                            .clone(),
                    )
                    .with_floor(saver_floor(
                        &config,
                        router.clone().map(|router| router as Arc<dyn gate::Outage>),
                    )),
                ),
            )?;
            #[cfg(not(feature = "mcp-executor-prototype"))]
            let backend = session_saver::SaverBackend::ObserveOnly;
            session_saver::spawn_saver(loaded, account, &config.db_id, backend)
        })
        .transpose()?;
    // Agent-sessions broker: optional sibling `agent-sessions.json` in the
    // node's working directory. Absent means off. Present but invalid, or
    // present without an explicit node account_id, fails serve visibly. When
    // `remote: {"enabled": true}` the node also opens the hosted node channel;
    // absent or false means no connection attempt.
    let broker = agent_sessions::load_agent_sessions(
        &config.socket_directory,
        config.account_id.as_deref(),
    )?
    .map(|loaded| {
        let broker = agent_sessions::broker::AgentSessionsBroker::new(loaded.config);
        let task = tokio::spawn(broker.clone().run());
        (broker, task)
    });
    let remote_task = match broker.as_ref() {
        Some((broker, _)) if broker.config_remote_enabled() => {
            let url = agent_sessions::remote::RemoteEndpoint::connect_url_for(
                &config.hosted_base_url,
                &config.db_id,
            )?;
            let account_id = config.account_id.clone().ok_or_else(|| {
                crate::error::Error::engine(
                    "agent-sessions remote requires an explicit node account_id",
                )
            })?;
            let endpoint = agent_sessions::remote::RemoteEndpoint {
                url,
                credential_file: config.credential_file.clone(),
                account_id,
                socket_dir: config.socket_directory.clone(),
            };
            let channel = agent_sessions::remote::RemoteChannel::new(broker.clone(), endpoint);
            Some(tokio::spawn(channel.run()))
        }
        _ => None,
    };
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut connections = JoinSet::new();
    let mut admission = Admission::new();
    admission.restart = restart.clone();
    let admission = Arc::new(admission);
    let mut restarting = false;
    loop {
        tokio::select! {
            _ = async { match &restart {
                Some(restart) => restart.notified().await,
                None => std::future::pending::<()>().await,
            } } => { restarting = true; break; },
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
            accepted = listener.accept() => {
                let stream = accepted?;
                let upstream = upstream.clone();
                let router = router.clone();
                let gate = gate.clone();
                let broker = broker.as_ref().map(|(broker, _)| broker.clone());
                let admission = admission.clone();
                connections.spawn(async move { serve_routed_connection(stream, upstream, router, gate, broker, admission).await });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    let cleanup = async {
        // Stop connection tasks before draining the shared generation. No replay.
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        if let Some(saver) = saver {
            saver.shutdown().await;
        }
        if let Some((_, broker_task)) = broker {
            broker_task.abort();
        }
        if let Some(remote_task) = remote_task {
            remote_task.abort();
        }
        #[cfg(feature = "mcp-executor-prototype")]
        {
            if let Some(housekeeping) = housekeeping {
                housekeeping.abort();
            }
            if let Some(queue) = queue {
                queue.abort();
            }
            if let Some(events) = events {
                events.abort();
            }
            if let Some(observer) = changes_observer {
                observer.abort();
                let _ = observer.await;
            }
            if let Some(monitor) = monitor {
                monitor.abort();
                let _ = monitor.await;
            }
            if let Some(router) = &router {
                if let Err(error) = router.shutdown_pending_fork().await {
                    tracing::warn!(%error, "pending fork shutdown failed; continuing standby shutdown");
                }
            }
            if let Some(standby) = standby {
                standby.shutdown().await?;
            }
        }
        Ok::<(), Error>(())
    };
    if restarting {
        match tokio::time::timeout(Duration::from_secs(15), cleanup).await {
            Ok(Ok(())) => {},
            Ok(Err(_)) => tracing::warn!("node restart: graceful cleanup failed; replacing process; retained writes use normal crash recovery"),
            Err(_) => tracing::warn!("node restart: graceful shutdown exceeded 15s; replacing process; retained writes use normal crash recovery"),
        }
    } else {
        cleanup.await?;
    }
    Ok(restarting)
}

fn lock_install(key: &crate::node_credential::InstallKey) -> Result<fs::File> {
    // Resolve the account's home from the OS. A configurable data path,
    // private /tmp mount or service environment cannot give another daemon
    // a second lock namespace for this key.
    let mut account = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut stored = std::ptr::null_mut();
    let mut storage = vec![0u8; 64 * 1024];
    // SAFETY: the account and result pointers are valid writable slots, and
    // the storage remains live until the C string has been copied.
    let status = unsafe {
        libc::getpwuid_r(
            current_uid(),
            account.as_mut_ptr(),
            storage.as_mut_ptr().cast(),
            storage.len(),
            &mut stored,
        )
    };
    let invalid = || Error::engine("cannot resolve the node install lock home");
    if status != 0 || stored.is_null() {
        return Err(invalid());
    }
    // SAFETY: getpwuid_r succeeded and returned an initialized account
    // whose home pointer refers to its NUL-terminated response.
    let home = unsafe { (*stored).pw_dir };
    if home.is_null() {
        return Err(invalid());
    }
    // SAFETY: the OS returned a non-null C string for the account home.
    let home = unsafe { std::ffi::CStr::from_ptr(home) };
    use std::os::unix::ffi::OsStrExt;
    let home = Path::new(std::ffi::OsStr::from_bytes(home.to_bytes()));
    if !home.is_absolute() {
        return Err(invalid());
    }
    let home = fs::canonicalize(home)?;
    if fs::metadata(&home)?.uid() != current_uid() {
        return Err(invalid());
    }
    open_install_lock(&home.join(".native-install-locks"), &key.id())
}

fn open_install_lock(directory: &Path, install_id: &str) -> Result<fs::File> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    match fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(directory)?;
    check_owned(&metadata, 0o700)?;
    if !metadata.is_dir() {
        return Err(Error::engine("node install lock directory is unavailable"));
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(directory.join(install_id))?;
    let metadata = file.metadata()?;
    check_owned(&metadata, 0o600)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(Error::engine(
            "node install lock must be a private regular file",
        ));
    }
    fs2::FileExt::try_lock_exclusive(&file)
        .map_err(|_| Error::engine("another node process owns this installation"))?;
    Ok(file)
}

/// Byte-only stdio shim, with a write half-close at stdin EOF and reply drain.
/// The user id a node socket's peer must have: this process's own. Shared with
/// `native status`, which makes the same check before it talks to a node.
pub(crate) fn current_uid() -> u32 {
    owner_uid()
}

pub async fn connect<R, W>(socket: &Path, input: R, output: W) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    shim::connect(socket, input, output).await
}

/// See [`failover::TEST_CONSUMER_IDENTITY`].
#[cfg(all(test, feature = "mcp-executor-prototype"))]
pub(crate) fn set_test_consumer_identity(
    identity: Option<crate::standby_snapshot::ObservedInstalledConsumerIdentity>,
) {
    *failover::TEST_CONSUMER_IDENTITY.lock().unwrap() = identity;
}

/// Validate `node connect` flags without opening a socket. Excludes the `connect` word.
/// The native CLI uses this to preserve its usage-error exit status.
pub fn validate_connect_arguments(args: &[String]) -> Result<()> {
    connection_binding::parse_cli(args).map(|_| ())
}

pub async fn run_cli(args: &[String]) -> Result<()> {
    if args.first().is_some_and(|mode| mode == "connect") {
        let (socket, scope) = connection_binding::parse_cli(&args[1..])?;
        return match scope {
            Some(scope) => {
                shim::connect_bound(&socket, tokio::io::stdin(), tokio::io::stdout(), scope).await
            }
            None => connect(&socket, tokio::io::stdin(), tokio::io::stdout()).await,
        };
    }
    match args {
        [mode, flag, path] if mode == "serve" && flag == "--config" => {
            let bytes = fs::read(path)?;
            let config = serde_json::from_slice(&bytes)
                .map_err(|error| Error::engine(format!("invalid node config JSON: {error}")))?;
            let executable = std::env::current_exe()?;
            let restart = Arc::new(tokio::sync::Notify::new());
            if serve_inner(config, Some(restart)).await? {
                use std::os::unix::process::CommandExt;
                // Re-exec the process, retaining argv/env, regardless of its service manager.
                // serve_inner has dropped the socket lock; all remaining threads and FDs
                // are replaced by exec, including a stuck background worker.
                return Err(std::process::Command::new(executable)
                    .args(std::env::args_os().skip(1)).exec().into());
            }
            Ok(())
        }
        [mode, flag, path, rest @ ..] if mode == "journal" && flag == "--socket" => {
            maintenance::cli(Path::new(path), rest).await
        }
        [mode, flag, path, rest @ ..]
            if mode == "agent-sessions" && flag == "--socket" =>
        {
            agent_sessions_cli(Path::new(path), rest).await
        }
        _ => Err(Error::engine(
            "usage: mcp-stdio node serve --config <file> | mcp-stdio node connect --socket <path> [--expect-account <principal> --expect-database <id> --expect-origin <origin>] | mcp-stdio node journal --socket <path> <acknowledge|withdraw|show|settle_original> ... | mcp-stdio node agent-sessions --socket <path> <capabilities|list|history|follow> ...",
        )),
    }
}

/// Read-only agent-sessions CLI over the node socket. Connects like `node
/// connect` and prints one JSON line per reply (plus pushed events for
/// `follow`, then an `unfollow`).
async fn agent_sessions_cli(socket: &Path, args: &[String]) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;
    let stream = UnixStream::connect(socket).await?;
    if stream.peer_cred()?.uid() != owner_uid() {
        return Err(Error::engine("node server UID rejected"));
    }
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut next_id: i64 = 0;
    macro_rules! call {
        ($name:expr, $arguments:expr) => {{
            next_id += 1;
            cli_tool_call(&mut write, &mut reader, next_id, $name, $arguments).await?
        }};
    }
    let (command, flags) = match args.split_first() {
        Some((command, flags)) => (command.as_str(), flags),
        None => {
            return Err(Error::engine(
                "usage: mcp-stdio node agent-sessions --socket <path> <capabilities|list|history|follow> ...",
            ));
        }
    };
    let flag = |key: &str| -> Option<String> {
        flags
            .windows(2)
            .find(|pair| pair[0] == format!("--{key}"))
            .and_then(|pair| pair[1].clone().into())
    };
    match command {
        "capabilities" => {
            let reply = call!("node_agent_sessions_capabilities", json!({}));
            print_reply(&reply);
        }
        "list" => {
            let mut arguments = json!({});
            if let Some(cursor) = flag("cursor") {
                arguments["cursor"] = cursor.into();
            }
            let reply = call!("node_agent_sessions_list", arguments);
            print_reply(&reply);
        }
        "history" => {
            let (Some(host), Some(epoch), Some(session)) =
                (flag("host"), flag("epoch"), flag("session"))
            else {
                return Err(Error::engine(
                    "usage: ... history --host <id> --epoch <epoch> --session <id> [--cursor <c>] [--limit <n>]",
                ));
            };
            let mut arguments = json!({
                "hostId": host,
                "hostEpoch": epoch,
                "sessionId": session,
            });
            if let Some(cursor) = flag("cursor") {
                arguments["cursor"] = cursor.into();
            }
            if let Some(limit) = flag("limit") {
                let limit: u64 = limit
                    .parse()
                    .map_err(|_| Error::engine("history --limit must be an integer"))?;
                arguments["limit"] = limit.into();
            }
            let reply = call!("node_agent_sessions_history", arguments);
            print_reply(&reply);
        }
        "follow" => {
            let (Some(host), Some(epoch), Some(session)) =
                (flag("host"), flag("epoch"), flag("session"))
            else {
                return Err(Error::engine(
                    "usage: ... follow --host <id> --epoch <epoch> --session <id> [--seconds <n>]",
                ));
            };
            let seconds: u64 = flag("seconds")
                .map(|s| {
                    s.parse()
                        .map_err(|_| Error::engine("follow --seconds must be an integer"))
                })
                .transpose()?
                .unwrap_or(30);
            let reply = call!(
                "node_agent_sessions_follow",
                json!({
                    "hostId": host,
                    "hostEpoch": epoch,
                    "sessionId": session,
                })
            );
            print_reply(&reply);
            let subscription = reply
                .pointer("/result/structuredContent/subscriptionId")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
            // Stream pushed events until the deadline, then unfollow.
            loop {
                let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                if left.is_zero() {
                    break;
                }
                match tokio::time::timeout(left, read_reply_line(&mut reader)).await {
                    Err(_) => break,
                    Ok(Err(_)) => break,
                    Ok(Ok(event)) => print_reply(&event),
                }
            }
            if let Some(subscription) = subscription {
                let reply = call!(
                    "node_agent_sessions_unfollow",
                    json!({"subscriptionId": subscription})
                );
                print_reply(&reply);
            }
            let _ = write.shutdown().await;
        }
        _ => {
            return Err(Error::engine(
                "usage: mcp-stdio node agent-sessions --socket <path> <capabilities|list|history|follow> ...",
            ));
        }
    }
    Ok(())
}

async fn cli_tool_call(
    write: &mut tokio::net::unix::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    id: i64,
    name: &str,
    arguments: Value,
) -> Result<Value> {
    use tokio::io::AsyncWriteExt as _;
    let frame = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    });
    let mut line = serde_json::to_string(&frame)
        .map_err(|e| Error::engine(format!("agent-sessions request did not serialize: {e}")))?;
    line.push('\n');
    write
        .write_all(line.as_bytes())
        .await
        .map_err(|e| Error::engine(format!("agent-sessions send failed: {e}")))?;
    read_reply_line(reader).await
}

async fn read_reply_line(reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>) -> Result<Value> {
    let mut line = String::new();
    let count = reader
        .read_line(&mut line)
        .await
        .map_err(|e| Error::engine(format!("agent-sessions read failed: {e}")))?;
    if count == 0 {
        return Err(Error::engine("agent-sessions connection closed"));
    }
    serde_json::from_str(line.trim())
        .map_err(|e| Error::engine(format!("agent-sessions reply was not JSON: {e}")))
}

fn print_reply(reply: &Value) {
    println!(
        "{}",
        serde_json::to_string(reply).unwrap_or_else(|_| "{}".into())
    );
}

#[cfg(test)]
mod tests;

/// Request-side scope only. Server fields cannot widen a failed operation.
fn compatibility_target(message: &Value) -> (String, String) {
    #[cfg(feature = "mcp-executor-prototype")]
    if let Some((executor, operation, _)) = failover::target(message) {
        return (executor, operation);
    }
    (
        "mcp".into(),
        message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .into(),
    )
}
