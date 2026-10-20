//! Optional execution-host saved-session worker.
//!
//! `sessions.json` is absent by default. Configured gated nodes discover
//! explicitly bound Save selections, serialize WebSocket I/O through a typed
//! mailbox, and drive bounded source windows into hosted Native. Each await
//! is fenced by the selected request revision; no prompt capability exists.
//! Host resets use separate durable stores and a narrow ended-state CAS.
//! Lifecycle and provider qualification use ephemeral fixture servers only.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use tokio::task::JoinHandle;

use crate::error::{Error, Result};

use super::daemon_client::{self, DaemonConnection, SAVER_CLIENT_ID, SAVER_CONTRACT};
use super::session_actor::{self, Command, DaemonHandle};
use super::session_control::{SaveRequest, StatusPublisher};
use super::session_identity::SaverIdentity;
use super::session_persist::Binding;

/// Sibling config file name, read from the node's working directory
/// (`socket_directory`). Absent means the saver is off.
pub const SESSIONS_FILE: &str = "sessions.json";
/// Local saver state directory name under the working directory.
pub const SESSIONS_STATE_DIR: &str = "sessions";
/// Default bound on spooled saver state (design §6.2).
pub const DEFAULT_PENDING_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
/// Reconnect backoff bounds: 1 s growing to 60 s (design §4.4).
pub const RECONNECT_MIN: Duration = Duration::from_secs(1);
pub const RECONNECT_MAX: Duration = Duration::from_secs(60);

/// Versioned saver config (`native.node.session-saver.v1`, design §4.1).
#[derive(Debug, Clone, Deserialize)]
pub struct SessionSaverConfig {
    /// Must equal [`SAVER_CONTRACT`].
    pub contract: String,
    pub daemon: DaemonRef,
    /// Hosted Saved-sessions folder id once created (S3); null until then.
    #[serde(default)]
    #[allow(dead_code)]
    pub saved_sessions_folder_id: Option<String>,
    /// Bound on pending saver state; defaults to 64 MiB.
    #[serde(default = "default_pending_limit")]
    pub pending_limit_bytes: u64,
}

fn default_pending_limit() -> u64 {
    DEFAULT_PENDING_LIMIT_BYTES
}

impl SessionSaverConfig {
    fn validate(&self) -> Result<()> {
        if self.contract != SAVER_CONTRACT {
            return Err(Error::engine(format!(
                "unsupported session saver contract: {}",
                self.contract
            )));
        }
        if self.daemon.paseo_home.trim().is_empty() {
            return Err(Error::engine("session saver daemon.paseo_home is empty"));
        }
        if self.pending_limit_bytes == 0 {
            return Err(Error::engine(
                "session saver pending_limit_bytes must be nonzero",
            ));
        }
        Ok(())
    }
}

/// Which daemon the saver follows.
#[derive(Debug, Clone, Deserialize)]
pub struct DaemonRef {
    /// `$PASEO_HOME`, with a leading `~` expanded. The listen address and the
    /// local credential are re-read from here before every connect.
    pub paseo_home: String,
}

/// Loaded saver: config plus resolved working paths.
#[derive(Debug, Clone)]
pub struct LoadedSaver {
    /// S3 seam: persistence reads folder id, limits, and daemon home from here.
    #[allow(dead_code)]
    pub config: SessionSaverConfig,
    /// Resolved `$PASEO_HOME`.
    pub paseo_home: PathBuf,
    /// `<socket_directory>/sessions/` (0700). S3 seam: spool and per-agent
    /// state live here.
    #[allow(dead_code)]
    pub state_dir: PathBuf,
}

/// Whether the gated write machinery the saver needs is compiled in.
/// The saver requires `mcp-executor-prototype` (WriteGate + journal); S1 must
/// refuse to enable the saver when that machinery is absent, visibly.
pub fn gate_available() -> bool {
    cfg!(feature = "mcp-executor-prototype")
}

/// Load the optional sibling config. `Ok(None)` when `sessions.json` is
/// absent: the saver is off (default). A present but invalid file, an
/// unsupported contract, or a missing gate build fails visibly.
pub fn load_session_saver(working_dir: &Path) -> Result<Option<LoadedSaver>> {
    let path = working_dir.join(SESSIONS_FILE);
    let raw = match std::fs::read(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Error::engine(format!(
                "cannot read session saver config: {e}"
            )));
        }
        Ok(raw) => raw,
    };
    if !gate_available() {
        return Err(Error::engine(
            "session saver requires the mcp-executor-prototype gate machinery, which is not compiled in",
        ));
    }
    let config: SessionSaverConfig = serde_json::from_slice(&raw)
        .map_err(|e| Error::engine(format!("invalid session saver config: {e}")))?;
    config.validate()?;
    let paseo_home = expand_home(&config.daemon.paseo_home);
    let state_dir = working_dir.join(SESSIONS_STATE_DIR);
    ensure_state_dir(&state_dir)?;
    Ok(Some(LoadedSaver {
        config,
        paseo_home,
        state_dir,
    }))
}

fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

#[cfg(unix)]
fn ensure_state_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| Error::engine(format!("cannot create saver state dir: {e}")))?;
    if !std::fs::symlink_metadata(dir)
        .map_err(|e| Error::engine(format!("cannot inspect saver state dir: {e}")))?
        .is_dir()
    {
        return Err(Error::engine("saver state directory must not be a symlink"));
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::engine(format!("cannot secure saver state dir: {e}")))?;
    Ok(())
}

#[cfg(not(unix))]
fn ensure_state_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)
        .map_err(|e| Error::engine(format!("cannot create saver state dir: {e}")))?;
    Ok(())
}

/// Running saver task. Dropping the handle does not stop the task; call
/// [`SaverHandle::shutdown`] during node shutdown.
pub struct SaverHandle {
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl SaverHandle {
    /// Signal shutdown and wait for the task to stop.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.task.await;
    }
}

/// Observe-only mode exists for transport fixtures and builds without the
/// write gate. The shipping gated node supplies the real hosted backend.
pub(super) enum SaverBackend {
    #[cfg(any(test, not(feature = "mcp-executor-prototype")))]
    ObserveOnly,
    #[cfg(feature = "mcp-executor-prototype")]
    Hosted {
        sink: std::sync::Arc<super::session_writer::GateSink>,
        registry: std::sync::Mutex<super::session_supervisor::HostRegistry>,
        started: std::time::Instant,
    },
}
#[cfg(feature = "mcp-executor-prototype")]
impl SaverBackend {
    pub(super) fn hosted(
        loaded: &LoadedSaver,
        account: &str,
        database: &str,
        sink: std::sync::Arc<super::session_writer::GateSink>,
    ) -> Result<Self> {
        Ok(Self::Hosted {
            sink,
            registry: std::sync::Mutex::new(super::session_supervisor::HostRegistry::new(
                &loaded.state_dir,
                account,
                database,
            )?),
            started: std::time::Instant::now(),
        })
    }
}

/// Spawn the saver reconnect loop. The loop re-reads `paseo.pid` and the local
/// credential before every connect attempt, backs off 1 s → 60 s between
/// attempts, and stops on shutdown. The backend supplies either the real
/// gated hosted writer or observe-only fixture plumbing.
pub(super) fn spawn_saver(
    loaded: LoadedSaver,
    account_id: &str,
    db_id: &str,
    backend: SaverBackend,
) -> Result<SaverHandle> {
    // Refuse a configured saver without an explicit account/database. The
    // server component comes only from the authenticated daemon handshake.
    Binding::new("pending-handshake", account_id, db_id, None)?;
    ensure_state_dir(&loaded.state_dir)?;
    let authority = SaverAuthority {
        account_id: account_id.to_owned(),
        db_id: db_id.to_owned(),
        identity: SaverIdentity::load(&loaded.state_dir)?,
        backend,
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(saver_loop(loaded, authority, shutdown_rx));
    Ok(SaverHandle { shutdown_tx, task })
}

struct SaverAuthority {
    account_id: String,
    db_id: String,
    // Consumed by the hosted writer integration; never regenerated at reconnect.
    #[allow(dead_code)]
    identity: SaverIdentity,
    backend: SaverBackend,
}

async fn saver_loop(
    loaded: LoadedSaver,
    authority: SaverAuthority,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut backoff = RECONNECT_MIN;
    loop {
        if *shutdown.borrow() {
            break;
        }
        match run_connected(&loaded, &authority, &mut shutdown).await {
            Ok(()) => {
                // Clean remote close: reconnect with backoff, re-reading the
                // credential (it rotates on every daemon start).
                backoff = RECONNECT_MIN;
            }
            Err(SaverStop::Shutdown) => break,
            Err(SaverStop::Retry) => {}
        }
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(backoff) => {},
        }
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

pub(super) enum SaverStop {
    Shutdown,
    Retry,
}

/// One connection lifetime: authenticate, discover, subscribe, then consume
/// events until the socket closes or shutdown arrives. Hosted workers share
/// this lifetime but never read or write the socket directly.
async fn run_connected(
    loaded: &LoadedSaver,
    authority: &SaverAuthority,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> std::result::Result<(), SaverStop> {
    // Re-read before every connect: the credential rotates on each daemon
    // start, and the listen target with it.
    let creds = match daemon_client::read_daemon_credentials(&loaded.paseo_home) {
        Ok(creds) => creds,
        Err(_) => return Err(SaverStop::Retry),
    };
    let mut conn = match DaemonConnection::connect(&creds).await {
        Ok(conn) => conn,
        Err(_) => return Err(SaverStop::Retry),
    };
    let binding = Binding::new(
        conn.server_id(),
        &authority.account_id,
        &authority.db_id,
        loaded.config.saved_sessions_folder_id.as_deref(),
    )
    .map_err(|_| SaverStop::Retry)?;
    let outcome = match &authority.backend {
        #[cfg(any(test, not(feature = "mcp-executor-prototype")))]
        SaverBackend::ObserveOnly => drive_connection(&mut conn, binding, shutdown).await,
        #[cfg(feature = "mcp-executor-prototype")]
        SaverBackend::Hosted {
            sink,
            registry,
            started,
        } => {
            let (store, old) = {
                let mut registry = registry.lock().map_err(|_| SaverStop::Retry)?;
                registry
                    .connect(binding.clone())
                    .map_err(|_| SaverStop::Retry)?
            };
            let limit =
                usize::try_from(loaded.config.pending_limit_bytes).map_err(|_| SaverStop::Retry)?;
            let supervisor = std::sync::Arc::new(super::session_supervisor::Supervisor::new(
                store,
                old,
                sink.clone(),
                authority.identity.clone(),
                limit,
                *started,
            ));
            let worker = supervisor.clone();
            let result =
                drive_connection_with_worker(&mut conn, binding, shutdown, move |handle| {
                    worker.run(handle)
                })
                .await;
            let _ = tokio::time::timeout(Duration::from_secs(30), supervisor.disconnected()).await;
            result
        }
    };
    // Bounded close: shutdown never hangs on the saver.
    let _ = conn.close().await;
    outcome
}

/// Observe-only connection driver for transport fixtures and ungated builds.
#[cfg(any(test, not(feature = "mcp-executor-prototype")))]
async fn drive_connection(
    conn: &mut DaemonConnection,
    binding: Binding,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> std::result::Result<(), SaverStop> {
    drive_connection_with_worker(conn, binding, shutdown, |handle| async move {
        // The hosted supervisor is wired after bounded source admission. Keep
        // its capability alive, but perform no hosted or daemon writes here.
        let _handle = handle;
        std::future::pending::<()>().await;
    })
    .await
}

pub(super) async fn drive_connection_with_worker<F, W>(
    conn: &mut DaemonConnection,
    binding: Binding,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    worker: F,
) -> std::result::Result<(), SaverStop>
where
    F: FnOnce(DaemonHandle) -> W,
    W: std::future::Future<Output = ()>,
{
    let (handle, mut mailbox) = session_actor::mailbox(binding.clone());
    let work = worker(handle);
    tokio::pin!(work);
    let mut commands_open = true;
    let mut publishers: HashMap<String, (session_actor::Selection, StatusPublisher)> =
        HashMap::new();
    let started = std::time::Instant::now();
    let mut request_seq: u64 = 0;
    let mut next_request_id = || {
        request_seq += 1;
        format!("{SAVER_CLIENT_ID}-{request_seq}")
    };
    // Initial discovery: fetch-all with a live subscription, paging to the
    // end before the snapshot replaces directory state (design §4.3).
    let initial_discovery = next_request_id();
    if conn
        .send_fetch_agents(&initial_discovery, None)
        .await
        .is_err()
    {
        return Err(SaverStop::Retry);
    }
    let mut pending_discovery = Some(initial_discovery);
    let mut discovery = Discovery::new(binding.clone());
    let mut subscribed: Vec<String> = Vec::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => return Err(SaverStop::Shutdown),
            _ = &mut work => return Err(SaverStop::Retry),
            command = mailbox.commands.recv(), if commands_open => {
                match command {
                    None => commands_open = false,
                    Some(Command::Fetch { agent, selection, cursor, reply }) => {
                        let id = next_request_id();
                        if mailbox.register(id.clone(), agent.clone(), selection, reply).is_ok()
                            && conn.send_timeline_fetch(&agent, &id, cursor.as_ref()).await.is_err()
                        {
                            return Err(SaverStop::Retry);
                        }
                    }
                    Some(Command::Status { agent, selection, status, reply }) => {
                        if reply.is_closed() { continue; }
                        if !mailbox.selected(&agent, &selection) {
                            let _ = reply.send(Err(Error::engine("status lost its Save authority")));
                            continue;
                        }
                        let request = SaveRequest::parse(&selection.label).expect("selected request");
                        let cached = publishers.entry(agent.clone())
                            .or_insert_with(|| (selection.clone(), StatusPublisher::default()));
                        if cached.0 != selection {
                            cached.0 = selection;
                            cached.1.revoke();
                        }
                        let publisher = &mut cached.1;
                        let tick = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                        let desired = publisher.request(&request, &binding).and_then(|_| publisher.next(&status, tick));
                        match desired {
                            Err(error) => { let _ = reply.send(Err(error)); }
                            Ok(None) => { let _ = reply.send(Ok(None)); }
                            Ok(Some(status)) => {
                                let label = status.label().map_err(|_| SaverStop::Retry)?;
                                let id = next_request_id();
                                if conn.send_status(&agent, &id, &label).await.is_err() {
                                    let _ = reply.send(Err(Error::engine("daemon status send failed")));
                                    return Err(SaverStop::Retry);
                                }
                                let settled = publisher.sent(&status, tick).map(|_| Some(status));
                                let _ = reply.send(settled);
                            }
                        }
                    }
                }
            }
            message = conn.next_message() => {
                match message {
                    Err(_) | Ok(None) => return Err(SaverStop::Retry),
                    Ok(Some(frame)) => {
                        let kind = daemon_client::inbound_kind(&frame);
                        if kind=="fetch_agents_response" {
                            if !pending_discovery.as_deref().is_some_and(|expected|frame.pointer("/payload/requestId").and_then(Value::as_str)==Some(expected)) {continue;}
                            pending_discovery=None;
                        } else if kind=="agent_list" { pending_discovery=None; }
                        let next = discovery.handle(&frame, &mut subscribed);
                        if discovery.failed {return Err(SaverStop::Retry);}
                        if discovery.ready && matches!(kind, "fetch_agents_response" | "agent_list" | "agent_update") {
                            mailbox.directory(&discovery.directory.snapshots).map_err(|_| SaverStop::Retry)?;
                        }
                        if kind == "fetch_agent_timeline_response" {
                            mailbox.response(&frame);
                        } else if matches!(kind, "agent_stream" | "agent.timeline.replacement") {
                            if let Some(agent) = frame.pointer("/payload/agentId").and_then(Value::as_str) {
                                mailbox.wake(agent, kind == "agent.timeline.replacement").map_err(|_| SaverStop::Retry)?;
                            }
                        }
                        if let Some(next) = next {
                            let id = next_request_id();
                            let sent = match next {
                                Outbound::Subscribe(ids) => {
                                    conn.send_timeline_subscription(&id, &ids).await
                                }
                                Outbound::FetchAgents { cursor } => {
                                    pending_discovery=Some(id.clone());
                                    conn.send_fetch_agents(&id, cursor.as_deref()).await
                                }
                                Outbound::FetchTimeline { agent, cursor } => {
                                    conn.send_timeline_fetch(&agent, &id, cursor.as_ref()).await
                                }
                            };
                            if sent.is_err() {
                                return Err(SaverStop::Retry);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Agent directory as the saver sees it: id → current labels. Seeded from the
/// full `fetch_agents_response` snapshot, then maintained incrementally from
/// `agent_update` upserts and removals. The subscription set is always derived
/// from this state — never from a single frame — so an update touching one
/// agent cannot drop the others.
#[derive(Debug, Default)]
struct AgentDirectory {
    agents: HashMap<String, HashMap<String, String>>,
    snapshots: HashMap<String, Value>,
}

impl AgentDirectory {
    /// Full snapshot: replaces the whole directory. Used for
    /// `fetch_agents_response` entries (`{agent, ...}`) and the legacy
    /// `agent_list` broadcast (`agents` snapshots).
    fn apply_snapshot(&mut self, snapshots: &[Value]) {
        let mut next = HashMap::new();
        for agent in snapshots
            .iter()
            .filter_map(daemon_client::SavableAgent::from_snapshot)
        {
            next.insert(agent.id, agent.labels);
        }
        self.snapshots = snapshots
            .iter()
            .filter_map(|snapshot| {
                let id = snapshot.get("id")?.as_str()?;
                next.contains_key(id)
                    .then(|| (id.to_owned(), snapshot.clone()))
            })
            .collect();
        self.agents = next;
    }

    /// Incremental `agent_update` payload: `upsert` replaces one entry,
    /// `remove` deletes one. Unknown shapes leave state untouched.
    fn apply_update(&mut self, payload: &Value) {
        match payload.get("kind").and_then(Value::as_str) {
            Some("upsert") => {
                if let Some(agent) = payload
                    .get("agent")
                    .and_then(daemon_client::SavableAgent::from_snapshot)
                {
                    self.snapshots
                        .insert(agent.id.clone(), payload["agent"].clone());
                    self.agents.insert(agent.id, agent.labels);
                }
            }
            Some("remove") => {
                if let Some(id) = payload.get("agentId").and_then(Value::as_str) {
                    self.agents.remove(id);
                    self.snapshots.remove(id);
                }
            }
            _ => {}
        }
    }

    /// Positively selected agents for this authenticated daemon binding.
    /// Label presence alone never admits a subscription or hosted writer.
    fn savable_ids(&self, binding: &Binding) -> Vec<String> {
        let mut ids: Vec<String> = self
            .agents
            .iter()
            .filter(|(id, labels)| {
                !self
                    .snapshots
                    .get(*id)
                    .is_some_and(super::session_control::agent_archived)
                    && labels
                        .get(daemon_client::SAVE_LABEL)
                        .and_then(|raw| SaveRequest::parse(raw))
                        .is_some_and(|request| request.authorizes_save(binding))
            })
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort();
        ids
    }
}

/// S3 will add per-agent catch-up pages behind the same boundary.
#[allow(dead_code)]
enum Outbound {
    Subscribe(Vec<String>),
    FetchAgents {
        cursor: Option<String>,
    },
    FetchTimeline {
        agent: String,
        cursor: Option<Value>,
    },
}

/// Discovery state: the agent directory plus an in-progress multi-page
/// snapshot. Pages accumulate until `pageInfo.hasMore` is false; only then
/// does the snapshot replace directory state. Incremental updates that arrive
/// mid-paging are buffered and replayed onto the fresh snapshot, so paging
/// can never truncate events the saver already saw.
#[derive(Debug)]
struct Discovery {
    binding: Binding,
    directory: AgentDirectory,
    pages: Vec<Value>,
    buffered: Vec<Value>,
    paging: bool,
    ready: bool,
    failed: bool,
}

impl Discovery {
    fn new(binding: Binding) -> Self {
        Self {
            binding,
            directory: AgentDirectory::default(),
            pages: Vec::new(),
            buffered: Vec::new(),
            // Subscribe begins with the initial fetch request, before its
            // first page arrives. Buffer updates throughout that window.
            paging: true,
            ready: false,
            failed: false,
        }
    }

    /// Fold one directory frame. Returns outbound plumbing when the savable
    /// set changed (including an explicit empty set on last Stop) or when
    /// the next snapshot page must be requested.
    fn handle(&mut self, frame: &Value, subscribed: &mut Vec<String>) -> Option<Outbound> {
        match daemon_client::inbound_kind(frame) {
            "fetch_agents_response" => {
                let p = &frame["payload"];
                let valid = p
                    .get("entries")
                    .and_then(Value::as_array)
                    .is_some_and(|rows| {
                        rows.iter().all(|r| {
                            r.pointer("/agent/id")
                                .and_then(Value::as_str)
                                .is_some_and(|id| !id.is_empty())
                        })
                    })
                    && p.pointer("/pageInfo/hasMore")
                        .is_some_and(Value::is_boolean)
                    && p.get("error").is_none_or(Value::is_null);
                if !valid {
                    self.failed = true;
                    self.ready = false;
                    return None;
                }
                let payload = frame.get("payload");
                let entries: Vec<Value> = payload
                    .and_then(|payload| payload.get("entries"))
                    .and_then(Value::as_array)
                    .map(|entries| {
                        entries
                            .iter()
                            .filter_map(|entry| entry.get("agent").cloned())
                            .collect()
                    })
                    .unwrap_or_default();
                self.pages.extend(entries);
                let page_info = payload.and_then(|payload| payload.get("pageInfo"));
                let has_more = page_info
                    .and_then(|info| info.get("hasMore"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if has_more {
                    self.paging = true;
                    match page_info
                        .and_then(|info| info.get("nextCursor"))
                        .and_then(Value::as_str)
                        .filter(|cursor| !cursor.is_empty())
                    {
                        Some(cursor) => {
                            return Some(Outbound::FetchAgents {
                                cursor: Some(cursor.to_owned()),
                            });
                        }
                        // Defensive: requesting the next page without a
                        // cursor would repeat the first page forever. Drop
                        // the partial snapshot and buffered updates instead
                        // of looping; incremental updates keep arriving and
                        // the next reconnect re-snapshots.
                        None => {
                            self.paging = false;
                            self.ready = false;
                            self.failed = true;
                            self.pages.clear();
                            self.buffered.clear();
                            return None;
                        }
                    }
                }
                // Snapshot complete: replace, then replay anything that
                // arrived while paging so no observed event is lost.
                self.paging = false;
                self.ready = true;
                let pages = std::mem::take(&mut self.pages);
                self.directory.apply_snapshot(&pages);
                let buffered = std::mem::take(&mut self.buffered);
                for payload in &buffered {
                    self.directory.apply_update(payload);
                }
            }
            "agent_list" => {
                if frame
                    .pointer("/payload/agents")
                    .and_then(Value::as_array)
                    .is_none_or(|rows| {
                        rows.iter().any(|a| {
                            a.get("id")
                                .and_then(Value::as_str)
                                .is_none_or(|id| id.is_empty())
                        })
                    })
                {
                    self.failed = true;
                    self.ready = false;
                    return None;
                }
                self.ready = true;
                let snapshots: Vec<Value> = frame
                    .pointer("/payload/agents")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                self.paging = false;
                self.pages.clear();
                self.buffered.clear();
                self.directory.apply_snapshot(&snapshots);
            }
            "agent_update" => {
                let payload = frame.get("payload").cloned()?;
                if self.paging {
                    self.buffered.push(payload);
                    return None;
                }
                self.directory.apply_update(&payload);
            }
            // Live rows and invalidation notices: S1 observes only. S2 curates
            // rows; S3 aligns on replacement with LCP from hosted state.
            _ => return None,
        }
        let fresh = self.directory.savable_ids(&self.binding);
        if *subscribed == fresh {
            None
        } else {
            *subscribed = fresh.clone();
            Some(Outbound::Subscribe(fresh))
        }
    }
}

/// Test-only single-frame compatibility shim over [`Discovery`]; the
/// connection loop uses `Discovery` directly.
#[cfg(test)]
fn handle_frame(
    frame: &Value,
    directory: &mut AgentDirectory,
    subscribed: &mut Vec<String>,
) -> Option<Outbound> {
    let mut discovery = Discovery::new(Binding::new("test-server", "x", "y", None).unwrap());
    discovery.directory = std::mem::take(directory);
    discovery.paging = false;
    let outbound = discovery.handle(frame, subscribed);
    *directory = discovery.directory;
    outbound
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_config_disables_saver() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_session_saver(dir.path()).unwrap().is_none());
    }

    #[test]
    fn invalid_config_fails_visibly() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SESSIONS_FILE), b"{not json").unwrap();
        assert!(load_session_saver(dir.path()).is_err());
    }

    #[test]
    fn wrong_contract_fails_visibly() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(SESSIONS_FILE),
            br#"{"contract":"other","daemon":{"paseo_home":"~/.x"}}"#,
        )
        .unwrap();
        assert!(load_session_saver(dir.path()).is_err());
    }

    #[test]
    fn valid_config_enables_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(SESSIONS_FILE),
            br#"{"contract":"native.node.session-saver.v1","daemon":{"paseo_home":"~/.local/share/paseo-pilot"}}"#,
        )
        .unwrap();
        let loaded = load_session_saver(dir.path()).unwrap().expect("enabled");
        assert!(loaded.state_dir.is_dir());
        assert_eq!(
            loaded.config.pending_limit_bytes,
            DEFAULT_PENDING_LIMIT_BYTES
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&loaded.state_dir)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[test]
    fn saver_requires_gate_machinery() {
        // The binary under test compiles with the gate; assert the wiring the
        // disabled build would refuse on: enabling needs the gate.
        assert_eq!(gate_available(), cfg!(feature = "mcp-executor-prototype"));
        if !cfg!(feature = "mcp-executor-prototype") {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join(SESSIONS_FILE),
                br#"{"contract":"native.node.session-saver.v1","daemon":{"paseo_home":"~"}}"#,
            )
            .unwrap();
            assert!(load_session_saver(dir.path()).is_err());
        }
    }

    #[test]
    fn frame_handler_tracks_directory_and_clears_on_last_stop() {
        // Real shapes: fetch_agents_response snapshot, agent_update
        // upsert/remove payloads.
        fn snapshot(id: &str, save: Option<&str>) -> Value {
            let mut labels = serde_json::Map::new();
            if let Some(save) = save {
                labels.insert("native.save".into(), save.into());
            }
            serde_json::json!({"id": id, "labels": Value::Object(labels)})
        }
        fn response(agents: Vec<Value>) -> Value {
            serde_json::json!({
                "type": "fetch_agents_response",
                "payload": {
                    "requestId": "r",
                    "entries": agents.into_iter().map(|agent| {
                        serde_json::json!({"agent": agent, "project": {}})
                    }).collect::<Vec<_>>(),
                    "pageInfo": {"nextCursor": null, "prevCursor": null, "hasMore": false},
                },
            })
        }
        fn update(payload: Value) -> Value {
            serde_json::json!({"type": "agent_update", "payload": payload})
        }

        let mut directory = AgentDirectory::default();
        let mut subscribed = Vec::new();

        // Snapshot with two savable agents subscribes to both.
        let frame = response(vec![
            snapshot(
                "a",
                Some("v1;acct=x;db=y;req=123e4567-e89b-12d3-a456-426614174000"),
            ),
            snapshot(
                "b",
                Some("v1;acct=x;db=y;req=223e4567-e89b-12d3-a456-426614174000"),
            ),
            snapshot("c", None),
        ]);
        assert!(matches!(
            handle_frame(&frame, &mut directory, &mut subscribed),
            Some(Outbound::Subscribe(_))
        ));
        assert_eq!(subscribed, vec!["a".to_owned(), "b".to_owned()]);

        // An update touching one agent must not drop the other.
        let frame = update(serde_json::json!({
            "kind": "upsert",
            "agent": snapshot("a", Some("v1;acct=x;db=y;req=123e4567-e89b-12d3-a456-426614174000")),
        }));
        assert!(handle_frame(&frame, &mut directory, &mut subscribed).is_none());
        assert_eq!(subscribed, vec!["a".to_owned(), "b".to_owned()]);

        // Archiving revokes subscriptions even if the Save label remains;
        // unarchiving can select it again through a fresh actor revision.
        let mut archived = snapshot(
            "a",
            Some("v1;acct=x;db=y;req=123e4567-e89b-12d3-a456-426614174000"),
        );
        archived["archivedAt"] = serde_json::json!("2026-10-18T00:00:00Z");
        handle_frame(
            &update(serde_json::json!({"kind":"upsert","agent":archived})),
            &mut directory,
            &mut subscribed,
        );
        assert_eq!(subscribed, vec!["b".to_owned()]);
        handle_frame(
            &update(
                serde_json::json!({"kind":"upsert","agent":snapshot("a",Some("v1;acct=x;db=y;req=123e4567-e89b-12d3-a456-426614174000"))}),
            ),
            &mut directory,
            &mut subscribed,
        );
        assert_eq!(subscribed, vec!["a".to_owned(), "b".to_owned()]);

        // Removing one agent refreshes to the remainder.
        let frame = update(serde_json::json!({"kind": "remove", "agentId": "a"}));
        assert!(matches!(
            handle_frame(&frame, &mut directory, &mut subscribed),
            Some(Outbound::Subscribe(_))
        ));
        assert_eq!(subscribed, vec!["b".to_owned()]);

        // The last Stop clears explicitly: an empty subscription, not silence.
        let frame = update(serde_json::json!({
            "kind": "upsert",
            "agent": snapshot("b", Some("off;req=3")),
        }));
        assert!(matches!(
            handle_frame(&frame, &mut directory, &mut subscribed),
            Some(Outbound::Subscribe(ref ids)) if ids.is_empty(),
        ));
        assert!(subscribed.is_empty());

        // Non-directory frames produce no outbound traffic and touch nothing.
        let dir_len = directory.agents.len();
        assert!(handle_frame(
            &serde_json::json!({"type": "agent_stream"}),
            &mut directory,
            &mut subscribed
        )
        .is_none());
        assert!(subscribed.is_empty());
        assert_eq!(directory.agents.len(), dir_len);
    }

    #[test]
    fn discovery_pages_to_completion_without_truncating_updates() {
        // Two-page snapshot: the first page must not replace state, and an
        // update arriving mid-paging must survive the final replace.
        fn snapshot(id: &str, save: Option<&str>) -> Value {
            let mut labels = serde_json::Map::new();
            if let Some(save) = save {
                labels.insert("native.save".into(), save.into());
            }
            serde_json::json!({"id": id, "labels": Value::Object(labels)})
        }
        fn page(entries: Vec<Value>, has_more: bool, cursor: Option<&str>) -> Value {
            serde_json::json!({
                "type": "fetch_agents_response",
                "payload": {
                    "requestId": "r",
                    "entries": entries.into_iter().map(|agent| {
                        serde_json::json!({"agent": agent, "project": {}})
                    }).collect::<Vec<_>>(),
                    "pageInfo": {
                        "nextCursor": cursor,
                        "prevCursor": null,
                        "hasMore": has_more,
                    },
                },
            })
        }

        let mut discovery = Discovery::new(Binding::new("test-server", "x", "y", None).unwrap());
        let mut subscribed = Vec::new();

        // Page one of two: requests the next page, emits no subscription.
        let next = discovery.handle(
            &page(
                vec![snapshot(
                    "a",
                    Some("v1;acct=x;db=y;req=123e4567-e89b-12d3-a456-426614174000"),
                )],
                true,
                Some("c1"),
            ),
            &mut subscribed,
        );
        assert!(
            matches!(next, Some(Outbound::FetchAgents { cursor }) if cursor == Some("c1".into()))
        );
        assert!(subscribed.is_empty());

        // An update landing mid-paging is buffered, not applied or emitted.
        let buffered = serde_json::json!({
            "type": "agent_update",
            "payload": {"kind": "upsert", "agent": snapshot("b", Some("v1;acct=x;db=y;req=223e4567-e89b-12d3-a456-426614174000"))},
        });
        assert!(discovery.handle(&buffered, &mut subscribed).is_none());
        assert!(subscribed.is_empty());

        // Final page: snapshot covers both pages plus the buffered update.
        let done = discovery.handle(
            &page(vec![snapshot("c", None)], false, None),
            &mut subscribed,
        );
        assert!(matches!(done, Some(Outbound::Subscribe(_))));
        assert_eq!(subscribed, vec!["a".to_owned(), "b".to_owned()]);
    }

    #[test]
    fn discovery_refuses_cursorless_continuation_instead_of_looping() {
        // hasMore=true with no nextCursor: requesting again would repeat the
        // first page forever. The partial snapshot is dropped and nothing is
        // emitted; later updates still apply incrementally.
        fn page_no_cursor(entries: Vec<Value>) -> Value {
            serde_json::json!({
                "type": "fetch_agents_response",
                "payload": {
                    "requestId": "r",
                    "entries": entries.into_iter().map(|agent| {
                        serde_json::json!({"agent": agent, "project": {}})
                    }).collect::<Vec<_>>(),
                    "pageInfo": {"nextCursor": null, "prevCursor": null, "hasMore": true},
                },
            })
        }
        fn snapshot(id: &str) -> Value {
            serde_json::json!({"id": id, "labels": {"native.save": "v1;acct=x;db=y;req=123e4567-e89b-12d3-a456-426614174000"}})
        }

        let mut discovery = Discovery::new(Binding::new("test-server", "x", "y", None).unwrap());
        let mut subscribed = Vec::new();
        assert!(discovery
            .handle(&page_no_cursor(vec![snapshot("a")]), &mut subscribed)
            .is_none());
        assert!(subscribed.is_empty());
        // Incremental updates still work afterwards.
        let update = serde_json::json!({
            "type": "agent_update",
            "payload": {"kind": "upsert", "agent": snapshot("b")},
        });
        assert!(matches!(
            discovery.handle(&update, &mut subscribed),
            Some(Outbound::Subscribe(_))
        ));
        assert_eq!(subscribed, vec!["b".to_owned()]);
    }

    #[test]
    fn bound_discovery_refuses_unbound_labels_and_revokes_changed_selection() {
        let mut discovery = Discovery::new(Binding::new("server", "x", "y", None).unwrap());
        let mut subscribed = Vec::new();
        let save = "v1;acct=x;db=y;req=123e4567-e89b-12d3-a456-426614174000";
        let labels = [
            ("matching", save),
            (
                "wrong-account",
                "v1;acct=other;db=y;req=123e4567-e89b-12d3-a456-426614174000",
            ),
            (
                "wrong-db",
                "v1;acct=x;db=other;req=123e4567-e89b-12d3-a456-426614174000",
            ),
            ("old-presence", "yes"),
            ("bad-request", "v1;acct=x;db=y;req=1"),
            ("stopped", "off;req=123e4567-e89b-12d3-a456-426614174000"),
        ];
        let agents: Vec<Value> = labels
            .into_iter()
            .map(|(id, label)| serde_json::json!({"id":id, "labels":{"native.save":label}}))
            .collect();
        let frame = serde_json::json!({"type":"agent_list", "payload":{"agents":agents}});
        assert!(matches!(
            discovery.handle(&frame, &mut subscribed),
            Some(Outbound::Subscribe(_))
        ));
        assert_eq!(subscribed, vec!["matching"]);
        let changed = serde_json::json!({"type":"agent_update", "payload":{"kind":"upsert", "agent":{
            "id":"matching", "labels":{"native.save":labels[1].1}
        }}});
        assert!(
            matches!(discovery.handle(&changed, &mut subscribed), Some(Outbound::Subscribe(ids)) if ids.is_empty())
        );
    }

    #[test]
    fn stop_before_first_snapshot_page_is_not_overwritten() {
        let mut discovery = Discovery::new(Binding::new("server", "x", "y", None).unwrap());
        let mut subscribed = Vec::new();
        let stop = serde_json::json!({"type":"agent_update", "payload":{"kind":"upsert", "agent":{
            "id":"agent", "labels":{"native.save":"off;req=223e4567-e89b-12d3-a456-426614174000"}
        }}});
        assert!(discovery.handle(&stop, &mut subscribed).is_none());
        let frame = serde_json::json!({"type":"fetch_agents_response", "payload":{
            "entries":[{"agent":{"id":"agent", "labels":{"native.save":"v1;acct=x;db=y;req=123e4567-e89b-12d3-a456-426614174000"}}}],
            "pageInfo":{"hasMore":false}
        }});
        assert!(discovery.handle(&frame, &mut subscribed).is_none());
        assert!(subscribed.is_empty());
        assert!(discovery
            .directory
            .savable_ids(&discovery.binding)
            .is_empty());
    }

    #[test]
    fn incomplete_or_refused_discovery_never_proves_an_empty_directory() {
        use serde_json::json;
        for payload in [
            json!({"entries":[],"pageInfo":{"hasMore":true}}),
            json!({"entries":[],"pageInfo":{"hasMore":false},"error":"refused"}),
            json!({"entries":[],"pageInfo":{}}),
        ] {
            let mut discovery = Discovery::new(Binding::new("server", "x", "y", None).unwrap());
            let mut subscribed = Vec::new();
            discovery.handle(
                &json!({"type":"fetch_agents_response","payload":payload}),
                &mut subscribed,
            );
            assert!(!discovery.ready);
            assert!(discovery.failed);
        }
    }

    #[test]
    fn state_directory_symlink_does_not_chmod_its_target() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let alias = dir.path().join("sessions");
        std::os::unix::fs::symlink(&target, &alias).unwrap();
        assert!(ensure_state_dir(&alias).is_err());
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[tokio::test]
    async fn connection_reader_retires_pending_fetch_on_stop_before_late_response() {
        use futures::{SinkExt, StreamExt};
        use serde_json::json;
        use tokio_tungstenite::tungstenite::Message;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            let hello = ws.next().await.unwrap().unwrap();
            assert!(matches!(hello, Message::Text(_)));
            ws.send(Message::Text(json!({"type":"session", "message":{"type":"status", "payload":{
                "status":"server_info", "protocolVersion":1, "serverId":"server", "hostname":"test", "version":"test", "permissions":{}
            }}}).to_string().into())).await.unwrap();
            let mut saw_fetch = false;
            while let Some(frame) = ws.next().await {
                let Message::Text(text) = frame.unwrap() else {
                    break;
                };
                let envelope: Value = serde_json::from_str(&text).unwrap();
                assert_eq!(envelope["type"], "session");
                let message = &envelope["message"];
                let response = match message["type"].as_str().unwrap() {
                    "fetch_agents_request" => {
                        Some(json!({"type":"fetch_agents_response", "payload":{
                            "requestId":message["requestId"],
                            "entries":[{"agent":{"id":"agent", "labels":{"native.save":"v1;acct=x;db=y;req=123e4567-e89b-12d3-a456-426614174000"}}}],
                            "pageInfo":{"hasMore":false}
                        }}))
                    }
                    "agent.timeline.set_subscription.request" => None,
                    "fetch_agent_timeline_request" => {
                        saw_fetch = true;
                        let stop = json!({"type":"agent_update", "payload":{"kind":"upsert", "agent":{
                            "id":"agent", "labels":{"native.save":"off;req=223e4567-e89b-12d3-a456-426614174000"}
                        }}});
                        ws.send(Message::Text(
                            json!({"type":"session", "message":stop}).to_string().into(),
                        ))
                        .await
                        .unwrap();
                        Some(json!({"type":"fetch_agent_timeline_response", "payload":{
                            "requestId":message["requestId"], "agentId":"agent"
                        }}))
                    }
                    unexpected => panic!("unexpected saver daemon write: {unexpected}"),
                };
                if let Some(response) = response {
                    if ws
                        .send(Message::Text(
                            json!({"type":"session", "message":response})
                                .to_string()
                                .into(),
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
            assert!(saw_fetch);
        });
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join("paseo.pid"),
            json!({"listen":address.to_string()}).to_string(),
        )
        .unwrap();
        std::fs::write(home.path().join("local-credential"), "a".repeat(43)).unwrap();
        let credentials = daemon_client::read_daemon_credentials(home.path()).unwrap();
        let mut connection = DaemonConnection::connect(&credentials).await.unwrap();
        let (_shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);
        let worker = |mut handle: DaemonHandle| async move {
            loop {
                let selected = handle
                    .view
                    .borrow()
                    .agents
                    .get("agent")
                    .map(|a| a.selection.clone());
                if let Some(selected) = selected {
                    assert!(handle.fetch("agent", &selected, None).await.is_err());
                    assert!(!handle.view.borrow().agents.contains_key("agent"));
                    break;
                }
                handle.view.changed().await.unwrap();
            }
        };
        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            drive_connection_with_worker(
                &mut connection,
                Binding::new("server", "x", "y", None).unwrap(),
                &mut shutdown,
                worker,
            ),
        )
        .await
        .expect("reader must process Stop while worker awaits its fetch");
        assert!(matches!(outcome, Err(SaverStop::Retry)));
        let _ = connection.close().await;
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn shutdown_stops_reconnect_loop() {
        // No daemon at this home: the loop backs off and retries until
        // shutdown arrives, then stops promptly.
        let home = tempfile::tempdir().unwrap();
        let loaded = LoadedSaver {
            config: SessionSaverConfig {
                contract: SAVER_CONTRACT.into(),
                daemon: DaemonRef {
                    paseo_home: home.path().to_string_lossy().into_owned(),
                },
                saved_sessions_folder_id: None,
                pending_limit_bytes: DEFAULT_PENDING_LIMIT_BYTES,
            },
            paseo_home: home.path().to_owned(),
            state_dir: home.path().join(SESSIONS_STATE_DIR),
        };
        let handle = spawn_saver(loaded, "account", "database", SaverBackend::ObserveOnly).unwrap();
        tokio::time::timeout(Duration::from_secs(10), handle.shutdown())
            .await
            .expect("saver stops on shutdown");
    }
}
