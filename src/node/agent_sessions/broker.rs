//! Broker worker: the node's own daemon connection with reconnect, the host
//! table, and the read-only list/history/follow operations.
//!
//! Slice 1 follows Desktop's broker semantics (`daemon.ts` list + 1 s tail
//! poll with diff) over the broker's own connection (`clientId:
//! "native-session-broker"`). No label writes, no sends, no creates, no
//! permission traffic — the outbound allowlist in `protocol.rs` enforces it.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use super::config::{expand_home, read_password_from_env_file, AgentSessionsConfig, DaemonAuth};
use super::daemon::{BrokerAuthSecret, BrokerConnection};
use super::protocol::{self, FOLLOW_PAGE_LIMIT, HISTORY_DEFAULT_LIMIT, HISTORY_MAX_LIMIT};
use crate::node::daemon_client::read_daemon_credentials;

use crate::error::{Error, Result};

/// Reconnect backoff bounds: 1 s growing to 30 s.
pub const RECONNECT_MIN: Duration = Duration::from_secs(1);
pub const RECONNECT_MAX: Duration = Duration::from_secs(30);
/// Follow poll interval (mirrors Desktop's 1 s tail poll).
pub const FOLLOW_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Bound on queued push events per subscription; overflow coalesces to one
/// `resync`.
pub const PUSH_QUEUE_BOUND: usize = 8;
/// Bound on the socket-facing push channel per subscription.
pub const PUSH_CHANNEL_BOUND: usize = 8;
/// Bound on one daemon RPC round (one fetch-all page, one poll fetch). Short
/// enough that a hung daemon surfaces in about ten seconds on tool paths
/// instead of chaining thirty-second holds.
const RPC_TIMEOUT: Duration = Duration::from_secs(10);
/// Overall deadline for `list` across fetch-all pages, answered as
/// `unavailable`. Bounds multi-page discovery even when each page responds.
const LIST_DEADLINE: Duration = Duration::from_secs(10);
/// Bound on waiting for the daemon slot in a tool-call path. A hung daemon
/// must not starve node permits: answer `busy` instead of queueing behind it.
const LOCK_TIMEOUT: Duration = Duration::from_secs(2);

/// Structured refusal for tool replies: `gone` (stale epoch / removed),
/// `unavailable` (unconfigured / unreachable / transient), or `busy` (the
/// broker is briefly unable to take the daemon slot).
#[derive(Debug, Clone)]
pub enum Refusal {
    Gone(String),
    Unavailable(String),
    Busy(String),
}

impl Refusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Gone(_) => "gone",
            Self::Unavailable(_) => "unavailable",
            Self::Busy(_) => "busy",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Gone(m) | Self::Unavailable(m) | Self::Busy(m) => m,
        }
    }

    pub fn tool_value(&self) -> Value {
        protocol::tool_refusal(self.code(), self.message(), json!({}))
    }
}

/// Push event delivered as a `notifications/node_agent_sessions/event`
/// notification on the connection that followed.
#[derive(Debug, Clone)]
pub enum PushEvent {
    /// The full projected tail. Replaces the consumer's view, as the app
    /// contract's `snapshot` event and Desktop's broker do.
    Snapshot(Value),
    Resync,
    Ended {
        code: String,
    },
}

impl PushEvent {
    pub fn notification(
        &self,
        subscription_id: &str,
        host_id: &str,
        host_epoch: &str,
        session_id: &str,
    ) -> Value {
        match self {
            Self::Snapshot(items) => json!({
                "jsonrpc": "2.0",
                "method": protocol::EVENT_NOTIFICATION,
                "params": {
                    "subscriptionId": subscription_id,
                    "hostId": host_id,
                    "hostEpoch": host_epoch,
                    "sessionId": session_id,
                    "kind": "snapshot",
                    "items": items,
                },
            }),
            Self::Resync => json!({
                "jsonrpc": "2.0",
                "method": protocol::EVENT_NOTIFICATION,
                "params": {
                    "subscriptionId": subscription_id,
                    "hostId": host_id,
                    "hostEpoch": host_epoch,
                    "sessionId": session_id,
                    "kind": "resync",
                },
            }),
            Self::Ended { code } => json!({
                "jsonrpc": "2.0",
                "method": protocol::EVENT_NOTIFICATION,
                "params": {
                    "subscriptionId": subscription_id,
                    "hostId": host_id,
                    "hostEpoch": host_epoch,
                    "sessionId": session_id,
                    "kind": "ended",
                    "code": code,
                },
            }),
        }
    }
}

/// Bounded socket-facing sink for one subscription. Updates coalesce: an
/// overflowing update is dropped and exactly one `resync` follows once the
/// consumer drains. `ended` is terminal and always queued.
pub struct SubSink {
    tx: mpsc::Sender<PushEvent>,
    resync_pending: bool,
}

impl SubSink {
    pub fn new(tx: mpsc::Sender<PushEvent>) -> Self {
        Self {
            tx,
            resync_pending: false,
        }
    }

    /// Queue an update, coalescing to `resync` on overflow. Returns false
    /// when the receiver is gone.
    pub fn push_update(&mut self, items: Value) -> bool {
        if self.resync_pending {
            return true;
        }
        match self.tx.try_send(PushEvent::Snapshot(items)) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.resync_pending = true;
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Send a `resync` now (from a coalescing queue flush), deferring to the
    /// pending flag when the channel is full. Returns false when the receiver
    /// is gone.
    pub fn send_resync_now(&mut self) -> bool {
        match self.tx.try_send(PushEvent::Resync) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.resync_pending = true;
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Flush a pending `resync` when the channel has room. Returns false when
    /// the receiver is gone.
    pub fn flush_resync(&mut self) -> bool {
        if !self.resync_pending {
            return true;
        }
        match self.tx.try_send(PushEvent::Resync) {
            Ok(()) => {
                self.resync_pending = false;
                true
            }
            Err(mpsc::error::TrySendError::Full(_)) => true,
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    #[cfg(test)]
    pub fn resync_pending(&self) -> bool {
        self.resync_pending
    }

    /// Queue the terminal event. Falls back to a blocking send when a slow
    /// consumer still holds the channel full.
    pub async fn push_ended(&self, code: &str) -> bool {
        match self.tx.try_send(PushEvent::Ended {
            code: code.to_owned(),
        }) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => self
                .tx
                .send(PushEvent::Ended {
                    code: code.to_owned(),
                })
                .await
                .is_ok(),
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}

/// In-memory coalescing queue used by the follow poll: bounded, overflow
/// drops queued updates and yields exactly one `resync`.
pub(crate) struct PushQueue {
    buf: VecDeque<Value>,
    bound: usize,
    resync_pending: bool,
}

impl PushQueue {
    pub(crate) fn new(bound: usize) -> Self {
        Self {
            buf: VecDeque::new(),
            bound,
            resync_pending: false,
        }
    }

    pub(crate) fn push_update(&mut self, items: Value) {
        if self.resync_pending {
            return;
        }
        if self.buf.len() < self.bound {
            self.buf.push_back(items);
        } else {
            self.buf.clear();
            self.resync_pending = true;
        }
    }

    pub(crate) fn take_flush(&mut self) -> Vec<PushEvent> {
        if self.resync_pending {
            self.resync_pending = false;
            return vec![PushEvent::Resync];
        }
        self.buf.drain(..).map(PushEvent::Snapshot).collect()
    }
}

struct BrokerState {
    reachable: bool,
    epoch: Option<String>,
    last_error: Option<String>,
}

#[allow(dead_code)]
struct SubRecord {
    host_epoch: String,
    session_id: String,
    task: JoinHandle<()>,
}

/// One live daemon connection, tagged with the epoch minted for it. The epoch
/// is the generation: error handlers only clear the slot (and the reachable
/// bit) when the slot still carries the epoch they operated on, so a stale
/// failure can never take down a newer connection.
struct LiveConn {
    epoch: String,
    conn: BrokerConnection,
}

/// The broker worker handle. Cheap to clone; all state lives behind locks.
/// Only the background [`AgentSessionsBroker::run`] loop opens connections;
/// tool paths fail fast on the state bit and never initiate a connect.
pub struct AgentSessionsBroker {
    config: AgentSessionsConfig,
    host_label: String,
    state: Mutex<BrokerState>,
    conn: Mutex<Option<LiveConn>>,
    subs: Mutex<HashMap<String, SubRecord>>,
}

impl AgentSessionsBroker {
    /// True only for `remote: {"enabled": true}` in `agent-sessions.json`.
    pub fn config_remote_enabled(&self) -> bool {
        self.config.remote_enabled()
    }

    pub fn new(config: AgentSessionsConfig) -> Arc<Self> {
        let label = format!("paseo:{}", config.daemon.server_id);
        Arc::new(Self {
            config,
            host_label: label,
            state: Mutex::new(BrokerState {
                reachable: false,
                epoch: None,
                last_error: Some("not yet connected".into()),
            }),
            conn: Mutex::new(None),
            subs: Mutex::new(HashMap::new()),
        })
    }

    async fn mark_unreachable(&self, detail: String) {
        let mut state = self.state.lock().await;
        state.reachable = false;
        state.epoch = None;
        state.last_error = Some(detail);
    }

    async fn mark_reachable(&self, epoch: String) {
        let mut state = self.state.lock().await;
        state.reachable = true;
        state.epoch = Some(epoch);
        state.last_error = None;
    }

    /// Resolve the per-connect secret (re-read every time so rotation is
    /// picked up) and open one authenticated connection. Validates the hello
    /// `serverId` against the configured binding: a mismatch fails closed —
    /// no connection is stored and the host stays unreachable.
    async fn connect_one(&self) -> Result<BrokerConnection> {
        let secret = match &self.config.daemon.auth {
            DaemonAuth::PasswordEnvFile { path, key } => {
                let bytes = read_password_from_env_file(path, key)?;
                BrokerAuthSecret::Password(bytes)
            }
            DaemonAuth::LocalCredential { paseo_home } => {
                let home = expand_home(paseo_home);
                let creds = read_daemon_credentials(&home).map_err(|e| {
                    Error::engine(format!("agent-sessions local credential unreadable: {e}"))
                })?;
                // Reuse the saver's exact-shape token without logging it; the
                // token lives only in this handshake.
                let token = creds_token(&creds);
                BrokerAuthSecret::LocalToken(token)
            }
        };
        let conn = BrokerConnection::connect(&self.config.daemon.url, &secret).await?;
        if conn.server_id() != self.config.daemon.server_id {
            // Fail closed without naming either side: both ids stay in the
            // local log, never in a client-visible error.
            tracing::warn!(
                target: "native_ce::node::agent_sessions",
                expected_server_id = %self.config.daemon.server_id,
                got_server_id = conn.server_id(),
                "agent-sessions daemon identity mismatch; host stays unreachable",
            );
            return Err(Error::engine(
                "agent-sessions daemon identity changed; refusing to bind",
            ));
        }
        Ok(conn)
    }

    /// Ensure a live, server-bound connection. Only the background `run` loop
    /// calls this: on success the host is marked reachable with a fresh epoch
    /// per connection lifetime, on failure it stays (or becomes) unreachable.
    /// The connection slot is held across the attempt so concurrent callers
    /// cannot double connect; daemon access is serialized on the same lock
    /// anyway.
    async fn ensure_connected(&self) -> std::result::Result<(), Refusal> {
        let mut guard = self.conn.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        match self.connect_one().await {
            Ok(conn) => {
                let epoch = uuid::Uuid::new_v4().to_string();
                *guard = Some(LiveConn {
                    epoch: epoch.clone(),
                    conn,
                });
                drop(guard);
                self.mark_reachable(epoch).await;
                Ok(())
            }
            Err(e) => {
                *guard = None;
                drop(guard);
                self.mark_unreachable(e.to_string()).await;
                Err(Refusal::Unavailable(format!("host unreachable: {e}")))
            }
        }
    }

    /// Fail fast when the host table says unreachable, without touching the
    /// connection lock. A hung daemon must not stall tool calls behind it;
    /// the `run` loop owns reconnecting.
    async fn require_live(&self) -> std::result::Result<(), Refusal> {
        if self.state.lock().await.reachable {
            Ok(())
        } else {
            Err(Refusal::Unavailable("host unreachable".into()))
        }
    }

    /// Generation-guarded teardown: clear the connection slot and the
    /// reachable bit only if the slot still carries `epoch`. A stale error
    /// handler can never take down a newer connection or leave the host
    /// stuck unreachable after a reconnect. The two locks are taken in slot
    /// order with the state re-checked, so an interleaved reconnect wins.
    async fn clear_conn_if_epoch(&self, epoch: &str) {
        let mut guard = self.conn.lock().await;
        let matches = guard.as_ref().is_some_and(|slot| slot.epoch == epoch);
        if matches {
            guard.take();
        }
        drop(guard);
        if matches {
            let mut state = self.state.lock().await;
            if state.epoch.as_deref() == Some(epoch) {
                state.reachable = false;
                state.epoch = None;
                state.last_error = Some("agent-sessions daemon connection failed".into());
            }
        }
    }

    /// Current host row for list/capabilities replies.
    pub async fn host_summary(&self) -> Value {
        let state = self.state.lock().await;
        json!({
            "id": self.config.daemon.server_id,
            "label": self.host_label,
            "status": if state.reachable { "reachable" } else { "unreachable" },
            "epoch": state.epoch.clone(),
        })
    }

    /// Check a history/follow/unfollow target against the current host table.
    /// Unreachable ⇒ `unavailable`; wrong host or stale epoch ⇒ `gone`.
    async fn check_target(
        &self,
        host_id: &str,
        host_epoch: &str,
    ) -> std::result::Result<(), Refusal> {
        let state = self.state.lock().await;
        if !state.reachable {
            return Err(Refusal::Unavailable("host unreachable".into()));
        }
        if host_id != self.config.daemon.server_id {
            return Err(Refusal::Gone("unknown host".into()));
        }
        match &state.epoch {
            Some(epoch) if epoch == host_epoch => Ok(()),
            _ => Err(Refusal::Gone(
                "host epoch changed; re-list and follow again".into(),
            )),
        }
    }

    /// Capabilities payload for `node_agent_sessions_capabilities`.
    pub async fn capabilities_payload(&self) -> Value {
        json!({
            "contract": super::config::AGENT_SESSIONS_CONTRACT,
            "operations": super::protocol::OPERATIONS,
            "hosts": [self.host_summary().await],
        })
    }

    /// List sessions: fetch-all agent discovery projected to summaries. The
    /// unreachable host is listed with empty sessions; a briefly contended
    /// daemon slot answers `busy`.
    pub async fn list(&self, cursor: Option<&str>) -> std::result::Result<Value, Refusal> {
        if self.require_live().await.is_err() {
            return Ok(json!({
                "sessions": [],
                "hosts": [self.host_summary().await],
            }));
        }
        match self.fetch_all_summaries(cursor).await {
            Ok((sessions, _epoch)) => Ok(json!({
                "sessions": sessions,
                "hosts": [self.host_summary().await],
            })),
            Err((Refusal::Busy(detail), _)) => Err(Refusal::Busy(detail)),
            Err((_, captured)) => {
                // Clear with the epoch the fetch captured, not the current
                // one: a reconnect that landed mid-list must survive a stale
                // failure. The `run` loop owns reconnecting. (The in-flight
                // RPC already drops its own slot under its guard; this is
                // the backstop for paths that return without one.)
                self.clear_conn_if_epoch(&captured).await;
                Ok(json!({
                    "sessions": [],
                    "hosts": [self.host_summary().await],
                }))
            }
        }
    }

    async fn fetch_all_summaries(
        &self,
        cursor: Option<&str>,
    ) -> std::result::Result<(Vec<Value>, String), (Refusal, String)> {
        let mut out = Vec::new();
        let mut next: Option<String> = cursor.map(str::to_owned);
        let host_id = self.config.daemon.server_id.clone();
        let host_label = self.host_label.clone();
        // The run's epoch: rows are stamped with it, and the failure path
        // clears with it — never with whatever the state says afterwards.
        let epoch = self.state.lock().await.epoch.clone().unwrap_or_default();
        let deadline = tokio::time::Instant::now() + LIST_DEADLINE;
        loop {
            if tokio::time::Instant::now() > deadline {
                let refusal = Refusal::Unavailable("agent-sessions list timed out".into());
                return Err((refusal, epoch));
            }
            let request_id = uuid::Uuid::new_v4().to_string();
            let page = self
                .rpc_fetch_agents(&request_id, next.as_deref(), &epoch)
                .await
                .map_err(|refusal| (refusal, epoch.clone()))?;
            let entries = page
                .pointer("/payload/entries")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for entry in &entries {
                let agent = entry.get("agent").unwrap_or(entry);
                let project = entry.get("project");
                if let Some(row) =
                    protocol::summarize_agent(agent, project, &host_id, &host_label, &epoch)
                {
                    out.push(row);
                }
            }
            let has_more = page
                .pointer("/payload/pageInfo/hasMore")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            next = page
                .pointer("/payload/pageInfo/nextCursor")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if !has_more || next.is_none() {
                break;
            }
        }
        Ok((out, epoch))
    }

    /// Take the daemon slot with a short bound: a hung daemon answers `busy`
    /// instead of starving the caller's permits behind the slot.
    async fn lock_conn(
        &self,
    ) -> std::result::Result<tokio::sync::MutexGuard<'_, Option<LiveConn>>, Refusal> {
        tokio::time::timeout(LOCK_TIMEOUT, self.conn.lock())
            .await
            .map_err(|_| Refusal::Busy("agent-sessions daemon is busy; retry shortly".into()))
    }

    /// Drop a dead slot while its guard is held, so FIFO waiters behind a
    /// hung daemon fail fast on `None` instead of chaining another full RPC
    /// on the same dead connection. Takes the slot only if it still carries
    /// `entry_epoch`, then drops the reachable bit only if the state still
    /// names that epoch. Lock order throughout: slot, then state.
    async fn drop_dead_slot(
        &self,
        mut guard: tokio::sync::MutexGuard<'_, Option<LiveConn>>,
        entry_epoch: Option<String>,
    ) {
        let matches = guard
            .as_ref()
            .is_some_and(|slot| Some(&slot.epoch) == entry_epoch.as_ref());
        if matches {
            guard.take();
        }
        drop(guard);
        if matches {
            if let Some(epoch) = entry_epoch {
                let mut state = self.state.lock().await;
                if state.epoch.as_deref() == Some(&epoch) {
                    state.reachable = false;
                    state.epoch = None;
                    state.last_error = Some("agent-sessions daemon connection failed".into());
                }
            }
        }
    }

    async fn rpc_fetch_agents(
        &self,
        request_id: &str,
        cursor: Option<&str>,
        run_epoch: &str,
    ) -> std::result::Result<Value, Refusal> {
        let mut guard = self.lock_conn().await?;
        let entry_epoch = guard.as_ref().map(|slot| slot.epoch.clone());
        let Some(entry_epoch) = entry_epoch else {
            return Err(Refusal::Unavailable("host unreachable".into()));
        };
        if entry_epoch != run_epoch {
            // The slot rotated between the caller's gate and this lock: rows
            // stamped with the caller's epoch would be stale, so refuse.
            return Err(Refusal::Gone(
                "host epoch changed; re-list and follow again".into(),
            ));
        }
        let outcome: std::result::Result<Value, Refusal> = async {
            let conn = &mut guard
                .as_mut()
                .ok_or_else(|| Refusal::Unavailable("host unreachable".into()))?
                .conn;
            conn.send_fetch_agents(request_id, cursor)
                .await
                .map_err(|e| Refusal::Unavailable(format!("host unreachable: {e}")))?;
            tokio::time::timeout(RPC_TIMEOUT, async {
                loop {
                    match conn
                        .next_message()
                        .await
                        .map_err(|e| Refusal::Unavailable(format!("host unreachable: {e}")))?
                    {
                        None => {
                            return Err(Refusal::Unavailable(
                                "agent-sessions daemon closed".into(),
                            ));
                        }
                        Some(msg) => {
                            if msg.get("type").and_then(Value::as_str)
                                == Some("fetch_agents_response")
                                && msg.pointer("/payload/requestId").and_then(Value::as_str)
                                    == Some(request_id)
                            {
                                return Ok(msg);
                            }
                            // No daemon subscriptions in slice 1; ignore anything
                            // else addressed to a different round.
                        }
                    }
                }
            })
            .await
            .map_err(|_| Refusal::Unavailable("agent-sessions list timed out".into()))?
        }
        .await;
        match outcome {
            Ok(reply) => Ok(reply),
            Err(refusal) => {
                self.drop_dead_slot(guard, Some(entry_epoch)).await;
                Err(refusal)
            }
        }
    }

    /// Projected timeline page for `node_agent_sessions_history`.
    pub async fn history(
        &self,
        host_id: &str,
        host_epoch: &str,
        session_id: &str,
        cursor: Option<Value>,
        limit: Option<u64>,
    ) -> std::result::Result<Value, Refusal> {
        // State-only gate: fail fast without touching the daemon slot, and
        // never initiate a connect here — the `run` loop owns that.
        self.check_target(host_id, host_epoch).await?;
        let limit = limit
            .unwrap_or(HISTORY_DEFAULT_LIMIT)
            .clamp(1, HISTORY_MAX_LIMIT);
        let direction = if cursor.is_some() { "after" } else { "tail" };
        match self
            .rpc_fetch_timeline(session_id, direction, cursor.as_ref(), limit, host_epoch)
            .await
        {
            Ok(page) => {
                let agent = page.get("agent");
                let live = agent.filter(|a| !a.is_null());
                let Some(agent) = live else {
                    return Err(Refusal::Gone("session ended".into()));
                };
                if agent.get("id").and_then(Value::as_str) != Some(session_id) {
                    return Err(Refusal::Gone("session ended".into()));
                }
                let entries = page
                    .get("entries")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let epoch = page
                    .get("epoch")
                    .and_then(Value::as_str)
                    .unwrap_or(host_epoch)
                    .to_owned();
                let status = agent.get("status").and_then(Value::as_str);
                let mut projected = protocol::project_timeline(&entries, &epoch, status);
                projected["hostId"] = host_id.into();
                projected["hostEpoch"] = host_epoch.into();
                projected["sessionId"] = session_id.into();
                for key in ["startCursor", "endCursor", "hasOlder", "hasNewer"] {
                    if let Some(v) = page.get(key) {
                        projected[key] = v.clone();
                    }
                }
                Ok(projected)
            }
            Err(refusal) => {
                // Drop the dead connection it ran on, guarded by this
                // call's epoch. Active polls notice on their next tick and
                // end themselves with `gone`; aborting them here would
                // swallow that event. `busy` passes through untouched.
                if !matches!(refusal, Refusal::Busy(_)) {
                    self.clear_conn_if_epoch(host_epoch).await;
                }
                Err(refusal)
            }
        }
    }

    async fn rpc_fetch_timeline(
        &self,
        agent_id: &str,
        direction: &str,
        cursor: Option<&Value>,
        limit: u64,
        run_epoch: &str,
    ) -> std::result::Result<Value, Refusal> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let mut guard = self.lock_conn().await?;
        let entry_epoch = guard.as_ref().map(|slot| slot.epoch.clone());
        let Some(entry_epoch) = entry_epoch else {
            return Err(Refusal::Unavailable("host unreachable".into()));
        };
        if entry_epoch != run_epoch {
            // The slot rotated between the caller's gate and this lock: the
            // page would belong to a dead world, so refuse it as stale.
            return Err(Refusal::Gone(
                "host epoch changed; re-list and follow again".into(),
            ));
        }
        let outcome: std::result::Result<Value, Refusal> = async {
            let conn = &mut guard
                .as_mut()
                .ok_or_else(|| Refusal::Unavailable("host unreachable".into()))?
                .conn;
            conn.send_timeline_fetch(agent_id, &request_id, direction, cursor, limit)
                .await
                .map_err(|e| Refusal::Unavailable(format!("host unreachable: {e}")))?;
            tokio::time::timeout(RPC_TIMEOUT, async {
                loop {
                    match conn
                        .next_message()
                        .await
                        .map_err(|e| Refusal::Unavailable(format!("host unreachable: {e}")))?
                    {
                        None => {
                            return Err(Refusal::Unavailable(
                                "agent-sessions daemon closed".into(),
                            ));
                        }
                        Some(msg) => {
                            if msg.get("type").and_then(Value::as_str)
                                == Some("fetch_agent_timeline_response")
                                && msg.pointer("/payload/requestId").and_then(Value::as_str)
                                    == Some(request_id.as_str())
                            {
                                return Ok(msg.pointer("/payload").cloned().unwrap_or(Value::Null));
                            }
                        }
                    }
                }
            })
            .await
            .map_err(|_| Refusal::Unavailable("agent-sessions history timed out".into()))?
        }
        .await;
        match outcome {
            Ok(reply) => Ok(reply),
            Err(refusal) => {
                self.drop_dead_slot(guard, Some(entry_epoch)).await;
                Err(refusal)
            }
        }
    }

    /// Start a follow: snapshot now, then 1 s tail polls with diff. Pushes go
    /// to `sink`; the caller owns the socket-facing forward.
    pub async fn follow(
        self: &Arc<Self>,
        host_id: &str,
        host_epoch: &str,
        session_id: &str,
        sink: mpsc::Sender<PushEvent>,
    ) -> std::result::Result<(String, Value), Refusal> {
        // State-only gate: fail fast without touching the daemon slot, and
        // never initiate a connect here — the `run` loop owns that.
        self.check_target(host_id, host_epoch).await?;
        let page = match self
            .rpc_fetch_timeline(session_id, "tail", None, FOLLOW_PAGE_LIMIT, host_epoch)
            .await
        {
            Ok(page) => page,
            Err(refusal) => {
                if !matches!(refusal, Refusal::Busy(_)) {
                    self.clear_conn_if_epoch(host_epoch).await;
                }
                return Err(refusal);
            }
        };
        let agent = page.get("agent").filter(|a| !a.is_null());
        let Some(agent) = agent else {
            return Err(Refusal::Gone("session ended".into()));
        };
        if agent.get("id").and_then(Value::as_str) != Some(session_id) {
            return Err(Refusal::Gone("session ended".into()));
        }
        let entries = page
            .get("entries")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let epoch = page
            .get("epoch")
            .and_then(Value::as_str)
            .unwrap_or(host_epoch)
            .to_owned();
        let status = agent.get("status").and_then(Value::as_str);
        let projected = protocol::project_timeline(&entries, &epoch, status);
        let snapshot = projected.clone();
        // Insert before spawning while holding the lock: no await sits
        // between the two, so a poll can never outrun its own record.
        let subscription_id = uuid::Uuid::new_v4().to_string();
        let this = self.clone();
        let hid = host_id.to_owned();
        let hepoch = host_epoch.to_owned();
        let sid = session_id.to_owned();
        let sub = subscription_id.clone();
        let mut subs = self.subs.lock().await;
        let task = tokio::spawn(async move {
            this.poll_loop(&sub, &hid, &hepoch, &sid, snapshot, sink)
                .await;
        });
        subs.insert(
            subscription_id.clone(),
            SubRecord {
                host_epoch: host_epoch.to_owned(),
                session_id: session_id.to_owned(),
                task,
            },
        );
        drop(subs);
        Ok((subscription_id, projected))
    }

    async fn poll_loop(
        &self,
        subscription_id: &str,
        host_id: &str,
        host_epoch: &str,
        session_id: &str,
        snapshot: Value,
        sink: mpsc::Sender<PushEvent>,
    ) {
        let mut sink = SubSink::new(sink);
        let mut previous = serde_json::to_string(&snapshot).unwrap_or_default();
        let mut queue = PushQueue::new(PUSH_QUEUE_BOUND);
        let mut ticker = tokio::time::interval(FOLLOW_POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if !sink.flush_resync() {
                break;
            }
            let page = match self
                .rpc_fetch_timeline(session_id, "tail", None, FOLLOW_PAGE_LIMIT, host_epoch)
                .await
            {
                Ok(page) => page,
                Err(Refusal::Busy(_)) => {
                    // Briefly contended slot: skip this tick and retry on
                    // the next one rather than ending the follow.
                    continue;
                }
                Err(_) => {
                    self.clear_conn_if_epoch(host_epoch).await;
                    sink.push_ended("gone").await;
                    break;
                }
            };
            // Epoch moved under us (reconnect raced the poll): this follow
            // belongs to a dead world.
            {
                let state = self.state.lock().await;
                let stale = !state.reachable || state.epoch.as_deref() != Some(host_epoch);
                if stale {
                    drop(state);
                    sink.push_ended("gone").await;
                    break;
                }
            }
            let agent = page.get("agent").filter(|a| !a.is_null());
            let live = match agent {
                Some(agent) if agent.get("id").and_then(Value::as_str) == Some(session_id) => agent,
                _ => {
                    sink.push_ended("gone").await;
                    break;
                }
            };
            let entries = page
                .get("entries")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let epoch = page
                .get("epoch")
                .and_then(Value::as_str)
                .unwrap_or(host_epoch)
                .to_owned();
            let status = live.get("status").and_then(Value::as_str);
            let projected = protocol::project_timeline(&entries, &epoch, status);
            let serialized = serde_json::to_string(&projected).unwrap_or_default();
            if serialized == previous {
                continue;
            }
            previous = serialized;
            let items = projected.get("items").cloned().unwrap_or(Value::Null);
            queue.push_update(items);
            let mut live_sink = true;
            for event in queue.take_flush() {
                let ok = match event {
                    PushEvent::Snapshot(items) => sink.push_update(items),
                    PushEvent::Resync => sink.send_resync_now(),
                    PushEvent::Ended { .. } => true,
                };
                if !ok {
                    live_sink = false;
                    break;
                }
            }
            if !live_sink {
                break;
            }
        }
        self.remove_sub(subscription_id).await;
        // Keep the address ids referenced for the notification layer even
        // though the wire row itself is items-only.
        let _ = (host_id, session_id);
    }

    /// Read-only count of live broker follows. Test seam: the cleanup
    /// regression tests assert the count without disturbing the subs.
    #[cfg(test)]
    pub async fn subscription_count(&self) -> usize {
        self.subs.lock().await.len()
    }

    /// End one follow without error when missing.
    pub async fn unfollow(&self, subscription_id: &str) -> bool {
        if let Some(record) = self.subs.lock().await.remove(subscription_id) {
            record.task.abort();
            true
        } else {
            false
        }
    }

    /// Remove one subscription record without aborting. Poll loops call this
    /// for themselves on every exit path so a reconnect starts clean.
    async fn remove_sub(&self, subscription_id: &str) {
        self.subs.lock().await.remove(subscription_id);
    }

    /// Background worker: initial connect plus reconnect with backoff
    /// (1 s → 30 s). Runs until the returned handle is aborted at shutdown.
    /// A dead peer surfaces here even with no active polls; active polls
    /// notice on their next tick and end themselves with `gone`.
    pub async fn run(self: Arc<Self>) {
        let mut backoff = RECONNECT_MIN;
        // Initial attempt is immediate so the host table populates.
        loop {
            if self.conn.lock().await.is_none() {
                match self.ensure_connected().await {
                    Ok(()) => backoff = RECONNECT_MIN,
                    Err(_) => {
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(RECONNECT_MAX);
                        continue;
                    }
                }
            }
            // Hold the connection open: probe it with a ping so a dead peer
            // surfaces here even with no active polls. The ping takes the
            // slot under the same short bound as tool calls; a contended
            // slot is skipped, a failed ping clears only its own epoch.
            tokio::time::sleep(FOLLOW_POLL_INTERVAL).await;
            let failed_epoch = {
                let guard = tokio::time::timeout(LOCK_TIMEOUT, self.conn.lock()).await;
                let Ok(mut guard) = guard else {
                    continue;
                };
                let Some(slot) = guard.as_mut() else {
                    continue;
                };
                if slot.conn.send_ping().await.is_err() {
                    let epoch = slot.epoch.clone();
                    guard.take();
                    Some(epoch)
                } else {
                    None
                }
            };
            if let Some(epoch) = failed_epoch {
                // Guarded by the pinged epoch: a reconnect that landed
                // between the take and this check keeps its reachable bit.
                let mut state = self.state.lock().await;
                if state.epoch.as_deref() == Some(&epoch) {
                    state.reachable = false;
                    state.epoch = None;
                    state.last_error = Some("daemon ping failed".into());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;

/// Read the saver's exact-shape token without logging it. The credential is
/// re-read before every (re)connect; only the handshake sees the bytes.
fn creds_token(
    creds: &crate::node::daemon_client::DaemonCredentials,
) -> zeroize::Zeroizing<String> {
    // `DaemonCredentials` exposes its token only for one handshake send; reach
    // it through a handshake-shaped borrow here. See daemon_client for the
    // redaction contract.
    creds.handshake_token()
}
