//! Minimal read-only Paseo daemon WebSocket client for the session saver (S1).
//!
//! The saver runs inside the Native node on each execution host and talks to
//! that host's daemon as an ordinary local client over its public wire
//! protocol. This module owns the credential handling, the handshake, and the
//! read allowlist. It performs **no** canonical Native session writes; those
//! belong to later slices (S2/S3).
//!
//! Wire reference (read-only, Desktop source; field names and envelope copied
//! from there, not invented):
//! - hello with `auth:{kind:"localCredential", token}`, answered by a
//!   session-wrapped `status`/`server_info` frame carrying `serverId`
//!   (`packages/protocol/src/messages.ts`: `WSHelloMessageSchema`,
//!   `StatusMessageSchema` inside `WSSessionOutboundSchema`, which is exactly
//!   `pong | session | hello.rejected` — there is no top-level `status`;
//!   `packages/server/src/server/websocket-server.ts`:
//!   `WS_PROTOCOL_VERSION = 1`; `createServerInfoMessage` returns the session
//!   envelope, sent first after a fresh or resumed hello; a refused hello
//!   gets top-level `hello.rejected`).
//! - every post-hello message is wrapped as `{type:"session", message:{...}}`
//!   (`WSSessionInboundSchema` / `WSSessionOutboundSchema`;
//!   `packages/client/src/daemon-client.ts` `sendSessionMessage`).
//! - `fetch_agents_request{subscribe}` → `fetch_agents_response` with
//!   `payload.entries[].agent` snapshots (`FetchAgentsRequestMessageSchema`,
//!   `FetchAgentsResponseMessageSchema`).
//! - incremental `agent_update` with `payload.kind` `upsert` (full `agent`
//!   snapshot) or `remove` (`agentId`) (`AgentUpdateMessageSchema`).
//! - `agent.timeline.set_subscription.request` + `selective_agent_timeline`
//!   and `owned_subscriptions` capabilities (`messages.ts`,
//!   `protocol/src/client-capabilities.ts`; Desktop's client defaults in
//!   `packages/client/src/connection/index.ts`).
//! - `fetch_agent_timeline_request{after, projection:"projected"}` →
//!   `fetch_agent_timeline_response`; live `agent_stream` and
//!   `agent.timeline.replacement` events.
//! - local credential + `paseo.pid` target binding
//!   (`readLocalCredentialForTarget` in `packages/server/src/`): the file
//!   holds 32 random bytes as base64url plus `"\n"`, validated as 43
//!   `[A-Za-z0-9_-]` chars; the credential is sent only to the listen target
//!   read from the same lock snapshot.
//! - per-agent string labels patched by merge through `update_agent_request`
//!   (`UpdateAgentRequestMessageSchema`: `type`, `agentId`, `name?`,
//!   `labels?`, `requestId`).
//!
//! S0 finding (reconciled design f38936b): snapshot/subscription filters
//! support exact string equality only, so discovery uses fetch-all plus local
//! `native.save` filtering.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Label the owner (Desktop) sets on an agent to request saving.
pub const SAVE_LABEL: &str = "native.save";
/// Label the saver writes back with its own status. The only label write the
/// read-only wrapper permits.
pub const SAVE_STATUS_LABEL: &str = "native.save.status";
/// Daemon wire capability the saver advertises so timeline events arrive only
/// for its explicit subscription set.
pub const SELECTIVE_TIMELINE_CAP: &str = "selective_agent_timeline";
/// Client identity presented in `hello`.
pub const SAVER_CLIENT_ID: &str = "native-session-saver";
/// Daemon hello protocol version (Desktop `websocket-server.ts`).
pub const DAEMON_PROTOCOL_VERSION: u32 = 1;
/// Contract string for the sibling `sessions.json` file (design §4.1).
pub const SAVER_CONTRACT: &str = "native.node.session-saver.v1";

/// Bound on the TCP+WS connect.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on waiting for the post-hello `server_info` acceptance.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on any single frame send.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on the closing handshake.
pub const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Authenticated daemon endpoint read from `$PASEO_HOME`.
///
/// The token is held in memory only for handshakes and reconnects. It is
/// never logged: [`DaemonCredentials`] redacts it in `Debug` (there is no
/// `Display`), and no log or error path formats it.
pub struct DaemonCredentials {
    /// `paseo.pid` listen address, e.g. `127.0.0.1:4123`.
    pub listen: String,
    token: String,
    /// Where the credential was read from, for diagnostics without secrets.
    pub paseo_home: PathBuf,
}

impl DaemonCredentials {
    /// Borrow the token for exactly one handshake send.
    fn token(&self) -> &str {
        &self.token
    }

    /// `ws://` URL for the daemon's websocket endpoint.
    fn ws_url(&self) -> String {
        format!("ws://{}/", self.listen.trim())
    }

    /// Best-effort in-process redaction. This clears the Rust allocation; it
    /// makes no claim about allocator copies, swap, or core dumps.
    pub fn wipe(&mut self) {
        self.token.zeroize();
        self.token.clear();
    }
}

impl Drop for DaemonCredentials {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl fmt::Debug for DaemonCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DaemonCredentials")
            .field("listen", &self.listen)
            .field("token", &"<redacted>")
            .field("paseo_home", &self.paseo_home)
            .finish()
    }
}

/// Why the daemon credential could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonAuthError {
    MissingPid,
    MissingListen,
    UnsupportedListen(String),
    MissingCredential,
    InvalidCredential,
    PidUnreadable(String),
}

impl fmt::Display for DaemonAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPid => write!(f, "daemon not running (no paseo.pid)"),
            Self::MissingListen => write!(f, "daemon lock has no listen address"),
            Self::UnsupportedListen(target) => write!(
                f,
                "daemon listen target is not a supported TCP address: {target}"
            ),
            Self::MissingCredential => write!(f, "daemon local credential absent"),
            Self::InvalidCredential => write!(f, "daemon local credential malformed"),
            Self::PidUnreadable(detail) => write!(f, "cannot read daemon lock: {detail}"),
        }
    }
}

/// Read `$PASEO_HOME/paseo.pid` (`listen`) and `$PASEO_HOME/local-credential`,
/// binding the credential to the listen target it was read alongside.
///
/// Mirrors Desktop's `readLocalCredentialForTarget`: the credential is only
/// returned together with the listen address from the same lock snapshot, and
/// callers must re-read both before every (re)connect because the daemon
/// rewrites the credential on each start. The credential is sent only to that
/// listen target.
pub fn read_daemon_credentials(
    paseo_home: &Path,
) -> std::result::Result<DaemonCredentials, DaemonAuthError> {
    let pid_path = paseo_home.join("paseo.pid");
    let raw = std::fs::read_to_string(&pid_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            DaemonAuthError::MissingPid
        } else {
            DaemonAuthError::PidUnreadable(e.to_string())
        }
    })?;
    let pid: Value =
        serde_json::from_str(&raw).map_err(|e| DaemonAuthError::PidUnreadable(e.to_string()))?;
    let listen = pid
        .get("listen")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(DaemonAuthError::MissingListen)?
        .to_owned();
    // S1 supports TCP listen targets only (`host:port`, `tcp://host:port`,
    // bare port). Unix-socket, pipe and other forms are refused explicitly
    // rather than turned into a broken URL.
    let listen = normalize_tcp_listen(&listen)
        .ok_or_else(|| DaemonAuthError::UnsupportedListen(listen.clone()))?;
    let token_path = paseo_home.join("local-credential");
    let token = std::fs::read_to_string(&token_path)
        .map_err(|_| DaemonAuthError::MissingCredential)?
        .trim()
        .to_owned();
    if !is_plausible_credential(&token) {
        return Err(DaemonAuthError::InvalidCredential);
    }
    Ok(DaemonCredentials {
        listen,
        token,
        paseo_home: paseo_home.to_owned(),
    })
}

fn is_plausible_credential(token: &str) -> bool {
    // Same shape Desktop validates in `local-credential.ts`: 32 random bytes
    // as base64url. Anything else is a corrupt or foreign file, not a secret
    // to try.
    token.len() == 43
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Normalize a daemon listen value to `host:port` when it names a TCP
/// endpoint: `host:port`, `tcp://host:port`, or a bare port (localhost).
/// Anything else (unix-socket paths, pipes, …) yields `None` so the caller
/// refuses it instead of building a broken URL.
fn normalize_tcp_listen(target: &str) -> Option<String> {
    let trimmed = target.trim();
    let without_scheme = trimmed.strip_prefix("tcp://").unwrap_or(trimmed);
    if without_scheme.starts_with('/') || without_scheme.starts_with("unix://") {
        return None;
    }
    normalize_listen_target(without_scheme)
}

/// Normalize a loopback listen target for comparison (`127.0.0.1:port`,
/// `localhost:port`, `[::1]:port` name the same endpoint).
pub fn normalize_listen_target(target: &str) -> Option<String> {
    let trimmed = target.trim();
    // Bare port, as Desktop's normalizer accepts.
    let host_port = if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_digit()) {
        format!("localhost:{trimmed}")
    } else {
        trimmed.to_owned()
    };
    let (host, port) = host_port.rsplit_once(':')?;
    if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let host = host
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .to_lowercase();
    let loopback = match host.as_str() {
        "127.0.0.1" | "localhost" | "::1" => "localhost",
        _ => host.as_str(),
    };
    Some(format!("{loopback}:{port}"))
}

/// True when a credential read alongside `lock_listen` may be sent to
/// `target`: both name the same TCP endpoint after normalization.
///
/// S3 seam: S1 binds by single-snapshot construction; S3 re-checks targets
/// across reconnects and takeover fencing.
#[allow(dead_code)]
pub fn credential_matches_target(lock_listen: &str, target: &str) -> bool {
    match (
        normalize_tcp_listen(lock_listen),
        normalize_tcp_listen(target),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Minimal agent snapshot for discovery filtering: id plus labels.
#[derive(Debug, Clone)]
pub struct SavableAgent {
    pub id: String,
    pub labels: HashMap<String, String>,
}

impl SavableAgent {
    pub fn from_snapshot(value: &Value) -> Option<Self> {
        let id = value.get("id")?.as_str()?.to_owned();
        let labels = value
            .get("labels")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        Some(Self { id, labels })
    }
}

/// True when the agent carries an active save request: a `native.save` label
/// whose value does not select the `off` state. Labels cannot be deleted over
/// the wire, so Stop saving is the value `off;req=<uuid>`.
///
/// S1 OBLIGATION (design §4.2/§4.3 step 2, review F4): this checks only the
/// request state, NOT the label binding. Before any S3 write, the saver must
/// parse the label's `acct=`/`db=` against the node's account/db context and
/// fence on the handshake `server_id`; until then discovery stays
/// observational and the saver writes nothing, so an unbound agent can only
/// ever enter the subscription set, never hosted state. Do not claim binding
/// match is implemented.
pub fn is_save_enabled(labels: &HashMap<String, String>) -> bool {
    match labels.get(SAVE_LABEL) {
        None => false,
        Some(value) => {
            let first = value.split(';').next().unwrap_or("").trim();
            !(first.is_empty() || first.eq_ignore_ascii_case("off"))
        }
    }
}

/// Fetch-all plus local `native.save` filtering (S0): the daemon only
/// supports exact-equality label filters, so the saver subscribes without a
/// label filter and selects savable agents itself.
///
/// S2/S3 seam: the curator and persistence layers reuse this batch filter.
#[allow(dead_code)]
pub fn filter_savable_agents(snapshots: &[Value]) -> Vec<SavableAgent> {
    snapshots
        .iter()
        .filter_map(SavableAgent::from_snapshot)
        .filter(|agent| is_save_enabled(&agent.labels))
        .collect()
}

/// `hello` frame with local-credential auth and the timeline capabilities the
/// saver needs. Sent bare (top-level), like every `hello`. The token is
/// embedded in the returned frame only; callers must not log the frame.
fn hello_message(client_id: &str, token: &str) -> Value {
    json!({
        "type": "hello",
        "clientId": client_id,
        "clientType": "mcp",
        "protocolVersion": DAEMON_PROTOCOL_VERSION,
        "auth": {"kind": "localCredential", "token": token},
        "capabilities": {
            SELECTIVE_TIMELINE_CAP: true,
            "explicit_event_subscriptions": true,
            "timeline_replacement_invalidation": true,
            "owned_subscriptions": true,
        },
    })
}

/// Wrap an inner message in the session envelope every post-hello frame uses.
fn wrap_session(inner: &Value) -> Value {
    json!({"type": "session", "message": inner})
}

/// Unwrap the session envelope. Non-envelope frames (top-level `status`,
/// `pong`, `hello.rejected`) are returned as-is.
pub fn unwrap_session(frame: &Value) -> &Value {
    if frame.get("type").and_then(Value::as_str) == Some("session") {
        if let Some(inner) = frame.get("message") {
            if inner.is_object() {
                return inner;
            }
        }
    }
    frame
}

/// `fetch_agents_request` without a label filter (fetch-all; §4.3 step 1).
/// Pages of 200 follow `pageInfo.nextCursor` until `hasMore` is false.
/// Only the initial page subscribes: with `owned_subscriptions` every page
/// carrying `subscribe` would add a duplicate live stream.
fn fetch_agents_message(request_id: &str, cursor: Option<&str>) -> Value {
    let mut message = json!({
        "type": "fetch_agents_request",
        "requestId": request_id,
        "page": {"limit": 200},
    });
    match cursor {
        None => {
            message["subscribe"] = json!({});
        }
        Some(cursor) => {
            message["page"]["cursor"] = cursor.into();
        }
    }
    message
}

/// Selective timeline subscription for exactly the saved set (§4.3 step 3).
/// An empty set clears the subscription (last Stop).
fn timeline_subscription_message(request_id: &str, agent_ids: &[String]) -> Value {
    json!({
        "type": "agent.timeline.set_subscription.request",
        "requestId": request_id,
        "agentIds": agent_ids,
    })
}

/// Projected timeline page fetch for catch-up (§4.3 step 4).
fn fetch_timeline_message(agent_id: &str, request_id: &str, cursor: Option<&Value>) -> Value {
    let mut message = json!({
        "type": "fetch_agent_timeline_request",
        "agentId": agent_id,
        "requestId": request_id,
        "direction": "after",
        "projection": "projected",
        "limit": super::session_catchup::SOURCE_PAGE_LIMIT,
    });
    if let Some(cursor) = cursor {
        message["cursor"] = cursor.clone();
    }
    message
}

/// Status payload the saver reports through its own label (§8.3).
///
/// S3 seam: heartbeat/state writes format through here.
#[allow(dead_code)]
pub fn save_status_value(kind: &str, detail: &str) -> String {
    if detail.is_empty() {
        kind.to_owned()
    } else {
        format!("{kind}:{detail}")
    }
}

/// `update_agent_request` touching **only** `native.save.status`, with exactly
/// the wire fields the saver may send. Every other label write — and every
/// other field — is refused by [`check_outbound_allowed`].
///
/// S3 seam: reached via [`DaemonConnection::send_status`].
#[allow(dead_code)]
fn status_label_update_message(agent_id: &str, request_id: &str, status: &str) -> Value {
    json!({
        "type": "update_agent_request",
        "agentId": agent_id,
        "requestId": request_id,
        "labels": {SAVE_STATUS_LABEL: status},
    })
}

/// Permitted top-level fields per outbound message type. Anything not listed
/// here — agent sends, agent creation, mode/model changes, and any extra
/// field smuggled alongside an allowed call — is refused (§10 test 13).
fn allowed_keys(kind: &str) -> Option<&'static [&'static str]> {
    match kind {
        "fetch_agents_request" => Some(&[
            "type",
            "requestId",
            "scope",
            "filter",
            "sort",
            "page",
            "subscribe",
            "sync",
        ]),
        "fetch_agent_timeline_request" => Some(&[
            "type",
            "agentId",
            "requestId",
            "direction",
            "cursor",
            "limit",
            "projection",
            "mergeWindow",
        ]),
        "agent.timeline.set_subscription.request" => Some(&["type", "agentIds", "requestId"]),
        "agent.timeline.search.request" => {
            Some(&["type", "agentId", "requestId", "query", "cursor"])
        }
        "agent.provider_subagents.timeline.get.request" => Some(&[
            "type",
            "parentAgentId",
            "subagentId",
            "requestId",
            "direction",
            "cursor",
            "limit",
        ]),
        "ping" => Some(&["type"]),
        // update_agent_request is gated by exact-shape check below, not here.
        _ => None,
    }
}

/// Allowlist gate for outbound daemon traffic. Each permitted read must carry
/// only its protocol fields; `update_agent_request` must match the exact
/// saver status-update shape (no `name`, no other labels, no extra fields).
/// Everything else is refused, in particular any agent send, agent creation,
/// or non-status label write.
pub fn check_outbound_allowed(message: &Value) -> std::result::Result<(), String> {
    let Some(kind) = message.get("type").and_then(Value::as_str) else {
        return Err("daemon message has no type".into());
    };
    if kind == "update_agent_request" {
        return check_status_update_shape(message);
    }
    let Some(keys) = allowed_keys(kind) else {
        return Err(format!("daemon call not permitted for the saver: {kind}"));
    };
    let Some(map) = message.as_object() else {
        return Err("daemon message is not an object".into());
    };
    for key in map.keys() {
        if !keys.contains(&key.as_str()) {
            return Err(format!("field not permitted on {kind}: {key}"));
        }
    }
    Ok(())
}

fn check_status_update_shape(message: &Value) -> std::result::Result<(), String> {
    let Some(map) = message.as_object() else {
        return Err("daemon message is not an object".into());
    };
    for key in ["type", "agentId", "requestId", "labels"] {
        if !map.contains_key(key) {
            return Err(format!("update_agent_request is missing {key}"));
        }
    }
    if map.len() != 4 {
        return Err("update_agent_request must carry exactly type/agentId/requestId/labels".into());
    }
    let Some(labels) = map.get("labels").and_then(Value::as_object) else {
        return Err("update_agent_request labels must be an object".into());
    };
    if labels.len() != 1 {
        return Err("only the native.save.status label may be written".into());
    }
    match labels.get(SAVE_STATUS_LABEL).and_then(Value::as_str) {
        Some(_) => Ok(()),
        None => Err("only the native.save.status label may be written".into()),
    }
}

/// Connected, hello-authenticated daemon transport.
///
/// All sends go through the allowlist and are time-bounded; the closing
/// handshake is time-bounded too, so node shutdown cannot hang on the saver.
/// Frame reads (`next_message`) are unbounded by design: the saver loop
/// always awaits them under a shutdown `select`.
pub struct DaemonConnection {
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    /// Handshake-accepted daemon `serverId` (host binding, §4.2). Read by S3
    /// fencing; S1 records it without acting on it.
    #[allow(dead_code)]
    server_id: String,
}

impl DaemonConnection {
    /// Connect to the listen target, run the `hello` handshake, and validate
    /// the daemon's `server_info` acceptance — all time-bounded. The
    /// credential is sent only to the target it was read alongside; a
    /// `hello.rejected` answer or any other first frame fails the connect.
    pub async fn connect(creds: &DaemonCredentials) -> Result<Self> {
        Self::connect_with(creds, CONNECT_TIMEOUT, HANDSHAKE_TIMEOUT).await
    }

    async fn connect_with(
        creds: &DaemonCredentials,
        connect_timeout: Duration,
        handshake_timeout: Duration,
    ) -> Result<Self> {
        let url = creds.ws_url();
        let (mut stream, _) = tokio::time::timeout(connect_timeout, connect_async(&url))
            .await
            .map_err(|_| Error::engine("daemon connect timed out"))?
            .map_err(|e| Error::engine(format!("daemon connect failed: {e}")))?;
        let hello = hello_message(SAVER_CLIENT_ID, creds.token());
        tokio::time::timeout(
            SEND_TIMEOUT,
            stream.send(Message::Text(hello.to_string().into())),
        )
        .await
        .map_err(|_| Error::engine("daemon hello send timed out"))?
        .map_err(|e| Error::engine(format!("daemon hello failed: {e}")))?;
        // The daemon answers an accepted hello with a session-wrapped
        // status/server_info (fresh or resumed); a refused hello gets
        // top-level hello.rejected. Anything else is a protocol mismatch.
        let first = tokio::time::timeout(handshake_timeout, stream.next())
            .await
            .map_err(|_| Error::engine("daemon handshake timed out"))?
            .ok_or_else(|| Error::engine("daemon closed during handshake"))?
            .map_err(|e| Error::engine(format!("daemon handshake failed: {e}")))?;
        let frame: Value = match first {
            Message::Text(text) => serde_json::from_str(&text)
                .map_err(|_| Error::engine("daemon sent a non-JSON frame during handshake")),
            Message::Close(_) => Err(Error::engine("daemon closed during handshake")),
            _ => Err(Error::engine("unexpected daemon frame during handshake")),
        }?;
        if frame.get("type").and_then(Value::as_str) == Some("hello.rejected") {
            return Err(Error::engine("daemon rejected hello (auth)"));
        }
        // The acceptance is always session-wrapped (the top-level schema is
        // exactly pong | session | hello.rejected); a bare status frame is a
        // protocol mismatch, not an acceptance.
        if frame.get("type").and_then(Value::as_str) != Some("session") {
            return Err(Error::engine("daemon handshake did not return server_info"));
        }
        let inner = unwrap_session(&frame);
        let server_id = inner
            .pointer("/payload/serverId")
            .and_then(Value::as_str)
            .filter(|_| {
                inner.get("type").and_then(Value::as_str) == Some("status")
                    && inner.pointer("/payload/status").and_then(Value::as_str)
                        == Some("server_info")
            })
            .ok_or_else(|| Error::engine("daemon handshake did not return server_info"))?
            .to_owned();
        Ok(Self { stream, server_id })
    }

    /// Daemon `serverId` accepted during the handshake (host binding, §4.2).
    ///
    /// S3 seam: generation-lease fencing compares against this.
    #[allow(dead_code)]
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// Typed read: fetch-all agent discovery, optionally resuming a page.
    pub async fn send_fetch_agents(
        &mut self,
        request_id: &str,
        cursor: Option<&str>,
    ) -> Result<()> {
        self.send_inner(&fetch_agents_message(request_id, cursor))
            .await
    }

    /// Typed read: selective timeline subscription for exactly `agent_ids`
    /// (empty clears the subscription).
    pub async fn send_timeline_subscription(
        &mut self,
        request_id: &str,
        agent_ids: &[String],
    ) -> Result<()> {
        self.send_inner(&timeline_subscription_message(request_id, agent_ids))
            .await
    }

    /// Typed read: projected timeline page for catch-up.
    pub async fn send_timeline_fetch(
        &mut self,
        agent_id: &str,
        request_id: &str,
        cursor: Option<&Value>,
    ) -> Result<()> {
        self.send_inner(&fetch_timeline_message(agent_id, request_id, cursor))
            .await
    }

    /// The saver's only permitted write: its own status label.
    ///
    /// S3 seam: heartbeat/state writes send through here.
    #[allow(dead_code)]
    pub async fn send_status(
        &mut self,
        agent_id: &str,
        request_id: &str,
        status: &str,
    ) -> Result<()> {
        self.send_inner(&status_label_update_message(agent_id, request_id, status))
            .await
    }

    async fn send_inner(&mut self, message: &Value) -> Result<()> {
        check_outbound_allowed(message)
            .map_err(|detail| Error::engine(format!("blocked daemon write: {detail}")))?;
        let frame = wrap_session(message).to_string();
        tokio::time::timeout(SEND_TIMEOUT, self.stream.send(Message::Text(frame.into())))
            .await
            .map_err(|_| Error::engine("daemon send timed out"))?
            .map_err(|e| Error::engine(format!("daemon send failed: {e}")))
    }

    /// Receive the next daemon message, unwrapped from its session envelope.
    /// `None` on clean close. `hello.rejected` can never arrive here (the
    /// handshake owns it) and surfaces as an error if it does.
    pub async fn next_message(&mut self) -> Result<Option<Value>> {
        loop {
            match self.stream.next().await {
                None => return Ok(None),
                Some(Err(e)) => return Err(Error::engine(format!("daemon read failed: {e}"))),
                Some(Ok(Message::Close(_))) => return Ok(None),
                Some(Ok(Message::Text(text))) => {
                    let frame: Value = serde_json::from_str(&text)
                        .map_err(|_| Error::engine("daemon sent a non-JSON text frame"))?;
                    if frame.get("type").and_then(Value::as_str) == Some("hello.rejected") {
                        return Err(Error::engine("daemon rejected hello (auth)"));
                    }
                    return Ok(Some(unwrap_session(&frame).clone()));
                }
                Some(Ok(Message::Binary(_))) => {
                    return Err(Error::engine("daemon sent binary frame"));
                }
                // Ping/pong/frame-level control:polled internally, never
                // surfaced; the consumer only sees daemon messages.
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
            }
        }
    }

    /// Best-effort bounded close for node shutdown.
    pub async fn close(&mut self) -> Result<()> {
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, self.stream.close(None)).await;
        Ok(())
    }
}

/// Classify an inbound daemon message by its `type`.
pub fn inbound_kind(message: &Value) -> &str {
    message.get("type").and_then(Value::as_str).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn agent_snapshot(id: &str, labels: &[(&str, &str)]) -> Value {
        let labels: serde_json::Map<String, Value> = labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), Value::String((*v).to_owned())))
            .collect();
        // Real AgentSnapshotPayloadShape subset: id, labels plus the required
        // neighbours a real daemon always sends.
        json!({
            "id": id,
            "provider": "claude",
            "cwd": "/tmp",
            "createdAt": "2026-10-16T00:00:00.000Z",
            "updatedAt": "2026-10-16T00:00:00.000Z",
            "lastUserMessageAt": null,
            "status": "idle",
            "currentModeId": null,
            "availableModes": [],
            "pendingPermissions": [],
            "persistence": null,
            "title": null,
            "labels": Value::Object(labels),
        })
    }

    fn server_info_frame(server_id: &str) -> Value {
        // Real post-hello acceptance: session-wrapped status/server_info.
        json!({
            "type": "session",
            "message": {
                "type": "status",
                "payload": {
                    "status": "server_info",
                    "protocolVersion": 1,
                    "serverId": server_id,
                    "hostname": "test",
                    "version": "0.0.0-test",
                    "permissions": {},
                },
            },
        })
    }

    fn fetch_agents_response_frame(request_id: &str, agents: Vec<Value>) -> Value {
        // Real initial fetch shape: entries carry {agent, project}.
        json!({
            "type": "session",
            "message": {
                "type": "fetch_agents_response",
                "payload": {
                    "requestId": request_id,
                    "entries": agents.into_iter().map(|agent| {
                        json!({"agent": agent, "project": {"projectId": "p", "projectRootPath": "/tmp"}})
                    }).collect::<Vec<_>>(),
                    "pageInfo": {"nextCursor": null, "prevCursor": null, "hasMore": false},
                },
            },
        })
    }

    fn agent_update_frame(upsert: Option<Value>, remove: Option<&str>) -> Value {
        let payload = if let Some(agent) = upsert {
            json!({"kind": "upsert", "agent": agent})
        } else {
            json!({"kind": "remove", "agentId": remove.unwrap()})
        };
        json!({"type": "session", "message": {"type": "agent_update", "payload": payload}})
    }

    #[test]
    fn save_label_filtering_matches_design() {
        assert!(!is_save_enabled(&HashMap::new()));
        let mut off = HashMap::new();
        off.insert(SAVE_LABEL.into(), "off;req=1".into());
        assert!(!is_save_enabled(&off));
        let mut on = HashMap::new();
        on.insert(SAVE_LABEL.into(), "v1;acct=a;db=d;req=1".into());
        assert!(is_save_enabled(&on));
    }

    #[test]
    fn discovery_filters_locally_from_fetch_all() {
        let snapshots = vec![
            agent_snapshot("a", &[(SAVE_LABEL, "v1;acct=x;db=y;req=1")]),
            agent_snapshot("b", &[]),
            agent_snapshot("c", &[(SAVE_LABEL, "off;req=2")]),
        ];
        let savable = filter_savable_agents(&snapshots);
        assert_eq!(
            savable.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            vec!["a"]
        );
    }

    #[test]
    fn outbound_allowlist_blocks_sends_creates_and_extra_fields() {
        assert!(check_outbound_allowed(&fetch_agents_message("r", None)).is_ok());
        let followup = fetch_agents_message("r", Some("cursor-1"));
        assert!(check_outbound_allowed(&followup).is_ok());
        // Follow-up pages must not re-subscribe: with owned_subscriptions
        // each subscribe-bearing page would add a duplicate live stream.
        assert!(followup.get("subscribe").is_none(), "{followup}");
        assert_eq!(followup["page"]["cursor"], "cursor-1");
        assert!(
            check_outbound_allowed(&timeline_subscription_message("r", &["a".to_owned()])).is_ok()
        );
        assert!(check_outbound_allowed(&status_label_update_message("a", "r", "ok:3")).is_ok());
        // Agent sends, creation, mode changes, and any non-status label write
        // are refused ...
        for blocked in [
            json!({"type": "send_agent_message_request", "agentId": "a", "requestId": "r", "text": "hi"}),
            json!({"type": "create_agent_request", "requestId": "r"}),
            json!({"type": "update_agent_request", "agentId": "a", "requestId": "r",
                   "labels": {"native.save": "v1"}}),
            json!({"type": "update_agent_request", "agentId": "a", "requestId": "r",
                   "labels": {"native.save.status": "ok:1", "other": "x"}}),
            json!({"type": "set_agent_mode_request", "agentId": "a", "modeId": "m", "requestId": "r"}),
        ] {
            assert!(check_outbound_allowed(&blocked).is_err(), "{blocked}");
        }
        // ... as is any extra field smuggled alongside the status label: a
        // prompt, rename, or second label mutation must not pass.
        for smuggled in [
            json!({"type": "update_agent_request", "agentId": "a", "requestId": "r",
                   "labels": {"native.save.status": "ok:1"}, "name": "renamed"}),
            json!({"type": "update_agent_request", "agentId": "a", "requestId": "r",
                   "labels": {"native.save.status": "ok:1"}, "text": "prompt"}),
            json!({"type": "fetch_agents_request", "requestId": "r", "labels": {"x": "y"}}),
        ] {
            assert!(check_outbound_allowed(&smuggled).is_err(), "{smuggled}");
        }
    }

    #[test]
    fn credentials_never_format() {
        let mut creds = DaemonCredentials {
            listen: "127.0.0.1:1".into(),
            token: "secret-token".into(),
            paseo_home: PathBuf::from("/tmp"),
        };
        assert!(!format!("{creds:?}").contains("secret-token"));
        creds.wipe();
        assert!(creds.token().is_empty());
    }

    #[test]
    fn non_tcp_listen_targets_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        for listen in [
            "/tmp/paseo.sock",
            "unix:///tmp/paseo.sock",
            "pipe://foo",
            "not a target",
        ] {
            std::fs::write(
                dir.path().join("paseo.pid"),
                format!(
                    r#"{{"pid":1,"startedAt":"t","hostname":"h","uid":1,"listen":"{listen}"}}"#
                ),
            )
            .unwrap();
            let token = format!("{}x", "a".repeat(42));
            std::fs::write(dir.path().join("local-credential"), format!("{token}\n")).unwrap();
            assert!(
                matches!(
                    read_daemon_credentials(dir.path()),
                    Err(DaemonAuthError::UnsupportedListen(_))
                        | Err(DaemonAuthError::MissingListen)
                ),
                "{listen}"
            );
        }
        // TCP forms are accepted and normalized.
        for (listen, normalized) in [
            ("127.0.0.1:4123", "localhost:4123"),
            ("tcp://127.0.0.1:4123", "localhost:4123"),
            ("4123", "localhost:4123"),
        ] {
            std::fs::write(
                dir.path().join("paseo.pid"),
                format!(
                    r#"{{"pid":1,"startedAt":"t","hostname":"h","uid":1,"listen":"{listen}"}}"#
                ),
            )
            .unwrap();
            let creds = read_daemon_credentials(dir.path()).unwrap();
            assert_eq!(
                normalize_tcp_listen(&creds.listen).as_deref(),
                Some(normalized)
            );
        }
    }

    #[test]
    fn target_binding_normalizes_loopback() {
        assert!(credential_matches_target(
            "127.0.0.1:4123",
            "localhost:4123"
        ));
        assert!(credential_matches_target(
            "localhost:4123",
            "127.0.0.1:4123"
        ));
        assert!(!credential_matches_target(
            "127.0.0.1:4123",
            "127.0.0.1:4124"
        ));
        assert!(!credential_matches_target(
            "10.0.0.1:4123",
            "127.0.0.1:4123"
        ));
    }

    #[test]
    fn reads_pid_and_credential_together() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("paseo.pid"),
            r#"{"pid":1,"startedAt":"t","hostname":"h","uid":1,"listen":"127.0.0.1:4123"}"#,
        )
        .unwrap();
        let mut token_file = std::fs::File::create(dir.path().join("local-credential")).unwrap();
        let token = format!("{}x", "a".repeat(42));
        writeln!(token_file, "{token}").unwrap();
        let creds = read_daemon_credentials(dir.path()).unwrap();
        // Stored normalized: same endpoint, loopback-canonical form.
        assert_eq!(creds.listen, "localhost:4123");
        assert_eq!(creds.token(), token);
        assert!(credential_matches_target(&creds.listen, "127.0.0.1:4123"));
    }

    /// Fake daemon speaking the real wire: bare `hello` in, session-wrapped
    /// `status`/`server_info` (or top-level `hello.rejected`) back, then session
    /// envelopes both ways. Fails the test if an agent send or creation is
    /// ever observed (§10 test 13).
    struct FakeDaemon {
        addr: std::net::SocketAddr,
        received_inner: std::sync::Arc<tokio::sync::Mutex<Vec<Value>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl FakeDaemon {
        async fn new(first_reply: Value, scripted: Vec<Value>) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let received_inner = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
            let task = {
                let received_inner = received_inner.clone();
                tokio::spawn(async move {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    // The handshake is a bare hello; everything after must
                    // arrive session-wrapped.
                    let Some(Ok(Message::Text(hello))) = ws.next().await else {
                        return;
                    };
                    let Ok(hello): std::result::Result<Value, _> = serde_json::from_str(&hello)
                    else {
                        return;
                    };
                    received_inner.lock().await.push(hello);
                    if ws
                        .send(Message::Text(first_reply.to_string().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let mut scripted = scripted.into_iter();
                    while let Some(msg) = ws.next().await {
                        let Ok(msg) = msg else { break };
                        let Message::Text(text) = msg else { continue };
                        let Ok(frame): std::result::Result<Value, _> = serde_json::from_str(&text)
                        else {
                            continue;
                        };
                        // Record the inner message; reject bare post-hello
                        // frames the same way the real daemon would.
                        let inner = unwrap_session(&frame).clone();
                        if frame.get("type").and_then(Value::as_str) != Some("session") {
                            break;
                        }
                        received_inner.lock().await.push(inner);
                        if let Some(next) = scripted.next() {
                            let _ = ws.send(Message::Text(next.to_string().into())).await;
                        }
                    }
                })
            };
            Self {
                addr,
                received_inner,
                task,
            }
        }

        async fn stop(self) -> Vec<Value> {
            self.task.abort();
            let _ = self.task.await;
            let received = self.received_inner.lock().await.clone();
            for message in &received {
                let kind = message.get("type").and_then(Value::as_str).unwrap_or("");
                assert!(
                    kind != "send_agent_message_request"
                        && kind != "create_agent_request"
                        && kind != "create_agent_with_id_request",
                    "saver must never send or create: {message}"
                );
            }
            received
        }
    }

    fn test_home_with_daemon(dir: &Path, listen: &str, token: &str) {
        std::fs::write(
            dir.join("paseo.pid"),
            format!(r#"{{"pid":1,"startedAt":"t","hostname":"h","uid":1,"listen":"{listen}"}}"#),
        )
        .unwrap();
        std::fs::write(dir.join("local-credential"), format!("{token}\n")).unwrap();
    }

    #[tokio::test]
    async fn handshake_validates_server_info_and_reads_real_shapes() {
        let home = tempfile::tempdir().unwrap();
        let agent_update = agent_update_frame(
            Some(agent_snapshot("a", &[(SAVE_LABEL, "v1;acct=x;db=y;req=1")])),
            None,
        );
        let fake = FakeDaemon::new(server_info_frame("srv_test"), vec![agent_update]).await;
        let token = format!("{}x", "b".repeat(42));
        test_home_with_daemon(home.path(), &fake.addr.to_string(), &token);

        let creds = read_daemon_credentials(home.path()).unwrap();
        let mut conn = DaemonConnection::connect(&creds).await.expect("connect");
        assert_eq!(conn.server_id(), "srv_test");
        // Typed reads arrive session-wrapped; the scripted agent_update (real
        // upsert shape) arrives as the next message, already unwrapped.
        conn.send_fetch_agents("r1", None).await.expect("fetch");
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), conn.next_message())
            .await
            .expect("frame in time")
            .expect("no read error")
            .expect("not closed");
        assert_eq!(inbound_kind(&frame), "agent_update");
        let agent = frame.pointer("/payload/agent").expect("upsert agent");
        let savable = filter_savable_agents(std::slice::from_ref(agent));
        assert_eq!(
            savable.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            vec!["a"]
        );

        let received = fake.stop().await;
        assert!(!received.is_empty(), "fake saw the handshake");
        let hello = &received[0];
        assert_eq!(hello["type"], "hello");
        assert_eq!(hello["clientType"], "mcp");
        assert_eq!(hello["auth"]["kind"], "localCredential");
        assert_eq!(hello["auth"]["token"], json!(token));
        assert_eq!(hello["capabilities"][SELECTIVE_TIMELINE_CAP], json!(true));
        assert_eq!(hello["capabilities"]["owned_subscriptions"], json!(true));
        assert!(received.iter().any(|m| m["type"] == "fetch_agents_request"));
        assert!(
            !received
                .iter()
                .any(|m| m["type"] == "send_agent_message_request"),
            "no send observed on the wire"
        );
    }

    #[tokio::test]
    async fn bare_status_is_not_an_acceptance() {
        // The top-level schema is pong | session | hello.rejected: a bare
        // status frame (the shape the first S1 revision wrongly expected)
        // must fail the handshake rather than connect.
        let home = tempfile::tempdir().unwrap();
        let fake = FakeDaemon::new(
            json!({"type": "status", "payload": {"status": "server_info", "serverId": "srv_x"}}),
            vec![],
        )
        .await;
        let token = format!("{}x", "g".repeat(42));
        test_home_with_daemon(home.path(), &fake.addr.to_string(), &token);
        let creds = read_daemon_credentials(home.path()).unwrap();
        assert!(DaemonConnection::connect(&creds).await.is_err());
        let _ = fake.stop().await;
    }

    #[tokio::test]
    async fn hello_rejected_fails_connect() {
        let home = tempfile::tempdir().unwrap();
        let fake = FakeDaemon::new(json!({"type": "hello.rejected", "reason": "incorrect_password", "accepts": ["password"]}), vec![]).await;
        let token = format!("{}x", "e".repeat(42));
        test_home_with_daemon(home.path(), &fake.addr.to_string(), &token);
        let creds = read_daemon_credentials(home.path()).unwrap();
        assert!(DaemonConnection::connect(&creds).await.is_err());
        let _ = fake.stop().await;
    }

    #[tokio::test]
    async fn handshake_times_out_without_server_info() {
        // Accepts TCP+WS but never answers: the bounded handshake must fail
        // instead of hanging shutdown.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                return;
            };
            let _ = ws.next().await;
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });
        let home = tempfile::tempdir().unwrap();
        let token = format!("{}x", "f".repeat(42));
        test_home_with_daemon(home.path(), &addr.to_string(), &token);
        let creds = read_daemon_credentials(home.path()).unwrap();
        let result = DaemonConnection::connect_with(
            &creds,
            Duration::from_secs(5),
            Duration::from_millis(200),
        )
        .await;
        assert!(result.is_err(), "handshake without server_info must fail");
        task.abort();
    }

    #[tokio::test]
    async fn reconnect_rereads_rotated_credential() {
        let home = tempfile::tempdir().unwrap();
        let token_v1 = format!("{}x", "c".repeat(42));
        let fake1 = FakeDaemon::new(server_info_frame("srv_1"), vec![]).await;
        test_home_with_daemon(home.path(), &fake1.addr.to_string(), &token_v1);
        let creds1 = read_daemon_credentials(home.path()).unwrap();
        let mut conn1 = DaemonConnection::connect(&creds1)
            .await
            .expect("connect v1");
        assert_eq!(conn1.server_id(), "srv_1");
        let _ = conn1.close().await;
        let seen1 = fake1.stop().await;
        assert_eq!(seen1[0]["auth"]["token"], json!(token_v1));

        // The daemon restarts: new listen target, rotated credential, new
        // server id. The saver re-reads all three before its next attempt.
        let token_v2 = format!("{}y", "d".repeat(42));
        let fake2 = FakeDaemon::new(server_info_frame("srv_2"), vec![]).await;
        test_home_with_daemon(home.path(), &fake2.addr.to_string(), &token_v2);
        let creds2 = read_daemon_credentials(home.path()).unwrap();
        assert_eq!(creds2.token(), token_v2);
        assert!(credential_matches_target(
            &creds2.listen,
            &fake2.addr.to_string()
        ));
        let mut conn2 = DaemonConnection::connect(&creds2)
            .await
            .expect("connect v2");
        assert_eq!(conn2.server_id(), "srv_2");
        let _ = conn2.close().await;
        let seen2 = fake2.stop().await;
        assert_eq!(seen2[0]["auth"]["token"], json!(token_v2));
    }

    #[test]
    fn fetch_response_and_update_shapes_parse() {
        // The saver consumes fetch_agents_response entries and agent_update
        // upsert/remove payloads exactly as the protocol defines them.
        let response = fetch_agents_response_frame(
            "r1",
            vec![agent_snapshot("a", &[(SAVE_LABEL, "v1;req=1")])],
        );
        let inner = unwrap_session(&response);
        assert_eq!(inbound_kind(inner), "fetch_agents_response");
        let agents: Vec<Value> = inner
            .pointer("/payload/entries")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .map(|entry| entry.pointer("/agent").cloned().unwrap())
            .collect();
        assert_eq!(filter_savable_agents(&agents).len(), 1);

        let upsert = agent_update_frame(Some(agent_snapshot("b", &[])), None);
        let payload = unwrap_session(&upsert).pointer("/payload").unwrap();
        assert_eq!(payload["kind"], "upsert");
        assert!(payload.get("agent").is_some());

        let remove = agent_update_frame(None, Some("b"));
        let payload = unwrap_session(&remove).pointer("/payload").unwrap();
        assert_eq!(payload["kind"], "remove");
        assert_eq!(payload["agentId"], "b");
    }
}
