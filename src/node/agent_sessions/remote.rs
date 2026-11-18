//! Node outbound channel to hosted (`remote: {"enabled": true}`).
//!
//! When enabled, the node dials `ws(s)://<hosted>/databases/{db_id}/nodes/connect`
//! with `Authorization: Bearer <token>` (re-read from the node's
//! `credential_file` on every connect via the shared guarded read), sends one
//! `hello`, then answers relayed `{capabilities,list,history}` requests with
//! the same broker functions the Unix-socket tools use. A hosted close (deploy,
//! expiry) is normal: back off with jitter and reconnect with a fresh token.
//! The token is never logged.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async_with_config, tungstenite::Message, MaybeTlsStream, WebSocketStream,
};

use crate::credential_file::read_guarded_credential;
use crate::error::{Error, Result};
use crate::node::session_identity::SaverIdentity;

use super::broker::{AgentSessionsBroker, PushEvent};

/// Whether a URI authority names this machine: `localhost`, a loopback IP,
/// or a bracketed IPv6 loopback with a port (`[::1]:8080`, which a naive
/// split on `:` misparses). Anything else keeps cleartext `ws://` refused.
/// An IP loopback, including IPv4-mapped IPv6 (`::ffff:127.0.0.1`), which
/// [`std::net::IpAddr::is_loopback`] alone does not cover.
fn ip_is_loopback(ip: std::net::IpAddr) -> bool {
    ip.is_loopback()
        || matches!(ip, std::net::IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()))
}

fn host_is_loopback(authority: &str) -> bool {
    let bare = authority.split('@').next_back().unwrap_or(authority);
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        ip_is_loopback(ip)
    } else if let Some(rest) = bare.strip_prefix('[') {
        rest.split_once(']')
            .and_then(|(ip, _)| ip.parse::<std::net::IpAddr>().ok())
            .is_some_and(ip_is_loopback)
    } else {
        let name = bare.split(':').next().unwrap_or(bare);
        name.eq_ignore_ascii_case("localhost") || name.parse().is_ok_and(ip_is_loopback)
    }
}

/// Contract string sent in the node `hello`.
pub const REMOTE_CONTRACT: &str = "native.node.agent-sessions.remote.v1";
/// Operations the node answers over the channel.
pub const REMOTE_OPERATIONS: &[&str] = &["capabilities", "list", "history", "follow"];
/// Follow budget per remote channel; beyond this the node answers `busy`.
pub const MAX_REMOTE_FOLLOWS_PER_CHANNEL: usize = 16;
/// Bound on one serialized response frame; larger answers become `unavailable`.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// Relayed requests served concurrently per connection; past this the node
/// answers `busy`.
pub const MAX_RELAY_IN_FLIGHT: usize = 16;
/// Heartbeat cadence while the channel is open.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
/// Reconnect backoff bounds with jitter: 1 s growing to 60 s.
pub const REMOTE_RECONNECT_MIN: Duration = Duration::from_secs(1);
pub const REMOTE_RECONNECT_MAX: Duration = Duration::from_secs(60);
/// Bound on the WS connect + hello send.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Where the channel connects and how it authenticates.
#[derive(Debug, Clone)]
pub struct RemoteEndpoint {
    /// `ws://`/`wss://` URL for `/databases/{db_id}/nodes/connect`.
    pub url: String,
    /// Node credential file; re-read on every connect.
    pub credential_file: PathBuf,
    /// Node config `account_id`, echoed in `hello.account_id`.
    pub account_id: String,
    /// Node socket directory; holds the durable remote identity subdir.
    pub socket_dir: PathBuf,
}

impl RemoteEndpoint {
    /// Derive the connect URL from the node's `hosted_base_url` plus
    /// `/databases/{db_id}/nodes/connect`, mapping `http(s)` to `ws(s)`.
    pub fn connect_url_for(hosted_base_url: &str, db_id: &str) -> Result<String> {
        if db_id.trim().is_empty() || db_id == "." || db_id == ".." || db_id.contains(['/', '\\']) {
            return Err(Error::engine(
                "node db_id must be one unambiguous route segment",
            ));
        }
        let mut url = reqwest::Url::parse(hosted_base_url)
            .map_err(|_| Error::engine("invalid node hosted_base_url"))?;
        match url.scheme() {
            "http" => url
                .set_scheme("ws")
                .map_err(|_| Error::engine("invalid node hosted_base_url"))?,
            "https" => url
                .set_scheme("wss")
                .map_err(|_| Error::engine("invalid node hosted_base_url"))?,
            _ => return Err(Error::engine("node hosted_base_url must be http(s)")),
        }
        url.path_segments_mut()
            .map_err(|_| Error::engine("invalid node base URL path"))?
            .pop_if_empty()
            .push("databases")
            .push(db_id)
            .push("nodes")
            .push("connect");
        Ok(url.to_string())
    }
}

/// Load (or mint) the durable remote identity under the socket directory. The
/// instance survives restarts; the boot id is fresh per process. Reuses
/// [`SaverIdentity`]'s guarded `instance-id` discipline in its own subdir so it
/// never shares the saver's file.
pub fn load_remote_identity(socket_dir: &Path) -> Result<SaverIdentity> {
    let dir = socket_dir.join("agent-sessions-remote");
    match std::fs::symlink_metadata(&dir) {
        Ok(meta) => {
            if !meta.is_dir() {
                return Err(Error::engine(
                    "agent-sessions remote identity is not a directory",
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&dir)
                    .map_err(|e| {
                        Error::engine(format!("cannot create remote identity dir: {e}"))
                    })?;
            }
            #[cfg(not(unix))]
            {
                std::fs::create_dir_all(&dir).map_err(|e| {
                    Error::engine(format!("cannot create remote identity dir: {e}"))
                })?;
            }
        }
        Err(e) => {
            return Err(Error::engine(format!(
                "cannot inspect remote identity dir: {e}"
            )))
        }
    }
    SaverIdentity::load(&dir)
}

/// Hello frame sent once per connection.
pub fn hello_value(instance: &str, boot: &str, account_id: &str) -> Value {
    json!({
        "type": "hello",
        "contract": REMOTE_CONTRACT,
        "node_instance": instance,
        "boot": boot,
        "account_id": account_id,
        "operations": REMOTE_OPERATIONS,
    })
}

/// Answer one hosted request with the same broker functions the socket tools
/// use. Unknown ops and malformed args get `invalid`; oversize serialized
/// replies become `unavailable`.
pub async fn answer_request(broker: &AgentSessionsBroker, request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let op = request.get("op").and_then(Value::as_str).unwrap_or("");
    let args = request.get("args").cloned().unwrap_or(json!({}));
    let ok = |value: Value| {
        let response = json!({"type": "response", "id": id, "ok": true, "value": value});
        cap_response(response)
    };
    let fail = |code: &str, message: String| {
        cap_response(
            json!({"type": "response", "id": id, "ok": false, "code": code, "message": message}),
        )
    };
    match op {
        "capabilities" => ok(broker.capabilities_payload().await),
        "list" => {
            let cursor = args
                .get("cursor")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if args.get("cursor").is_some() && cursor.is_none() {
                return fail("invalid", "list needs a string cursor".into());
            }
            match broker.list(cursor.as_deref()).await {
                Ok(payload) => ok(payload),
                Err(refusal) => fail(refusal.code(), refusal.message().to_owned()),
            }
        }
        "history" => {
            let host_id = args.get("hostId").and_then(Value::as_str).unwrap_or("");
            let host_epoch = args.get("hostEpoch").and_then(Value::as_str).unwrap_or("");
            let session_id = args.get("sessionId").and_then(Value::as_str).unwrap_or("");
            if host_id.is_empty() || host_epoch.is_empty() || session_id.is_empty() {
                return fail(
                    "invalid",
                    "history needs hostId, hostEpoch and sessionId".into(),
                );
            }
            let cursor = args.get("cursor").cloned();
            let limit = args.get("limit").and_then(Value::as_u64);
            match broker
                .history(host_id, host_epoch, session_id, cursor, limit)
                .await
            {
                Ok(page) => ok(page),
                Err(refusal) => fail(refusal.code(), refusal.message().to_owned()),
            }
        }
        _ => fail("invalid", format!("unknown op: {op}")),
    }
}

/// Frame one broker push for the remote channel. Oversized snapshots become
/// a small `resync`; `resync` and `ended` are tiny by construction.
pub fn remote_event_frame(subscription_id: &str, event: &PushEvent) -> String {
    let frame = match event {
        PushEvent::Snapshot(items) => json!({
            "type": "event",
            "subscriptionId": subscription_id,
            "kind": "snapshot",
            "items": items,
        }),
        PushEvent::Resync => json!({
            "type": "event",
            "subscriptionId": subscription_id,
            "kind": "resync",
        }),
        PushEvent::Ended { code } => json!({
            "type": "event",
            "subscriptionId": subscription_id,
            "kind": "ended",
            "code": code,
        }),
    };
    let text = frame.to_string();
    if text.len() <= MAX_RESPONSE_BYTES {
        return text;
    }
    // Only snapshots can realistically overflow; anything oversized degrades
    // to a resync so the consumer re-reads instead of stalling.
    json!({
        "type": "event",
        "subscriptionId": subscription_id,
        "kind": "resync",
    })
    .to_string()
}

/// Forward one remote follow's pushes after its response is on the wire.
/// Nothing is written before the release fires; dropping the release without
/// firing (cancelled follow setup) tears the follow down without writing.
async fn forward_remote_pushes(
    broker: Arc<AgentSessionsBroker>,
    follows: RemoteFollows,
    write: Arc<
        tokio::sync::Mutex<
            futures::stream::SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
        >,
    >,
    mut rx: tokio::sync::mpsc::Receiver<PushEvent>,
    release: tokio::sync::oneshot::Receiver<()>,
    subscription_id: String,
) {
    if release.await.is_err() {
        cleanup_remote_follow(&follows, &broker, &subscription_id).await;
        return;
    }
    while let Some(event) = rx.recv().await {
        let terminal = matches!(event, PushEvent::Ended { .. });
        let frame = remote_event_frame(&subscription_id, &event);
        let failed = tokio::time::timeout(SEND_TIMEOUT, async {
            let mut guard = write.lock().await;
            guard.send(Message::Text(frame.into())).await
        })
        .await;
        if !matches!(failed, Ok(Ok(()))) {
            break;
        }
        if terminal {
            break;
        }
    }
    cleanup_remote_follow(&follows, &broker, &subscription_id).await;
}

/// Forget one remote follow and release its broker subscription. This runs at
/// the end of the forwarder task itself, so the broker `unfollow` runs in a
/// separately spawned task: aborting the current task would cancel the
/// unfollow before it completes and leak the broker-side follow.
async fn cleanup_remote_follow(
    follows: &RemoteFollows,
    broker: &Arc<AgentSessionsBroker>,
    subscription_id: &str,
) {
    follows.lock().await.remove(subscription_id);
    let broker = broker.clone();
    let subscription_id = subscription_id.to_owned();
    tokio::spawn(async move {
        broker.unfollow(&subscription_id).await;
    });
}

/// Per-channel remote follows: subscription id to its forwarder task.
type RemoteFollows = Arc<tokio::sync::Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>;

/// Enforce the 256 KiB serialized-response cap. Oversize answers become a
/// small `unavailable` refusal instead of a large frame.
fn cap_response(response: Value) -> Value {
    let bytes = serde_json::to_string(&response)
        .map(|s| s.len())
        .unwrap_or(usize::MAX);
    if bytes <= MAX_RESPONSE_BYTES {
        return response;
    }
    let id = response.get("id").cloned().unwrap_or(Value::Null);
    json!({"type": "response", "id": id, "ok": false, "code": "unavailable", "message": "response too large"})
}

/// The outbound channel worker. Cheap to clone; all broker state lives behind
/// the broker's locks. Only this loop dials hosted; tool paths never touch it.
pub struct RemoteChannel {
    broker: Arc<AgentSessionsBroker>,
    endpoint: RemoteEndpoint,
}

impl RemoteChannel {
    pub fn new(broker: Arc<AgentSessionsBroker>, endpoint: RemoteEndpoint) -> Arc<Self> {
        Arc::new(Self { broker, endpoint })
    }

    /// Run until cancelled: connect, hello, serve, then jittered backoff and
    /// reconnect with a freshly read token. A hosted close is normal.
    pub async fn run(self: Arc<Self>) {
        let mut backoff = REMOTE_RECONNECT_MIN;
        loop {
            // Fresh token every connect so rotation is picked up; the bytes
            // live only in this iteration and are never logged.
            let token = match read_guarded_credential(&self.endpoint.credential_file, "node") {
                Ok(token) => token,
                Err(e) => {
                    tracing::warn!(
                        target: "native_ce::node::agent_sessions",
                        error = %e,
                        "agent-sessions remote credential unreadable; retrying",
                    );
                    sleep_with_jitter(backoff).await;
                    backoff = (backoff * 2).min(REMOTE_RECONNECT_MAX);
                    continue;
                }
            };
            let identity = match load_remote_identity(&self.endpoint.socket_dir) {
                Ok(identity) => identity,
                Err(e) => {
                    tracing::warn!(
                        target: "native_ce::node::agent_sessions",
                        error = %e,
                        "agent-sessions remote identity unavailable; retrying",
                    );
                    sleep_with_jitter(backoff).await;
                    backoff = (backoff * 2).min(REMOTE_RECONNECT_MAX);
                    continue;
                }
            };
            match self.connect_once(&token, &identity).await {
                Ok(stream) => {
                    backoff = REMOTE_RECONNECT_MIN;
                    self.serve_stream(stream).await;
                    // Clean close or failure alike: reconnect after a short
                    // beat so a fast hosted restart is picked up promptly.
                    sleep_with_jitter(REMOTE_RECONNECT_MIN).await;
                }
                Err(e) => {
                    tracing::warn!(
                        target: "native_ce::node::agent_sessions",
                        error = %e,
                        "agent-sessions remote connect failed; retrying",
                    );
                    sleep_with_jitter(backoff).await;
                    backoff = (backoff * 2).min(REMOTE_RECONNECT_MAX);
                }
            }
        }
    }

    /// Dial hosted with the fresh bearer, send one hello, and hand back the
    /// open stream. The request carries no secret-derived log fields.
    async fn connect_once(
        &self,
        token: &zeroize::Zeroizing<Vec<u8>>,
        identity: &SaverIdentity,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
        use axum::http::Request;
        use tokio_tungstenite::tungstenite::handshake::client::generate_key;
        let token_text = std::str::from_utf8(token.as_slice())
            .map_err(|_| Error::engine("node credential is not UTF-8"))?;
        // A hand-built `Request` travels as-is: tungstenite only fills in the
        // handshake headers for URI connects, so generate the key and the
        // upgrade headers here alongside `Authorization`.
        let uri: axum::http::Uri = self
            .endpoint
            .url
            .parse()
            .map_err(|_| Error::engine("agent-sessions remote URL did not parse"))?;
        let host = uri
            .authority()
            .map(|authority| authority.to_string())
            .ok_or_else(|| Error::engine("agent-sessions remote URL has no host"))?;
        // The bearer never travels over cleartext off-host: `ws://` is a
        // test-only scheme and is refused unless the host is loopback.
        let is_loopback = host_is_loopback(&host);
        if uri.scheme_str() == Some("ws") && !is_loopback {
            return Err(Error::engine(
                "agent-sessions remote refuses cleartext off-host",
            ));
        }
        let request = Request::builder()
            .uri(self.endpoint.url.as_str())
            .header("Host", host)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", generate_key())
            .header("Sec-WebSocket-Version", "13")
            .header("Authorization", format!("Bearer {token_text}"))
            .body(())
            .map_err(|e| Error::engine(format!("agent-sessions remote request failed: {e}")))?;
        // Bound inbound frames at the tungstenite layer; anything larger
        // fails the connection instead of reaching the broker.
        // (`WebSocketConfig` is non-exhaustive, so set the field on a
        // default value rather than using a struct expression.)
        let mut config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
        config.max_message_size = Some(MAX_RESPONSE_BYTES);
        let (mut stream, _) = tokio::time::timeout(
            CONNECT_TIMEOUT,
            connect_async_with_config(request, Some(config), false),
        )
        .await
        .map_err(|_| Error::engine("agent-sessions remote connect timed out"))?
        .map_err(|e| Error::engine(format!("agent-sessions remote connect failed: {e}")))?;
        let hello = hello_value(
            &identity.instance,
            &identity.boot,
            &self.endpoint.account_id,
        );
        let text = serde_json::to_string(&hello)
            .map_err(|_| Error::engine("agent-sessions remote hello did not serialize"))?;
        tokio::time::timeout(SEND_TIMEOUT, stream.send(Message::Text(text.into())))
            .await
            .map_err(|_| Error::engine("agent-sessions remote hello send timed out"))?
            .map_err(|e| Error::engine(format!("agent-sessions remote hello failed: {e}")))?;
        Ok(stream)
    }

    /// Serve one connection: answer requests, heartbeat every 15 s, and
    /// return on any close or failure so the `run` loop reconnects.
    ///
    /// Relayed requests run concurrently (up to [`MAX_RELAY_IN_FLIGHT`]): one
    /// slow `history` never stalls the others. Past the cap the node answers
    /// `busy` instead of queueing without bound.
    async fn serve_stream(&self, stream: WebSocketStream<MaybeTlsStream<TcpStream>>) {
        let (write, mut read) = stream.split();
        let write = Arc::new(tokio::sync::Mutex::new(write));
        let permits = Arc::new(tokio::sync::Semaphore::new(MAX_RELAY_IN_FLIGHT));
        let follows: RemoteFollows = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let follow_permits = Arc::new(tokio::sync::Semaphore::new(MAX_REMOTE_FOLLOWS_PER_CHANNEL));
        // Finished relay tasks report back so they never accumulate: `true`
        // means the response send failed and the connection must close so
        // the `run` loop reconnects.
        let mut tasks: tokio::task::JoinSet<bool> = tokio::task::JoinSet::new();
        let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
        // The first tick fires immediately; skip it so the cadence starts
        // after a full interval on a fresh connection.
        heartbeat.tick().await;
        loop {
            tokio::select! {
                _ = heartbeat.tick() => {
                    // Bound the whole beat (lock plus send): a node-side stall
                    // ends the connection instead of wedging the loop.
                    let beat = tokio::time::timeout(SEND_TIMEOUT, async {
                        let mut guard = write.lock().await;
                        guard.send(Message::Ping(b"agent-sessions".to_vec().into())).await
                    })
                    .await;
                    if !matches!(beat, Ok(Ok(()))) {
                        break;
                    }
                }
                done = tasks.join_next(), if !tasks.is_empty() => {
                    if matches!(done, Some(Ok(true))) {
                        break;
                    }
                }
                next = read.next() => {
                    match next {
                        None => break,
                        Some(Err(_)) => break,
                        Some(Ok(Message::Close(_))) => break,
                        Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
                        Some(Ok(Message::Binary(_))) => {
                            // Binary is not part of the contract; ignore it.
                        }
                        Some(Ok(Message::Text(text))) => {
                            let request: Value = match serde_json::from_str(&text) {
                                Ok(request) => request,
                                Err(_) => continue,
                            };
                            if request.get("type").and_then(Value::as_str) != Some("request") {
                                continue;
                            }
                            let op = request.get("op").and_then(Value::as_str).unwrap_or("");
                            if op == "follow" || op == "unfollow" {
                                let broker = self.broker.clone();
                                let write = write.clone();
                                let follows = follows.clone();
                                let follow_permits = follow_permits.clone();
                                tasks.spawn(async move {
                                    serve_follow_request(
                                        broker,
                                        write,
                                        follows,
                                        follow_permits,
                                        request,
                                    )
                                    .await
                                });
                                continue;
                            }
                            let id = request.get("id").cloned().unwrap_or(Value::Null);
                            match permits.clone().try_acquire_owned() {
                                Err(_) => {
                                    let busy = json!({"type": "response", "id": id, "ok": false, "code": "busy", "message": "too many in-flight relay requests"});
                                    let frame = serde_json::to_string(&busy).unwrap_or_else(|_| String::from("{}"));
                                    let refused = tokio::time::timeout(SEND_TIMEOUT, async {
                                        let mut guard = write.lock().await;
                                        guard.send(Message::Text(frame.into())).await
                                    })
                                    .await;
                                    if !matches!(refused, Ok(Ok(()))) {
                                        break;
                                    }
                                }
                                Ok(permit) => {
                                    let broker = self.broker.clone();
                                    let write = write.clone();
                                    tasks.spawn(async move {
                                        let _permit = permit;
                                        let response = answer_request(&broker, &request).await;
                                        let frame = match serde_json::to_string(&response) {
                                            Ok(frame) => frame,
                                            Err(_) => return false,
                                        };
                                        let sent = tokio::time::timeout(SEND_TIMEOUT, async {
                                            let mut guard = write.lock().await;
                                            guard.send(Message::Text(frame.into())).await
                                        })
                                        .await;
                                        !matches!(sent, Ok(Ok(())))
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        // Best-effort goodbye: a failed send already decided to reconnect, and
        // a clean close lets hosted drain instead of timing the node out.
        let _ = tokio::time::timeout(SEND_TIMEOUT, async {
            let mut guard = write.lock().await;
            guard.close().await
        })
        .await;
        tasks.abort_all();
        // Channel close unfollows everything: free poll tasks and push state.
        let owned: Vec<String> = {
            let mut guard = follows.lock().await;
            guard
                .drain()
                .map(|(id, handle)| {
                    handle.abort();
                    id
                })
                .collect()
        };
        for id in owned {
            broker_ref(&self.broker, &id).await;
        }
    }
}

/// Unfollow helper for channel teardown (avoids borrowing `self` in the drain).
async fn broker_ref(broker: &Arc<AgentSessionsBroker>, id: &str) {
    broker.unfollow(id).await;
}

/// Serve one `follow`/`unfollow` request on the remote channel. Returns `true`
/// when the response send failed and the connection must close. `follow`
/// reserves a budget permit (at most [`MAX_REMOTE_FOLLOWS_PER_CHANNEL`] per
/// channel); the permit moves into the forwarder so it frees only when the
/// follow ends. Events are never sent before the follow response: the
/// forwarder waits on a release fired after the response is on the wire,
/// mirroring the socket `PushRelease` pattern.
async fn serve_follow_request(
    broker: Arc<AgentSessionsBroker>,
    write: Arc<
        tokio::sync::Mutex<
            futures::stream::SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
        >,
    >,
    follows: RemoteFollows,
    follow_permits: Arc<tokio::sync::Semaphore>,
    request: Value,
) -> bool {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let op = request.get("op").and_then(Value::as_str).unwrap_or("");
    let args = request.get("args").cloned().unwrap_or(json!({}));
    let send_write = write.clone();
    let send = move |response: Value| {
        let write = send_write.clone();
        async move {
            let frame = serde_json::to_string(&response).unwrap_or_else(|_| String::from("{}"));
            let sent = tokio::time::timeout(SEND_TIMEOUT, async {
                let mut guard = write.lock().await;
                guard.send(Message::Text(frame.into())).await
            })
            .await;
            !matches!(sent, Ok(Ok(())))
        }
    };
    let fail = |code: &str, message: String| {
        cap_response(
            json!({"type": "response", "id": id, "ok": false, "code": code, "message": message}),
        )
    };
    if op == "unfollow" {
        let subscription_id = args
            .get("subscriptionId")
            .and_then(Value::as_str)
            .unwrap_or("");
        if subscription_id.is_empty() {
            return send(fail("invalid", "unfollow needs subscriptionId".into())).await;
        }
        let owned = follows.lock().await.remove(subscription_id);
        if let Some(handle) = owned {
            handle.abort();
            broker.unfollow(subscription_id).await;
            let response = json!({"type": "response", "id": id, "ok": true, "value": {"subscriptionId": subscription_id, "unfollowed": true}});
            return send(cap_response(response)).await;
        }
        let response = json!({"type": "response", "id": id, "ok": true, "value": {"subscriptionId": subscription_id, "unfollowed": false}});
        return send(cap_response(response)).await;
    }
    // op == "follow"
    let host_id = args.get("hostId").and_then(Value::as_str).unwrap_or("");
    let host_epoch = args.get("hostEpoch").and_then(Value::as_str).unwrap_or("");
    let session_id = args.get("sessionId").and_then(Value::as_str).unwrap_or("");
    if host_id.is_empty() || host_epoch.is_empty() || session_id.is_empty() {
        return send(fail(
            "invalid",
            "follow needs hostId, hostEpoch and sessionId".into(),
        ))
        .await;
    }
    let permit = match follow_permits.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return send(fail("busy", "too many follows for this channel".into())).await;
        }
    };
    let (tx, rx) = tokio::sync::mpsc::channel(super::broker::PUSH_CHANNEL_BOUND);
    let (subscription_id, snapshot) = match broker.follow(host_id, host_epoch, session_id, tx).await
    {
        Ok(pair) => pair,
        Err(refusal) => {
            drop(permit);
            return send(fail(refusal.code(), refusal.message().to_owned())).await;
        }
    };
    // Release-after-reply: the forwarder waits for this before writing
    // anything, so no event can precede the response frame.
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let response = cap_response(json!({
        "type": "response",
        "id": id,
        "ok": true,
        "value": {"subscriptionId": subscription_id, "snapshot": snapshot},
    }));
    let failed_response = response.get("ok").and_then(Value::as_bool) != Some(true);
    if failed_response {
        drop(release_tx);
        drop(permit);
        broker.unfollow(&subscription_id).await;
        return send(response).await;
    }
    // Spawn the forwarder before replying so a fast push cannot be lost; it
    // blocks on the release until the response is on the wire.
    let forward_handle = {
        let broker = broker.clone();
        let write = write.clone();
        let follows = follows.clone();
        let subscription_id = subscription_id.clone();
        tokio::spawn(async move {
            let _permit = permit;
            forward_remote_pushes(broker, follows, write, rx, release_rx, subscription_id).await;
        })
    };
    follows
        .lock()
        .await
        .insert(subscription_id.clone(), forward_handle);
    let send_failed = send(response).await;
    if send_failed {
        let handle = follows.lock().await.remove(&subscription_id);
        if let Some(handle) = handle {
            handle.abort();
        }
        broker.unfollow(&subscription_id).await;
        return true;
    }
    let _ = release_tx.send(());
    false
}

/// Sleep `base` plus time-derived jitter in `[base, 1.5 * base)`: decorrelated
/// enough to avoid reconnect herds without a new RNG dependency.
async fn sleep_with_jitter(base: Duration) {
    let half_ms = base.as_millis().max(1) as u64 / 2 + 1;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.subsec_nanos() as u64 + d.as_secs() * 1_000_000_007) % half_ms)
        .unwrap_or(0);
    tokio::time::sleep(base + Duration::from_millis(nanos)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::agent_sessions::test_support::{self, FakeDaemon, FakeScript};
    use std::collections::VecDeque;
    use tokio::sync::mpsc as tmpsc;

    type ServerWs = WebSocketStream<tokio::net::TcpStream>;

    struct ServerConn {
        ws: ServerWs,
        auth: String,
        hello: Value,
    }

    struct FakeHosted {
        url: String,
        hellos: Arc<std::sync::Mutex<Vec<Value>>>,
        auths: Arc<std::sync::Mutex<Vec<String>>>,
        conns: tmpsc::UnboundedReceiver<ServerConn>,
        _task: tokio::task::JoinHandle<()>,
    }

    impl FakeHosted {
        async fn new() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!(
                "ws://{}/databases/db1/nodes/connect",
                listener.local_addr().unwrap()
            );
            let hellos = Arc::new(std::sync::Mutex::new(Vec::new()));
            let auths = Arc::new(std::sync::Mutex::new(Vec::new()));
            let (tx, conns) = tmpsc::unbounded_channel();
            let task = {
                let hellos = hellos.clone();
                let auths = auths.clone();
                tokio::spawn(async move {
                    loop {
                        let Ok((stream, _)) = listener.accept().await else {
                            break;
                        };
                        let hellos = hellos.clone();
                        let auths = auths.clone();
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            let auth_seen = Arc::new(std::sync::Mutex::new(String::new()));
                            let auth_inner = auth_seen.clone();
                            let mut ws: ServerWs = match tokio_tungstenite::accept_hdr_async(
                                stream,
                                // The callback signature is fixed by
                                // `accept_hdr_async`: the large `Err`
                                // variant is tungstenite's, not ours.
                                #[allow(clippy::result_large_err)]
                                move |req: &axum::http::Request<()>,
                                      resp: tokio_tungstenite::tungstenite::handshake::server::Response|
                                      -> std::result::Result<
                                    tokio_tungstenite::tungstenite::handshake::server::Response,
                                    tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
                                > {
                                    let auth = req
                                        .headers()
                                        .get("authorization")
                                        .and_then(|v| v.to_str().ok())
                                        .unwrap_or("")
                                        .to_owned();
                                    *auth_inner.lock().unwrap() = auth;
                                    Ok(resp)
                                },
                            )
                            .await
                            {
                                Ok(ws) => ws,
                                Err(_) => return,
                            };
                            let auth = auth_seen.lock().unwrap().clone();
                            // First frame must be the node hello.
                            let hello = match tokio::time::timeout(
                                Duration::from_secs(10),
                                ws.next(),
                            )
                            .await
                            {
                                Ok(Some(Ok(Message::Text(text)))) => {
                                    serde_json::from_str::<Value>(&text).unwrap_or(json!(null))
                                }
                                _ => return,
                            };
                            hellos.lock().unwrap().push(hello.clone());
                            auths.lock().unwrap().push(auth.clone());
                            let _ = tx.send(ServerConn { ws, auth, hello });
                        });
                    }
                })
            };
            Self {
                url,
                hellos,
                auths,
                conns,
                _task: task,
            }
        }

        async fn next_conn(&mut self, label: &str) -> ServerConn {
            tokio::time::timeout(Duration::from_secs(10), self.conns.recv())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for {label}"))
                .expect("hosted still accepting")
        }

        fn hello_count(&self) -> usize {
            self.hellos.lock().unwrap().len()
        }
    }

    fn credential_file(dir: &Path, token: &str) -> PathBuf {
        let path = dir.join(format!("node-cred-{}", uuid::Uuid::new_v4().simple()));
        std::fs::write(&path, token.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    fn socket_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    async fn broker_with_daemon(
        script: FakeScript,
    ) -> (
        FakeDaemon,
        Arc<AgentSessionsBroker>,
        tokio::task::JoinHandle<()>,
    ) {
        let daemon = FakeDaemon::new(script).await;
        let env_dir = tempfile::tempdir().unwrap();
        let env = test_support::password_env(env_dir.path());
        // Keep env_dir alive via the daemon task? No: broker only needs the
        // path; leak the dir for the test lifetime.
        std::mem::forget(env_dir);
        let broker =
            test_support::broker_for(&daemon.url, &daemon.script.lock().await.server_id, &env);
        let task = test_support::run_until_reachable(&broker).await;
        (daemon, broker, task)
    }

    async fn request(conn: &mut ServerConn, op: &str, args: Value, id: &str) -> Value {
        conn.ws
            .send(Message::Text(
                json!({"type": "request", "id": id, "op": op, "args": args})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), conn.ws.next())
                .await
                .expect("response in time")
                .expect("stream open")
                .expect("ws ok");
            if let Message::Text(text) = msg {
                let value: Value = serde_json::from_str(&text).unwrap();
                if value.get("type").and_then(Value::as_str) == Some("response") {
                    return value;
                }
            }
        }
    }

    #[test]
    fn connect_url_derivation_maps_scheme_and_path() {
        let ws = RemoteEndpoint::connect_url_for("http://h:1/base", "db1").unwrap();
        assert_eq!(ws, "ws://h:1/base/databases/db1/nodes/connect");
        let wss = RemoteEndpoint::connect_url_for("https://h/", "db1").unwrap();
        assert_eq!(wss, "wss://h/databases/db1/nodes/connect");
        assert!(RemoteEndpoint::connect_url_for("http://h/", "..").is_err());
        assert!(RemoteEndpoint::connect_url_for("ws://h/", "db1").is_err());
    }

    #[test]
    fn heartbeat_cadence_is_fifteen_seconds() {
        assert_eq!(HEARTBEAT_INTERVAL, Duration::from_secs(15));
    }

    #[test]
    fn loopback_check_covers_bracketed_ipv6() {
        for loopback in [
            "localhost",
            "localhost:8080",
            "127.0.0.1",
            "127.0.0.1:1",
            "::1",
            "[::1]",
            "[::1]:8080",
            "user@[::1]:8080",
            "::ffff:127.0.0.1",
        ] {
            assert!(host_is_loopback(loopback), "{loopback}");
        }
        for remote in [
            "example.com",
            "example.com:80",
            "10.0.0.1",
            "10.0.0.1:8080",
            "[::2]",
            "[::2]:8080",
            "[::1",
            "",
        ] {
            assert!(!host_is_loopback(remote), "{remote}");
        }
    }

    #[test]
    fn remote_config_absent_or_false_means_no_channel() {
        use crate::node::agent_sessions::config::{AGENT_SESSIONS_CONTRACT, AGENT_SESSIONS_FILE};
        // Absent remote key: no channel.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(AGENT_SESSIONS_FILE),
            format!(
                r#"{{"contract":{contract:?},"daemon":{{"url":"ws://127.0.0.1:1/ws","server_id":"s","auth":{{"kind":"local_credential","paseo_home":"~"}}}}}}"#,
                contract = AGENT_SESSIONS_CONTRACT,
            ),
        )
        .unwrap();
        let loaded = crate::node::agent_sessions::load_agent_sessions(dir.path(), Some("a"))
            .unwrap()
            .unwrap();
        assert!(!loaded.config.remote_enabled());
        // Explicit false: no channel. Empty object defaults to disabled.
        for body in [r#"{"enabled":false}"#.to_owned(), r#"{}"#.to_owned()] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join(AGENT_SESSIONS_FILE),
                format!(
                    r#"{{"contract":{contract:?},"daemon":{{"url":"ws://127.0.0.1:1/ws","server_id":"s","auth":{{"kind":"local_credential","paseo_home":"~"}}}},"remote":{body}}}"#,
                    contract = AGENT_SESSIONS_CONTRACT,
                ),
            )
            .unwrap();
            let loaded = crate::node::agent_sessions::load_agent_sessions(dir.path(), Some("a"))
                .unwrap()
                .unwrap();
            assert!(!loaded.config.remote_enabled(), "{body}");
        }
        // True: channel on.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(AGENT_SESSIONS_FILE),
            format!(
                r#"{{"contract":{contract:?},"daemon":{{"url":"ws://127.0.0.1:1/ws","server_id":"s","auth":{{"kind":"local_credential","paseo_home":"~"}}}},"remote":{{"enabled":true}}}}"#,
                contract = AGENT_SESSIONS_CONTRACT,
            ),
        )
        .unwrap();
        let loaded = crate::node::agent_sessions::load_agent_sessions(dir.path(), Some("a"))
            .unwrap()
            .unwrap();
        assert!(loaded.config.remote_enabled());
        // Unknown remote fields are refused.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(AGENT_SESSIONS_FILE),
            format!(
                r#"{{"contract":{contract:?},"daemon":{{"url":"ws://127.0.0.1:1/ws","server_id":"s","auth":{{"kind":"local_credential","paseo_home":"~"}}}},"remote":{{"enabled":true,"extra":1}}}}"#,
                contract = AGENT_SESSIONS_CONTRACT,
            ),
        )
        .unwrap();
        assert!(crate::node::agent_sessions::load_agent_sessions(dir.path(), Some("a")).is_err());
    }

    #[tokio::test]
    async fn hello_shape_and_bearer() {
        let (_daemon, broker, _btask) = broker_with_daemon(FakeScript::one()).await;
        let mut hosted = FakeHosted::new().await;
        let sock = socket_dir();
        let cred = credential_file(sock.path(), "test-token-abc");
        let channel = RemoteChannel::new(
            broker,
            RemoteEndpoint {
                url: hosted.url.clone(),
                credential_file: cred,
                account_id: "acct-1".into(),
                socket_dir: sock.path().to_owned(),
            },
        );
        let task = tokio::spawn(channel.run());
        let conn = hosted.next_conn("hello").await;
        assert_eq!(conn.auth, "Bearer test-token-abc");
        assert_eq!(conn.hello["type"], "hello");
        assert_eq!(conn.hello["contract"], REMOTE_CONTRACT);
        assert_eq!(conn.hello["account_id"], "acct-1");
        assert_eq!(
            conn.hello["operations"],
            json!(["capabilities", "list", "history", "follow"])
        );
        assert!(conn.hello["node_instance"]
            .as_str()
            .is_some_and(|s| !s.is_empty()));
        assert!(conn.hello["boot"].as_str().is_some_and(|s| !s.is_empty()));
        task.abort();
    }

    #[tokio::test]
    async fn relay_matches_socket_tools() {
        let (_daemon, broker, _btask) = broker_with_daemon(FakeScript::one()).await;
        let mut hosted = FakeHosted::new().await;
        let sock = socket_dir();
        let cred = credential_file(sock.path(), "tok-relay");
        let channel = RemoteChannel::new(
            broker.clone(),
            RemoteEndpoint {
                url: hosted.url.clone(),
                credential_file: cred,
                account_id: "acct-1".into(),
                socket_dir: sock.path().to_owned(),
            },
        );
        let task = tokio::spawn(channel.run());
        let mut conn = hosted.next_conn("relay hello").await;
        let caps = request(&mut conn, "capabilities", json!({}), "c1").await;
        assert_eq!(caps["ok"], true);
        assert_eq!(caps["value"], broker.capabilities_payload().await);
        let list = request(&mut conn, "list", json!({}), "l1").await;
        assert_eq!(list["ok"], true);
        assert_eq!(list["value"], broker.list(None).await.unwrap());
        let summary = broker.host_summary().await;
        let hist = request(
            &mut conn,
            "history",
            json!({
                "hostId": summary["id"],
                "hostEpoch": summary["epoch"],
                "sessionId": "a",
            }),
            "h1",
        )
        .await;
        assert_eq!(hist["ok"], true);
        assert_eq!(
            hist["value"],
            broker
                .history(
                    summary["id"].as_str().unwrap(),
                    summary["epoch"].as_str().unwrap(),
                    "a",
                    None,
                    None
                )
                .await
                .unwrap()
        );
        task.abort();
    }

    #[tokio::test]
    async fn unknown_op_is_invalid() {
        let (_daemon, broker, _btask) = broker_with_daemon(FakeScript::one()).await;
        let mut hosted = FakeHosted::new().await;
        let sock = socket_dir();
        let cred = credential_file(sock.path(), "tok-invalid");
        let channel = RemoteChannel::new(
            broker,
            RemoteEndpoint {
                url: hosted.url.clone(),
                credential_file: cred,
                account_id: "acct-1".into(),
                socket_dir: sock.path().to_owned(),
            },
        );
        let task = tokio::spawn(channel.run());
        let mut conn = hosted.next_conn("invalid hello").await;
        for op in ["bogus", "send", ""] {
            let reply = request(&mut conn, op, json!({}), "x").await;
            assert_eq!(reply["ok"], false, "{op}");
            assert_eq!(reply["code"], "invalid", "{op}");
        }
        task.abort();
    }

    #[tokio::test]
    async fn requests_beyond_concurrency_cap_get_busy() {
        use std::collections::HashMap;
        use std::sync::atomic::Ordering;

        let (daemon, broker, _btask) = broker_with_daemon(FakeScript::one()).await;
        // Wedge the daemon mid-discovery so relay tasks pile up on permits.
        daemon.hang_fetch.store(true, Ordering::SeqCst);
        let mut hosted = FakeHosted::new().await;
        let sock = socket_dir();
        let cred = credential_file(sock.path(), "tok-busy");
        let channel = RemoteChannel::new(
            broker,
            RemoteEndpoint {
                url: hosted.url.clone(),
                credential_file: cred,
                account_id: "acct-1".into(),
                socket_dir: sock.path().to_owned(),
            },
        );
        let task = tokio::spawn(channel.run());
        let mut conn = hosted.next_conn("busy hello").await;
        // Fill every relay permit with a hung `list`, without reading back.
        for n in 0..MAX_RELAY_IN_FLIGHT {
            let id = format!("hung-{n}");
            conn.ws
                .send(Message::Text(
                    json!({"type": "request", "id": id, "op": "list", "args": {}})
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();
        }
        // Let all sixteen tasks take their permits before the next request.
        tokio::time::sleep(Duration::from_millis(500)).await;
        // The seventeenth request is refused `busy` instead of queueing.
        conn.ws
            .send(Message::Text(
                json!({"type": "request", "id": "over-cap", "op": "list", "args": {}})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        let mut busy = false;
        let mut answered: HashMap<String, Value> = HashMap::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline && !busy {
            let msg = tokio::time::timeout(Duration::from_secs(10), conn.ws.next())
                .await
                .expect("response in time")
                .expect("stream open")
                .expect("ws ok");
            if let Message::Text(text) = msg {
                let value: Value = serde_json::from_str(&text).unwrap();
                if value.get("type").and_then(Value::as_str) == Some("response") {
                    let id = value["id"].as_str().unwrap_or("").to_owned();
                    if id == "over-cap" {
                        assert_eq!(value["ok"], false);
                        assert_eq!(value["code"], "busy");
                        busy = true;
                    } else {
                        answered.insert(id, value);
                    }
                }
            }
        }
        assert!(busy, "over-cap request must be refused busy");
        // Unwedge: the sixteen hung requests still complete normally.
        daemon.hang_fetch.store(false, Ordering::SeqCst);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while answered.len() < MAX_RELAY_IN_FLIGHT && tokio::time::Instant::now() < deadline {
            let msg = tokio::time::timeout(Duration::from_secs(10), conn.ws.next())
                .await
                .expect("response in time")
                .expect("stream open")
                .expect("ws ok");
            if let Message::Text(text) = msg {
                let value: Value = serde_json::from_str(&text).unwrap();
                if value.get("type").and_then(Value::as_str) == Some("response") {
                    let id = value["id"].as_str().unwrap_or("").to_owned();
                    answered.insert(id, value);
                }
            }
        }
        assert_eq!(answered.len(), MAX_RELAY_IN_FLIGHT);
        assert!(answered.values().all(|reply| reply["ok"] == true));
        task.abort();
    }

    #[tokio::test]
    async fn oversize_response_is_refused() {
        let mut script = FakeScript::one();
        script.agents = (0..3000)
            .map(|i| test_support::snap(&format!("sess-{i:05}")))
            .collect();
        script.timelines.clear();
        let (_daemon, broker, _btask) = broker_with_daemon(script).await;
        let mut hosted = FakeHosted::new().await;
        let sock = socket_dir();
        let cred = credential_file(sock.path(), "tok-big");
        let channel = RemoteChannel::new(
            broker,
            RemoteEndpoint {
                url: hosted.url.clone(),
                credential_file: cred,
                account_id: "acct-1".into(),
                socket_dir: sock.path().to_owned(),
            },
        );
        let task = tokio::spawn(channel.run());
        let mut conn = hosted.next_conn("oversize hello").await;
        let reply = request(&mut conn, "list", json!({}), "big").await;
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["code"], "unavailable");
        task.abort();
    }

    #[tokio::test]
    async fn reconnect_after_server_close() {
        let (_daemon, broker, _btask) = broker_with_daemon(FakeScript::one()).await;
        let mut hosted = FakeHosted::new().await;
        let sock = socket_dir();
        let cred = credential_file(sock.path(), "tok-reconnect");
        let channel = RemoteChannel::new(
            broker,
            RemoteEndpoint {
                url: hosted.url.clone(),
                credential_file: cred,
                account_id: "acct-1".into(),
                socket_dir: sock.path().to_owned(),
            },
        );
        let task = tokio::spawn(channel.run());
        let mut first = hosted.next_conn("first hello").await;
        assert_eq!(hosted.hello_count(), 1);
        first.ws.close(None).await.ok();
        drop(first);
        let second = hosted.next_conn("second hello").await;
        assert_eq!(hosted.hello_count(), 2);
        assert_eq!(second.auth, "Bearer tok-reconnect");
        task.abort();
    }

    #[tokio::test]
    async fn token_is_reread_on_reconnect() {
        let (_daemon, broker, _btask) = broker_with_daemon(FakeScript::one()).await;
        let mut hosted = FakeHosted::new().await;
        let sock = socket_dir();
        let cred = credential_file(sock.path(), "tok-first");
        let channel = RemoteChannel::new(
            broker,
            RemoteEndpoint {
                url: hosted.url.clone(),
                credential_file: cred.clone(),
                account_id: "acct-1".into(),
                socket_dir: sock.path().to_owned(),
            },
        );
        let task = tokio::spawn(channel.run());
        let mut first = hosted.next_conn("token hello 1").await;
        assert_eq!(first.auth, "Bearer tok-first");
        // Rotate the file, then drop the server side so the channel redials
        // with a freshly read token.
        std::fs::write(&cred, b"tok-second").unwrap();
        first.ws.close(None).await.ok();
        drop(first);
        let second = hosted.next_conn("token hello 2").await;
        assert_eq!(second.auth, "Bearer tok-second");
        assert_eq!(hosted.auths.lock().unwrap().len(), 2);
        task.abort();
    }

    #[tokio::test]
    async fn remote_follow_matches_socket_tools() {
        let (_daemon, broker, _btask) = broker_with_daemon(FakeScript::one()).await;
        let mut hosted = FakeHosted::new().await;
        let sock = socket_dir();
        let cred = credential_file(sock.path(), "tok-follow-match");
        let channel = RemoteChannel::new(
            broker.clone(),
            RemoteEndpoint {
                url: hosted.url.clone(),
                credential_file: cred,
                account_id: "acct-1".into(),
                socket_dir: sock.path().to_owned(),
            },
        );
        let task = tokio::spawn(channel.run());
        let mut conn = hosted.next_conn("follow hello").await;
        let summary = broker.host_summary().await;
        let host_id = summary["id"].as_str().unwrap();
        let epoch = summary["epoch"].as_str().unwrap();
        let reply = request(
            &mut conn,
            "follow",
            json!({"hostId": host_id, "hostEpoch": epoch, "sessionId": "a"}),
            "f1",
        )
        .await;
        assert_eq!(reply["ok"], true);
        let sub = reply["value"]["subscriptionId"].as_str().unwrap();
        assert!(!sub.is_empty());
        let snapshot = reply["value"]["snapshot"].clone();
        let history = broker
            .history(host_id, epoch, "a", None, None)
            .await
            .unwrap();
        assert_eq!(snapshot["items"], history["items"]);
        let unfollow = request(&mut conn, "unfollow", json!({"subscriptionId": sub}), "u1").await;
        assert_eq!(unfollow["ok"], true);
        assert_eq!(unfollow["value"]["unfollowed"], true);
        let again = request(&mut conn, "unfollow", json!({"subscriptionId": sub}), "u2").await;
        assert_eq!(again["value"]["unfollowed"], false);
        task.abort();
    }

    #[tokio::test]
    async fn remote_follow_events_follow_response_order() {
        let (_daemon, broker, _btask) = broker_with_daemon(FakeScript::one()).await;
        let mut hosted = FakeHosted::new().await;
        let sock = socket_dir();
        let cred = credential_file(sock.path(), "tok-follow-order");
        let channel = RemoteChannel::new(
            broker.clone(),
            RemoteEndpoint {
                url: hosted.url.clone(),
                credential_file: cred,
                account_id: "acct-1".into(),
                socket_dir: sock.path().to_owned(),
            },
        );
        let task = tokio::spawn(channel.run());
        let mut conn = hosted.next_conn("order hello").await;
        let summary = broker.host_summary().await;
        let host_id = summary["id"].as_str().unwrap().to_owned();
        let epoch = summary["epoch"].as_str().unwrap().to_owned();
        conn.ws
            .send(Message::Text(
                json!({"type": "request", "id": "f1", "op": "follow", "args": {"hostId": host_id, "hostEpoch": epoch, "sessionId": "a"}})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        // The first frame after the request must be the response: the
        // forwarder waits on the release fired after the reply is on the
        // wire, so no event can precede it.
        let first = tokio::time::timeout(Duration::from_secs(10), conn.ws.next())
            .await
            .expect("response in time")
            .expect("stream open")
            .expect("ws ok");
        if let Message::Text(text) = first {
            let value: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(value.get("type").and_then(Value::as_str), Some("response"));
            assert_eq!(value["ok"], true);
        } else {
            panic!("first frame must be a text response");
        }
        task.abort();
    }

    #[tokio::test]
    async fn remote_channel_close_unfollows_everything() {
        let (_daemon, broker, _btask) = broker_with_daemon(FakeScript::one()).await;
        let mut hosted = FakeHosted::new().await;
        let sock = socket_dir();
        let cred = credential_file(sock.path(), "tok-follow-close");
        let channel = RemoteChannel::new(
            broker.clone(),
            RemoteEndpoint {
                url: hosted.url.clone(),
                credential_file: cred,
                account_id: "acct-1".into(),
                socket_dir: sock.path().to_owned(),
            },
        );
        let task = tokio::spawn(channel.run());
        let mut conn = hosted.next_conn("close hello").await;
        let summary = broker.host_summary().await;
        let host_id = summary["id"].as_str().unwrap();
        let epoch = summary["epoch"].as_str().unwrap();
        let reply = request(
            &mut conn,
            "follow",
            json!({"hostId": host_id, "hostEpoch": epoch, "sessionId": "a"}),
            "f1",
        )
        .await;
        let sub = reply["value"]["subscriptionId"]
            .as_str()
            .unwrap()
            .to_owned();
        // Closing the channel must unfollow everything: the broker record is
        // gone, so a direct unfollow finds nothing left.
        task.abort();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if !broker.unfollow(&sub).await {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                panic!("channel close did not unfollow");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Drive one forwarder against a dead peer without any channel: the
    /// socket pair's reader is dropped up front, so the first forwarded
    /// push fails fast (RST) with no buffer-filling, no sleeps, and — since
    /// there is no channel at all — no teardown drain that could release
    /// the sub instead of the cleanup.
    async fn forwarder_against_dead_peer(
        broker: &Arc<AgentSessionsBroker>,
        follows: RemoteFollows,
        session: &str,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio_tungstenite::tungstenite::protocol::Role;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server_tcp, _) = listener.accept().await.unwrap();
        // Zero linger makes the drop send RST rather than FIN, so the
        // forwarder's first write fails deterministically instead of being
        // accepted by the kernel before the reset comes back.
        peer.set_zero_linger().unwrap();
        drop(peer);
        let ws =
            WebSocketStream::from_raw_socket(MaybeTlsStream::Plain(server_tcp), Role::Server, None)
                .await;
        let (write, _read) = ws.split();
        let write = Arc::new(tokio::sync::Mutex::new(write));
        let summary = broker.host_summary().await;
        let (tx, rx) = tmpsc::channel::<PushEvent>(8);
        let (sub, _snapshot) = broker
            .follow(
                summary["id"].as_str().unwrap(),
                summary["epoch"].as_str().unwrap(),
                session,
                tx,
            )
            .await
            .unwrap();
        let (_release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(forward_remote_pushes(
            broker.clone(),
            follows.clone(),
            write,
            rx,
            release_rx,
            sub.clone(),
        ));
        (sub, task)
    }

    #[tokio::test]
    async fn remote_forwarder_send_failure_releases_the_broker_sub() {
        // Only the forwarder cleanup can release this sub: the session stays
        // live (no terminal push), there is no channel (no teardown drain),
        // and no unfollow is ever sent.
        let (daemon, broker, _btask) = broker_with_daemon(FakeScript::one()).await;
        let follows: RemoteFollows = Default::default();
        let (sub, task) = forwarder_against_dead_peer(&broker, follows.clone(), "a").await;
        assert_eq!(broker.subscription_count().await, 1);
        // Trigger a push: the forwarder's send fails on the dead peer,
        // ends, and its cleanup removes the record and releases the sub.
        {
            let mut script = daemon.script.lock().await;
            script
                .timelines
                .get_mut("a")
                .expect("session a timeline")
                .push(test_support::text_entry(2, "hi-2"));
        }
        tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("forwarder ends after the failed send")
            .expect("forwarder completes");
        assert!(follows.lock().await.get(&sub).is_none());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if broker.subscription_count().await == 0 {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                panic!("send failure did not release the broker sub");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[tokio::test]
    async fn remote_broker_ended_follow_releases_the_channel_record() {
        // Normal path: the session ends, the poll loop pushes Ended, the
        // forwarder relays it and its cleanup releases the channel record.
        // No manual unfollow anywhere.
        let (daemon, broker, _btask) = broker_with_daemon(FakeScript::one()).await;
        let follows: RemoteFollows = Default::default();
        let (_sub, task) = forwarder_against_dead_peer(&broker, follows.clone(), "a").await;
        // End the session: the agent disappears, so the next poll ends the
        // follow with a terminal event instead of a snapshot.
        {
            let mut script = daemon.script.lock().await;
            script
                .agents
                .retain(|a| a.get("id").and_then(Value::as_str) != Some("a"));
        }
        tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("forwarder ends after the terminal event")
            .expect("forwarder completes");
        assert!(follows.lock().await.is_empty());
    }

    /// Cleanup must never abort the forwarder task it cleans up after: the
    /// old shape aborted the record's own handle and then awaited the
    /// broker unfollow, so a yield in between cancelled the unfollow and
    /// leaked the broker-side follow. The victim below blocks forever
    /// holding a drop probe, so any abort is observable: the new shape only
    /// detaches the record and the victim keeps running.
    #[tokio::test]
    async fn remote_cleanup_never_aborts_the_forwarder_task() {
        struct AbortProbe(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for AbortProbe {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let (_daemon, broker, _btask) = broker_with_daemon(FakeScript::one()).await;
        let follows: RemoteFollows = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let aborted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let probe = AbortProbe(aborted.clone());
        let (_alive_tx, alive_rx) = tokio::sync::oneshot::channel::<()>();
        let victim = tokio::spawn(async move {
            let _probe = probe;
            let _ = alive_rx.await;
        });
        follows.lock().await.insert("sub-victim".to_owned(), victim);
        cleanup_remote_follow(&follows, &broker, "sub-victim").await;
        // The channel-side record is gone synchronously.
        assert!(follows.lock().await.get("sub-victim").is_none());
        // An abort would drop the victim at once; a hundred milliseconds is
        // orders of magnitude past abort latency, so a quiet probe proves
        // the victim is still running.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !aborted.load(std::sync::atomic::Ordering::SeqCst),
            "cleanup aborted the forwarder task"
        );
    }

    #[tokio::test]
    async fn remote_follow_budget_is_sixteen_per_channel() {
        let (_daemon, broker, _btask) = broker_with_daemon(FakeScript::one()).await;
        let mut hosted = FakeHosted::new().await;
        let sock = socket_dir();
        let cred = credential_file(sock.path(), "tok-follow-budget");
        let channel = RemoteChannel::new(
            broker.clone(),
            RemoteEndpoint {
                url: hosted.url.clone(),
                credential_file: cred,
                account_id: "acct-1".into(),
                socket_dir: sock.path().to_owned(),
            },
        );
        let task = tokio::spawn(channel.run());
        let mut conn = hosted.next_conn("budget hello").await;
        let summary = broker.host_summary().await;
        let host_id = summary["id"].as_str().unwrap();
        let epoch = summary["epoch"].as_str().unwrap();
        let mut subs = Vec::new();
        for n in 0..MAX_REMOTE_FOLLOWS_PER_CHANNEL {
            let reply = request(
                &mut conn,
                "follow",
                json!({"hostId": host_id, "hostEpoch": epoch, "sessionId": "a"}),
                &format!("f{n}"),
            )
            .await;
            assert_eq!(reply["ok"], true, "{n}");
            subs.push(
                reply["value"]["subscriptionId"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            );
        }
        let over = request(
            &mut conn,
            "follow",
            json!({"hostId": host_id, "hostEpoch": epoch, "sessionId": "a"}),
            "over",
        )
        .await;
        assert_eq!(over["ok"], false);
        assert_eq!(over["code"], "busy");
        task.abort();
    }

    #[test]
    fn remote_oversize_snapshot_becomes_resync() {
        let big = Value::String("x".repeat(MAX_RESPONSE_BYTES));
        let event = crate::node::agent_sessions::broker::PushEvent::Snapshot(big);
        let frame = remote_event_frame("sub-1", &event);
        let value: Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(value["kind"], "resync");
        assert!(value.get("items").is_none());
    }

    #[allow(dead_code)]
    fn _no_connection_without_remote(_: ()) {
        // `serve` only spawns `RemoteChannel::run` when
        // `broker.config_remote_enabled()` is true (see the
        // `remote_config_absent_or_false_means_no_channel` test): absent or
        // false performs no connection attempt.
        let _ = VecDeque::<u8>::new();
    }
}
