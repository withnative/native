//! MCP-aware stdio shim for `node connect`: survives node EOF with bounded
//! reconnect, replays only legacy `initialize`, and never replays business
//! calls. See `docs/local-node.md`.

use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::error::{Error, Result};

use super::owner_uid;

/// Reconnect policy for the stdio shim. Fixed, not operator configuration:
/// a node restart for an upgrade should complete well inside this window,
/// and a longer wait would leave an agent silently without tools.
#[derive(Clone, Copy)]
pub(crate) struct ShimPolicy {
    pub(crate) window: Duration,
    pub(crate) initial_delay: Duration,
    pub(crate) max_delay: Duration,
}

impl Default for ShimPolicy {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(180),
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
        }
    }
}

const SHIM_QUEUE_FRAMES: usize = 64;
const SHIM_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const SHIM_INTERNAL_PREFIX: &str = "native-shim-reconnect";
const MAX_FRAME: usize = 8 * 1024 * 1024;

fn shim_error(id: &Value, outcome: &str, reason: &str, message: &str) -> String {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":message,
        "data":{"outcome":outcome,"reason":reason}}})
    .to_string()
}

/// Whether a framed reply is a definite account/credential refusal, from the
/// node's own framed data: an upstream 401/403, or the structured
/// `credential_refused` reason the node stamps on its own credential
/// failures. Generic errors and bare `not_sent` outcomes are not auth.
fn is_auth_refusal(reply: &Value) -> bool {
    let Some(data) = reply.pointer("/error/data") else {
        return false;
    };
    matches!(
        data.get("http_status").and_then(Value::as_u64),
        Some(401 | 403)
    ) || data.get("reason").and_then(Value::as_str) == Some("credential_refused")
}

fn without_tools(capabilities: &Value) -> Value {
    let mut value = capabilities.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("tools");
    }
    value
}

/// Whether two negotiated capability sets are contract-compatible for a
/// resumed session: everything except the `tools` capability itself must
/// match, including whether `tools` is offered at all. Inside `tools`, the
/// client-visible `listChanged` is the shim's own advertisement (see
/// [`inject_list_changed`]), so an upstream `listChanged` change does not
/// alter what the client was promised; the tool list itself is reconciled
/// separately by probing `tools/list`.
///
/// The shim itself implements `notifications/tools/list_changed` (it probes
/// `tools/list` after a reconnect), so on the session-establishment replies
/// it forwards to the agent — legacy `initialize` and modern
/// `server/discover` — it advertises that notification honestly as its own
/// capability. The upstream negotiated set is tracked separately, without
/// this injection, for reconnect compatibility checks. Ordinary business
/// replies are forwarded untouched.
fn inject_list_changed(result: &mut Value) {
    if let Some(tools) = result
        .get_mut("capabilities")
        .and_then(|caps| caps.get_mut("tools"))
        .and_then(Value::as_object_mut)
    {
        tools.insert("listChanged".into(), json!(true));
    }
}

fn capabilities_compatible(old: &Value, new: &Value) -> bool {
    without_tools(old) == without_tools(new)
        && old.get("tools").is_some() == new.get("tools").is_some()
}

fn backoff_delay(policy: &ShimPolicy, attempt: u32) -> Duration {
    let base = policy
        .initial_delay
        .saturating_mul(1u32 << attempt.min(10))
        .min(policy.max_delay);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0)
        ^ (std::process::id() as u64) << 16
        ^ attempt as u64;
    // Jitter in [0.8, 1.2) of the base delay.
    let scaled = base.as_nanos() as u64 * (800 + nanos % 400) / 1000;
    Duration::from_nanos(scaled)
}

#[derive(Default)]
struct ShimSession {
    /// Original legacy `initialize` request, replayed verbatim on reconnect.
    initialize_request: Option<Value>,
    initialize_established: bool,
    negotiated_version: Option<String>,
    negotiated_capabilities: Option<Value>,
    discover_result: Option<Value>,
    modern_seen: bool,
    last_modern_meta: Option<Value>,
    tools_cache: Option<Value>,
}

struct InFlight {
    id: Value,
    method: String,
}

enum ShimEvent {
    Input(Vec<u8>),
    InputEof,
    Socket(u64, Vec<u8>),
    SocketEof(u64),
}

#[derive(PartialEq, Clone, Copy)]
enum Phase {
    Connected,
    Handshaking,
    Reconnecting,
    Draining,
}

#[derive(PartialEq, Clone, Copy)]
enum Handshake {
    None,
    AwaitInitialize,
    AwaitDiscover,
    AwaitTools,
}

pub(crate) async fn connect<R, W>(socket: &Path, input: R, output: W) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    connect_with_policy(socket, input, output, ShimPolicy::default()).await
}

pub(super) async fn connect_bound<R, W>(
    socket: &Path,
    input: R,
    output: W,
    scope: super::connection_binding::Scope,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    connect_scoped_with_policy(socket, input, output, ShimPolicy::default(), Some(scope)).await
}

pub(crate) async fn connect_with_policy<R, W>(
    socket: &Path,
    input: R,
    output: W,
    policy: ShimPolicy,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    connect_scoped_with_policy(socket, input, output, policy, None).await
}

pub(super) async fn connect_scoped_with_policy<R, W>(
    socket: &Path,
    input: R,
    mut output: W,
    policy: ShimPolicy,
    scope: Option<super::connection_binding::Scope>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    use std::collections::{HashMap, VecDeque};
    use tokio::sync::mpsc;

    let stream = super::connection_binding::connect(socket, scope.as_ref()).await?;
    if stream.peer_cred()?.uid() != owner_uid() {
        return Err(Error::engine("node server UID rejected"));
    }
    let (events_tx, mut events) = mpsc::channel::<ShimEvent>(8);
    {
        let tx = events_tx.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(input);
            loop {
                let mut buf = Vec::new();
                match (&mut reader)
                    .take((MAX_FRAME + 1) as u64)
                    .read_until(b'\n', &mut buf)
                    .await
                {
                    Ok(0) | Err(_) => {
                        let _ = tx.send(ShimEvent::InputEof).await;
                        return;
                    }
                    Ok(n) if n > MAX_FRAME => {
                        let _ = tx.send(ShimEvent::InputEof).await;
                        return;
                    }
                    Ok(_) => {
                        if tx.send(ShimEvent::Input(buf)).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
    }
    let spawn_socket_reader = |read: tokio::net::unix::OwnedReadHalf, gen: u64| {
        let tx = events_tx.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(read);
            loop {
                let mut buf = Vec::new();
                match (&mut reader)
                    .take((MAX_FRAME + 1) as u64)
                    .read_until(b'\n', &mut buf)
                    .await
                {
                    Ok(0) | Err(_) => {
                        let _ = tx.send(ShimEvent::SocketEof(gen)).await;
                        return;
                    }
                    Ok(n) if n > MAX_FRAME => {
                        let _ = tx.send(ShimEvent::SocketEof(gen)).await;
                        return;
                    }
                    Ok(_) => {
                        if tx.send(ShimEvent::Socket(gen, buf)).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
    };

    let mut session = ShimSession::default();
    let mut in_flight: HashMap<String, InFlight> = HashMap::new();
    let mut tool_list_ids: std::collections::HashSet<String> = Default::default();
    let mut discover_ids: std::collections::HashSet<String> = Default::default();
    let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
    let mut queue_bytes = 0usize;
    let mut gen: u64 = 0;
    let (read, write) = stream.into_split();
    spawn_socket_reader(read, gen);
    let mut socket_write: Option<tokio::net::unix::OwnedWriteHalf> = Some(write);
    let mut phase = Phase::Connected;
    let mut handshake = Handshake::None;
    let mut internal_id: Option<String> = None;
    let mut internal_counter: u64 = 0;
    let mut held_initialize: Option<InFlight> = None;
    let mut deadline: Option<tokio::time::Instant> = None;
    let mut attempt: u32 = 0;
    let mut next_attempt = tokio::time::Instant::now();
    let mut emit_list_changed = false;

    macro_rules! out_line {
        ($line:expr) => {{
            let owned = $line;
            let line: &[u8] = owned.as_ref();
            output.write_all(line).await?;
            if !line.ends_with(b"\n") {
                output.write_all(b"\n").await?;
            }
            output.flush().await?;
        }};
    }

    macro_rules! expire_window {
        () => {{
            for frame in queue.drain(..) {
                if let Ok(value) = serde_json::from_slice::<Value>(&frame) {
                    for item in value.as_array().cloned().unwrap_or_else(|| vec![value]) {
                        if item.get("method").is_some() {
                            if let Some(id) = item.get("id") {
                                out_line!(shim_error(id, "not_sent", "reconnect_window_expired",
                                    "Node did not return within the reconnect window; request was not sent"));
                            }
                        }
                    }
                }
            }
            if let Some(held) = held_initialize.take() {
                out_line!(shim_error(&held.id, "unknown", "reconnect_window_expired",
                    "Node did not return within the reconnect window; initialize outcome unknown"));
            }
            eprintln!("mcp-stdio node connect: reconnect window expired; shim exiting");
            return Ok(());
        }};
    }

    // Settle everything waiting on a definite account/credential refusal:
    // queued requests were never sent, and a held initialize is refused
    // explicitly rather than left hanging.
    macro_rules! settle_refusal {
        ($reason:expr,$message:expr,$held_message:expr) => {{
            for frame in queue.drain(..) {
                if let Ok(value) = serde_json::from_slice::<Value>(&frame) {
                    for item in value.as_array().cloned().unwrap_or_else(|| vec![value]) {
                        if item.get("method").is_some() {
                            if let Some(id) = item.get("id") {
                                out_line!(shim_error(id, "not_sent", $reason, $message));
                            }
                        }
                    }
                }
            }
            if let Some(held) = held_initialize.take() {
                out_line!(shim_error(&held.id, "refused", $reason, $held_message));
            }
            eprintln!("mcp-stdio node connect: definite refusal on reconnect; shim exiting");
        }};
    }

    macro_rules! settle_auth {
        () => {
            settle_refusal!(
                "node_auth_refused",
                "Node refused the account or credential; request was not sent",
                "Node refused the account or credential; initialize was not established"
            );
        };
    }

    macro_rules! flush_queue {
        () => {{
            while let Some(frame) = queue.pop_front() {
                queue_bytes = queue_bytes.saturating_sub(frame.len());
                let text = String::from_utf8_lossy(&frame).into_owned();
                track_client_frame(
                    &text,
                    &mut session,
                    &mut in_flight,
                    &mut tool_list_ids,
                    &mut discover_ids,
                );
                let mut bytes = frame;
                if !bytes.ends_with(b"\n") {
                    bytes.push(b'\n');
                }
                let failed = match socket_write.as_mut() {
                    Some(w) => w.write_all(&bytes).await.is_err(),
                    None => true,
                };
                if failed {
                    socket_write = None;
                    begin_reconnect(
                        &mut in_flight,
                        &mut held_initialize,
                        &mut session,
                        &mut output,
                    )
                    .await?;
                    tool_list_ids.clear();
                    discover_ids.clear();
                    phase = Phase::Reconnecting;
                    if deadline.is_none() {
                        deadline = Some(tokio::time::Instant::now() + policy.window);
                        next_attempt = tokio::time::Instant::now();
                    } else {
                        next_attempt =
                            tokio::time::Instant::now() + backoff_delay(&policy, attempt);
                        attempt += 1;
                    }
                    break;
                }
            }
        }};
    }

    loop {
        // Reconnect attempts are driven from the event loop so stdin EOF and
        // queued input are still handled while waiting.
        let sleep_for = if phase == Phase::Reconnecting {
            next_attempt.saturating_duration_since(tokio::time::Instant::now())
        } else {
            Duration::from_secs(3600)
        };
        let expiry = deadline.filter(|_| matches!(phase, Phase::Handshaking | Phase::Reconnecting));
        let event = tokio::select! {
            _ = tokio::time::sleep_until(expiry.unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(3600))), if expiry.is_some() => {
                expire_window!();
            }
            _ = tokio::time::sleep(sleep_for), if phase == Phase::Reconnecting => {
                if deadline.is_some_and(|d| tokio::time::Instant::now() >= d) {
                    expire_window!();
                }
                match tokio::time::timeout_at(deadline.unwrap_or_else(|| tokio::time::Instant::now() + policy.window), super::connection_binding::connect(socket,scope.as_ref())).await.unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::TimedOut))) {
                    Ok(stream) => {
                        if stream.peer_cred().map(|c| c.uid() != owner_uid()).unwrap_or(true) {
                            settle_auth!();
                            return Err(Error::engine("node server UID rejected"));
                        }
                        gen += 1;
                        attempt = 0;
                        let (read, write) = stream.into_split();
                        spawn_socket_reader(read, gen);
                        socket_write = Some(write);
                        // Begin session re-establishment for this generation.
                        let mut step = Handshake::None;
                        if session.initialize_established {
                            let candidate = next_internal_id("init", gen, &mut internal_counter, &in_flight, &queue, &held_initialize);
                            internal_id = Some(candidate.clone());
                            let mut replay = session.initialize_request.clone().unwrap_or_default();
                            replay["id"] = json!(candidate);
                            let line = format!("{replay}\n");
                            match tokio::time::timeout_at(
                                deadline.unwrap_or_else(|| tokio::time::Instant::now() + policy.window),
                                socket_write.as_mut().unwrap().write_all(line.as_bytes()),
                            ).await.unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::TimedOut))) {
                                Ok(()) => step = Handshake::AwaitInitialize,
                                Err(_) => step = Handshake::None,
                            }
                            if step == Handshake::None {
                                socket_write = None;
                                phase = Phase::Reconnecting;
                                next_attempt = tokio::time::Instant::now() + backoff_delay(&policy, attempt);
                                attempt += 1;
                                continue;
                            }
                        } else if held_initialize.is_some() {
                            let candidate = next_internal_id("init", gen, &mut internal_counter, &in_flight, &queue, &held_initialize);
                            internal_id = Some(candidate.clone());
                            let mut replay = session.initialize_request.clone().unwrap_or_default();
                            replay["id"] = json!(candidate);
                            let line = format!("{replay}\n");
                            match tokio::time::timeout_at(
                                deadline.unwrap_or_else(|| tokio::time::Instant::now() + policy.window),
                                socket_write.as_mut().unwrap().write_all(line.as_bytes()),
                            ).await.unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::TimedOut))) {
                                Ok(()) => step = Handshake::AwaitInitialize,
                                Err(_) => {
                                    socket_write = None;
                                    phase = Phase::Reconnecting;
                                    next_attempt = tokio::time::Instant::now() + backoff_delay(&policy, attempt);
                                    attempt += 1;
                                    continue;
                                }
                            }
                        } else if session.modern_seen && session.discover_result.is_some() {
                            let candidate = next_internal_id("discover", gen, &mut internal_counter, &in_flight, &queue, &held_initialize);
                            internal_id = Some(candidate.clone());
                            let mut params = json!({});
                            if let Some(meta) = &session.last_modern_meta {
                                params["_meta"] = meta.clone();
                            }
                            let probe = json!({"jsonrpc":"2.0","id":candidate,"method":"server/discover","params":params});
                            let line = format!("{probe}\n");
                            match tokio::time::timeout_at(
                                deadline.unwrap_or_else(|| tokio::time::Instant::now() + policy.window),
                                socket_write.as_mut().unwrap().write_all(line.as_bytes()),
                            ).await.unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::TimedOut))) {
                                Ok(()) => step = Handshake::AwaitDiscover,
                                Err(_) => {
                                    socket_write = None;
                                    phase = Phase::Reconnecting;
                                    next_attempt = tokio::time::Instant::now() + backoff_delay(&policy, attempt);
                                    attempt += 1;
                                    continue;
                                }
                            }
                        } else if session.modern_seen && session.tools_cache.is_some() {
                            let candidate = next_internal_id("tools", gen, &mut internal_counter, &in_flight, &queue, &held_initialize);
                            internal_id = Some(candidate.clone());
                            let mut params = json!({});
                            if let Some(meta) = &session.last_modern_meta {
                                params["_meta"] = meta.clone();
                            }
                            let probe = json!({"jsonrpc":"2.0","id":candidate,"method":"tools/list","params":params});
                            let line = format!("{probe}\n");
                            match tokio::time::timeout_at(
                                deadline.unwrap_or_else(|| tokio::time::Instant::now() + policy.window),
                                socket_write.as_mut().unwrap().write_all(line.as_bytes()),
                            ).await.unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::TimedOut))) {
                                Ok(()) => step = Handshake::AwaitTools,
                                Err(_) => {
                                    socket_write = None;
                                    phase = Phase::Reconnecting;
                                    next_attempt = tokio::time::Instant::now() + backoff_delay(&policy, attempt);
                                    attempt += 1;
                                    continue;
                                }
                            }
                        }
                        if step == Handshake::None {
                            phase = Phase::Connected;
                            deadline = None;
                            flush_queue!();
                        } else {
                            handshake = step;
                            phase = Phase::Handshaking;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                        settle_refusal!("connection_binding_refused", "Node account/workspace binding could not be verified; reconnect Native explicitly", "Node account/workspace binding could not be verified; reconnect Native explicitly");
                        return Err(error.into());
                    }
                    _ => {
                        attempt += 1;
                        next_attempt = tokio::time::Instant::now() + backoff_delay(&policy, attempt);
                        eprintln!("mcp-stdio node connect: node unavailable, reconnect attempt {attempt} pending");
                    }
                }
                continue;
            }
            event = events.recv() => match event {
                Some(event) => event,
                None => return Ok(()),
            },
        };
        match event {
            ShimEvent::InputEof => match phase {
                Phase::Connected => {
                    if let Some(mut w) = socket_write.take() {
                        let _ = w.shutdown().await;
                        socket_write = Some(w);
                    }
                    phase = Phase::Draining;
                }
                _ => return Ok(()),
            },
            ShimEvent::Input(frame) => {
                if phase == Phase::Draining {
                    continue;
                }
                if phase == Phase::Reconnecting || phase == Phase::Handshaking {
                    let parsed = serde_json::from_slice::<Value>(&frame).ok();
                    let is_response = parsed.as_ref().is_some_and(|v| {
                        v.get("method").is_none()
                            && (v.get("result").is_some() || v.get("error").is_some())
                    });
                    if is_response {
                        continue;
                    }
                    if queue.len() >= SHIM_QUEUE_FRAMES
                        || queue_bytes + frame.len() > SHIM_QUEUE_BYTES
                    {
                        if let Some(value) = parsed {
                            for item in value.as_array().cloned().unwrap_or_else(|| vec![value]) {
                                if item.get("method").is_some() {
                                    if let Some(id) = item.get("id") {
                                        out_line!(shim_error(
                                            id,
                                            "not_sent",
                                            "reconnect_queue_full",
                                            "Reconnect queue is full; request was not sent"
                                        ));
                                    }
                                }
                            }
                        }
                        continue;
                    }
                    queue_bytes += frame.len();
                    queue.push_back(frame);
                    continue;
                }
                let text = String::from_utf8_lossy(&frame).into_owned();
                track_client_frame(
                    &text,
                    &mut session,
                    &mut in_flight,
                    &mut tool_list_ids,
                    &mut discover_ids,
                );
                let mut bytes = frame.clone();
                if !bytes.ends_with(b"\n") {
                    bytes.push(b'\n');
                }
                let write_failed = match socket_write.as_mut() {
                    Some(w) => w.write_all(&bytes).await.is_err(),
                    None => true,
                };
                if write_failed && phase != Phase::Draining {
                    socket_write = None;
                    begin_reconnect(
                        &mut in_flight,
                        &mut held_initialize,
                        &mut session,
                        &mut output,
                    )
                    .await?;
                    tool_list_ids.clear();
                    discover_ids.clear();
                    phase = Phase::Reconnecting;
                    deadline = Some(tokio::time::Instant::now() + policy.window);
                    attempt = 0;
                    next_attempt = tokio::time::Instant::now();
                }
            }
            ShimEvent::Socket(socket_gen, frame) => {
                if socket_gen != gen {
                    continue;
                }
                if phase == Phase::Handshaking {
                    let Ok(value) = serde_json::from_slice::<Value>(&frame) else {
                        continue;
                    };
                    let id_matches = internal_id.as_ref().is_some_and(|expected| {
                        value.get("id").and_then(Value::as_str) == Some(expected.as_str())
                    });
                    if !id_matches {
                        out_line!(&frame);
                        continue;
                    }
                    match handshake {
                        Handshake::AwaitInitialize => {
                            if value.get("error").is_some() {
                                if is_auth_refusal(&value) {
                                    settle_auth!();
                                    return Ok(());
                                }
                                socket_write = None;
                                handshake = Handshake::None;
                                internal_id = None;
                                phase = Phase::Reconnecting;
                                next_attempt =
                                    tokio::time::Instant::now() + backoff_delay(&policy, attempt);
                                attempt += 1;
                                continue;
                            }
                            let new_version = value
                                .pointer("/result/protocolVersion")
                                .and_then(Value::as_str)
                                .map(str::to_owned);
                            let new_caps = value
                                .pointer("/result/capabilities")
                                .cloned()
                                .unwrap_or(Value::Null);
                            let version_bad = session.initialize_established
                                && session.negotiated_version.is_some()
                                && new_version != session.negotiated_version;
                            let caps_bad = session.initialize_established
                                && session
                                    .negotiated_capabilities
                                    .as_ref()
                                    .is_some_and(|old| !capabilities_compatible(old, &new_caps));
                            if version_bad || caps_bad {
                                for queued in queue.drain(..) {
                                    if let Ok(qv) = serde_json::from_slice::<Value>(&queued) {
                                        for item in
                                            qv.as_array().cloned().unwrap_or_else(|| vec![qv])
                                        {
                                            if item.get("method").is_some() {
                                                if let Some(id) = item.get("id") {
                                                    out_line!(shim_error(id, "not_sent", "protocol_changed_on_reconnect",
                                                        "Node protocol or capabilities changed on reconnect; request was not sent"));
                                                }
                                            }
                                        }
                                    }
                                }
                                eprintln!("mcp-stdio node connect: incompatible protocol or capabilities on reconnect; shim exiting");
                                return Ok(());
                            }
                            if !session.initialize_established {
                                session.negotiated_version = new_version.clone();
                                session.negotiated_capabilities = Some(new_caps.clone());
                                session.initialize_established = true;
                            }
                            if let Some(w) = socket_write.as_mut() {
                                let _ = w.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await;
                            }
                            if let Some(held) = held_initialize.take() {
                                let mut forwarded = value.clone();
                                forwarded["id"] = held.id.clone();
                                if let Some(result) = forwarded.get_mut("result") {
                                    inject_list_changed(result);
                                }
                                out_line!(serde_json::to_string(&forwarded).unwrap_or_default());
                            }
                            if session.tools_cache.is_some() {
                                let candidate = next_internal_id(
                                    "tools",
                                    gen,
                                    &mut internal_counter,
                                    &in_flight,
                                    &queue,
                                    &held_initialize,
                                );
                                internal_id = Some(candidate.clone());
                                let probe = json!({"jsonrpc":"2.0","id":candidate,"method":"tools/list","params":{}});
                                let line = format!("{probe}\n");
                                match socket_write.as_mut().map(|w| w.write_all(line.as_bytes())) {
                                    Some(fut) => {
                                        if !matches!(
                                            tokio::time::timeout_at(
                                                deadline
                                                    .unwrap_or_else(|| tokio::time::Instant::now()
                                                        + policy.window),
                                                fut
                                            )
                                            .await,
                                            Ok(Ok(()))
                                        ) {
                                            socket_write = None;
                                            handshake = Handshake::None;
                                            phase = Phase::Reconnecting;
                                            next_attempt = tokio::time::Instant::now();
                                            continue;
                                        }
                                        handshake = Handshake::AwaitTools;
                                    }
                                    None => {
                                        handshake = Handshake::None;
                                        phase = Phase::Connected;
                                        deadline = None;
                                        flush_queue!();
                                    }
                                }
                            } else {
                                handshake = Handshake::None;
                                internal_id = None;
                                phase = Phase::Connected;
                                deadline = None;
                                flush_queue!();
                            }
                        }
                        Handshake::AwaitDiscover => {
                            if value.get("error").is_some() {
                                if is_auth_refusal(&value) {
                                    settle_auth!();
                                    return Ok(());
                                }
                                socket_write = None;
                                handshake = Handshake::None;
                                internal_id = None;
                                phase = Phase::Reconnecting;
                                next_attempt =
                                    tokio::time::Instant::now() + backoff_delay(&policy, attempt);
                                attempt += 1;
                                continue;
                            }
                            let old = session.discover_result.clone().unwrap_or_default();
                            let changed = old.get("supportedVersions")
                                != value.pointer("/result/supportedVersions")
                                || !capabilities_compatible(
                                    &old.get("capabilities").cloned().unwrap_or(Value::Null),
                                    &value
                                        .pointer("/result/capabilities")
                                        .cloned()
                                        .unwrap_or(Value::Null),
                                );
                            // Store the fresh result body for comparison basis.
                            if let Some(result) = value.get("result") {
                                session.discover_result = Some(result.clone());
                            }
                            if changed {
                                for queued in queue.drain(..) {
                                    if let Ok(qv) = serde_json::from_slice::<Value>(&queued) {
                                        for item in
                                            qv.as_array().cloned().unwrap_or_else(|| vec![qv])
                                        {
                                            if item.get("method").is_some() {
                                                if let Some(id) = item.get("id") {
                                                    out_line!(shim_error(id, "not_sent", "protocol_changed_on_reconnect",
                                                        "Node protocol or capabilities changed on reconnect; request was not sent"));
                                                }
                                            }
                                        }
                                    }
                                }
                                eprintln!("mcp-stdio node connect: incompatible protocol or capabilities on reconnect; shim exiting");
                                return Ok(());
                            }
                            if session.tools_cache.is_some() {
                                let candidate = next_internal_id(
                                    "tools",
                                    gen,
                                    &mut internal_counter,
                                    &in_flight,
                                    &queue,
                                    &held_initialize,
                                );
                                internal_id = Some(candidate.clone());
                                let mut params = json!({});
                                if let Some(meta) = &session.last_modern_meta {
                                    params["_meta"] = meta.clone();
                                }
                                let probe = json!({"jsonrpc":"2.0","id":candidate,"method":"tools/list","params":params});
                                let line = format!("{probe}\n");
                                match socket_write.as_mut().map(|w| w.write_all(line.as_bytes())) {
                                    Some(fut) => {
                                        if !matches!(
                                            tokio::time::timeout_at(
                                                deadline
                                                    .unwrap_or_else(|| tokio::time::Instant::now()
                                                        + policy.window),
                                                fut
                                            )
                                            .await,
                                            Ok(Ok(()))
                                        ) {
                                            socket_write = None;
                                            handshake = Handshake::None;
                                            phase = Phase::Reconnecting;
                                            next_attempt = tokio::time::Instant::now();
                                            continue;
                                        }
                                        handshake = Handshake::AwaitTools;
                                    }
                                    None => {
                                        handshake = Handshake::None;
                                        phase = Phase::Connected;
                                    }
                                }
                            } else {
                                handshake = Handshake::None;
                                internal_id = None;
                                phase = Phase::Connected;
                                deadline = None;
                                flush_queue!();
                            }
                        }
                        Handshake::AwaitTools => {
                            if value.get("error").is_some() && is_auth_refusal(&value) {
                                settle_auth!();
                                return Ok(());
                            }
                            if value.get("result").is_some() {
                                let cached = session.tools_cache.clone().unwrap_or_default();
                                let paginated =
                                    cached.get("nextCursor").is_some_and(|c| !c.is_null())
                                        || value["result"]
                                            .get("nextCursor")
                                            .is_some_and(|c| !c.is_null());
                                if paginated || cached.get("tools") != value["result"].get("tools")
                                {
                                    emit_list_changed = true;
                                }
                                session.tools_cache = value.get("result").cloned();
                            } else {
                                // No usable probe answer: do not claim the
                                // tool list is unchanged.
                                emit_list_changed = session.tools_cache.is_some();
                            }
                            handshake = Handshake::None;
                            internal_id = None;
                            phase = Phase::Connected;
                            deadline = None;
                            if emit_list_changed {
                                emit_list_changed = false;
                                out_line!(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}".as_slice());
                            }
                            eprintln!("mcp-stdio node connect: reconnected to node");
                            flush_queue!();
                        }
                        Handshake::None => {
                            out_line!(&frame);
                        }
                    }
                    continue;
                }
                // Connected or Draining: inspect for session bookkeeping, then
                // forward the frame. Only session-establishment replies
                // (initialize / server/discover) are amended, with the shim's
                // own listChanged advertisement; all other frames keep their
                // exact bytes.
                let mut rewritten: Option<String> = None;
                if let Ok(value) = serde_json::from_slice::<Value>(&frame) {
                    let is_batch = value.is_array();
                    let mut items = value
                        .as_array()
                        .cloned()
                        .unwrap_or_else(|| vec![value.clone()]);
                    let mut amend = false;
                    for item in items.iter_mut() {
                        let Some(id) = item.get("id").cloned() else {
                            continue;
                        };
                        let key = id.to_string();
                        if item.get("method").is_none() {
                            if tool_list_ids.remove(&key) {
                                if let Some(result) = item.get("result") {
                                    session.tools_cache = Some(result.clone());
                                }
                            }
                            if discover_ids.remove(&key) {
                                if let Some(result) = item.get("result") {
                                    // Track the upstream answer before the
                                    // shim's own advertisement is added.
                                    session.discover_result = Some(result.clone());
                                }
                                if let Some(result) = item.get_mut("result") {
                                    inject_list_changed(result);
                                    amend = true;
                                }
                            }
                            if let Some(sent) = in_flight.remove(&key) {
                                if sent.method == "initialize" {
                                    if let Some(result) = item.get("result") {
                                        session.negotiated_version = result
                                            .get("protocolVersion")
                                            .and_then(Value::as_str)
                                            .map(str::to_owned);
                                        session.negotiated_capabilities =
                                            result.get("capabilities").cloned();
                                        session.initialize_established = true;
                                    }
                                    if let Some(result) = item.get_mut("result") {
                                        inject_list_changed(result);
                                        amend = true;
                                    }
                                }
                            }
                        }
                    }
                    if amend {
                        rewritten = Some(if is_batch {
                            Value::Array(items).to_string()
                        } else {
                            items.into_iter().next().unwrap_or(value).to_string()
                        });
                    }
                }
                match rewritten {
                    Some(line) => out_line!(line),
                    None => out_line!(&frame),
                }
            }
            ShimEvent::SocketEof(socket_gen) => {
                if socket_gen != gen {
                    continue;
                }
                if phase == Phase::Draining {
                    return Ok(());
                }
                if phase == Phase::Reconnecting {
                    continue;
                }
                // Node EOF (idle, mid-request, or mid-handshake): never replay
                // in-flight business calls.
                socket_write = None;
                handshake = Handshake::None;
                internal_id = None;
                begin_reconnect(
                    &mut in_flight,
                    &mut held_initialize,
                    &mut session,
                    &mut output,
                )
                .await?;
                // tool/discover bookkeeping for dead generation is moot.
                tool_list_ids.clear();
                discover_ids.clear();
                phase = Phase::Reconnecting;
                if deadline.is_none() {
                    deadline = Some(tokio::time::Instant::now() + policy.window);
                    next_attempt = tokio::time::Instant::now();
                } else {
                    // A generation that died mid-handshake must not extend
                    // the window; retry with backoff inside it.
                    next_attempt = tokio::time::Instant::now() + backoff_delay(&policy, attempt);
                    attempt += 1;
                }
                eprintln!("mcp-stdio node connect: node connection lost; reconnecting");
            }
        }
    }
}

/// Mint a shim-internal id that cannot collide with any caller id that is
/// in flight, held, or queued. Completed caller ids need no reservation:
/// internal ids are only matched during Handshaking, when no caller frame
/// is forwarded, so a later caller reuse of the same string is unambiguous.
fn next_internal_id(
    kind: &str,
    gen: u64,
    counter: &mut u64,
    in_flight: &std::collections::HashMap<String, InFlight>,
    queue: &std::collections::VecDeque<Vec<u8>>,
    held: &Option<InFlight>,
) -> String {
    loop {
        *counter += 1;
        let candidate = format!("{SHIM_INTERNAL_PREFIX}:{kind}:{gen}:{counter}");
        let collides = in_flight.contains_key(&candidate)
            || held
                .as_ref()
                .is_some_and(|h| h.id.as_str() == Some(candidate.as_str()))
            || queue.iter().any(|frame| {
                serde_json::from_slice::<Value>(frame).is_ok_and(|v| {
                    v.as_array()
                        .cloned()
                        .unwrap_or_else(|| vec![v])
                        .iter()
                        .any(|item| {
                            item.get("id").and_then(Value::as_str) == Some(candidate.as_str())
                        })
                })
            });
        if !collides {
            return candidate;
        }
    }
}

/// Track a client frame before it is written to the node. Returns nothing;
/// bookkeeping lives in `session`, `in_flight`, and the discovery id sets.
fn track_client_frame(
    text: &str,
    session: &mut ShimSession,
    in_flight: &mut std::collections::HashMap<String, InFlight>,
    tool_list_ids: &mut std::collections::HashSet<String>,
    discover_ids: &mut std::collections::HashSet<String>,
) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text.trim()) else {
        return false;
    };
    let mut is_initialize = false;
    for item in value.as_array().cloned().unwrap_or_else(|| vec![value]) {
        let Some(method) = item.get("method").and_then(Value::as_str) else {
            continue;
        };
        if crate::mcp::is_modern_request(&item) {
            session.modern_seen = true;
            if let Some(meta) = item.pointer("/params/_meta") {
                session.last_modern_meta = Some(meta.clone());
            }
        }
        if method == "initialize" {
            is_initialize = true;
            if session.initialize_request.is_none() || !session.initialize_established {
                session.initialize_request = Some(item.clone());
            }
        }
        if let Some(id) = item.get("id") {
            in_flight.insert(
                id.to_string(),
                InFlight {
                    id: id.clone(),
                    method: method.to_owned(),
                },
            );
            if method == "tools/list" {
                tool_list_ids.insert(id.to_string());
            }
            if method == "server/discover" {
                discover_ids.insert(id.to_string());
            }
        }
    }
    is_initialize
}

/// On node EOF, settle every in-flight request honestly: an unreplied
/// `initialize` that never established a session is held for replay, every
/// other sent request gets `unknown`, and nothing is replayed.
async fn begin_reconnect<W: AsyncWrite + Unpin>(
    in_flight: &mut std::collections::HashMap<String, InFlight>,
    held_initialize: &mut Option<InFlight>,
    session: &mut ShimSession,
    output: &mut W,
) -> Result<()> {
    let mut sent: Vec<InFlight> = in_flight.drain().map(|(_, v)| v).collect();
    sent.sort_by_key(|entry| entry.id.to_string());
    for entry in sent {
        if entry.method == "initialize" && !session.initialize_established {
            *held_initialize = Some(entry);
            continue;
        }
        let line = shim_error(
            &entry.id,
            "unknown",
            "node_disconnected",
            "Node connection lost before a reply; outcome unknown, check before retrying",
        );
        output.write_all(line.as_bytes()).await?;
        output.write_all(b"\n").await?;
    }
    output.flush().await?;
    Ok(())
}
