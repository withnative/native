//! The broker's own daemon transport: a read-only WebSocket client with its
//! own hello identity (`native-session-broker`) and its own outbound
//! allowlist ([`super::protocol::check_broker_outbound_allowed`]).
//!
//! Shares only the session-envelope helpers with `daemon_client.rs` (reused
//! `unwrap_session`/`inbound_kind`); the saver keeps its own connection,
//! allowlist, and `native-session-saver` identity untouched.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

use super::protocol::{
    check_broker_outbound_allowed, fetch_agents_message, fetch_timeline_message,
};
use crate::node::daemon_client::{inbound_kind, unwrap_session};

use crate::error::{Error, Result};

/// Client identity presented in the broker's `hello`.
pub const BROKER_CLIENT_ID: &str = "native-session-broker";
/// Daemon hello protocol version (mirrors the saver).
pub const DAEMON_PROTOCOL_VERSION: u32 = 1;

/// Bound on the TCP+WS connect.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on waiting for the post-hello `server_info` acceptance.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on any single frame send.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on the closing handshake.
///
/// S2 seam: graceful shutdown closes the broker connection through this.
#[allow(dead_code)]
pub const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolved per-connect secret. Held only for one handshake; never logged.
pub enum BrokerAuthSecret {
    Password(zeroize::Zeroizing<Vec<u8>>),
    LocalToken(zeroize::Zeroizing<String>),
}

impl std::fmt::Debug for BrokerAuthSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => write!(f, "Password(<redacted>)"),
            Self::LocalToken(_) => write!(f, "LocalToken(<redacted>)"),
        }
    }
}

fn hello_message(client_id: &str, secret: &BrokerAuthSecret) -> Value {
    let auth = match secret {
        BrokerAuthSecret::Password(password) => {
            let text = String::from_utf8_lossy(password.as_slice()).into_owned();
            json!({"kind": "password", "password": text})
        }
        BrokerAuthSecret::LocalToken(token) => {
            json!({"kind": "localCredential", "token": token.as_str()})
        }
    };
    json!({
        "type": "hello",
        "clientId": client_id,
        "clientType": "mcp",
        "protocolVersion": DAEMON_PROTOCOL_VERSION,
        "auth": auth,
    })
}

fn wrap_session(inner: &Value) -> Value {
    json!({"type": "session", "message": inner})
}

/// Connected, hello-authenticated broker transport.
///
/// All sends go through the broker allowlist and are time-bounded; frame
/// reads (`next_message`) are unbounded by design so the broker loop always
/// awaits them under a shutdown `select`.
pub struct BrokerConnection {
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    server_id: String,
}

impl BrokerConnection {
    /// Connect to `url`, run the `hello` handshake, and validate the daemon's
    /// `server_info` acceptance — all time-bounded. A `hello.rejected` answer
    /// or any other first frame fails the connect. The secret is embedded in
    /// the returned hello frame only; callers must not log it.
    pub async fn connect(url: &str, secret: &BrokerAuthSecret) -> Result<Self> {
        Self::connect_with(url, secret, CONNECT_TIMEOUT, HANDSHAKE_TIMEOUT).await
    }

    async fn connect_with(
        url: &str,
        secret: &BrokerAuthSecret,
        connect_timeout: Duration,
        handshake_timeout: Duration,
    ) -> Result<Self> {
        let (mut stream, _) = tokio::time::timeout(connect_timeout, connect_async(url))
            .await
            .map_err(|_| Error::engine("agent-sessions daemon connect timed out"))?
            .map_err(|e| Error::engine(format!("agent-sessions daemon connect failed: {e}")))?;
        // The secret is formatted into exactly one hello frame.
        let hello = hello_message(BROKER_CLIENT_ID, secret);
        let hello_text = serde_json::to_string(&hello)
            .map_err(|_| Error::engine("agent-sessions hello did not serialize"))?;
        // Best-effort: the hello carries the only copy of the secret on the
        // stack; the `BrokerAuthSecret` owner wipes/owns its own bytes.
        tokio::time::timeout(SEND_TIMEOUT, stream.send(Message::Text(hello_text.into())))
            .await
            .map_err(|_| Error::engine("agent-sessions daemon hello send timed out"))?
            .map_err(|e| Error::engine(format!("agent-sessions daemon hello failed: {e}")))?;
        let first = tokio::time::timeout(handshake_timeout, stream.next())
            .await
            .map_err(|_| Error::engine("agent-sessions daemon handshake timed out"))?
            .ok_or_else(|| Error::engine("agent-sessions daemon closed during handshake"))?
            .map_err(|e| Error::engine(format!("agent-sessions daemon handshake failed: {e}")))?;
        let frame: Value = match first {
            Message::Text(text) => serde_json::from_str(&text).map_err(|_| {
                Error::engine("agent-sessions daemon sent a non-JSON frame during handshake")
            }),
            Message::Close(_) => Err(Error::engine(
                "agent-sessions daemon closed during handshake",
            )),
            _ => Err(Error::engine(
                "unexpected agent-sessions daemon frame during handshake",
            )),
        }?;
        if frame.get("type").and_then(Value::as_str) == Some("hello.rejected") {
            return Err(Error::engine("agent-sessions daemon rejected hello (auth)"));
        }
        if frame.get("type").and_then(Value::as_str) != Some("session") {
            return Err(Error::engine(
                "agent-sessions daemon handshake did not return server_info",
            ));
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
            .ok_or_else(|| {
                Error::engine("agent-sessions daemon handshake did not return server_info")
            })?
            .to_owned();
        // Classify the acceptance for diagnostics without surfacing it.
        let _ = inbound_kind(inner);
        Ok(Self { stream, server_id })
    }

    /// Daemon `serverId` accepted during the handshake (host binding).
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

    /// Typed read: projected timeline page. `direction` is `tail` (snapshot)
    /// or `after` (history paging with `cursor`).
    pub async fn send_timeline_fetch(
        &mut self,
        agent_id: &str,
        request_id: &str,
        direction: &str,
        cursor: Option<&Value>,
        limit: u64,
    ) -> Result<()> {
        self.send_inner(&fetch_timeline_message(
            agent_id, request_id, direction, cursor, limit,
        ))
        .await
    }

    /// Liveness probe; the only other permitted outbound frame.
    pub async fn send_ping(&mut self) -> Result<()> {
        self.send_inner(&json!({"type": "ping"})).await
    }

    async fn send_inner(&mut self, message: &Value) -> Result<()> {
        check_broker_outbound_allowed(message)
            .map_err(|detail| Error::engine(format!("blocked broker daemon write: {detail}")))?;
        let frame = wrap_session(message).to_string();
        tokio::time::timeout(SEND_TIMEOUT, self.stream.send(Message::Text(frame.into())))
            .await
            .map_err(|_| Error::engine("agent-sessions daemon send timed out"))?
            .map_err(|e| Error::engine(format!("agent-sessions daemon send failed: {e}")))
    }

    /// Receive the next daemon message, unwrapped from its session envelope.
    /// `None` on clean close.
    pub async fn next_message(&mut self) -> Result<Option<Value>> {
        loop {
            match self.stream.next().await {
                None => return Ok(None),
                Some(Err(e)) => {
                    return Err(Error::engine(format!(
                        "agent-sessions daemon read failed: {e}"
                    )))
                }
                Some(Ok(Message::Close(_))) => return Ok(None),
                Some(Ok(Message::Text(text))) => {
                    let frame: Value = serde_json::from_str(&text).map_err(|_| {
                        Error::engine("agent-sessions daemon sent a non-JSON text frame")
                    })?;
                    if frame.get("type").and_then(Value::as_str) == Some("hello.rejected") {
                        return Err(Error::engine("agent-sessions daemon rejected hello (auth)"));
                    }
                    return Ok(Some(unwrap_session(&frame).clone()));
                }
                Some(Ok(Message::Binary(_))) => {
                    return Err(Error::engine("agent-sessions daemon sent binary frame"));
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
            }
        }
    }

    /// Best-effort bounded close.
    ///
    /// S2 seam: graceful shutdown closes the broker connection through this.
    #[allow(dead_code)]
    pub async fn close(&mut self) -> Result<()> {
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, self.stream.close(None)).await;
        Ok(())
    }
}
