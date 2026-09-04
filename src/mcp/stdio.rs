//! The stdio MCP transport — JSON-RPC 2.0, one message per line, over any
//! `AsyncBufRead`/`AsyncWrite` pair (stdin/stdout in production; in-memory
//! duplex pipes in tests). Hand-rolled rather than `rmcp` — the reasoning
//! lives in `docs/mcp-crate-choice.md`.
//!
//! It is dual-era: stateless 2026-07-28 requests (selected by their per-request
//! protocol metadata) dispatch through `mcp::protocol`, the same core as hosted
//! Streamable HTTP. Legacy clients can still open with `initialize` and use the
//! previously supported 2025/2024 revisions through the same dispatcher as
//! hosted HTTP.
//!
//! The server fronts one selected local database. Auth is
//! the file system (whoever can point the server at a `.db` owns it) — OTP /
//! bearer auth is the hosted HTTP transport's concern. Before this transport
//! starts, the binary resolves one portable account token from the file and
//! supplies it as the caller retained for the server lifetime.
//!
//! Rendering happens HERE, not in handlers, in whichever shape the call's
//! `format` argument selects (`super::render`): audited standalone default-text
//! renderings carry one prose `content` block without duplicate
//! `structuredContent`; explicit `"json"`, Apps, unrendered tools,
//! conservative mutation/mixed families, and defensive recovery paths preserve
//! the structured object plus its serialized or rendered text. Failure mapping
//! (messages are the contract surface):
//!   - `Error::Engine` / `Error::Auth` → tool result with `isError: true`,
//!     message verbatim (MCP-proper: the model may see tool failures);
//!   - infrastructure errors (sqlx/io/json) → JSON-RPC `-32603`;
//!   - malformed JSON → `-32700`; unknown method → `-32601`; bad params
//!     (missing/unknown tool name) → `-32602`.

use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::error::Result;

use super::protocol::{self, RpcOutcome};
use super::registry::{Caller, EngineHandle, ToolRegistry};

/// Legacy MCP protocol revision this server prefers when a client opens with
/// the pre-2026 `initialize` handshake.
pub const LEGACY_PROTOCOL_VERSION: &str = protocol::LEGACY_PROTOCOL_VERSION;

/// Every revision this server implements. Modern clients discover
/// `2026-07-28`; legacy initialize negotiates within the remaining entries.
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 4] = [
    protocol::PROTOCOL_VERSION,
    protocol::LEGACY_SUPPORTED_PROTOCOL_VERSIONS[0],
    protocol::LEGACY_SUPPORTED_PROTOCOL_VERSIONS[1],
    protocol::LEGACY_SUPPORTED_PROTOCOL_VERSIONS[2],
];

/// An MCP server over one registry and one selected engine handle.
pub struct StdioServer {
    registry: Arc<ToolRegistry>,
    engine: EngineHandle,
    caller: Caller,
}

impl StdioServer {
    /// Construct a server with the account identity resolved by its startup
    /// boundary. The caller is retained for the process lifetime; run context
    /// remains request-scoped and is attached by the shared dispatcher.
    pub fn new(
        registry: Arc<ToolRegistry>,
        engine: impl Into<EngineHandle>,
        caller: Caller,
    ) -> Self {
        StdioServer {
            registry,
            engine: engine.into(),
            caller,
        }
    }

    /// Serve process stdin/stdout until EOF.
    pub async fn serve_stdio(&self) -> Result<()> {
        self.serve(BufReader::new(tokio::io::stdin()), tokio::io::stdout())
            .await
    }

    /// The transport loop: read one JSON-RPC message per line, write one
    /// response per request (notifications get none), until EOF. Tests drive
    /// this directly over in-memory pipes.
    pub async fn serve<R, W>(&self, mut reader: R, mut writer: W) -> Result<()>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                return Ok(()); // EOF — client hung up.
            }
            if line.trim().is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<Value>(&line) {
                Ok(message) => self.handle_message(message).await,
                Err(e) => Some(protocol::error_response(
                    Value::Null,
                    protocol::PARSE_ERROR,
                    &format!("parse error: {e}"),
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

    /// Dispatch one message. `None` means no response goes out (notification,
    /// or a stray response message we ignore per JSON-RPC).
    async fn handle_message(&self, message: Value) -> Option<Value> {
        // Presence of per-request protocol metadata selects the modern,
        // stateless era. Both dispatchers are shared with hosted HTTP; this
        // wrapper contributes only stdio framing.
        let outcome = if protocol::is_modern_request(&message) {
            protocol::handle_modern_engine_message(
                self.registry.clone(),
                self.engine.clone(),
                self.caller.clone(),
                message,
            )
            .await
        } else {
            protocol::handle_legacy_engine_message(
                self.registry.clone(),
                self.engine.clone(),
                self.caller.clone(),
                message,
            )
            .await
        };
        match outcome {
            RpcOutcome::Notification => None,
            RpcOutcome::Response { body, .. } => Some(body),
        }
    }
}
