//! The client side of the node's Unix socket, shared by `native status` and
//! `native call`/`search`/`get`/`sql`.
//!
//! It does what `native node connect` does and nothing more: read `node.json`,
//! check the socket is a socket and ours, connect, check the process on the
//! other end runs as this user (peer credentials), then speak line-delimited
//! MCP JSON-RPC with every reply read through a bounded reader. A failure is
//! a [`NodeState`] with a short sentence, never a panic and never an echo of
//! file or peer content.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};

use crate::node::NodeConfig;

/// The most one reply may carry before the connection is dropped.
pub const MAX_REPLY_BYTES: usize = 4 * 1024 * 1024;

/// What a connection insists on; tests lower the reply bound or name another user.
pub struct Limits {
    pub max_reply: usize,
    /// The user id the socket's other end must have.
    pub peer_uid: u32,
}

impl Limits {
    pub fn standard() -> Self {
        Self {
            max_reply: MAX_REPLY_BYTES,
            peer_uid: crate::node::current_uid(),
        }
    }
}

/// Whether the node could be read, and if not, why.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    Running,
    /// No `node.json`: `native setup` has not been run.
    NoConfig,
    /// `node.json` fails the node's loader.
    InvalidConfig,
    /// No socket: the node is not running.
    NoSocket,
    /// A socket file exists but nothing listens on it.
    StaleSocket,
    /// The socket is not ours, or access to it was refused.
    PermissionDenied,
    /// The node closed the connection at once (it may have rejected our UID).
    PeerRejected,
    /// Connected, but no usable reply in time.
    NotAnswering,
    /// The node answered but could not give its status.
    StatusUnavailable,
}

#[derive(Debug, Serialize)]
pub struct NodeInfo {
    pub state: NodeState,
    pub detail: Option<String>,
    pub config: Option<String>,
    pub socket: Option<String>,
}

pub fn down(
    state: NodeState,
    detail: impl Into<String>,
    config: Option<&Path>,
    socket: Option<&Path>,
) -> NodeInfo {
    NodeInfo {
        state,
        detail: Some(detail.into()),
        config: config.map(|p| p.display().to_string()),
        socket: socket.map(|p| p.display().to_string()),
    }
}

pub fn read_config(path: &Path) -> Result<NodeConfig, NodeInfo> {
    use std::io::Read as _;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(down(
                NodeState::NoConfig,
                "no node.json found; run `native setup` first",
                Some(path),
                None,
            ))
        }
        Err(error) => {
            return Err(down(
                NodeState::InvalidConfig,
                format!("cannot read node.json ({})", io_kind(&error)),
                Some(path),
                None,
            ))
        }
    };
    let mut bytes = Vec::new();
    let _ = file.take(65_537).read_to_end(&mut bytes);
    if bytes.len() > 65_536 {
        return Err(down(
            NodeState::InvalidConfig,
            "node.json is too large",
            Some(path),
            None,
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        down(
            NodeState::InvalidConfig,
            // serde's message can quote file content (an unknown field's name,
            // a value): say only where the problem is.
            format!(
                "node.json is not a valid node config (line {}, column {}); run `native setup` again",
                error.line(),
                error.column()
            ),
            Some(path),
            None,
        )
    })
}

pub fn io_kind(error: &std::io::Error) -> String {
    use std::io::ErrorKind::*;
    match error.kind() {
        PermissionDenied => "permission denied".into(),
        NotFound => "not found".into(),
        other => format!("{other}"),
    }
}

/// An open, vetted connection to the node's socket.
///
/// Requests are numbered by the connection itself, and a reply is accepted only
/// if it carries the number of the request being waited for: a late reply to an
/// earlier request, or a notification, is skipped, never taken for the answer.
/// After any error or timeout the connection is spent (see [`Connection::is_spent`]):
/// a reply may still be on its way, so it must not carry another request.
pub struct Connection {
    write: tokio::net::unix::OwnedWriteHalf,
    lines: tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
    timeout: Duration,
    max_reply: usize,
    here: (std::path::PathBuf, std::path::PathBuf),
    next_id: u64,
    spent: bool,
}

impl Connection {
    /// Check the socket and connect to it. `tool` names the command in the
    /// messages ("native status only talks to your own node").
    pub async fn open(
        tool: &str,
        config_path: &Path,
        socket: &Path,
        timeout: Duration,
        limits: &Limits,
    ) -> Result<Self, NodeInfo> {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
        use tokio::io::BufReader;
        let here = |state, detail: String| down(state, detail, Some(config_path), Some(socket));
        let meta = match std::fs::symlink_metadata(socket) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(here(
                    NodeState::NoSocket,
                    format!(
                        "the node is not running (no socket at {}); start it with `native service install` or `native node serve --config {}`",
                        socket.display(),
                        config_path.display()
                    ),
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(here(
                    NodeState::PermissionDenied,
                    format!("permission denied reading {}", socket.display()),
                ))
            }
            Err(error) => {
                return Err(here(
                    NodeState::NotAnswering,
                    format!("cannot inspect the socket ({})", io_kind(&error)),
                ))
            }
        };
        if !meta.file_type().is_socket() {
            return Err(here(
                NodeState::NotAnswering,
                format!("{} is not a socket", socket.display()),
            ));
        }
        // SAFETY: geteuid has no preconditions or pointer arguments.
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(here(
                NodeState::PermissionDenied,
                format!(
                    "the socket belongs to another user (uid {}); {tool} only talks to your own node",
                    meta.uid()
                ),
            ));
        }
        let stream =
            match tokio::time::timeout(timeout, tokio::net::UnixStream::connect(socket)).await {
                Err(_) => {
                    return Err(here(
                        NodeState::NotAnswering,
                        format!(
                            "the node did not accept a connection within {}s",
                            timeout.as_secs()
                        ),
                    ))
                }
                Ok(Err(error)) => {
                    return Err(match error.kind() {
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound => here(
                            NodeState::StaleSocket,
                            format!(
                                "the node is not running (a socket file exists at {} but nothing listens on it)",
                                socket.display()
                            ),
                        ),
                        std::io::ErrorKind::PermissionDenied => here(
                            NodeState::PermissionDenied,
                            format!("permission denied connecting to {}", socket.display()),
                        ),
                        _ => here(
                            NodeState::NotAnswering,
                            format!("cannot connect to the node ({})", io_kind(&error)),
                        ),
                    })
                }
                Ok(Ok(stream)) => stream,
            };
        // As `native node connect` does: the other end must be this user's process.
        match stream.peer_cred() {
            Ok(cred) if cred.uid() == limits.peer_uid => {}
            Ok(cred) => {
                return Err(here(
                    NodeState::PermissionDenied,
                    format!(
                        "the process on the other end of the socket runs as another user (uid {}); {tool} only talks to your own node",
                        cred.uid()
                    ),
                ))
            }
            Err(error) => {
                return Err(here(
                    NodeState::PermissionDenied,
                    format!("cannot verify who runs the node ({})", io_kind(&error)),
                ))
            }
        }
        let (read, write) = stream.into_split();
        Ok(Self {
            write,
            lines: BufReader::new(read),
            timeout,
            max_reply: limits.max_reply,
            here: (config_path.to_path_buf(), socket.to_path_buf()),
            next_id: 1,
            spent: false,
        })
    }

    /// The MCP `initialize` handshake. A close with no reply reads as the node
    /// rejecting this user.
    pub async fn initialize(
        &mut self,
        client_name: &str,
        protocol_version: &str,
    ) -> Result<(), NodeInfo> {
        let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":protocol_version,"clientInfo":{"name":client_name,"version":crate::engine_version_string()},"capabilities":{}}});
        self.exchange(init, true)
            .await
            .map(|_| ())
            .map_err(|why| self.not_answering(&why))
    }

    /// Why a failed exchange is a [`NodeInfo`].
    pub fn not_answering(&self, why: &str) -> NodeInfo {
        let (config, socket) = (&self.here.0, &self.here.1);
        if why == "PEER_REJECTED" {
            down(
                NodeState::PeerRejected,
                "the node closed the connection at once; it may have rejected this user (UID mismatch)",
                Some(config),
                Some(socket),
            )
        } else {
            down(
                NodeState::NotAnswering,
                format!("the node is not answering: {why}"),
                Some(config),
                Some(socket),
            )
        }
    }

    /// One request out and its reply back, within the timeout and the reply
    /// bound. The request's `id` is replaced by one unique to this connection.
    /// `first` marks the opening exchange: a close with no reply then reads as
    /// a rejection. Any error leaves the connection spent.
    pub async fn exchange(&mut self, mut request: Value, first: bool) -> Result<Value, String> {
        if self.spent {
            return Err("the connection was closed after an earlier error".to_owned());
        }
        let id = self.next_id;
        self.next_id += 1;
        request["id"] = json!(id);
        let result = exchange(
            &mut self.write,
            &mut self.lines,
            request,
            id,
            first,
            self.timeout,
            self.max_reply,
        )
        .await;
        if result.is_err() {
            self.spent = true;
        }
        result
    }

    /// An earlier exchange failed or timed out. Its reply may still arrive, so
    /// this connection must not be used again; open another.
    pub fn is_spent(&self) -> bool {
        self.spent
    }

    /// Replace the per-exchange timeout (a tool call may take longer than a
    /// connection).
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
}

/// Why a bounded line read ended without a line.
enum LineError {
    TooLong,
    Closed,
    Io,
    NotJson,
}

/// Read one `\n`-terminated line of at most `limit` bytes, giving up the moment
/// more than that has arrived (no unbounded buffer, however long the peer goes
/// on without a newline).
async fn read_line_bounded(
    reader: &mut tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
    limit: usize,
) -> Result<Vec<u8>, LineError> {
    use tokio::io::AsyncBufReadExt as _;
    let mut line = Vec::new();
    loop {
        let chunk = reader.fill_buf().await.map_err(|_| LineError::Io)?;
        if chunk.is_empty() {
            return Err(LineError::Closed);
        }
        match chunk.iter().position(|b| *b == b'\n') {
            Some(end) => {
                if line.len() + end > limit {
                    return Err(LineError::TooLong);
                }
                line.extend_from_slice(&chunk[..end]);
                reader.consume(end + 1);
                return Ok(line);
            }
            None => {
                if line.len() + chunk.len() > limit {
                    return Err(LineError::TooLong);
                }
                line.extend_from_slice(chunk);
                let taken = chunk.len();
                reader.consume(taken);
            }
        }
    }
}

/// Send `request` (numbered `id`) and read lines until the reply numbered `id`
/// arrives, skipping notifications and replies to other requests, all within
/// `timeout`.
async fn exchange(
    write: &mut tokio::net::unix::OwnedWriteHalf,
    lines: &mut tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
    request: Value,
    id: u64,
    first: bool,
    timeout: Duration,
    max_reply: usize,
) -> Result<Value, String> {
    use tokio::io::AsyncWriteExt as _;
    let payload = format!("{request}\n");
    let wanted = json!(id);
    let attempt = async {
        write
            .write_all(payload.as_bytes())
            .await
            .map_err(|_| LineError::Io)?;
        loop {
            let line = read_line_bounded(lines, max_reply).await?;
            let reply: Value = serde_json::from_slice(&line).map_err(|_| LineError::NotJson)?;
            // Only the reply to this request. A late reply to an earlier one,
            // or a notification (no id), is not the answer.
            if reply.get("id") == Some(&wanted) {
                return Ok(reply);
            }
        }
    };
    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(LineError::NotJson)) => Err("the reply was not JSON".to_owned()),
        Ok(Err(LineError::TooLong)) => Err(format!("the reply was larger than {max_reply} bytes")),
        Ok(Err(LineError::Closed | LineError::Io)) if first => Err("PEER_REJECTED".to_owned()),
        Ok(Err(LineError::Closed | LineError::Io)) => {
            Err("the node closed the connection".to_owned())
        }
        Err(_) => Err(format!("no reply within {}s", timeout.as_secs())),
    }
}

/// The `structuredContent` of a tool reply, or a short reason it has none.
pub fn structured(reply: &Value) -> Result<Value, String> {
    if let Some(error) = reply.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("the node returned an error");
        return Err(clean(message, 160));
    }
    let result = reply.get("result").ok_or("no result in the reply")?;
    if result.get("isError") == Some(&Value::Bool(true)) {
        let text = result
            .pointer("/content/0/text")
            .and_then(Value::as_str)
            .unwrap_or("the node reported an error");
        return Err(clean(text, 160));
    }
    result
        .get("structuredContent")
        .filter(|v| v.is_object())
        .cloned()
        .ok_or_else(|| "the reply carried no status".to_owned())
}

/// A single line of printable text, at most `max` characters.
pub fn clean(text: &str, max: usize) -> String {
    let single: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let single = single.split_whitespace().collect::<Vec<_>>().join(" ");
    if single.chars().count() > max {
        let cut: String = single.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    } else {
        single
    }
}
