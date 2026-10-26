//! Owner-local hosted MCP transport and conservative standby failover.

mod accept;
pub mod oauth;

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

pub(crate) mod daemon_client;
// S3 seam: the persistence slice is the in-crate consumer of the curator.
// Until it lands, the whole module would read as dead code.
#[cfg(feature = "mcp-executor-prototype")]
mod failover;
#[cfg(feature = "mcp-executor-prototype")]
mod gate;
#[cfg(feature = "mcp-executor-prototype")]
mod hold;
#[cfg(feature = "mcp-executor-prototype")]
mod journal;
#[allow(dead_code)]
pub(crate) mod session_persist;
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

struct SendReport {
    reply: Option<String>,
    failure: Option<Health>,
    attempt: Attempt,
    /// The HTTP status hosted answered with, apart from whatever body came
    /// back (a framed JSON-RPC error body carries no status of its own).
    status: Option<u16>,
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
}

impl Caller {
    fn new(client_info: Option<Value>, cancel: Cancel) -> Self {
        Self {
            client_info,
            cancel,
            received: std::time::Instant::now(),
        }
    }
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

impl NodeConfig {
    pub fn socket_path(&self) -> PathBuf {
        self.socket_directory.join(SOCKET_NAME)
    }

    fn endpoint(&self) -> Result<reqwest::Url> {
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
        url.path_segments_mut()
            .map_err(|_| Error::engine("invalid node base URL path"))?
            .pop_if_empty()
            .push("mcp")
            .push(&self.db_id);
        Ok(url)
    }
}

struct Upstream {
    // This configuration is the state key: (home_id, db_id), N = 1.
    config: NodeConfig,
    endpoint: reqwest::Url,
    client: reqwest::Client,
    oauth: Option<std::sync::Arc<oauth::OAuthRenewer>>,
}

impl Upstream {
    fn new(config: NodeConfig, timeout: Duration) -> Result<Self> {
        let endpoint = config.endpoint()?;
        read_guarded_credential(&config.credential_file, "node")?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(timeout)
            .build()
            .map_err(|_| Error::engine("cannot build node HTTP client"))?;
        let oauth = match &config.oauth_auth_file {
            Some(auth_path) => {
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
            config,
            endpoint,
            client,
            oauth,
        })
    }

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
        let mut failure = None;
        let mut attempt = Attempt::Answered;
        let mut status = None;
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
        ))
        .await;
        SendReport {
            reply,
            failure,
            attempt,
            status,
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
                        json!({"outcome":"not_sent","detail":error.to_string()}),
                    );
                }
                Err(reason) => {
                    *attempt = Attempt::Stopped;
                    return frame_error(
                        id,
                        &format!("Credential renewal {reason}; request was not sent"),
                        json!({"outcome":"not_sent"}),
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
                    json!({"outcome":"not_sent"}),
                );
            }
        };
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
        let mut request = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(std::str::from_utf8(&token).expect("guarded UTF-8"))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .body(body.to_owned());
        if !crate::mcp::is_modern_request(message) {
            if let Some(revision) = revision {
                request = request.header("MCP-Protocol-Version", revision);
            }
        }
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
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
        if status == 202 && bytes.is_empty() && id.is_none() {
            return None;
        }
        let text = std::str::from_utf8(&bytes).ok();
        let reply = text.and_then(decode_reply);
        if let Some((raw, value)) = reply {
            if is_rpc_reply(&value) {
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
    serve_routed_connection(stream, upstream, None, None, Arc::new(Admission::new())).await
}

#[cfg(feature = "mcp-executor-prototype")]
type Router = Arc<Failover>;
#[cfg(not(feature = "mcp-executor-prototype"))]
type Router = ();

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
    body: &str,
    message: Value,
    revision: Option<&str>,
    direct: &std::sync::atomic::AtomicBool,
    caller: &Caller,
) -> Option<String> {
    let local = match local_route(&message) {
        Ok(local) => local,
        Err(reason) => return route_refusal(&message, reason),
    };
    #[cfg(feature = "mcp-executor-prototype")]
    {
        if let Some(gate) = gate {
            if message.pointer("/params/name") == Some(&json!("node_status"))
                && message["method"] == "tools/call"
            {
                let filter = status_filter(message.pointer("/params/arguments"));
                let mut status = gate.status(&filter);
                status["account_id"] = json!(upstream.config.account_id);
                if let Some(router) = router {
                    status["hosted"] = router.hosted_summary().await;
                }
                return node_status_reply(
                    message.get("id"),
                    status,
                    crate::mcp::is_modern_request(&message),
                );
            }
            // A run that bootstraps again hears about the writes the node is
            // holding for it, and for the runs it started.
            let bootstrap_run = failover::target(&message)
                .filter(|(executor, _, _)| executor == "bootstrap")
                .and_then(|(_, _, arguments)| {
                    arguments
                        .get("run_key")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
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
                return reply.map(|reply| gate.note_held_writes(&reply, &run));
            }
        }
    }
    route_unnoted(
        upstream, router, gate, body, message, revision, direct, caller, local,
    )
    .await
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
                    // Ordinary caller traffic may be held; only the session
                    // saver opts out via its own gate path (S3).
                    no_hold: false,
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
        .send(body, &message, revision, message.get("id"))
        .await
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
    let in_flight = Arc::new(InFlight::default());
    let watcher = tokio::spawn({
        let in_flight = in_flight.clone();
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
                    in_flight.close();
                    return;
                }
            }
        }
    });
    let result =
        serve_split_connection(stream, upstream, router, gate, admission, in_flight.clone()).await;
    // Whatever ended the connection, nobody is waiting for retries any more.
    in_flight.close();
    watcher.abort();
    result
}

async fn serve_split_connection(
    stream: UnixStream,
    upstream: Arc<Upstream>,
    router: Option<Router>,
    gate: Option<Arc<WriteGate>>,
    admission: Arc<Admission>,
    in_flight: Arc<InFlight>,
) -> Result<()> {
    let (read, write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let writer = Arc::new(Mutex::new(write));
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut tasks = JoinSet::new();
    let mut revision: Option<String> = None;
    let mut client_info: Option<Value> = None;
    let direct = Arc::new(std::sync::atomic::AtomicBool::new(false));
    loop {
        // Bound a single frame without losing partial reads.
        let mut bytes = Vec::new();
        let count = (&mut reader)
            .take((MAX_FRAME + 1) as u64)
            .read_until(b'\n', &mut bytes)
            .await?;
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
        if message.get("method").and_then(Value::as_str) == Some("initialize") {
            client_info = message.pointer("/params/clientInfo").cloned();
            let caller = Caller::new(client_info.clone(), Cancel::new());
            let reply = route_message(
                &upstream,
                router.as_ref(),
                gate.as_ref(),
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
        };
        let upstream = upstream.clone();
        let writer = writer.clone();
        let revision = revision.clone();
        let router = router.clone();
        let gate = gate.clone();
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
            let reply = route_message(
                &upstream,
                router.as_ref(),
                gate.as_ref(),
                &body,
                message.clone(),
                revision.as_deref(),
                &direct,
                &caller,
            )
            .await;
            // MCP: a cancelled request gets no reply.
            if in_flight.finish(&track) {
                return Ok(());
            }
            write_reply(&writer, reply).await
        });
        while let Some(result) = tasks.try_join_next() {
            result.map_err(|_| Error::engine("node request task failed"))??;
        }
    }
    // EOF does not cancel an already sent request or cause a resend.
    while let Some(result) = tasks.join_next().await {
        result.map_err(|_| Error::engine("node request task failed"))??;
    }
    Ok(())
}

/// Serve until SIGINT/SIGTERM. Shutdown never retries outstanding requests.
pub async fn serve(config: NodeConfig) -> Result<()> {
    let upstream = Arc::new(Upstream::new(config.clone(), REQUEST_TIMEOUT)?);
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
    let gate = Some(Arc::new(WriteGate::open(
        &config.socket_directory,
        gate::GateConfig {
            disk_floor_bytes: config.disk_floor_bytes.unwrap_or(gate::DEFAULT_DISK_FLOOR),
            record_url_base: Some(config.hosted_base_url.trim_end_matches('/').to_owned()),
            ..gate::GateConfig::default()
        },
    )?));
    #[cfg(not(feature = "mcp-executor-prototype"))]
    let gate: Option<Arc<WriteGate>> = None;
    #[cfg(feature = "mcp-executor-prototype")]
    let housekeeping = gate.as_ref().map(WriteGate::spawn_housekeeping);
    #[cfg(feature = "mcp-executor-prototype")]
    let standby = failover::start_standby(&config)?;
    #[cfg(feature = "mcp-executor-prototype")]
    if let (Some(gate), Some(standby)) = (&gate, &standby) {
        gate.set_copy_root(standby.replica_root.clone());
    }
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
    let monitor = router
        .as_ref()
        .map(|router| tokio::spawn(router.clone().monitor()));
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
                Arc::new(session_writer::GateSink::new(
                    upstream.clone(),
                    gate.as_ref()
                        .ok_or_else(|| Error::engine("session saver requires its write gate"))?
                        .clone(),
                )),
            )?;
            #[cfg(not(feature = "mcp-executor-prototype"))]
            let backend = session_saver::SaverBackend::ObserveOnly;
            session_saver::spawn_saver(loaded, account, &config.db_id, backend)
        })
        .transpose()?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut connections = JoinSet::new();
    let admission = Arc::new(Admission::new());
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
            accepted = listener.accept() => {
                let stream = accepted?;
                let upstream = upstream.clone();
                let router = router.clone();
                let gate = gate.clone();
                let admission = admission.clone();
                connections.spawn(async move { serve_routed_connection(stream, upstream, router, gate, admission).await });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    // Stop connection tasks before draining the shared generation. No replay.
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    if let Some(saver) = saver {
        saver.shutdown().await;
    }
    #[cfg(feature = "mcp-executor-prototype")]
    {
        if let Some(housekeeping) = housekeeping {
            housekeeping.abort();
        }
        if let Some(queue) = queue {
            queue.abort();
        }
        if let Some(monitor) = monitor {
            monitor.abort();
            let _ = monitor.await;
        }
        if let Some(standby) = standby {
            standby.shutdown().await?;
        }
    }
    Ok(())
}

/// Byte-only stdio shim, with a write half-close at stdin EOF and reply drain.
/// The user id a node socket's peer must have: this process's own. Shared with
/// `native status`, which makes the same check before it talks to a node.
pub(crate) fn current_uid() -> u32 {
    owner_uid()
}

pub async fn connect<R, W>(socket: &Path, mut input: R, mut output: W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let stream = UnixStream::connect(socket).await?;
    if stream.peer_cred()?.uid() != owner_uid() {
        return Err(Error::engine("node server UID rejected"));
    }
    let (mut read, mut write) = stream.into_split();
    let upload = async {
        tokio::io::copy(&mut input, &mut write).await?;
        write.shutdown().await
    };
    let download = async {
        tokio::io::copy(&mut read, &mut output).await?;
        output.flush().await
    };
    tokio::pin!(upload, download);
    tokio::select! {
        result = &mut upload => {
            result?;
            // Stdin EOF half-closes the socket, then waits for outstanding replies.
            download.await?;
        }
        result = &mut download => {
            // A dead node must close stdout even if the agent keeps stdin open.
            result?;
        }
    }
    Ok(())
}

/// See [`failover::TEST_CONSUMER_IDENTITY`].
#[cfg(test)]
pub(crate) fn set_test_consumer_identity(
    identity: Option<crate::standby_snapshot::ObservedInstalledConsumerIdentity>,
) {
    *failover::TEST_CONSUMER_IDENTITY.lock().unwrap() = identity;
}

pub async fn run_cli(args: &[String]) -> Result<()> {
    match args {
        [mode, flag, path] if mode == "serve" && flag == "--config" => {
            let bytes = fs::read(path)?;
            let config = serde_json::from_slice(&bytes)
                .map_err(|error| Error::engine(format!("invalid node config JSON: {error}")))?;
            serve(config).await
        }
        [mode, flag, path] if mode == "connect" && flag == "--socket" => {
            connect(Path::new(path), tokio::io::stdin(), tokio::io::stdout()).await
        }
        _ => Err(Error::engine(
            "usage: mcp-stdio node serve --config <file> | mcp-stdio node connect --socket <path>",
        )),
    }
}

#[cfg(test)]
mod tests;
