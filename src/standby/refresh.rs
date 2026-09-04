//! Authenticated hosted-snapshot acquisition for the local standby.
//!
//! This is a controller kernel, not an MCP tool. It talks only to the hosted
//! MCP endpoint and the generation store; the local MCP remains physically
//! read-only and keeps serving its already-leased immutable generation.

use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use fs2::FileExt as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use crate::error::{Error, Result};
use crate::standby_snapshot::{
    CanonicalFrontierV1, ObservedInstalledConsumerIdentity, StandbyConsumerIdentity,
    StandbySnapshotManifest, STANDBY_CONSUMER_CONTRACT, STANDBY_SNAPSHOT_MEDIA_TYPE,
};

use super::{GenerationStore, InstalledGeneration, StandbyRuntimeConfig};

const STATE_CONTRACT: &str = "native.standby-refresh-state.v1";
const CONFIG_CONTRACT: &str = "native.standby-refresh-config.v1";
const PROTOCOL_VERSION: &str = "2026-07-28";
const MAX_PAGE_BYTES: usize = crate::mcp::SNAPSHOT_MAX_PAGE_BYTES;
// A complete MCP result carries the page in both text and structured content.
// One maximum-sized (512 KiB) page therefore expands to roughly 1.4 MiB after
// base64 and JSON framing.
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 4096;
const SCHEDULE_INTERVAL: Duration = Duration::from_secs(120);
const MANUAL_POLL_INTERVAL: Duration = Duration::from_secs(1);
// Export handles expire after five minutes. Leave time for state finalization
// and never splice a timed-out transfer into a new export.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(270);
const NETWORK_RECOVERY_PROBE_INTERVAL: Duration = Duration::from_secs(10);
const WAKE_DETECTION_SLOP: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandbyRefreshConfig {
    pub contract: String,
    pub version: u32,
    pub hosted_origin: String,
    pub credential_file: PathBuf,
}

impl StandbyRefreshConfig {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let config: Self = serde_json::from_slice(bytes)
            .map_err(|error| Error::engine(format!("invalid standby refresh config: {error}")))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.contract != CONFIG_CONTRACT || self.version != 1 {
            return Err(Error::engine("invalid standby refresh config contract"));
        }
        validate_exact_origin(&self.hosted_origin)?;
        // Availability and metadata are checked on every attempt so an
        // initially missing or atomically rotated credential can recover
        // without restarting the local reader.
        validate_credential_path(&self.credential_file)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshCause {
    Startup,
    Scheduled,
    Wake,
    NetworkRecovery,
    Manual,
    AfterAdmittedWrite,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshFailureClass {
    Authentication,
    Network,
    Protocol,
    DownloadIntegrity,
    Verification,
    Compatibility,
    Timeout,
    LocalIo,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StandbyRefreshState {
    pub contract: String,
    pub version: u32,
    pub refresh_active: bool,
    pub manual_refresh_pending: bool,
    #[serde(default)]
    pub active_candidate_generation_id: Option<String>,
    #[serde(default)]
    pub active_candidate_captured_at: Option<String>,
    #[serde(default)]
    pub active_candidate_completed_at: Option<String>,
    #[serde(default)]
    pub active_candidate_frontier: Option<CanonicalFrontierV1>,
    pub last_attempt_at: Option<String>,
    pub last_attempt_cause: Option<RefreshCause>,
    pub last_success_at: Option<String>,
    pub installed_generation_id: Option<String>,
    pub snapshot_captured_at: Option<String>,
    pub snapshot_completed_at: Option<String>,
    pub promoted_at: Option<String>,
    pub frontier: Option<CanonicalFrontierV1>,
    pub consecutive_failure_count: u32,
    pub last_failure_class: Option<RefreshFailureClass>,
    pub last_failure: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) enum RefreshStateObservation {
    NeverRecorded,
    Available(Box<StandbyRefreshState>),
    Unavailable,
}

const MAX_STATUS_DIAGNOSTIC_FILE_BYTES: u64 = 64 * 1024;

fn valid_status_timestamp(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(|value| {
        value.len() <= 40 && chrono::DateTime::parse_from_rfc3339(value).is_ok()
    })
}

fn status_time(value: &Option<String>) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    value
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
}

fn valid_status_generation_id(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_status_state(state: &StandbyRefreshState) -> bool {
    let active_evidence = [
        state.active_candidate_generation_id.is_some(),
        state.active_candidate_captured_at.is_some(),
        state.active_candidate_completed_at.is_some(),
        state.active_candidate_frontier.is_some(),
    ];
    let success_evidence = [
        state.last_success_at.is_some(),
        state.installed_generation_id.is_some(),
        state.snapshot_captured_at.is_some(),
        state.snapshot_completed_at.is_some(),
        state.frontier.is_some(),
    ];
    state.last_attempt_at.is_some() == state.last_attempt_cause.is_some()
        && state.last_failure_class.is_some() == state.last_failure.is_some()
        && active_evidence
            .iter()
            .all(|present| *present == active_evidence[0])
        && success_evidence
            .iter()
            .all(|present| *present == success_evidence[0])
        && (state.promoted_at.is_none() || success_evidence[0])
        && valid_status_generation_id(&state.active_candidate_generation_id)
        && valid_status_generation_id(&state.installed_generation_id)
        && state
            .active_candidate_frontier
            .as_ref()
            .is_none_or(|frontier| frontier.validate().is_ok())
        && state
            .frontier
            .as_ref()
            .is_none_or(|frontier| frontier.validate().is_ok())
        && [
            &state.active_candidate_captured_at,
            &state.active_candidate_completed_at,
            &state.last_attempt_at,
            &state.last_success_at,
            &state.snapshot_captured_at,
            &state.snapshot_completed_at,
            &state.promoted_at,
        ]
        .into_iter()
        .all(valid_status_timestamp)
        && match (
            status_time(&state.active_candidate_captured_at),
            status_time(&state.active_candidate_completed_at),
        ) {
            (Some(captured), Some(completed)) => captured <= completed,
            (None, None) => true,
            _ => false,
        }
        && match (
            status_time(&state.snapshot_captured_at),
            status_time(&state.snapshot_completed_at),
        ) {
            (Some(captured), Some(completed)) => captured <= completed,
            (None, None) => true,
            _ => false,
        }
}

pub(super) fn observe_refresh_state(replica_root: &Path) -> RefreshStateObservation {
    let refresh_dir = replica_root.join("refresh");
    let path = refresh_dir.join("state.json");
    let mut state = match fs::symlink_metadata(&path) {
        Ok(_) => {
            if require_regular_file(&path).is_err()
                || fs::metadata(&path)
                    .map(|metadata| metadata.len() > MAX_STATUS_DIAGNOSTIC_FILE_BYTES)
                    .unwrap_or(true)
            {
                return RefreshStateObservation::Unavailable;
            }
            let Ok(bytes) = fs::read(&path) else {
                return RefreshStateObservation::Unavailable;
            };
            let Ok(state) = serde_json::from_slice::<StandbyRefreshState>(&bytes) else {
                return RefreshStateObservation::Unavailable;
            };
            if state.contract != STATE_CONTRACT || state.version != 1 || !valid_status_state(&state)
            {
                return RefreshStateObservation::Unavailable;
            }
            state
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return RefreshStateObservation::NeverRecorded
        }
        Err(_) => return RefreshStateObservation::Unavailable,
    };
    let pending = refresh_dir.join("pending.json");
    state.manual_refresh_pending = match fs::symlink_metadata(&pending) {
        Ok(_) => {
            if require_regular_file(&pending).is_err()
                || fs::metadata(&pending)
                    .map(|metadata| metadata.len() > MAX_STATUS_DIAGNOSTIC_FILE_BYTES)
                    .unwrap_or(true)
            {
                return RefreshStateObservation::Unavailable;
            }
            let Ok(bytes) = fs::read(&pending) else {
                return RefreshStateObservation::Unavailable;
            };
            let Ok(pending) = serde_json::from_slice::<PendingTriggers>(&bytes) else {
                return RefreshStateObservation::Unavailable;
            };
            pending.causes.contains(&RefreshCause::Manual)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return RefreshStateObservation::Unavailable,
    };
    RefreshStateObservation::Available(Box::new(state))
}

impl Default for StandbyRefreshState {
    fn default() -> Self {
        Self {
            contract: STATE_CONTRACT.into(),
            version: 1,
            refresh_active: false,
            manual_refresh_pending: false,
            active_candidate_generation_id: None,
            active_candidate_captured_at: None,
            active_candidate_completed_at: None,
            active_candidate_frontier: None,
            last_attempt_at: None,
            last_attempt_cause: None,
            last_success_at: None,
            installed_generation_id: None,
            snapshot_captured_at: None,
            snapshot_completed_at: None,
            promoted_at: None,
            frontier: None,
            consecutive_failure_count: 0,
            last_failure_class: None,
            last_failure: None,
        }
    }
}

#[derive(Debug)]
pub enum StandbyRefreshOutcome {
    Installed {
        generation: Box<InstalledGeneration>,
        retention_warnings: Vec<String>,
    },
    Accepted {
        coalesced: bool,
    },
}

/// Exclusive ownership of scheduling for one replica root.
pub struct StandbyRefreshDaemonGuard {
    _file: File,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingTriggers {
    causes: Vec<RefreshCause>,
}

#[derive(Debug)]
struct AttemptError {
    class: RefreshFailureClass,
    safe_message: &'static str,
    source: Error,
}

struct AttemptStagingFiles {
    snapshot: PathBuf,
    manifest: PathBuf,
}

impl Drop for AttemptStagingFiles {
    fn drop(&mut self) {
        remove_owned_staging_file(&self.snapshot);
        remove_owned_staging_file(&self.manifest);
    }
}

impl AttemptError {
    fn new(class: RefreshFailureClass, safe_message: &'static str, source: Error) -> Self {
        Self {
            class,
            safe_message,
            source,
        }
    }
}

type PageFuture =
    Pin<Box<dyn Future<Output = std::result::Result<SnapshotPage, AttemptError>> + Send>>;

trait SnapshotPageClient: Send + Sync {
    fn page(&self, endpoint: String, bearer: String, request: SnapshotPageRequest) -> PageFuture;
}

struct HttpSnapshotPageClient {
    client: reqwest::Client,
}

impl HttpSnapshotPageClient {
    fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| {
                Error::engine(format!("cannot build standby refresh client: {error}"))
            })?;
        Ok(Self { client })
    }
}

impl SnapshotPageClient for HttpSnapshotPageClient {
    fn page(&self, endpoint: String, bearer: String, request: SnapshotPageRequest) -> PageFuture {
        let client = self.client.clone();
        Box::pin(async move {
            let body = modern_export_call(&request);
            let response = client
                .post(endpoint)
                .bearer_auth(bearer)
                .header(
                    reqwest::header::ACCEPT,
                    "application/json, text/event-stream",
                )
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header("MCP-Protocol-Version", PROTOCOL_VERSION)
                .header("Mcp-Method", "tools/call")
                .header("Mcp-Name", EXPORT_EXECUTOR)
                .json(&body)
                .send()
                .await
                .map_err(|_| {
                    AttemptError::new(
                        RefreshFailureClass::Network,
                        "hosted snapshot request failed",
                        Error::engine("hosted snapshot request failed"),
                    )
                })?;
            if matches!(response.status().as_u16(), 401 | 403) {
                return Err(AttemptError::new(
                    RefreshFailureClass::Authentication,
                    "hosted snapshot authentication was refused",
                    Error::auth("hosted snapshot credential refused"),
                ));
            }
            if !response.status().is_success() {
                let transient = response.status().is_server_error()
                    || matches!(response.status().as_u16(), 408 | 425 | 429);
                return Err(AttemptError::new(
                    if transient {
                        RefreshFailureClass::Network
                    } else {
                        RefreshFailureClass::Protocol
                    },
                    if transient {
                        "hosted snapshot endpoint was unavailable"
                    } else {
                        "hosted snapshot request was refused"
                    },
                    Error::engine(format!("hosted snapshot HTTP status {}", response.status())),
                ));
            }
            if response
                .content_length()
                .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
            {
                return Err(AttemptError::new(
                    RefreshFailureClass::Protocol,
                    "hosted snapshot response exceeded its bound",
                    Error::engine("hosted snapshot response too large"),
                ));
            }
            let mut response = response;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| {
                AttemptError::new(
                    RefreshFailureClass::Network,
                    "hosted snapshot response was interrupted",
                    Error::engine("hosted snapshot response was interrupted"),
                )
            })? {
                if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                    return Err(AttemptError::new(
                        RefreshFailureClass::Protocol,
                        "hosted snapshot response exceeded its bound",
                        Error::engine("hosted snapshot response too large"),
                    ));
                }
                bytes.extend_from_slice(&chunk);
            }
            let envelope: RpcEnvelope = serde_json::from_slice(&bytes).map_err(|error| {
                AttemptError::new(
                    RefreshFailureClass::Protocol,
                    "hosted snapshot returned an invalid protocol response",
                    error.into(),
                )
            })?;
            if envelope.jsonrpc != "2.0" || envelope.id != json!(1) {
                return Err(AttemptError::new(
                    RefreshFailureClass::Protocol,
                    "hosted snapshot returned an invalid protocol response",
                    Error::engine("hosted snapshot response correlation mismatch"),
                ));
            }
            if let Some(error) = envelope.error {
                return Err(AttemptError::new(
                    RefreshFailureClass::Protocol,
                    "hosted snapshot tool call was refused",
                    Error::engine(format!("hosted snapshot RPC error {}", error.code)),
                ));
            }
            let result = envelope.result.ok_or_else(|| {
                AttemptError::new(
                    RefreshFailureClass::Protocol,
                    "hosted snapshot omitted its tool result",
                    Error::engine("hosted snapshot missing result"),
                )
            })?;
            // `resultType` is advisory: hosted sends "complete", the stdio
            // executor surface omits it entirely. Absent means complete; a
            // present value that is anything else is a partial result and must
            // not be treated as a snapshot page.
            let incomplete = result
                .result_type
                .as_deref()
                .is_some_and(|kind| kind != "complete");
            if result.is_error || incomplete {
                return Err(AttemptError::new(
                    RefreshFailureClass::Protocol,
                    "hosted snapshot tool reported failure",
                    Error::engine("hosted snapshot tool failure"),
                ));
            }
            result.structured_content.ok_or_else(|| {
                AttemptError::new(
                    RefreshFailureClass::Protocol,
                    "hosted snapshot omitted structured content",
                    Error::engine("hosted snapshot missing structured content"),
                )
            })
        })
    }
}

pub struct StandbyRefreshController {
    runtime: StandbyRuntimeConfig,
    config: StandbyRefreshConfig,
    store: GenerationStore,
    observed: ObservedInstalledConsumerIdentity,
    refresh_dir: PathBuf,
    client: Arc<dyn SnapshotPageClient>,
}

impl StandbyRefreshController {
    pub fn new(
        runtime: StandbyRuntimeConfig,
        config: StandbyRefreshConfig,
        store: GenerationStore,
        observed: ObservedInstalledConsumerIdentity,
    ) -> Result<Self> {
        runtime.validate()?;
        config.validate()?;
        let refresh_dir = runtime.replica_root.join("refresh");
        create_private_directory(&refresh_dir)?;
        Ok(Self {
            runtime,
            config,
            store,
            observed,
            refresh_dir,
            client: Arc::new(HttpSnapshotPageClient::new()?),
        })
    }

    #[cfg(test)]
    fn new_with_client(
        runtime: StandbyRuntimeConfig,
        config: StandbyRefreshConfig,
        store: GenerationStore,
        observed: ObservedInstalledConsumerIdentity,
        client: Arc<dyn SnapshotPageClient>,
    ) -> Result<Self> {
        let mut controller = Self::new(runtime, config, store, observed)?;
        controller.client = client;
        Ok(controller)
    }

    pub fn try_acquire_daemon(&self) -> Result<Option<StandbyRefreshDaemonGuard>> {
        let file = open_private_lock(&self.refresh_dir.join("controller.lock"))?;
        match file.try_lock_exclusive() {
            Ok(()) => {
                self.recover_interrupted_state_if_idle()?;
                Ok(Some(StandbyRefreshDaemonGuard { _file: file }))
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Persist one payload-free manual trigger. `false` means that cause was
    /// already represented by the durable coalesced trigger set.
    pub fn request_manual_refresh(&self) -> Result<bool> {
        self.request_refresh(RefreshCause::Manual)
    }

    /// Durable, payload-free trigger seam for wake/network recovery and the
    /// future admitted-write hook. All causes coalesce while one attempt runs.
    pub fn request_refresh(&self, cause: RefreshCause) -> Result<bool> {
        let lock = open_private_lock(&self.refresh_dir.join("trigger.lock"))?;
        lock.lock_exclusive()?;
        let mut pending = self.read_pending_triggers().unwrap_or_default();
        let inserted = !pending.causes.contains(&cause);
        if inserted {
            pending.causes.push(cause);
            pending.causes.sort_by_key(|cause| *cause as u8);
            self.write_pending_triggers(&pending)?;
            let state = self.state()?;
            self.write_state_unlocked(&state)?;
        }
        Ok(inserted)
    }

    pub fn state(&self) -> Result<StandbyRefreshState> {
        let path = self.state_path();
        let mut state = match fs::symlink_metadata(&path) {
            Ok(_) => {
                require_regular_file(&path)?;
                let bytes = fs::read(&path)?;
                let state: StandbyRefreshState = serde_json::from_slice(&bytes)?;
                if state.contract != STATE_CONTRACT || state.version != 1 {
                    return Err(Error::engine("invalid standby refresh state"));
                }
                state
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                StandbyRefreshState::default()
            }
            Err(error) => return Err(error.into()),
        };
        state.manual_refresh_pending = self
            .read_pending_triggers()?
            .causes
            .contains(&RefreshCause::Manual);
        Ok(state)
    }

    pub async fn refresh_once(&self, cause: RefreshCause) -> Result<StandbyRefreshOutcome> {
        let attempt_lock = open_private_lock(&self.refresh_dir.join("attempt.lock"))?;
        if let Err(error) = attempt_lock.try_lock_exclusive() {
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(error.into());
            }
            let coalesced = !self.request_refresh(cause)?;
            return Ok(StandbyRefreshOutcome::Accepted { coalesced });
        }

        let attempted_at = now();
        // Any durable causes present before this acquisition are represented
        // by this attempt. Requests arriving after this point remain pending
        // for one follow-up.
        let _ = self.take_pending_triggers()?;
        let mut state = match self.state() {
            Ok(state) => state,
            Err(_) => {
                let state = unreadable_state();
                self.write_state(&state)?;
                state
            }
        };
        state.manual_refresh_pending = self
            .read_pending_triggers()?
            .causes
            .contains(&RefreshCause::Manual);
        state.refresh_active = true;
        state.last_attempt_at = Some(attempted_at.clone());
        state.last_attempt_cause = Some(cause);
        state.last_failure_class = None;
        state.last_failure = None;
        self.write_state(&state)?;

        let outcome = match tokio::time::timeout(ATTEMPT_TIMEOUT, self.run_attempt()).await {
            Ok(outcome) => outcome,
            Err(_) => Err(AttemptError::new(
                RefreshFailureClass::Timeout,
                "standby refresh attempt exceeded its time bound",
                Error::engine("standby refresh attempt timed out"),
            )),
        };
        state.refresh_active = false;
        state.active_candidate_generation_id = None;
        state.active_candidate_captured_at = None;
        state.active_candidate_completed_at = None;
        state.active_candidate_frontier = None;
        state.manual_refresh_pending = self
            .read_pending_triggers()?
            .causes
            .contains(&RefreshCause::Manual);
        match outcome {
            Ok((generation, retention_warnings)) => {
                state.last_success_at = Some(now());
                state.installed_generation_id = Some(generation.id.clone());
                state.snapshot_captured_at = Some(generation.manifest.captured_at.clone());
                state.snapshot_completed_at =
                    Some(generation.manifest.snapshot_completed_at.clone());
                state.promoted_at = Some(now());
                state.frontier = Some(generation.manifest.frontier.clone());
                state.consecutive_failure_count = 0;
                state.last_failure_class = None;
                state.last_failure = None;
                self.write_state(&state)?;
                Ok(StandbyRefreshOutcome::Installed {
                    generation: Box::new(generation),
                    retention_warnings,
                })
            }
            Err(error) => {
                state.consecutive_failure_count = state.consecutive_failure_count.saturating_add(1);
                state.last_failure_class = Some(error.class);
                state.last_failure = Some(error.safe_message.into());
                self.write_state(&state)?;
                Err(error.source)
            }
        }
    }

    /// Hold the supplied lifetime lock, service durable triggers, and keep
    /// cadence anchored to absolute deadlines. A deadline missed during an
    /// attempt produces one immediate follow-up, never a catch-up burst.
    pub async fn run_daemon_after_startup(
        &self,
        _guard: StandbyRefreshDaemonGuard,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut poll = tokio::time::interval(MANUAL_POLL_INTERVAL);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut scheduled = tokio::time::Instant::now() + SCHEDULE_INTERVAL;
        let mut startup_pending = true;
        let mut last_monotonic = tokio::time::Instant::now();
        let mut last_wall = SystemTime::now();
        let mut network_probe_at = None;
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { break; }
                }
                _ = poll.tick() => {
                    let pending = self.take_pending_triggers().unwrap_or_default();
                    let now = tokio::time::Instant::now();
                    let wall = SystemTime::now();
                    let monotonic_elapsed = now.saturating_duration_since(last_monotonic);
                    let wall_elapsed = wall.duration_since(last_wall).unwrap_or_default();
                    let woke = elapsed_indicates_wake(wall_elapsed, monotonic_elapsed);
                    last_monotonic = now;
                    last_wall = wall;

                    let network_failed = self.state().ok().is_some_and(|state| {
                        state.last_failure_class == Some(RefreshFailureClass::Network)
                    });
                    if network_failed {
                        network_probe_at.get_or_insert(now + NETWORK_RECOVERY_PROBE_INTERVAL);
                    } else {
                        network_probe_at = None;
                    }
                    let network_recovery_due = network_probe_at.is_some_and(|at| now >= at);
                    let cause = if startup_pending {
                        startup_pending = false;
                        Some(RefreshCause::Startup)
                    } else {
                        pending
                            .first()
                            .copied()
                            .or_else(|| woke.then_some(RefreshCause::Wake))
                            .or_else(|| {
                                network_recovery_due.then_some(RefreshCause::NetworkRecovery)
                            })
                            .or_else(|| (now >= scheduled).then_some(RefreshCause::Scheduled))
                    };
                    if let Some(cause) = cause {
                        // Extra causes in the same set are intentionally
                        // represented by this one acquisition.
                        let attempt = self.refresh_once(cause);
                        tokio::pin!(attempt);
                        tokio::select! {
                            _ = &mut attempt => {}
                            changed = shutdown.changed() => {
                                if changed.is_err() || *shutdown.borrow() {
                                    break;
                                }
                            }
                        }
                        let completed = tokio::time::Instant::now();
                        scheduled = next_scheduled_deadline(scheduled, now, completed, cause);
                        if cause == RefreshCause::NetworkRecovery {
                            network_probe_at = Some(
                                tokio::time::Instant::now() + NETWORK_RECOVERY_PROBE_INTERVAL,
                            );
                        }
                    }
                }
            }
        }
    }

    async fn run_attempt(
        &self,
    ) -> std::result::Result<(InstalledGeneration, Vec<String>), AttemptError> {
        let bearer = read_credential(&self.config.credential_file)?;
        let endpoint = format!(
            "{}/mcp/{}",
            self.config.hosted_origin,
            utf8_percent_encode(&self.runtime.hosted_route_database_id, NON_ALPHANUMERIC)
        );
        let attempt_id = uuid::Uuid::new_v4();
        let snapshot_path = self
            .store
            .staging_dir()
            .join(format!("refresh-{attempt_id}.snapshot.db"));
        let manifest_path = self
            .store
            .staging_dir()
            .join(format!("refresh-{attempt_id}.manifest.json"));
        let _cleanup = AttemptStagingFiles {
            snapshot: snapshot_path.clone(),
            manifest: manifest_path.clone(),
        };
        self.download_and_install(&endpoint, bearer, &snapshot_path, &manifest_path)
            .await
    }

    async fn download_and_install(
        &self,
        endpoint: &str,
        bearer: String,
        snapshot_path: &Path,
        manifest_path: &Path,
    ) -> std::result::Result<(InstalledGeneration, Vec<String>), AttemptError> {
        let mut output = create_private_file(snapshot_path)?;
        let mut digest = Sha256::new();
        let mut offset = 0_u64;
        let mut export_id: Option<String> = None;
        let mut expected_size = None;
        let mut expected_sha = None;
        let mut manifest: Option<StandbySnapshotManifest> = None;

        loop {
            let request = SnapshotPageRequest {
                export_id: export_id.clone(),
                offset,
                length: MAX_PAGE_BYTES,
                standby_consumer: export_id.is_none().then(|| self.declared_consumer()),
            };
            let page = self
                .fetch_page_with_retry(endpoint, &bearer, request)
                .await?;
            validate_page(
                &page,
                export_id.as_deref(),
                offset,
                expected_size,
                expected_sha.as_deref(),
                manifest.as_ref(),
            )?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&page.data_base64)
                .map_err(|_| {
                    integrity(
                        "snapshot page is not valid base64",
                        Error::engine("invalid snapshot page base64"),
                    )
                })?;
            if bytes.len() != page.length || bytes.len() > MAX_PAGE_BYTES {
                return Err(integrity(
                    "snapshot page length does not match its bytes",
                    Error::engine("snapshot page length mismatch"),
                ));
            }
            output
                .write_all(&bytes)
                .map_err(|error| local_io(error.into()))?;
            digest.update(&bytes);
            if export_id.is_none() {
                export_id = Some(page.export_id.clone());
                expected_size = Some(page.size_bytes);
                expected_sha = Some(page.sha256.clone());
                manifest = page.manifest.clone();
            }
            offset = offset.saturating_add(bytes.len() as u64);
            if page.eof {
                break;
            }
        }
        output.sync_all().map_err(|error| local_io(error.into()))?;
        drop(output);
        let expected_size = expected_size.ok_or_else(|| {
            integrity(
                "snapshot transfer returned no pages",
                Error::engine("empty transfer"),
            )
        })?;
        let expected_sha = expected_sha.expect("set with expected size");
        if offset != expected_size || hex::encode(digest.finalize()) != expected_sha {
            return Err(integrity(
                "completed snapshot identity did not match its declaration",
                Error::engine("snapshot transfer digest mismatch"),
            ));
        }
        let manifest = manifest.ok_or_else(|| {
            integrity(
                "hosted snapshot omitted its standby manifest",
                Error::engine("missing standby manifest"),
            )
        })?;
        let manifest_bytes = manifest.canonical_json().map_err(|error| {
            AttemptError::new(
                RefreshFailureClass::Verification,
                "hosted snapshot manifest failed validation",
                error,
            )
        })?;
        let mut manifest_file = create_private_file(manifest_path)?;
        manifest_file
            .write_all(&manifest_bytes)
            .map_err(|error| local_io(error.into()))?;
        manifest_file
            .sync_all()
            .map_err(|error| local_io(error.into()))?;
        File::open(self.store.staging_dir())
            .and_then(|file| file.sync_all())
            .map_err(|error| local_io(error.into()))?;

        self.record_active_candidate(&manifest)?;

        let generation = self
            .store
            .install_staged(snapshot_path, manifest_path, &self.observed)
            .await
            .map_err(classify_install_error)?;
        let retention_warnings = match self.store.prune_retention(&self.observed).await {
            Ok(warnings) => warnings,
            Err(_) => vec!["post-refresh retention deferred".into()],
        };
        Ok((generation, retention_warnings))
    }

    async fn fetch_page_with_retry(
        &self,
        endpoint: &str,
        bearer: &str,
        request: SnapshotPageRequest,
    ) -> std::result::Result<SnapshotPage, AttemptError> {
        let delays = [
            Duration::ZERO,
            Duration::from_millis(250),
            Duration::from_millis(750),
        ];
        for (attempt, delay) in delays.into_iter().enumerate() {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            match self
                .client
                .page(endpoint.to_string(), bearer.to_string(), request.clone())
                .await
            {
                Ok(page) => return Ok(page),
                Err(error)
                    if error.class == RefreshFailureClass::Network
                        && attempt + 1 < delays.len() => {}
                Err(error) => return Err(error),
            }
        }
        unreachable!("bounded retry loop returns on its last attempt")
    }

    fn declared_consumer(&self) -> StandbyConsumerIdentity {
        StandbyConsumerIdentity {
            contract: STANDBY_CONSUMER_CONTRACT.into(),
            version: 1,
            platform: self.observed.platform,
            source_sha: self.observed.source_sha.clone(),
            artifact_sha256: self.observed.artifact_sha256.clone(),
            engine_schema_version: self.observed.engine_schema_version,
            ddl_sha256: self.observed.ddl_sha256.clone(),
        }
    }

    fn state_path(&self) -> PathBuf {
        self.refresh_dir.join("state.json")
    }

    fn pending_marker_path(&self) -> PathBuf {
        self.refresh_dir.join("pending.json")
    }

    fn read_pending_triggers(&self) -> Result<PendingTriggers> {
        let path = self.pending_marker_path();
        match fs::read(&path) {
            Ok(bytes) => {
                require_regular_file(&path)?;
                serde_json::from_slice(&bytes).map_err(Into::into)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(PendingTriggers::default())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn write_pending_triggers(&self, pending: &PendingTriggers) -> Result<()> {
        let temp = self
            .refresh_dir
            .join(format!(".pending-{}.tmp", uuid::Uuid::new_v4()));
        let mut file = create_private_file(&temp).map_err(|error| error.source)?;
        file.write_all(&serde_jcs::to_vec(pending)?)?;
        file.sync_all()?;
        drop(file);
        fs::rename(temp, self.pending_marker_path())?;
        File::open(&self.refresh_dir)?.sync_all()?;
        Ok(())
    }

    fn take_pending_triggers(&self) -> Result<Vec<RefreshCause>> {
        let lock = open_private_lock(&self.refresh_dir.join("trigger.lock"))?;
        lock.lock_exclusive()?;
        let pending = self.read_pending_triggers().unwrap_or_default();
        match fs::remove_file(self.pending_marker_path()) {
            Ok(()) => {
                File::open(&self.refresh_dir)?.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let state = self.state()?;
        self.write_state_unlocked(&state)?;
        Ok(pending.causes)
    }

    fn write_state(&self, state: &StandbyRefreshState) -> Result<()> {
        let lock = open_private_lock(&self.refresh_dir.join("trigger.lock"))?;
        lock.lock_exclusive()?;
        let mut state = state.clone();
        state.manual_refresh_pending = self
            .read_pending_triggers()?
            .causes
            .contains(&RefreshCause::Manual);
        self.write_state_unlocked(&state)
    }

    fn write_state_unlocked(&self, state: &StandbyRefreshState) -> Result<()> {
        let path = self.state_path();
        let temp = self
            .refresh_dir
            .join(format!(".state-{}.tmp", uuid::Uuid::new_v4()));
        let mut file = create_private_file(&temp).map_err(|error| error.source)?;
        file.write_all(&serde_jcs::to_vec(state)?)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)?;
        File::open(&self.refresh_dir)?.sync_all()?;
        Ok(())
    }

    fn record_active_candidate(
        &self,
        manifest: &StandbySnapshotManifest,
    ) -> std::result::Result<(), AttemptError> {
        let generation_id = hex::encode(Sha256::digest(manifest.canonical_json().map_err(
            |error| {
                AttemptError::new(
                    RefreshFailureClass::Verification,
                    "hosted snapshot manifest failed validation",
                    error,
                )
            },
        )?));
        let mut state = self.state().map_err(local_io)?;
        state.active_candidate_generation_id = Some(generation_id);
        state.active_candidate_captured_at = Some(manifest.captured_at.clone());
        state.active_candidate_completed_at = Some(manifest.snapshot_completed_at.clone());
        state.active_candidate_frontier = Some(manifest.frontier.clone());
        self.write_state(&state).map_err(local_io)
    }

    fn recover_interrupted_state_if_idle(&self) -> Result<()> {
        let attempt = open_private_lock(&self.refresh_dir.join("attempt.lock"))?;
        match attempt.try_lock_exclusive() {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        self.reset_invalid_pending_triggers()?;
        let mut state = match self.state() {
            Ok(state) => state,
            Err(_) => {
                let state = unreadable_state();
                self.write_state(&state)?;
                state
            }
        };
        if state.refresh_active {
            let promoted =
                state
                    .active_candidate_generation_id
                    .as_deref()
                    .is_some_and(|candidate| {
                        self.current_generation_id().as_deref() == Some(candidate)
                    });
            state.refresh_active = false;
            if promoted {
                state.last_success_at = Some(now());
                state.installed_generation_id = state.active_candidate_generation_id.clone();
                state.snapshot_captured_at = state.active_candidate_captured_at.clone();
                state.snapshot_completed_at = state.active_candidate_completed_at.clone();
                state.promoted_at = None;
                state.frontier = state.active_candidate_frontier.clone();
                state.consecutive_failure_count = 0;
                state.last_failure_class = None;
                state.last_failure = None;
            } else {
                state.consecutive_failure_count = state.consecutive_failure_count.saturating_add(1);
                state.last_failure_class = Some(RefreshFailureClass::LocalIo);
                state.last_failure = Some("previous standby refresh was interrupted".into());
            }
            state.active_candidate_generation_id = None;
            state.active_candidate_captured_at = None;
            state.active_candidate_completed_at = None;
            state.active_candidate_frontier = None;
            self.write_state(&state)?;
        }
        self.cleanup_interrupted_staging()?;
        Ok(())
    }

    fn reset_invalid_pending_triggers(&self) -> Result<()> {
        let lock = open_private_lock(&self.refresh_dir.join("trigger.lock"))?;
        lock.lock_exclusive()?;
        if self.read_pending_triggers().is_err() {
            match fs::remove_file(self.pending_marker_path()) {
                Ok(()) => File::open(&self.refresh_dir)?.sync_all()?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn current_generation_id(&self) -> Option<String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Pointer {
            contract: String,
            version: u32,
            generation_id: String,
            snapshot_sha256: String,
        }
        let path = self.runtime.replica_root.join("accepted/current.json");
        let pointer: Pointer = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
        let _ = pointer.snapshot_sha256;
        (pointer.contract == "native.standby-current-pointer.v1"
            && pointer.version == 1
            && pointer.generation_id.len() == 64)
            .then_some(pointer.generation_id)
    }

    fn cleanup_interrupted_staging(&self) -> Result<()> {
        let staging = self.store.staging_dir();
        for entry in fs::read_dir(&staging)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(rest) = name.strip_prefix("refresh-") else {
                continue;
            };
            let id = rest
                .strip_suffix(".snapshot.db")
                .or_else(|| rest.strip_suffix(".manifest.json"));
            if id.is_none_or(|id| uuid::Uuid::parse_str(id).is_err()) {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.is_file() || metadata.file_type().is_symlink() {
                fs::remove_file(entry.path())?;
            }
        }
        File::open(staging)?.sync_all()?;
        Ok(())
    }
}

#[derive(Clone)]
struct SnapshotPageRequest {
    export_id: Option<String>,
    offset: u64,
    length: usize,
    standby_consumer: Option<StandbyConsumerIdentity>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotPage {
    export_id: String,
    file_name: String,
    media_type: String,
    size_bytes: u64,
    sha256: String,
    offset: u64,
    length: usize,
    eof: bool,
    data_base64: String,
    #[serde(rename = "expires_in_seconds")]
    _expires_in_seconds: u64,
    manifest: Option<StandbySnapshotManifest>,
    /// The executor surface annotates every result with run correlation. It is
    /// not snapshot evidence, but `deny_unknown_fields` must still admit it or
    /// no page from a real deployment parses at all.
    #[serde(default, rename = "run_context")]
    _run_context: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcEnvelope {
    jsonrpc: String,
    id: Value,
    result: Option<RpcToolResult>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcToolResult {
    #[serde(rename = "content")]
    _content: Vec<Value>,
    #[serde(rename = "structuredContent")]
    structured_content: Option<SnapshotPage>,
    #[serde(rename = "isError")]
    is_error: bool,
    #[serde(default, rename = "resultType")]
    result_type: Option<String>,
    #[serde(default, rename = "_meta")]
    _meta: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcError {
    code: i64,
    #[serde(rename = "message")]
    _message: String,
    #[serde(default)]
    _data: Value,
}

/// Hosted Native serves the executor surface: snapshot pages are reached
/// through the `export` executor with an explicit operation, not through a
/// flat `export_snapshot` tool. The flat form is the legacy surface and is not
/// served by any current deployment.
const EXPORT_EXECUTOR: &str = "export";
const EXPORT_OPERATION: &str = "export_snapshot";

fn modern_export_call(request: &SnapshotPageRequest) -> Value {
    let mut arguments = json!({
        "offset": request.offset,
        "length": request.length,
    });
    if let Some(export_id) = &request.export_id {
        arguments["export_id"] = json!(export_id);
    }
    if let Some(consumer) = &request.standby_consumer {
        arguments["standby_consumer"] = json!(consumer);
    }
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": EXPORT_EXECUTOR,
            "arguments": {
                "operation": EXPORT_OPERATION,
                "arguments": arguments,
            },
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientInfo": {
                    "name": "native-standby-refresh",
                    "version": crate::engine_version_string(),
                },
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        }
    })
}

fn validate_page(
    page: &SnapshotPage,
    export_id: Option<&str>,
    offset: u64,
    size: Option<u64>,
    sha256: Option<&str>,
    manifest: Option<&StandbySnapshotManifest>,
) -> std::result::Result<(), AttemptError> {
    let valid_sha = page.sha256.len() == 64
        && page
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    if page.export_id.is_empty()
        || page.file_name != "native-ce-export.db"
        || page.media_type != STANDBY_SNAPSHOT_MEDIA_TYPE
        || page.size_bytes == 0
        || !valid_sha
        || page.offset != offset
        || page.length == 0
        || page.length > MAX_PAGE_BYTES
        || export_id.is_some_and(|expected| expected != page.export_id)
        || size.is_some_and(|expected| expected != page.size_bytes)
        || sha256.is_some_and(|expected| expected != page.sha256)
        || manifest.is_some_and(|expected| page.manifest.as_ref() != Some(expected))
        || page
            .offset
            .checked_add(page.length as u64)
            .is_none_or(|end| end > page.size_bytes || page.eof != (end == page.size_bytes))
    {
        return Err(integrity(
            "hosted snapshot page sequence was inconsistent",
            Error::engine("inconsistent snapshot page"),
        ));
    }
    if page.manifest.as_ref().is_none_or(|value| {
        value.snapshot.size_bytes != page.size_bytes || value.snapshot.sha256 != page.sha256
    }) {
        return Err(integrity(
            "hosted snapshot manifest did not bind the transferred bytes",
            Error::engine("snapshot manifest identity mismatch"),
        ));
    }
    Ok(())
}

fn validate_exact_origin(raw: &str) -> Result<()> {
    let url = url::Url::parse(raw)
        .map_err(|_| Error::engine("standby hosted_origin must be an exact URL origin"))?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(name)) => name == "localhost",
        None => false,
    };
    let allowed_scheme = url.scheme() == "https" || (url.scheme() == "http" && loopback);
    if !allowed_scheme
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.origin().ascii_serialization() != raw
    {
        return Err(Error::engine(
            "standby hosted_origin must be an exact HTTPS origin (or HTTP loopback) without credentials, path, query, or fragment",
        ));
    }
    Ok(())
}

fn validate_credential_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(Error::engine("standby credential_file must be absolute"));
    }
    let mut resolved = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => resolved.push(component.as_os_str()),
            Component::Normal(name) => {
                resolved.push(name);
                match fs::symlink_metadata(&resolved) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(Error::engine(
                            "standby credential_file must not traverse symbolic links",
                        ));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(Error::engine(
                    "standby credential_file must be lexically unambiguous",
                ));
            }
        }
    }
    Ok(())
}

fn read_credential(path: &Path) -> std::result::Result<String, AttemptError> {
    validate_credential_path(path).map_err(local_io)?;
    validate_credential_metadata(path).map_err(local_io)?;
    let before = fs::metadata(path).map_err(|error| local_io(error.into()))?;
    let file = File::open(path).map_err(|error| local_io(error.into()))?;
    let opened = file.metadata().map_err(|error| local_io(error.into()))?;
    let after = fs::symlink_metadata(path).map_err(|error| local_io(error.into()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != opened.dev()
            || before.ino() != opened.ino()
            || opened.dev() != after.dev()
            || opened.ino() != after.ino()
            || after.file_type().is_symlink()
        {
            return Err(local_io(Error::engine(
                "standby credential file changed while opening",
            )));
        }
    }
    let mut bytes = Vec::new();
    file.take((MAX_CREDENTIAL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| local_io(error.into()))?;
    if bytes.len() > MAX_CREDENTIAL_BYTES {
        return Err(local_io(Error::engine(
            "standby credential exceeded its bound",
        )));
    }
    let token = std::str::from_utf8(&bytes)
        .map_err(|_| local_io(Error::engine("standby credential is not UTF-8")))?
        .trim_end_matches(['\r', '\n']);
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        return Err(local_io(Error::engine(
            "standby credential is empty or contains whitespace",
        )));
    }
    Ok(token.to_string())
}

fn validate_credential_metadata(path: &Path) -> Result<()> {
    require_regular_file(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let metadata = fs::metadata(path)?;
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(Error::engine(
                "standby credential file is not owner-only or is hard-linked",
            ));
        }
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::engine("standby refresh path is not a directory"));
    }
    set_mode(path, 0o700)
}

fn create_private_file(path: &Path) -> std::result::Result<File, AttemptError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|error| local_io(error.into()))?;
    set_mode(path, 0o600).map_err(local_io)?;
    Ok(file)
}

fn open_private_lock(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(0x20_000); // O_NOFOLLOW
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(Error::engine(
            "standby refresh lock is not a regular non-symlink file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let opened = file.metadata()?;
        if opened.nlink() != 1
            || opened.dev() != path_metadata.dev()
            || opened.ino() != path_metadata.ino()
        {
            return Err(Error::engine(
                "standby refresh lock is hard-linked or changed during open",
            ));
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn require_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::engine(
            "standby refresh path is not a regular non-symlink file",
        ));
    }
    Ok(())
}

fn remove_owned_staging_file(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                let _ = File::open(parent).and_then(|file| file.sync_all());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {}
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

fn integrity(safe_message: &'static str, source: Error) -> AttemptError {
    AttemptError::new(RefreshFailureClass::DownloadIntegrity, safe_message, source)
}

fn local_io(source: Error) -> AttemptError {
    AttemptError::new(
        RefreshFailureClass::LocalIo,
        "local standby refresh storage failed",
        source,
    )
}

fn classify_install_error(source: Error) -> AttemptError {
    let (class, message) = match &source {
        Error::Io(_) => (
            RefreshFailureClass::LocalIo,
            "local standby refresh storage failed",
        ),
        Error::Engine(message)
            if [
                "route",
                "origin",
                "consumer",
                "schema",
                "DDL",
                "rollback",
                "successor",
                "platform",
                "source SHA",
                "artifact",
            ]
            .iter()
            .any(|needle| message.contains(needle)) =>
        {
            (
                RefreshFailureClass::Compatibility,
                "downloaded snapshot was incompatible with this standby",
            )
        }
        _ => (
            RefreshFailureClass::Verification,
            "downloaded snapshot was not admitted",
        ),
    };
    AttemptError::new(class, message, source)
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn unreadable_state() -> StandbyRefreshState {
    StandbyRefreshState {
        consecutive_failure_count: 1,
        last_failure_class: Some(RefreshFailureClass::LocalIo),
        last_failure: Some("standby refresh state was unreadable and reset".into()),
        ..StandbyRefreshState::default()
    }
}

fn elapsed_indicates_wake(wall: Duration, monotonic: Duration) -> bool {
    wall > monotonic.saturating_add(WAKE_DETECTION_SLOP)
}

fn next_scheduled_deadline(
    scheduled: tokio::time::Instant,
    attempt_started: tokio::time::Instant,
    completed: tokio::time::Instant,
    cause: RefreshCause,
) -> tokio::time::Instant {
    if cause == RefreshCause::Scheduled {
        let next = scheduled + SCHEDULE_INTERVAL;
        if attempt_started.saturating_duration_since(scheduled) >= SCHEDULE_INTERVAL
            || next <= completed
        {
            completed + SCHEDULE_INTERVAL
        } else {
            next
        }
    } else if scheduled <= completed {
        // A non-cadence acquisition also represents a cadence that became due
        // before it completed.
        completed + SCHEDULE_INTERVAL
    } else {
        scheduled
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::*;
    use crate::standby_snapshot::{
        HostedStandbyManifestContext, ProducerBuildIdentity, StandbyConsumerPlatform,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    struct AlwaysFailClient {
        class: RefreshFailureClass,
        calls: AtomicUsize,
    }

    impl SnapshotPageClient for AlwaysFailClient {
        fn page(
            &self,
            _endpoint: String,
            _bearer: String,
            _request: SnapshotPageRequest,
        ) -> PageFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let class = self.class;
            Box::pin(async move {
                Err(AttemptError::new(
                    class,
                    "injected refresh failure",
                    Error::engine("injected refresh failure"),
                ))
            })
        }
    }

    enum ScriptedReply {
        Page(Box<SnapshotPage>),
        Failure(RefreshFailureClass),
    }

    struct ScriptedClient {
        replies: Mutex<VecDeque<ScriptedReply>>,
        calls: AtomicUsize,
    }

    impl ScriptedClient {
        fn new(replies: impl IntoIterator<Item = ScriptedReply>) -> Self {
            Self {
                replies: Mutex::new(replies.into_iter().collect()),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl SnapshotPageClient for ScriptedClient {
        fn page(
            &self,
            endpoint: String,
            bearer: String,
            request: SnapshotPageRequest,
        ) -> PageFuture {
            assert_eq!(endpoint, "http://localhost/mcp/route%2D1");
            assert_eq!(bearer, "secret");
            assert_eq!(request.length, MAX_PAGE_BYTES);
            self.calls.fetch_add(1, Ordering::SeqCst);
            let reply = self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted refresh request");
            Box::pin(async move {
                match reply {
                    ScriptedReply::Page(page) => {
                        assert_eq!(request.offset, page.offset);
                        if page.offset == 0 {
                            assert!(request.export_id.is_none());
                            assert!(request.standby_consumer.is_some());
                        } else {
                            assert_eq!(request.export_id.as_deref(), Some(page.export_id.as_str()));
                            assert!(request.standby_consumer.is_none());
                        }
                        Ok(*page)
                    }
                    ScriptedReply::Failure(class) => Err(AttemptError::new(
                        class,
                        "injected refresh failure",
                        Error::engine("injected refresh failure"),
                    )),
                }
            })
        }
    }

    fn observed() -> ObservedInstalledConsumerIdentity {
        ObservedInstalledConsumerIdentity {
            platform: StandbyConsumerPlatform::LinuxX8664,
            source_sha: "1".repeat(40),
            artifact_sha256: "2".repeat(64),
            engine_schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
            ddl_sha256: crate::schema::FROZEN_DDL_SHA256.into(),
        }
    }

    fn consumer() -> StandbyConsumerIdentity {
        let observed = observed();
        StandbyConsumerIdentity {
            contract: STANDBY_CONSUMER_CONTRACT.into(),
            version: 1,
            platform: observed.platform,
            source_sha: observed.source_sha,
            artifact_sha256: observed.artifact_sha256,
            engine_schema_version: observed.engine_schema_version,
            ddl_sha256: observed.ddl_sha256,
        }
    }

    async fn snapshot_fixture(db: &crate::Db) -> (Vec<u8>, StandbySnapshotManifest) {
        let export = crate::export::export_connected_db(db, None).await.unwrap();
        let bytes = fs::read(export.path()).unwrap();
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let manifest = crate::standby_snapshot::manifest_from_completed_export(
            &export.path(),
            bytes.len() as u64,
            sha256,
            export.captured_at().into(),
            export.snapshot_completed_at().into(),
            HostedStandbyManifestContext::new_with_producer(
                "route-1".into(),
                consumer(),
                ProducerBuildIdentity::new("a".repeat(40), crate::schema::FROZEN_DDL_SHA256.into())
                    .unwrap(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        export.cleanup().await;
        (bytes, manifest)
    }

    fn paged_replies(
        export_id: &str,
        bytes: &[u8],
        manifest: &StandbySnapshotManifest,
    ) -> Vec<ScriptedReply> {
        bytes
            .chunks(MAX_PAGE_BYTES)
            .scan(0_u64, |offset, chunk| {
                let page_offset = *offset;
                *offset += chunk.len() as u64;
                Some(ScriptedReply::Page(Box::new(SnapshotPage {
                    export_id: export_id.into(),
                    file_name: "native-ce-export.db".into(),
                    media_type: STANDBY_SNAPSHOT_MEDIA_TYPE.into(),
                    size_bytes: bytes.len() as u64,
                    sha256: manifest.snapshot.sha256.clone(),
                    offset: page_offset,
                    length: chunk.len(),
                    eof: *offset == bytes.len() as u64,
                    data_base64: base64::engine::general_purpose::STANDARD.encode(chunk),
                    _expires_in_seconds: 30,
                    manifest: Some(manifest.clone()),
                    _run_context: Value::Null,
                })))
            })
            .collect()
    }

    fn controller_for_origin(
        directory: &tempfile::TempDir,
        origin: String,
        client: Arc<dyn SnapshotPageClient>,
    ) -> StandbyRefreshController {
        let replica_root = directory.path().join("replica");
        let credential = directory.path().join("credential");
        fs::write(&credential, b"secret\n").unwrap();
        set_mode(&credential, 0o600).unwrap();
        let runtime = StandbyRuntimeConfig {
            replica_root: replica_root.clone(),
            hosted_route_database_id: "route-1".into(),
            origin_database_id: origin.clone(),
        };
        let config = StandbyRefreshConfig {
            contract: CONFIG_CONTRACT.into(),
            version: 1,
            hosted_origin: "http://localhost".into(),
            credential_file: credential,
        };
        let store = GenerationStore::open(&replica_root, "route-1", Some(origin)).unwrap();
        StandbyRefreshController::new_with_client(runtime, config, store, observed(), client)
            .unwrap()
    }

    async fn read_http_request(stream: &mut TcpStream) -> (String, Value) {
        let mut bytes = Vec::new();
        let header_end = loop {
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
            let mut chunk = [0_u8; 2048];
            let read = stream.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0, "HTTP request ended before its headers");
            bytes.extend_from_slice(&chunk[..read]);
        };
        let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        while bytes.len() < header_end + content_length {
            let mut chunk = [0_u8; 2048];
            let read = stream.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0, "HTTP request ended before its body");
            bytes.extend_from_slice(&chunk[..read]);
        }
        let body = serde_json::from_slice(&bytes[header_end..header_end + content_length]).unwrap();
        (headers, body)
    }

    async fn write_json_response(stream: &mut TcpStream, status: &str, body: &Value) {
        let body = serde_json::to_vec(body).unwrap();
        let head = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        stream.shutdown().await.unwrap();
    }

    fn controller_with_client(
        client: Arc<dyn SnapshotPageClient>,
    ) -> (tempfile::TempDir, StandbyRefreshController) {
        let directory = tempfile::tempdir().unwrap();
        let replica_root = directory.path().join("replica");
        let credential = directory.path().join("credential");
        fs::write(&credential, b"secret\n").unwrap();
        set_mode(&credential, 0o600).unwrap();
        let runtime = StandbyRuntimeConfig {
            replica_root: replica_root.clone(),
            hosted_route_database_id: "route-1".into(),
            origin_database_id: "ndb_0123456789abcdef0123456789abcdef".into(),
        };
        let config = StandbyRefreshConfig {
            contract: CONFIG_CONTRACT.into(),
            version: 1,
            hosted_origin: "http://localhost".into(),
            credential_file: credential,
        };
        let store = GenerationStore::open(
            &replica_root,
            &runtime.hosted_route_database_id,
            Some(runtime.origin_database_id.clone()),
        )
        .unwrap();
        let observed = ObservedInstalledConsumerIdentity {
            platform: crate::standby_snapshot::StandbyConsumerPlatform::LinuxX8664,
            source_sha: "1".repeat(40),
            artifact_sha256: "2".repeat(64),
            engine_schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
            ddl_sha256: crate::schema::FROZEN_DDL_SHA256.into(),
        };
        let controller =
            StandbyRefreshController::new_with_client(runtime, config, store, observed, client)
                .unwrap();
        (directory, controller)
    }

    #[test]
    fn refresh_config_is_strict_and_keeps_credentials_out_of_json() {
        let dir = tempfile::tempdir().unwrap();
        let credential = dir.path().join("credential");
        fs::write(&credential, b"secret\n").unwrap();
        set_mode(&credential, 0o600).unwrap();
        let config = StandbyRefreshConfig::from_json(
            &serde_json::to_vec(&json!({
                "contract": CONFIG_CONTRACT,
                "version": 1,
                "hosted_origin": "https://plugin.withnative.ai",
                "credential_file": credential,
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(config.hosted_origin, "https://plugin.withnative.ai");

        assert!(StandbyRefreshConfig::from_json(
            &serde_json::to_vec(&json!({
                "contract": CONFIG_CONTRACT,
                "version": 1,
                "hosted_origin": "http://example.com",
                "credential_file": config.credential_file,
            }))
            .unwrap()
        )
        .is_err());
        assert!(StandbyRefreshConfig::from_json(
            br#"{"contract":"native.standby-refresh-config.v1","version":1,"hosted_origin":"https://plugin.withnative.ai","credential_file":"relative","token":"nope"}"#
        )
        .is_err());
    }

    #[test]
    fn manual_requests_are_durable_and_coalesced() {
        let client = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Authentication,
            calls: AtomicUsize::new(0),
        });
        let (_directory, controller) = controller_with_client(client);
        assert!(controller.request_manual_refresh().unwrap());
        assert!(!controller.request_manual_refresh().unwrap());
        assert!(controller.state().unwrap().manual_refresh_pending);
    }

    #[test]
    fn all_trigger_causes_coalesce_durably_and_consumption_updates_state() {
        let client = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Authentication,
            calls: AtomicUsize::new(0),
        });
        let (_directory, controller) = controller_with_client(client);
        assert!(controller.request_refresh(RefreshCause::Wake).unwrap());
        assert!(!controller.request_refresh(RefreshCause::Wake).unwrap());
        assert!(controller
            .request_refresh(RefreshCause::AfterAdmittedWrite)
            .unwrap());
        assert!(controller.request_manual_refresh().unwrap());
        assert!(controller.state().unwrap().manual_refresh_pending);

        let pending = controller.take_pending_triggers().unwrap();
        assert_eq!(pending.len(), 3);
        assert!(pending.contains(&RefreshCause::Wake));
        assert!(pending.contains(&RefreshCause::AfterAdmittedWrite));
        assert!(pending.contains(&RefreshCause::Manual));
        assert!(!controller.state().unwrap().manual_refresh_pending);
        let raw: StandbyRefreshState =
            serde_json::from_slice(&fs::read(controller.state_path()).unwrap()).unwrap();
        assert!(!raw.manual_refresh_pending);
    }

    #[test]
    fn wake_and_cadence_helpers_coalesce_without_catch_up_bursts() {
        assert!(elapsed_indicates_wake(
            Duration::from_secs(30),
            Duration::from_secs(1)
        ));
        assert!(!elapsed_indicates_wake(
            Duration::from_secs(2),
            Duration::from_secs(1)
        ));

        let now = tokio::time::Instant::now();
        let badly_overdue = now - SCHEDULE_INTERVAL - Duration::from_secs(1);
        assert_eq!(
            next_scheduled_deadline(badly_overdue, now, now, RefreshCause::Scheduled),
            now + SCHEDULE_INTERVAL
        );
        let on_time = now + Duration::from_secs(1);
        let long_completion = on_time + SCHEDULE_INTERVAL + Duration::from_secs(1);
        assert_eq!(
            next_scheduled_deadline(on_time, on_time, long_completion, RefreshCause::Scheduled),
            long_completion + SCHEDULE_INTERVAL
        );
        let due_during_manual = now + Duration::from_secs(5);
        let completed = now + Duration::from_secs(10);
        assert_eq!(
            next_scheduled_deadline(due_during_manual, now, completed, RefreshCause::Manual),
            completed + SCHEDULE_INTERVAL
        );
        let future = now + SCHEDULE_INTERVAL;
        assert_eq!(
            next_scheduled_deadline(future, now, now, RefreshCause::Wake),
            future
        );
    }

    #[test]
    fn missing_credential_does_not_disable_controller_construction() {
        let directory = tempfile::tempdir().unwrap();
        let replica_root = directory.path().join("replica");
        let runtime = StandbyRuntimeConfig {
            replica_root: replica_root.clone(),
            hosted_route_database_id: "route-1".into(),
            origin_database_id: "ndb_0123456789abcdef0123456789abcdef".into(),
        };
        let missing = directory.path().join("rotating-credential");
        let config = StandbyRefreshConfig {
            contract: CONFIG_CONTRACT.into(),
            version: 1,
            hosted_origin: "http://localhost".into(),
            credential_file: missing,
        };
        let store = GenerationStore::open(
            &replica_root,
            &runtime.hosted_route_database_id,
            Some(runtime.origin_database_id.clone()),
        )
        .unwrap();
        assert!(StandbyRefreshController::new(runtime, config, store, observed()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn refresh_locks_reject_symbolic_and_hard_links() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.lock");
        fs::write(&target, b"").unwrap();
        let hard = directory.path().join("hard.lock");
        fs::hard_link(&target, &hard).unwrap();
        assert!(open_private_lock(&hard).is_err());

        use std::os::unix::fs::symlink;
        let symbolic = directory.path().join("symbolic.lock");
        symlink(&target, &symbolic).unwrap();
        assert!(open_private_lock(&symbolic).is_err());
    }

    #[tokio::test]
    async fn refresh_installs_multipage_snapshot_and_recovers_after_bounded_failures() {
        let directory = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        crate::store::create_record(
            &db,
            json!({"type":"Document","kind":"note","name":"first refresh"}),
        )
        .await
        .unwrap();
        let (first_bytes, first_manifest) = snapshot_fixture(&db).await;

        crate::store::create_record(
            &db,
            json!({"type":"Document","kind":"note","name":"recovered refresh"}),
        )
        .await
        .unwrap();
        let (second_bytes, second_manifest) = snapshot_fixture(&db).await;

        let mut replies = paged_replies("export-first", &first_bytes, &first_manifest);
        let first_page_count = replies.len();
        replies.push(ScriptedReply::Failure(RefreshFailureClass::Authentication));
        replies.push(ScriptedReply::Failure(RefreshFailureClass::Authentication));
        let recovered_replies = paged_replies("export-recovered", &second_bytes, &second_manifest);
        let recovered_page_count = recovered_replies.len();
        replies.extend(recovered_replies);
        let client = Arc::new(ScriptedClient::new(replies));
        let controller = controller_for_origin(&directory, origin, client.clone());
        let accepted = directory.path().join("replica/accepted");

        assert!(controller.request_manual_refresh().unwrap());
        let installed = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap();
        let StandbyRefreshOutcome::Installed {
            generation: first, ..
        } = installed
        else {
            panic!("startup refresh must install its snapshot")
        };
        assert_eq!(fs::read(&first.snapshot_path).unwrap(), first_bytes);
        let first_pointer = fs::read(accepted.join("current.json")).unwrap();
        let first_pointer_json: Value = serde_json::from_slice(&first_pointer).unwrap();
        assert_eq!(first_pointer_json["generation_id"], first.id);
        let first_state = controller.state().unwrap();
        assert_eq!(
            first_state.installed_generation_id.as_deref(),
            Some(first.id.as_str())
        );
        assert_eq!(
            first_state.snapshot_captured_at,
            Some(first_manifest.captured_at.clone())
        );
        assert_eq!(
            first_state.snapshot_completed_at,
            Some(first_manifest.snapshot_completed_at.clone())
        );
        assert_eq!(first_state.frontier, Some(first_manifest.frontier.clone()));
        assert_eq!(first_state.consecutive_failure_count, 0);
        assert_eq!(first_state.last_attempt_cause, Some(RefreshCause::Startup));
        assert!(!first_state.manual_refresh_pending);
        assert!(!first_state.refresh_active);
        assert!(first_state.last_attempt_at.is_some());
        assert!(first_state.last_success_at.is_some());
        assert!(first_state.promoted_at.is_some());

        // Simulate a crash after GenerationStore made current durable but
        // before the refresh success projection was finalized.
        let mut interrupted = first_state.clone();
        interrupted.refresh_active = true;
        interrupted.last_success_at = None;
        interrupted.installed_generation_id = None;
        interrupted.snapshot_captured_at = None;
        interrupted.snapshot_completed_at = None;
        interrupted.promoted_at = None;
        interrupted.frontier = None;
        interrupted.active_candidate_generation_id = Some(first.id.clone());
        interrupted.active_candidate_captured_at = Some(first_manifest.captured_at.clone());
        interrupted.active_candidate_completed_at =
            Some(first_manifest.snapshot_completed_at.clone());
        interrupted.active_candidate_frontier = Some(first_manifest.frontier.clone());
        controller.write_state(&interrupted).unwrap();
        controller.recover_interrupted_state_if_idle().unwrap();
        let reconciled = controller.state().unwrap();
        assert_eq!(
            reconciled.installed_generation_id.as_deref(),
            Some(first.id.as_str())
        );
        assert_eq!(reconciled.frontier, Some(first_manifest.frontier.clone()));
        assert_eq!(reconciled.consecutive_failure_count, 0);
        assert_eq!(reconciled.last_failure_class, None);
        assert_eq!(reconciled.promoted_at, None);

        for expected_count in [1, 2] {
            assert!(controller
                .refresh_once(RefreshCause::Scheduled)
                .await
                .is_err());
            assert_eq!(
                fs::read(accepted.join("current.json")).unwrap(),
                first_pointer
            );
            assert_eq!(fs::read(&first.snapshot_path).unwrap(), first_bytes);
            let failed = controller.state().unwrap();
            assert_eq!(failed.consecutive_failure_count, expected_count);
            assert_eq!(
                failed.last_failure_class,
                Some(RefreshFailureClass::Authentication)
            );
            assert_eq!(
                failed.installed_generation_id.as_deref(),
                Some(first.id.as_str())
            );
            assert_eq!(failed.frontier, Some(first_manifest.frontier.clone()));
        }

        let recovered = controller
            .refresh_once(RefreshCause::NetworkRecovery)
            .await
            .unwrap();
        let StandbyRefreshOutcome::Installed {
            generation: recovered,
            ..
        } = recovered
        else {
            panic!("healthy retry must install its snapshot")
        };
        assert_ne!(recovered.id, first.id);
        assert_eq!(fs::read(&recovered.snapshot_path).unwrap(), second_bytes);
        assert_ne!(
            fs::read(accepted.join("current.json")).unwrap(),
            first_pointer
        );
        let recovered_pointer: Value =
            serde_json::from_slice(&fs::read(accepted.join("current.json")).unwrap()).unwrap();
        assert_eq!(recovered_pointer["generation_id"], recovered.id);
        let recovered_state = controller.state().unwrap();
        assert_eq!(
            recovered_state.installed_generation_id.as_deref(),
            Some(recovered.id.as_str())
        );
        assert_eq!(recovered_state.frontier, Some(second_manifest.frontier));
        assert_eq!(recovered_state.consecutive_failure_count, 0);
        assert_eq!(
            recovered_state.last_attempt_cause,
            Some(RefreshCause::NetworkRecovery)
        );
        assert!(!recovered_state.refresh_active);
        assert_eq!(recovered_state.last_failure_class, None);
        assert_eq!(recovered_state.last_failure, None);
        assert_eq!(
            client.calls.load(Ordering::SeqCst),
            first_page_count + 2 + recovered_page_count
        );
        assert!(client.replies.lock().unwrap().is_empty());
        db.close().await;
    }

    #[tokio::test]
    async fn http_page_client_sends_the_scoped_modern_contract_and_parses_pages() {
        let manifest: StandbySnapshotManifest = serde_json::from_value(json!({
            "contract":"native.standby-snapshot-manifest.v1","version":1,
            "hosted_route_database_id":"route-1","origin_database_id":"ndb_0123456789abcdef0123456789abcdef",
            "captured_at":"2026-09-02T00:00:00Z","snapshot_completed_at":"2026-09-02T00:00:01Z",
            "engine":{"name":crate::ENGINE_NAME,"source_sha":"1".repeat(40),"schema_version":crate::CURRENT_ENGINE_SCHEMA_VERSION,"ddl_sha256":crate::schema::FROZEN_DDL_SHA256},
            "consumer":{"contract":STANDBY_CONSUMER_CONTRACT,"version":1,"platform":"linux-x86_64","source_sha":"1".repeat(40),"artifact_sha256":"2".repeat(64),"engine_schema_version":crate::CURRENT_ENGINE_SCHEMA_VERSION,"ddl_sha256":crate::schema::FROZEN_DDL_SHA256},
            "frontier":{"contract":"native.canonical-frontier.v1","version":1,"content_event_seq":0,"policy_event_seq":0,"awareness_event_seq":0,"notification_candidate_event_seq":0,"binding_audit_seq":0,"database_identity_audit_seq":0,"meta_event_seq":0,"control_event_seq":0,"derivation_event_seq":0,"relationship_event_seq":0,"authorization_revision_epoch":0,"storage_portability_policy_revision":0},
            "snapshot":{"media_type":STANDBY_SNAPSHOT_MEDIA_TYPE,"size_bytes":2,"sha256":"a".repeat(64)}
        })).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let served_manifest = manifest.clone();
        let server = tokio::spawn(async move {
            for (ordinal, (offset, eof, data)) in [(0_u64, false, "eA=="), (1_u64, true, "eQ==")]
                .into_iter()
                .enumerate()
            {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (headers, body) = read_http_request(&mut stream).await;
                let lower = headers.to_ascii_lowercase();
                assert!(lower.starts_with("post /mcp/route%2d1 http/1.1\r\n"));
                assert!(lower.contains("authorization: bearer wire-secret\r\n"));
                assert!(lower.contains("content-type: application/json\r\n"));
                assert!(lower.contains("accept: application/json, text/event-stream\r\n"));
                assert!(lower.contains("mcp-protocol-version: 2026-07-28\r\n"));
                assert!(lower.contains("mcp-method: tools/call\r\n"));
                assert!(lower.contains("mcp-name: export\r\n"));
                assert_eq!(body["jsonrpc"], "2.0");
                assert_eq!(body["id"], 1);
                assert_eq!(body["method"], "tools/call");
                assert_eq!(body["params"]["name"], "export");
                assert_eq!(body["params"]["arguments"]["operation"], "export_snapshot");
                assert_eq!(
                    body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
                    PROTOCOL_VERSION
                );
                assert!(
                    body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]
                        .is_object()
                );
                assert_eq!(body["params"]["arguments"]["arguments"]["offset"], offset);
                if ordinal == 0 {
                    assert!(body["params"]["arguments"]["arguments"]
                        .as_object()
                        .unwrap()
                        .get("export_id")
                        .is_none());
                    assert_eq!(
                        body["params"]["arguments"]["arguments"]["standby_consumer"]
                            ["artifact_sha256"],
                        "2".repeat(64)
                    );
                } else {
                    assert_eq!(
                        body["params"]["arguments"]["arguments"]["export_id"],
                        "export-wire"
                    );
                    assert!(body["params"]["arguments"]["arguments"]
                        .as_object()
                        .unwrap()
                        .get("standby_consumer")
                        .is_none());
                }
                let page = json!({
                    "export_id":"export-wire",
                    "file_name":"native-ce-export.db",
                    "media_type":STANDBY_SNAPSHOT_MEDIA_TYPE,
                    "size_bytes":2,
                    "sha256":"a".repeat(64),
                    "offset":offset,
                    "length":1,
                    "eof":eof,
                    "data_base64":data,
                    "expires_in_seconds":30,
                    "manifest":served_manifest,
                });
                write_json_response(
                    &mut stream,
                    "200 OK",
                    &json!({
                        "jsonrpc":"2.0",
                        "id":1,
                        "result":{
                            "content":[],
                            "structuredContent":page,
                            "isError":false,
                            "resultType":"complete",
                            "_meta":{}
                        }
                    }),
                )
                .await;
            }
        });

        let client = HttpSnapshotPageClient::new().unwrap();
        let endpoint = format!("http://{address}/mcp/route%2D1");
        let first = client
            .page(
                endpoint.clone(),
                "wire-secret".into(),
                SnapshotPageRequest {
                    export_id: None,
                    offset: 0,
                    length: MAX_PAGE_BYTES,
                    standby_consumer: Some(consumer()),
                },
            )
            .await
            .unwrap();
        assert_eq!(first.export_id, "export-wire");
        assert!(!first.eof);
        let second = client
            .page(
                endpoint,
                "wire-secret".into(),
                SnapshotPageRequest {
                    export_id: Some(first.export_id.clone()),
                    offset: 1,
                    length: MAX_PAGE_BYTES,
                    standby_consumer: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(second.offset, 1);
        assert!(second.eof);
        assert_eq!(second.manifest, Some(manifest));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_page_client_classifies_unauthorized_without_echoing_the_credential() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (headers, _) = read_http_request(&mut stream).await;
            assert!(headers
                .to_ascii_lowercase()
                .contains("authorization: bearer must-not-echo\r\n"));
            write_json_response(&mut stream, "401 Unauthorized", &json!({"error":"denied"})).await;
        });
        let client = HttpSnapshotPageClient::new().unwrap();
        let error = client
            .page(
                format!("http://{address}/mcp/route"),
                "must-not-echo".into(),
                SnapshotPageRequest {
                    export_id: None,
                    offset: 0,
                    length: MAX_PAGE_BYTES,
                    standby_consumer: Some(consumer()),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.class, RefreshFailureClass::Authentication);
        assert!(!error.safe_message.contains("must-not-echo"));
        assert!(!error.source.to_string().contains("must-not-echo"));
        server.await.unwrap();
    }

    #[test]
    fn page_sequence_rejects_identity_and_offset_drift() {
        let manifest: StandbySnapshotManifest = serde_json::from_value(json!({
            "contract":"native.standby-snapshot-manifest.v1","version":1,
            "hosted_route_database_id":"route","origin_database_id":"ndb_0123456789abcdef0123456789abcdef",
            "captured_at":"2026-09-02T00:00:00Z","snapshot_completed_at":"2026-09-02T00:00:01Z",
            "engine":{"name":crate::ENGINE_NAME,"source_sha":"1".repeat(40),"schema_version":crate::CURRENT_ENGINE_SCHEMA_VERSION,"ddl_sha256":crate::schema::FROZEN_DDL_SHA256},
            "consumer":{"contract":STANDBY_CONSUMER_CONTRACT,"version":1,"platform":"linux-x86_64","source_sha":"1".repeat(40),"artifact_sha256":"2".repeat(64),"engine_schema_version":crate::CURRENT_ENGINE_SCHEMA_VERSION,"ddl_sha256":crate::schema::FROZEN_DDL_SHA256},
            "frontier":{"contract":"native.canonical-frontier.v1","version":1,"content_event_seq":0,"policy_event_seq":0,"awareness_event_seq":0,"notification_candidate_event_seq":0,"binding_audit_seq":0,"database_identity_audit_seq":0,"meta_event_seq":0,"control_event_seq":0,"derivation_event_seq":0,"relationship_event_seq":0,"authorization_revision_epoch":0,"storage_portability_policy_revision":0},
            "snapshot":{"media_type":STANDBY_SNAPSHOT_MEDIA_TYPE,"size_bytes":2,"sha256":"a".repeat(64)}
        })).unwrap();
        let page = SnapshotPage {
            export_id: "export".into(),
            file_name: "native-ce-export.db".into(),
            media_type: STANDBY_SNAPSHOT_MEDIA_TYPE.into(),
            size_bytes: 2,
            sha256: "a".repeat(64),
            offset: 0,
            length: 1,
            eof: false,
            data_base64: "eA==".into(),
            _expires_in_seconds: 30,
            manifest: Some(manifest),
            _run_context: Value::Null,
        };
        assert!(validate_page(&page, None, 0, None, None, None).is_ok());
        assert!(validate_page(
            &page,
            Some("export"),
            1,
            Some(2),
            Some(&"a".repeat(64)),
            page.manifest.as_ref()
        )
        .is_err());
    }

    #[tokio::test]
    async fn page_retry_is_bounded_and_network_only() {
        let network = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Network,
            calls: AtomicUsize::new(0),
        });
        let (_directory, controller) = controller_with_client(network.clone());
        let request = SnapshotPageRequest {
            export_id: Some("export".into()),
            offset: 7,
            length: MAX_PAGE_BYTES,
            standby_consumer: None,
        };
        assert!(controller
            .fetch_page_with_retry("http://localhost/mcp/route", "secret", request.clone())
            .await
            .is_err());
        assert_eq!(network.calls.load(Ordering::SeqCst), 3);

        let protocol = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });
        let (_directory, controller) = controller_with_client(protocol.clone());
        assert!(controller
            .fetch_page_with_retry("http://localhost/mcp/route", "secret", request)
            .await
            .is_err());
        assert_eq!(protocol.calls.load(Ordering::SeqCst), 1);
    }

    /// Drive the real executor surface rather than a hand-written fixture.
    ///
    /// The controller previously sent a flat `export_snapshot` tool call and
    /// parsed a response shape no deployment produces, yet every refresh test
    /// passed: the fixture answered whatever the controller happened to ask.
    /// This serves genuine `ExecutorPrototypeStdioServer` output over HTTP, so
    /// the executor envelope, the surface's `run_context` annotation and its
    /// optional `resultType` are proven against real dispatch code. A future
    /// change to any of the three breaks this test instead of only production.
    #[tokio::test]
    async fn page_client_parses_a_real_executor_surface_response() {
        use crate::mcp::{
            register_builtin_tools, register_snapshot_tool, register_surface_tools, Caller,
            ExecutorPrototypeStdioServer, ToolRegistry,
        };

        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("real-surface.db");
        let db = crate::create_database(database_path.to_str().unwrap())
            .await
            .unwrap();

        let mut registry = ToolRegistry::new();
        register_builtin_tools(&mut registry).unwrap();
        register_surface_tools(&mut registry).unwrap();
        register_snapshot_tool(
            &mut registry,
            Arc::new(crate::export::LocalSnapshotSource::new()),
        )
        .unwrap();
        let server = ExecutorPrototypeStdioServer::new(
            Arc::new(registry),
            db.clone(),
            Caller::authenticated("standby-refresh-real-surface"),
            None,
        )
        .await
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = format!("http://{address}/mcp/route");
        let served = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (_headers, request) = read_http_request(&mut stream).await;
            let response = server
                .handle_message(request)
                .await
                .expect("the executor surface must answer a tools/call");
            write_json_response(&mut stream, "200 OK", &response).await;
        });

        let page = HttpSnapshotPageClient::new()
            .unwrap()
            .page(
                endpoint,
                "test-credential".into(),
                SnapshotPageRequest {
                    export_id: None,
                    offset: 0,
                    length: MAX_PAGE_BYTES,
                    standby_consumer: None,
                },
            )
            .await
            .expect("a page from the real executor surface must parse");

        served.await.unwrap();
        assert!(
            !page.export_id.is_empty(),
            "real page must carry an export handle"
        );
        assert_eq!(page.offset, 0);
        assert_eq!(page.media_type, "application/vnd.sqlite3");
        assert!(page.size_bytes > 0);
        db.close().await;
    }
}
