//! Authenticated hosted act-delta refresh with whole-snapshot fallback.
//!
//! This is a controller kernel, not an MCP tool. It talks only to the hosted
//! MCP endpoint and the generation store; the local MCP surface stays read-only.
//!
//! A whole snapshot is acquired on first install and as the single fallback.
//! Its head act is the checkpoint. After it, each refresh probes the hosted act
//! head; an equal head is a no-op, and an advance fetches one authenticated
//! whole-act delta and applies it directly to the current generation inside one
//! SQLite write transaction, so readers see either the old state or the new
//! one. The copy trusts the authenticated server: there is no base re-proof,
//! clone, rehash or re-admission on this path. Any gap, identity or schema
//! mismatch, oversize cut or apply refusal rolls back and takes the snapshot
//! path; a failed fallback leaves the current copy serving.

use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::Write as _;
use std::path::{Path, PathBuf};
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
use tracing::Instrument as _;

use crate::error::{Error, Result};
use crate::standby_snapshot::{
    CanonicalFrontierV1, ObservedInstalledConsumerIdentity, StandbyConsumerIdentity,
    StandbySnapshotManifest, STANDBY_CONSUMER_CONTRACT, STANDBY_SNAPSHOT_MEDIA_TYPE,
};

use super::act_materialise::apply_authority_act_delta_and_finalize_head;
use super::authority_probe::read_authority_act_head_from_path;
use super::delta_transport::{AuthorityActTransport, MAINTENANCE_SNAPSHOT_ERROR};
use super::generation_store::DeltaDeferral;
#[cfg(any(test, feature = "v2-kernel-probe"))]
use super::phase_timings::PhaseTimings;
use super::{GenerationStore, InstalledGeneration, StandbyRuntimeConfig};

mod binary;

mod binary_resume;
mod binary_work;
mod shape_transition;
mod transfer_progress;
mod transfer_repr;
pub use transfer_progress::{
    StandbyTransferActivity, StandbyTransferProgress, StandbyTransferStage,
};

const STATE_CONTRACT: &str = "native.standby-refresh-state.v1";
pub(crate) const CONFIG_CONTRACT: &str = "native.standby-refresh-config.v1";
const PROTOCOL_VERSION: &str = "2026-07-28";
const MAX_PAGE_BYTES: usize = crate::mcp::SNAPSHOT_MAX_PAGE_BYTES;
// A complete MCP result carries the page in both text and structured content.
// One maximum-sized (512 KiB) page therefore expands to roughly 1.4 MiB after
// base64 and JSON framing.
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MANUAL_POLL_INTERVAL: Duration = Duration::from_secs(1);
// Export handles expire after five minutes. Leave time for state finalization
// and never splice a timed-out transfer into a new export.
// Allow the server's thirty-minute initial capture plus download and local
// verification. Subsequent refreshes still coalesce under the same controller.
pub(crate) const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(45 * 60);
pub(crate) const FOLLOW_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_FULL_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const DEFAULT_FULL_REFRESH_REPAIR_RETRY: Duration = Duration::from_secs(30 * 60);
const NETWORK_RECOVERY_PROBE_INTERVAL: Duration = Duration::from_secs(10);
const WAKE_DETECTION_SLOP: Duration = Duration::from_secs(5);
/// First retry after a busy hosted delta export: hosted asks for one second
/// via `Retry-After`; without it wait a few seconds. Consecutive busy
/// failures double toward the cap while the export plausibly still runs.
const EXPORT_BUSY_BASE_BACKOFF: Duration = Duration::from_secs(5);
const EXPORT_BUSY_MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Fixed receipt details for the two "hosted may still be exporting" signals:
/// a refused start while the account's export lease is held, and a poll this
/// node gave up on.
const EXPORT_BUSY_DETAIL: &str = "export_in_progress";
const EXPORT_CAPTURE_TIMEOUT_DETAIL: &str = "capture_timed_out";
/// Tracing target for the follow-loop scheduler's own observability: skipped
/// ticks, coalesced acquisitions, the per-deadline alive trace and the stall
/// WARN. Separate from the transport target so journal readers can isolate
/// scheduler health from attempt outcomes.
const FOLLOW_LOG_TARGET: &str = "native_ce::standby::follow";
/// A follow loop that starts no attempt for this many of its own cadences
/// while a scheduled deadline sits overdue owes a stall WARN. Five is far
/// outside healthy jitter (a tick is ~1 s, an attempt re-anchors the deadline
/// on completion) and far inside the incident window this was built for.
const STALL_WARN_INTERVAL_MULTIPLE: u32 = 5;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandbyRefreshConfig {
    pub contract: String,
    pub version: u32,
    pub hosted_origin: String,
    pub credential_file: PathBuf,
    /// Seconds between scheduled refreshes; defaults to
    /// [`super::STANDBY_REFRESH_INTERVAL_SECONDS`]. A no-change refresh is one
    /// cheap head probe, so a short interval does not load hosted Native.
    #[serde(default)]
    pub refresh_interval_seconds: Option<u64>,
    /// Minimum seconds between the starts of two whole-snapshot refreshes of
    /// an existing copy, except for consumer-change and audit repairs; defaults
    /// to six hours. A persistent fallback reason costs one full copy per
    /// interval, not one per tick. Zero disables the minimum.
    #[serde(default)]
    pub full_refresh_min_interval_seconds: Option<u64>,
    /// Minimum seconds before retrying a failed whole snapshot to repair a
    /// changed consumer or failed audit; defaults to thirty minutes, floored
    /// at sixty seconds and capped by full_refresh_min_interval_seconds (zero
    /// there disables the hold). Counted from the last FULL failure's end,
    /// falling back to its start if the failure end is unavailable.
    #[serde(default)]
    pub full_refresh_repair_retry_seconds: Option<u64>,
    /// Apply SMALL kernel-v2 deltas in place, in one WAL transaction on the
    /// serving database, instead of copying and republishing the whole file
    /// (epic c15a932). Off by default. Large deltas, gaps, identity or schema
    /// changes, periodic re-checkpoints and any copy not served by this build
    /// keep the staged path. Older builds refuse a config naming this field.
    #[serde(default)]
    pub kernel_in_place_deltas: bool,
    /// Seconds between required audits of a copy advanced in place (design
    /// record 5065900 §5, "N"); default 21,600 (six hours), bounds 60 to 86,400. Applies only
    /// while `kernel_in_place_deltas` is on. Online local reads are forwarded
    /// to hosted once the last successful audit is older than twice this.
    /// Older builds refuse a config naming this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_audit_interval_seconds: Option<u64>,
    /// Seconds between deltas that carry the full projection proof; default
    /// 1800, bounds 60 to 86,400. A host that offers wire version 3 cuts
    /// deltas WITHOUT that proof (it is most of a cut's cost), so at this
    /// interval, on the first follow after start, and right after any apply
    /// anomaly, the node asks for a delta with the proof instead and checks it
    /// the ordinary way. A divergence found that way takes the existing
    /// whole-snapshot repair. Reads are never held for it. Older builds refuse
    /// a config naming this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection_proof_interval_seconds: Option<u64>,
}

/// Bounds on [`StandbyRefreshConfig::projection_proof_interval_seconds`].
pub const MIN_PROJECTION_PROOF_INTERVAL_SECONDS: u64 = 60;
pub const MAX_PROJECTION_PROOF_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
pub const DEFAULT_PROJECTION_PROOF_INTERVAL_SECONDS: u64 = 30 * 60;

/// Bounds on [`StandbyRefreshConfig::kernel_audit_interval_seconds`].
pub const MIN_KERNEL_AUDIT_INTERVAL_SECONDS: u64 = 60;
pub const MAX_KERNEL_AUDIT_INTERVAL_SECONDS: u64 = 24 * 60 * 60;

impl StandbyRefreshConfig {
    /// Seconds between required audits, or `None` when none is required (the
    /// in-place flag is off).
    pub fn audit_interval(&self) -> Option<Duration> {
        #[cfg(any(test, feature = "v2-kernel-probe"))]
        {
            self.kernel_in_place_deltas.then(|| {
                Duration::from_secs(self.kernel_audit_interval_seconds.unwrap_or(
                    super::generation_store::kernel_in_place::audit::DEFAULT_AUDIT_INTERVAL_SECONDS,
                ))
            })
        }
        #[cfg(not(any(test, feature = "v2-kernel-probe")))]
        {
            None
        }
    }

    /// How long a proof-less (wire version 3) stretch may run before the next
    /// delta must carry the projection proof.
    pub fn projection_proof_interval(&self) -> Duration {
        Duration::from_secs(
            self.projection_proof_interval_seconds
                .unwrap_or(DEFAULT_PROJECTION_PROOF_INTERVAL_SECONDS),
        )
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let config: Self = serde_json::from_slice(bytes)
            .map_err(|_| Error::engine("invalid standby refresh config"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.contract != CONFIG_CONTRACT || self.version != 1 {
            return Err(Error::engine("invalid standby refresh config contract"));
        }
        validate_exact_origin(&self.hosted_origin)?;
        if self.kernel_audit_interval_seconds.is_some_and(|seconds| {
            !(MIN_KERNEL_AUDIT_INTERVAL_SECONDS..=MAX_KERNEL_AUDIT_INTERVAL_SECONDS)
                .contains(&seconds)
        }) {
            return Err(Error::engine(
                "standby kernel_audit_interval_seconds must be between 60 and 86400",
            ));
        }
        if self
            .projection_proof_interval_seconds
            .is_some_and(|seconds| {
                !(MIN_PROJECTION_PROOF_INTERVAL_SECONDS..=MAX_PROJECTION_PROOF_INTERVAL_SECONDS)
                    .contains(&seconds)
            })
        {
            return Err(Error::engine(
                "standby projection_proof_interval_seconds must be between 60 and 86400",
            ));
        }
        if self.refresh_interval_seconds == Some(0) {
            return Err(Error::engine(
                "standby refresh_interval_seconds must be positive",
            ));
        }
        // Availability and metadata are checked on every attempt so an
        // initially missing or atomically rotated credential can recover
        // without restarting the local reader.
        crate::credential_file::validate_credential_path(&self.credential_file, "standby")
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
    /// A whole-snapshot attempt was held back by its minimum interval. This
    /// is scheduling, not a storage fault, and must never overwrite the last
    /// full-refresh failure detail.
    Throttled,
    /// Hosted authors a canonical-interchange revision this build cannot
    /// read. Following pauses instead of burning a capture the node could
    /// never admit; upgrading the node is the only repair.
    RevisionUnsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StandbyRefreshState {
    pub contract: String,
    pub version: u32,
    pub refresh_active: bool,
    pub manual_refresh_pending: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_progress: Option<StandbyTransferProgress>,
    #[serde(default)]
    pub active_candidate_generation_id: Option<String>,
    #[serde(default)]
    pub active_candidate_captured_at: Option<String>,
    #[serde(default)]
    pub active_candidate_completed_at: Option<String>,
    #[serde(default)]
    pub active_candidate_frontier: Option<CanonicalFrontierV1>,
    #[serde(default)]
    pub last_attempt_id: Option<String>,
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
    #[serde(default)]
    pub last_delta_fallback_class: Option<DeltaFallbackClass>,
    #[serde(default)]
    pub last_delta_fallback: Option<String>,
    /// Start of the most recent whole-snapshot refresh of an existing copy.
    #[serde(default)]
    pub last_full_refresh_at: Option<String>,
    /// Why the last attempt changed nothing without failing, if it did.
    #[serde(default)]
    pub last_deferral: Option<String>,
    /// When a whole snapshot deferred by `full_refresh_interval` next becomes
    /// eligible. Set only by that deferral and cleared by every other outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_full_refresh_eligible_at: Option<String>,
    /// Last whole-snapshot failure, retained separately so a later throttle
    /// refusal or delta-only attempt cannot overwrite it.
    #[serde(default)]
    pub last_full_failure_attempt_id: Option<String>,
    #[serde(default)]
    pub last_full_failure_at: Option<String>,
    #[serde(default)]
    pub last_full_failure_class: Option<RefreshFailureClass>,
    #[serde(default)]
    pub last_full_failure: Option<String>,
    /// Static allowlisted install fence or verification identifier.
    #[serde(default)]
    pub last_full_failure_detail: Option<String>,
    /// The cause that triggered the failed whole snapshot, so a later
    /// throttle or delta-only attempt cannot reattribute it.
    #[serde(default)]
    pub last_full_failure_cause: Option<RefreshCause>,
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

fn is_sqlite_busy_or_locked(error: &Error) -> bool {
    matches!(error, Error::Sqlx(sqlx::Error::Database(database))
        if database
            .code()
            .and_then(|code| code.parse::<i32>().ok())
            .is_some_and(|code| matches!(code & 0xff, 5 | 6)))
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
    state
        .transfer_progress
        .as_ref()
        .is_none_or(|progress| progress.valid(state.refresh_active))
        && state.last_attempt_at.is_some() == state.last_attempt_cause.is_some()
        && state.last_failure_class.is_some() == state.last_failure.is_some()
        && state.last_delta_fallback_class.is_some() == state.last_delta_fallback.is_some()
        && state
            .last_delta_fallback
            .as_ref()
            .is_none_or(|message| message.len() <= 160)
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
            &state.last_full_refresh_at,
            &state.next_full_refresh_eligible_at,
        ]
        .into_iter()
        .all(valid_status_timestamp)
        && state
            .last_deferral
            .as_ref()
            .is_none_or(|reason| reason.len() <= 64)
        && state.last_full_failure_class.is_some() == state.last_full_failure.is_some()
        && state
            .last_full_failure_detail
            .as_ref()
            .is_none_or(|detail| detail.len() <= 1000)
        && valid_status_timestamp(&state.last_full_failure_at)
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
    if transfer_progress::merge_observation(&refresh_dir, &mut state).is_err() {
        return RefreshStateObservation::Unavailable;
    }
    if transfer_progress::observe_owner(&refresh_dir, &mut state).is_err() {
        return RefreshStateObservation::Unavailable;
    }
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
            transfer_progress: None,
            active_candidate_generation_id: None,
            active_candidate_captured_at: None,
            active_candidate_completed_at: None,
            active_candidate_frontier: None,
            last_attempt_id: None,
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
            last_delta_fallback_class: None,
            last_delta_fallback: None,
            last_full_refresh_at: None,
            last_deferral: None,
            next_full_refresh_eligible_at: None,
            last_full_failure_attempt_id: None,
            last_full_failure_at: None,
            last_full_failure_class: None,
            last_full_failure: None,
            last_full_failure_detail: None,
            last_full_failure_cause: None,
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
    Unchanged {
        generation: Box<InstalledGeneration>,
    },
    /// One whole-act delta was applied in place to the current generation.
    Advanced {
        generation: Box<InstalledGeneration>,
        head_act: i64,
    },
    /// Nothing changed and nothing failed: the copy is waiting for a serving
    /// build that can follow in-place deltas, for a verification to finish,
    /// or for the minimum interval between whole snapshots.
    Deferred {
        generation: Box<InstalledGeneration>,
        reason: &'static str,
    },
}

/// Outcome of [`StandbyRefreshController::refresh_delta_only`]: the external
/// scheduler runs this every tick and takes its whole-snapshot path only when
/// told to.
#[derive(Debug, Serialize)]
#[serde(tag = "delta", rename_all = "snake_case")]
pub enum StandbyDeltaOutcome {
    Unchanged {
        generation_id: String,
        head_act: i64,
    },
    Advanced {
        generation_id: String,
        head_act: i64,
    },
    FullRefreshRequired {
        reason: DeltaFallbackClass,
    },
    Deferred {
        reason: &'static str,
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

/// No synchronous flock on the single-thread refresh runtime may wait forever.
fn lock_exclusive_bounded(lock: &File, budget: Duration) -> Result<()> {
    let started = std::time::Instant::now();
    loop {
        match lock.try_lock_exclusive() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if started.elapsed() >= budget {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "standby refresh lock wait timed out",
                    )
                    .into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// In-memory hold while hosted plausibly still runs a delta export for this
/// account: a busy refusal, or a poll the node gave up on. Never persisted —
/// a rolled-back binary simply retries on its normal cadence — so it only
/// ever delays attempts, never correctness or read availability.
#[derive(Default)]
struct BusyExportBackoff {
    until: Option<tokio::time::Instant>,
    consecutive: u32,
}

/// In-memory liveness heartbeat for the follow loop: the loop stamps every
/// `poll.tick()`, and an independent watchdog warns while the stamps stop.
/// Monotonic and never persisted, so older builds keep parsing state strictly.
/// `u64::MAX` marks "never": before the loop's first tick there is no quiet
/// history to judge, so the watchdog stays silent through slow startup.
#[derive(Debug)]
pub(crate) struct FollowHeartbeat {
    base: tokio::time::Instant,
    last_tick_ms: std::sync::atomic::AtomicU64,
    attempt_started_ms: std::sync::atomic::AtomicU64,
    warned: std::sync::atomic::AtomicBool,
    expired: tokio::sync::Notify,
}

impl FollowHeartbeat {
    fn new() -> Self {
        Self {
            base: tokio::time::Instant::now(),
            last_tick_ms: std::sync::atomic::AtomicU64::new(u64::MAX),
            attempt_started_ms: std::sync::atomic::AtomicU64::new(u64::MAX),
            warned: std::sync::atomic::AtomicBool::new(false),
            expired: tokio::sync::Notify::new(),
        }
    }

    /// Stamp the latest scheduler tick. Called once per `poll.tick()`.
    fn note_tick(&self) {
        self.last_tick_ms.store(
            self.millis_since_base(),
            std::sync::atomic::Ordering::Release,
        );
    }

    /// Stamp the start of a refresh attempt; cleared by [`Self::note_attempt_end`].
    fn note_attempt_start(&self) {
        self.attempt_started_ms.store(
            self.millis_since_base(),
            std::sync::atomic::Ordering::Release,
        );
    }

    /// Clear the in-flight attempt stamp on completion.
    fn note_attempt_end(&self) {
        self.attempt_started_ms
            .store(u64::MAX, std::sync::atomic::Ordering::Release);
    }

    fn millis_since_base(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// How long since the last stamped tick, or zero before the first tick.
    fn tick_age(&self, now: tokio::time::Instant) -> Duration {
        let last_ms = self.last_tick_ms.load(std::sync::atomic::Ordering::Acquire);
        if last_ms == u64::MAX {
            return Duration::ZERO;
        }
        let last = self.base + Duration::from_millis(last_ms);
        now.saturating_duration_since(last)
    }

    /// How long the current attempt has held the loop, or `None` between attempts.
    fn attempt_age(&self, now: tokio::time::Instant) -> Option<Duration> {
        let started_ms = self
            .attempt_started_ms
            .load(std::sync::atomic::Ordering::Acquire);
        if started_ms == u64::MAX {
            return None;
        }
        let started = self.base + Duration::from_millis(started_ms);
        Some(now.saturating_duration_since(started))
    }
}

/// Warn once while the follow loop's ticks stop arriving, and re-arm when
/// they resume. Runs on a thread independent of the loop's own runtime, so a
/// parked loop cannot park its watcher. Nothing here is persisted.
async fn run_follow_watchdog(
    heartbeat: &FollowHeartbeat,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut probe = tokio::time::interval(interval);
    probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            _ = probe.tick() => {
                let now = tokio::time::Instant::now();
                let idle = heartbeat.tick_age(now);
                if heartbeat.attempt_age(now).is_some_and(|age| age >= ATTEMPT_TIMEOUT) {
                    heartbeat.expired.notify_waiters();
                }
                if idle > stall_warn_after(interval) {
                    if !heartbeat
                        .warned
                        .swap(true, std::sync::atomic::Ordering::AcqRel)
                    {
                        match heartbeat.attempt_age(now) {
                            Some(running) => tracing::warn!(
                                target: FOLLOW_LOG_TARGET,
                                attempt_secs = running.as_secs(),
                                tick_idle_secs = idle.as_secs(),
                                "standby follow loop has an attempt running for {}s; ticks are parked while it runs",
                                running.as_secs()
                            ),
                            None => tracing::warn!(
                                target: FOLLOW_LOG_TARGET,
                                tick_idle_secs = idle.as_secs(),
                                "standby follow loop scheduler parked between attempts for {}s; hosted may be ahead",
                                idle.as_secs()
                            ),
                        }
                    }
                } else {
                    heartbeat
                        .warned
                        .store(false, std::sync::atomic::Ordering::Release);
                }
            }
        }
    }
}

#[derive(Debug)]
struct AttemptError {
    class: RefreshFailureClass,
    safe_message: &'static str,
    detail: &'static str,
    source: Box<Error>,
    /// Hosted's `retry-after` hint for a busy export refusal, if it carried a
    /// parseable one. Consumed once by the daemon's busy backoff; never
    /// persisted or disclosed.
    retry_after: Option<Duration>,
    delta_fallback: Option<DeltaFallbackDiagnostic>,
    /// Allowlisted fence/check identifier naming the refusing stage (e.g.
    /// `install-fence:successor`). `None` means no specific fence claimed.
    /// Sinks may render this; they must never render `source`.
    check: Option<&'static str>,
}

struct AttemptStagingFiles {
    snapshot: PathBuf,
    manifest: PathBuf,
}

enum AttemptSuccess {
    Installed {
        generation: InstalledGeneration,
        retention_warnings: Vec<String>,
        delta_fallback: Option<DeltaFallbackDiagnostic>,
    },
    Unchanged(InstalledGeneration),
    Advanced {
        generation: InstalledGeneration,
        head_act: i64,
    },
    Deferred {
        generation: InstalledGeneration,
        reason: &'static str,
        delta_fallback: Option<DeltaFallbackDiagnostic>,
    },
}

enum DeltaAttempt {
    Unchanged(InstalledGeneration),
    Advanced {
        generation: InstalledGeneration,
        head_act: i64,
    },
    Deferred {
        generation: InstalledGeneration,
        reason: &'static str,
    },
    FallBackToSnapshot(DeltaFallbackDiagnostic),
    /// This attempt observed an exact, directed registry transition. A saved
    /// retry-budget receipt alone never authorizes the cooldown exception.
    ShapeTransition(DeltaFallbackDiagnostic),
    /// Hosted authors an unreadable interchange revision: pause following
    /// instead of falling back to a whole snapshot that could never admit.
    Paused(InstalledGeneration, &'static str),
}

/// The serving process has not opened the current generation with a build
/// that reads it as a mutable SQLite file.
const DEFERRED_READER_NOT_UPGRADED: &str = "reader_not_upgraded";
/// A verification is hashing the checkpoint the first delta would change.
const DEFERRED_CHECKPOINT_VERIFYING: &str = "checkpoint_being_verified";
/// A whole snapshot is needed but the previous one started too recently.
pub(super) const DEFERRED_FULL_REFRESH_INTERVAL: &str = "full_refresh_interval";
/// A serving reader held the database past the writer's wait. Nothing was
/// written; the next tick tries again.
const DEFERRED_DATABASE_BUSY: &str = "database_busy";
/// Hosted authors an unreadable interchange revision. Following pauses on
/// every cause, including Manual: no snapshot acquisition can succeed
/// until the node is upgraded.
const DEFERRED_REVISION_UNSUPPORTED: &str = "revision_unsupported";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaFallbackClass {
    HeadCompatibility,
    DeltaUnavailable,
    IntegrityOrApplyRefusal,
    RemoteHeadRegression,
    UntrustedLocalBase,
    AuditFailed,
    ConsumerChanged,
    /// The exact cut is above the delta transfer ceiling (the chunked route's
    /// `delta_too_large`, or the legacy MCP oversize refusal), so only a whole
    /// snapshot can express it.
    DeltaTooLarge,
    BlobInventoryLimit,
    ProjectionDivergence,
}

#[derive(Clone, Copy, Debug)]
struct DeltaFallbackDiagnostic {
    class: DeltaFallbackClass,
    message: &'static str,
}

impl Drop for AttemptStagingFiles {
    fn drop(&mut self) {
        remove_owned_sqlite_sidecars(&self.snapshot);
        remove_owned_staging_file(&self.snapshot);
        remove_owned_staging_file(&self.manifest);
    }
}

impl AttemptError {
    fn new(class: RefreshFailureClass, safe_message: &'static str, source: Error) -> Self {
        Self {
            class,
            safe_message,
            detail: "unclassified",
            source: Box::new(source),
            retry_after: None,
            delta_fallback: None,
            check: None,
        }
    }

    // Callers supply only fixed vocabulary tokens, never source text.
    fn with_detail(mut self, detail: &'static str) -> Self {
        self.detail = detail;
        self
    }

    fn with_check(mut self, check: &'static str) -> Self {
        self.check = Some(check);
        self
    }

    fn after_delta_fallback(mut self, diagnostic: DeltaFallbackDiagnostic) -> Self {
        self.delta_fallback = Some(diagnostic);
        self
    }
}

/// The only rendering of an attempt failure permitted at persistence, log
/// and CLI sinks. Every component is allowlisted: the failure class, the
/// static safe message, the static fence/check identifier and the static
/// delta-fallback class. The raw `source` error — which may carry row dumps,
/// bodies or credentials — is never stringified here. Because no dynamic
/// text is rendered, no byte bounding is needed and none is attempted.
#[cfg(test)]
fn safe_diagnostic(error: &AttemptError) -> String {
    format!(
        "class={:?} safe={:?} check={} fallback={}",
        error.class,
        error.safe_message,
        error.check.unwrap_or(UNCLASSIFIED_CHECK),
        error
            .delta_fallback
            .map(|diagnostic| format!("{:?}", diagnostic.class))
            .unwrap_or_else(|| "none".into()),
    )
}

/// Project a retained detail token only when it is allowlisted. State files
/// written before the sink hardening may hold raw bounded source text in
/// `last_full_failure_detail`; readers (status projection, CLI) must never
/// disclose unknown opaque text, so anything else becomes `unclassified`.
pub fn sanitize_retained_detail(raw: Option<&str>) -> &'static str {
    match raw {
        // Return the canonical `&'static` token, never the state-file string.
        Some(UNCLASSIFIED_CHECK) => UNCLASSIFIED_CHECK,
        Some(INSTALL_VERIFY_CHECK) => INSTALL_VERIFY_CHECK,
        Some("attempt_timeout") => "attempt_timeout",
        Some("lock_wait_timeout") => "lock_wait_timeout",
        Some(value) => ADMISSION_CHECKS
            .iter()
            .map(|check| check.token())
            .chain(LEGACY_INSTALL_CHECKS.iter().copied())
            .find(|check| *check == value)
            .unwrap_or(UNCLASSIFIED_CHECK),
        None => UNCLASSIFIED_CHECK,
    }
}

/// Project a persisted deferral only when it is one of the closed tokens, so a
/// state file can never put prose into status.
pub fn sanitize_deferral(raw: &str) -> Option<&'static str> {
    [
        DEFERRED_READER_NOT_UPGRADED,
        DEFERRED_CHECKPOINT_VERIFYING,
        DEFERRED_FULL_REFRESH_INTERVAL,
        DEFERRED_DATABASE_BUSY,
        DEFERRED_REVISION_UNSUPPORTED,
        "engine v2 requires v2-kernel-probe build",
        "kernel_v2_replay_cooldown",
        "insufficient_disk",
        "refresh_in_progress",
    ]
    .into_iter()
    .find(|token| *token == raw)
}

fn refresh_pause_message(reason: &'static str) -> &'static str {
    if reason == DEFERRED_REVISION_UNSUPPORTED {
        "hosted uses a newer interchange revision; upgrade the node to resume following"
    } else {
        reason
    }
}

/// Legacy states without correlation IDs cannot attribute a retained detail.
pub fn current_attempt_detail(state: &StandbyRefreshState) -> &'static str {
    match (&state.last_attempt_id, &state.last_full_failure_attempt_id) {
        (Some(attempt), Some(full)) if attempt == full => {
            sanitize_retained_detail(state.last_full_failure_detail.as_deref())
        }
        _ => UNCLASSIFIED_CHECK,
    }
}

/// Phase is an explicit observation of this invocation, never inferred from time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshAttemptPhase {
    Preparation,
    Following,
    Full,
    Persistence,
}

/// Payload-free failure receipt for this invocation, available even if state
/// cannot be opened or persisted. The original library API still returns Error.
#[derive(Clone, Debug)]
pub struct RefreshFailureReceipt {
    pub attempt_id: uuid::Uuid,
    pub cause: RefreshCause,
    pub phase: RefreshAttemptPhase,
    pub class: RefreshFailureClass,
    pub safe_message: &'static str,
    /// Fixed, payload-free diagnostic token; never persisted in refresh state.
    pub detail: &'static str,
    pub check: &'static str,
    pub delta_fallback: Option<DeltaFallbackClass>,
}

impl RefreshFailureReceipt {
    pub fn diagnostic(&self) -> String {
        format!(
            "attempt={} cause={:?} phase={:?} class={:?} safe={} detail={} check={} fallback={:?}",
            self.attempt_id,
            self.cause,
            self.phase,
            self.class,
            self.safe_message,
            self.detail,
            self.check,
            self.delta_fallback
        )
    }
    fn emit(&self) {
        eprintln!(
            "native-standby-refresh: refresh failed {}",
            self.diagnostic()
        );
        tracing::warn!(attempt_id = %self.attempt_id, cause = ?self.cause, phase = ?self.phase,
            class = ?self.class, safe_message = self.safe_message, detail = self.detail, check = self.check,
            fallback = ?self.delta_fallback, "standby refresh attempt failed");
    }
}

#[derive(Debug)]
pub struct RefreshAttemptFailure {
    pub receipt: Box<RefreshFailureReceipt>,
    pub source: Error,
}

// This marker lives outside the timed future and survives its cancellation.
struct AttemptProgress {
    resume_observation: Option<(binary_resume::ResumeBinding, binary::BinaryExport)>,
    transition: bool,
    receipt: RefreshFailureReceipt,
    diagnosed: bool,
    full_started_at: Option<String>,
    /// Set when FULL was held back by `full_refresh_interval`.
    full_eligible_at: Option<String>,
}
impl AttemptProgress {
    fn new(cause: RefreshCause) -> Self {
        Self {
            resume_observation: None,
            transition: false,
            receipt: RefreshFailureReceipt {
                attempt_id: uuid::Uuid::new_v4(),
                cause,
                phase: RefreshAttemptPhase::Preparation,
                class: RefreshFailureClass::LocalIo,
                safe_message: "local standby refresh preparation or persistence failed",
                detail: "unclassified",
                check: UNCLASSIFIED_CHECK,
                delta_fallback: None,
            },
            diagnosed: false,
            full_started_at: None,
            full_eligible_at: None,
        }
    }
    fn diagnose_boundary(&mut self, source: &Error) {
        if self.diagnosed {
            return;
        }
        if matches!(source, Error::Io(error) if error.kind() == std::io::ErrorKind::TimedOut) {
            self.receipt.class = RefreshFailureClass::Timeout;
            self.receipt.safe_message =
                "standby refresh coordination lock wait exceeded its time bound";
            self.receipt.detail = "lock_wait_timeout";
            self.receipt.check = "lock_wait_timeout";
        }
        self.receipt.emit();
        self.diagnosed = true;
    }

    fn diagnose(&mut self, error: &AttemptError) {
        self.receipt.class = error.class;
        self.receipt.safe_message = error.safe_message;
        self.receipt.detail = error.detail;
        self.receipt.check = error.check.unwrap_or(UNCLASSIFIED_CHECK);
        self.receipt.delta_fallback = error.delta_fallback.map(|value| value.class);
        self.receipt.emit();
        self.diagnosed = true;
    }
}

type PageFuture =
    Pin<Box<dyn Future<Output = std::result::Result<SnapshotPage, AttemptError>> + Send>>;

trait SnapshotPageClient: Send + Sync {
    fn page(&self, endpoint: String, bearer: String, request: SnapshotPageRequest) -> PageFuture;
}

struct HttpSnapshotPageClient {
    compatibility: crate::client_compatibility::Monitor,
    client: reqwest::Client,
    install_key: Option<crate::node_credential::InstallKey>,
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
        Ok(Self {
            client,
            compatibility: Default::default(),
            install_key: None,
        })
    }
}

impl SnapshotPageClient for HttpSnapshotPageClient {
    fn page(&self, endpoint: String, bearer: String, request: SnapshotPageRequest) -> PageFuture {
        let client = self.client.clone();
        let compatibility = self.compatibility.clone();
        let install_key = self.install_key.clone();
        Box::pin(async move {
            let mut body = modern_export_call(&request);
            let endpoint = if install_key.is_some() {
                let mut url = reqwest::Url::parse(&endpoint).map_err(|_| {
                    AttemptError::new(
                        RefreshFailureClass::Network,
                        "invalid installed snapshot URL",
                        Error::engine("invalid installed snapshot URL"),
                    )
                })?;
                let Some(database) = url.path().strip_prefix("/mcp/") else {
                    return Err(AttemptError::new(
                        RefreshFailureClass::Protocol,
                        "invalid installed snapshot route",
                        Error::engine("invalid installed snapshot route"),
                    ));
                };
                url.set_path(&format!("/internal/node/databases/{database}/mcp"));
                body["params"]["name"] = json!("call_executor");
                body["params"]["arguments"]["executor"] = json!(EXPORT_EXECUTOR);
                url.to_string()
            } else {
                endpoint
            };
            let builder = client
                .post(endpoint)
                .header(
                    super::shapes::ACCEPTED_SHAPES_HEADER,
                    super::shapes::advertisement(),
                )
                .header(
                    crate::client_compatibility::HEADER,
                    crate::client_compatibility::advertisement(),
                )
                .bearer_auth(bearer)
                .header(
                    reqwest::header::ACCEPT,
                    "application/json, text/event-stream",
                )
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header("MCP-Protocol-Version", PROTOCOL_VERSION)
                .header("Mcp-Method", "tools/call")
                .header("Mcp-Name", EXPORT_EXECUTOR)
                .json(&body);
            let response =
                crate::node_credential::send_request(&client, builder, install_key.as_ref())
                    .await
                    .map_err(|_| {
                        AttemptError::new(
                            RefreshFailureClass::Network,
                            "hosted snapshot request failed",
                            Error::engine("hosted snapshot request failed"),
                        )
                    })?;
            let response =
                crate::client_compatibility::inspect(response, &compatibility, "snapshot", "page")
                    .await
                    .map_err(classify_delta_transport_error)?;
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
            let selected_shape = super::delta_transport::selected_header(response.headers())
                .map_err(|error| {
                    integrity("hosted snapshot selected an unsupported shape", error)
                })?;
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
            let refusal: Value = serde_json::from_slice(&bytes).map_err(|error| {
                integrity("hosted snapshot returned invalid JSON", error.into())
            })?;
            if refusal.pointer("/result/isError").and_then(Value::as_bool) == Some(true)
                && refusal
                    .pointer("/result/structuredContent/error_code")
                    .and_then(Value::as_str)
                    == Some(super::shapes::UPDATE_REQUIRED)
            {
                return Err(AttemptError::new(
                    RefreshFailureClass::Compatibility,
                    "update this receiver to refresh",
                    Error::engine(super::shapes::UPDATE_REQUIRED),
                ));
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
            let mut page = result.structured_content.ok_or_else(|| {
                AttemptError::new(
                    RefreshFailureClass::Protocol,
                    "hosted snapshot omitted structured content",
                    Error::engine("hosted snapshot missing structured content"),
                )
            })?;
            page.selected_shape = selected_shape;
            Ok(page)
        })
    }
}

/// A transport owner's refresh lifetime. Verification and acquisition run on
/// a dedicated runtime; stopping it releases the single-owner daemon guard.
/// Another daemon may already own the replica: hints then reach that owner
/// through the controller's existing durable, coalesced trigger set.
pub struct BackgroundRefresh {
    shutdown: watch::Sender<bool>,
    cancellation: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    watchdog: Option<std::thread::JoinHandle<()>>,
    hints: RefreshHints,
}

/// Process-local, nonblocking handoff of the original transport witness after
/// its accepted commit. Implementations must only enqueue, never do owner work.
pub(crate) trait AcceptedDeltaObserver: Send + Sync {
    fn begin(&self) {}
    fn finish(&self) {}
    fn committed(
        &self,
        generation: String,
        delta: super::act_materialise::TrustedAuthorityActDelta,
    );
}

pub(crate) struct AcceptedDeltaNotice(Option<Arc<dyn AcceptedDeltaObserver>>);
impl AcceptedDeltaNotice {
    pub(crate) fn committed(
        mut self,
        generation: String,
        delta: super::act_materialise::TrustedAuthorityActDelta,
    ) {
        if let Some(observer) = self.0.take() {
            observer.committed(generation, delta);
        }
    }
}
impl Drop for AcceptedDeltaNotice {
    fn drop(&mut self) {
        if let Some(observer) = &self.0 {
            observer.finish();
        }
    }
}

/// Actual kernel-v2 accepted publication, minted only by this refresh owner
/// AFTER native accepted commit/publication. This is not a v1 authority delta,
/// a receipt/head claim, or a constructor-granted verdict capability.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) struct AcceptedKernelDelta {
    source: String,
    destination: String,
    before: super::kernel_v2::KernelGeneration,
    delta: super::kernel_v2_delta::TrustedKernelDelta,
}
#[cfg(feature = "v2-kernel-probe")]
impl AcceptedKernelDelta {
    pub(crate) fn source(&self) -> &str {
        &self.source
    }
    pub(crate) fn destination(&self) -> &str {
        &self.destination
    }
    pub(crate) fn before(&self) -> &super::kernel_v2::KernelGeneration {
        &self.before
    }
    pub(crate) fn delta(&self) -> &super::kernel_v2_delta::TrustedKernelDelta {
        &self.delta
    }
    #[cfg(test)]
    pub(crate) fn fixture_materialized(
        source: String,
        destination: String,
        before: super::kernel_v2::KernelGeneration,
        delta: super::kernel_v2_delta::TrustedKernelDelta,
    ) -> Result<Self> {
        if source.is_empty()
            || destination.is_empty()
            || before.head_act != delta.delta().from_exclusive_act
            || before.genesis_event_id != delta.delta().head.genesis_event_id
        {
            return Err(Error::engine(
                "fixture kernel publication coordinates differ",
            ));
        }
        Ok(Self {
            source,
            destination,
            before,
            delta,
        })
    }
}
#[cfg(feature = "v2-kernel-probe")]
pub(crate) trait AcceptedKernelDeltaObserver: Send + Sync {
    fn begin(&self) {}
    fn no_publication(&self) {}
    fn finish(&self) {}
    fn committed(&self, accepted: AcceptedKernelDelta);
}
#[cfg(feature = "v2-kernel-probe")]
struct AcceptedKernelNotice(Option<Arc<dyn AcceptedKernelDeltaObserver>>);
#[cfg(feature = "v2-kernel-probe")]
impl AcceptedKernelNotice {
    fn no_publication(mut self) {
        if let Some(observer) = self.0.take() {
            observer.no_publication();
        }
    }
    fn committed(
        mut self,
        source: String,
        destination: String,
        before: super::kernel_v2::KernelGeneration,
        delta: super::kernel_v2_delta::TrustedKernelDelta,
    ) {
        if let Some(observer) = self.0.take() {
            observer.committed(AcceptedKernelDelta {
                source,
                destination,
                before,
                delta,
            });
        }
    }
}
#[cfg(feature = "v2-kernel-probe")]
impl Drop for AcceptedKernelNotice {
    fn drop(&mut self) {
        if let Some(observer) = &self.0 {
            observer.finish();
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct RefreshHints(Arc<RefreshHintsInner>);

#[derive(Default)]
struct RefreshHintsInner {
    compatibility: crate::client_compatibility::Monitor,
    #[cfg(feature = "v2-kernel-probe")]
    kernel_observer: std::sync::Mutex<Option<Arc<dyn AcceptedKernelDeltaObserver>>>,
    observer: std::sync::Mutex<Option<Arc<dyn AcceptedDeltaObserver>>>,
    pending: std::sync::atomic::AtomicU8,
    ready: tokio::sync::Notify,
}

impl RefreshHints {
    pub(crate) fn compatibility(&self) -> crate::client_compatibility::Monitor {
        self.0.compatibility.clone()
    }

    pub(crate) fn observe_accepted_deltas(&self, observer: Arc<dyn AcceptedDeltaObserver>) {
        *self.0.observer.lock().unwrap_or_else(|e| e.into_inner()) = Some(observer);
    }
    pub(crate) fn begin_accepted(&self) -> Option<AcceptedDeltaNotice> {
        let observer = self
            .0
            .observer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()?;
        observer.begin();
        Some(AcceptedDeltaNotice(Some(observer)))
    }

    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) fn observe_accepted_kernel_deltas(
        &self,
        observer: Arc<dyn AcceptedKernelDeltaObserver>,
    ) {
        *self
            .0
            .kernel_observer
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(observer);
    }
    #[cfg(feature = "v2-kernel-probe")]
    fn begin_kernel_accepted(&self) -> Option<AcceptedKernelNotice> {
        let observer = self
            .0
            .kernel_observer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()?;
        observer.begin();
        Some(AcceptedKernelNotice(Some(observer)))
    }
    /// Payload-free, coalesced notification only: no filesystem or network work
    /// runs on an agent request or health-probe task.
    pub(crate) fn request(&self, cause: RefreshCause) {
        self.0
            .pending
            .fetch_or(1 << cause as u8, std::sync::atomic::Ordering::AcqRel);
        self.0.ready.notify_one();
    }

    async fn persist(&self, controller: &StandbyRefreshController) {
        loop {
            self.0.ready.notified().await;
            let pending = self.0.pending.swap(0, std::sync::atomic::Ordering::AcqRel);
            for cause in [
                RefreshCause::Startup,
                RefreshCause::Scheduled,
                RefreshCause::Wake,
                RefreshCause::NetworkRecovery,
                RefreshCause::Manual,
                RefreshCause::AfterAdmittedWrite,
            ] {
                if pending & (1 << cause as u8) != 0 && controller.request_refresh(cause).is_err() {
                    tracing::warn!(target: "native_ce::standby::verification", "standby refresh hint unavailable");
                }
            }
        }
    }
}

impl BackgroundRefresh {
    pub(crate) fn hints(&self) -> RefreshHints {
        self.hints.clone()
    }

    pub async fn stop(mut self) {
        self.cancel();
        if let Some(worker) = self.worker.take() {
            let _ = tokio::task::spawn_blocking(move || worker.join()).await;
        }
        if let Some(watchdog) = self.watchdog.take() {
            let _ = tokio::task::spawn_blocking(move || watchdog.join()).await;
        }
    }

    fn cancel(&self) {
        self.cancellation
            .store(true, std::sync::atomic::Ordering::Release);
        let _ = self.shutdown.send(true);
    }
}

impl Drop for BackgroundRefresh {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Shared stdio/node refresh composition, with the controller's existing
/// daemon guard, cadence, causes, failure state and generation publication.
pub fn start_background_refresh(
    runtime: &StandbyRuntimeConfig,
    observed: &ObservedInstalledConsumerIdentity,
    refresh_config_path: impl AsRef<Path>,
) -> Result<BackgroundRefresh> {
    let store = GenerationStore::open(
        &runtime.replica_root,
        &runtime.hosted_route_database_id,
        Some(runtime.origin_database_id.clone()),
    )?;
    start_background_refresh_with_store(runtime, observed, refresh_config_path, store)
}

/// Compose refresh with the serving store's process-local verification cache.
pub fn start_background_refresh_with_store(
    runtime: &StandbyRuntimeConfig,
    observed: &ObservedInstalledConsumerIdentity,
    refresh_config_path: impl AsRef<Path>,
    store: GenerationStore,
) -> Result<BackgroundRefresh> {
    start_background_refresh_inner(
        runtime,
        observed,
        refresh_config_path.as_ref(),
        None,
        store,
        None,
    )
}

/// Node refresh waits for its supervisor's cold recovery before acquiring any
/// new copy. It publishes through the ordinary store; only the supervisor's
/// existing accepted-generation watcher performs serving handover.
pub(crate) fn start_background_refresh_after_startup(
    runtime: &StandbyRuntimeConfig,
    observed: &ObservedInstalledConsumerIdentity,
    refresh_config_path: &Path,
    startup_ready: tokio::sync::oneshot::Receiver<()>,
    store: GenerationStore,
    install_key: Option<crate::node_credential::InstallKey>,
) -> Result<BackgroundRefresh> {
    start_background_refresh_inner(
        runtime,
        observed,
        refresh_config_path,
        Some(startup_ready),
        store,
        install_key,
    )
}

fn start_background_refresh_inner(
    runtime: &StandbyRuntimeConfig,
    observed: &ObservedInstalledConsumerIdentity,
    refresh_config_path: &Path,
    startup_ready: Option<tokio::sync::oneshot::Receiver<()>>,
    store: GenerationStore,
    install_key: Option<crate::node_credential::InstallKey>,
) -> Result<BackgroundRefresh> {
    let refresh_config = StandbyRefreshConfig::from_json(&fs::read(refresh_config_path)?)?;
    let controller = StandbyRefreshController::new_with_install_key(
        runtime.clone(),
        refresh_config,
        store,
        observed.clone(),
        install_key,
    )?;
    let hints = controller.pending_observer.clone();
    let controller = Arc::new(controller);
    let guard = controller.try_acquire_daemon()?;
    // The watchdog's handle and the daemon question are settled before the
    // refresher worker takes the controller: the watchdog below must only
    // run for a live daemon loop, never for a process that lost the lock.
    let watchdog_heartbeat = controller.follow_heartbeat.clone();
    let daemon_owned = guard.is_some();
    let follow_interval = refresh_cadence(&controller.config);
    let (started, readiness) = std::sync::mpsc::sync_channel(1);
    let (shutdown, mut receiver) = watch::channel(false);
    let worker_hints = hints.clone();
    let cancellation = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_cancellation = cancellation.clone();
    let worker = std::thread::Builder::new()
        .name("standby-refresh".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            // Build and drop the runtime on its own thread, including setup
            // failures; a Tokio runtime must not be dropped inside a caller's
            // asynchronous transport runtime.
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = started.send(Err(error));
                    return;
                }
            };
            let _ = started.send(Ok(()));
            super::generation_store::with_verification_cancellation(worker_cancellation, || {
                runtime.block_on(async {
                    if let Some(startup_ready) = startup_ready {
                        tokio::select! {
                            result = startup_ready => if result.is_err() { return; },
                            _ = receiver.changed() => return,
                        }
                    }
                    if *receiver.borrow() {
                        return;
                    }
                    let hints = worker_hints.persist(&controller);
                    if let Some(guard) = guard {
                        tokio::select! {
                            _ = controller.run_daemon_after_startup(guard, receiver) => {},
                            _ = hints => {},
                        }
                    } else {
                        tokio::select! {
                            _ = receiver.changed() => {},
                            _ = hints => {},
                        }
                    }
                });
                runtime.shutdown_timeout(Duration::from_secs(5));
            });
        })?;
    match readiness.recv() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            // The watchdog is only spawned below, so a failed start joins
            // just the worker — which already exited after reporting.
            let _ = worker.join();
            return Err(error.into());
        }
        Err(_) => {
            let _ = worker.join();
            return Err(Error::engine("standby refresh runtime startup failed"));
        }
    }
    // The watchdog watches the follow loop's heartbeat from its own thread
    // and runtime: a parked loop must not park its watcher. It starts only
    // once the refresher runtime is up, and only for a process that owns
    // the daemon — without a guard no follow loop runs, so there is nothing
    // to watch. The bootstrap has no handle to the caller's runtime, so a
    // sibling thread — the same shape as the refresher worker — is the
    // independent home.
    let watchdog = if daemon_owned {
        let watchdog_shutdown = shutdown.subscribe();
        Some(
            std::thread::Builder::new()
                .name("standby-follow-watchdog".into())
                .spawn(move || {
                    let runtime = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => runtime,
                        Err(error) => {
                            eprintln!(
                                "native-standby-refresh: follow watchdog runtime failed: {error}"
                            );
                            return;
                        }
                    };
                    runtime.block_on(run_follow_watchdog(
                        &watchdog_heartbeat,
                        follow_interval,
                        watchdog_shutdown,
                    ));
                })?,
        )
    } else {
        None
    };
    Ok(BackgroundRefresh {
        shutdown,
        cancellation,
        worker: Some(worker),
        watchdog,
        hints,
    })
}

pub struct StandbyRefreshController {
    install_key: Option<crate::node_credential::InstallKey>,
    #[cfg(test)]
    attempt_timeout: Option<Duration>,
    pending_observer: RefreshHints,
    #[cfg(test)]
    kernel_available_space: Option<u64>,
    #[cfg(test)]
    kernel_in_place_crash: Option<super::generation_store::kernel_in_place::InPlaceCrash>,
    runtime: StandbyRuntimeConfig,
    config: StandbyRefreshConfig,
    store: GenerationStore,
    observed: ObservedInstalledConsumerIdentity,
    // Only a successful authority probe selects non-legacy reader coordinates.
    route_kernel_v2: std::sync::atomic::AtomicBool,
    refresh_dir: PathBuf,
    /// In-memory hold while hosted plausibly still runs a delta export (see
    /// [`BusyExportBackoff`]). Guarded inline: reads never block an attempt.
    busy_backoff: std::sync::Mutex<BusyExportBackoff>,
    /// In-memory liveness heartbeat for the follow loop, watched from an
    /// independent thread. Never persisted.
    follow_heartbeat: Arc<FollowHeartbeat>,
    /// In memory only, by design: after a restart the first follow is an
    /// audit, so nothing needs persisting (and no older binary has to
    /// tolerate a new file).
    #[cfg_attr(not(any(test, feature = "v2-kernel-probe")), allow(dead_code))]
    proof_audit: std::sync::Mutex<ProofAudit>,
    client: Arc<dyn SnapshotPageClient>,
    binary_client: Arc<dyn binary::BinarySnapshotClient>,
    binary_snapshot_enabled: bool,
    delta_enabled: bool,
    #[cfg(test)]
    transfer_pause: std::sync::Mutex<Option<transfer_progress::TransferPause>>,
}

/// When the last delta that carried the full projection proof was applied, and
/// whether something since looked wrong. Wire-version-3 deltas carry no proof,
/// so this decides when the next follow must ask for one.
#[derive(Debug, Default)]
#[cfg_attr(not(any(test, feature = "v2-kernel-probe")), allow(dead_code))]
struct ProofAudit {
    /// `None` until a proof-carrying delta applies (so the first follow after
    /// a start audits).
    last: Option<std::time::Instant>,
    /// An apply anomaly or refusal: audit on the next follow, not on schedule.
    trouble: bool,
}

/// Authenticated whole-copy acquisition, NOT an admitted/serving generation.
/// Drop removes its private files; an operator may preserve them for separate
/// complete offline admission. No current pointer or refresh success is set.
pub struct StandbySnapshotDownload {
    snapshot_path: PathBuf,
    manifest_path: PathBuf,
    cleanup: bool,
}

impl StandbySnapshotDownload {
    pub fn snapshot_path(&self) -> &Path {
        &self.snapshot_path
    }

    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    /// Preserve the exact downloaded bytes and producer manifest for the
    /// offline admission command. This does not certify or publish either.
    pub fn preserve(mut self) -> (PathBuf, PathBuf) {
        self.cleanup = false;
        (self.snapshot_path.clone(), self.manifest_path.clone())
    }
}

impl Drop for StandbySnapshotDownload {
    fn drop(&mut self) {
        if self.cleanup {
            remove_owned_staging_file(&self.snapshot_path);
            remove_owned_staging_file(&self.manifest_path);
        }
    }
}

/// The shortest rest after a failed or large v2 replay.
#[cfg(any(test, feature = "v2-kernel-probe"))]
const KERNEL_REPLAY_FLOOR: Duration = Duration::from_secs(60);

#[cfg(any(test, feature = "v2-kernel-probe"))]
struct KernelReplayCooldown<'a> {
    controller: &'a StandbyRefreshController,
    started: std::time::Instant,
    timings: PhaseTimings,
    /// How this attempt ended; anything but a completed small delta keeps
    /// the one-minute floor.
    outcome: KernelReplayOutcome,
    /// `staged` or `in_place`, and why a small delta was not applied in place.
    path: &'static str,
    in_place_skip: Option<&'static str>,
}
#[cfg(any(test, feature = "v2-kernel-probe"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KernelReplayOutcome {
    /// Dropped without a verdict: an error or refusal part-way through.
    Failed,
    /// A delta over the small-delta cap completed.
    CompletedLarge,
    /// A delta within the small-delta cap completed.
    CompletedSmall,
}
#[cfg(any(test, feature = "v2-kernel-probe"))]
impl KernelReplayOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::CompletedLarge => "completed_large",
            Self::CompletedSmall => "completed_small",
        }
    }
}
#[cfg(any(test, feature = "v2-kernel-probe"))]
impl<'a> KernelReplayCooldown<'a> {
    fn start(controller: &'a StandbyRefreshController, timings: PhaseTimings) -> Result<Self> {
        // The attempt marks itself resting before it begins, so a crash
        // part-way through still leaves the floor in place.
        controller.defer_kernel_replay(Duration::ZERO)?;
        Ok(Self {
            controller,
            started: std::time::Instant::now(),
            timings,
            outcome: KernelReplayOutcome::Failed,
            path: "staged",
            in_place_skip: None,
        })
    }

    fn complete(&mut self, small: bool) {
        self.outcome = if small {
            KernelReplayOutcome::CompletedSmall
        } else {
            KernelReplayOutcome::CompletedLarge
        };
    }
}
#[cfg(any(test, feature = "v2-kernel-probe"))]
impl Drop for KernelReplayCooldown<'_> {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed();
        let floor = if self.outcome == KernelReplayOutcome::CompletedSmall {
            Duration::ZERO
        } else {
            KERNEL_REPLAY_FLOOR
        };
        // Display-only: a staged attempt with no recorded skip reason means
        // the flag is off, so name it for counting. Recorded state keeps
        // `in_place_skip` as `None` there; only this log line carries the
        // `in_place_disabled` reason.
        let logged_skip = self.in_place_skip.unwrap_or(if self.path == "staged" {
            "in_place_disabled"
        } else {
            ""
        });
        tracing::info!(
            target: "native_ce::standby::kernel_delta",
            outcome = self.outcome.label(),
            path = self.path,
            in_place_skip = logged_skip,
            replay_ms = elapsed.as_millis() as u64,
            phases = %self.timings.to_json(),
            "kernel-v2 delta attempt finished"
        );
        if self
            .controller
            .write_kernel_replay(
                elapsed,
                floor,
                self.outcome.label(),
                self.path,
                self.in_place_skip,
                &self.timings,
            )
            .is_err()
        {
            tracing::warn!("kernel replay cooldown persistence failed");
        }
    }
}

impl StandbyRefreshController {
    #[cfg(test)]
    pub(crate) fn set_pending_observer_for_test(&mut self, hints: RefreshHints) {
        self.pending_observer = hints;
    }

    /// Deliberately acquire ONE full snapshot without delta fallback, admission
    /// or pruning. Network acquisition retains its existing bounded transport,
    /// credential rotation, manifest binding and digest checks. Expensive
    /// offline verification is a separate step and cannot expire this download.
    pub async fn acquire_snapshot_only(&self) -> Result<StandbySnapshotDownload> {
        // Never overlap the normal refresh daemon or another acquisition.
        let controller_lock = open_private_lock(&self.refresh_dir.join("controller.lock"))?;
        controller_lock.try_lock_exclusive()?;
        let attempt_lock = open_private_lock(&self.refresh_dir.join("attempt.lock"))?;
        attempt_lock.try_lock_exclusive()?;
        let id = uuid::Uuid::new_v4();
        let download = StandbySnapshotDownload {
            snapshot_path: self
                .store
                .staging_dir()
                .join(format!("acquire-{id}.snapshot.db")),
            manifest_path: self
                .store
                .staging_dir()
                .join(format!("acquire-{id}.manifest.json")),
            cleanup: true,
        };
        let bearer =
            read_credential(&self.config.credential_file).map_err(|error| *error.source)?;
        if self.delta_enabled {
            if let Ok(Some(reason)) = self.revision_pause_needed(&bearer).await {
                return Err(Error::engine(refresh_pause_message(reason)));
            }
        }
        let manifest = tokio::time::timeout(
            ATTEMPT_TIMEOUT,
            self.download_binary_only(
                bearer,
                download.snapshot_path(),
                binary::FreshCaptureBudget::Allowed,
            ),
        )
        .await
        .map_err(|_| Error::engine("standby acquisition timed out; no generation published"))?
        .map_err(|error| *error.source)?;
        self.write_downloaded_manifest(&manifest, download.manifest_path())
            .map_err(|error| *error.source)?;
        Ok(download)
    }

    /// One delta-only refresh, for an external scheduler that owns the
    /// whole-snapshot path itself. It probes the hosted head and, when hosted
    /// Native has moved, applies one whole-act delta in place. It never
    /// downloads a snapshot: anything the delta path cannot handle returns
    /// [`StandbyDeltaOutcome::FullRefreshRequired`]. Network and authentication
    /// failures are errors, not reasons to take a whole snapshot.
    pub async fn refresh_delta_only(&self) -> Result<StandbyDeltaOutcome> {
        #[cfg(any(test, feature = "v2-kernel-probe"))]
        self.apply_audit_policy();
        let _verification_retry = self.store.retry_verification_after_refresh(&self.observed);
        // Never overlap the built-in refresh daemon or another attempt.
        let controller_lock = open_private_lock(&self.refresh_dir.join("controller.lock"))?;
        if let Err(error) = controller_lock.try_lock_exclusive() {
            if error.kind() == std::io::ErrorKind::WouldBlock
                && self
                    .store
                    .current_for_head_probe()
                    .ok()
                    .flatten()
                    .is_some_and(|g| g.manifest.kernel_v2.is_some())
            {
                return Ok(StandbyDeltaOutcome::Deferred {
                    reason: "refresh_in_progress",
                });
            }
            return Err(error.into());
        }
        let attempt_lock = open_private_lock(&self.refresh_dir.join("attempt.lock"))?;
        if let Err(error) = attempt_lock.try_lock_exclusive() {
            if error.kind() == std::io::ErrorKind::WouldBlock
                && self
                    .store
                    .current_for_head_probe()
                    .ok()
                    .flatten()
                    .is_some_and(|g| g.manifest.kernel_v2.is_some())
            {
                return Ok(StandbyDeltaOutcome::Deferred {
                    reason: "refresh_in_progress",
                });
            }
            return Err(error.into());
        }
        let bearer =
            read_credential(&self.config.credential_file).map_err(|error| *error.source)?;
        let Some(current) = self.store.current_for_head_probe().ok().flatten() else {
            if let Some(reason) = self
                .revision_pause_needed(&bearer)
                .await
                .map_err(|error| *error.source)?
            {
                return Ok(StandbyDeltaOutcome::Deferred { reason });
            }
            return Ok(StandbyDeltaOutcome::FullRefreshRequired {
                reason: DeltaFallbackClass::UntrustedLocalBase,
            });
        };
        let attempt = self
            .try_delta_attempt(&bearer, current)
            .await
            .map_err(|error| *error.source)?;
        Ok(match attempt {
            DeltaAttempt::Unchanged(generation) => StandbyDeltaOutcome::Unchanged {
                head_act: self
                    .store
                    .generation_head(&generation.id)?
                    .map_or(generation.manifest.head_act.unwrap_or_default(), |head| {
                        head.head_act
                    }),
                generation_id: generation.id,
            },
            DeltaAttempt::Advanced {
                generation,
                head_act,
            } => StandbyDeltaOutcome::Advanced {
                generation_id: generation.id,
                head_act,
            },
            DeltaAttempt::Deferred { reason, .. } => StandbyDeltaOutcome::Deferred { reason },
            DeltaAttempt::FallBackToSnapshot(diagnostic)
            | DeltaAttempt::ShapeTransition(diagnostic) => {
                StandbyDeltaOutcome::FullRefreshRequired {
                    reason: diagnostic.class,
                }
            }
            // A revision pause is not a snapshot request: the external
            // scheduler must wait, not capture.
            DeltaAttempt::Paused(_, reason) => StandbyDeltaOutcome::Deferred { reason },
        })
    }

    pub fn new(
        runtime: StandbyRuntimeConfig,
        config: StandbyRefreshConfig,
        store: GenerationStore,
        observed: ObservedInstalledConsumerIdentity,
    ) -> Result<Self> {
        Self::new_with_install_key(runtime, config, store, observed, None)
    }

    fn new_with_install_key(
        runtime: StandbyRuntimeConfig,
        config: StandbyRefreshConfig,
        store: GenerationStore,
        observed: ObservedInstalledConsumerIdentity,
        install_key: Option<crate::node_credential::InstallKey>,
    ) -> Result<Self> {
        runtime.validate()?;
        config.validate()?;
        let refresh_dir = runtime.replica_root.join("refresh");
        create_private_directory(&refresh_dir)?;
        #[cfg(any(test, feature = "v2-kernel-probe"))]
        store.set_audit_interval(config.audit_interval());
        let pending_observer = RefreshHints::default();
        let mut client = HttpSnapshotPageClient::new()?;
        client.compatibility = pending_observer.compatibility();
        client.install_key = install_key.clone();
        let mut binary_client = binary::HttpBinarySnapshotClient::new()?;
        binary_client.compatibility = pending_observer.compatibility();
        binary_client.install_key = install_key.clone();
        Ok(Self {
            install_key,
            #[cfg(test)]
            attempt_timeout: None,
            pending_observer,
            runtime,
            config,
            store,
            observed,
            route_kernel_v2: std::sync::atomic::AtomicBool::new(false),
            refresh_dir,
            busy_backoff: std::sync::Mutex::new(BusyExportBackoff::default()),
            follow_heartbeat: Arc::new(FollowHeartbeat::new()),
            proof_audit: std::sync::Mutex::new(ProofAudit::default()),
            client: Arc::new(client),
            binary_client: Arc::new(binary_client),
            binary_snapshot_enabled: true,
            delta_enabled: true,
            #[cfg(test)]
            transfer_pause: std::sync::Mutex::new(None),
            #[cfg(test)]
            kernel_available_space: None,
            #[cfg(test)]
            kernel_in_place_crash: None,
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
        controller.binary_snapshot_enabled = false;
        // Existing snapshot-controller fixtures intentionally exercise the
        // legacy path in isolation. Dedicated delta tests cover the new path.
        controller.delta_enabled = false;
        // Fixtures replace copies back to back; the interval test sets its own.
        controller
            .config
            .full_refresh_min_interval_seconds
            .get_or_insert(0);
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

    /// Whether the daemon must skip starting attempts: hosted plausibly still
    /// runs a delta export for this account, so a fresh start would only hit
    /// the same busy lease. The durable triggers stay in place and fire once
    /// the hold lapses.
    fn busy_backoff_active(&self) -> bool {
        self.busy_backoff.lock().is_ok_and(|backoff| {
            backoff
                .until
                .is_some_and(|until| tokio::time::Instant::now() < until)
        })
    }

    /// Hold fresh starts for a short bounded backoff: hosted's `retry-after`
    /// hint when it sent one, else a few seconds, doubling toward the cap on
    /// consecutive busy failures. Never persisted and never a read block —
    /// the node keeps serving its last copy throughout.
    fn note_busy_export(&self, retry_after: Option<Duration>) {
        let base = retry_after.unwrap_or(EXPORT_BUSY_BASE_BACKOFF);
        let Ok(mut backoff) = self.busy_backoff.lock() else {
            return;
        };
        let shift = backoff.consecutive.min(5);
        let delay = base
            .saturating_mul(1 << shift)
            .min(EXPORT_BUSY_MAX_BACKOFF)
            .max(Duration::from_secs(1));
        backoff.consecutive = backoff.consecutive.saturating_add(1);
        backoff.until = Some(tokio::time::Instant::now() + delay);
    }

    /// A non-busy outcome means hosted answered: drop any busy hold.
    fn clear_busy_export(&self) {
        if let Ok(mut backoff) = self.busy_backoff.lock() {
            *backoff = BusyExportBackoff::default();
        }
    }

    /// How long the busy-export hold still has to run, if armed. Lock-only:
    /// no filesystem or clock work beyond reading the deadline.
    fn busy_backoff_remaining(&self) -> Option<Duration> {
        self.busy_backoff.lock().ok().and_then(|backoff| {
            backoff
                .until
                .map(|until| until.saturating_duration_since(tokio::time::Instant::now()))
        })
    }

    /// Durable, payload-free trigger seam for wake/network recovery and the
    /// future admitted-write hook. All causes coalesce while one attempt runs.
    pub fn request_refresh(&self, cause: RefreshCause) -> Result<bool> {
        let lock = open_private_lock(&self.refresh_dir.join("trigger.lock"))?;
        lock_exclusive_bounded(&lock, LOCK_WAIT_TIMEOUT)?;
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
                if state.contract != STATE_CONTRACT
                    || state.version != 1
                    || state
                        .transfer_progress
                        .as_ref()
                        .is_some_and(|progress| !progress.valid(state.refresh_active))
                {
                    return Err(Error::engine("invalid standby refresh state"));
                }
                state
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                StandbyRefreshState::default()
            }
            Err(error) => return Err(error.into()),
        };
        // A damaged advisory sidecar cannot erase durable scheduling state.
        // Status readers reject it; the controller retains the valid primary
        // state and can replace the observation on its next phase transition.
        let _ = transfer_progress::merge_observation(&self.refresh_dir, &mut state);
        state.manual_refresh_pending = self
            .read_pending_triggers()?
            .causes
            .contains(&RefreshCause::Manual);
        Ok(state)
    }

    pub async fn refresh_once(&self, cause: RefreshCause) -> Result<StandbyRefreshOutcome> {
        self.refresh_once_with_receipt(cause)
            .await
            .map_err(|failure| failure.source)
    }

    pub async fn refresh_once_with_receipt(
        &self,
        cause: RefreshCause,
    ) -> std::result::Result<StandbyRefreshOutcome, RefreshAttemptFailure> {
        #[cfg(test)]
        let timeout = self.attempt_timeout.unwrap_or(ATTEMPT_TIMEOUT);
        #[cfg(not(test))]
        let timeout = ATTEMPT_TIMEOUT;
        self.refresh_once_receipt_with_timeout(cause, timeout).await
    }

    /// One-shot CLI scheduling boundary: daemon-lock/recovery and trigger
    /// failures receive this invocation's receipt too.
    pub async fn refresh_or_request_with_receipt(
        &self,
        cause: RefreshCause,
    ) -> std::result::Result<StandbyRefreshOutcome, RefreshAttemptFailure> {
        let mut progress = AttemptProgress::new(cause);
        let span = tracing::info_span!(target: "native_ce::standby::transport",
            "standby_refresh", attempt_id = %progress.receipt.attempt_id, cause = ?cause);
        let result = async {
            if let Some(_guard) = self.try_acquire_daemon()? {
                self.refresh_once_inner(cause, ATTEMPT_TIMEOUT, &mut progress)
                    .await
            } else {
                let coalesced = !self.request_refresh(cause)?;
                tracing::info!(
                    target: FOLLOW_LOG_TARGET,
                    cause = ?cause,
                    coalesced,
                    "standby refresh coalesced: the daemon holds the acquisition, so this caller is represented by its attempt"
                );
                Ok(StandbyRefreshOutcome::Accepted { coalesced })
            }
        }
        .instrument(span)
        .await;
        result.map_err(|source| {
            progress.diagnose_boundary(&source);
            RefreshAttemptFailure {
                receipt: Box::new(progress.receipt),
                source,
            }
        })
    }

    async fn refresh_once_receipt_with_timeout(
        &self,
        cause: RefreshCause,
        timeout: Duration,
    ) -> std::result::Result<StandbyRefreshOutcome, RefreshAttemptFailure> {
        let mut progress = AttemptProgress::new(cause);
        let span = tracing::info_span!(target: "native_ce::standby::transport",
            "standby_refresh", attempt_id = %progress.receipt.attempt_id, cause = ?cause);
        self.refresh_once_inner(cause, timeout, &mut progress)
            .instrument(span)
            .await
            .map_err(|source| {
                progress.diagnose_boundary(&source);
                RefreshAttemptFailure {
                    receipt: Box::new(progress.receipt),
                    source,
                }
            })
    }

    async fn refresh_once_inner(
        &self,
        cause: RefreshCause,
        timeout: Duration,
        progress: &mut AttemptProgress,
    ) -> Result<StandbyRefreshOutcome> {
        let _verification_retry = self.store.retry_verification_after_refresh(&self.observed);
        let attempt_lock = open_private_lock(&self.refresh_dir.join("attempt.lock"))?;
        if let Err(error) = attempt_lock.try_lock_exclusive() {
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(error.into());
            }
            let coalesced = !self.request_refresh(cause)?;
            tracing::info!(
                target: FOLLOW_LOG_TARGET,
                cause = ?cause,
                coalesced,
                "standby refresh coalesced: another holder owns the attempt, so this caller is represented by its acquisition"
            );
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
        state.transfer_progress = Some(StandbyTransferProgress::following());
        transfer_progress::clear_observation(&self.refresh_dir)?;
        state.last_attempt_id = Some(progress.receipt.attempt_id.to_string());
        state.last_attempt_at = Some(attempted_at);
        state.last_attempt_cause = Some(cause);
        state.last_failure_class = None;
        state.last_failure = None;
        state.last_delta_fallback_class = None;
        state.last_delta_fallback = None;
        self.write_state(&state)?;

        let _activity = transfer_progress::AttemptActivity::new(self, progress.receipt.attempt_id);
        let _pending = crate::async_diagnostics::Pending::new("refresh.attempt");

        // The attempt includes snapshot import and delta verification. Keep its
        // state on the heap instead of enlarging every refresh/daemon caller.
        let result = {
            let attempt =
                tokio::time::timeout(timeout, Box::pin(self.run_attempt(cause, progress)));
            tokio::pin!(attempt);
            tokio::select! {
                result = &mut attempt => result.ok(),
                _ = self.follow_heartbeat.expired.notified() => None,
            }
        };
        let outcome = match result {
            Some(outcome) => outcome,
            None => {
                let error = AttemptError::new(
                    RefreshFailureClass::Timeout,
                    "standby refresh attempt exceeded its time bound",
                    Error::engine("standby refresh attempt timed out"),
                )
                .with_detail("attempt_timeout")
                .with_check("attempt_timeout");
                Err(error)
            }
        };
        // Progress updates read/merge state independently. Preserve the latest
        // observation without replacing a primary failure with a read error.
        if let Ok(latest) = self.state() {
            state.transfer_progress = latest.transfer_progress;
        }
        state.refresh_active = false;
        self.settle_transfer_progress(
            &mut state,
            matches!(
                &outcome,
                Ok(AttemptSuccess::Installed { .. }
                    | AttemptSuccess::Advanced { .. }
                    | AttemptSuccess::Unchanged(_))
            ),
        );
        if let Some(started) = &progress.full_started_at {
            state.last_full_refresh_at = Some(started.clone());
        }
        if outcome.is_ok() {
            progress.receipt.phase = RefreshAttemptPhase::Persistence;
        }
        state.last_deferral = None;
        state.next_full_refresh_eligible_at = None;
        state.active_candidate_generation_id = None;
        state.active_candidate_captured_at = None;
        state.active_candidate_completed_at = None;
        state.active_candidate_frontier = None;
        // write_state merges pending triggers; do not lose the primary failure
        // to another fallible read before its diagnostic is emitted.
        match outcome {
            Ok(AttemptSuccess::Installed {
                generation,
                retention_warnings,
                delta_fallback,
            }) => {
                state.last_success_at = Some(now());
                state.installed_generation_id = Some(generation.id.clone());
                state.snapshot_captured_at = Some(generation.manifest.captured_at.clone());
                state.snapshot_completed_at =
                    Some(generation.manifest.snapshot_completed_at.clone());
                state.promoted_at = Some(now());
                state.frontier = Some(generation.manifest.frontier.clone());
                // Best effort: a missed marker only delays the next repair.
                let _ = self.record_full_outcome(true);
                state.consecutive_failure_count = 0;
                self.clear_busy_export();
                state.last_failure_class = None;
                state.last_failure = None;
                set_delta_fallback(&mut state, delta_fallback);
                self.write_state(&state)?;
                Ok(StandbyRefreshOutcome::Installed {
                    generation: Box::new(generation),
                    retention_warnings,
                })
            }
            Ok(AttemptSuccess::Advanced {
                generation,
                head_act,
            }) => {
                state.last_success_at = Some(now());
                state.installed_generation_id = Some(generation.id.clone());
                state.snapshot_captured_at = Some(generation.manifest.captured_at.clone());
                state.snapshot_completed_at =
                    Some(generation.manifest.snapshot_completed_at.clone());
                state.frontier = Some(generation.manifest.frontier.clone());
                state.consecutive_failure_count = 0;
                self.clear_busy_export();
                state.last_failure_class = None;
                state.last_failure = None;
                set_delta_fallback(&mut state, None);
                self.write_state(&state)?;
                Ok(StandbyRefreshOutcome::Advanced {
                    generation: Box::new(generation),
                    head_act,
                })
            }
            Ok(AttemptSuccess::Deferred {
                generation,
                reason,
                delta_fallback,
            }) => {
                state.last_deferral = Some(reason.into());
                state.next_full_refresh_eligible_at = progress.full_eligible_at.clone();
                self.clear_busy_export();
                set_delta_fallback(&mut state, delta_fallback);
                self.write_state(&state)?;
                Ok(StandbyRefreshOutcome::Deferred {
                    generation: Box::new(generation),
                    reason,
                })
            }
            Ok(AttemptSuccess::Unchanged(generation)) => {
                state.last_success_at = Some(now());
                state.installed_generation_id = Some(generation.id.clone());
                state.snapshot_captured_at = Some(generation.manifest.captured_at.clone());
                state.snapshot_completed_at =
                    Some(generation.manifest.snapshot_completed_at.clone());
                state.frontier = Some(generation.manifest.frontier.clone());
                state.consecutive_failure_count = 0;
                self.clear_busy_export();
                state.last_failure_class = None;
                state.last_failure = None;
                set_delta_fallback(&mut state, None);
                self.write_state(&state)?;
                Ok(StandbyRefreshOutcome::Unchanged {
                    generation: Box::new(generation),
                })
            }
            Err(error) => {
                // A busy hosted export is routine scheduling, not a fault:
                // keep the trigger and back off, and leave the failure count
                // alone so status never reads it as an outage. A poll this
                // node gave up on while hosted may still run it still counts:
                // a five-minute patience expiring is genuinely ambiguous.
                if error.class == RefreshFailureClass::Throttled
                    && error.detail == EXPORT_BUSY_DETAIL
                {
                    self.note_busy_export(error.retry_after);
                    let _ = self.request_refresh(cause);
                } else {
                    state.consecutive_failure_count =
                        state.consecutive_failure_count.saturating_add(1);
                    if error.detail == EXPORT_CAPTURE_TIMEOUT_DETAIL {
                        self.note_busy_export(None);
                        let _ = self.request_refresh(cause);
                    } else {
                        self.clear_busy_export();
                    }
                }
                state.last_failure_class = Some(error.class);
                state.last_failure = Some(error.safe_message.into());
                set_delta_fallback(&mut state, error.delta_fallback);
                // Only a real whole-snapshot failure updates the separate
                // FULL slot: the invocation marker records when FULL actually
                // starts, so delta-only and throttle failures cannot
                // overwrite it. The retained detail is the allowlisted
                // fence/check identifier only — never raw source text.
                if progress.receipt.phase == RefreshAttemptPhase::Full {
                    state.last_full_failure_attempt_id =
                        Some(progress.receipt.attempt_id.to_string());
                    state.last_full_failure_at = Some(now());
                    state.last_full_failure_class = Some(error.class);
                    state.last_full_failure = Some(error.safe_message.into());
                    state.last_full_failure_detail =
                        Some(error.check.unwrap_or(UNCLASSIFIED_CHECK).into());
                    state.last_full_failure_cause = Some(cause);
                }
                // Emit the safe original diagnostic before persistence: a
                // disk, permission or sync failure must neither suppress it
                // nor replace it. Persistence trouble is logged separately.
                progress.diagnose(&error);
                if self.write_state(&state).is_err() {
                    eprintln!("native-standby-refresh: refresh state persistence failed");
                    tracing::error!("standby refresh state persistence failed");
                }
                Err(*error.source)
            }
        }
    }

    /// Hold the supplied lifetime lock, service durable triggers, and keep
    /// cadence anchored to absolute deadlines. A deadline missed during an
    /// attempt produces one immediate follow-up, never a catch-up burst.
    pub async fn run_daemon_after_startup(
        &self,
        guard: StandbyRefreshDaemonGuard,
        shutdown: watch::Receiver<bool>,
    ) {
        // The required audit is its own schedule, on the same tick source: an
        // attempt that sits in a download, a delta, a disk-space deferral or a
        // cooldown never delays it, and it never delays an attempt.
        #[cfg(any(test, feature = "v2-kernel-probe"))]
        let audit = crate::async_diagnostics::track(
            "refresh.audit_loop",
            self.run_audit_loop(shutdown.clone()),
        );
        #[cfg(not(any(test, feature = "v2-kernel-probe")))]
        let audit = async {};
        tokio::join!(self.run_follow_loop(guard, shutdown), audit);
    }

    async fn run_follow_loop(
        &self,
        _guard: StandbyRefreshDaemonGuard,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut poll = tokio::time::interval(MANUAL_POLL_INTERVAL);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let interval = refresh_cadence(&self.config);
        let mut scheduled = tokio::time::Instant::now() + interval;
        let mut startup_pending = true;
        let mut last_monotonic = tokio::time::Instant::now();
        let mut last_wall = SystemTime::now();
        let mut network_probe_at = None;
        // Scheduler-health bookkeeping only: loop-local Instants and a latch,
        // never persisted, so older builds keep parsing state strictly.
        let mut last_attempt_start: Option<tokio::time::Instant> = None;
        let mut stall_warned = false;
        let mut last_busy_skip_log: Option<tokio::time::Instant> = None;
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { break; }
                }
                _ = poll.tick() => {
                    let now = tokio::time::Instant::now();
                    let wall = SystemTime::now();
                    let monotonic_elapsed = now.saturating_duration_since(last_monotonic);
                    let wall_elapsed = wall.duration_since(last_wall).unwrap_or_default();
                    let woke = elapsed_indicates_wake(wall_elapsed, monotonic_elapsed);
                    last_monotonic = now;
                    last_wall = wall;
                    // The loop is alive on this tick even when it starts
                    // nothing: stamp first so the watchdog only fires on a
                    // genuinely parked scheduler.
                    self.follow_heartbeat.note_tick();
                    if self.busy_backoff_active() {
                        // Hosted plausibly still runs an export for this
                        // account: leave the durable triggers in place and
                        // retry after the backoff instead of firing a fresh
                        // start into the same busy lease.
                        if busy_skip_log_due(now, last_busy_skip_log, interval) {
                            last_busy_skip_log = Some(now);
                            tracing::info!(
                                target: FOLLOW_LOG_TARGET,
                                hold_remaining_secs =
                                    self.busy_backoff_remaining().map(|left| left.as_secs()),
                                "standby follow loop skipping tick while the busy-export hold is active; durable triggers stay queued"
                            );
                        }
                        continue;
                    }
                    if !stall_warned {
                        if let Some(stall) =
                            follow_loop_stall_report(now, last_attempt_start, scheduled, interval)
                        {
                            stall_warned = true;
                            tracing::warn!(
                                target: FOLLOW_LOG_TARGET,
                                idle_secs = stall.idle.as_secs(),
                                scheduled_overdue_secs = stall.scheduled_overdue.as_secs(),
                                "standby follow loop resumed after {}s without starting an attempt; scheduled deadline {}s overdue, hosted may be ahead",
                                stall.idle.as_secs(),
                                stall.scheduled_overdue.as_secs()
                            );
                        }
                    }
                    let pending = self.take_pending_triggers().unwrap_or_default();

                    let state_snapshot = self.state().ok();
                    let network_failed = state_snapshot.as_ref().is_some_and(|state| {
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
                        last_attempt_start = Some(now);
                        stall_warned = false;
                        self.follow_heartbeat.note_attempt_start();
                        tracing::info!(
                            target: FOLLOW_LOG_TARGET,
                            cause = ?cause,
                            previous_attempt_at = state_snapshot
                                .as_ref()
                                .and_then(|state| state.last_attempt_at.as_deref())
                                .unwrap_or("never"),
                            "standby follow loop starting refresh attempt"
                        );
                        let attempt = crate::async_diagnostics::track("refresh.scheduled_attempt", self.refresh_once(cause));
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
                        scheduled =
                            next_scheduled_deadline(scheduled, now, completed, cause, interval);
                        let attempt_took = completed.saturating_duration_since(now);
                        if cause == RefreshCause::Scheduled {
                            let attempt_started_at =
                                chrono::DateTime::<chrono::Utc>::from(wall)
                                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                            tracing::info!(
                                target: FOLLOW_LOG_TARGET,
                                last_attempt_at = %attempt_started_at,
                                next_deadline_in_secs =
                                    scheduled.saturating_duration_since(completed).as_secs(),
                                attempt_secs = attempt_took.as_secs(),
                                "standby follow loop scheduler alive: scheduled attempt finished, next deadline anchored"
                            );
                        } else {
                            tracing::info!(
                                target: FOLLOW_LOG_TARGET,
                                cause = ?cause,
                                attempt_secs = attempt_took.as_secs(),
                                "standby follow loop finished refresh attempt"
                            );
                        }
                        if attempt_took > stall_warn_after(interval) {
                            tracing::warn!(
                                target: FOLLOW_LOG_TARGET,
                                cause = ?cause,
                                attempt_secs = attempt_took.as_secs(),
                                "standby follow loop attempt ran well over its cadence; ticks were parked while it ran"
                            );
                        }
                        self.follow_heartbeat.note_attempt_end();
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

    /// Make the store agree with this config about whether audits are
    /// required: the status provider that gates serving reads the store.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    fn apply_audit_policy(&self) {
        self.store.set_audit_interval(self.config.audit_interval());
    }

    /// Run the required audit of the current generation once, now. `Ok(None)`
    /// when none is required or the copy needs none (a staged or immutable
    /// generation); an infrastructure error is returned and recorded nowhere.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    pub(crate) async fn audit_once(
        &self,
    ) -> Result<Option<super::generation_store::kernel_in_place::audit::AuditResult>> {
        use super::generation_store::kernel_in_place::audit::AuditResult;
        self.apply_audit_policy();
        if self.config.audit_interval().is_none() {
            return Ok(None);
        }
        let Some(current) = self.store.current_for_head_probe()? else {
            return Ok(None);
        };
        Ok(
            match self
                .store
                .run_required_audit(&current, &self.observed)
                .await?
            {
                AuditResult::NotApplicable => None,
                other => Some(other),
            },
        )
    }

    /// How long until the current generation's next audit is due: the last
    /// verdict's snapshot time plus the interval, floored at one second.
    ///
    /// Zero (due now) when this process has observed no audit success for the
    /// current generation (a restart, or a new generation), when no at-rest
    /// record exists yet, or when a passed at-rest record was written under a
    /// different receipts DDL than the database now carries (an upgrade
    /// rewrote the chain). The wall-clock record is never used to seed the
    /// in-memory observation. A copy whose latest verdict is a failure keeps
    /// the ordinary schedule: it is waiting for a whole snapshot, not for
    /// another audit.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    pub(crate) async fn next_audit_delay(&self, interval: Duration) -> Duration {
        let Some(current) = self.store.current_for_head_probe().ok().flatten() else {
            return interval;
        };
        let advanced = current.manifest.kernel_v2.is_some()
            && self
                .store
                .generation_head(&current.id)
                .ok()
                .flatten()
                .is_some_and(|head| head.advanced_in_place());
        if !advanced {
            return interval;
        }
        let audit = self.store.generation_audit(&current.id);
        let at_rest = self.store.generation_at_rest(&current.id);
        let failed = audit.as_ref().is_some_and(|record| !record.passed())
            || at_rest.as_ref().is_some_and(|record| !record.passed());
        if !failed {
            let unobserved = self.store.audit_last_success(&current.id).is_none();
            let ddl_changed = match &at_rest {
                None => true,
                Some(record) => self
                    .store
                    .database_receipts_ddl(&current)
                    .await
                    .is_some_and(|ddl| ddl.label() != record.receipts_ddl),
            };
            if unobserved || ddl_changed {
                return Duration::ZERO;
            }
        }
        let delay = match audit {
            None => Duration::ZERO,
            Some(record) => {
                let age = record.acquired().map_or(u64::MAX, |at| {
                    u64::try_from(chrono::Utc::now().signed_duration_since(at).num_seconds())
                        .unwrap_or(0)
                });
                interval.saturating_sub(Duration::from_secs(age))
            }
        };
        delay.max(Duration::from_secs(1))
    }

    /// Audit every N minutes until shutdown, and at once after a start or a
    /// receipts-DDL change. After an infrastructure error it retries with
    /// backoff (10 s doubling, capped at five minutes and at the interval); the
    /// deadline keeps running meanwhile, because only a success moves the
    /// record. An "at once" audit that leaves the copy still due at once (the
    /// record could not advance) is not repeated back to back.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    async fn run_audit_loop(&self, mut shutdown: watch::Receiver<bool>) {
        let mut failures = 0_u32;
        let mut last_was_immediate = false;
        loop {
            self.apply_audit_policy();
            let Some(interval) = self.config.audit_interval() else {
                // Audits are not required: nothing to schedule.
                let _ = shutdown.changed().await;
                return;
            };
            let mut immediate = false;
            let delay = if failures == 0 {
                let due = self.next_audit_delay(interval).await;
                immediate = due.is_zero();
                if immediate && last_was_immediate {
                    Duration::from_secs(60).min(interval)
                } else {
                    due
                }
            } else {
                Duration::from_secs(10)
                    .saturating_mul(1 << failures.saturating_sub(1).min(5))
                    .min(Duration::from_secs(300))
                    .min(interval)
            };
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                    continue;
                }
                _ = tokio::time::sleep(delay) => {}
            }
            match self.audit_once().await {
                Ok(_) => {
                    failures = 0;
                    last_was_immediate = immediate;
                }
                Err(_) => {
                    failures = failures.saturating_add(1);
                    tracing::warn!(
                        target: "native_ce::standby::audit",
                        failures,
                        "required audit hit an infrastructure error; retrying with backoff"
                    );
                }
            }
        }
    }

    fn record_full_start(
        &self,
        progress: &mut AttemptProgress,
    ) -> std::result::Result<(), AttemptError> {
        if progress.transition {
            self.consume_transition_attempt().map_err(local_io)?;
        }
        progress.full_started_at = Some(now());
        let mut state = self.state().map_err(local_io)?;
        state.last_full_refresh_at = progress.full_started_at.clone();
        self.record_full_outcome(false).map_err(local_io)?;
        self.write_state(&state).map_err(local_io)
    }

    async fn run_attempt(
        &self,
        cause: RefreshCause,
        progress: &mut AttemptProgress,
    ) -> std::result::Result<AttemptSuccess, AttemptError> {
        progress.receipt.phase = RefreshAttemptPhase::Following;
        let bearer = read_credential(&self.config.credential_file)?;
        let endpoint = format!(
            "{}/mcp/{}",
            self.config.hosted_origin,
            utf8_percent_encode(&self.runtime.hosted_route_database_id, NON_ALPHANUMERIC)
        );
        let mut delta_fallback = None;
        // The head probe checks pointer/manifest identity, not snapshot bytes.
        // It is only a candidate for the delta path, never proof that the
        // existing generation can safely justify the legacy snapshot path.
        let probe_base = self.store.current_for_head_probe().ok().flatten();
        if self.delta_enabled {
            if let Some(current) = probe_base.clone() {
                match tokio::time::timeout(
                    FOLLOW_ATTEMPT_TIMEOUT,
                    crate::async_diagnostics::track(
                        "refresh.follow_delta",
                        self.try_delta_attempt(&bearer, current),
                    ),
                )
                .await
                .map_err(|_| {
                    AttemptError::new(
                        RefreshFailureClass::Timeout,
                        "standby following attempt exceeded its time bound",
                        Error::engine("standby following attempt timed out"),
                    )
                    .with_detail("attempt_timeout")
                    .with_check("attempt_timeout")
                })?? {
                    DeltaAttempt::Advanced {
                        generation,
                        head_act,
                    } => {
                        return Ok(AttemptSuccess::Advanced {
                            generation,
                            head_act,
                        })
                    }
                    DeltaAttempt::Unchanged(generation) => {
                        return Ok(AttemptSuccess::Unchanged(generation))
                    }
                    DeltaAttempt::Deferred { generation, reason } => {
                        return Ok(AttemptSuccess::Deferred {
                            generation,
                            reason,
                            delta_fallback: None,
                        })
                    }
                    DeltaAttempt::FallBackToSnapshot(diagnostic) => {
                        delta_fallback = Some(diagnostic)
                    }
                    DeltaAttempt::ShapeTransition(diagnostic) => {
                        progress.transition = true;
                        delta_fallback = Some(diagnostic);
                    }
                    DeltaAttempt::Paused(generation, reason) => {
                        return Ok(AttemptSuccess::Deferred {
                            generation,
                            reason,
                            delta_fallback: None,
                        })
                    }
                }
            } else {
                delta_fallback = Some(DeltaFallbackDiagnostic {
                    class: DeltaFallbackClass::UntrustedLocalBase,
                    message: "delta base was unavailable or not immutable",
                });
            }
        }
        // When the delta path did not run, its head probe never ruled on the
        // hosted interchange revision. Probe once before any acquisition —
        // on every cause, including Manual — so a bump pauses here instead
        // of burning a capture the node could never admit. Production FULL
        // acquisition requires a validated compatible head observation.
        let pause = if self.delta_enabled && probe_base.is_some() {
            None
        } else {
            self.revision_pause_needed(&bearer).await?
        };
        if let Some(reason) = pause {
            return match probe_base {
                Some(generation) => Ok(AttemptSuccess::Deferred {
                    generation,
                    reason,
                    delta_fallback,
                }),
                None => Err(AttemptError::new(
                    RefreshFailureClass::RevisionUnsupported,
                    refresh_pause_message(reason),
                    Error::engine(if reason == DEFERRED_REVISION_UNSUPPORTED {
                        "hosted interchange revision is not readable by this build"
                    } else {
                        reason
                    }),
                )),
            };
        }
        #[cfg(any(test, feature = "v2-kernel-probe"))]
        if let Some(current) = probe_base
            .as_ref()
            .filter(|g| g.manifest.kernel_v2.is_some())
        {
            if !self.kernel_has_disk_space(current, 3).map_err(local_io)? {
                return Ok(AttemptSuccess::Deferred {
                    generation: current.clone(),
                    reason: super::generation_store::INSUFFICIENT_DISK,
                    delta_fallback,
                });
            }
        }
        // A retained export spends no new hosted capture: one authorized
        // poll decides. A live handle bypasses the FULL cooldown below
        // without consuming capture budget; a gone handle was already
        // cleared, so the ordinary gate decides between deferral and one
        // fresh export. Other poll failures return through existing paths.
        progress.resume_observation = None;
        let resume_live = match self.probe_binary_resume().await {
            Ok(binary::ResumeProbe::Live(observation)) => {
                progress.resume_observation = Some(*observation);
                true
            }
            Ok(binary::ResumeProbe::Absent) | Ok(binary::ResumeProbe::Gone) => false,
            Err(error) => return Err(error),
        };
        // A whole snapshot costs a database-sized capture on hosted Native.
        // Ordinary fallbacks wait since the previous start. Failed repairs
        // wait since failure completion so even a slow failure gets a pause.
        // A first install is never held back, but its start is recorded too.
        // Compute new-capture eligibility independently of handle liveness.
        let capture_allowed = {
            // Only this attempt's observed edge grants the exception. Retain
            // the durable budget receipt through a hosted reversion so head
            // churn cannot refill the cap; the receipt grants no exception.
            if progress.transition {
                if let Some(current) = probe_base.as_ref() {
                    if let Some(eligible) = self.transition_eligible(current).map_err(local_io)? {
                        if eligible > chrono::Utc::now().timestamp_millis() && !resume_live {
                            progress.full_eligible_at =
                                chrono::DateTime::from_timestamp_millis(eligible)
                                    .map(|date| date.to_rfc3339());
                            return Ok(AttemptSuccess::Deferred {
                                generation: current.clone(),
                                reason: "shape_transition_backoff",
                                delta_fallback,
                            });
                        }
                    }
                }
            }
            let state = self.state().map_err(local_io)?;
            let repair = delta_fallback.is_some_and(|diagnostic| {
                matches!(
                    diagnostic.class,
                    DeltaFallbackClass::AuditFailed | DeltaFallbackClass::ConsumerChanged
                )
            });
            let bypass = cause == RefreshCause::Manual
                || progress.transition
                || (repair && !self.last_full_failed());
            let ordinary_minimum = self
                .config
                .full_refresh_min_interval_seconds
                .map_or(DEFAULT_FULL_REFRESH_MIN_INTERVAL, Duration::from_secs);
            let minimum = if repair {
                self.config
                    .full_refresh_repair_retry_seconds
                    .map_or(DEFAULT_FULL_REFRESH_REPAIR_RETRY, Duration::from_secs)
                    .max(Duration::from_secs(60))
                    .min(ordinary_minimum)
            } else {
                ordinary_minimum
            };
            let recent = full_refresh_is_recent(&state, repair, minimum);
            let has_copy = self.store.accepted_identity_hint().ok().flatten().is_some();
            if self.delta_enabled && recent && has_copy && !bypass {
                progress.full_eligible_at = full_refresh_eligible_at(&state, repair, minimum);
                if !resume_live {
                    return match probe_base {
                        Some(generation) => Ok(AttemptSuccess::Deferred {
                            generation,
                            reason: DEFERRED_FULL_REFRESH_INTERVAL,
                            delta_fallback,
                        }),
                        None => Err(AttemptError::new(
                            RefreshFailureClass::Throttled,
                            "standby whole snapshot held back by its minimum interval",
                            Error::engine(
                                "standby whole snapshot held back by its minimum interval",
                            ),
                        )),
                    };
                }
                false
            } else {
                true
            }
        };
        progress.receipt.phase = RefreshAttemptPhase::Full;
        let attempt_id = progress.receipt.attempt_id;
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
        // Every full snapshot uses the bounded binary capture/transfer path,
        // including fallback from a valid local generation. The legacy MCP
        // first page awaits the whole capture under a ten-second HTTP budget;
        // a trusted base does not make a large authority capture any smaller.
        // GenerationStore still verifies both the candidate and current base
        // before promotion. Tests may explicitly select the paged fixture path.
        let budget = if capture_allowed {
            binary::FreshCaptureBudget::Allowed
        } else {
            binary::FreshCaptureBudget::ReuseOnly
        };
        let acquisition = if self.binary_snapshot_enabled {
            self.download_binary_and_install(
                bearer,
                &snapshot_path,
                &manifest_path,
                budget,
                progress,
            )
            .await
        } else {
            self.record_full_start(progress)?;
            self.download_and_install(&endpoint, bearer, &snapshot_path, &manifest_path)
                .await
        };
        // A retained handle lost inside the cooldown refuses creation with
        // Throttled: surface the ordinary gate deferral instead of a failure.
        // The invocation marker records FULL independently of persistence or clocks.
        let (generation, retention_warnings) = match acquisition {
            Err(error) if resume_live && matches!(error.class, RefreshFailureClass::Throttled) => {
                return match self.store.current_for_head_probe().ok().flatten() {
                    Some(generation) => Ok(AttemptSuccess::Deferred {
                        generation,
                        reason: DEFERRED_FULL_REFRESH_INTERVAL,
                        delta_fallback,
                    }),
                    None => Err(match delta_fallback {
                        Some(diagnostic) => error.after_delta_fallback(diagnostic),
                        None => error,
                    }),
                };
            }
            result => result.map_err(|error| match delta_fallback {
                Some(diagnostic) => error.after_delta_fallback(diagnostic),
                None => error,
            })?,
        };
        if self.complete_transition(&generation).is_err() {
            tracing::warn!(target: "native_ce::standby::refresh", "receiver transition cleanup deferred");
        }
        Ok(AttemptSuccess::Installed {
            generation,
            retention_warnings,
            delta_fallback,
        })
    }

    /// Cheap revision gate for paths the delta probe never ruled on: true
    /// when hosted authors an interchange revision this build cannot read.
    /// Production refuses acquisition on all other head errors. Tests that
    /// disable following may use an isolated snapshot client without a head server.
    async fn revision_pause_needed(
        &self,
        bearer: &str,
    ) -> std::result::Result<Option<&'static str>, AttemptError> {
        let transport = AuthorityActTransport::new_with_install_key(
            &self.config.hosted_origin,
            &self.runtime.hosted_route_database_id,
            &self.runtime.origin_database_id,
            bearer,
            self.pending_observer.compatibility(),
            self.install_key.clone(),
        )
        .map_err(classify_delta_transport_error)?;
        match crate::async_diagnostics::track("refresh.hosted_head", transport.head()).await {
            Ok(head) => {
                self.route_kernel_v2.store(
                    head.head().is_kernel_v2(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                Ok(head.refresh_pause_reason())
            }
            Err(error) if crate::standby::is_revision_unsupported(&error) => {
                Ok(Some(DEFERRED_REVISION_UNSUPPORTED))
            }
            Err(Error::Engine(detail))
                if detail == crate::client_compatibility::UPDATE_REQUIRED =>
            {
                Err(classify_delta_transport_error(Error::Engine(detail)))
            }
            Err(error) if self.delta_enabled => Err(classify_delta_transport_error(error)),
            Err(_) => Ok(None),
        }
    }

    async fn try_delta_attempt(
        &self,
        bearer: &str,
        current: InstalledGeneration,
    ) -> std::result::Result<DeltaAttempt, AttemptError> {
        // Conservative freshness boundary: sampled before the hosted probe.
        let synced_at = now();
        // Observe hosted compatibility before any local fallback can request FULL.
        let transport = AuthorityActTransport::new_with_install_key(
            &self.config.hosted_origin,
            &self.runtime.hosted_route_database_id,
            &self.runtime.origin_database_id,
            bearer,
            self.pending_observer.compatibility(),
            self.install_key.clone(),
        )
        .map_err(classify_delta_transport_error)?;
        let remote_head =
            match crate::async_diagnostics::track("refresh.hosted_head", transport.head()).await {
                Ok(head) => head,
                Err(Error::Engine(reason)) if reason == super::shapes::UNSUPPORTED => {
                    return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                        class: DeltaFallbackClass::HeadCompatibility,
                        message: "hosted receiver shape is unknown; a whole snapshot is required",
                    }));
                }
                // An unreadable interchange revision pauses following here: it
                // must never become a HeadCompatibility whole-snapshot fallback.
                Err(error) if crate::standby::is_revision_unsupported(&error) => {
                    return Ok(DeltaAttempt::Paused(current, DEFERRED_REVISION_UNSUPPORTED))
                }
                Err(error) => return Err(classify_delta_transport_error(error)),
            };
        self.route_kernel_v2.store(
            remote_head.head().is_kernel_v2(),
            std::sync::atomic::Ordering::Relaxed,
        );
        if let Some(reason) = remote_head.refresh_pause_reason() {
            return Ok(DeltaAttempt::Paused(current, reason));
        }
        if remote_head.head().is_kernel_v2() != current.manifest.kernel_v2.is_some() {
            return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                class: DeltaFallbackClass::HeadCompatibility,
                message: "upstream engine changed; a fresh generation is required",
            }));
        }
        if let super::delta_transport::AuthorityHead::KernelV2(remote) = remote_head.head() {
            if current.manifest.kernel_v2.as_ref().is_some_and(|local| {
                local.schema_sha256 != remote.generation.schema_sha256
                    || local.reader_format != remote.generation.reader_format
            }) {
                if let (Some(from), Some(to)) = (
                    super::shapes::manifest(&current.manifest),
                    super::shapes::v2(
                        remote.generation.reader_format,
                        &remote.generation.schema_sha256,
                    ),
                ) {
                    if super::shapes::follows(from, to) {
                        self.observe_transition(from, to).map_err(local_io)?;
                        return Ok(DeltaAttempt::ShapeTransition(DeltaFallbackDiagnostic {
                            class: DeltaFallbackClass::HeadCompatibility,
                            message: "receiver shape changed; a staged whole snapshot is required",
                        }));
                    }
                }
                return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                    class: DeltaFallbackClass::HeadCompatibility,
                    message: "receiver shape changed; a staged whole snapshot is required",
                }));
            }
        }
        if let Some(selected) = transport.selected_shapes().0 {
            if let (Some(from), Some(to)) = (
                super::shapes::manifest(&current.manifest),
                super::shapes::lookup(&selected),
            ) {
                if from.shape() != to.shape() {
                    if super::shapes::follows(from, to) {
                        self.observe_transition(from, to).map_err(local_io)?;
                        return Ok(DeltaAttempt::ShapeTransition(DeltaFallbackDiagnostic {
                            class: DeltaFallbackClass::HeadCompatibility,
                            message: "receiver shape changed; a staged whole snapshot is required",
                        }));
                    }
                    return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                        class: DeltaFallbackClass::HeadCompatibility,
                        message: "receiver shape changed; a staged whole snapshot is required",
                    }));
                }
            }
        }
        // New v1 dialects require an explicit authenticated selection even for
        // an equal-head probe. A missing signal cannot refresh a95 copy's age
        // or become a legacy94 fallback merely because no rows changed.
        if current.manifest.kernel_v2.is_none()
            && super::shapes::manifest(&current.manifest).is_some_and(|entry| {
                entry.observation_envelope
                    && transport.selected_shapes().0.as_ref() != Some(&entry.shape())
            })
        {
            return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                class: DeltaFallbackClass::HeadCompatibility,
                message: "receiver dialect requires explicit shape selection; a whole snapshot is required",
            }));
        }
        // A same-format replacement can re-verify and bind the existing copy
        // locally. Any format/evidence failure keeps the consumer_changed FULL.
        // The serving copy is re-bound without a whole-file pass when it
        // qualifies for trust at rest; anything else runs every check.
        if let Err(error) = self
            .store
            .ensure_consumer_binding_depth(&current.id, &self.observed, true)
            .await
        {
            if super::generation_store::audit_infrastructure_error(&error) {
                return Err(local_io(error));
            }
            return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                class: DeltaFallbackClass::ConsumerChanged,
                message: "installed consumer changed; a whole snapshot is required",
            }));
        }
        let verified_base = self
            .store
            .verified_refresh_base(&current.id, &self.observed);
        let head = match self.store.generation_head(&current.id) {
            Ok(head) => head,
            Err(_) => {
                return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                    class: DeltaFallbackClass::UntrustedLocalBase,
                    message: "local copy head record was unreadable; a whole snapshot is required",
                }))
            }
        };
        // This precedes the equal-head/no-op fast path: a freshly synced v1
        // generation can still lack historical issuance authority and links.
        if head
            .as_ref()
            .is_some_and(|head| head.needs_projection_recovery())
        {
            return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                class: DeltaFallbackClass::UntrustedLocalBase,
                message:
                    "v1 delta copy requires authority/link recovery; a whole snapshot is required",
            }));
        }
        if head.as_ref().is_some_and(|head| head.full_refresh_required) {
            return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                class: DeltaFallbackClass::AuditFailed,
                message: "an audit of the local copy failed; a whole snapshot is required",
            }));
        }
        if head.as_ref().is_some_and(|head| head.advanced_in_place())
            && sqlite_journal_path(&current.snapshot_path).exists()
        {
            // An interrupted delta left its rollback journal. Opening the
            // writer rolls it back before the read-only head probe below.
            match crate::async_diagnostics::track("refresh.open_writer", self.store.open_head_writer(&current)).await {
                Ok(Some(writer)) => writer.close().await,
                _ => {
                    return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                        class: DeltaFallbackClass::UntrustedLocalBase,
                        message:
                            "local copy could not recover an interrupted delta; a whole snapshot is required",
                    }))
                }
            }
        }
        #[cfg(any(test, feature = "v2-kernel-probe"))]
        if let super::delta_transport::AuthorityHead::KernelV2(remote) = remote_head.head() {
            let attempt = self
                .try_kernel_delta(&transport, current, remote, &synced_at)
                .await;
            // A copy that could not take its delta is trouble: the next follow
            // carries the projection proof (a whole snapshot is on its way).
            if matches!(attempt, Ok(DeltaAttempt::FallBackToSnapshot(_))) {
                self.proof_audit.lock().expect("proof audit").trouble = true;
            }
            return attempt;
        }
        let local_head = match read_authority_act_head_from_path(&current.snapshot_path).await {
            Ok(head) => head,
            Err(_) => {
                return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                    class: DeltaFallbackClass::UntrustedLocalBase,
                    message: "local copy act head could not be read; a whole snapshot is required",
                }))
            }
        };

        if remote_head.head().matches_authority_head(&local_head) {
            self.store
                .record_synced(&current, local_head.head_act, &synced_at)
                .map_err(local_io)?;
            self.store.complete_validated_refresh(
                &current.id,
                &self.observed,
                verified_base,
                local_head.head_act,
                false,
            );
            return Ok(DeltaAttempt::Unchanged(current));
        }
        if remote_head.head().head_act() < local_head.head_act {
            return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                class: DeltaFallbackClass::RemoteHeadRegression,
                message: "hosted delta head regressed behind the installed generation",
            }));
        }

        // A delta rewrites the file the serving process reads. Only a build
        // that opens it as an ordinary (not immutable) SQLite file may be
        // serving it, so wait until such a build has opened this generation.
        if !self
            .store
            .served_by_build(&current.id, &self.observed.source_sha)
        {
            self.store
                .note_deferral(&current.id, DeltaDeferral::ReaderNotUpgraded, true);
            return Ok(DeltaAttempt::Deferred {
                generation: current,
                reason: DEFERRED_READER_NOT_UPGRADED,
            });
        }
        self.store
            .note_deferral(&current.id, DeltaDeferral::ReaderNotUpgraded, false);

        // A successful authenticated head probe established connectivity and
        // origin binding. Any exact-cut refusal from here is a typed request
        // to take the whole-snapshot path (oversize, incompatible pins,
        // identity movement, or an unrepresentable gap).
        let delta = match crate::async_diagnostics::track("refresh.fetch_delta", transport.delta(local_head.head_act)).await {
            Ok(delta) => delta,
            Err(Error::Auth(message)) => {
                return Err(AttemptError::new(
                    RefreshFailureClass::Authentication,
                    "hosted delta authentication was refused",
                    Error::Auth(message),
                ))
            }
            // Too large for a delta transfer is a typed reason of its own: the
            // cut itself is the problem, not integrity, so say so.
            Err(error) if super::delta_transport::is_delta_too_large(&error) => {
                return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                    class: DeltaFallbackClass::DeltaTooLarge,
                    message: "hosted delta exceeds the delta transfer ceiling; a whole snapshot is required",
                }))
            }
            Err(error) => {
                let mut classified = classify_delta_transport_error(error);
                if classified.class == RefreshFailureClass::Throttled {
                    // Only a busy export classifies as Throttled here: fail
                    // the attempt for a bounded retry, never a whole snapshot.
                    classified.retry_after = transport.take_busy_retry_after();
                }
                if matches!(
                    classified.class,
                    RefreshFailureClass::Authentication
                        | RefreshFailureClass::Network
                        | RefreshFailureClass::Throttled
                ) || matches!(classified.source.as_ref(), Error::Engine(detail)
                    if detail == crate::client_compatibility::UPDATE_REQUIRED) {
                    return Err(classified);
                }
                let rpc_refusal = classified.source.to_string().contains("RPC error")
                    || classified.source.to_string().contains("response too large");
                return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                    class: if rpc_refusal {
                        DeltaFallbackClass::DeltaUnavailable
                    } else {
                        DeltaFallbackClass::IntegrityOrApplyRefusal
                    },
                    message: if rpc_refusal {
                        "hosted delta was unavailable; a whole snapshot is required"
                    } else {
                        "hosted delta failed integrity validation; a whole snapshot is required"
                    },
                }));
            }
        };

        // Format proof is a pre-writer gate. Missing wire identity is a
        // bounded legacy-94 dialect, never evidence of a remote schema.
        let dialect = async {
            let entry = super::shapes::manifest(&current.manifest)
                .filter(|e| e.family == super::shapes::Family::V1)
                .ok_or_else(|| Error::engine("unsupported v1 receiver shape"))?;
            let (head, cut) = transport.selected_shapes();
            match (head, cut) {
                (Some(head), Some(cut)) if head == cut && cut == entry.shape() => {}
                (None, None) if entry.engine_schema == 94 => {}
                _ => {
                    return Err(Error::engine(
                        "delta shape is missing, incompatible, or changed after the head",
                    ))
                }
            }
            super::shapes::check_v1_cut(delta.act_cut(), entry).await
        }
        .await;
        if dialect.is_err() {
            return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                class: DeltaFallbackClass::HeadCompatibility,
                message: "delta does not match the selected exact receiver dialect; a whole snapshot is required",
            }));
        }

        // Apply in place. The materialiser checks contiguity (the delta starts
        // exactly at this copy's head), origin and pins, destination schema,
        // and its exact postconditions inside one write transaction; any
        // refusal rolls the whole transaction back.
        let writer =
            match crate::async_diagnostics::track(
                "refresh.open_writer",
                self.store.open_head_writer(&current),
            )
            .await
            {
                Ok(Some(writer)) => writer,
                Ok(None) => {
                    return Ok(DeltaAttempt::Deferred {
                        generation: current,
                        reason: DEFERRED_CHECKPOINT_VERIFYING,
                    })
                }
                Err(_) => return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                    class: DeltaFallbackClass::UntrustedLocalBase,
                    message:
                        "local copy could not be opened for a delta; a whole snapshot is required",
                })),
            };
        let applied = apply_authority_act_delta_and_finalize_head(&writer, &delta).await;
        writer.close().await;
        match applied {
            Ok(_) => {
                let notice = self.pending_observer.begin_accepted();
                let head_act = delta.to_inclusive_act();
                self.store
                    .record_synced(&current, head_act, &synced_at)
                    .map_err(local_io)?;
                self.store.complete_validated_refresh(
                    &current.id,
                    &self.observed,
                    verified_base,
                    head_act,
                    true,
                );
                self.store
                    .note_deferral(&current.id, DeltaDeferral::DatabaseBusy, false);
                // Accepted publication is complete before any private undo or
                // replay. Cancellation drops the notice and releases the fence;
                // the owner then detects a missing handoff and fully rebuilds.
                if let Some(notice) = notice {
                    notice.committed(current.id.clone(), delta);
                }
                Ok(DeltaAttempt::Advanced {
                    generation: current,
                    head_act,
                })
            }
            Err(Error::Auth(message)) => Err(classify_delta_transport_error(Error::Auth(message))),
            // A reader kept its lock past the writer's wait. The transaction
            // rolled back and the delta is still valid, so try it next tick
            // instead of replacing the copy.
            Err(error) if is_sqlite_busy_or_locked(&error) => {
                self.store
                    .note_deferral(&current.id, DeltaDeferral::DatabaseBusy, true);
                Ok(DeltaAttempt::Deferred {
                    generation: current,
                    reason: DEFERRED_DATABASE_BUSY,
                })
            }
            Err(_) => Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                class: DeltaFallbackClass::IntegrityOrApplyRefusal,
                message: "hosted delta was refused during apply; a whole snapshot is required",
            })),
        }
    }

    #[cfg(any(test, feature = "v2-kernel-probe"))]
    async fn try_kernel_delta(
        &self,
        transport: &AuthorityActTransport,
        current: InstalledGeneration,
        remote: &super::delta_transport::KernelHead,
        synced_at: &str,
    ) -> std::result::Result<DeltaAttempt, AttemptError> {
        let fallback = |message| {
            DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                class: DeltaFallbackClass::IntegrityOrApplyRefusal,
                message,
            })
        };
        let timings = PhaseTimings::default();
        let before = match super::kernel_v2::verify_path(&current.snapshot_path).await {
            Ok(value) => value,
            Err(_) => {
                return Ok(fallback(
                    "kernel-v2 local base is invalid; a whole snapshot is required",
                ))
            }
        };
        timings.lap("verify_base");
        if before.schema_sha256 != remote.generation.schema_sha256
            || before.reader_format != remote.generation.reader_format
        {
            return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                class: DeltaFallbackClass::HeadCompatibility,
                message: "receiver shape changed; a staged whole snapshot is required",
            }));
        }
        // A copy advanced in place is judged by the receipts inside its own
        // database, on every tick and whether or not the flag is still on. A
        // copy that cannot be shown to continue them is never served onward:
        // it is replaced by a whole snapshot.
        let state = match self
            .store
            .check_in_place_integrity(
                &current,
                super::generation_store::kernel_in_place::IntegrityDepth::Light,
            )
            .await
        {
            Ok(state) => state,
            Err(error) if super::generation_store::audit_infrastructure_error(&error) => {
                return Err(local_io(error));
            }
            Err(_) => {
                let _ = self.store.require_full_refresh(&current);
                return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                    class: DeltaFallbackClass::UntrustedLocalBase,
                    message:
                        "in-place copy failed its apply-receipt check; a whole snapshot is required",
                }));
            }
        };
        if let super::generation_store::kernel_in_place::InPlaceState::Sound {
            db_head_act, ..
        } = state
        {
            // The head sidecar is a cache of the database; repair a lag.
            let _ = self.store.heal_head_from_database(&current.id, db_head_act);
        }
        // Count and age limits are evaluated here, so a copy that has gone on
        // long enough is re-checkpointed even when no new delta has arrived.
        let recheckpoint = self.store.kernel_recheckpoint_due(&current, state);
        let verified = self
            .store
            .verified_refresh_base(&current.id, &self.observed);
        // A due audit must not wait for the next write: with the head
        // unchanged, ask for a zero-act delta that carries the projection
        // proof, which compares the projection at the current head. Only the
        // cheap in-place path does this: the staged path copies the whole
        // database for every delta, so there an audit rides on the next real
        // one.
        let idle_audit = before == remote.generation
            && recheckpoint.is_none()
            && self.config.kernel_in_place_deltas
            && self.proof_due()
            && self
                .store
                .kernel_in_place_ineligible(&current, &self.observed, state)
                .is_none();
        if before == remote.generation && recheckpoint.is_none() && !idle_audit {
            self.store
                .record_synced(&current, before.head_act, synced_at)
                .map_err(local_io)?;
            self.store.complete_validated_refresh(
                &current.id,
                &self.observed,
                verified,
                before.head_act,
                false,
            );
            return Ok(DeltaAttempt::Unchanged(current));
        }
        if before.genesis_event_id != remote.generation.genesis_event_id
            || before.head_act > remote.generation.head_act
        {
            return Ok(fallback("kernel-v2 hosted history changed or regressed"));
        }
        // The head record is written only after the database commit, so it
        // can lag the database but never lead it. A head ahead of the file
        // means the file was replaced or rolled back under us.
        match self.store.generation_head(&current.id) {
            Ok(Some(head)) if head.head_act > before.head_act => {
                return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                    class: DeltaFallbackClass::UntrustedLocalBase,
                    message:
                        "local head record is ahead of its database; a whole snapshot is required",
                }));
            }
            Ok(_) => {}
            Err(_) => {
                return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                    class: DeltaFallbackClass::UntrustedLocalBase,
                    message: "local copy head record was unreadable; a whole snapshot is required",
                }))
            }
        }
        if self.kernel_replay_cooling_down().map_err(local_io)? {
            return Ok(DeltaAttempt::Deferred {
                generation: current,
                reason: "kernel_v2_replay_cooldown",
            });
        }
        if !self.kernel_has_disk_space(&current, 2).map_err(local_io)? {
            return Ok(DeltaAttempt::Deferred {
                generation: current,
                reason: super::generation_store::INSUFFICIENT_DISK,
            });
        }
        if before.blob_count > super::kernel_v2_delta::MAX_BLOB_INVENTORY as i64 {
            return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                class: DeltaFallbackClass::BlobInventoryLimit,
                message: "kernel_v2_blob_inventory_limit; a whole snapshot is required",
            }));
        }
        let inventory = super::kernel_v2::blob_inventory_path(&current.snapshot_path)
            .await
            .map_err(local_io)?;
        timings.lap("blob_inventory");
        let want_proof = self.proof_due();
        let delta = match crate::async_diagnostics::track(
            "refresh.fetch_kernel_delta",
            transport.kernel_delta_with_proof(before.head_act, &inventory, want_proof),
        )
        .await
        {
            Ok(delta) => delta,
            Err(error) => {
                let mut classified = classify_delta_transport_error(error);
                if classified.class == RefreshFailureClass::Throttled {
                    // Only a busy export classifies as Throttled here: fail
                    // the attempt for a bounded retry, never a whole snapshot.
                    classified.retry_after = transport.take_busy_retry_after();
                }
                if matches!(
                    classified.class,
                    RefreshFailureClass::Authentication
                        | RefreshFailureClass::Network
                        | RefreshFailureClass::Throttled
                ) || matches!(classified.source.as_ref(), Error::Engine(detail)
                    if detail == crate::client_compatibility::UPDATE_REQUIRED)
                {
                    return Err(classified);
                }
                return Ok(fallback(
                    "kernel-v2 delta unavailable or invalid; a whole snapshot is required",
                ));
            }
        };
        timings.lap("fetch_delta");
        // Preparation alone cannot change the accepted base. Arm only at the
        // actual in-place apply or staged publication boundary.
        #[cfg(feature = "v2-kernel-probe")]
        let mut kernel_notice = None;

        let size = delta.delta().size();
        let mut cooldown = KernelReplayCooldown::start(self, timings.clone()).map_err(local_io)?;
        if self.config.kernel_in_place_deltas {
            if !size.is_small() {
                cooldown.in_place_skip = Some("delta_not_small");
            } else {
                match self
                    .store
                    .kernel_in_place_ineligible(&current, &self.observed, state)
                {
                    None => {
                        cooldown.path = "in_place";
                        #[cfg(test)]
                        let crash = self.kernel_in_place_crash;
                        #[cfg(not(test))]
                        let crash = None;
                        #[cfg(feature = "v2-kernel-probe")]
                        if delta.delta().head.generation != before {
                            kernel_notice = self.pending_observer.begin_kernel_accepted();
                        }
                        match crate::async_diagnostics::track("refresh.apply_kernel_delta", self.store.apply_kernel_delta_in_place(&current, &delta, synced_at, &timings, crash)).await
                        {
                            Ok(super::generation_store::kernel_in_place::InPlaceApplied::Applied) => {
                                let head_act = delta.delta().head.head_act;
                                self.store.complete_validated_refresh(
                                    &current.id,
                                    &self.observed,
                                    verified,
                                    head_act,
                                    true,
                                );
                                self.store.note_deferral(
                                    &current.id,
                                    DeltaDeferral::DatabaseBusy,
                                    false,
                                );
                                timings.lap("in_place_finish");
                                self.note_proof_outcome(&delta, &timings);
                                cooldown.complete(true);
                                // The delta carries no hosted creation/acceptance
                                // time for its newest act (coordinates only),
                                // so visibility is just the local commit time
                                // and the act it reached.
                                tracing::info!(
                                    target: "native_ce::standby::kernel_delta",
                                    to_act = head_act,
                                    applied_at = now(),
                                    "kernel-v2 delta applied"
                                );
                                if idle_audit {
                                    // Nothing advanced: this was only the audit.
                                    return Ok(DeltaAttempt::Unchanged(current));
                                }
                                #[cfg(feature="v2-kernel-probe")]
        if let Some(notice)=kernel_notice {notice.committed(current.id.clone(),current.id.clone(),before,delta);}
                                return Ok(DeltaAttempt::Advanced {
                                    generation: current,
                                    head_act,
                                });
                            }
                            Ok(super::generation_store::kernel_in_place::InPlaceApplied::CheckpointVerifying) => {
                                #[cfg(feature = "v2-kernel-probe")]
                                if let Some(notice) = kernel_notice.take() { notice.no_publication(); }
                                return Ok(DeltaAttempt::Deferred {
                                    generation: current,
                                    reason: DEFERRED_CHECKPOINT_VERIFYING,
                                });
                            }
                            // The commit happened; only a sidecar write failed
                            // or a fault was injected. Do not also publish a
                            // staged copy: the next tick heals the sidecars
                            // from the database's own head.
                            Err(super::generation_store::kernel_in_place::InPlaceError::AfterCommit(error)) => {
                                return Err(local_io(error));
                            }
                            Err(super::generation_store::kernel_in_place::InPlaceError::BeforeCommit(error)) => {
                                // Rolled back: the serving database is unchanged.
                                if matches!(&error, Error::Engine(message) if message == super::generation_store::kernel_in_place::RECEIPTS_INCONSISTENT)
                                {
                                    let _ = self.store.require_full_refresh(&current);
                                    return Ok(DeltaAttempt::FallBackToSnapshot(
                                        DeltaFallbackDiagnostic {
                                            class: DeltaFallbackClass::UntrustedLocalBase,
                                            message: "in-place copy failed its apply-receipt check; a whole snapshot is required",
                                        },
                                    ));
                                }
                                if is_sqlite_busy_or_locked(&error) {
                                #[cfg(feature = "v2-kernel-probe")]
                                if let Some(notice) = kernel_notice.take() { notice.no_publication(); }
                                    self.store.note_deferral(
                                        &current.id,
                                        DeltaDeferral::DatabaseBusy,
                                        true,
                                    );
                                    return Ok(DeltaAttempt::Deferred {
                                        generation: current,
                                        reason: DEFERRED_DATABASE_BUSY,
                                    });
                                }
                                if super::generation_store::is_kernel_disk_refusal(&error) {
                                #[cfg(feature = "v2-kernel-probe")]
                                if let Some(notice) = kernel_notice.take() { notice.no_publication(); }
                                    return Ok(DeltaAttempt::Deferred {
                                        generation: current,
                                        reason: super::generation_store::INSUFFICIENT_DISK,
                                    });
                                }
                                if matches!(&error, Error::Engine(message) if message == "kernel_v2_projection_divergence")
                                {
                                    // The staged path would replay the same delta
                                    // over the same bytes to the same verdict.
                                    return Ok(DeltaAttempt::FallBackToSnapshot(
                                        DeltaFallbackDiagnostic {
                                            class: DeltaFallbackClass::ProjectionDivergence,
                                            message: "kernel_v2_projection_divergence; a whole snapshot is required",
                                        },
                                    ));
                                }
                                #[cfg(test)]
                                if matches!(&error, Error::Engine(message) if message == super::generation_store::kernel_in_place::INJECTED_CRASH)
                                {
                                    return Err(local_io(error));
                                }
                                tracing::warn!(
                                    target: "native_ce::standby::kernel_delta",
                                    "in-place kernel-v2 delta refused; using the staged path"
                                );
                                cooldown.in_place_skip = Some("in_place_refused");
                                // Whatever the staged path does next, the copy
                                // met trouble: audit until a proof checks out.
                                self.proof_audit.lock().expect("proof audit").trouble = true;
                            }
                        }
                    }
                    Some(reason) => cooldown.in_place_skip = Some(reason),
                }
            }
        } else if let Some(reason) = recheckpoint {
            cooldown.in_place_skip = Some(reason);
        }
        let prepared = match crate::async_diagnostics::track(
            "refresh.prepare_kernel_delta",
            self.store
                .prepare_kernel_delta_timed(&current, &delta, synced_at, &timings),
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(error) if super::generation_store::is_kernel_disk_refusal(&error) => {
                return Ok(DeltaAttempt::Deferred {
                    generation: current,
                    reason: super::generation_store::INSUFFICIENT_DISK,
                });
            }
            Err(Error::Engine(message))
                if message == super::generation_store::kernel_in_place::BASE_UNPROVED =>
            {
                return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                    class: DeltaFallbackClass::UntrustedLocalBase,
                    message: "in-place copy could not be proved; a whole snapshot is required",
                }));
            }
            Err(Error::Engine(message)) if message == "kernel_v2_projection_divergence" => {
                return Ok(DeltaAttempt::FallBackToSnapshot(DeltaFallbackDiagnostic {
                    class: DeltaFallbackClass::ProjectionDivergence,
                    message: "kernel_v2_projection_divergence; a whole snapshot is required",
                }));
            }
            Err(_) => {
                return Ok(fallback(
                    "kernel-v2 scratch delta apply refused; serving generation unchanged",
                ))
            }
        };
        #[cfg(feature = "v2-kernel-probe")]
        if kernel_notice.is_none() && delta.delta().head.generation != before {
            kernel_notice = self.pending_observer.begin_kernel_accepted();
        }
        let generation =
            match crate::async_diagnostics::track(
                "refresh.publish_kernel_delta",
                self.store
                    .publish_kernel_delta_timed(prepared, &self.observed, &timings),
            )
            .await
            {
                Ok(generation) => generation,
                Err(error) if super::generation_store::is_kernel_disk_refusal(&error) => {
                    return Ok(DeltaAttempt::Deferred {
                        generation: current,
                        reason: super::generation_store::INSUFFICIENT_DISK,
                    });
                }
                Err(_) => return Ok(fallback(
                    "kernel-v2 scratch generation admission refused; serving generation unchanged",
                )),
            };
        let head_act = delta.delta().head.head_act;
        self.store
            .record_synced(&generation, head_act, synced_at)
            .map_err(local_io)?;
        timings.lap("record_synced");
        self.note_proof_outcome(&delta, &timings);
        self.store.schedule_maintenance(&self.observed);
        cooldown.complete(size.is_small());
        // As above: no hosted per-act time in the delta, so log the local
        // commit time and the act reached.
        tracing::info!(
            target: "native_ce::standby::kernel_delta",
            to_act = head_act,
            applied_at = now(),
            "kernel-v2 delta applied"
        );
        #[cfg(feature = "v2-kernel-probe")]
        if let Some(notice) = kernel_notice {
            notice.committed(current.id.clone(), generation.id.clone(), before, delta);
        }
        Ok(DeltaAttempt::Advanced {
            generation,
            head_act,
        })
    }

    /// Whether the next delta must carry the projection proof: on the first
    /// follow after a start, at the configured interval, and straight after
    /// any trouble. Never blocks anything; it only chooses which wire version
    /// to ask for.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    fn proof_due(&self) -> bool {
        let audit = self.proof_audit.lock().expect("proof audit");
        audit.trouble
            || audit
                .last
                .is_none_or(|at| at.elapsed() >= self.config.projection_proof_interval())
    }

    /// Record what an applied delta did for the audit schedule. A delta that
    /// carried the proof was checked against it, so it restarts the interval
    /// and clears any trouble. A proof-less one that hit a set-path anomaly or
    /// a reseed is trouble: the next follow audits.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    fn note_proof_outcome(
        &self,
        delta: &super::kernel_v2_delta::TrustedKernelDelta,
        timings: &PhaseTimings,
    ) {
        let mut audit = self.proof_audit.lock().expect("proof audit");
        if delta.delta().version != super::kernel_v2_delta::WIRE_VERSION_3 {
            audit.last = Some(std::time::Instant::now());
            audit.trouble = false;
            return;
        }
        // Anything that made the cache or the capture unreliable is trouble;
        // so is every reseed the node did not plan. (A first-DDL copy's
        // `skipped:no_accumulator` and a version-1 delta's `skipped:v1_delta`
        // are ordinary.)
        let path = timings.set_path_json();
        let label = path["last_set_path"].as_str().unwrap_or("");
        if ["anomaly", "mismatch_reseeded", "divergence"]
            .iter()
            .any(|prefix| label.starts_with(prefix))
            || label == "skipped:accumulator_invalid"
            || label == "skipped:suppressed"
        {
            audit.trouble = true;
        }
    }

    #[cfg(any(test, feature = "v2-kernel-probe"))]
    fn kernel_has_disk_space(&self, current: &InstalledGeneration, copies: u64) -> Result<bool> {
        let available = fs2::available_space(self.store.staging_dir())?;
        #[cfg(test)]
        let available = self.kernel_available_space.unwrap_or(available);
        Ok(available
            >= super::generation_store::kernel_disk_budget(&current.snapshot_path, copies)?)
    }

    #[cfg(any(test, feature = "v2-kernel-probe"))]
    fn kernel_replay_cooling_down(&self) -> Result<bool> {
        let path = self.refresh_dir.join("kernel-replay.json");
        if !path.try_exists()? {
            return Ok(false);
        }
        require_regular_file(&path)?;
        let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
        let until = value["not_before"]
            .as_str()
            .ok_or_else(|| Error::engine("invalid kernel replay schedule"))?;
        let until = chrono::DateTime::parse_from_rfc3339(until)
            .map_err(|_| Error::engine("invalid kernel replay timestamp"))?;
        Ok(until > chrono::Utc::now())
    }

    #[cfg(any(test, feature = "v2-kernel-probe"))]
    fn defer_kernel_replay(&self, elapsed: Duration) -> Result<()> {
        self.write_kernel_replay(
            elapsed,
            KERNEL_REPLAY_FLOOR,
            "in_progress",
            "staged",
            None,
            &PhaseTimings::default(),
        )
    }

    /// Persist the rest after a replay: at least as long as the replay took
    /// (so replay never takes more than half the wall clock) and at least
    /// `floor`. The attempt lock covers copy, replay, verification and
    /// publication. `phases` is the per-phase wall time of the attempt.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    fn write_kernel_replay(
        &self,
        elapsed: Duration,
        floor: Duration,
        outcome: &str,
        path: &str,
        in_place_skip: Option<&str>,
        timings: &PhaseTimings,
    ) -> Result<()> {
        let rest = elapsed.max(floor);
        let until = chrono::Utc::now()
            + chrono::Duration::milliseconds(rest.as_millis().min(i64::MAX as u128) as i64);
        let mut temp = tempfile::NamedTempFile::new_in(&self.refresh_dir)?;
        temp.write_all(&serde_jcs::to_vec(&serde_json::json!({
            "not_before": until.to_rfc3339(),
            "last_wall_millis": elapsed.as_millis(),
            "last_outcome": outcome,
            "last_path": path,
            "last_in_place_skip": in_place_skip,
            "last_rest_millis": rest.as_millis(),
            "last_phases": timings.to_json(),
            "last_digest_tables": timings.tables_json(),
            // What the set-digest path did: `fast`, `anomaly:<reason>`,
            // `mismatch_reseeded:<table>`, `divergence`, or `skipped:<cause>`
            // when a full scan proved the apply without attempting it; the
            // generation's counters; and the capture's sizes.
            "last_set_path": timings.set_path_json()["last_set_path"].clone(),
            "set_path": timings.set_path_json(),
        }))?)?;
        temp.as_file().sync_all()?;
        temp.persist(self.refresh_dir.join("kernel-replay.json"))
            .map_err(|e| e.error)?;
        File::open(&self.refresh_dir)?.sync_all()?;
        Ok(())
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
        let mut selected_transfer: Option<Option<super::shapes::Shape>> = None;
        let mut disk_budget = None;

        loop {
            self.check_transition_transfer_budget(disk_budget.as_ref(), offset)
                .map_err(local_io)?;
            let request = SnapshotPageRequest {
                export_id: export_id.clone(),
                offset,
                length: MAX_PAGE_BYTES,
                standby_consumer: export_id.is_none().then(|| self.declared_consumer()),
            };
            let page = self
                .fetch_page_with_retry(endpoint, &bearer, request)
                .await?;
            if selected_transfer
                .as_ref()
                .is_some_and(|shape| shape != &page.selected_shape)
            {
                return Err(integrity(
                    "snapshot selected shape changed between pages",
                    Error::engine("snapshot selected shape changed"),
                ));
            }
            selected_transfer = Some(page.selected_shape.clone());
            if let Some(entry) = page
                .manifest
                .as_ref()
                .or(manifest.as_ref())
                .and_then(super::shapes::manifest)
            {
                super::shapes::check_selection(page.selected_shape.as_ref(), entry).map_err(
                    |error| integrity("snapshot shape signal is missing or conflicting", error),
                )?;
            }
            if let Some(selected) = &page.selected_shape {
                let described = page
                    .manifest
                    .as_ref()
                    .or(manifest.as_ref())
                    .and_then(super::shapes::manifest)
                    .map(super::shapes::Entry::shape);
                if described.as_ref() != Some(selected) {
                    return Err(integrity(
                        "snapshot selected shape disagrees with its manifest",
                        Error::engine("snapshot shape mismatch"),
                    ));
                }
            }
            validate_page(
                &page,
                export_id.as_deref(),
                offset,
                expected_size,
                expected_sha.as_deref(),
                manifest.as_ref(),
            )?;
            if offset == 0 {
                if let Some(manifest) = &page.manifest {
                    // The legacy route combines metadata with one bounded
                    // first page. Gate before writing it or requesting more.
                    disk_budget = self
                        .transition_transfer_budget(manifest, page.size_bytes)
                        .map_err(local_io)?;
                }
            }
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
        self.install_downloaded_snapshot(manifest, snapshot_path, manifest_path)
            .await
    }

    fn write_downloaded_manifest(
        &self,
        manifest: &StandbySnapshotManifest,
        manifest_path: &Path,
    ) -> std::result::Result<(), AttemptError> {
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

        Ok(())
    }

    async fn install_downloaded_snapshot(
        &self,
        manifest: StandbySnapshotManifest,
        snapshot_path: &Path,
        manifest_path: &Path,
    ) -> std::result::Result<(InstalledGeneration, Vec<String>), AttemptError> {
        self.write_downloaded_manifest(&manifest, manifest_path)?;

        self.record_active_candidate(&manifest)?;

        self.record_transfer_stage(
            StandbyTransferStage::Verification,
            Some((manifest.snapshot.size_bytes, manifest.snapshot.size_bytes)),
            false,
        )?;

        let generation = self
            .store
            .install_staged_observing_publication(
                snapshot_path,
                manifest_path,
                &self.observed,
                || {
                    self.record_transfer_stage(
                        StandbyTransferStage::Publication,
                        Some((manifest.snapshot.size_bytes, manifest.snapshot.size_bytes)),
                        false,
                    )
                    .map_err(|error| *error.source)
                },
            )
            .await
            .map_err(classify_install_error)?;
        self.store.schedule_maintenance(&self.observed);
        let retention_warnings = Vec::new();
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
            kernel_v2_reader: self.observed.kernel_v2_reader.clone(),
            contract: STANDBY_CONSUMER_CONTRACT.into(),
            version: 1,
            platform: self.observed.platform,
            source_sha: self.observed.source_sha.clone(),
            artifact_sha256: self.observed.artifact_sha256.clone(),
            engine_schema_version: self.observed.engine_schema_version,
            ddl_sha256: self.observed.ddl_sha256.clone(),
        }
        .for_engine(
            self.route_kernel_v2
                .load(std::sync::atomic::Ordering::Relaxed),
        )
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
        let mut file = create_private_file(&temp).map_err(|error| *error.source)?;
        file.write_all(&serde_jcs::to_vec(pending)?)?;
        file.sync_all()?;
        drop(file);
        fs::rename(temp, self.pending_marker_path())?;
        File::open(&self.refresh_dir)?.sync_all()?;
        Ok(())
    }

    fn take_pending_triggers(&self) -> Result<Vec<RefreshCause>> {
        let lock = open_private_lock(&self.refresh_dir.join("trigger.lock"))?;
        lock_exclusive_bounded(&lock, LOCK_WAIT_TIMEOUT)?;
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
        lock_exclusive_bounded(&lock, LOCK_WAIT_TIMEOUT)?;
        let mut state = state.clone();
        state.manual_refresh_pending = self
            .read_pending_triggers()?
            .causes
            .contains(&RefreshCause::Manual);
        self.write_state_unlocked(&state)
    }

    /// Whether the last whole snapshot did not complete. It is marked failed
    /// when it starts and completed when it is installed, so an interrupted
    /// one counts, and a clock step cannot change the answer. A bare marker
    /// file rather than a state field: older builds parse the state strictly.
    fn last_full_failed(&self) -> bool {
        fs::read_to_string(self.refresh_dir.join("last-full-outcome"))
            .is_ok_and(|outcome| outcome.trim() == "failed")
    }

    fn record_full_outcome(&self, completed: bool) -> Result<()> {
        let temp = self
            .refresh_dir
            .join(format!(".last-full-{}.tmp", uuid::Uuid::new_v4()));
        let mut file = create_private_file(&temp).map_err(|error| *error.source)?;
        file.write_all(if completed { b"completed" } else { b"failed" })?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, self.refresh_dir.join("last-full-outcome"))?;
        File::open(&self.refresh_dir)?.sync_all()?;
        Ok(())
    }

    fn write_state_unlocked(&self, state: &StandbyRefreshState) -> Result<()> {
        let path = self.state_path();
        let temp = self
            .refresh_dir
            .join(format!(".state-{}.tmp", uuid::Uuid::new_v4()));
        let bytes = serde_jcs::to_vec(state)?;
        if bytes.len() as u64 > MAX_STATUS_DIAGNOSTIC_FILE_BYTES {
            return Err(Error::engine("standby refresh state exceeds its bound"));
        }
        let mut file = create_private_file(&temp).map_err(|error| *error.source)?;
        file.write_all(&bytes)?;
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
        if state.refresh_active || state.active_candidate_generation_id.is_some() {
            let promoted =
                state
                    .active_candidate_generation_id
                    .as_deref()
                    .is_some_and(|candidate| {
                        self.current_generation_id().as_deref() == Some(candidate)
                    });
            state.refresh_active = false;
            self.settle_transfer_progress(&mut state, promoted);
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
        lock_exclusive_bounded(&lock, LOCK_WAIT_TIMEOUT)?;
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
            let kernel_replay = name
                .strip_prefix("kernel-replay-")
                .is_some_and(|s| s.len() == 6 && s.bytes().all(|b| b.is_ascii_alphanumeric()));
            let kernel_file = ["kernel-delta-", "kernel-manifest-"].iter().any(|prefix| {
                name.strip_prefix(prefix)
                    .is_some_and(|s| s.len() == 6 && s.bytes().all(|b| b.is_ascii_alphanumeric()))
            });
            if kernel_replay || kernel_file {
                let metadata = fs::symlink_metadata(entry.path())?;
                if kernel_replay && metadata.is_dir() {
                    fs::remove_dir_all(entry.path())?;
                } else if metadata.is_file() || metadata.file_type().is_symlink() {
                    fs::remove_file(entry.path())?;
                }
                continue;
            }
            let Some(rest) = name.strip_prefix("refresh-") else {
                continue;
            };
            let id = rest
                .strip_suffix(".snapshot.db")
                .or_else(|| rest.strip_suffix(".snapshot.db-wal"))
                .or_else(|| rest.strip_suffix(".snapshot.db-shm"))
                .or_else(|| rest.strip_suffix(".snapshot.db-journal"))
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
    #[serde(skip)]
    selected_shape: Option<super::shapes::Shape>,
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

pub(crate) fn validate_exact_origin(raw: &str) -> Result<()> {
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

fn read_credential(path: &Path) -> std::result::Result<String, AttemptError> {
    // Shared, hardened reader; the member-copy adapter reuses the same
    // discipline. `label` preserves the standby diagnostics and error class.
    let bytes =
        crate::credential_file::read_guarded_credential(path, "standby").map_err(local_io)?;
    String::from_utf8(bytes.to_vec())
        .map_err(|_| local_io(Error::engine("standby credential is not UTF-8")))
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

pub(super) fn open_private_lock(path: &Path) -> Result<File> {
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

fn sqlite_journal_path(path: &Path) -> PathBuf {
    let mut journal = path.as_os_str().to_os_string();
    journal.push("-journal");
    PathBuf::from(journal)
}

fn remove_owned_sqlite_sidecars(path: &Path) {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        remove_owned_staging_file(&PathBuf::from(sidecar));
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

/// The check identifier for install failures no needle claims, and the
/// empty token. Both are allowlisted disclosure tokens alongside the table.
const UNCLASSIFIED_CHECK: &str = "unclassified";
const INSTALL_VERIFY_CHECK: &str = "install-fence:verify";

// Preserve old static tokens for status reads only. They never classify new errors.
const LEGACY_INSTALL_CHECKS: &[&str] = &[
    "install-fence:route",
    "install-fence:origin",
    "install-fence:consumer",
    "install-fence:engine-schema",
    "install-fence:frozen-ddl",
    "install-fence:rollback",
    "install-fence:successor",
    "install-fence:platform",
    "install-fence:source-sha",
    "install-fence:artifact",
];
const ADMISSION_CHECKS: &[crate::error::StandbyAdmissionCheck] = &[
    crate::error::StandbyAdmissionCheck::RouteOrigin,
    crate::error::StandbyAdmissionCheck::Consumer,
    crate::error::StandbyAdmissionCheck::ByteIdentity,
    crate::error::StandbyAdmissionCheck::EngineShape,
    crate::error::StandbyAdmissionCheck::ManifestState,
    crate::error::StandbyAdmissionCheck::ActOrderContinuity,
    crate::error::StandbyAdmissionCheck::CurrentGeneration,
    crate::error::StandbyAdmissionCheck::ScalarRollbackContinuity,
    crate::error::StandbyAdmissionCheck::SuccessorPreservation,
    crate::error::StandbyAdmissionCheck::Integrity,
    crate::error::StandbyAdmissionCheck::Conformance,
    crate::error::StandbyAdmissionCheck::Awareness,
];

fn classify_install_error(source: Error) -> AttemptError {
    use crate::error::StandbyAdmissionCheck;
    let (class, message, check) = match &source {
        Error::Io(_) => (
            RefreshFailureClass::LocalIo,
            "local standby refresh storage failed",
            None,
        ),
        Error::StandbyAdmission { check, .. } => {
            let compatibility = matches!(
                check,
                StandbyAdmissionCheck::RouteOrigin
                    | StandbyAdmissionCheck::Consumer
                    | StandbyAdmissionCheck::EngineShape
                    | StandbyAdmissionCheck::ManifestState
            );
            (
                if compatibility {
                    RefreshFailureClass::Compatibility
                } else {
                    RefreshFailureClass::Verification
                },
                if compatibility {
                    "downloaded snapshot was incompatible with this standby"
                } else {
                    "downloaded snapshot was not admitted"
                },
                Some(check.token()),
            )
        }
        _ => (
            RefreshFailureClass::Verification,
            "downloaded snapshot was not admitted",
            Some(INSTALL_VERIFY_CHECK),
        ),
    };
    let error = AttemptError::new(class, message, source);
    match check {
        Some(check) => error.with_check(check),
        None => error,
    }
}

/// HTTP detail vocabulary is bounded independently of remote reason phrases.
fn http_failure_detail(status: u16) -> &'static str {
    match status {
        400 => "http_400",
        401 => "http_401",
        403 => "http_403",
        404 => "http_404",
        408 => "http_408",
        409 => "http_409",
        410 => "http_410",
        412 => "http_412",
        413 => "http_413",
        416 => "http_416",
        422 => "http_422",
        425 => "http_425",
        429 => "http_429",
        _ if (400..=499).contains(&status) => "http_4xx_other",
        500..=599 => "http_5xx",
        _ => "http_other",
    }
}

/// The delta transport exposes Engine(String), so recognize only its fixed
/// prefixes (delta_transport.rs). Never forward any part of the source text.
fn delta_transport_failure_detail(source: &Error) -> &'static str {
    let Error::Engine(message) = source else {
        return "unclassified";
    };
    if let Some(detail) = super::delta_transport::diagnostics::failure_detail(message) {
        return detail;
    }
    if message == super::delta_transport::DELTA_EXPORT_BUSY_MESSAGE {
        return EXPORT_BUSY_DETAIL;
    }
    if message == "hosted authority act delta export request failed: capture unavailable" {
        return "capture_unavailable";
    }
    if let Some(status) = message
        .strip_prefix("hosted authority act HTTP status ")
        .or_else(|| message.strip_prefix("hosted authority act delta export HTTP status "))
    {
        return status
            .split_whitespace()
            .next()
            .and_then(|code| code.parse::<u16>().ok())
            .map_or("unclassified", http_failure_detail);
    }
    if message == MAINTENANCE_SNAPSHOT_ERROR {
        "maintenance"
    } else if message == "hosted authority act tool reported failure"
        || message.starts_with("hosted authority act tool call was refused (")
    {
        "tool_failure"
    } else if message == "hosted authority act response too large" {
        "response_too_large"
    } else if message.starts_with("hosted authority act returned an invalid protocol response:") {
        "decode"
    } else if message == super::delta_transport::DELTA_EXPORT_CAPTURE_TIMEOUT_MESSAGE {
        EXPORT_CAPTURE_TIMEOUT_DETAIL
    } else {
        "unclassified"
    }
}

fn classify_delta_transport_error(source: Error) -> AttemptError {
    let (class, message) = match &source {
        Error::Engine(detail)
            if detail == super::shapes::UPDATE_REQUIRED
                || detail == crate::client_compatibility::UPDATE_REQUIRED =>
        {
            (
                RefreshFailureClass::Compatibility,
                "update this receiver to refresh",
            )
        }
        Error::Auth(_) => (
            RefreshFailureClass::Authentication,
            "hosted delta authentication was refused",
        ),
        Error::Io(_) => (
            RefreshFailureClass::LocalIo,
            "local standby delta preparation failed",
        ),
        // Hosted runs one delta export per account and database: a busy
        // refusal is scheduling, not an outage. Throttled keeps the
        // trigger for a bounded retry and never schedules network-recovery
        // probes or a network-failure disclosure — and, below, never buys a
        // whole snapshot for a momentarily busy host.
        Error::Engine(detail) if detail == super::delta_transport::DELTA_EXPORT_BUSY_MESSAGE => (
            RefreshFailureClass::Throttled,
            "hosted delta export is already in progress",
        ),
        Error::Engine(detail)
            if detail == MAINTENANCE_SNAPSHOT_ERROR
                || detail.contains("request failed")
                || detail.contains("was interrupted")
                || detail.contains("HTTP status 5")
                || detail.contains("HTTP status 408")
                || detail.contains("HTTP status 425")
                || detail.contains("HTTP status 429") =>
        {
            (RefreshFailureClass::Network, "hosted delta request failed")
        }
        _ => (
            RefreshFailureClass::Protocol,
            "hosted delta protocol exchange failed",
        ),
    };
    let detail = delta_transport_failure_detail(&source);
    AttemptError::new(class, message, source).with_detail(detail)
}

fn set_delta_fallback(
    state: &mut StandbyRefreshState,
    diagnostic: Option<DeltaFallbackDiagnostic>,
) {
    state.last_delta_fallback_class = diagnostic.map(|value| value.class);
    state.last_delta_fallback = diagnostic.map(|value| value.message.to_string());
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

/// When a whole snapshot held back by the minimum interval becomes eligible:
/// the same reference instant `full_refresh_is_recent` measures from, plus the
/// minimum. `None` when no reference is recorded.
fn full_refresh_eligible_at(
    state: &StandbyRefreshState,
    repair: bool,
    minimum: Duration,
) -> Option<String> {
    let parse = |value: &Option<String>| {
        value
            .as_deref()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
    };
    let started = parse(&state.last_full_refresh_at);
    let reference = if repair {
        started.max(parse(&state.last_full_failure_at))
    } else {
        started
    }?;
    let minimum = chrono::Duration::from_std(minimum).ok()?;
    Some(
        (reference + minimum)
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    )
}

fn full_refresh_is_recent(state: &StandbyRefreshState, repair: bool, minimum: Duration) -> bool {
    if minimum.is_zero() {
        return false;
    }
    let parse = |value: &Option<String>| {
        value
            .as_deref()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
    };
    let started = parse(&state.last_full_refresh_at);
    let reference = if repair {
        // An interrupted FULL may retain the previous attempt's failure end.
        // Never let that older timestamp shorten the start-based fallback.
        started.max(parse(&state.last_full_failure_at))
    } else {
        started
    };
    reference.is_some_and(|reference| {
        chrono::Utc::now()
            .signed_duration_since(reference)
            .to_std()
            .map_or(true, |elapsed| elapsed < minimum)
    })
}

fn elapsed_indicates_wake(wall: Duration, monotonic: Duration) -> bool {
    wall > monotonic.saturating_add(WAKE_DETECTION_SLOP)
}

/// The follow loop's own cadence: the configured refresh interval, defaulting
/// to the 60 s backstop. Shared by the loop and its watchdog so the two can
/// never disagree about what "overdue" means.
fn refresh_cadence(config: &StandbyRefreshConfig) -> Duration {
    Duration::from_secs(
        config
            .refresh_interval_seconds
            .unwrap_or(super::status::STANDBY_REFRESH_INTERVAL_SECONDS),
    )
}

/// How long the follow loop may stay quiet before it owes a stall WARN:
/// well over its own cadence, floored so sub-second test intervals still
/// produce a meaningful bound.
fn stall_warn_after(interval: Duration) -> Duration {
    interval
        .saturating_mul(STALL_WARN_INTERVAL_MULTIPLE)
        .max(Duration::from_secs(1))
}

/// The scheduler-health evidence carried by a stall WARN: how long since the
/// loop last started an attempt, and by how much the scheduled deadline it
/// should have followed sits overdue. Both are loop-local; nothing here is
/// persisted, so older builds keep parsing state strictly.
struct FollowLoopStall {
    idle: Duration,
    scheduled_overdue: Duration,
}

/// Whether the follow loop owes a stall WARN on this tick: it has started no
/// attempt for well over its cadence while the scheduled deadline sits
/// overdue by the same bound. Either half alone is healthy — a fresh start
/// with a future deadline, or a just-completed long attempt whose completion
/// re-anchored the deadline — so both are required. A tick that fires this is
/// itself the recovery evidence: the loop is running again, and the very next
/// selection starts the overdue Scheduled probe that learns whether hosted is
/// ahead.
fn follow_loop_stall_report(
    now: tokio::time::Instant,
    last_attempt_start: Option<tokio::time::Instant>,
    scheduled: tokio::time::Instant,
    interval: Duration,
) -> Option<FollowLoopStall> {
    let threshold = stall_warn_after(interval);
    let started = last_attempt_start?;
    let idle = now.saturating_duration_since(started);
    let scheduled_overdue = now.saturating_duration_since(scheduled);
    if idle > threshold && scheduled_overdue > threshold {
        Some(FollowLoopStall {
            idle,
            scheduled_overdue,
        })
    } else {
        None
    }
}

/// Whether a busy-backoff skip earns a log line: the first skip of an episode
/// always does; further skips log at most once per cadence. A second episode
/// starting within the same cadence window stays silent — a deliberate blind
/// spot that keeps a flapping hold from flooding the journal.
fn busy_skip_log_due(
    now: tokio::time::Instant,
    last_log: Option<tokio::time::Instant>,
    interval: Duration,
) -> bool {
    last_log.is_none_or(|logged| now.saturating_duration_since(logged) >= interval)
}

fn next_scheduled_deadline(
    scheduled: tokio::time::Instant,
    attempt_started: tokio::time::Instant,
    completed: tokio::time::Instant,
    cause: RefreshCause,
    interval: Duration,
) -> tokio::time::Instant {
    if cause == RefreshCause::Scheduled {
        let next = scheduled + interval;
        if attempt_started.saturating_duration_since(scheduled) >= interval || next <= completed {
            completed + interval
        } else {
            next
        }
    } else if scheduled <= completed {
        // A non-cadence acquisition also represents a cadence that became due
        // before it completed.
        completed + interval
    } else {
        scheduled
    }
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) use tests::kernel_v2_in_place::trust::audited_and_recorded;
/// Test-only reuse of the kernel-v2 in-place setup from the generation-store
/// churn tests: the setup lives under `tests` but is re-exported here so the
/// churn tests can drive a real delta without duplicating the fixture.
#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) use tests::kernel_v2_in_place::Setup;

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use axum::body::Body;
    use axum::extract::{Path as HttpPath, State as HttpState};
    use axum::http::header::{
        ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, RANGE,
    };
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use axum::{Json, Router};

    use sqlx::Connection as _;

    use super::*;
    use crate::standby_snapshot::{
        HostedStandbyManifestContext, ProducerBuildIdentity, StandbyConsumerPlatform,
        StandbyGenerationMaterialization,
    };

    use super::super::authority_probe::read_authority_act_head;

    mod chunked;
    mod concurrent;
    mod gzip;
    mod gzip_http;
    mod gzip_recovery;
    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) mod kernel_v2_in_place;
    #[cfg(feature = "v2-kernel-probe")]
    mod kernel_v2_refresh;
    mod progress;
    mod receiver_shapes;

    /// Reader locks stand in for serving processes that outlive the test.
    static READER_LOCKS: std::sync::Mutex<Vec<std::fs::File>> = std::sync::Mutex::new(Vec::new());

    /// Serve `id` as an upgraded build would: hold the reader lock and record
    /// the build marker.
    fn serve_as_reader(
        store: &GenerationStore,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) {
        READER_LOCKS
            .lock()
            .unwrap()
            .push(store.hold_serving_reader(id).unwrap());
        store.record_serving_reader(id, observed).unwrap();
    }

    /// Enable the delta path and record that an upgraded serving build is
    /// serving the current generation, as a running reader would.
    fn enable_deltas(controller: &mut StandbyRefreshController) {
        controller.delta_enabled = true;
        if let Some(current) = controller.store.current_for_head_probe().unwrap() {
            serve_as_reader(&controller.store, &current.id, &controller.observed);
        }
    }

    const SCHEDULE_INTERVAL: Duration =
        Duration::from_secs(super::super::status::STANDBY_REFRESH_INTERVAL_SECONDS);
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
            assert!(
                endpoint.ends_with("/mcp/route%2D1"),
                "unexpected snapshot endpoint {endpoint}"
            );
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
            kernel_v2_reader: Default::default(),
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
            kernel_v2_reader: Default::default(),
            contract: STANDBY_CONSUMER_CONTRACT.into(),
            version: 1,
            platform: observed.platform,
            source_sha: observed.source_sha,
            artifact_sha256: observed.artifact_sha256,
            engine_schema_version: observed.engine_schema_version,
            ddl_sha256: observed.ddl_sha256,
        }
    }

    #[tokio::test]
    async fn v1_full_request_and_manifest_ignore_a_v2_reader_bump() {
        struct V1Client(ScriptedClient);
        impl SnapshotPageClient for V1Client {
            fn page(
                &self,
                endpoint: String,
                bearer: String,
                request: SnapshotPageRequest,
            ) -> PageFuture {
                if let Some(consumer) = &request.standby_consumer {
                    assert!(serde_json::to_value(consumer)
                        .unwrap()
                        .get("kernel_v2_reader")
                        .is_none());
                }
                self.0.page(endpoint, bearer, request)
            }
        }
        let db = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&db).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(V1Client(ScriptedClient::new(paged_replies(
                "v1-reader",
                &bytes,
                &manifest,
            )))),
        );
        controller.observed.kernel_v2_reader.reader_format += 1;
        controller.delta_enabled = true;
        let (port, server) = serve_authority_act_calls(db.clone(), 1).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        let StandbyRefreshOutcome::Installed { generation, .. } = controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap()
        else {
            panic!("a v2-only reader bump must not change v1 FULL admission")
        };
        assert!(
            serde_json::to_value(&generation.manifest).unwrap()["consumer"]
                .get("kernel_v2_reader")
                .is_none()
        );
        assert!(controller
            .store
            .consumer_rebind(&generation.id, &controller.observed)
            .unwrap()
            .is_none());
        server.await.unwrap();
        controller.store.maintenance_idle().await;
        db.close().await;
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
                    selected_shape: None,
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
            refresh_interval_seconds: None,
            full_refresh_min_interval_seconds: None,
            full_refresh_repair_retry_seconds: None,
            kernel_in_place_deltas: false,
            kernel_audit_interval_seconds: None,
            projection_proof_interval_seconds: None,
        };
        let store = GenerationStore::open(&replica_root, "route-1", Some(origin)).unwrap();
        StandbyRefreshController::new_with_client(runtime, config, store, observed(), client)
            .unwrap()
    }

    #[derive(Clone, Copy)]
    enum BinaryWireFault {
        None,
        HeadProbeUnavailable,
        ContentRange,
        Etag,
        Length,
        HeaderLength,
        Unsatisfiable,
        FailedPoll,
        InvalidPollJson,
        InvalidPollFields,
        Redirect,
        Unauthorized,
        InterruptedOnce,
        InterruptedAlways,
        MediaType,
        ContentEncoding,
        WrongApi,
        WrongHandle,
        UnknownLevel,
        UnknownEncoding,
        WrongApiHeader,
        MissingEncoded,
        ShortBody,
        StartContract,
        StartStructured404,
        WrongPollSelection,
        MatchingPollSelection,
        WrongReadySelection,
        WrongRangeSelection,
    }

    #[derive(Clone)]
    struct BinaryHttpFixture {
        bytes: Arc<Vec<u8>>,
        manifest: StandbySnapshotManifest,
        authority: Option<crate::Db>,
        transfer: transfer_repr::SnapshotTransfer,
        legacy_starts: Arc<AtomicUsize>,
        fault: BinaryWireFault,
        starts: Arc<AtomicUsize>,
        ranges: Arc<Mutex<Vec<String>>>,
        polls: Arc<AtomicUsize>,
        mcp_calls: Arc<AtomicUsize>,
        cancels: Arc<AtomicUsize>,
    }

    const BINARY_TEST_HANDLE: &str = "0dc9aadc-46b9-438d-8fca-5f719a8d6dc7";

    fn assert_receiver_advertisement(headers: &HeaderMap) {
        assert_eq!(
            headers[crate::client_compatibility::HEADER],
            crate::client_compatibility::advertisement()
        );
        assert_eq!(
            headers
                .get(super::super::shapes::ACCEPTED_SHAPES_HEADER)
                .unwrap()
                .to_str()
                .unwrap(),
            super::super::shapes::advertisement()
        );
    }

    fn binary_json(
        transfer: transfer_repr::SnapshotTransfer,
        status: StatusCode,
        body: Value,
    ) -> Response {
        let mut response = (status, Json(body)).into_response();
        response.headers_mut().insert(
            "x-native-export-api",
            HeaderValue::from_static(transfer.route_api()),
        );
        response
    }

    async fn binary_start_fixture(
        HttpState(fixture): HttpState<BinaryHttpFixture>,
        HttpPath(database): HttpPath<String>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Response {
        assert_receiver_advertisement(&headers);
        assert_eq!(database, "route-1");
        assert_eq!(headers.get("authorization").unwrap(), "Bearer secret");
        assert_eq!(body["contract"], fixture.transfer.route_api());
        assert_eq!(body["version"], 1);
        assert_eq!(body["consumer"], serde_json::to_value(consumer()).unwrap());
        fixture.starts.fetch_add(1, Ordering::SeqCst);
        if matches!(
            fixture.fault,
            BinaryWireFault::StartContract | BinaryWireFault::StartStructured404
        ) {
            return binary_json(
                fixture.transfer,
                if matches!(fixture.fault, BinaryWireFault::StartContract) {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::NOT_FOUND
                },
                json!({"api": fixture.transfer.route_api(), "error": {"code": if matches!(fixture.fault, BinaryWireFault::StartContract) { "invalid_request_contract" } else { "database_not_found" }}}),
            );
        }
        binary_json(
            fixture.transfer,
            StatusCode::ACCEPTED,
            json!({"api":fixture.transfer.route_api(),"export_handle":BINARY_TEST_HANDLE,
                   "status":"pending","expires_at":"2026-09-29T21:00:00Z"}),
        )
    }

    async fn binary_poll_fixture(
        HttpState(fixture): HttpState<BinaryHttpFixture>,
        HttpPath((database, handle)): HttpPath<(String, String)>,
        headers: HeaderMap,
    ) -> Response {
        assert_receiver_advertisement(&headers);
        assert_eq!(database, "route-1");
        assert_eq!(handle, BINARY_TEST_HANDLE);
        assert_eq!(headers.get("authorization").unwrap(), "Bearer secret");
        if fixture.polls.fetch_add(1, Ordering::SeqCst) == 0 {
            let mut response = binary_json(
                fixture.transfer,
                StatusCode::OK,
                json!({"api":fixture.transfer.route_api(),"export_handle":BINARY_TEST_HANDLE,
                       "status":"pending","expires_at":"2026-09-29T21:00:00Z"}),
            );
            if matches!(
                fixture.fault,
                BinaryWireFault::WrongPollSelection | BinaryWireFault::MatchingPollSelection
            ) {
                response.headers_mut().insert(
                    super::super::shapes::SELECTED_SHAPE_HEADER,
                    HeaderValue::from_str(
                        &serde_json::to_string(
                            &if matches!(fixture.fault, BinaryWireFault::MatchingPollSelection) {
                                super::super::shapes::v1(94, super::super::shapes::V1_94)
                            } else {
                                super::super::shapes::v1(95, super::super::shapes::V1_95)
                            }
                            .unwrap()
                            .shape(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                );
            }
            return response;
        }
        if matches!(fixture.fault, BinaryWireFault::InvalidPollJson) {
            return binary_json(fixture.transfer, StatusCode::OK, json!("not a poll object"));
        }
        if matches!(fixture.fault, BinaryWireFault::InvalidPollFields) {
            return binary_json(
                fixture.transfer,
                StatusCode::OK,
                json!({"api":"wrong-api","export_handle":BINARY_TEST_HANDLE,
                       "status":"pending","expires_at":"2026-09-29T21:00:00Z"}),
            );
        }
        if matches!(fixture.fault, BinaryWireFault::FailedPoll) {
            return binary_json(
                fixture.transfer,
                StatusCode::OK,
                json!({"api":fixture.transfer.route_api(),"export_handle":BINARY_TEST_HANDLE,
                       "status":"failed","expires_at":"2026-09-29T21:00:00Z",
                       "error_code":"capture_failed"}),
            );
        }
        let mut ready = json!({"api":fixture.transfer.route_api(),"export_handle":BINARY_TEST_HANDLE,
                   "status":"ready","expires_at":"2026-09-29T21:00:00Z",
                   "manifest":fixture.manifest,"size_bytes":fixture.manifest.snapshot.size_bytes,
                   "sha256":fixture.manifest.snapshot.sha256});
        if fixture.transfer != transfer_repr::SnapshotTransfer::IdentityV1 {
            ready["encoded_size_bytes"] = json!(fixture.bytes.len());
            ready["encoded_sha256"] = json!(hex::encode(Sha256::digest(&*fixture.bytes)));
            ready["transfer"] = json!({"encoding":"gzip","level":1});
        }
        match fixture.fault {
            BinaryWireFault::WrongApi => ready["api"] = json!("wrong-api"),
            BinaryWireFault::WrongHandle => {
                ready["export_handle"] = json!("12345678-1234-1234-1234-1234567890ab")
            }
            BinaryWireFault::UnknownLevel => ready["transfer"]["level"] = json!(9),
            BinaryWireFault::UnknownEncoding => ready["transfer"]["encoding"] = json!("zstd"),
            BinaryWireFault::MissingEncoded => {
                ready.as_object_mut().unwrap().remove("encoded_sha256");
            }
            _ => {}
        }
        let mut response = binary_json(fixture.transfer, StatusCode::OK, ready);
        if matches!(fixture.fault, BinaryWireFault::WrongReadySelection) {
            response.headers_mut().insert(
                super::super::shapes::SELECTED_SHAPE_HEADER,
                HeaderValue::from_str(
                    &serde_json::to_string(
                        &super::super::shapes::v1(95, super::super::shapes::V1_95)
                            .unwrap()
                            .shape(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            );
        }
        response
    }

    async fn binary_bytes_fixture(
        HttpState(fixture): HttpState<BinaryHttpFixture>,
        HttpPath((database, handle)): HttpPath<(String, String)>,
        headers: HeaderMap,
    ) -> Response {
        assert_receiver_advertisement(&headers);
        assert_eq!(database, "route-1");
        assert_eq!(handle, BINARY_TEST_HANDLE);
        assert_eq!(headers.get("authorization").unwrap(), "Bearer secret");
        let range = headers.get(RANGE).unwrap().to_str().unwrap().to_owned();
        let range_attempt = {
            let mut ranges = fixture.ranges.lock().unwrap();
            ranges.push(range.clone());
            ranges.iter().filter(|request| *request == &range).count()
        };
        if matches!(fixture.fault, BinaryWireFault::Redirect) {
            let mut response = StatusCode::FOUND.into_response();
            response.headers_mut().insert(
                axum::http::header::LOCATION,
                HeaderValue::from_static("http://127.0.0.1/should-not-follow"),
            );
            return response;
        }
        if matches!(fixture.fault, BinaryWireFault::Unauthorized) {
            return binary_json(
                fixture.transfer,
                StatusCode::FORBIDDEN,
                json!({"error":{"code":"owner_required"}}),
            );
        }
        let (start, end) = range
            .strip_prefix("bytes=")
            .unwrap()
            .split_once('-')
            .unwrap();
        let start: usize = start.parse().unwrap();
        let end: usize = end.parse().unwrap();
        assert!(end < fixture.bytes.len());
        if matches!(fixture.fault, BinaryWireFault::Unsatisfiable) {
            let mut response = binary_json(
                fixture.transfer,
                StatusCode::RANGE_NOT_SATISFIABLE,
                json!({"error":{"code":"range_not_satisfiable"}}),
            );
            response.headers_mut().insert(
                CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes */{}", fixture.bytes.len())).unwrap(),
            );
            return response;
        }
        let mut bytes = fixture.bytes[start..=end].to_vec();
        let byte_length = bytes.len();
        let interrupted = matches!(fixture.fault, BinaryWireFault::ShortBody)
            || start > 0
                && match fixture.fault {
                    BinaryWireFault::InterruptedOnce => range_attempt == 1,
                    BinaryWireFault::InterruptedAlways => true,
                    _ => false,
                };
        // A streamed body has no exact size hint, so this fixture can put a
        // deliberately false Content-Length on the wire without Hyper
        // rejecting the test response before the client sees it.
        if matches!(fixture.fault, BinaryWireFault::HeaderLength) {
            bytes.push(0);
        }
        let body = if matches!(fixture.fault, BinaryWireFault::Length) || interrupted {
            let bytes = if interrupted {
                bytes[..byte_length - 1].to_vec()
            } else {
                bytes
            };
            Body::from_stream(futures::stream::once(async move {
                Ok::<_, std::io::Error>(axum::body::Bytes::from(bytes))
            }))
        } else {
            Body::from(bytes.clone())
        };
        let mut response = Response::new(body);
        *response.status_mut() = StatusCode::PARTIAL_CONTENT;
        let headers = response.headers_mut();
        if matches!(fixture.fault, BinaryWireFault::WrongRangeSelection) {
            headers.insert(
                super::super::shapes::SELECTED_SHAPE_HEADER,
                HeaderValue::from_str(
                    &serde_json::to_string(
                        &super::super::shapes::v1(95, super::super::shapes::V1_95)
                            .unwrap()
                            .shape(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            );
        }
        headers.insert(
            "x-native-export-api",
            HeaderValue::from_static(
                if matches!(fixture.fault, BinaryWireFault::WrongApiHeader) {
                    "wrong-api"
                } else {
                    fixture.transfer.route_api()
                },
            ),
        );
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(if matches!(fixture.fault, BinaryWireFault::MediaType) {
                "application/octet-stream"
            } else if fixture.transfer == transfer_repr::SnapshotTransfer::IdentityV1 {
                STANDBY_SNAPSHOT_MEDIA_TYPE
            } else {
                "application/gzip"
            }),
        );
        if matches!(fixture.fault, BinaryWireFault::ContentEncoding) {
            headers.insert(
                axum::http::header::CONTENT_ENCODING,
                HeaderValue::from_static("gzip"),
            );
        }
        headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        let claimed_length = if matches!(
            fixture.fault,
            BinaryWireFault::Length | BinaryWireFault::HeaderLength
        ) {
            byte_length + 1
        } else {
            byte_length
        };
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&claimed_length.to_string()).unwrap(),
        );
        let content_range = if matches!(fixture.fault, BinaryWireFault::ContentRange) {
            format!("bytes {start}-{end}/{}", fixture.bytes.len() + 1)
        } else {
            format!("bytes {start}-{end}/{}", fixture.bytes.len())
        };
        headers.insert(
            CONTENT_RANGE,
            HeaderValue::from_str(&content_range).unwrap(),
        );
        let etag = if matches!(fixture.fault, BinaryWireFault::Etag) {
            format!("\"{}\"", "0".repeat(64))
        } else {
            format!(
                "\"{}\"",
                if fixture.transfer == transfer_repr::SnapshotTransfer::IdentityV1 {
                    fixture.manifest.snapshot.sha256.clone()
                } else {
                    hex::encode(Sha256::digest(&*fixture.bytes))
                }
            )
        };
        headers.insert(ETAG, HeaderValue::from_str(&etag).unwrap());
        response
    }

    async fn binary_cancel_fixture(
        HttpState(fixture): HttpState<BinaryHttpFixture>,
        HttpPath((database, handle)): HttpPath<(String, String)>,
        headers: HeaderMap,
    ) -> Response {
        assert_receiver_advertisement(&headers);
        assert_eq!(database, "route-1");
        assert_eq!(handle, BINARY_TEST_HANDLE);
        assert_eq!(headers.get("authorization").unwrap(), "Bearer secret");
        fixture.cancels.fetch_add(1, Ordering::SeqCst);
        binary_json(
            fixture.transfer,
            StatusCode::OK,
            json!({"api":fixture.transfer.route_api(),"status":"cancelled"}),
        )
    }

    async fn binary_authority_fixture(
        HttpState(fixture): HttpState<BinaryHttpFixture>,
        HttpPath(database): HttpPath<String>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Response {
        assert_receiver_advertisement(&headers);
        assert_eq!(database, "route-1");
        assert_eq!(headers.get("authorization").unwrap(), "Bearer secret");
        fixture.mcp_calls.fetch_add(1, Ordering::SeqCst);
        if fixture.authority.is_none()
            || matches!(fixture.fault, BinaryWireFault::HeadProbeUnavailable)
        {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"head unavailable"})),
            )
                .into_response();
        }
        let authority = fixture.authority.expect("delta authority fixture");
        let operation = body["params"]["arguments"]["operation"].as_str().unwrap();
        let result = match operation {
            super::super::delta_transport::AUTHORITY_ACT_HEAD_OPERATION => {
                super::super::delta_transport::observe_authority_act_head(&authority, "route-1")
                    .await
                    .map(|value| serde_json::to_value(value).unwrap())
            }
            super::super::delta_transport::AUTHORITY_ACT_DELTA_OPERATION => {
                let from = body["params"]["arguments"]["arguments"]["from_exclusive_act"]
                    .as_i64()
                    .unwrap();
                super::super::delta_transport::observe_authority_act_delta(
                    &authority, "route-1", from,
                )
                .await
                .map(|value| serde_json::to_value(value).unwrap())
            }
            other => panic!("unexpected authority operation {other}"),
        };
        let envelope = match result {
            Ok(structured) => json!({
                "jsonrpc":"2.0","id":1,
                "result":{"content":[],"structuredContent":structured,
                          "isError":false,"resultType":"complete","_meta":{}}
            }),
            Err(_) => json!({"jsonrpc":"2.0","id":1,
                              "error":{"code":-32000,"message":"authority refused"}}),
        };
        (StatusCode::OK, Json(envelope)).into_response()
    }

    async fn serve_binary_fixture(
        fixture: BinaryHttpFixture,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let version = if fixture.transfer == transfer_repr::SnapshotTransfer::IdentityV1 {
            "v1"
        } else {
            "v2"
        };
        let base = format!("/{version}/databases/{{database}}/standby-snapshot/exports");
        let mut router = Router::new()
            .route("/mcp/{database}", post(binary_authority_fixture))
            .route(&base, post(binary_start_fixture))
            .route(
                &format!("{base}/{{handle}}"),
                get(binary_poll_fixture).delete(binary_cancel_fixture),
            )
            .route(
                &format!("{base}/{{handle}}/bytes"),
                get(binary_bytes_fixture),
            );
        if version == "v2" {
            let legacy = fixture.legacy_starts.clone();
            router = router.route(
                "/v1/databases/{database}/standby-snapshot/exports",
                post(move || {
                    let legacy = legacy.clone();
                    async move {
                        legacy.fetch_add(1, Ordering::SeqCst);
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                }),
            );
        }
        let router = router.with_state(fixture);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (port, task)
    }

    #[tokio::test]
    async fn binary_capture_and_transfer_observe_rotated_credentials() {
        type Reply<T> = Pin<Box<dyn Future<Output = std::result::Result<T, AttemptError>> + Send>>;
        struct RotatingClient {
            credential: PathBuf,
            bytes: Vec<u8>,
            manifest: StandbySnapshotManifest,
            expected: Mutex<String>,
            reads: AtomicUsize,
        }
        impl binary::BinarySnapshotClient for RotatingClient {
            fn start(
                &self,
                _origin: String,
                _database: String,
                bearer: String,
                _consumer: StandbyConsumerIdentity,
                _transfer: transfer_repr::SnapshotTransfer,
            ) -> Reply<binary::BinaryExport> {
                assert_eq!(bearer, "secret");
                fs::write(&self.credential, "after-capture-start").unwrap();
                *self.expected.lock().unwrap() = "after-capture-start".into();
                Box::pin(async { Ok(BINARY_TEST_HANDLE.into()) })
            }
            fn poll(
                &self,
                _origin: String,
                _database: String,
                bearer: String,
                _handle: binary::BinaryExport,
            ) -> Reply<binary::BinaryPoll> {
                assert_eq!(bearer, *self.expected.lock().unwrap());
                fs::write(&self.credential, "after-capture-ready").unwrap();
                *self.expected.lock().unwrap() = "after-capture-ready".into();
                let reply = binary::BinaryPoll::Ready {
                    selected: None,
                    manifest: Box::new(self.manifest.clone()),
                    size: self.bytes.len() as u64,
                    sha256: self.manifest.snapshot.sha256.clone(),
                    encoded: None,
                };
                Box::pin(async { Ok(reply) })
            }
            fn read(&self, request: binary::BinaryReadRequest) -> Reply<Vec<u8>> {
                assert_eq!(request.bearer, *self.expected.lock().unwrap());
                let next = format!("after-chunk-{}", self.reads.fetch_add(1, Ordering::SeqCst));
                fs::write(&self.credential, &next).unwrap();
                *self.expected.lock().unwrap() = next;
                let start = request.offset as usize;
                let bytes = self.bytes[start..start + request.length].to_vec();
                Box::pin(async { Ok(bytes) })
            }
            fn cancel(
                &self,
                _origin: String,
                _database: String,
                bearer: String,
                _handle: binary::BinaryExport,
            ) -> Reply<()> {
                assert_eq!(bearer, *self.expected.lock().unwrap());
                Box::pin(async { Ok(()) })
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO blobs (id, bytes, size_bytes, storage_tier, created_at)
             VALUES ('credential-padding', zeroblob(1200000), 1200000, 'inline', '2026-07-31T00:00:00Z')",
        )
        .execute(db.write_pool())
        .await
        .unwrap();
        let (bytes, manifest) = snapshot_fixture(&db).await;
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(AlwaysFailClient {
                class: RefreshFailureClass::Protocol,
                calls: AtomicUsize::new(0),
            }),
        );
        let client = Arc::new(RotatingClient {
            credential: controller.config.credential_file.clone(),
            bytes,
            manifest,
            expected: Mutex::new("secret".into()),
            reads: AtomicUsize::new(0),
        });
        controller.binary_client = client.clone();
        controller.binary_snapshot_enabled = true;
        let result = controller.refresh_once(RefreshCause::Manual).await.unwrap();
        assert!(matches!(result, StandbyRefreshOutcome::Installed { .. }));
        assert!(client.reads.load(Ordering::SeqCst) >= 2);
    }

    type BinaryReply<T> =
        Pin<Box<dyn Future<Output = std::result::Result<T, AttemptError>> + Send>>;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ResumePollMode {
        Ready,
        ChangedSha,
        ChangedDecodedSize,
        ChangedManifest,
        ChangedEncodedSha,
        ChangedEncodedSize,
        Pending,
        Gone,
        Auth,
        Refused(RefreshFailureClass),
    }

    /// Deterministic BinarySnapshotClient seam for resume tests: scripted
    /// polls and a read budget, with full observability of starts, polls,
    /// range reads, cancels, and presented bearers.
    struct ScriptedBinaryClient {
        transfer: Mutex<transfer_repr::SnapshotTransfer>,
        bytes: Mutex<Vec<u8>>,
        manifest: Mutex<StandbySnapshotManifest>,
        starts: AtomicUsize,
        polls: AtomicUsize,
        reads: AtomicUsize,
        cancels: AtomicUsize,
        poll_selection_once: Mutex<Option<super::super::shapes::Shape>>,
        poll_bearers: Mutex<Vec<String>>,
        start_bearers: Mutex<Vec<String>>,
        read_bearers: Mutex<Vec<String>>,
        fail_pending_save: Mutex<Option<PathBuf>>,
        obstruct_cleanup_on_read: Mutex<Option<PathBuf>>,
        poll_mode: Mutex<ResumePollMode>,
        succeed_reads: AtomicUsize,
        /// One poll index answers Gone; the replacement remains live.
        gone_on_poll: AtomicUsize,
        /// One-shot gate: the first range read past offset 0 takes and
        /// waits on it, letting abort tests strand a transfer mid-fill.
        range_gate: Mutex<Option<Arc<tokio::sync::Notify>>>,
        range_control: Mutex<Option<Arc<concurrent::RangeReadControl>>>,
    }

    impl ScriptedBinaryClient {
        fn for_snapshot(bytes: Vec<u8>, manifest: StandbySnapshotManifest) -> Self {
            Self {
                transfer: Mutex::new(transfer_repr::SnapshotTransfer::IdentityV1),
                bytes: Mutex::new(bytes),
                manifest: Mutex::new(manifest),
                starts: AtomicUsize::new(0),
                polls: AtomicUsize::new(0),
                reads: AtomicUsize::new(0),
                cancels: AtomicUsize::new(0),
                poll_selection_once: Mutex::new(None),
                poll_bearers: Mutex::new(Vec::new()),
                start_bearers: Mutex::new(Vec::new()),
                read_bearers: Mutex::new(Vec::new()),
                fail_pending_save: Mutex::new(None),
                obstruct_cleanup_on_read: Mutex::new(None),
                poll_mode: Mutex::new(ResumePollMode::Ready),
                succeed_reads: AtomicUsize::new(usize::MAX),
                gone_on_poll: AtomicUsize::new(usize::MAX),
                range_gate: Mutex::new(None),
                range_control: Mutex::new(None),
            }
        }

        fn handle_for(starts: usize) -> String {
            format!("12345678-1234-1234-1234-{starts:012}")
        }

        fn auth_error() -> AttemptError {
            AttemptError::new(
                RefreshFailureClass::Authentication,
                "standby binary authentication was refused",
                Error::auth("standby binary authentication was refused"),
            )
        }

        fn gone_error() -> AttemptError {
            AttemptError::new(
                RefreshFailureClass::Protocol,
                "standby binary export is gone",
                Error::engine("standby binary export is gone"),
            )
            .with_detail("http_404")
        }

        fn network_error() -> AttemptError {
            AttemptError::new(
                RefreshFailureClass::Network,
                "hosted snapshot request failed",
                Error::engine("hosted snapshot request failed"),
            )
        }
    }

    impl binary::BinarySnapshotClient for ScriptedBinaryClient {
        fn start(
            &self,
            _origin: String,
            _database: String,
            bearer: String,
            _consumer: StandbyConsumerIdentity,
            _transfer: transfer_repr::SnapshotTransfer,
        ) -> BinaryReply<binary::BinaryExport> {
            self.start_bearers.lock().unwrap().push(bearer);
            if let Some(dir) = self.fail_pending_save.lock().unwrap().take() {
                fs::create_dir(dir.join("transfer-pending.json.tmp")).unwrap();
            }
            let index = self.starts.fetch_add(1, Ordering::SeqCst) + 1;
            let handle = binary::BinaryExport {
                selected: None,
                actual_shape: None,
                poll_selection: None,
                handle: Self::handle_for(index),
                transfer: *self.transfer.lock().unwrap(),
            };
            Box::pin(async move { Ok(handle) })
        }

        fn poll(
            &self,
            _origin: String,
            _database: String,
            bearer: String,
            _handle: binary::BinaryExport,
        ) -> BinaryReply<binary::BinaryPoll> {
            let index = self.polls.fetch_add(1, Ordering::SeqCst);
            self.poll_bearers.lock().unwrap().push(bearer);
            if index == self.gone_on_poll.load(Ordering::SeqCst) {
                return Box::pin(async { Err(Self::gone_error()) });
            }
            if let Some(selected) = self.poll_selection_once.lock().unwrap().take() {
                return Box::pin(async move { Ok(binary::BinaryPoll::Pending(Some(selected))) });
            }
            match *self.poll_mode.lock().unwrap() {
                ResumePollMode::Pending => {
                    Box::pin(async { Ok(binary::BinaryPoll::Pending(None)) })
                }
                ResumePollMode::Gone => Box::pin(async { Err(Self::gone_error()) }),
                ResumePollMode::Auth => Box::pin(async { Err(Self::auth_error()) }),
                ResumePollMode::Refused(class) => Box::pin(async move {
                    Err(AttemptError::new(
                        class,
                        "standby binary poll refused",
                        Error::engine("standby binary poll refused"),
                    ))
                }),
                mode => {
                    let bytes = self.bytes.lock().unwrap().clone();
                    let mut manifest = self.manifest.lock().unwrap().clone();
                    if mode == ResumePollMode::ChangedSha {
                        manifest.snapshot.sha256 = "f".repeat(64);
                    }
                    if mode == ResumePollMode::ChangedDecodedSize {
                        manifest.snapshot.size_bytes += 1;
                    }
                    if mode == ResumePollMode::ChangedManifest {
                        manifest.engine.source_sha = "b".repeat(40);
                        manifest.validate().unwrap();
                    }
                    let reply = binary::BinaryPoll::Ready {
                        selected: None,
                        size: manifest.snapshot.size_bytes,
                        sha256: manifest.snapshot.sha256.clone(),
                        manifest: Box::new(manifest),
                        encoded: if *self.transfer.lock().unwrap()
                            == transfer_repr::SnapshotTransfer::IdentityV1
                        {
                            None
                        } else {
                            Some((
                                bytes.len() as u64
                                    + u64::from(mode == ResumePollMode::ChangedEncodedSize),
                                if mode == ResumePollMode::ChangedEncodedSha {
                                    "e".repeat(64)
                                } else {
                                    hex::encode(Sha256::digest(&bytes))
                                },
                            ))
                        },
                    };
                    Box::pin(async { Ok(reply) })
                }
            }
        }

        fn read(&self, request: binary::BinaryReadRequest) -> BinaryReply<Vec<u8>> {
            self.read_bearers
                .lock()
                .unwrap()
                .push(request.bearer.clone());
            let index = self.reads.fetch_add(1, Ordering::SeqCst);
            if index >= self.succeed_reads.load(Ordering::SeqCst) {
                return Box::pin(async { Err(Self::network_error()) });
            }
            let bytes = self.bytes.lock().unwrap();
            let chunk =
                bytes[request.offset as usize..request.offset as usize + request.length].to_vec();
            let is_last = request.offset as usize + request.length == bytes.len();
            drop(bytes);
            if let Some(control) = self.range_control.lock().unwrap().clone() {
                return control.read(request.offset, request.bearer, chunk);
            }
            if is_last {
                if let Some(dir) = self.obstruct_cleanup_on_read.lock().unwrap().take() {
                    fs::create_dir(dir.join("binary-pending.json.tmp")).unwrap();
                }
            }
            if request.offset > 0 {
                if let Some(gate) = self.range_gate.lock().unwrap().take() {
                    return Box::pin(async move {
                        gate.notified().await;
                        Ok(chunk)
                    });
                }
            }
            Box::pin(async { Ok(chunk) })
        }

        fn cancel(
            &self,
            _origin: String,
            _database: String,
            _bearer: String,
            _handle: binary::BinaryExport,
        ) -> BinaryReply<()> {
            self.cancels.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }

    fn resume_test_controller(
        directory: &tempfile::TempDir,
        origin: String,
        client: Arc<ScriptedBinaryClient>,
    ) -> StandbyRefreshController {
        let mut controller = controller_for_origin(
            directory,
            origin,
            Arc::new(AlwaysFailClient {
                class: RefreshFailureClass::Protocol,
                calls: AtomicUsize::new(0),
            }),
        );
        controller.binary_client = client;
        controller.binary_snapshot_enabled = true;
        controller
    }

    type SnapshotFixture = (Vec<u8>, StandbySnapshotManifest);

    /// Two genuine snapshots: a base install plus a grown replacement that
    /// spans several 1 MiB ranges.
    async fn resume_snapshots(db: &crate::Db) -> (SnapshotFixture, SnapshotFixture) {
        let base = snapshot_fixture(db).await;
        sqlx::query(
            "INSERT INTO blobs (id, bytes, size_bytes, storage_tier, created_at)
             VALUES ('resume-padding', zeroblob(1200000), 1200000, 'inline', '2026-07-31T00:00:00Z')",
        )
        .execute(db.write_pool())
        .await
        .unwrap();
        crate::store::append(
            db,
            crate::store::AppendSpec {
                record_id: uuid::Uuid::new_v4().to_string(),
                event_type: "record.created".into(),
                payload: json!({"type":"Document","kind":"note","name":"resume successor"}),
                actor: None,
            },
        )
        .await
        .unwrap();
        let grown = snapshot_fixture(db).await;
        assert!(grown.0.len() > 1024 * 1024);
        (base, grown)
    }

    #[tokio::test]
    async fn resume_survives_exhausted_retries_and_restarts_within_cooldown() {
        let authority = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let ((bytes_a, manifest_a), (bytes_b, manifest_b)) = resume_snapshots(&authority).await;
        let chunks_b = bytes_b.len().div_ceil(1024 * 1024);
        assert!(chunks_b >= 2);
        let (port, server, _) =
            chunked::serve_host(authority.clone(), chunked::HostRoute::CaptureTooLarge).await;
        let host_origin = format!("http://127.0.0.1:{port}");
        let directory = tempfile::tempdir().unwrap();
        let fake = Arc::new(ScriptedBinaryClient::for_snapshot(
            bytes_a.clone(),
            manifest_a.clone(),
        ));
        let mut controller = resume_test_controller(&directory, origin.clone(), fake.clone());
        controller.config.hosted_origin = host_origin.clone();
        // Phase 0: install the accepted copy the later cooldown needs.
        let StandbyRefreshOutcome::Installed { generation, .. } =
            controller.refresh_once(RefreshCause::Manual).await.unwrap()
        else {
            panic!("the base snapshot must install");
        };
        assert_eq!(fs::read(&generation.snapshot_path).unwrap(), bytes_a);
        let accepted_before_failure = controller.state().unwrap();
        // Phase 1: a replacement export fails midway through its ranges.
        enable_deltas(&mut controller);
        *fake.bytes.lock().unwrap() = bytes_b.clone();
        *fake.manifest.lock().unwrap() = manifest_b.clone();
        fake.succeed_reads
            .store(fake.reads.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
        assert!(controller.refresh_once(RefreshCause::Manual).await.is_err());
        assert_eq!(
            controller.state().unwrap().last_failure_class,
            Some(RefreshFailureClass::Network)
        );
        let refresh_dir = controller.refresh_dir.clone();
        assert!(refresh_dir.join("binary-resume.json").exists());
        assert!(refresh_dir.join("binary-resume.partial.db").exists());
        let saved = binary_resume::load_resume_ledger(&refresh_dir, &controller.resume_binding())
            .unwrap()
            .unwrap();
        let failed = controller.state().unwrap();
        assert!(!failed.refresh_active);
        assert_eq!(
            failed.last_success_at,
            accepted_before_failure.last_success_at
        );
        assert_eq!(
            failed.snapshot_captured_at,
            accepted_before_failure.snapshot_captured_at
        );
        let transfer = failed.transfer_progress.unwrap();
        assert_eq!(transfer.activity, StandbyTransferActivity::Inactive);
        assert_eq!(
            transfer.bytes_completed,
            Some(saved.completed.iter().map(|range| range.length).sum())
        );
        assert!(transfer.retained_for_resume);
        assert_eq!(saved.completed.len(), 1);
        assert_eq!(saved.completed[0].length, binary_resume::RESUME_CHUNK_BYTES);
        let full_refresh_at = controller.state().unwrap().last_full_refresh_at.clone();
        assert!(full_refresh_at.is_some());
        // Phase 2: a new controller with renewed credentials resumes inside
        // the cooldown instead of deferring or capturing again.
        drop(controller);
        let mut controller = resume_test_controller(&directory, origin.clone(), fake.clone());
        controller.config.hosted_origin = host_origin;
        enable_deltas(&mut controller);
        fs::write(&controller.config.credential_file, b"rotated\n").unwrap();
        controller.config.full_refresh_min_interval_seconds = Some(3600);
        fake.succeed_reads.store(usize::MAX, Ordering::SeqCst);
        let polls_before = fake.polls.load(Ordering::SeqCst);
        let reads_before = fake.reads.load(Ordering::SeqCst);
        let StandbyRefreshOutcome::Installed { generation, .. } = controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap()
        else {
            panic!("the retained export must resume inside the cooldown");
        };
        assert_eq!(fs::read(&generation.snapshot_path).unwrap(), bytes_b);
        assert_eq!(fake.starts.load(Ordering::SeqCst), 2);
        assert_eq!(
            controller.state().unwrap().last_full_refresh_at,
            full_refresh_at
        );
        assert!(fake.polls.load(Ordering::SeqCst) >= polls_before + 2);
        assert_eq!(
            fake.reads.load(Ordering::SeqCst) - reads_before,
            chunks_b - 1
        );
        assert!(fake
            .poll_bearers
            .lock()
            .unwrap()
            .iter()
            .any(|bearer| bearer == "rotated"));
        assert!(fake.read_bearers.lock().unwrap()[reads_before..]
            .iter()
            .all(|bearer| bearer == "rotated"));
        assert_eq!(
            controller.state().unwrap().last_delta_fallback_class,
            Some(DeltaFallbackClass::DeltaTooLarge)
        );
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        authority.close().await;
    }

    #[tokio::test]
    async fn missing_handle_defers_replacement_inside_cooldown() {
        let authority = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let ((bytes_a, manifest_a), (bytes_b, manifest_b)) = resume_snapshots(&authority).await;
        let (port, server, _) =
            chunked::serve_host(authority.clone(), chunked::HostRoute::CaptureTooLarge).await;
        let host_origin = format!("http://127.0.0.1:{port}");
        let directory = tempfile::tempdir().unwrap();
        let fake = Arc::new(ScriptedBinaryClient::for_snapshot(
            bytes_a.clone(),
            manifest_a.clone(),
        ));
        let mut controller = resume_test_controller(&directory, origin.clone(), fake.clone());
        controller.config.hosted_origin = host_origin.clone();
        let StandbyRefreshOutcome::Installed { .. } =
            controller.refresh_once(RefreshCause::Manual).await.unwrap()
        else {
            panic!("the base snapshot must install");
        };
        let accepted_before = controller.state().unwrap();
        enable_deltas(&mut controller);
        *fake.bytes.lock().unwrap() = bytes_b.clone();
        *fake.manifest.lock().unwrap() = manifest_b.clone();
        fake.succeed_reads
            .store(fake.reads.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
        assert!(controller.refresh_once(RefreshCause::Manual).await.is_err());
        controller.config.full_refresh_min_interval_seconds = Some(3600);
        // The handle is gone server-side: clear the cache, then defer the
        // replacement while the cooldown holds instead of capturing again.
        *fake.poll_mode.lock().unwrap() = ResumePollMode::Gone;
        let StandbyRefreshOutcome::Deferred { reason, .. } = controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap()
        else {
            panic!("a missing handle inside the cooldown must defer");
        };
        assert_eq!(reason, DEFERRED_FULL_REFRESH_INTERVAL);
        let deferred = controller.state().unwrap();
        assert!(!deferred.refresh_active);
        assert_eq!(deferred.last_success_at, accepted_before.last_success_at);
        assert_eq!(
            deferred.snapshot_captured_at,
            accepted_before.snapshot_captured_at
        );
        let transfer = deferred.transfer_progress.unwrap();
        assert_eq!(transfer.activity, StandbyTransferActivity::Inactive);
        assert!(!transfer.retained_for_resume);
        assert_eq!(transfer.bytes_completed, None);
        assert_eq!(fake.starts.load(Ordering::SeqCst), 2);
        assert!(!controller.refresh_dir.join("binary-resume.json").exists());
        assert!(!controller
            .refresh_dir
            .join("binary-resume.partial.db")
            .exists());
        // Outside the cooldown the same attempt starts exactly one fresh export.
        let mut state = controller.state().unwrap();
        state.last_full_refresh_at = Some("2020-01-01T00:00:00Z".into());
        controller.write_state(&state).unwrap();
        *fake.poll_mode.lock().unwrap() = ResumePollMode::Ready;
        fake.succeed_reads.store(usize::MAX, Ordering::SeqCst);
        let StandbyRefreshOutcome::Installed { generation, .. } = controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap()
        else {
            panic!("a missing handle outside the cooldown must capture once");
        };
        assert_eq!(fs::read(&generation.snapshot_path).unwrap(), bytes_b);
        assert_eq!(fake.starts.load(Ordering::SeqCst), 3);
        assert_eq!(
            controller.state().unwrap().last_delta_fallback_class,
            Some(DeltaFallbackClass::DeltaTooLarge)
        );
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        authority.close().await;
    }

    #[tokio::test]
    async fn fully_cached_export_still_polls_before_reuse() {
        let authority = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let fake = Arc::new(ScriptedBinaryClient::for_snapshot(
            bytes.clone(),
            manifest.clone(),
        ));
        let controller = resume_test_controller(&directory, origin, fake.clone());
        // Seed a fully downloaded ledger plus partial directly: the success
        // path consumes them, so a completed download cannot set this up.
        let refresh_dir = controller.refresh_dir.clone();
        let binding = binary_resume::ResumeBinding {
            origin: controller.config.hosted_origin.clone(),
            hosted_route_database_id: "route-1".into(),
            origin_database_id: controller.runtime.origin_database_id.clone(),
            consumer: controller.declared_consumer(),
        };
        let mut ledger = binary_resume::new_ready_ledger(
            &binding,
            ScriptedBinaryClient::handle_for(0),
            bytes.len() as u64,
            manifest.snapshot.sha256.clone(),
            manifest.clone(),
            "2026-10-16T00:00:00Z".into(),
        );
        // Seed via the same helpers the downloader uses.
        binary_resume::prepare_partial_file(&refresh_dir, bytes.len() as u64).unwrap();
        let mut offset = 0_u64;
        for chunk in bytes.chunks(1024 * 1024) {
            let hash = binary_resume::write_range_and_hash(&refresh_dir, offset, chunk).unwrap();
            binary_resume::record_completed_range(&mut ledger, offset, chunk.len() as u64, hash)
                .unwrap();
            offset += chunk.len() as u64;
        }
        binary_resume::save_resume_ledger(&refresh_dir, &ledger).unwrap();
        // Even complete bytes cannot bypass a fresh authorization decision.
        *fake.poll_mode.lock().unwrap() = ResumePollMode::Auth;
        let refused = directory.path().join("refused.snapshot.db");
        let error = controller
            .download_binary_only(
                "obsolete".into(),
                &refused,
                binary::FreshCaptureBudget::Allowed,
            )
            .await
            .unwrap_err();
        assert_eq!(error.class, RefreshFailureClass::Authentication);
        assert!(!refused.exists());
        assert_eq!(fake.reads.load(Ordering::SeqCst), 0);
        assert_eq!(fake.starts.load(Ordering::SeqCst), 0);
        assert!(refresh_dir.join("binary-resume.json").exists());
        *fake.poll_mode.lock().unwrap() = ResumePollMode::Ready;
        // Reuse re-polls the server and downloads nothing: no fresh capture.
        let target = directory.path().join("reused.snapshot.db");
        let reused = controller
            .download_binary_only(
                "secret".into(),
                &target,
                binary::FreshCaptureBudget::Allowed,
            )
            .await
            .unwrap();
        assert_eq!(reused.snapshot.sha256, manifest.snapshot.sha256);
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert_eq!(fake.starts.load(Ordering::SeqCst), 0);
        assert_eq!(fake.reads.load(Ordering::SeqCst), 0);
        assert!(fake.polls.load(Ordering::SeqCst) >= 1);
        authority.close().await;
    }

    #[tokio::test]
    async fn changed_ready_metadata_is_refused() {
        let authority = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let ((_, _), (bytes_b, manifest_b)) = resume_snapshots(&authority).await;
        for mode in [
            ResumePollMode::ChangedSha,
            ResumePollMode::ChangedManifest,
            ResumePollMode::Ready,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let fake = Arc::new(ScriptedBinaryClient::for_snapshot(
                bytes_b.clone(),
                manifest_b.clone(),
            ));
            let controller = resume_test_controller(&directory, origin.clone(), fake.clone());
            // Interrupt after the ready identity is ledgered but bytes remain.
            fake.succeed_reads
                .store(fake.reads.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
            let partial = directory.path().join("partial.snapshot.db");
            assert!(controller
                .download_binary_only(
                    "secret".into(),
                    &partial,
                    binary::FreshCaptureBudget::Allowed
                )
                .await
                .is_err());
            assert!(controller.refresh_dir.join("binary-resume.json").exists());
            // The server's ready identity moved: refuse outright, clear the
            // cache, and never capture a replacement as a fallback here.
            if mode == ResumePollMode::Ready {
                let path = controller.refresh_dir.join("binary-resume.json");
                let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                saved.as_object_mut().unwrap().remove("manifest");
                fs::write(path, serde_json::to_vec(&saved).unwrap()).unwrap();
            }
            *fake.poll_mode.lock().unwrap() = mode;
            fake.succeed_reads.store(usize::MAX, Ordering::SeqCst);
            let retry = directory.path().join("retry.snapshot.db");
            let failure = controller
                .download_binary_only("secret".into(), &retry, binary::FreshCaptureBudget::Allowed)
                .await
                .unwrap_err();
            assert_eq!(failure.class, RefreshFailureClass::DownloadIntegrity);
            assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
            assert!(!controller.refresh_dir.join("binary-resume.json").exists());
            assert!(!retry.exists());
        }
        authority.close().await;
    }

    #[tokio::test]
    async fn interrupted_staging_cleanup_spares_owned_resume() {
        let authority = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let ((_, _), (bytes_b, manifest_b)) = resume_snapshots(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let fake = Arc::new(ScriptedBinaryClient::for_snapshot(
            bytes_b.clone(),
            manifest_b.clone(),
        ));
        fake.succeed_reads
            .store(fake.reads.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
        let controller = resume_test_controller(&directory, origin, fake.clone());
        let partial = directory.path().join("partial.snapshot.db");
        assert!(controller
            .download_binary_only(
                "secret".into(),
                &partial,
                binary::FreshCaptureBudget::Allowed
            )
            .await
            .is_err());
        let orphan = controller
            .store
            .staging_dir()
            .join(format!("refresh-{}.snapshot.db", uuid::Uuid::new_v4()));
        fs::write(&orphan, b"orphan").unwrap();
        let replay = controller.store.staging_dir().join("kernel-replay-AbCd12");
        fs::create_dir(&replay).unwrap();
        fs::write(replay.join("snapshot.db"), b"private scratch").unwrap();
        let delta = controller.store.staging_dir().join("kernel-delta-AbCd12");
        let manifest = controller
            .store
            .staging_dir()
            .join("kernel-manifest-AbCd12");
        fs::write(&delta, b"scratch checkpoint").unwrap();
        fs::write(&manifest, b"scratch manifest").unwrap();
        let unrelated = controller
            .store
            .staging_dir()
            .join("kernel-replay-operator-notes");
        fs::write(&unrelated, b"keep").unwrap();
        controller.cleanup_interrupted_staging().unwrap();
        assert!(!replay.exists() && !delta.exists() && !manifest.exists());
        assert!(unrelated.exists());
        assert!(!orphan.exists());
        assert!(controller.refresh_dir.join("binary-resume.json").exists());
        assert!(controller
            .refresh_dir
            .join("binary-resume.partial.db")
            .exists());
        authority.close().await;
    }

    #[tokio::test]
    async fn auth_refusal_preserves_cache_without_fresh_capture() {
        let authority = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let ((_, _), (bytes_b, manifest_b)) = resume_snapshots(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let fake = Arc::new(ScriptedBinaryClient::for_snapshot(
            bytes_b.clone(),
            manifest_b.clone(),
        ));
        let controller = resume_test_controller(&directory, origin, fake.clone());
        // Interrupt after the ready identity is ledgered but bytes remain.
        fake.succeed_reads
            .store(fake.reads.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
        let partial = directory.path().join("partial.snapshot.db");
        assert!(controller
            .download_binary_only(
                "secret".into(),
                &partial,
                binary::FreshCaptureBudget::Allowed
            )
            .await
            .is_err());
        // An authentication refusal on reuse preserves the cache and never
        // starts a fresh capture as a fallback.
        *fake.poll_mode.lock().unwrap() = ResumePollMode::Auth;
        let retry = directory.path().join("retry.snapshot.db");
        let failure = controller
            .download_binary_only("secret".into(), &retry, binary::FreshCaptureBudget::Allowed)
            .await
            .unwrap_err();
        assert_eq!(failure.class, RefreshFailureClass::Authentication);
        assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
        assert_eq!(fake.cancels.load(Ordering::SeqCst), 0);
        assert!(controller.refresh_dir.join("binary-resume.json").exists());
        assert!(!retry.exists());
        authority.close().await;
    }

    #[tokio::test]
    async fn live_probe_then_gone_transfer_defers_inside_cooldown() {
        let authority = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let ((bytes_a, manifest_a), (bytes_b, manifest_b)) = resume_snapshots(&authority).await;
        let (port, server, _) =
            chunked::serve_host(authority.clone(), chunked::HostRoute::CaptureTooLarge).await;
        let host_origin = format!("http://127.0.0.1:{port}");
        let directory = tempfile::tempdir().unwrap();
        let fake = Arc::new(ScriptedBinaryClient::for_snapshot(
            bytes_a.clone(),
            manifest_a.clone(),
        ));
        let mut controller = resume_test_controller(&directory, origin.clone(), fake.clone());
        controller.config.hosted_origin = host_origin.clone();
        let StandbyRefreshOutcome::Installed { .. } =
            controller.refresh_once(RefreshCause::Manual).await.unwrap()
        else {
            panic!("the base snapshot must install");
        };
        enable_deltas(&mut controller);
        *fake.bytes.lock().unwrap() = bytes_b.clone();
        *fake.manifest.lock().unwrap() = manifest_b.clone();
        fake.succeed_reads
            .store(fake.reads.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
        assert!(controller.refresh_once(RefreshCause::Manual).await.is_err());
        let full_refresh_at = controller.state().unwrap().last_full_refresh_at.clone();
        controller.config.full_refresh_min_interval_seconds = Some(3600);
        // The probe poll still sees the handle; the next poll reports it
        // gone. No replacement capture may start inside the cooldown.
        let cancels_before = fake.cancels.load(Ordering::SeqCst);
        fake.gone_on_poll
            .store(fake.polls.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
        let StandbyRefreshOutcome::Deferred { reason, .. } = controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap()
        else {
            panic!("a handle lost inside the cooldown must defer");
        };
        assert_eq!(reason, DEFERRED_FULL_REFRESH_INTERVAL);
        assert!(controller
            .state()
            .unwrap()
            .next_full_refresh_eligible_at
            .is_some());
        assert_eq!(fake.starts.load(Ordering::SeqCst), 2);
        // The base successful download may already have issued DELETE.
        assert_eq!(fake.cancels.load(Ordering::SeqCst), cancels_before);
        assert_eq!(
            controller.state().unwrap().last_full_refresh_at,
            full_refresh_at
        );
        assert!(!controller.refresh_dir.join("binary-resume.json").exists());
        assert_eq!(
            controller.state().unwrap().last_delta_fallback_class,
            Some(DeltaFallbackClass::DeltaTooLarge)
        );
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        authority.close().await;
    }

    // Generation maintenance and detached binary workers have independent
    // lifetimes. A cancellation counter is also not a worker-completion signal.
    // Wait for both leases before a test asks the next tick to exercise policy,
    // rather than the production busy/coalescing path. Never retry the tick.
    async fn refresh_workers_idle(controller: &StandbyRefreshController) {
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                controller.store.maintenance_idle().await;
                let locks = ["attempt.lock", "binary-work.lock"]
                    .map(|name| open_private_lock(&controller.refresh_dir.join(name)).unwrap());
                let acquired = locks
                    .each_ref()
                    .map(|lock| match lock.try_lock_exclusive() {
                        Ok(()) => true,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
                        Err(error) => panic!("refresh worker quiescence failed: {error}"),
                    });
                let idle = acquired.iter().all(|acquired| *acquired);
                for (lock, acquired) in locks.iter().zip(acquired) {
                    if acquired {
                        // Explicit unlock also releases an inherited open-file
                        // description if another test forks during this probe.
                        fs2::FileExt::unlock(lock).unwrap();
                    }
                }
                drop(locks);
                if idle {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("refresh maintenance and transfer workers must become idle");
    }

    #[tokio::test]
    async fn refresh_workers_idle_waits_for_attempt_and_transfer_leases() {
        let directory = tempfile::tempdir().unwrap();
        let controller = controller_for_origin(
            &directory,
            "ndb_0123456789abcdef0123456789abcdef".into(),
            Arc::new(AlwaysFailClient {
                class: RefreshFailureClass::Protocol,
                calls: AtomicUsize::new(0),
            }),
        );
        for name in ["attempt.lock", "binary-work.lock"] {
            let lease = open_private_lock(&controller.refresh_dir.join(name)).unwrap();
            lease.try_lock_exclusive().unwrap();
            // Maintenance is already idle: either independent lease must still
            // prevent the helper from completing. This uses no timing race.
            controller.store.maintenance_idle().await;
            let idle = refresh_workers_idle(&controller);
            tokio::pin!(idle);
            assert!(futures::poll!(idle.as_mut()).is_pending(), "{name}");
            drop(lease);
            idle.await;
        }
    }

    #[tokio::test]
    async fn resume_probe_refusal_obeys_terminal_custody_and_later_capture_budget() {
        let authority = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let ((bytes_a, manifest_a), (bytes_b, manifest_b)) = resume_snapshots(&authority).await;
        let (port, server, _) =
            chunked::serve_host(authority.clone(), chunked::HostRoute::CaptureTooLarge).await;
        for (class, terminal) in [
            (RefreshFailureClass::Protocol, true),
            (RefreshFailureClass::DownloadIntegrity, true),
            (RefreshFailureClass::Authentication, false),
            (RefreshFailureClass::Network, false),
            (RefreshFailureClass::Timeout, false),
        ] {
            for eligible_before_refusal in [false, true] {
                if !terminal && eligible_before_refusal {
                    continue;
                }
                let directory = tempfile::tempdir().unwrap();
                let fake = Arc::new(ScriptedBinaryClient::for_snapshot(
                    bytes_a.clone(),
                    manifest_a.clone(),
                ));
                let mut controller =
                    resume_test_controller(&directory, origin.clone(), fake.clone());
                controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
                controller.config.full_refresh_min_interval_seconds = Some(3600);
                controller.refresh_once(RefreshCause::Manual).await.unwrap();
                tokio::time::timeout(Duration::from_secs(2), async {
                    while fake.cancels.load(Ordering::SeqCst) < 1 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                refresh_workers_idle(&controller).await;
                enable_deltas(&mut controller);
                *fake.bytes.lock().unwrap() = bytes_b.clone();
                *fake.manifest.lock().unwrap() = manifest_b.clone();
                fake.succeed_reads
                    .store(fake.reads.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
                refresh_workers_idle(&controller).await;
                assert!(controller.refresh_once(RefreshCause::Manual).await.is_err());
                let ledger_path = controller.refresh_dir.join("binary-resume.json");
                let partial_path = controller.refresh_dir.join("binary-resume.partial.db");
                let saved = fs::read(&ledger_path).unwrap();
                if eligible_before_refusal {
                    let mut state = controller.state().unwrap();
                    state.last_full_refresh_at = Some("2020-01-01T00:00:00Z".into());
                    controller.write_state(&state).unwrap();
                }
                assert_eq!(
                    full_refresh_is_recent(
                        &controller.state().unwrap(),
                        false,
                        Duration::from_secs(3600)
                    ),
                    !eligible_before_refusal,
                    "the fixture must establish the intended capture eligibility",
                );
                let capture_at = controller.state().unwrap().last_full_refresh_at;
                let starts_before = fake.starts.load(Ordering::SeqCst);
                let cancels_before = fake.cancels.load(Ordering::SeqCst);
                let polls_before = fake.polls.load(Ordering::SeqCst);
                *fake.poll_mode.lock().unwrap() = ResumePollMode::Refused(class);
                // This is the real controller path: head, delta fallback,
                // retained-handle probe, then (only on success) the FULL gate.
                refresh_workers_idle(&controller).await;
                assert!(controller
                    .refresh_once(RefreshCause::Scheduled)
                    .await
                    .is_err());
                assert_eq!(controller.state().unwrap().last_failure_class, Some(class));
                assert_eq!(controller.state().unwrap().last_full_refresh_at, capture_at);
                assert_eq!(fake.polls.load(Ordering::SeqCst), polls_before + 1);
                assert_eq!(
                    fake.starts.load(Ordering::SeqCst),
                    starts_before,
                    "a probe refusal cannot silently capture even when eligible"
                );
                if !terminal {
                    tokio::task::yield_now().await;
                    assert_eq!(fs::read(&ledger_path).unwrap(), saved);
                    assert!(partial_path.exists());
                    assert_eq!(fake.cancels.load(Ordering::SeqCst), cancels_before);
                    continue;
                }
                assert!(!ledger_path.exists());
                assert!(!partial_path.exists());
                tokio::time::timeout(Duration::from_secs(2), async {
                    while fake.cancels.load(Ordering::SeqCst) <= cancels_before {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                assert_eq!(fake.cancels.load(Ordering::SeqCst), cancels_before + 1);
                *fake.poll_mode.lock().unwrap() = ResumePollMode::Ready;
                fake.succeed_reads.store(usize::MAX, Ordering::SeqCst);
                if !eligible_before_refusal {
                    // Wait for verification and transfer custody so this tick
                    // exercises the production FULL gate, not busy coalescing.
                    refresh_workers_idle(&controller).await;
                    let outcome = controller
                        .refresh_once(RefreshCause::Scheduled)
                        .await
                        .unwrap();
                    let StandbyRefreshOutcome::Deferred { reason, .. } = outcome else {
                        panic!(
                            "the next tick must respect the original capture cooldown: {outcome:?}"
                        );
                    };
                    assert_eq!(reason, DEFERRED_FULL_REFRESH_INTERVAL);
                    assert!(controller
                        .state()
                        .unwrap()
                        .next_full_refresh_eligible_at
                        .is_some());
                    assert_eq!(fake.starts.load(Ordering::SeqCst), starts_before);
                    assert_eq!(controller.state().unwrap().last_full_refresh_at, capture_at);
                    let mut state = controller.state().unwrap();
                    state.last_full_refresh_at = Some("2020-01-01T00:00:00Z".into());
                    controller.write_state(&state).unwrap();
                }
                refresh_workers_idle(&controller).await;
                let StandbyRefreshOutcome::Installed { generation, .. } = controller
                    .refresh_once(RefreshCause::Scheduled)
                    .await
                    .unwrap()
                else {
                    panic!("a later eligible tick must recover with one new capture");
                };
                assert_eq!(fs::read(&generation.snapshot_path).unwrap(), bytes_b);
                assert_eq!(fake.starts.load(Ordering::SeqCst), starts_before + 1);
                assert_ne!(
                    controller.state().unwrap().last_full_refresh_at.as_deref(),
                    Some("2020-01-01T00:00:00Z")
                );
                assert_eq!(
                    controller.state().unwrap().last_delta_fallback_class,
                    Some(DeltaFallbackClass::DeltaTooLarge)
                );
            }
        }
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        authority.close().await;
    }

    #[tokio::test]
    async fn aborted_download_never_cancels_its_retained_export() {
        let authority = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let ((_, _), (bytes_b, manifest_b)) = resume_snapshots(&authority).await;
        for replacement in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let fake = Arc::new(ScriptedBinaryClient::for_snapshot(
                bytes_b.clone(),
                manifest_b.clone(),
            ));
            let gate = Arc::new(tokio::sync::Notify::new());
            *fake.range_gate.lock().unwrap() = Some(gate);
            let controller = resume_test_controller(&directory, origin.clone(), fake.clone());
            if replacement {
                let pending = binary_resume::pending_capture(
                    &controller.resume_binding(),
                    ScriptedBinaryClient::handle_for(0),
                    now(),
                );
                binary_resume::save_pending_capture(&controller.refresh_dir, &pending).unwrap();
                fake.gone_on_poll.store(0, Ordering::SeqCst);
            }
            let target = directory.path().join("aborted.snapshot.db");
            let task = tokio::spawn(async move {
                controller
                    .download_binary_only(
                        "secret".into(),
                        &target,
                        binary::FreshCaptureBudget::Allowed,
                    )
                    .await
            });
            // Strand the transfer with its first range ledgered, then abort it
            // the way a timeout or shutdown would drop the future.
            tokio::time::timeout(Duration::from_secs(10), async {
                while fake.range_gate.lock().unwrap().is_some() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the gated range read must start");
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            tokio::time::sleep(Duration::from_millis(200)).await;
            // The retained export survives: no server DELETE fired.
            assert_eq!(fake.cancels.load(Ordering::SeqCst), 0);
            let refresh_dir = directory.path().join("replica/refresh");
            // Aborting the waiter does not stop its blocking worker, which keeps
            // `binary-work.lock` until it finishes. Wait (bounded) for that
            // worker to go quiet instead of racing it with a fixed delay.
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let lock = open_private_lock(&refresh_dir.join("binary-work.lock")).unwrap();
                    if lock.try_lock_exclusive().is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the aborted transfer worker must release its lock");
            assert!(refresh_dir.join("binary-resume.json").exists());
            assert!(refresh_dir.join("binary-resume.partial.db").exists());
            // A new controller resumes the same handle to a complete transfer.
            let controller = resume_test_controller(&directory, origin.clone(), fake.clone());
            let finished = directory.path().join("finished.snapshot.db");
            controller
                .download_binary_only(
                    "secret".into(),
                    &finished,
                    binary::FreshCaptureBudget::Allowed,
                )
                .await
                .unwrap();
            assert_eq!(fs::read(&finished).unwrap(), bytes_b);
            assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
        }
        authority.close().await;
    }

    #[tokio::test]
    async fn live_resume_loss_can_replace_when_capture_is_eligible() {
        let authority = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let ((bytes_a, manifest_a), (bytes_b, manifest_b)) = resume_snapshots(&authority).await;
        let (port, server, _) =
            chunked::serve_host(authority.clone(), chunked::HostRoute::CaptureTooLarge).await;
        for (first_install, cause) in [
            (false, RefreshCause::Scheduled),
            (false, RefreshCause::Manual),
            (true, RefreshCause::Scheduled),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let fake = Arc::new(ScriptedBinaryClient::for_snapshot(
                bytes_a.clone(),
                manifest_a.clone(),
            ));
            let mut controller = resume_test_controller(&directory, origin.clone(), fake.clone());
            controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
            if !first_install {
                controller.refresh_once(RefreshCause::Manual).await.unwrap();
            }
            enable_deltas(&mut controller);
            *fake.bytes.lock().unwrap() = bytes_b.clone();
            *fake.manifest.lock().unwrap() = manifest_b.clone();
            let pending = binary_resume::pending_capture(
                &controller.resume_binding(),
                ScriptedBinaryClient::handle_for(0),
                now(),
            );
            binary_resume::save_pending_capture(&controller.refresh_dir, &pending).unwrap();
            let mut state = controller.state().unwrap();
            let previous = if cause == RefreshCause::Scheduled && !first_install {
                "2020-01-01T00:00:00Z".to_string()
            } else {
                "2099-01-01T00:00:00Z".to_string()
            };
            state.last_full_refresh_at = Some(previous.clone());
            controller.write_state(&state).unwrap();
            *fake.poll_selection_once.lock().unwrap() = Some(
                super::super::shapes::v1(95, super::super::shapes::V1_95)
                    .unwrap()
                    .shape(),
            );
            // The liveness probe succeeds; the immediately following poll loses
            // the retained handle. Only the replacement's polls are live again.
            fake.gone_on_poll
                .store(fake.polls.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
            let starts_before = fake.starts.load(Ordering::SeqCst);
            let StandbyRefreshOutcome::Installed { generation, .. } =
                controller.refresh_once(cause).await.unwrap()
            else {
                panic!("eligible replacement must install")
            };
            assert_eq!(fs::read(generation.snapshot_path).unwrap(), bytes_b);
            assert_eq!(fake.starts.load(Ordering::SeqCst), starts_before + 1);
            let state = controller.state().unwrap();
            assert!(state.last_full_refresh_at.is_some());
            assert_ne!(state.last_full_refresh_at, Some(previous));
        }
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        authority.close().await;
    }

    #[tokio::test]
    async fn pending_save_failure_cancels_initial_and_replacement_exports() {
        let authority = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        for replacement in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let fake = Arc::new(ScriptedBinaryClient::for_snapshot(
                bytes.clone(),
                manifest.clone(),
            ));
            let controller = resume_test_controller(&directory, origin.clone(), fake.clone());
            if replacement {
                let pending = binary_resume::pending_capture(
                    &controller.resume_binding(),
                    ScriptedBinaryClient::handle_for(0),
                    now(),
                );
                binary_resume::save_pending_capture(&controller.refresh_dir, &pending).unwrap();
                fake.gone_on_poll.store(0, Ordering::SeqCst);
            }
            *fake.fail_pending_save.lock().unwrap() = Some(controller.refresh_dir.clone());
            fs::write(&controller.config.credential_file, b"rotated\n").unwrap();
            let target = directory.path().join("failed.db");
            let error = controller
                .download_binary_only(
                    "obsolete".into(),
                    &target,
                    binary::FreshCaptureBudget::Allowed,
                )
                .await
                .unwrap_err();
            assert_eq!(error.class, RefreshFailureClass::LocalIo);
            tokio::time::timeout(Duration::from_secs(2), async {
                while fake.cancels.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
            assert_eq!(fake.cancels.load(Ordering::SeqCst), 1);
            assert_eq!(*fake.start_bearers.lock().unwrap(), vec!["rotated"]);
            assert!(!target.exists());
        }
        authority.close().await;
    }

    #[tokio::test]
    async fn orphan_resume_files_are_reconciled_before_capture_and_cleanup_errors_refuse() {
        let authority = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let fake = Arc::new(ScriptedBinaryClient::for_snapshot(bytes.clone(), manifest));
        let controller = resume_test_controller(&directory, origin, fake.clone());
        for name in [
            "binary-resume.partial.db",
            "binary-resume.json.tmp",
            "binary-pending.json.tmp",
        ] {
            fs::write(controller.refresh_dir.join(name), b"orphan").unwrap();
        }
        let target = directory.path().join("recovered.db");
        controller
            .download_binary_only(
                "secret".into(),
                &target,
                binary::FreshCaptureBudget::Allowed,
            )
            .await
            .unwrap();
        assert_eq!(fs::read(target).unwrap(), bytes);
        assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
        // An un-unlinkable fixed pathname must refuse before a fresh capture.
        fs::create_dir(controller.refresh_dir.join("binary-resume.partial.db")).unwrap();
        let target = directory.path().join("refused.db");
        let error = controller
            .download_binary_only(
                "secret".into(),
                &target,
                binary::FreshCaptureBudget::Allowed,
            )
            .await
            .unwrap_err();
        assert_eq!(error.class, RefreshFailureClass::LocalIo);
        assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
        assert!(!target.exists());
        authority.close().await;
    }

    #[tokio::test]
    async fn resume_cleanup_failure_refuses_gone_probe_and_completed_transfer() {
        let authority = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let fake = Arc::new(ScriptedBinaryClient::for_snapshot(bytes, manifest));
        let controller = resume_test_controller(&directory, origin, fake.clone());
        for mode in [
            ResumePollMode::Gone,
            ResumePollMode::Refused(RefreshFailureClass::Protocol),
            ResumePollMode::Refused(RefreshFailureClass::DownloadIntegrity),
        ] {
            let pending = binary_resume::pending_capture(
                &controller.resume_binding(),
                ScriptedBinaryClient::handle_for(0),
                now(),
            );
            binary_resume::save_pending_capture(&controller.refresh_dir, &pending).unwrap();
            let obstruction = controller.refresh_dir.join("binary-resume.partial.db");
            fs::create_dir(&obstruction).unwrap();
            *fake.poll_mode.lock().unwrap() = mode;
            let cancels_before = fake.cancels.load(Ordering::SeqCst);
            let error = match controller.probe_binary_resume().await {
                Err(error) => error,
                Ok(_) => panic!("failed probe cleanup must refuse"),
            };
            assert_eq!(error.class, RefreshFailureClass::LocalIo);
            assert_eq!(fake.starts.load(Ordering::SeqCst), 0);
            if mode != ResumePollMode::Gone {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while fake.cancels.load(Ordering::SeqCst) <= cancels_before {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
            }
            fs::remove_dir(obstruction).unwrap();
        }
        *fake.poll_mode.lock().unwrap() = ResumePollMode::Ready;
        *fake.obstruct_cleanup_on_read.lock().unwrap() = Some(controller.refresh_dir.clone());
        let target = directory.path().join("not-admitted.db");
        let error = controller
            .download_binary_only(
                "secret".into(),
                &target,
                binary::FreshCaptureBudget::Allowed,
            )
            .await
            .unwrap_err();
        assert_eq!(error.class, RefreshFailureClass::LocalIo);
        assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
        // A complete file reaching attempt staging is still not success or
        // admission while durable custody cleanup remains uncertain.
        assert!(controller.store.accepted_identity_hint().unwrap().is_none());
        authority.close().await;
    }

    fn acquisition_fixture(bytes: Vec<u8>, manifest: StandbySnapshotManifest) -> BinaryHttpFixture {
        BinaryHttpFixture {
            bytes: Arc::new(bytes),
            manifest,
            authority: None,
            transfer: transfer_repr::SnapshotTransfer::IdentityV1,
            legacy_starts: Arc::default(),
            fault: BinaryWireFault::None,
            starts: Arc::default(),
            ranges: Arc::default(),
            polls: Arc::default(),
            mcp_calls: Arc::default(),
            cancels: Arc::default(),
        }
    }

    #[tokio::test]
    async fn acquisition_only_ignores_head_probe_errors_for_v1() {
        let directory = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&db).await;
        let mut fixture = acquisition_fixture(bytes, manifest);
        fixture.fault = BinaryWireFault::HeadProbeUnavailable;
        let (port, server) = serve_binary_fixture(fixture.clone()).await;
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(AlwaysFailClient {
                class: RefreshFailureClass::Protocol,
                calls: AtomicUsize::new(0),
            }),
        );
        controller.delta_enabled = true;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        // No head authority: the endpoint refuses the preliminary probe, but
        // standalone snapshot acquisition retains its independent v1 transport.
        let download = controller.acquire_snapshot_only().await.unwrap();
        assert!(download.snapshot_path().is_file());
        assert_eq!(fixture.mcp_calls.load(Ordering::SeqCst), 1);
        server.abort();
        db.close().await;
    }

    #[tokio::test]
    async fn v1_delta_only_lock_contention_remains_an_error() {
        let client = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Network,
            calls: AtomicUsize::new(0),
        });
        let directory = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let mut controller = controller_for_origin(&directory, origin, client.clone());
        controller.observed = super::super::generation_store::tests::observed();
        let (snapshot, manifest) =
            super::super::generation_store::tests::stage(&controller.store, &db, "v1-lock").await;
        let installed = controller
            .store
            .install_staged(&snapshot, &manifest, &controller.observed)
            .await
            .unwrap();
        assert!(installed.manifest.kernel_v2.is_none());
        for name in ["controller.lock", "attempt.lock"] {
            let lock = open_private_lock(&controller.refresh_dir.join(name)).unwrap();
            lock.try_lock_exclusive().unwrap();
            assert!(controller.refresh_delta_only().await.is_err(), "{name}");
        }
        assert_eq!(client.calls.load(Ordering::SeqCst), 0);
        db.close().await;
    }

    #[tokio::test]
    async fn acquisition_only_preserves_producer_binding_without_admitting_or_publishing() {
        let directory = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let (_, mut manifest) = snapshot_fixture(&db).await;
        // Authenticated, digest-correct bytes still require the separate kernel
        // admission. Deliberately invalid SQLite proves that this is acquisition only.
        let bytes = b"not an admitted SQLite database".to_vec();
        manifest.snapshot.size_bytes = bytes.len() as u64;
        manifest.snapshot.sha256 = hex::encode(Sha256::digest(&bytes));
        let fixture = acquisition_fixture(bytes.clone(), manifest.clone());
        let (port, server) = serve_binary_fixture(fixture.clone()).await;
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(AlwaysFailClient {
                class: RefreshFailureClass::Protocol,
                calls: AtomicUsize::new(0),
            }),
        );
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        let first = controller.acquire_snapshot_only().await.unwrap();
        let snapshot = first.snapshot_path().to_owned();
        let metadata = first.manifest_path().to_owned();
        assert_eq!(fs::read(&snapshot).unwrap(), bytes);
        assert_eq!(
            fs::read(&metadata).unwrap(),
            manifest.canonical_json().unwrap()
        );
        assert!(!controller
            .runtime
            .replica_root
            .join("accepted/current.json")
            .exists());
        assert!(!controller.refresh_dir.join("state.json").exists());
        assert_eq!(fixture.mcp_calls.load(Ordering::SeqCst), 0);
        drop(first);
        assert!(!snapshot.exists());
        assert!(!metadata.exists());
        let (snapshot, metadata) = controller.acquire_snapshot_only().await.unwrap().preserve();
        assert_eq!(fs::read(&snapshot).unwrap(), bytes);
        assert_eq!(
            fs::read(&metadata).unwrap(),
            manifest.canonical_json().unwrap()
        );
        assert!(!controller
            .runtime
            .replica_root
            .join("accepted/current.json")
            .exists());
        server.abort();
    }

    #[tokio::test]
    async fn acquisition_only_refuses_bad_binding_and_digest_without_leaving_staging() {
        for fault in ["digest", "consumer", "origin"] {
            let directory = tempfile::tempdir().unwrap();
            let db = crate::create_database(":memory:").await.unwrap();
            let origin = crate::identity::database_id(&db).await.unwrap();
            let (mut bytes, mut manifest) = snapshot_fixture(&db).await;
            match fault {
                "consumer" => manifest.consumer.artifact_sha256 = "f".repeat(64),
                "origin" => manifest.origin_database_id = format!("ndb_{}", "f".repeat(32)),
                _ => bytes[0] ^= 1,
            }
            let fixture = acquisition_fixture(bytes, manifest);
            let (port, server) = serve_binary_fixture(fixture.clone()).await;
            let mut controller = controller_for_origin(
                &directory,
                origin,
                Arc::new(AlwaysFailClient {
                    class: RefreshFailureClass::Protocol,
                    calls: AtomicUsize::new(0),
                }),
            );
            controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
            assert!(controller.acquire_snapshot_only().await.is_err());
            if fault != "digest" {
                assert!(
                    fixture.ranges.lock().unwrap().is_empty(),
                    "identity refusal must precede download"
                );
            }
            assert_eq!(
                fs::read_dir(controller.store.staging_dir())
                    .unwrap()
                    .count(),
                0
            );
            assert!(!controller
                .runtime
                .replica_root
                .join("accepted/current.json")
                .exists());
            server.abort();
        }
    }

    #[tokio::test]
    async fn acquisition_only_refuses_refresh_locks_before_starting_capture() {
        let directory = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&db).await;
        let fixture = acquisition_fixture(bytes, manifest);
        let (port, server) = serve_binary_fixture(fixture.clone()).await;
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(AlwaysFailClient {
                class: RefreshFailureClass::Protocol,
                calls: AtomicUsize::new(0),
            }),
        );
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        for name in ["controller.lock", "attempt.lock"] {
            let lock = open_private_lock(&controller.refresh_dir.join(name)).unwrap();
            lock.try_lock_exclusive().unwrap();
            assert!(controller.acquire_snapshot_only().await.is_err());
            assert_eq!(fixture.starts.load(Ordering::SeqCst), 0);
            assert_eq!(
                fs::read_dir(controller.store.staging_dir())
                    .unwrap()
                    .count(),
                0
            );
        }
        server.abort();
    }

    #[tokio::test]
    async fn binary_first_install_uses_raw_ranges_and_verified_generation_store() {
        let directory = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO blobs (id, bytes, size_bytes, storage_tier, created_at)
             VALUES ('binary-padding', zeroblob(1200000), 1200000, 'inline', '2026-07-31T00:00:00Z')",
        )
        .execute(db.write_pool())
        .await
        .unwrap();
        let (bytes, manifest) = snapshot_fixture(&db).await;
        assert!(bytes.len() > 1024 * 1024);
        let fixture = BinaryHttpFixture {
            bytes: Arc::new(bytes.clone()),
            manifest: manifest.clone(),
            authority: None,
            transfer: transfer_repr::SnapshotTransfer::IdentityV1,
            legacy_starts: Arc::default(),
            fault: BinaryWireFault::None,
            starts: Arc::default(),
            ranges: Arc::default(),
            polls: Arc::default(),
            mcp_calls: Arc::default(),
            cancels: Arc::default(),
        };
        let (port, server) = serve_binary_fixture(fixture.clone()).await;
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(AlwaysFailClient {
                class: RefreshFailureClass::Protocol,
                calls: AtomicUsize::new(0),
            }),
        );
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        controller.binary_snapshot_enabled = true;
        let outcome = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap();
        let StandbyRefreshOutcome::Installed { generation, .. } = outcome else {
            panic!("first install must promote the binary snapshot")
        };
        assert_eq!(fs::read(&generation.snapshot_path).unwrap(), bytes);
        assert_eq!(generation.manifest, manifest);
        assert!(directory
            .path()
            .join("replica/accepted/current.json")
            .exists());
        let ranges = fixture.ranges.lock().unwrap().clone();
        assert!(ranges.iter().any(|range| range == "bytes=0-1048575"));
        assert!(ranges.len() >= 2, "snapshot must use more than one range");
        assert!(fixture.polls.load(Ordering::SeqCst) >= 2);
        tokio::time::timeout(Duration::from_secs(2), async {
            while fixture.cancels.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn binary_interrupted_range_retries_same_handle_and_offset_boundedly() {
        let authority = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        sqlx::query(
            "INSERT INTO blobs (id, bytes, size_bytes, storage_tier, created_at)
             VALUES ('retry-padding', zeroblob(1200000), 1200000, 'inline', '2026-07-31T00:00:00Z')",
        )
        .execute(authority.write_pool())
        .await
        .unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        assert!(bytes.len() > 1024 * 1024);
        for (fault, succeeds) in [
            (BinaryWireFault::InterruptedOnce, true),
            (BinaryWireFault::InterruptedAlways, false),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let fixture = BinaryHttpFixture {
                bytes: Arc::new(bytes.clone()),
                manifest: manifest.clone(),
                authority: None,
                transfer: transfer_repr::SnapshotTransfer::IdentityV1,
                legacy_starts: Arc::default(),
                fault,
                starts: Arc::default(),
                ranges: Arc::default(),
                polls: Arc::default(),
                mcp_calls: Arc::default(),
                cancels: Arc::default(),
            };
            let (port, server) = serve_binary_fixture(fixture.clone()).await;
            let mcp_pages = Arc::new(AlwaysFailClient {
                class: RefreshFailureClass::Protocol,
                calls: AtomicUsize::new(0),
            });
            let mut controller =
                controller_for_origin(&directory, origin.clone(), mcp_pages.clone());
            controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
            controller.binary_snapshot_enabled = true;
            let outcome = controller.refresh_once(RefreshCause::Startup).await;
            if succeeds {
                let StandbyRefreshOutcome::Installed { generation, .. } = outcome.unwrap() else {
                    panic!("same-handle retry must install")
                };
                assert_eq!(fs::read(&generation.snapshot_path).unwrap(), bytes);
            } else {
                assert!(outcome.is_err());
                assert_eq!(
                    controller.state().unwrap().last_failure_class,
                    Some(RefreshFailureClass::Network)
                );
                assert!(!directory
                    .path()
                    .join("replica/accepted/current.json")
                    .exists());
                assert_eq!(
                    fs::read_dir(controller.store.staging_dir())
                        .unwrap()
                        .count(),
                    0
                );
            }
            assert_eq!(fixture.starts.load(Ordering::SeqCst), 1);
            assert_eq!(mcp_pages.calls.load(Ordering::SeqCst), 0);
            let ranges = fixture.ranges.lock().unwrap().clone();
            assert!(ranges.iter().any(|range| range == "bytes=0-1048575"));
            let chunks = bytes.len().div_ceil(1024 * 1024);
            let first = "bytes=0-1048575";
            assert_eq!(
                ranges
                    .iter()
                    .filter(|range| range.as_str() == first)
                    .count(),
                1
            );
            for chunk in 1..chunks {
                let offset = chunk * 1024 * 1024;
                let end = (offset + 1024 * 1024).min(bytes.len()) - 1;
                let expected = format!("bytes={offset}-{end}");
                let attempts = ranges.iter().filter(|range| **range == expected).count();
                if succeeds {
                    assert_eq!(
                        attempts, 2,
                        "each interrupted range retries once on the same handle"
                    );
                } else {
                    assert!(
                        attempts <= 3,
                        "in-flight ranges are dropped on the first exhausted failure"
                    );
                }
            }
            if !succeeds {
                assert!(ranges.iter().any(|range| ranges
                    .iter()
                    .filter(|other| *other == range)
                    .count()
                    == 3));
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                while fixture.cancels.load(Ordering::SeqCst) == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap_or_else(|_| {
                assert!(
                    !succeeds,
                    "a completed transfer must cancel its consumed export"
                );
            });
            if !succeeds {
                // The exhausted export is retained for resume, never
                // cancelled: the next attempt must reuse its handle.
                assert_eq!(fixture.cancels.load(Ordering::SeqCst), 0);
                assert!(directory
                    .path()
                    .join("replica/refresh/binary-resume.json")
                    .exists());
                assert!(directory
                    .path()
                    .join("replica/refresh/binary-resume.partial.db")
                    .exists());
            }
            server.abort();
        }
        authority.close().await;
    }

    /// The off-path audit runs the full verifier. When it fails, the copy keeps
    /// serving but the next refresh skips deltas and takes the whole-snapshot
    /// path, which may replace the copy the audit found bad.
    #[tokio::test]
    async fn failed_audit_forces_a_whole_snapshot_that_replaces_the_copy() {
        let directory = tempfile::tempdir().unwrap();
        let authority = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (base_bytes, base_manifest) = snapshot_fixture(&authority).await;
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "audit-base",
                &base_bytes,
                &base_manifest,
            ))),
        );
        let StandbyRefreshOutcome::Installed {
            generation: first, ..
        } = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap()
        else {
            panic!("fixture base must install")
        };
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
        assert!(
            controller
                .store
                .audit_current(&controller.observed)
                .await
                .unwrap()
                .passed
        );
        set_mode(&first.snapshot_path, 0o600).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&first.snapshot_path)
            .unwrap()
            .write_all(b"the audit must reject this copy")
            .unwrap();
        set_mode(&first.snapshot_path, 0o400).unwrap();
        let audit = controller
            .store
            .audit_current(&controller.observed)
            .await
            .unwrap();
        assert_eq!(audit.generation_id, first.id);
        assert!(!audit.passed);

        crate::store::append(
            &authority,
            crate::store::AppendSpec {
                record_id: "1a7e4000-0000-4000-8000-00000000d203".into(),
                event_type: "record.created".into(),
                payload: json!({"type":"Document","kind":"note","name":"after the audit"}),
                actor: None,
            },
        )
        .await
        .unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let fixture = BinaryHttpFixture {
            bytes: Arc::new(bytes),
            manifest,
            authority: Some(authority.clone()),
            transfer: transfer_repr::SnapshotTransfer::IdentityV1,
            legacy_starts: Arc::default(),
            fault: BinaryWireFault::None,
            starts: Arc::default(),
            ranges: Arc::default(),
            polls: Arc::default(),
            mcp_calls: Arc::default(),
            cancels: Arc::default(),
        };
        let (port, server) = serve_binary_fixture(fixture.clone()).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        enable_deltas(&mut controller);
        controller.binary_snapshot_enabled = true;
        let StandbyRefreshOutcome::Installed { generation, .. } = controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap()
        else {
            panic!("a failed audit must take the whole-snapshot path")
        };
        assert_ne!(generation.id, first.id);
        assert_eq!(
            fixture.mcp_calls.load(Ordering::SeqCst),
            1,
            "compatible head before FULL"
        );
        assert!(!fixture.ranges.lock().unwrap().is_empty());
        assert_eq!(
            controller.state().unwrap().last_delta_fallback_class,
            Some(DeltaFallbackClass::AuditFailed)
        );
        assert_eq!(
            controller
                .store
                .current_for_head_probe()
                .unwrap()
                .unwrap()
                .id,
            generation.id
        );
        server.abort();
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    #[tokio::test]
    async fn receiver_fresh_poll_selections_bind_to_ready_manifest_before_transfer() {
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&db).await;
        for retained in [false, true] {
            for fault in [
                BinaryWireFault::None,
                BinaryWireFault::MatchingPollSelection,
                BinaryWireFault::WrongPollSelection,
                BinaryWireFault::WrongReadySelection,
            ] {
                let directory = tempfile::tempdir().unwrap();
                let fixture = BinaryHttpFixture {
                    bytes: Arc::new(bytes.clone()),
                    manifest: manifest.clone(),
                    authority: None,
                    transfer: transfer_repr::SnapshotTransfer::IdentityV1,
                    legacy_starts: Arc::default(),
                    fault,
                    starts: Arc::default(),
                    ranges: Arc::default(),
                    polls: Arc::default(),
                    mcp_calls: Arc::default(),
                    cancels: Arc::default(),
                };
                let (port, server) = serve_binary_fixture(fixture.clone()).await;
                let mut controller = controller_for_origin(
                    &directory,
                    origin.clone(),
                    Arc::new(AlwaysFailClient {
                        class: RefreshFailureClass::Protocol,
                        calls: AtomicUsize::new(0),
                    }),
                );
                controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
                controller.binary_snapshot_enabled = true;
                let mut previous_full = None;
                if retained {
                    let pending = binary_resume::pending_capture(
                        &controller.resume_binding(),
                        BINARY_TEST_HANDLE.into(),
                        now(),
                    );
                    binary_resume::save_pending_capture(&controller.refresh_dir, &pending).unwrap();
                    previous_full = Some(now());
                    let mut state = controller.state().unwrap();
                    state.last_full_refresh_at = previous_full.clone();
                    controller.write_state(&state).unwrap();
                }
                let result = controller.refresh_once(RefreshCause::Startup).await;
                assert_eq!(
                    fixture.starts.load(Ordering::SeqCst),
                    if retained { 0 } else { 1 }
                );
                if retained {
                    assert_eq!(
                        controller.state().unwrap().last_full_refresh_at,
                        previous_full,
                        "resuming must not spend another capture or cooldown start"
                    );
                }
                if matches!(
                    fault,
                    BinaryWireFault::None | BinaryWireFault::MatchingPollSelection
                ) {
                    assert!(matches!(
                        result.unwrap(),
                        StandbyRefreshOutcome::Installed { .. }
                    ));
                    assert!(!fixture.ranges.lock().unwrap().is_empty());
                } else {
                    assert!(
                        result.is_err(),
                        "a contradictory poll selection must refuse"
                    );
                    assert_eq!(
                        controller.state().unwrap().last_failure_class,
                        Some(RefreshFailureClass::Protocol)
                    );
                    assert!(
                        fixture.ranges.lock().unwrap().is_empty(),
                        "refuse before GET"
                    );
                    assert!(controller.store.current_for_head_probe().unwrap().is_none());
                    assert_eq!(
                        fs::read_dir(controller.store.staging_dir())
                            .unwrap()
                            .count(),
                        0
                    );
                }
                controller.store.maintenance_idle().await;
                server.abort();
            }
        }
        db.close().await;
    }

    #[tokio::test]
    async fn binary_first_install_rejects_invalid_wire_without_promotion() {
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&db).await;
        for fault in [
            BinaryWireFault::ContentRange,
            BinaryWireFault::Etag,
            BinaryWireFault::Length,
            BinaryWireFault::Unsatisfiable,
            BinaryWireFault::FailedPoll,
            BinaryWireFault::InvalidPollJson,
            BinaryWireFault::InvalidPollFields,
            BinaryWireFault::Redirect,
            BinaryWireFault::Unauthorized,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let fixture = BinaryHttpFixture {
                bytes: Arc::new(bytes.clone()),
                manifest: manifest.clone(),
                authority: None,
                transfer: transfer_repr::SnapshotTransfer::IdentityV1,
                legacy_starts: Arc::default(),
                fault,
                starts: Arc::default(),
                ranges: Arc::default(),
                polls: Arc::default(),
                mcp_calls: Arc::default(),
                cancels: Arc::default(),
            };
            let (port, server) = serve_binary_fixture(fixture.clone()).await;
            let mut controller = controller_for_origin(
                &directory,
                origin.clone(),
                Arc::new(AlwaysFailClient {
                    class: RefreshFailureClass::Protocol,
                    calls: AtomicUsize::new(0),
                }),
            );
            controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
            controller.binary_snapshot_enabled = true;
            let failure = controller
                .refresh_once_with_receipt(RefreshCause::Startup)
                .await
                .unwrap_err();
            if matches!(
                fault,
                BinaryWireFault::InvalidPollJson | BinaryWireFault::InvalidPollFields
            ) {
                assert_eq!(failure.receipt.detail, "invalid_response");
            }
            let expected_class = match fault {
                BinaryWireFault::FailedPoll
                | BinaryWireFault::Redirect
                | BinaryWireFault::InvalidPollJson
                | BinaryWireFault::InvalidPollFields => RefreshFailureClass::Protocol,
                BinaryWireFault::Unauthorized => RefreshFailureClass::Authentication,
                _ => RefreshFailureClass::DownloadIntegrity,
            };
            assert_eq!(
                controller.state().unwrap().last_failure_class,
                Some(expected_class)
            );
            assert!(!controller
                .state()
                .unwrap()
                .last_failure
                .as_deref()
                .unwrap()
                .contains("secret"));
            assert!(!directory
                .path()
                .join("replica/accepted/current.json")
                .exists());
            assert_eq!(
                fs::read_dir(controller.store.staging_dir())
                    .unwrap()
                    .count(),
                0
            );
            tokio::time::timeout(Duration::from_secs(2), async {
                while fixture.cancels.load(Ordering::SeqCst) == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap_or_else(|_| {
                assert!(
                    matches!(fault, BinaryWireFault::Unauthorized),
                    "terminal wire faults must cancel their export"
                );
            });
            if matches!(fault, BinaryWireFault::Unauthorized) {
                // Authentication preserves the adopted ready ledger for a
                // later attempt with renewed credentials instead of
                // cancelling it.
                assert_eq!(fixture.cancels.load(Ordering::SeqCst), 0);
                assert!(directory
                    .path()
                    .join("replica/refresh/binary-resume.json")
                    .exists());
            }
            server.abort();
        }
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

    /// An older host has no chunked delta route: answer its start with the bare
    /// 404 such a host gives, so the client takes the MCP tool. Not counted as a
    /// served call.
    async fn refuse_chunked_route(stream: &mut TcpStream, headers: &str) -> bool {
        if !headers.starts_with("POST /v1/databases/") {
            return false;
        }
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        true
    }

    async fn serve_authority_act_calls(
        db: crate::Db,
        expected_calls: usize,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        serve_authority_act_calls_with(db, expected_calls, AuthorityFault::None).await
    }

    /// How a fixture authority misbehaves on its delta response.
    #[derive(Clone, Copy)]
    // The version-2 variants are used by the in-place tests (v2-kernel-probe).
    #[cfg_attr(not(feature = "v2-kernel-probe"), allow(dead_code))]
    enum AuthorityFault {
        None,
        /// Cut from one act after the requested lower bound: a gap.
        Gap,
        /// A correctly re-signed delta whose carried storage-policy pin no
        /// longer matches the local copy, so only the apply step refuses it.
        PolicyDrift,
        /// A hosted whose deployment flag for version-2 deltas is on: the head
        /// advertises it and a request carrying `kernel_delta_version: 2` is cut
        /// at version 2.
        AdvertiseV2,
        /// A mixed fleet: the head advertises version 2, but the replica that
        /// answers the delta request cannot read the field and refuses it.
        MixedFleet,
        /// A hosted that advertises wire version 3 (the set digest alone) and
        /// cuts at whatever version the request names.
        AdvertiseV3,
        /// The head advertises versions 2 and 3, but the replica that answers
        /// cannot read version 3 (it knows only 1 and 2) and refuses that
        /// request; version 2 is served.
        RefuseV3,
    }

    fn drift_delta_policy(mut structured: Value) -> Value {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(structured["data_base64"].as_str().unwrap())
            .unwrap();
        let mut inner: Value = serde_json::from_slice(&bytes).unwrap();
        inner["authority_head"]["storage_portability_policy"] = json!({
            "policy_revision": 1,
            "source_profile_id": "kite-local",
            "source_profile_revision": 1,
            "source_mode": "embedded",
        });
        let mut payload = inner.clone();
        payload.as_object_mut().unwrap().remove("content_sha256");
        inner["content_sha256"] = Value::String(hex::encode(Sha256::digest(
            serde_jcs::to_vec(&payload).unwrap(),
        )));
        let bytes = serde_jcs::to_vec(&inner).unwrap();
        structured["content_sha256"] = inner["content_sha256"].clone();
        structured["outer_sha256"] = Value::String(hex::encode(Sha256::digest(&bytes)));
        structured["data_base64"] =
            Value::String(base64::engine::general_purpose::STANDARD.encode(&bytes));
        structured
    }

    async fn serve_authority_act_calls_with(
        db: crate::Db,
        expected_calls: usize,
        fault: AuthorityFault,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut served = 0;
            while served < expected_calls {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (headers, body) = read_http_request(&mut stream).await;
                if refuse_chunked_route(&mut stream, &headers).await {
                    continue;
                }
                served += 1;
                assert!(headers
                    .to_ascii_lowercase()
                    .contains("authorization: bearer secret"));
                let operation = body["params"]["arguments"]["operation"].as_str().unwrap();
                let result = match operation {
                    super::super::delta_transport::AUTHORITY_ACT_HEAD_OPERATION => {
                        super::super::delta_transport::observe_authority_act_head_advertising(
                            &db,
                            "route-1",
                            matches!(
                                fault,
                                AuthorityFault::AdvertiseV2
                                    | AuthorityFault::MixedFleet
                                    | AuthorityFault::AdvertiseV3
                                    | AuthorityFault::RefuseV3
                            ),
                        )
                        .await
                        .map(|value| serde_json::to_value(value).unwrap())
                        .map(|mut value| {
                            // Hosted advertises [1, 2] at most; a version-3 host
                            // is scripted by adding 3 to the advertised list.
                            if matches!(
                                fault,
                                AuthorityFault::AdvertiseV3 | AuthorityFault::RefuseV3
                            ) {
                                value["kernel_delta_versions"] = json!([1, 2, 3]);
                            }
                            value
                        })
                    }
                    super::super::delta_transport::AUTHORITY_ACT_DELTA_OPERATION => {
                        let from = body["params"]["arguments"]["arguments"]["from_exclusive_act"]
                            .as_i64()
                            .unwrap();
                        let from = match fault {
                            AuthorityFault::Gap => from + 1,
                            _ => from,
                        };
                        let inventory: Option<Vec<String>> = serde_json::from_value(
                            body["params"]["arguments"]["arguments"]["blob_inventory"].clone(),
                        )
                        .unwrap();
                        let refused = (matches!(fault, AuthorityFault::MixedFleet)
                            && body["params"]["arguments"]["arguments"]["kernel_delta_version"]
                                .is_number())
                            || (matches!(fault, AuthorityFault::RefuseV3)
                                && body["params"]["arguments"]["arguments"]
                                    ["kernel_delta_version"]
                                    == 3);
                        if refused {
                            let envelope = json!({
                                "jsonrpc": "2.0",
                                "id": 1,
                                "error": {"code": -32602, "message": "unknown field kernel_delta_version"}
                            });
                            write_json_response(&mut stream, "200 OK", &envelope).await;
                            continue;
                        }
                        let version = if matches!(
                            fault,
                            AuthorityFault::AdvertiseV2
                                | AuthorityFault::AdvertiseV3
                                | AuthorityFault::RefuseV3
                        ) {
                            body["params"]["arguments"]["arguments"]["kernel_delta_version"]
                                .as_u64()
                                .unwrap_or(1) as u32
                        } else {
                            1
                        };
                        super::super::delta_transport::observe_authority_act_delta_versioned(
                            &db,
                            "route-1",
                            from,
                            inventory.as_deref(),
                            version,
                        )
                        .await
                        .map(|value| serde_json::to_value(value).unwrap())
                        .map(|value| match fault {
                            AuthorityFault::PolicyDrift => drift_delta_policy(value),
                            _ => value,
                        })
                    }
                    other => panic!("unexpected authority operation {other}"),
                };
                let envelope = match result {
                    Ok(structured) => json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "content": [],
                            "structuredContent": structured,
                            "isError": false,
                            "resultType": "complete",
                            "_meta": {}
                        }
                    }),
                    Err(error) => json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {"code": -32000, "message": error.to_string()}
                    }),
                };
                write_json_response(&mut stream, "200 OK", &envelope).await;
            }
        });
        (port, task)
    }

    async fn serve_one_head_refusal(
        status: &'static str,
        envelope: Value,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (_, body) = read_http_request(&mut stream).await;
            assert_eq!(
                body["params"]["arguments"]["operation"],
                super::super::delta_transport::AUTHORITY_ACT_HEAD_OPERATION
            );
            write_json_response(&mut stream, status, &envelope).await;
        });
        (port, task)
    }

    /// Serve `connections` authority-head answers shaped exactly like the
    /// real probe but authoring an unreadable interchange revision.
    async fn serve_bumped_head(
        db: crate::Db,
        connections: usize,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            for _ in 0..connections {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (_, body) = read_http_request(&mut stream).await;
                assert_eq!(
                    body["params"]["arguments"]["operation"],
                    super::super::delta_transport::AUTHORITY_ACT_HEAD_OPERATION
                );
                let mut structured = serde_json::to_value(
                    super::super::delta_transport::observe_authority_act_head(&db, "route-1")
                        .await
                        .unwrap(),
                )
                .unwrap();
                structured["head"]["native_interchange_revision"] =
                    serde_json::json!(crate::standby::REQUIRED_NATIVE_INTERCHANGE_REVISION + 1);
                write_json_response(
                    &mut stream,
                    "200 OK",
                    &json!({
                        "jsonrpc": "2.0", "id": 1,
                        "result": {"content": [], "structuredContent": structured,
                                   "isError": false, "resultType": "complete", "_meta": {}}
                    }),
                )
                .await;
            }
        });
        (port, task)
    }

    async fn serve_valid_head_then_invalid_delta(
        db: crate::Db,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut index = 0;
            while index < 2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (headers, body) = read_http_request(&mut stream).await;
                if refuse_chunked_route(&mut stream, &headers).await {
                    continue;
                }
                index += 1;
                let index = index - 1;
                let operation = body["params"]["arguments"]["operation"].as_str().unwrap();
                let structured = if index == 0 {
                    assert_eq!(
                        operation,
                        super::super::delta_transport::AUTHORITY_ACT_HEAD_OPERATION
                    );
                    serde_json::to_value(
                        super::super::delta_transport::observe_authority_act_head(&db, "route-1")
                            .await
                            .unwrap(),
                    )
                    .unwrap()
                } else {
                    assert_eq!(
                        operation,
                        super::super::delta_transport::AUTHORITY_ACT_DELTA_OPERATION
                    );
                    json!({"invalid": "delta"})
                };
                write_json_response(
                    &mut stream,
                    "200 OK",
                    &json!({
                        "jsonrpc": "2.0", "id": 1,
                        "result": {"content": [], "structuredContent": structured,
                                   "isError": false, "resultType": "complete", "_meta": {}}
                    }),
                )
                .await;
            }
        });
        (port, task)
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
            refresh_interval_seconds: None,
            full_refresh_min_interval_seconds: None,
            full_refresh_repair_retry_seconds: None,
            kernel_in_place_deltas: false,
            kernel_audit_interval_seconds: None,
            projection_proof_interval_seconds: None,
        };
        let store = GenerationStore::open(
            &replica_root,
            &runtime.hosted_route_database_id,
            Some(runtime.origin_database_id.clone()),
        )
        .unwrap();
        let observed = ObservedInstalledConsumerIdentity {
            kernel_v2_reader: Default::default(),
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

    #[tokio::test]
    async fn migrated_revision5_persona_delta_refresh_promotes_and_survives_restart_with_status_provenance(
    ) {
        const RECORD_ID: &str = "1a7e4000-0000-4000-8000-00000000d200";

        let authority = crate::db::create_database(":memory:").await.unwrap();
        // Recreate a revision-5 schema-82 authority, then use the production
        // migration edge before capturing the standby's delta base.
        let mut connection = authority.write_pool().acquire().await.unwrap();
        crate::schema::step_down::step_down(&mut connection, 82)
            .await
            .unwrap();
        sqlx::query(&format!(
            "PRAGMA application_id = {}",
            crate::interchange::source_history_application_id(5)
        ))
        .execute(&mut *connection)
        .await
        .unwrap();
        drop(connection);
        let registry = crate::migrations::EngineMigrationRegistry::production();
        // Table rebuilds (engine 87) run with foreign keys fenced off, as the
        // runner does, so the edges apply on one connection with the fence up
        // rather than inside a pool transaction (the pragma is a no-op there).
        let mut migrating = authority.write_pool().acquire().await.unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut *migrating)
            .await
            .unwrap();
        // Each edge validates its own source stamp, as the runner stamps them.
        for edge in registry
            .pending(82, crate::db::CURRENT_ENGINE_SCHEMA_VERSION)
            .unwrap()
        {
            edge.apply(&mut migrating).await.unwrap();
            sqlx::query(&format!("PRAGMA user_version = {}", edge.to()))
                .execute(&mut *migrating)
                .await
                .unwrap();
        }
        sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&mut *migrating)
            .await
            .unwrap();
        drop(migrating);
        let head = read_authority_act_head(&authority).await.unwrap();
        head.validate().unwrap();
        assert_eq!(
            head.native_interchange_revision,
            crate::interchange::REVISION
        );
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (initial_bytes, initial_manifest) = snapshot_fixture(&authority).await;
        let initial_client = Arc::new(ScriptedClient::new(paged_replies(
            "delta-base",
            &initial_bytes,
            &initial_manifest,
        )));
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(&directory, origin, initial_client);
        let first = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap();
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
        let StandbyRefreshOutcome::Installed {
            generation: first, ..
        } = first
        else {
            panic!("initial snapshot refresh must install")
        };

        crate::store::append(
            &authority,
            crate::store::AppendSpec {
                record_id: RECORD_ID.into(),
                event_type: "record.created".into(),
                payload: json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "delta controller evidence",
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
        let expected_head = read_authority_act_head(&authority).await.unwrap().head_act;
        let (port, server) = serve_authority_act_calls(authority.clone(), 2).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        enable_deltas(&mut controller);
        let snapshot_fallback = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });
        controller.client = snapshot_fallback.clone();

        let outcome = controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap();
        server.await.unwrap();
        let StandbyRefreshOutcome::Advanced {
            generation,
            head_act,
        } = outcome
        else {
            panic!("an advanced authority must be applied in place")
        };
        assert_eq!(generation.id, first.id);
        assert_eq!(head_act, expected_head);
        assert_eq!(snapshot_fallback.calls.load(Ordering::SeqCst), 0);
        let accepted = crate::db::open_existing_database_standby_read_only(
            generation.snapshot_path.to_string_lossy().as_ref(),
        )
        .await
        .unwrap();
        let name: String = sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
            .bind(RECORD_ID)
            .fetch_one(accepted.pool())
            .await
            .unwrap();
        assert_eq!(name, "delta controller evidence");
        accepted.close().await;

        let activated = controller
            .store
            .activate_for_startup(&controller.observed)
            .await
            .unwrap();
        let super::super::StandbyStartupOutcome::Serving(active) = activated else {
            panic!("the advanced copy must remain activatable after restart")
        };
        assert_eq!(active.generation.id, first.id);
        let provider = super::super::StandbyStatusProvider::for_serving(
            controller.runtime.clone(),
            controller.store.clone(),
            controller.observed.clone(),
            &active,
            true,
            true,
        );
        let status = provider.status().await;
        let accepted_status = status.accepted_generation.unwrap();
        assert_eq!(
            accepted_status.materialization,
            StandbyGenerationMaterialization::Delta
        );
        assert_eq!(accepted_status.head_act, Some(expected_head));
        assert_eq!(accepted_status.source_history, "exhaustive");
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    /// The checkpoint rule (Richard, 7 Oct 2026): a whole snapshot whose source
    /// history is unknown (`application_id` 0, as on Native HQ) still takes
    /// forward deltas. The delta lands in place in the generation already
    /// being served, an open reader sees it, the copy survives restart and an
    /// off-path audit, and status keeps the earlier history labelled unknown.
    #[tokio::test]
    async fn history_unknown_checkpoint_takes_deltas_in_place() {
        const RECORD_ID: &str = "1a7e4000-0000-4000-8000-00000000d210";

        let authority = crate::db::create_database(":memory:").await.unwrap();
        sqlx::query("PRAGMA application_id = 0")
            .execute(authority.write_pool())
            .await
            .unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "unknown-history",
                &bytes,
                &manifest,
            ))),
        );
        let StandbyRefreshOutcome::Installed {
            generation: checkpoint,
            ..
        } = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap()
        else {
            panic!("the first refresh installs a whole snapshot")
        };
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
        let serving = crate::db::open_existing_database_standby_read_only(
            checkpoint.snapshot_path.to_string_lossy().as_ref(),
        )
        .await
        .unwrap();

        crate::store::append(
            &authority,
            crate::store::AppendSpec {
                record_id: RECORD_ID.into(),
                event_type: "record.created".into(),
                payload: json!({"type":"Document","kind":"note","name":"after the checkpoint"}),
                actor: None,
            },
        )
        .await
        .unwrap();
        let expected_head = read_authority_act_head(&authority).await.unwrap().head_act;
        let (port, server) = serve_authority_act_calls(authority.clone(), 2).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        let original = controller.observed.clone();
        controller.observed.source_sha = "d".repeat(40);
        controller.observed.artifact_sha256 = "e".repeat(64);
        enable_deltas(&mut controller);
        let snapshot_fallback = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });
        controller.client = snapshot_fallback.clone();
        let outcome = controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap();
        server.await.unwrap();
        let StandbyRefreshOutcome::Advanced {
            generation,
            head_act,
        } = outcome
        else {
            panic!("a history-unknown checkpoint must take the delta")
        };
        assert_eq!(generation.id, checkpoint.id);
        assert!(controller
            .store
            .consumer_rebind(&generation.id, &controller.observed)
            .unwrap()
            .is_some());
        assert_eq!(head_act, expected_head);
        assert_eq!(snapshot_fallback.calls.load(Ordering::SeqCst), 0);
        assert_eq!(controller.state().unwrap().last_delta_fallback_class, None);

        // The reader opened before the delta now sees it.
        let name: String = sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
            .bind(RECORD_ID)
            .fetch_one(serving.pool())
            .await
            .unwrap();
        assert_eq!(name, "after the checkpoint");
        serving.close().await;
        // The history marker is left exactly as it was.
        assert_eq!(
            &fs::read(&generation.snapshot_path).unwrap()[68..72],
            &[0; 4]
        );

        let audit = controller
            .store
            .audit_current(&controller.observed)
            .await
            .unwrap();
        assert!(audit.passed, "the advanced copy passes the full audit");

        let super::super::StandbyStartupOutcome::Serving(active) = controller
            .store
            .activate_for_startup(&controller.observed)
            .await
            .unwrap()
        else {
            panic!("the advanced copy must remain activatable after restart")
        };
        assert_eq!(active.generation.id, checkpoint.id);
        // A rollback to the original manifest consumer still validates and
        // serves the same copy after the replacement binary advanced it.
        let super::super::StandbyStartupOutcome::Serving(rollback) = controller
            .store
            .activate_for_startup(&original)
            .await
            .unwrap()
        else {
            panic!("rollback")
        };
        assert_eq!(rollback.generation.id, checkpoint.id);
        let rolled_back = crate::db::open_existing_database_standby_read_only(
            rollback.generation.snapshot_path.to_string_lossy().as_ref(),
        )
        .await
        .unwrap();
        let name: String = sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
            .bind(RECORD_ID)
            .fetch_one(rolled_back.pool())
            .await
            .unwrap();
        assert_eq!(name, "after the checkpoint");
        rolled_back.close().await;
        let provider = super::super::StandbyStatusProvider::for_serving(
            controller.runtime.clone(),
            controller.store.clone(),
            controller.observed.clone(),
            &active,
            true,
            true,
        );
        assert!(provider
            .response_context()
            .serving_consumer_rebound_at
            .is_some());
        let status = provider.status().await;
        assert_eq!(status.consumer_compatible, Some(true));
        assert!(status
            .serving_generation
            .as_ref()
            .unwrap()
            .consumer_rebind
            .is_some());
        for generation in [
            status.serving_generation.clone().unwrap(),
            status.accepted_generation.clone().unwrap(),
        ] {
            assert_eq!(
                generation.materialization,
                StandbyGenerationMaterialization::Delta
            );
            assert_eq!(generation.head_act, Some(expected_head));
            assert_eq!(generation.source_history, "unknown");
            assert!(generation.synced_at.is_some());
        }
        assert_eq!(
            status.freshness.state,
            super::super::StandbyFreshnessState::Fresh
        );
        let context = provider.response_context();
        assert_eq!(context.serving_head_act, Some(expected_head));
        assert_eq!(
            context.serving_materialization,
            Some(StandbyGenerationMaterialization::Delta)
        );
        assert_eq!(context.serving_source_history, Some("unknown"));
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    #[tokio::test]
    async fn validated_deltas_keep_live_status_verified_without_rechecking() {
        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "steady-state",
                &bytes,
                &manifest,
            ))),
        );
        let StandbyRefreshOutcome::Installed { generation, .. } = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap()
        else {
            panic!("initial snapshot")
        };
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
        let super::super::StandbyStartupOutcome::Serving(active) = controller
            .store
            .activate_for_startup(&controller.observed)
            .await
            .unwrap()
        else {
            panic!("active reader")
        };
        let provider = super::super::StandbyStatusProvider::for_serving(
            controller.runtime.clone(),
            controller.store.clone(),
            controller.observed.clone(),
            &active,
            true,
            true,
        );
        enable_deltas(&mut controller);
        let original_bytes = fs::read(&generation.snapshot_path).unwrap();
        // Probe-only publication creates the initial head, then two actual
        // applies change the DB and advance its act. No audit/reactivation.
        for ordinal in 0..3 {
            if ordinal > 0 {
                crate::store::create_record(
                    &authority,
                    json!({"type":"Document", "kind":"note", "name":format!("delta-{ordinal}")}),
                )
                .await
                .unwrap();
            }
            let (port, server) =
                serve_authority_act_calls(authority.clone(), if ordinal == 0 { 1 } else { 2 })
                    .await;
            controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
            let outcome = controller
                .refresh_once(RefreshCause::Scheduled)
                .await
                .unwrap();
            if ordinal > 0 {
                assert!(matches!(outcome, StandbyRefreshOutcome::Advanced { .. }));
            }
            server.await.unwrap();
            let status = provider.status().await;
            assert_eq!(status.accepted_generation_provenance, "available");
            assert_eq!(
                status.accepted_generation.as_ref().unwrap().generation_id,
                generation.id
            );
            assert_eq!(status.retained_generation_ids, vec![generation.id.clone()]);
            assert!(!status.degraded, "{:?}", status.degraded_reasons);
            controller.store.maintenance_idle().await;
        }
        assert_ne!(fs::read(&generation.snapshot_path).unwrap(), original_bytes);
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    /// A no-change refresh is one cheap probe: it neither hashes nor deeply
    /// verifies the copy. Bytes that no longer match the checkpoint digest
    /// would fail either check, yet the probe finishes unchanged.
    #[tokio::test]
    async fn no_change_probe_neither_hashes_nor_verifies_the_copy() {
        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "no-change",
                &bytes,
                &manifest,
            ))),
        );
        let StandbyRefreshOutcome::Installed {
            generation: checkpoint,
            ..
        } = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap()
        else {
            panic!("the first refresh installs a whole snapshot")
        };
        // Installation schedules maintenance, whose unknown-current check takes
        // attempt.lock and may hash/verify the copy. Finish it before corrupting
        // the fixture so this refresh exercises the no-change probe.
        controller.store.maintenance_idle().await;
        set_mode(&checkpoint.snapshot_path, 0o600).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&checkpoint.snapshot_path)
            .unwrap()
            .write_all(b"a hash or deep verification would refuse these bytes")
            .unwrap();
        set_mode(&checkpoint.snapshot_path, 0o400).unwrap();

        let (port, server) = serve_authority_act_calls(authority.clone(), 1).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        enable_deltas(&mut controller);
        let snapshot_fallback = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });
        controller.client = snapshot_fallback.clone();
        let StandbyRefreshOutcome::Unchanged { generation } = controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap()
        else {
            panic!("equal heads finish after the one probe")
        };
        server.await.unwrap();
        assert_eq!(generation.id, checkpoint.id);
        assert_eq!(snapshot_fallback.calls.load(Ordering::SeqCst), 0);
        let head = controller
            .store
            .generation_head(&checkpoint.id)
            .unwrap()
            .expect("the probe records when the copy was found current");
        assert!(!head.advanced_in_place());
        assert_eq!(
            head.head_act,
            read_authority_act_head(&authority).await.unwrap().head_act
        );
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    /// A delta that does not start at the copy's head (the authority skipped
    /// an act) is refused before anything is written, and the whole-snapshot
    /// path replaces the copy.
    #[tokio::test]
    async fn delta_gap_falls_back_to_a_whole_snapshot() {
        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "gap-base", &bytes, &manifest,
            ))),
        );
        let StandbyRefreshOutcome::Installed {
            generation: checkpoint,
            ..
        } = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap()
        else {
            panic!("the first refresh installs a whole snapshot")
        };
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
        for (index, name) in ["first", "second"].into_iter().enumerate() {
            crate::store::append(
                &authority,
                crate::store::AppendSpec {
                    record_id: format!("1a7e4000-0000-4000-8000-00000000d22{index}"),
                    event_type: "record.created".into(),
                    payload: json!({"type":"Document","kind":"note","name":name}),
                    actor: None,
                },
            )
            .await
            .unwrap();
        }
        let (fallback_bytes, fallback_manifest) = snapshot_fixture(&authority).await;
        controller.client = Arc::new(ScriptedClient::new(paged_replies(
            "gap-fallback",
            &fallback_bytes,
            &fallback_manifest,
        )));
        let (port, server) =
            serve_authority_act_calls_with(authority.clone(), 2, AuthorityFault::Gap).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        enable_deltas(&mut controller);
        let StandbyRefreshOutcome::Installed { generation, .. } = controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap()
        else {
            panic!("a gap must take the whole-snapshot path")
        };
        server.await.unwrap();
        assert_ne!(generation.id, checkpoint.id);
        assert_eq!(
            controller.state().unwrap().last_delta_fallback_class,
            Some(DeltaFallbackClass::IntegrityOrApplyRefusal)
        );
        assert!(controller
            .store
            .generation_head(&checkpoint.id)
            .unwrap()
            .is_none_or(|head| !head.advanced_in_place()));
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    /// A delta refused inside the apply transaction rolls back completely. If
    /// the whole-snapshot fallback then fails too, the same copy keeps serving
    /// exactly what it served before.
    #[tokio::test]
    async fn apply_refusal_rolls_back_and_failed_fallback_keeps_the_copy_serving() {
        const RECORD_ID: &str = "1a7e4000-0000-4000-8000-00000000d230";

        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "apply-base",
                &bytes,
                &manifest,
            ))),
        );
        let StandbyRefreshOutcome::Installed {
            generation: checkpoint,
            ..
        } = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap()
        else {
            panic!("the first refresh installs a whole snapshot")
        };
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
        let before = read_authority_act_head_from_path(&checkpoint.snapshot_path)
            .await
            .unwrap();
        let serving = crate::db::open_existing_database_standby_read_only(
            checkpoint.snapshot_path.to_string_lossy().as_ref(),
        )
        .await
        .unwrap();

        crate::store::append(
            &authority,
            crate::store::AppendSpec {
                record_id: RECORD_ID.into(),
                event_type: "record.created".into(),
                payload: json!({"type":"Document","kind":"note","name":"refused"}),
                actor: None,
            },
        )
        .await
        .unwrap();
        let failed_snapshot = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Network,
            calls: AtomicUsize::new(0),
        });
        controller.client = failed_snapshot.clone();
        let (port, server) =
            serve_authority_act_calls_with(authority.clone(), 2, AuthorityFault::PolicyDrift).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        enable_deltas(&mut controller);
        assert!(controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .is_err());
        server.await.unwrap();
        assert!(failed_snapshot.calls.load(Ordering::SeqCst) > 0);
        assert_eq!(
            controller.state().unwrap().last_delta_fallback_class,
            Some(DeltaFallbackClass::IntegrityOrApplyRefusal)
        );

        assert_eq!(
            controller
                .store
                .current_for_head_probe()
                .unwrap()
                .unwrap()
                .id,
            checkpoint.id
        );
        assert!(!sqlite_journal_path(&checkpoint.snapshot_path).exists());
        assert_eq!(
            read_authority_act_head_from_path(&checkpoint.snapshot_path)
                .await
                .unwrap(),
            before
        );
        let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE id = ?")
            .bind(RECORD_ID)
            .fetch_one(serving.pool())
            .await
            .unwrap();
        assert_eq!(applied, 0);
        serving.close().await;
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    /// A successful whole snapshot followed at once by the same fallback
    /// reason (here, an unreadable local act head) does not download again:
    /// whole snapshots of an existing copy wait a minimum interval whatever
    /// the previous outcome, and waiting is not a failure.
    #[tokio::test]
    async fn whole_snapshots_keep_a_minimum_interval_after_success() {
        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "interval-base",
                &bytes,
                &manifest,
            ))),
        );
        controller.config.full_refresh_min_interval_seconds = Some(3600);
        let StandbyRefreshOutcome::Installed {
            generation: installed,
            ..
        } = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap()
        else {
            panic!("the first refresh installs a whole snapshot")
        };
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
        let downloads = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });
        controller.client = downloads.clone();
        enable_deltas(&mut controller);
        let local = controller.store.current_for_head_probe().unwrap().unwrap();
        set_mode(&local.snapshot_path, 0o600).unwrap();
        fs::write(&local.snapshot_path, b"unreadable local act head").unwrap();
        set_mode(&local.snapshot_path, 0o400).unwrap();
        for _ in 0..2 {
            let (port, server) = serve_authority_act_calls(authority.clone(), 1).await;
            controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
            let StandbyRefreshOutcome::Deferred { generation, reason } = controller
                .refresh_once(RefreshCause::Scheduled)
                .await
                .unwrap()
            else {
                panic!("a whole snapshot inside the interval is deferred")
            };
            server.await.unwrap();
            assert_eq!(generation.id, installed.id);
            assert_eq!(reason, DEFERRED_FULL_REFRESH_INTERVAL);
            // The unreadable fixture can schedule unknown-current recovery.
            controller.store.maintenance_idle().await;
        }
        assert_eq!(downloads.calls.load(Ordering::SeqCst), 0);
        let state = controller.state().unwrap();
        assert_eq!(state.consecutive_failure_count, 0);
        assert_eq!(
            state.last_deferral.as_deref(),
            Some("full_refresh_interval")
        );
        assert_eq!(
            state.last_delta_fallback_class,
            Some(DeltaFallbackClass::UntrustedLocalBase)
        );
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    /// A copy with an incompatible installed consumer is never advanced:
    /// startup would refuse it, so the refresh takes a whole snapshot after
    /// probing hosted compatibility.
    #[tokio::test]
    async fn consumer_format_change_takes_a_whole_snapshot_instead_of_a_delta() {
        for fault in ["schema", "ddl", "platform", "revision"] {
            let authority = crate::db::create_database(":memory:").await.unwrap();
            let origin = crate::identity::database_id(&authority).await.unwrap();
            let (bytes, manifest) = snapshot_fixture(&authority).await;
            let directory = tempfile::tempdir().unwrap();
            let mut controller = controller_for_origin(
                &directory,
                origin,
                Arc::new(ScriptedClient::new(paged_replies(
                    "consumer-base",
                    &bytes,
                    &manifest,
                ))),
            );
            let StandbyRefreshOutcome::Installed {
                generation: installed,
                ..
            } = controller
                .refresh_once(RefreshCause::Startup)
                .await
                .unwrap()
            else {
                panic!("the first refresh installs a whole snapshot")
            };
            // Installation maintenance shares attempt.lock with the refresh below.
            controller.store.maintenance_idle().await;
            enable_deltas(&mut controller);
            controller.observed.artifact_sha256 = "9".repeat(64);
            match fault {
                "schema" => controller.observed.engine_schema_version += 1,
                "ddl" => controller.observed.ddl_sha256 = "9".repeat(64),
                "platform" => controller.observed.platform = StandbyConsumerPlatform::MacosArm64,
                "revision" => {
                    controller
                        .store
                        .ensure_consumer_binding(&installed.id, &controller.observed)
                        .await
                        .unwrap();
                    let path = directory
                        .path()
                        .join("replica/accepted/heads")
                        .join(format!(
                            "{}.consumer-rebind-{}.json",
                            installed.id, controller.observed.artifact_sha256
                        ));
                    let mut receipt: Value =
                        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    receipt["acceptance"]["native_interchange_revision"] =
                        json!(crate::interchange::REVISION + 1);
                    receipt["sha256"] = json!(hex::encode(Sha256::digest(
                        serde_jcs::to_vec(&receipt["acceptance"]).unwrap()
                    )));
                    fs::write(path, serde_json::to_vec(&receipt).unwrap()).unwrap();
                }
                _ => unreachable!(),
            }
            let downloads = Arc::new(AlwaysFailClient {
                class: RefreshFailureClass::Protocol,
                calls: AtomicUsize::new(0),
            });
            controller.client = downloads.clone();
            let (port, server) = serve_authority_act_calls(authority.clone(), 1).await;
            controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
            assert!(controller
                .refresh_once(RefreshCause::Scheduled)
                .await
                .is_err());
            server.await.unwrap();
            let state = controller.state().unwrap();
            assert_eq!(
                state.last_delta_fallback_class,
                Some(DeltaFallbackClass::ConsumerChanged)
            );
            assert_eq!(
                state.last_failure_class,
                Some(RefreshFailureClass::Protocol)
            );
            assert!(downloads.calls.load(Ordering::SeqCst) > 0);
            assert!(controller
                .store
                .generation_head(&installed.id)
                .unwrap()
                .is_none_or(|head| !head.advanced_in_place()));
            controller.store.maintenance_idle().await;
            authority.close().await;
        }
    }

    #[tokio::test]
    async fn rebind_verification_refusal_requests_full_without_publishing_acceptance() {
        assert_rebind_failure_routing("corrupt").await;
    }

    #[tokio::test]
    async fn rebind_infrastructure_failure_does_not_request_full() {
        assert_rebind_failure_routing("io").await;
    }

    #[tokio::test]
    async fn rebind_shutdown_cancellation_does_not_request_full() {
        assert_rebind_failure_routing("cancel").await;
    }

    async fn assert_rebind_failure_routing(fault: &str) {
        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "rebind-base",
                &bytes,
                &manifest,
            ))),
        );
        let StandbyRefreshOutcome::Installed { generation, .. } = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap()
        else {
            panic!("install")
        };
        // This proof needs an actual refresh attempt, not busy/coalescing.
        // Wait for maintenance AND independently held attempt/transfer leases
        // before changing verification inputs. Worker completion alone does
        // not establish that every open lock description has been released.
        refresh_workers_idle(&controller).await;
        controller.observed.artifact_sha256 = "9".repeat(64);
        enable_deltas(&mut controller);
        if fault == "io" {
            // A healthy advanced copy needs scratch space for consistent-copy
            // verification. Make that scratch path unusable without damaging
            // the generation or its compatibility evidence.
            controller
                .store
                .open_head_writer(&generation)
                .await
                .unwrap()
                .unwrap()
                .close()
                .await;
            fs::remove_dir_all(controller.store.staging_dir()).unwrap();
            fs::write(controller.store.staging_dir(), b"not a directory").unwrap();
        } else if fault == "corrupt" {
            set_mode(&generation.snapshot_path, 0o600).unwrap();
            fs::write(&generation.snapshot_path, b"damaged checkpoint").unwrap();
            set_mode(&generation.snapshot_path, 0o400).unwrap();
        }
        let downloads = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });
        controller.client = downloads.clone();
        let (port, server) = serve_authority_act_calls(authority.clone(), 1).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        let outcome = if fault == "cancel" {
            let mut work = std::pin::pin!(controller.refresh_once(RefreshCause::Scheduled));
            let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(true));
            std::future::poll_fn(|cx| {
                super::super::generation_store::with_verification_cancellation(
                    cancelled.clone(),
                    || work.as_mut().poll(cx),
                )
            })
            .await
        } else {
            controller.refresh_once(RefreshCause::Scheduled).await
        };
        assert!(
            outcome.is_err(),
            "rebind verification must refuse {fault}: {outcome:?}"
        );
        server.await.unwrap();
        let state = controller.state().unwrap();
        if fault != "corrupt" {
            assert_eq!(state.last_failure_class, Some(RefreshFailureClass::LocalIo));
            assert_eq!(state.last_delta_fallback_class, None);
            assert_eq!(downloads.calls.load(Ordering::SeqCst), 0);
        } else {
            assert_eq!(
                state.last_delta_fallback_class,
                Some(DeltaFallbackClass::ConsumerChanged)
            );
            assert!(downloads.calls.load(Ordering::SeqCst) > 0);
        }
        let sidecar = directory
            .path()
            .join("replica/accepted/heads")
            .join(format!(
                "{}.consumer-rebind-{}.json",
                generation.id, controller.observed.artifact_sha256
            ));
        assert!(!sidecar.exists());
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    /// A one-shot repair (here a changed consumer) does not wait out the
    /// interval between whole snapshots, but one that follows a whole snapshot
    /// that did not complete waits the repair retry interval, unless manual.
    #[tokio::test]
    async fn repairs_skip_the_full_interval_unless_the_last_whole_snapshot_failed() {
        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "repair-base",
                &bytes,
                &manifest,
            ))),
        );
        controller.config.full_refresh_min_interval_seconds = Some(3600);
        controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap();
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
        enable_deltas(&mut controller);
        controller.observed.ddl_sha256 = "9".repeat(64);
        let downloads = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });
        controller.client = downloads.clone();

        let (port, server) = serve_authority_act_calls(authority.clone(), 3).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        // The first whole snapshot started a moment ago, yet the repair runs.
        assert!(controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .is_err());
        assert_eq!(downloads.calls.load(Ordering::SeqCst), 1);
        // That repair failed, so the next scheduled tick waits the interval.
        controller.store.maintenance_idle().await;
        let StandbyRefreshOutcome::Deferred { reason, .. } = controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap()
        else {
            panic!("a repair after a failed whole snapshot waits")
        };
        assert_eq!(reason, DEFERRED_FULL_REFRESH_INTERVAL);
        assert_eq!(downloads.calls.load(Ordering::SeqCst), 1);
        // An operator's manual refresh does not.
        controller.store.maintenance_idle().await;
        assert!(controller.refresh_once(RefreshCause::Manual).await.is_err());
        assert_eq!(downloads.calls.load(Ordering::SeqCst), 2);
        server.await.unwrap();
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    async fn assert_full_retry(
        fallback: DeltaFallbackClass,
        minutes_since_start: i64,
        cause: RefreshCause,
        configure: impl FnOnce(&mut StandbyRefreshController, &mut StandbyRefreshState),
        should_run: bool,
    ) {
        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "failed-full-base",
                &bytes,
                &manifest,
            ))),
        );
        controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap();
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
        enable_deltas(&mut controller);
        controller.config.full_refresh_min_interval_seconds = None;
        let mut state = controller.state().unwrap();
        state.last_full_refresh_at = Some(
            (chrono::Utc::now() - chrono::Duration::minutes(minutes_since_start)).to_rfc3339(),
        );
        controller.record_full_outcome(false).unwrap();
        configure(&mut controller, &mut state);
        controller.write_state(&state).unwrap();
        let local = controller.store.current_for_head_probe().unwrap().unwrap();
        match fallback {
            DeltaFallbackClass::ConsumerChanged => {
                controller.observed.ddl_sha256 = "9".repeat(64);
            }
            DeltaFallbackClass::AuditFailed => {
                controller.store.require_full_refresh(&local).unwrap();
            }
            DeltaFallbackClass::UntrustedLocalBase => {
                set_mode(&local.snapshot_path, 0o600).unwrap();
                fs::write(&local.snapshot_path, b"unreadable local act head").unwrap();
                set_mode(&local.snapshot_path, 0o400).unwrap();
            }
            _ => panic!("unsupported test fallback"),
        }
        let downloads = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });
        controller.client = downloads.clone();
        let (port, server) = serve_authority_act_calls(authority.clone(), 1).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        let result = controller.refresh_once(cause).await;
        server.await.unwrap();
        if should_run {
            assert!(
                result.is_err(),
                "the injected download failure proves FULL ran"
            );
            assert_eq!(downloads.calls.load(Ordering::SeqCst), 1);
        } else {
            assert!(matches!(
                result.unwrap(),
                StandbyRefreshOutcome::Deferred {
                    reason: DEFERRED_FULL_REFRESH_INTERVAL,
                    ..
                }
            ));
            assert_eq!(downloads.calls.load(Ordering::SeqCst), 0);
        }
        assert_eq!(
            controller.state().unwrap().last_delta_fallback_class,
            Some(fallback)
        );
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    #[tokio::test]
    async fn consumer_changed_repair_retries_a_failed_full_after_thirty_minutes() {
        assert_full_retry(
            DeltaFallbackClass::ConsumerChanged,
            31,
            RefreshCause::Scheduled,
            |_, _| {},
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn consumer_changed_repair_holds_a_recent_failed_full() {
        assert_full_retry(
            DeltaFallbackClass::ConsumerChanged,
            5,
            RefreshCause::Scheduled,
            |_, _| {},
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn non_repair_keeps_six_hour_interval_after_a_failed_full() {
        assert_full_retry(
            DeltaFallbackClass::UntrustedLocalBase,
            31,
            RefreshCause::Scheduled,
            |_, _| {},
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn failed_full_repair_retry_interval_is_configurable() {
        for (started_minutes_ago, retry, ordinary, should_run) in [
            (5, 60, None, true),
            (31, 3600, None, false),
            (0, 0, None, false), // Zero still waits sixty seconds.
            (2, 0, None, true),
            (0, 0, Some(0), true), // The ordinary zero knob disables both holds.
            (11, 1800, Some(600), true),
            (5, 1800, Some(600), false),
        ] {
            assert_full_retry(
                DeltaFallbackClass::ConsumerChanged,
                started_minutes_ago,
                RefreshCause::Scheduled,
                |controller, _| {
                    controller.config.full_refresh_repair_retry_seconds = Some(retry);
                    controller.config.full_refresh_min_interval_seconds = ordinary;
                },
                should_run,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn repair_after_success_bypasses_a_recent_full_start() {
        assert_full_retry(
            DeltaFallbackClass::ConsumerChanged,
            0,
            RefreshCause::Scheduled,
            |controller, _| controller.record_full_outcome(true).unwrap(),
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn manual_bypasses_the_failed_full_repair_hold() {
        assert_full_retry(
            DeltaFallbackClass::ConsumerChanged,
            0,
            RefreshCause::Manual,
            |_, _| {},
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn slow_failed_full_repair_waits_from_failure_completion() {
        assert_full_retry(
            DeltaFallbackClass::ConsumerChanged,
            40,
            RefreshCause::Scheduled,
            |_, state| {
                state.last_full_failure_at =
                    Some((chrono::Utc::now() - chrono::Duration::minutes(5)).to_rfc3339())
            },
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn audit_failed_repair_uses_the_same_failure_completion_hold() {
        for (minutes_since_end, should_run) in [(5, false), (31, true)] {
            assert_full_retry(
                DeltaFallbackClass::AuditFailed,
                40,
                RefreshCause::Scheduled,
                |_, state| {
                    state.last_full_failure_at = Some(
                        (chrono::Utc::now() - chrono::Duration::minutes(minutes_since_end))
                            .to_rfc3339(),
                    )
                },
                should_run,
            )
            .await;
        }
    }

    #[test]
    fn repair_failure_time_falls_back_safely_and_holds_future_timestamps() {
        let mut state = StandbyRefreshState {
            last_full_refresh_at: Some(
                (chrono::Utc::now() - chrono::Duration::minutes(5)).to_rfc3339(),
            ),
            ..Default::default()
        };
        let minimum = Duration::from_secs(1800);
        for failed_at in [None, Some("invalid"), Some("2000-01-01T00:00:00Z")] {
            state.last_full_failure_at = failed_at.map(str::to_owned);
            assert!(full_refresh_is_recent(&state, true, minimum));
        }
        state.last_full_refresh_at =
            Some((chrono::Utc::now() - chrono::Duration::minutes(40)).to_rfc3339());
        for failed_at in [None, Some("invalid")] {
            state.last_full_failure_at = failed_at.map(str::to_owned);
            assert!(!full_refresh_is_recent(&state, true, minimum));
        }
        state.last_full_failure_at = Some("2099-01-01T00:00:00Z".into());
        assert!(full_refresh_is_recent(&state, true, minimum));
        assert!(!full_refresh_is_recent(&state, false, minimum));
        assert!(!full_refresh_is_recent(&state, true, Duration::ZERO));
        state.last_full_refresh_at = state.last_full_failure_at.clone();
        state.last_full_failure_at = None;
        assert!(full_refresh_is_recent(&state, true, minimum));
    }

    /// The one-shot CLI can now carry an automatic cause. Whatever that cause
    /// is, only Manual bypasses the whole-snapshot minimum interval: an
    /// automatic hint that falls back to the snapshot path still waits, so a
    /// persistent delta refusal cannot turn SSE bursts into repeated
    /// database-sized captures.
    #[tokio::test]
    async fn automatic_causes_keep_the_full_interval_that_manual_bypasses() {
        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "cause-base",
                &bytes,
                &manifest,
            ))),
        );
        controller.config.full_refresh_min_interval_seconds = Some(3600);
        controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap();
        enable_deltas(&mut controller);
        let downloads = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });
        controller.client = downloads.clone();
        controller.store.maintenance_idle().await;
        let local = controller.store.current_for_head_probe().unwrap().unwrap();
        set_mode(&local.snapshot_path, 0o600).unwrap();
        fs::write(&local.snapshot_path, b"unreadable local act head").unwrap();
        set_mode(&local.snapshot_path, 0o400).unwrap();
        for cause in [
            RefreshCause::Scheduled,
            RefreshCause::Wake,
            RefreshCause::NetworkRecovery,
            RefreshCause::AfterAdmittedWrite,
        ] {
            // Unknown-current recovery shares attempt.lock with refresh. Let
            // it settle so this fixture tests the FULL cooldown, not coalescing.
            controller.store.maintenance_idle().await;
            let (port, server) = serve_authority_act_calls(authority.clone(), 1).await;
            controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
            let outcome = controller.refresh_once(cause).await.unwrap();
            server.await.unwrap();
            let StandbyRefreshOutcome::Deferred { reason, .. } = outcome else {
                panic!("automatic cause {cause:?} must not bypass the whole-snapshot interval");
            };
            assert_eq!(reason, DEFERRED_FULL_REFRESH_INTERVAL, "{cause:?}");
        }
        assert_eq!(downloads.calls.load(Ordering::SeqCst), 0);
        // Manual remains the one-shot repair path and does not wait it out.
        controller.store.maintenance_idle().await;
        let (port, server) = serve_authority_act_calls(authority.clone(), 1).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        let manual = controller.refresh_once(RefreshCause::Manual).await;
        assert!(manual.is_err(), "manual repair must try FULL: {manual:?}");
        server.await.unwrap();
        assert_eq!(downloads.calls.load(Ordering::SeqCst), 1);
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    /// Until a serving build that reads generations as ordinary SQLite files
    /// has opened the current generation, deltas wait instead of rewriting a
    /// file an older, immutable reader may be serving.
    #[tokio::test]
    async fn deltas_wait_for_an_upgraded_serving_reader() {
        const RECORD_ID: &str = "1a7e4000-0000-4000-8000-00000000d240";

        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "reader-base",
                &bytes,
                &manifest,
            ))),
        );
        let StandbyRefreshOutcome::Installed {
            generation: installed,
            ..
        } = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap()
        else {
            panic!("the first refresh installs a whole snapshot")
        };
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
        crate::store::append(
            &authority,
            crate::store::AppendSpec {
                record_id: RECORD_ID.into(),
                event_type: "record.created".into(),
                payload: json!({"type":"Document","kind":"note","name":"waits for the reader"}),
                actor: None,
            },
        )
        .await
        .unwrap();
        let before = read_authority_act_head_from_path(&installed.snapshot_path)
            .await
            .unwrap();
        controller.delta_enabled = true;
        controller.client = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });

        // An older build serving it leaves no marker: the head probe runs,
        // but no delta is fetched or applied.
        let (port, server) = serve_authority_act_calls(authority.clone(), 1).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        let StandbyRefreshOutcome::Deferred { reason, .. } = controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap()
        else {
            panic!("the delta waits for an upgraded reader")
        };
        server.await.unwrap();
        assert_eq!(reason, DEFERRED_READER_NOT_UPGRADED);
        assert_eq!(
            read_authority_act_head_from_path(&installed.snapshot_path)
                .await
                .unwrap(),
            before
        );

        // A marker from a different build does not count either, and a
        // matching marker only counts while its reader still holds the lock.
        let store = &controller.store;
        let sha = &controller.observed.source_sha;
        let mut other = controller.observed.clone();
        other.source_sha = "8".repeat(40);
        let reader = store.hold_serving_reader(&installed.id).unwrap();
        store.record_serving_reader(&installed.id, &other).unwrap();
        assert!(!store.served_by_build(&installed.id, sha));
        store
            .record_serving_reader(&installed.id, &controller.observed)
            .unwrap();
        assert!(store.served_by_build(&installed.id, sha));
        drop(reader);
        assert!(!store.served_by_build(&installed.id, sha));

        enable_deltas(&mut controller);
        let (port, server) = serve_authority_act_calls(authority.clone(), 2).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        assert!(matches!(
            controller
                .refresh_once(RefreshCause::Scheduled)
                .await
                .unwrap(),
            StandbyRefreshOutcome::Advanced { .. }
        ));
        server.await.unwrap();
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    /// A serving read that outlasts the writer's wait makes the commit fail
    /// BUSY. That is a deferral, not a reason to replace the copy.
    #[tokio::test]
    async fn writer_busy_defers_the_delta_instead_of_replacing_the_copy() {
        const RECORD_ID: &str = "1a7e4000-0000-4000-8000-00000000d241";

        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "busy-base",
                &bytes,
                &manifest,
            ))),
        );
        let StandbyRefreshOutcome::Installed {
            generation: installed,
            ..
        } = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap()
        else {
            panic!("the first refresh installs a whole snapshot")
        };
        controller.store.maintenance_idle().await;
        let super::super::StandbyStartupOutcome::Serving(active) = controller
            .store
            .activate_for_startup(&controller.observed)
            .await
            .unwrap()
        else {
            panic!("active reader")
        };
        let provider = super::super::StandbyStatusProvider::for_serving(
            controller.runtime.clone(),
            controller.store.clone(),
            controller.observed.clone(),
            &active,
            true,
            true,
        );
        assert_eq!(
            provider.status().await.accepted_generation_provenance,
            "available"
        );
        let (entered, resume) = controller.store.pause_next_verification();
        crate::store::append(
            &authority,
            crate::store::AppendSpec {
                record_id: RECORD_ID.into(),
                event_type: "record.created".into(),
                payload: json!({"type":"Document","kind":"note","name":"waits for a long read"}),
                actor: None,
            },
        )
        .await
        .unwrap();
        let before = read_authority_act_head_from_path(&installed.snapshot_path)
            .await
            .unwrap();
        enable_deltas(&mut controller);
        let downloads = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });
        controller.client = downloads.clone();
        crate::db::STANDBY_HEAD_WRITER_BUSY_TIMEOUT
            .with(|timeout| timeout.set(Some(Duration::from_millis(100))));

        // A serving read holds its shared lock across the writer's commit.
        let mut reader = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&installed.snapshot_path)
                .read_only(true),
        )
        .await
        .unwrap();
        sqlx::query("BEGIN").execute(&mut reader).await.unwrap();
        sqlx::query("SELECT count(*) FROM sqlite_master")
            .fetch_one(&mut reader)
            .await
            .unwrap();

        let (port, server) = serve_authority_act_calls(authority.clone(), 2).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        let StandbyRefreshOutcome::Deferred { reason, .. } = controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap()
        else {
            panic!("a busy writer defers the delta")
        };
        server.await.unwrap();
        assert_eq!(reason, DEFERRED_DATABASE_BUSY);
        assert_eq!(downloads.calls.load(Ordering::SeqCst), 0);
        let state = controller.state().unwrap();
        assert_eq!(state.consecutive_failure_count, 0);
        assert_eq!(state.last_delta_fallback_class, None);
        assert_eq!(state.last_deferral.as_deref(), Some("database_busy"));
        assert_eq!(
            controller
                .store
                .deferral_counts(&installed.id)
                .database_busy,
            1
        );
        assert!(controller
            .store
            .generation_head(&installed.id)
            .unwrap()
            .is_none_or(|head| !head.full_refresh_required));

        // Once the read ends, the next tick applies the same delta.
        reader.close().await.unwrap();
        assert_eq!(
            read_authority_act_head_from_path(&installed.snapshot_path)
                .await
                .unwrap(),
            before
        );
        // The failed commit changed the head/file stamp, evicting its verdict.
        // Maintenance was requested by the failed attempt itself, without a
        // FULL, restart or another delta. Hold its check to observe both states.
        entered.notified().await;
        let status = provider.status().await;
        assert_eq!(status.accepted_generation_provenance, "unverified");
        assert!(status.degraded);
        resume.notify_one();
        controller.store.maintenance_idle().await;
        let status = provider.status().await;
        assert_eq!(status.accepted_generation_provenance, "available");
        assert!(!status.degraded, "{:?}", status.degraded_reasons);
        let (port, server) = serve_authority_act_calls(authority.clone(), 2).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        assert!(matches!(
            controller
                .refresh_once(RefreshCause::Scheduled)
                .await
                .unwrap(),
            StandbyRefreshOutcome::Advanced { .. }
        ));
        server.await.unwrap();
        assert_eq!(
            controller.store.deferral_counts(&installed.id),
            Default::default()
        );
        crate::db::STANDBY_HEAD_WRITER_BUSY_TIMEOUT.with(|timeout| timeout.set(None));
        authority.close().await;
    }

    /// A reader that never upgrades is counted tick by tick, and the count
    /// clears once an upgraded reader serves the copy.
    #[tokio::test]
    async fn reader_deferrals_are_counted_until_an_upgraded_reader_serves() {
        const RECORD_ID: &str = "1a7e4000-0000-4000-8000-00000000d242";

        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "count-base",
                &bytes,
                &manifest,
            ))),
        );
        let StandbyRefreshOutcome::Installed {
            generation: installed,
            ..
        } = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap()
        else {
            panic!("the first refresh installs a whole snapshot")
        };
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
        crate::store::append(
            &authority,
            crate::store::AppendSpec {
                record_id: RECORD_ID.into(),
                event_type: "record.created".into(),
                payload: json!({"type":"Document","kind":"note","name":"counted deferral"}),
                actor: None,
            },
        )
        .await
        .unwrap();
        controller.delta_enabled = true;
        for expected in 1..=3_u32 {
            let (port, server) = serve_authority_act_calls(authority.clone(), 1).await;
            controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
            controller
                .refresh_once(RefreshCause::Scheduled)
                .await
                .unwrap();
            server.await.unwrap();
            assert_eq!(
                controller
                    .store
                    .deferral_counts(&installed.id)
                    .reader_not_upgraded,
                expected
            );
        }

        // The count never enters the head record: a build that predates it
        // parses that record strictly.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct HeadAsBuiltBeforeDeferralCounts {
            contract: String,
            version: u32,
            generation_id: String,
            head_act: i64,
            materialization: StandbyGenerationMaterialization,
            synced_at: String,
            full_refresh_required: bool,
        }
        controller
            .store
            .record_synced(&installed, 1, &now())
            .unwrap();
        let heads = directory.path().join("replica/accepted/heads");
        serde_json::from_slice::<HeadAsBuiltBeforeDeferralCounts>(
            &fs::read(heads.join(format!("{}.json", installed.id))).unwrap(),
        )
        .unwrap();
        assert!(heads.join(format!("{}.deferrals", installed.id)).is_file());

        enable_deltas(&mut controller);
        let (port, server) = serve_authority_act_calls(authority.clone(), 2).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(
            controller.store.deferral_counts(&installed.id),
            Default::default()
        );
        assert!(!heads.join(format!("{}.deferrals", installed.id)).exists());
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    #[tokio::test]
    async fn maintenance_head_preserves_freshness_without_full_and_recovers() {
        for header in [false, true] {
            assert_maintenance_preserves_copy_and_recovers(false, header, false, false).await;
        }
    }

    #[tokio::test]
    async fn maintenance_delta_preserves_freshness_without_full_and_recovers() {
        for header in [false, true] {
            assert_maintenance_preserves_copy_and_recovers(true, header, false, false).await;
        }
    }

    #[tokio::test]
    async fn update_required_head_and_delta_preserve_generation_without_full_then_recover() {
        for delta in [false, true] {
            assert_maintenance_preserves_copy_and_recovers(delta, false, true, false).await;
        }
    }

    #[tokio::test]
    async fn receiver_shape_update_required_delta_retains_existing_full_fallback() {
        assert_maintenance_preserves_copy_and_recovers(true, false, false, true).await;
    }

    async fn assert_maintenance_preserves_copy_and_recovers(
        delta: bool,
        header: bool,
        update: bool,
        receiver_shape_update: bool,
    ) {
        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let base_act = read_authority_act_head(&authority).await.unwrap().head_act;
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "maintenance-base",
                &bytes,
                &manifest,
            ))),
        );
        let StandbyRefreshOutcome::Installed { generation, .. } = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap()
        else {
            panic!("initial snapshot must install")
        };
        // Settle installation verification before changing the fixture's head.
        controller.store.maintenance_idle().await;
        // Give the timestamp a distinct value so a false no-op refresh cannot
        // pass merely because the two attempts ran in the same millisecond.
        let synced_at = "2026-10-14T00:00:00Z";
        controller
            .store
            .record_synced(&generation, base_act, synced_at)
            .unwrap();
        let before_bytes = fs::read(&generation.snapshot_path).unwrap();
        let before_state = controller.state().unwrap();
        if delta {
            crate::store::append(&authority, crate::store::AppendSpec {
                record_id: "1a7e4000-0000-4000-8000-00000000d945".into(),
                event_type: "record.created".into(),
                payload: json!({"type":"Document","kind":"note","name":"after maintenance base"}),
                actor: None,
            }).await.unwrap();
        }
        let expected_act = read_authority_act_head(&authority).await.unwrap().head_act;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let db = authority.clone();
        let server = tokio::spawn(async move {
            use super::super::delta_transport::{
                observe_authority_act_delta, observe_authority_act_head,
                AUTHORITY_ACT_DELTA_OPERATION, AUTHORITY_ACT_HEAD_OPERATION,
            };
            let calls = if delta {
                vec![
                    (AUTHORITY_ACT_HEAD_OPERATION, false),
                    (AUTHORITY_ACT_DELTA_OPERATION, true),
                    (AUTHORITY_ACT_HEAD_OPERATION, false),
                    (AUTHORITY_ACT_DELTA_OPERATION, false),
                ]
            } else {
                vec![
                    (AUTHORITY_ACT_HEAD_OPERATION, true),
                    (AUTHORITY_ACT_HEAD_OPERATION, false),
                ]
            };
            for (operation, maintenance) in calls {
                let (mut stream, request) = loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let (headers, request) = read_http_request(&mut stream).await;
                    if refuse_chunked_route(&mut stream, &headers).await {
                        continue;
                    }
                    break (stream, request);
                };
                assert_eq!(request["params"]["arguments"]["operation"], operation);
                if maintenance && receiver_shape_update {
                    write_json_response(&mut stream,"200 OK",&json!({"jsonrpc":"2.0","id":1,"result":{
                        "content":[],"isError":true,"structuredContent":{"error_code":super::super::shapes::UPDATE_REQUIRED},
                        "resultType":"complete","_meta":{}
                    }})).await;
                    continue;
                }
                if maintenance && update {
                    write_json_response(&mut stream, "426 Upgrade Required", &json!({
                        "error_code":"client_update_required","outcome":"refused","applied":false
                    })).await;
                    continue;
                }

                let structured = if operation == AUTHORITY_ACT_HEAD_OPERATION {
                    serde_json::to_value(observe_authority_act_head(&db, "route-1").await.unwrap())
                        .unwrap()
                } else {
                    let from = request["params"]["arguments"]["arguments"]["from_exclusive_act"]
                        .as_i64()
                        .unwrap();
                    assert_eq!(from, base_act);
                    serde_json::to_value(
                        observe_authority_act_delta(&db, "route-1", from)
                            .await
                            .unwrap(),
                    )
                    .unwrap()
                };
                let mut envelope = json!({"jsonrpc":"2.0","id":1,"result":{
                    "content":[],"structuredContent":structured,"isError":false,"resultType":"complete","_meta":{}}});
                if maintenance && !header {
                    envelope["result"]["_meta"]["nativeMaintenance"] = json!({
                        "read_only":true,"snapshot_at":"2026-10-15T20:31:33.444Z"
                    });
                }
                if maintenance && header {
                    let body = serde_json::to_vec(&envelope).unwrap();
                    stream.write_all(format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-native-read-only: true\r\nx-native-snapshot-at: 2026-10-15T20:31:33.444Z\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()
                    ).as_bytes()).await.unwrap();
                    stream.write_all(&body).await.unwrap();
                    stream.shutdown().await.unwrap();
                } else {
                    write_json_response(&mut stream, "200 OK", &envelope).await;
                }
            }
        });
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        enable_deltas(&mut controller);
        let fallback = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });
        controller.client = fallback.clone();
        let failure = controller
            .refresh_once_with_receipt(RefreshCause::Manual)
            .await
            .unwrap_err();
        if receiver_shape_update {
            assert_eq!(failure.receipt.class, RefreshFailureClass::Protocol);
            assert_eq!(failure.receipt.phase, RefreshAttemptPhase::Full);
            assert!(failure.receipt.delta_fallback.is_some());
            assert_eq!(fallback.calls.load(Ordering::SeqCst), 1);
            assert_eq!(fs::read(&generation.snapshot_path).unwrap(), before_bytes);
            assert_eq!(
                controller
                    .store
                    .current_for_head_probe()
                    .unwrap()
                    .unwrap()
                    .id,
                generation.id
            );
            server.abort();
            controller.store.maintenance_idle().await;
            authority.close().await;
            return;
        }
        assert_eq!(
            failure.receipt.class,
            if update {
                RefreshFailureClass::Compatibility
            } else {
                RefreshFailureClass::Network
            }
        );
        if update {
            assert_eq!(
                controller.pending_observer.compatibility().status()["status"],
                "demand_recorded"
            );
        } else {
            assert_eq!(failure.receipt.detail, "maintenance");
        }
        assert_eq!(failure.receipt.phase, RefreshAttemptPhase::Following);
        assert_eq!(failure.receipt.delta_fallback, None);
        let state = controller.state().unwrap();
        assert_eq!(state.last_success_at, before_state.last_success_at);
        assert_eq!(
            state.last_full_refresh_at,
            before_state.last_full_refresh_at
        );
        assert_eq!(state.last_delta_fallback_class, None);
        assert_eq!(state.installed_generation_id, Some(generation.id.clone()));
        let head = controller
            .store
            .generation_head(&generation.id)
            .unwrap()
            .unwrap();
        assert_eq!(head.synced_at, synced_at);
        assert_eq!(head.head_act, base_act);
        assert_eq!(fs::read(&generation.snapshot_path).unwrap(), before_bytes);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);

        // record_synced creates the previously absent head (None -> Some),
        // invalidating the installed verification stamp; synced_at alone is
        // excluded from that stamp. The failed refresh can schedule verification
        // recovery, which shares attempt.lock. Settle it before hosted recovery
        // so the assertion cannot race a legitimate Accepted/coalesced result.
        controller.store.maintenance_idle().await;
        let outcome = controller
            .refresh_once(RefreshCause::NetworkRecovery)
            .await
            .unwrap();
        if delta {
            assert!(
                matches!(outcome, StandbyRefreshOutcome::Advanced { head_act, .. } if head_act == expected_act),
                "live delta recovery must advance to {expected_act} (header={header}): {outcome:?}"
            );
        } else {
            assert!(
                matches!(outcome, StandbyRefreshOutcome::Unchanged { .. }),
                "live head recovery must confirm the existing copy (header={header}): {outcome:?}"
            );
        }
        server.await.unwrap();
        let head = controller
            .store
            .generation_head(&generation.id)
            .unwrap()
            .unwrap();
        assert_ne!(head.synced_at, synced_at);
        assert_eq!(head.head_act, expected_act);
        assert_eq!(
            controller
                .store
                .current_for_head_probe()
                .unwrap()
                .unwrap()
                .id,
            generation.id
        );
        let state = controller.state().unwrap();
        assert_eq!(state.last_failure_class, None);
        assert_eq!(state.consecutive_failure_count, 0);
        assert_eq!(
            state.last_full_refresh_at,
            before_state.last_full_refresh_at
        );
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    #[tokio::test]
    async fn head_refusals_never_acquire_without_compatible_observation() {
        for (label, status, envelope) in [
            (
                "head-http-refusal",
                "400 Bad Request",
                json!({"error": "unsupported authority head"}),
            ),
            (
                "pre-59-authority",
                "200 OK",
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"code": -32000, "message": "engine schema predates act head"}
                }),
            ),
        ] {
            let authority = crate::db::create_database(":memory:").await.unwrap();
            let origin = crate::identity::database_id(&authority).await.unwrap();
            let (bytes, manifest) = snapshot_fixture(&authority).await;
            let directory = tempfile::tempdir().unwrap();
            let mut controller = controller_for_origin(
                &directory,
                origin,
                Arc::new(ScriptedClient::new(paged_replies(label, &bytes, &manifest))),
            );
            controller
                .refresh_once(RefreshCause::Startup)
                .await
                .unwrap();
            // Installation maintenance shares attempt.lock with the refresh below.
            controller.store.maintenance_idle().await;

            let (port, server) = serve_one_head_refusal(status, envelope).await;
            controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
            enable_deltas(&mut controller);
            let fallback = Arc::new(ScriptedClient::new(paged_replies(
                &format!("{label}-fallback"),
                &bytes,
                &manifest,
            )));
            controller.client = fallback.clone();
            assert!(controller.refresh_once(RefreshCause::Manual).await.is_err());
            server.await.unwrap();
            let state = controller.state().unwrap();
            assert_eq!(
                state.last_failure_class,
                Some(RefreshFailureClass::Protocol)
            );
            assert_eq!(state.last_delta_fallback_class, None);
            assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
            controller.store.maintenance_idle().await;
            authority.close().await;
        }

        let network =
            classify_delta_transport_error(Error::engine("hosted authority act request failed"));
        assert_eq!(network.class, RefreshFailureClass::Network);
    }

    #[tokio::test]
    async fn invalid_delta_falls_back_with_bounded_integrity_diagnostic() {
        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (base_bytes, base_manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "invalid-delta-base",
                &base_bytes,
                &base_manifest,
            ))),
        );
        controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap();
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
        crate::store::append(
            &authority,
            crate::store::AppendSpec {
                record_id: "1a7e4000-0000-4000-8000-00000000d202".into(),
                event_type: "record.created".into(),
                payload: json!({"type":"Document","kind":"note","name":"fallback"}),
                actor: None,
            },
        )
        .await
        .unwrap();
        let (fallback_bytes, fallback_manifest) = snapshot_fixture(&authority).await;
        controller.client = Arc::new(ScriptedClient::new(paged_replies(
            "invalid-delta-fallback",
            &fallback_bytes,
            &fallback_manifest,
        )));
        let (port, server) = serve_valid_head_then_invalid_delta(authority.clone()).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        enable_deltas(&mut controller);

        assert!(matches!(
            controller
                .refresh_once(RefreshCause::Scheduled)
                .await
                .unwrap(),
            StandbyRefreshOutcome::Installed { .. }
        ));
        server.await.unwrap();
        let state = controller.state().unwrap();
        assert_eq!(
            state.last_delta_fallback_class,
            Some(DeltaFallbackClass::IntegrityOrApplyRefusal)
        );
        assert!(state
            .last_delta_fallback
            .as_deref()
            .is_some_and(|message| message.len() <= 160 && !message.contains("secret")));
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    #[tokio::test]
    async fn oversize_delta_falls_back_and_failed_fallback_preserves_current() {
        const RECORD_ID: &str = "1a7e4000-0000-4000-8000-00000000d201";

        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (initial_bytes, initial_manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "fallback-base",
                &initial_bytes,
                &initial_manifest,
            ))),
        );
        let first = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap();
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
        let StandbyRefreshOutcome::Installed {
            generation: first, ..
        } = first
        else {
            panic!("initial snapshot refresh must install")
        };

        crate::store::append(
            &authority,
            crate::store::AppendSpec {
                record_id: RECORD_ID.into(),
                event_type: "record.created".into(),
                payload: json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "oversize fallback",
                    "body": "x".repeat(800_000),
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
        let (fallback_bytes, fallback_manifest) = snapshot_fixture(&authority).await;

        let failed_snapshot = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Network,
            calls: AtomicUsize::new(0),
        });
        controller.client = failed_snapshot.clone();
        enable_deltas(&mut controller);
        let (port, refused_delta) = serve_authority_act_calls(authority.clone(), 2).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        assert!(controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .is_err());
        refused_delta.await.unwrap();
        assert_eq!(failed_snapshot.calls.load(Ordering::SeqCst), 3);
        controller.store.maintenance_idle().await;
        let retained = controller.store.current_for_head_probe().unwrap().unwrap();
        assert_eq!(retained.id, first.id);

        let snapshot_fallback = Arc::new(ScriptedClient::new(paged_replies(
            "oversize-fallback",
            &fallback_bytes,
            &fallback_manifest,
        )));
        controller.client = snapshot_fallback.clone();
        let (port, refused_delta) = serve_authority_act_calls(authority.clone(), 2).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        let outcome = controller
            .refresh_once(RefreshCause::NetworkRecovery)
            .await
            .unwrap();
        refused_delta.await.unwrap();
        let StandbyRefreshOutcome::Installed { generation, .. } = outcome else {
            panic!("oversize exact cut must install through snapshot fallback")
        };
        assert_ne!(generation.id, first.id);
        assert_eq!(
            generation.manifest.materialization,
            StandbyGenerationMaterialization::Snapshot
        );
        assert!(snapshot_fallback.calls.load(Ordering::SeqCst) > 0);
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    #[test]
    fn delta_transport_failure_details_are_fixed_and_payload_free() {
        for (message, expected) in [
            (MAINTENANCE_SNAPSHOT_ERROR, "maintenance"),
            ("hosted authority act HTTP status 409 Conflict", "http_409"),
            (
                "hosted authority act HTTP status 418 secret-body",
                "http_4xx_other",
            ),
            (
                "hosted authority act HTTP status 503 Unavailable",
                "http_5xx",
            ),
            (
                "hosted authority act HTTP status invalid-secret",
                "unclassified",
            ),
            ("hosted authority act tool reported failure", "tool_failure"),
            (
                "hosted authority act tool call was refused (-32602)",
                "tool_failure",
            ),
            (
                "hosted authority act response too large",
                "response_too_large",
            ),
            (
                "hosted authority act returned an invalid protocol response: secret-body",
                "decode",
            ),
            (
                "unrecognized error with https://secret.invalid/token",
                "unclassified",
            ),
            (
                "hosted authority act request failed: request_timeout",
                "request_timeout",
            ),
            (
                "hosted authority act response was interrupted: connection_reset",
                "connection_reset",
            ),
            (
                "hosted authority act request failed: secret-body",
                "unclassified",
            ),
            (
                "hosted authority act delta export request failed: export_in_progress",
                "export_in_progress",
            ),
            (
                "hosted authority act delta export request failed: capture unavailable",
                "capture_unavailable",
            ),
            (
                "hosted authority act delta export request failed: capture timed out",
                "capture_timed_out",
            ),
            (
                "hosted authority act delta export HTTP status 503 (capacity_exhausted)",
                "http_5xx",
            ),
            ("payload mentions HTTP status 409", "unclassified"),
        ] {
            let error = classify_delta_transport_error(Error::engine(message));
            assert_eq!(error.detail, expected, "{message}");
            let mut progress = AttemptProgress::new(RefreshCause::Scheduled);
            progress.diagnose(&error);
            let diagnostic = progress.receipt.diagnostic();
            assert!(diagnostic.contains(&format!("detail={expected}")));
            assert!(!diagnostic.contains("secret"));
        }
        assert_eq!(
            delta_transport_failure_detail(&Error::auth("secret")),
            "unclassified"
        );
        // A busy export is scheduling, not an outage: it must never read as
        // a network failure (which would schedule network-recovery probes
        // into the same busy lease). A poll this node gave up on keeps the
        // network class — hosted may still be running that export.
        let busy = classify_delta_transport_error(Error::engine(
            super::super::delta_transport::DELTA_EXPORT_BUSY_MESSAGE,
        ));
        assert_eq!(busy.class, RefreshFailureClass::Throttled);
        assert_eq!(busy.detail, EXPORT_BUSY_DETAIL);
        assert_eq!(
            busy.safe_message,
            "hosted delta export is already in progress"
        );
        let timed_out = classify_delta_transport_error(Error::engine(
            super::super::delta_transport::DELTA_EXPORT_CAPTURE_TIMEOUT_MESSAGE,
        ));
        assert_eq!(timed_out.class, RefreshFailureClass::Network);
        assert_eq!(timed_out.detail, EXPORT_CAPTURE_TIMEOUT_DETAIL);
    }

    #[test]
    fn http_failure_details_use_a_fixed_vocabulary() {
        for (status, expected) in [
            (400, "http_400"),
            (401, "http_401"),
            (403, "http_403"),
            (404, "http_404"),
            (408, "http_408"),
            (409, "http_409"),
            (410, "http_410"),
            (412, "http_412"),
            (413, "http_413"),
            (416, "http_416"),
            (422, "http_422"),
            (425, "http_425"),
            (429, "http_429"),
            (418, "http_4xx_other"),
            (499, "http_4xx_other"),
            (500, "http_5xx"),
            (599, "http_5xx"),
            (302, "http_other"),
        ] {
            assert_eq!(http_failure_detail(status), expected);
        }
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
        assert_eq!(config.full_refresh_repair_retry_seconds, None);
        let configured = StandbyRefreshConfig::from_json(
            &serde_json::to_vec(&json!({
                "contract": CONFIG_CONTRACT,
                "version": 1,
                "hosted_origin": "https://plugin.withnative.ai",
                "credential_file": credential,
                "full_refresh_repair_retry_seconds": 120,
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(configured.full_refresh_repair_retry_seconds, Some(120));

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

    #[tokio::test]
    async fn a_burst_of_hints_leaves_one_durable_pending_cause() {
        let client = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Authentication,
            calls: AtomicUsize::new(0),
        });
        let (_directory, controller) = controller_with_client(client);
        let hints = RefreshHints::default();
        // A hosted-change burst: many hints before the controller drains any.
        for _ in 0..200 {
            hints.request(RefreshCause::AfterAdmittedWrite);
        }
        let _ = tokio::time::timeout(Duration::from_millis(300), hints.persist(&controller)).await;
        assert_eq!(
            controller.take_pending_triggers().unwrap(),
            vec![RefreshCause::AfterAdmittedWrite]
        );
        // Hints that arrive while that one acquisition runs become exactly one
        // follow-up, not a queue.
        for _ in 0..200 {
            hints.request(RefreshCause::AfterAdmittedWrite);
        }
        let _ = tokio::time::timeout(Duration::from_millis(300), hints.persist(&controller)).await;
        assert_eq!(controller.take_pending_triggers().unwrap().len(), 1);
    }

    /// Hosted answers chunked delta starts with 409 `export_in_progress`
    /// (plus `Retry-After: 1`) while it runs an export for this account.
    /// Serve the MCP head for real and refuse every start, counting them.
    async fn serve_busy_delta_starts(
        authority: crate::Db,
        starts: Arc<AtomicUsize>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (headers, body) = read_http_request(&mut stream).await;
                if headers.starts_with("POST /v1/databases/") {
                    starts.fetch_add(1, Ordering::SeqCst);
                    let body = serde_json::to_vec(&json!({
                        "api": super::super::delta_transport::AUTHORITY_ACT_DELTA_EXPORT_CONTRACT,
                        "error_code": "export_in_progress",
                    }))
                    .unwrap();
                    let head = format!(
                        "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\nRetry-After: 1\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(head.as_bytes()).await.unwrap();
                    stream.write_all(&body).await.unwrap();
                    stream.shutdown().await.unwrap();
                    continue;
                }
                let operation = body["params"]["arguments"]["operation"].as_str().unwrap();
                assert_eq!(
                    operation,
                    super::super::delta_transport::AUTHORITY_ACT_HEAD_OPERATION
                );
                let structured =
                    super::super::delta_transport::observe_authority_act_head_advertising(
                        &authority, "route-1", false,
                    )
                    .await
                    .map(|value| serde_json::to_value(value).unwrap())
                    .unwrap();
                write_json_response(
                    &mut stream,
                    "200 OK",
                    &json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "content": [],
                            "structuredContent": structured,
                            "isError": false,
                            "resultType": "complete",
                            "_meta": {}
                        }
                    }),
                )
                .await;
            }
        });
        (port, task)
    }

    /// Install a delta-eligible copy, move the hosted head past it, and point
    /// the controller at a hosted fixture. Returns the controller, the busy
    /// fixture's start counter, and a snapshot client that counts any whole
    /// snapshot fallback.
    async fn busy_delta_setup() -> (
        tempfile::TempDir,
        StandbyRefreshController,
        Arc<AtomicUsize>,
        Arc<AlwaysFailClient>,
        crate::Db,
    ) {
        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "busy-base",
                &bytes,
                &manifest,
            ))),
        );
        controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap();
        enable_deltas(&mut controller);
        controller.store.maintenance_idle().await;
        crate::store::append(
            &authority,
            crate::store::AppendSpec {
                record_id: "1a7e4000-0000-4000-8000-00000000d240".into(),
                event_type: "record.created".into(),
                payload: json!({"type":"Document","kind":"note","name":"busy head"}),
                actor: None,
            },
        )
        .await
        .unwrap();
        // A whole snapshot fallback would go through this client.
        let downloads = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });
        controller.client = downloads.clone();
        let starts = Arc::new(AtomicUsize::new(0));
        (directory, controller, starts, downloads, authority)
    }

    #[tokio::test]
    async fn busy_delta_failure_keeps_trigger_and_backs_off_without_network_class() {
        let (_directory, mut controller, starts, downloads, authority) = busy_delta_setup().await;
        let (port, server) = serve_busy_delta_starts(authority.clone(), starts.clone()).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        let before = tokio::time::Instant::now();
        let error = controller
            .refresh_once(RefreshCause::AfterAdmittedWrite)
            .await
            .unwrap_err();
        assert!(
            format!("{error}").contains("export_in_progress"),
            "{error:?}"
        );
        // One follow-up, not a snapshot, a probe, or a verdict of outage.
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert_eq!(
            downloads.calls.load(Ordering::SeqCst),
            0,
            "a busy export must never buy a whole snapshot"
        );
        let state = controller.state().unwrap();
        assert_eq!(
            state.last_failure_class,
            Some(RefreshFailureClass::Throttled),
            "busy must not read as a network failure: that schedules recovery probes"
        );
        assert_eq!(
            state.consecutive_failure_count, 0,
            "a busy export is scheduling and must not count as a failure"
        );
        assert_eq!(
            controller.take_pending_triggers().unwrap(),
            vec![RefreshCause::AfterAdmittedWrite]
        );
        // Hosted asked for one second via Retry-After: the hold is armed
        // for one second from the failure. Read the deadline itself: the
        // wall clock may pass the one-second hold before this assert runs
        // under parallel load.
        {
            let backoff = controller.busy_backoff.lock().unwrap();
            assert!(
                backoff
                    .until
                    .is_some_and(|until| until >= before + Duration::from_secs(1)),
                "Retry-After: 1 must arm a one-second hold"
            );
            assert_eq!(backoff.consecutive, 1);
        }
        server.abort();
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    #[tokio::test]
    async fn burst_hints_become_one_busy_attempt_plus_one_follow_up() {
        let (_directory, mut controller, starts, _downloads, authority) = busy_delta_setup().await;
        let (port, server) = serve_busy_delta_starts(authority.clone(), starts.clone()).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        // Hold the attempt lock so the whole burst coalesces before any
        // attempt can run: an SSE burst is one acquisition, never a queue.
        let lock = open_private_lock(&controller.refresh_dir.join("attempt.lock")).unwrap();
        fs2::FileExt::lock_exclusive(&lock).unwrap();
        for _ in 0..8 {
            let outcome = controller
                .refresh_or_request_with_receipt(RefreshCause::AfterAdmittedWrite)
                .await
                .unwrap();
            assert!(
                matches!(outcome, StandbyRefreshOutcome::Accepted { .. }),
                "{outcome:?}"
            );
        }
        assert_eq!(starts.load(Ordering::SeqCst), 0);
        assert_eq!(
            controller.take_pending_triggers().unwrap(),
            vec![RefreshCause::AfterAdmittedWrite]
        );
        drop(lock);
        // The one follow-up runs, hits the same busy lease, and re-arms.
        let error = controller
            .refresh_once(RefreshCause::AfterAdmittedWrite)
            .await
            .unwrap_err();
        assert!(
            format!("{error}").contains("export_in_progress"),
            "{error:?}"
        );
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert_eq!(
            controller.take_pending_triggers().unwrap(),
            vec![RefreshCause::AfterAdmittedWrite]
        );
        assert!(
            controller.busy_backoff.lock().unwrap().until.is_some(),
            "the follow-up failure must re-arm the busy hold"
        );
        server.abort();
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    #[tokio::test]
    async fn daemon_skips_attempts_while_the_busy_backoff_holds() {
        let client = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });
        let (_directory, controller) = controller_with_client(client.clone());
        controller
            .request_refresh(RefreshCause::AfterAdmittedWrite)
            .unwrap();
        // Pretend a busy failure just armed the hold; the busy-failure test
        // above covers the real path that sets it.
        controller.note_busy_export(Some(Duration::from_secs(30)));
        // Consecutive busy failures push the hold further out, toward the cap.
        let first = controller
            .busy_backoff
            .lock()
            .unwrap()
            .until
            .expect("busy hold must be armed");
        controller.note_busy_export(Some(Duration::from_secs(30)));
        let second = controller
            .busy_backoff
            .lock()
            .unwrap()
            .until
            .expect("busy hold must still be armed");
        assert!(second > first);
        let guard = controller.try_acquire_daemon().unwrap().unwrap();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::time::timeout(
            Duration::from_millis(1200),
            controller.run_daemon_after_startup(guard, shutdown_rx),
        )
        .await
        .expect_err("the daemon must still be running");
        assert_eq!(
            client.calls.load(Ordering::SeqCst),
            0,
            "no attempt may start while the busy backoff holds"
        );
        assert_eq!(
            controller.take_pending_triggers().unwrap(),
            vec![RefreshCause::AfterAdmittedWrite],
            "the trigger stays durable for the retry"
        );
        // Once the hold lapses the daemon runs the pending trigger: the
        // first tick fires immediately, the next only after the 1 s poll.
        controller.clear_busy_export();
        let guard = controller.try_acquire_daemon().unwrap().unwrap();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::time::timeout(
            Duration::from_millis(900),
            controller.run_daemon_after_startup(guard, shutdown_rx),
        )
        .await
        .expect_err("the daemon must still be running");
        assert_eq!(
            client.calls.load(Ordering::SeqCst),
            1,
            "the pending trigger retries after the backoff"
        );
        controller.store.maintenance_idle().await;
    }

    #[test]
    fn follow_loop_stall_report_fires_only_when_idle_and_overdue() {
        let interval = Duration::from_secs(60);
        assert_eq!(
            stall_warn_after(interval),
            Duration::from_secs(300),
            "well over the cadence means a multiple of it"
        );
        // A future base keeps every offset below clear of underflow.
        let now = tokio::time::Instant::now() + Duration::from_secs(7200);
        // Healthy: an attempt just started and the deadline lies ahead.
        assert!(follow_loop_stall_report(now, Some(now), now + interval, interval).is_none());
        // Healthy: a long attempt completed 40 minutes after it started and
        // its completion re-anchored the deadline into the future.
        assert!(follow_loop_stall_report(
            now,
            Some(now - Duration::from_secs(2400)),
            now + interval,
            interval
        )
        .is_none());
        // Healthy: the deadline is overdue but an attempt just started — the
        // overdue probe is already running.
        assert!(
            follow_loop_stall_report(now, Some(now), now - Duration::from_secs(600), interval)
                .is_none()
        );
        // Stalled: no attempt for 35 minutes while the scheduled deadline
        // sits 17 minutes overdue — the incident's recovery-tick shape.
        let stall = follow_loop_stall_report(
            now,
            Some(now - Duration::from_secs(2100)),
            now - Duration::from_secs(1020),
            interval,
        )
        .expect("the recovery tick after a 35-minute stall must warn");
        assert_eq!(stall.idle, Duration::from_secs(2100));
        assert_eq!(stall.scheduled_overdue, Duration::from_secs(1020));
        // Never started: the first tick always runs Startup, so there is no
        // quiet history to judge yet.
        assert!(
            follow_loop_stall_report(now, None, now - Duration::from_secs(3600), interval)
                .is_none()
        );
    }

    #[test]
    fn busy_skip_log_rate_limits_repeated_skips() {
        let interval = Duration::from_secs(60);
        let now = tokio::time::Instant::now();
        assert!(
            busy_skip_log_due(now, None, interval),
            "the first skip of an episode always logs"
        );
        assert!(!busy_skip_log_due(now, Some(now), interval));
        assert!(!busy_skip_log_due(
            now + Duration::from_secs(59),
            Some(now),
            interval
        ));
        assert!(busy_skip_log_due(now + interval, Some(now), interval));
    }

    #[tokio::test]
    async fn busy_backoff_remaining_tracks_the_armed_hold() {
        // Freeze the clock: arming a 30 s hold must report exactly 30 s back.
        tokio::time::pause();
        let client = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });
        let (_directory, controller) = controller_with_client(client);
        assert_eq!(controller.busy_backoff_remaining(), None);
        controller.note_busy_export(Some(Duration::from_secs(30)));
        assert_eq!(
            controller.busy_backoff_remaining(),
            Some(Duration::from_secs(30))
        );
        controller.clear_busy_export();
        assert_eq!(controller.busy_backoff_remaining(), None);
    }

    /// Log capture for the follow-loop scheduler target, mirroring the
    /// verification capture in `generation_store::test_diagnostics`: scoped to
    /// the awaiting task with a second live dispatcher so parallel tests
    /// cannot cache the callsite as disabled.
    #[derive(Clone, Default)]
    struct FollowLogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for FollowLogCapture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl FollowLogCapture {
        fn subscriber(&self) -> tracing::Dispatch {
            use tracing_subscriber::prelude::*;
            let writer = self.clone();
            tracing::Dispatch::new(
                tracing_subscriber::registry().with(
                    tracing_subscriber::fmt::layer()
                        .without_time()
                        .with_ansi(false)
                        .with_writer(move || writer.clone())
                        .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
                            metadata.target() == FOLLOW_LOG_TARGET
                        })),
                ),
            )
        }

        fn output(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    #[tokio::test]
    async fn accepted_coalescing_is_logged() {
        use tracing::instrument::WithSubscriber as _;
        let _capture_guard = crate::standby::generation_store::test_diagnostics::LOG_CAPTURE_LOCK
            .lock()
            .await;
        let client = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });
        let (_directory, controller) = controller_with_client(client);
        // The test holds the daemon lock, so the one-shot scheduling
        // boundary must coalesce instead of acquiring.
        let _guard = controller
            .try_acquire_daemon()
            .unwrap()
            .expect("test holds the daemon lock");
        let logs = FollowLogCapture::default();
        let _keepalive = tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .with_writer(std::io::sink)
                .finish(),
        );
        let outcome = controller
            .refresh_or_request_with_receipt(RefreshCause::AfterAdmittedWrite)
            .with_subscriber(logs.subscriber())
            .await
            .unwrap();
        assert!(
            matches!(outcome, StandbyRefreshOutcome::Accepted { .. }),
            "{outcome:?}"
        );
        assert!(
            logs.output().contains("coalesced"),
            "the coalesced acquisition must leave a scheduler log line"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn follow_watchdog_warns_once_until_ticks_resume() {
        use tracing::instrument::WithSubscriber as _;
        let _capture_guard = crate::standby::generation_store::test_diagnostics::LOG_CAPTURE_LOCK
            .lock()
            .await;
        let heartbeat = std::sync::Arc::new(FollowHeartbeat::new());
        let interval = Duration::from_secs(2);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let logs = FollowLogCapture::default();
        let _keepalive = tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .with_writer(std::io::sink)
                .finish(),
        );
        // Drive the watchdog future directly. Advancing the clock fires its
        // probe timers, but a fired probe is only observed when this task
        // polls the future again — so each phase advances the clock, then
        // drives the future once with a yield race it cannot lose except by
        // exiting (which only shutdown may cause).
        let watchdog = run_follow_watchdog(&heartbeat, interval, shutdown_rx)
            .with_subscriber(logs.subscriber());
        tokio::pin!(watchdog);
        macro_rules! drive_once {
            () => {
                tokio::select! {
                    _ = &mut watchdog => {
                        panic!("the watchdog must not exit before shutdown")
                    }
                    _ = tokio::task::yield_now() => {}
                }
            };
        }
        // The loop has not ticked yet (slow startup): no quiet history to
        // judge, so no warning is owed no matter how far the clock runs.
        tokio::time::advance(Duration::from_secs(30)).await;
        drive_once!();
        assert!(
            !heartbeat.warned.load(std::sync::atomic::Ordering::SeqCst)
                && !logs.output().contains("parked between attempts")
                && !logs.output().contains("attempt running for"),
            "the watchdog must stay silent before the loop's first tick"
        );
        // The loop ticks once and then parks between attempts: the probe
        // sees a 30 s idle heartbeat and warns once (threshold is 5 x 2 s).
        heartbeat.note_tick();
        tokio::time::advance(Duration::from_secs(30)).await;
        drive_once!();
        assert!(
            heartbeat.warned.load(std::sync::atomic::Ordering::SeqCst),
            "the watchdog must observe the 30 s idle heartbeat"
        );
        assert_eq!(
            logs.output().matches("parked between attempts").count(),
            1,
            "a parked scheduler must warn while the stall is happening"
        );
        // Still parked: the latch holds, so no second line.
        tokio::time::advance(Duration::from_secs(20)).await;
        drive_once!();
        assert_eq!(
            logs.output().matches("parked between attempts").count(),
            1,
            "the watchdog must not repeat itself while nothing recovers"
        );
        // A tick resumes the loop: the next probe re-arms the latch without
        // a new warning.
        heartbeat.note_tick();
        tokio::time::advance(Duration::from_secs(2)).await;
        drive_once!();
        assert_eq!(
            logs.output().matches("parked between attempts").count(),
            1,
            "a fresh tick must re-arm the watchdog without a new warning"
        );
        // An attempt starts and then holds the loop: ticks stop while it
        // runs, so the next warning names the running attempt instead.
        heartbeat.note_attempt_start();
        tokio::time::advance(Duration::from_secs(20)).await;
        drive_once!();
        assert_eq!(
            logs.output().matches("attempt running for").count(),
            1,
            "a stalled attempt must warn while it is still running"
        );
        heartbeat.note_attempt_end();
        drop(shutdown_tx);
        watchdog.await;
    }

    fn lifecycle_harness() -> (
        tempfile::TempDir,
        StandbyRuntimeConfig,
        ObservedInstalledConsumerIdentity,
        std::path::PathBuf,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let replica_root = directory.path().join("replica");
        let credential = directory.path().join("credential");
        std::fs::write(&credential, b"secret\n").unwrap();
        set_mode(&credential, 0o600).unwrap();
        let runtime = StandbyRuntimeConfig {
            replica_root: replica_root.clone(),
            hosted_route_database_id: "route-1".into(),
            origin_database_id: "ndb_0123456789abcdef0123456789abcdef".into(),
        };
        let observed = ObservedInstalledConsumerIdentity {
            kernel_v2_reader: Default::default(),
            platform: crate::standby_snapshot::StandbyConsumerPlatform::LinuxX8664,
            source_sha: "1".repeat(40),
            artifact_sha256: "2".repeat(64),
            engine_schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
            ddl_sha256: crate::schema::FROZEN_DDL_SHA256.into(),
        };
        let config_path = directory.path().join("refresh.json");
        std::fs::write(
            &config_path,
            serde_json::json!({
                "contract": CONFIG_CONTRACT,
                "version": 1,
                "hosted_origin": "http://localhost",
                "credential_file": credential,
                "refresh_interval_seconds": 2,
                "full_refresh_min_interval_seconds": 0,
                "full_refresh_repair_retry_seconds": 60,
                "kernel_in_place_deltas": false,
                "kernel_audit_interval_seconds": null,
                "projection_proof_interval_seconds": null,
            })
            .to_string(),
        )
        .unwrap();
        (directory, runtime, observed, config_path)
    }

    #[tokio::test]
    async fn background_refresh_stop_joins_worker_and_watchdog() {
        let (_directory, runtime, observed, config_path) = lifecycle_harness();
        let store = GenerationStore::open(
            &runtime.replica_root,
            &runtime.hosted_route_database_id,
            Some(runtime.origin_database_id.clone()),
        )
        .unwrap();
        // Startup already failed elsewhere: the worker exits at once, and
        // stop must still join both threads instead of hanging.
        let (startup_tx, startup_rx) = tokio::sync::oneshot::channel();
        drop(startup_tx);
        let refresh = start_background_refresh_inner(
            &runtime,
            &observed,
            &config_path,
            Some(startup_rx),
            store,
            None,
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(30), refresh.stop())
            .await
            .expect("stop must join the worker and watchdog threads");
    }

    #[tokio::test]
    async fn background_refresh_without_daemon_guard_spawns_no_watchdog() {
        let (_directory, runtime, observed, config_path) = lifecycle_harness();
        // Hold the daemon lock before startup: this process loses the
        // acquisition, runs no follow loop, and must spawn no watchdog.
        // Owner-only modes are set explicitly: create_dir_all would inherit
        // the process umask (0755 under CI's 022), which the store refuses.
        create_private_directory(&runtime.replica_root).unwrap();
        create_private_directory(&runtime.replica_root.join("refresh")).unwrap();
        let held = open_private_lock(&runtime.replica_root.join("refresh").join("controller.lock"))
            .unwrap();
        fs2::FileExt::lock_exclusive(&held).unwrap();
        let store = GenerationStore::open(
            &runtime.replica_root,
            &runtime.hosted_route_database_id,
            Some(runtime.origin_database_id.clone()),
        )
        .unwrap();
        let (startup_tx, startup_rx) = tokio::sync::oneshot::channel();
        drop(startup_tx);
        let refresh = start_background_refresh_inner(
            &runtime,
            &observed,
            &config_path,
            Some(startup_rx),
            store,
            None,
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(30), refresh.stop())
            .await
            .expect("stop must return without a watchdog thread");
        drop(held);
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
            next_scheduled_deadline(
                badly_overdue,
                now,
                now,
                RefreshCause::Scheduled,
                SCHEDULE_INTERVAL
            ),
            now + SCHEDULE_INTERVAL
        );
        let on_time = now + Duration::from_secs(1);
        let long_completion = on_time + SCHEDULE_INTERVAL + Duration::from_secs(1);
        assert_eq!(
            next_scheduled_deadline(
                on_time,
                on_time,
                long_completion,
                RefreshCause::Scheduled,
                SCHEDULE_INTERVAL
            ),
            long_completion + SCHEDULE_INTERVAL
        );
        let due_during_manual = now + Duration::from_secs(5);
        let completed = now + Duration::from_secs(10);
        assert_eq!(
            next_scheduled_deadline(
                due_during_manual,
                now,
                completed,
                RefreshCause::Manual,
                SCHEDULE_INTERVAL
            ),
            completed + SCHEDULE_INTERVAL
        );
        let future = now + SCHEDULE_INTERVAL;
        assert_eq!(
            next_scheduled_deadline(future, now, now, RefreshCause::Wake, SCHEDULE_INTERVAL),
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
            refresh_interval_seconds: None,
            full_refresh_min_interval_seconds: None,
            full_refresh_repair_retry_seconds: None,
            kernel_in_place_deltas: false,
            kernel_audit_interval_seconds: None,
            projection_proof_interval_seconds: None,
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
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
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
        interrupted.transfer_progress = Some(StandbyTransferProgress {
            stage: StandbyTransferStage::Publication,
            activity: StandbyTransferActivity::Active,
            updated_at: now(),
            bytes_completed: Some(first_manifest.snapshot.size_bytes),
            bytes_remaining: Some(0),
            bytes_total: Some(first_manifest.snapshot.size_bytes),
            retained_for_resume: false,
        });
        // Both a process crash and cancellation that already cleared activity
        // must reconcile a pointer published before final bookkeeping.
        for active in [true, false] {
            interrupted.refresh_active = active;
            interrupted.transfer_progress.as_mut().unwrap().activity = if active {
                StandbyTransferActivity::Active
            } else {
                StandbyTransferActivity::Interrupted
            };
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
        }

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
        controller.store.maintenance_idle().await;
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
                assert!(lower.contains(&format!(
                    "{}: {}\r\n",
                    super::super::shapes::ACCEPTED_SHAPES_HEADER,
                    super::super::shapes::advertisement()
                )));
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
            selected_shape: None,
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
    #[cfg(feature = "mcp-executor-prototype")]
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

    #[test]
    fn throttle_failure_is_not_local_io_and_serializes_distinctly() {
        assert_ne!(RefreshFailureClass::Throttled, RefreshFailureClass::LocalIo);
        let encoded = serde_json::to_value(RefreshFailureClass::Throttled).unwrap();
        assert_eq!(encoded, serde_json::json!("throttled"));
    }

    #[test]
    fn retained_detail_sanitizes_legacy_raw_text_and_attributes_by_attempt() {
        assert_eq!(sanitize_retained_detail(None), "unclassified");
        assert_eq!(
            sanitize_retained_detail(Some("install-fence:successor")),
            "install-fence:successor"
        );
        // Legacy raw source text from pre-hardening state files is dropped.
        assert_eq!(
            sanitize_retained_detail(Some(
                "standby snapshot conformance failed: row 0: live={\"body\":\"x\"}"
            )),
            "unclassified"
        );
        // Attribution follows the writing attempt, not the class.
        let mut state = StandbyRefreshState::default();
        state.last_attempt_id = Some("attempt-one".into());
        state.last_full_failure_attempt_id = state.last_attempt_id.clone();
        state.last_attempt_at = Some("2026-10-13T00:00:01.000Z".into());
        state.last_full_failure_at = Some("2026-10-13T00:00:02.000Z".into());
        state.last_full_failure_detail = Some("install-fence:verify".into());
        assert_eq!(current_attempt_detail(&state), "install-fence:verify");
        // A later attempt that did not touch the slot loses attribution,
        // even with the same failure class, and legacy text stays buried.
        state.last_attempt_id = Some("attempt-two".into());
        state.last_attempt_at = Some("2026-10-13T00:00:03.000Z".into());
        assert_eq!(current_attempt_detail(&state), "unclassified");
        state.last_full_failure_detail = Some("standby snapshot conformance failed: row 0".into());
        state.last_full_failure_at = Some("2026-10-13T00:00:04.000Z".into());
        assert_eq!(current_attempt_detail(&state), "unclassified");
    }

    #[test]
    fn full_failure_slot_validates_and_bounds_detail() {
        let mut state = StandbyRefreshState {
            last_full_failure_at: Some(now()),
            last_full_failure_class: Some(RefreshFailureClass::Verification),
            last_full_failure: Some("downloaded snapshot was not admitted".into()),
            last_full_failure_detail: Some("install-fence:verify".into()),
            ..Default::default()
        };
        assert!(valid_status_state(&state));
        state.last_full_failure_detail = Some("x".repeat(1001));
        assert!(!valid_status_state(&state));
    }

    /// A delta-only failure must not overwrite the retained FULL failure:
    /// install a base, fail a whole snapshot, then fail a delta probe, and
    /// show the FULL slot still names the original whole-snapshot failure.
    #[tokio::test]
    async fn delta_failure_preserves_retained_full_failure() {
        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "export-base",
                &bytes,
                &manifest,
            ))),
        );
        let StandbyRefreshOutcome::Installed { .. } = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap()
        else {
            panic!("startup refresh must install its snapshot")
        };
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
        // Deltas stay disabled so the tampered snapshot fails in the FULL
        // phase; the retained slot records it.
        let mut bad = bytes.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        controller.client = Arc::new(ScriptedClient::new(paged_replies(
            "export-bad",
            &bad,
            &manifest,
        )));
        controller
            .refresh_once(RefreshCause::Manual)
            .await
            .unwrap_err();
        let full_class = controller.state().unwrap().last_full_failure_class;
        let full_detail = controller.state().unwrap().last_full_failure_detail;
        assert!(full_class.is_some(), "FULL failure must be retained");
        assert_eq!(controller.state().unwrap().last_failure_class, full_class,);
        // A delta head probe refused with 401 fails before any FULL work;
        // the retained FULL slot must be untouched.
        enable_deltas(&mut controller);
        let (port, server) =
            serve_one_head_refusal("401 Unauthorized", json!({"error": "denied"})).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap_err();
        server.await.unwrap();
        let state = controller.state().unwrap();
        assert_eq!(
            state.last_failure_class,
            Some(RefreshFailureClass::Authentication),
        );
        assert_eq!(state.last_full_failure_class, full_class);
        assert_eq!(state.last_full_failure_detail, full_detail);
        assert_eq!(state.consecutive_failure_count, 2);
        // A successful delta clears the latest failure but retains the
        // FULL slot — and must need no snapshot pages to do it.
        const RECORD_ID: &str = "1a7e4000-0000-4000-8000-00000000d250";
        crate::store::append(
            &authority,
            crate::store::AppendSpec {
                record_id: RECORD_ID.into(),
                event_type: "record.created".into(),
                payload: json!({"type":"Document","kind":"note","name":"after the failures"}),
                actor: None,
            },
        )
        .await
        .unwrap();
        let (port, server) = serve_authority_act_calls(authority.clone(), 2).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        let snapshot_fallback = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        });
        controller.client = snapshot_fallback.clone();
        let StandbyRefreshOutcome::Advanced { .. } = controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap()
        else {
            panic!("an advanced authority must delta in place")
        };
        server.await.unwrap();
        assert_eq!(snapshot_fallback.calls.load(Ordering::SeqCst), 0);
        let state = controller.state().unwrap();
        assert_eq!(state.last_failure_class, None);
        assert_eq!(state.consecutive_failure_count, 0);
        assert_eq!(state.last_full_failure_class, full_class);
        assert_eq!(state.last_full_failure_detail, full_detail);
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    /// A hosted interchange-revision bump pauses following before any
    /// snapshot acquisition, on scheduled and manual causes alike: the
    /// attempt defers with `revision_unsupported`, counts no failure, and
    /// fetches zero snapshot pages.
    #[tokio::test]
    async fn revision_pause_precedes_full_acquisition_on_any_cause() {
        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let base_pages = paged_replies("export-base", &bytes, &manifest);
        let base_count = base_pages.len();
        let client = Arc::new(ScriptedClient::new(base_pages));
        let mut controller = controller_for_origin(&directory, origin, client.clone());
        let StandbyRefreshOutcome::Installed { .. } = controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap()
        else {
            panic!("startup refresh must install its snapshot")
        };
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
        enable_deltas(&mut controller);
        let (port, server) = serve_bumped_head(authority.clone(), 2).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        for cause in [RefreshCause::Scheduled, RefreshCause::Manual] {
            let StandbyRefreshOutcome::Deferred { reason, .. } =
                controller.refresh_once(cause).await.unwrap()
            else {
                panic!("a revision bump must pause, not acquire: {cause:?}")
            };
            assert_eq!(reason, "revision_unsupported");
        }
        server.await.unwrap();
        let state = controller.state().unwrap();
        assert_eq!(state.last_deferral.as_deref(), Some("revision_unsupported"));
        assert_eq!(state.consecutive_failure_count, 0);
        assert_eq!(state.last_failure_class, None);
        assert_eq!(
            client.calls.load(Ordering::SeqCst),
            base_count,
            "paused attempts must fetch no snapshot pages"
        );
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    /// A v1 head may be perfectly current while missing issuance anchors.
    /// Consumer rebind and the equal-head fast path must not bless that base.
    #[tokio::test]
    async fn v1_delta_head_forces_full_before_equal_head_fast_path() {
        for (version, advanced, needs_full) in
            [(1, true, true), (1, false, false), (2, true, false)]
        {
            let authority = crate::db::create_database(":memory:").await.unwrap();
            let origin = crate::identity::database_id(&authority).await.unwrap();
            let (bytes, manifest) = snapshot_fixture(&authority).await;
            let directory = tempfile::tempdir().unwrap();
            let client = Arc::new(ScriptedClient::new(paged_replies(
                "base", &bytes, &manifest,
            )));
            let mut controller = controller_for_origin(&directory, origin, client);
            let StandbyRefreshOutcome::Installed { generation, .. } = controller
                .refresh_once(RefreshCause::Startup)
                .await
                .unwrap()
            else {
                panic!("install")
            };
            // Installation maintenance shares attempt.lock with the refresh below.
            controller.store.maintenance_idle().await;
            controller
                .store
                .record_synced(&generation, manifest.head_act.unwrap(), &now())
                .unwrap();
            if advanced {
                controller
                    .store
                    .open_head_writer(&generation)
                    .await
                    .unwrap()
                    .unwrap()
                    .close()
                    .await;
            }
            let path = directory
                .path()
                .join("replica/accepted/heads")
                .join(format!("{}.json", generation.id));
            let mut head: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            head["version"] = json!(version);
            fs::write(&path, serde_json::to_vec(&head).unwrap()).unwrap();
            if needs_full {
                assert!(
                    controller
                        .store
                        .open_head_writer(&generation)
                        .await
                        .is_err(),
                    "v1 base cannot be silently upgraded by opening a writer"
                );
            }
            let (port, server) = serve_authority_act_calls(authority.clone(), 1).await;
            controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
            let result = controller
                .try_delta_attempt("secret", *generation)
                .await
                .unwrap();
            server.await.unwrap();
            match result {
                DeltaAttempt::FallBackToSnapshot(diagnostic) if needs_full => {
                    assert_eq!(diagnostic.class, DeltaFallbackClass::UntrustedLocalBase);
                    assert!(diagnostic.message.contains("authority/link recovery"));
                }
                DeltaAttempt::Unchanged(_) if !needs_full => {}
                _ => panic!("unexpected v{version} advanced={advanced} recovery result"),
            }
            controller.store.maintenance_idle().await;
            authority.close().await;
        }
    }

    #[tokio::test]
    async fn revision_pause_precedes_local_early_fallbacks_and_delta_only() {
        for fault in ["consumer", "audit", "head", "local-act"] {
            let authority = crate::db::create_database(":memory:").await.unwrap();
            let origin = crate::identity::database_id(&authority).await.unwrap();
            let (bytes, manifest) = snapshot_fixture(&authority).await;
            let directory = tempfile::tempdir().unwrap();
            let pages = paged_replies("export-base", &bytes, &manifest);
            let count = pages.len();
            let client = Arc::new(ScriptedClient::new(pages));
            let mut controller = controller_for_origin(&directory, origin, client.clone());
            let StandbyRefreshOutcome::Installed { generation, .. } = controller
                .refresh_once(RefreshCause::Startup)
                .await
                .unwrap()
            else {
                panic!("install")
            };
            // Installation maintenance shares attempt.lock with the refresh below.
            controller.store.maintenance_idle().await;
            enable_deltas(&mut controller);
            let head_path = directory
                .path()
                .join("replica/accepted/heads")
                .join(format!("{}.json", generation.id));
            match fault {
                "consumer" => controller.observed.source_sha = "a".repeat(40),
                "audit" => {
                    controller
                        .store
                        .record_synced(&generation, 1, &now())
                        .unwrap();
                    let mut head: Value =
                        serde_json::from_slice(&fs::read(&head_path).unwrap()).unwrap();
                    head["full_refresh_required"] = json!(true);
                    fs::write(&head_path, serde_json::to_vec(&head).unwrap()).unwrap();
                }
                "head" => {
                    fs::write(&head_path, b"invalid head").unwrap();
                }
                "local-act" => {
                    set_mode(&generation.snapshot_path, 0o600).unwrap();
                    fs::write(&generation.snapshot_path, b"not sqlite").unwrap();
                    set_mode(&generation.snapshot_path, 0o400).unwrap();
                }
                _ => unreachable!(),
            }
            let (port, server) = serve_bumped_head(authority.clone(), 3).await;
            controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
            for cause in [RefreshCause::Scheduled, RefreshCause::Manual] {
                match controller.refresh_once_with_receipt(cause).await {
                    Ok(StandbyRefreshOutcome::Deferred {
                        reason: DEFERRED_REVISION_UNSUPPORTED,
                        ..
                    }) => {}
                    Err(failure) if fault == "head" => {
                        assert_eq!(
                            failure.receipt.class,
                            RefreshFailureClass::RevisionUnsupported
                        );
                        assert_eq!(failure.receipt.phase, RefreshAttemptPhase::Following);
                    }
                    outcome => panic!("{fault}: must pause, got {outcome:?}"),
                }
                // Faulted local inputs can request verification recovery.
                controller.store.maintenance_idle().await;
            }
            assert!(
                matches!(
                    controller.refresh_delta_only().await.unwrap(),
                    StandbyDeltaOutcome::Deferred {
                        reason: DEFERRED_REVISION_UNSUPPORTED
                    }
                ),
                "{fault}"
            );
            server.await.unwrap();
            assert_eq!(
                client.calls.load(Ordering::SeqCst),
                count,
                "{fault}: zero acquisition"
            );
            assert_eq!(controller.state().unwrap().last_full_failure_class, None);
            controller.store.maintenance_idle().await;
            authority.close().await;
        }
    }

    /// Without a local base there is nothing to defer: the pause fails
    /// fast with its distinct class, still acquiring nothing and writing
    /// no FULL slot.
    #[tokio::test]
    async fn revision_pause_without_base_fails_distinctly_without_acquiring() {
        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let client = Arc::new(ScriptedClient::new(vec![]));
        let mut controller = controller_for_origin(&directory, origin, client.clone());
        let (port, server) = serve_bumped_head(authority.clone(), 1).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        let error = controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap_err();
        server.await.unwrap();
        assert!(
            error.to_string().contains("interchange revision"),
            "{error}"
        );
        let state = controller.state().unwrap();
        assert_eq!(
            state.last_failure_class,
            Some(RefreshFailureClass::RevisionUnsupported)
        );
        assert_eq!(state.last_full_failure_class, None);
        assert_eq!(client.calls.load(Ordering::SeqCst), 0);
        authority.close().await;
    }

    #[tokio::test]
    async fn attempt_receipts_do_not_attribute_previous_full_failure_to_lock_errors() {
        let directory = tempfile::tempdir().unwrap();
        let client = Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Verification,
            calls: AtomicUsize::new(0),
        });
        let controller = controller_for_origin(
            &directory,
            "ndb_00000000000000000000000000000000".into(),
            client,
        );
        let first = controller
            .refresh_once_with_receipt(RefreshCause::Manual)
            .await
            .unwrap_err();
        assert_eq!(first.receipt.phase, RefreshAttemptPhase::Full);
        let old = controller.state().unwrap();
        assert_eq!(
            old.last_attempt_id.as_deref(),
            Some(first.receipt.attempt_id.to_string().as_str())
        );
        fs::remove_file(controller.refresh_dir.join("attempt.lock")).unwrap();
        fs::create_dir(controller.refresh_dir.join("attempt.lock")).unwrap();
        let next = controller
            .refresh_once_with_receipt(RefreshCause::Scheduled)
            .await
            .unwrap_err();
        assert_ne!(next.receipt.attempt_id, first.receipt.attempt_id);
        assert_eq!(next.receipt.cause, RefreshCause::Scheduled);
        assert_eq!(next.receipt.phase, RefreshAttemptPhase::Preparation);
        assert_eq!(next.receipt.class, RefreshFailureClass::LocalIo);
        assert_eq!(next.receipt.check, UNCLASSIFIED_CHECK);
        assert_eq!(
            controller.state().unwrap().last_attempt_id,
            old.last_attempt_id
        );
    }

    // Run the real stderr boundaries in an isolated test process. This captures
    // eprintln output without process-global fd changes racing other tests.
    #[test]
    fn stderr_redacts_pending_and_legacy_state_on_failed_attempts() {
        const CHILD: &str = "NATIVE_TEST_REFRESH_STDERR_CHILD";
        const SENTINEL: &str = "private-body-credential-SENTINEL-🔐";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "standby::refresh::tests::stderr_redacts_pending_and_legacy_state_on_failed_attempts", "--nocapture"])
                .env(CHILD, "1").output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(stderr.contains("class=Verification"), "{stderr}");
            assert!(
                stderr.contains("refresh state persistence failed"),
                "{stderr}"
            );
            assert!(stderr.contains("phase=Preparation"), "{stderr}");
            assert!(!stderr.contains(SENTINEL), "{stderr}");
            assert!(stderr.len() < 4000, "{stderr}");
            return;
        }
        struct PendingFailureClient {
            pending: PathBuf,
        }
        impl SnapshotPageClient for PendingFailureClient {
            fn page(&self, _: String, _: String, _: SnapshotPageRequest) -> PageFuture {
                let pending = self.pending.clone();
                Box::pin(async move {
                    fs::write(
                        pending,
                        serde_json::to_vec(&json!({"causes":[SENTINEL]})).unwrap(),
                    )
                    .unwrap();
                    Err(AttemptError::new(
                        RefreshFailureClass::Verification,
                        "downloaded snapshot was not admitted",
                        Error::engine(SENTINEL),
                    ))
                })
            }
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let directory = tempfile::tempdir().unwrap();
                let mut controller = controller_for_origin(
                    &directory,
                    "ndb_00000000000000000000000000000000".into(),
                    Arc::new(AlwaysFailClient {
                        class: RefreshFailureClass::Verification,
                        calls: AtomicUsize::new(0),
                    }),
                );
                controller.client = Arc::new(PendingFailureClient {
                    pending: controller.refresh_dir.join("pending.json"),
                });
                let failure = controller
                    .refresh_once_with_receipt(RefreshCause::Manual)
                    .await
                    .unwrap_err();
                assert_eq!(failure.receipt.class, RefreshFailureClass::Verification);
                assert_eq!(failure.receipt.phase, RefreshAttemptPhase::Full);
                // The final write failed, but the invocation retains its primary diagnosis.
                assert!(controller
                    .state()
                    .unwrap_err()
                    .to_string()
                    .contains(SENTINEL));
                fs::remove_file(controller.refresh_dir.join("pending.json")).unwrap();
                let mut state = controller.state().unwrap();
                state.last_failure = Some(SENTINEL.into());
                state.last_full_failure_detail = Some(SENTINEL.into());
                controller.write_state(&state).unwrap();
                fs::remove_file(controller.refresh_dir.join("attempt.lock")).unwrap();
                fs::create_dir(controller.refresh_dir.join("attempt.lock")).unwrap();
                let early = controller
                    .refresh_once_with_receipt(RefreshCause::Scheduled)
                    .await
                    .unwrap_err();
                assert_eq!(early.receipt.phase, RefreshAttemptPhase::Preparation);
            });
    }

    #[tokio::test]
    async fn timeouts_use_invocation_phase_under_clock_skew_and_unreadable_state() {
        async fn timeout_after_entering(
            controller: &StandbyRefreshController,
            cause: RefreshCause,
            entered: Arc<std::sync::atomic::AtomicBool>,
        ) -> RefreshAttemptFailure {
            tokio::time::pause();
            let future =
                controller.refresh_once_receipt_with_timeout(cause, Duration::from_millis(100));
            tokio::pin!(future);
            // Keep a runnable driver while real socket I/O reaches the seam,
            // preventing Tokio's paused clock from automatically jumping ahead.
            let reached = async {
                let watchdog = std::time::Instant::now();
                while !entered.load(Ordering::SeqCst) {
                    assert!(
                        watchdog.elapsed() < Duration::from_secs(5),
                        "fixture did not enter its phase"
                    );
                    tokio::task::yield_now().await;
                }
            };
            tokio::select! {
                _ = reached => {},
                result = &mut future => panic!("attempt ended before entering the controlled phase: {result:?}"),
            }
            tokio::time::advance(Duration::from_millis(101)).await;
            let failure = future.await.unwrap_err();
            if let Ok(state) = controller.state() {
                assert!(!state.refresh_active);
                assert_ne!(
                    state.transfer_progress.unwrap().activity,
                    StandbyTransferActivity::Active
                );
            }
            tokio::time::resume();
            failure
        }
        struct HangingFull {
            state_path: PathBuf,
            unreadable: bool,
            entered: Arc<std::sync::atomic::AtomicBool>,
        }
        impl SnapshotPageClient for HangingFull {
            fn page(&self, _: String, _: String, _: SnapshotPageRequest) -> PageFuture {
                let path = self.state_path.clone();
                let unreadable = self.unreadable;
                let entered = self.entered.clone();
                Box::pin(async move {
                    if unreadable {
                        fs::remove_file(&path).unwrap();
                        fs::create_dir(path).unwrap();
                    } else {
                        let mut state: StandbyRefreshState =
                            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                        // Simulate a backward wall clock during the FULL phase.
                        state.last_full_refresh_at = Some("2000-01-01T00:00:00.000Z".into());
                        fs::write(path, serde_json::to_vec(&state).unwrap()).unwrap();
                    }
                    entered.store(true, Ordering::SeqCst);
                    std::future::pending().await
                })
            }
        }
        for unreadable in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let mut controller = controller_for_origin(
                &directory,
                "ndb_00000000000000000000000000000000".into(),
                Arc::new(AlwaysFailClient {
                    class: RefreshFailureClass::Verification,
                    calls: AtomicUsize::new(0),
                }),
            );
            let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
            controller.client = Arc::new(HangingFull {
                state_path: controller.state_path(),
                unreadable,
                entered: entered.clone(),
            });
            let failure = timeout_after_entering(&controller, RefreshCause::Manual, entered).await;
            assert_eq!(failure.receipt.class, RefreshFailureClass::Timeout);
            assert_eq!(failure.receipt.phase, RefreshAttemptPhase::Full);
            if !unreadable {
                let state = controller.state().unwrap();
                assert_eq!(
                    state.last_full_failure_class,
                    Some(RefreshFailureClass::Timeout)
                );
                assert_eq!(
                    state.last_full_failure_attempt_id,
                    Some(failure.receipt.attempt_id.to_string())
                );
            }
        }
        // A previous FULL timestamp in the future must not make a timed-out
        // following probe overwrite its retained FULL failure.
        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "base", &bytes, &manifest,
            ))),
        );
        controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap();
        // Installation maintenance shares attempt.lock with the refresh below.
        controller.store.maintenance_idle().await;
        let mut state = controller.state().unwrap();
        state.last_full_refresh_at = Some("2099-01-01T00:00:00.000Z".into());
        state.last_full_failure_at = state.last_full_refresh_at.clone();
        state.last_full_failure_attempt_id = Some(uuid::Uuid::new_v4().to_string());
        state.last_full_failure_class = Some(RefreshFailureClass::Verification);
        state.last_full_failure = Some("downloaded snapshot was not admitted".into());
        state.last_full_failure_detail = Some(INSTALL_VERIFY_CHECK.into());
        controller.write_state(&state).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        controller.config.hosted_origin = format!("http://{}", listener.local_addr().unwrap());
        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server_entered = entered.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/mcp/{route}",
                    post(move || {
                        let entered = server_entered.clone();
                        async move {
                            entered.store(true, Ordering::SeqCst);
                            std::future::pending::<Json<Value>>().await
                        }
                    }),
                ),
            )
            .await
            .unwrap();
        });
        enable_deltas(&mut controller);
        let failure = timeout_after_entering(&controller, RefreshCause::Scheduled, entered).await;
        assert_eq!(failure.receipt.phase, RefreshAttemptPhase::Following);
        assert_eq!(failure.receipt.class, RefreshFailureClass::Timeout);
        let after = controller.state().unwrap();
        assert_eq!(
            after.last_full_failure_attempt_id,
            state.last_full_failure_attempt_id
        );
        assert_eq!(after.last_full_failure_at, state.last_full_failure_at);
        assert_eq!(after.last_full_failure_class, state.last_full_failure_class);
        server.abort();
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    #[tokio::test]
    async fn hung_hosted_connection_times_out_and_daemon_resumes_without_restart() {
        let authority = crate::db::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&authority).await.unwrap();
        let (bytes, manifest) = snapshot_fixture(&authority).await;
        let directory = tempfile::tempdir().unwrap();
        let mut controller = controller_for_origin(
            &directory,
            origin,
            Arc::new(ScriptedClient::new(paged_replies(
                "base", &bytes, &manifest,
            ))),
        );
        controller
            .refresh_once(RefreshCause::Startup)
            .await
            .unwrap();
        controller.store.maintenance_idle().await;
        enable_deltas(&mut controller);
        controller.config.refresh_interval_seconds = Some(1);
        controller.attempt_timeout = Some(Duration::from_millis(500));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        controller.config.hosted_origin = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let server_calls = calls.clone();
        let db = authority.clone();
        let release = Arc::new(tokio::sync::Notify::new());
        let server_release = release.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/mcp/{route}",
                    post(move || {
                        let calls = server_calls.clone();
                        let db = db.clone();
                        let release = server_release.clone();
                        async move {
                            // Hosted accepts the request but sends no headers or bytes.
                            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                                release.notified().await;
                            }
                            let head = super::super::delta_transport::observe_authority_act_head(
                                &db, "route-1",
                            )
                            .await
                            .unwrap();
                            Json(json!({"jsonrpc":"2.0","id":1,"result":{
                        "structuredContent":head,"content":[],"isError":false}}))
                        }
                    }),
                ),
            )
            .await
            .unwrap();
        });
        let controller = Arc::new(controller);
        let guard = controller.try_acquire_daemon().unwrap().unwrap();
        let (shutdown, receiver) = watch::channel(false);
        let daemon = tokio::spawn({
            let controller = controller.clone();
            async move { controller.run_daemon_after_startup(guard, receiver).await }
        });
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let state = controller.state().unwrap();
                if state.last_failure_class == Some(RefreshFailureClass::Timeout) {
                    assert!(!state.refresh_active);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            loop {
                let state = controller.state().unwrap();
                if calls.load(Ordering::SeqCst) >= 2
                    && state.last_failure_class.is_none()
                    && state.consecutive_failure_count == 0
                    && !state.refresh_active
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the same daemon must follow again without a restart");
        shutdown.send(true).unwrap();
        daemon.await.unwrap();
        release.notify_waiters();
        server.abort();
        controller.store.maintenance_idle().await;
        authority.close().await;
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_wakes_the_expired_attempt_boundary() {
        let heartbeat = Arc::new(FollowHeartbeat::new());
        heartbeat.note_tick();
        heartbeat.note_attempt_start();
        let expired = heartbeat.expired.notified();
        tokio::pin!(expired);
        expired.as_mut().enable();
        let (shutdown, receiver) = watch::channel(false);
        let watcher = tokio::spawn({
            let heartbeat = heartbeat.clone();
            async move { run_follow_watchdog(&heartbeat, Duration::from_secs(1), receiver).await }
        });
        tokio::task::yield_now().await;
        tokio::time::advance(ATTEMPT_TIMEOUT + Duration::from_secs(1)).await;
        expired.await;
        shutdown.send(true).unwrap();
        watcher.await.unwrap();
        heartbeat.note_attempt_end();
        assert!(heartbeat.attempt_age(tokio::time::Instant::now()).is_none());
    }

    #[test]
    fn held_refresh_lock_has_a_deadline_and_can_be_acquired_after_release() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("held.lock");
        let holder = open_private_lock(&path).unwrap();
        holder.try_lock_exclusive().unwrap();
        let waiter = open_private_lock(&path).unwrap();
        let error = lock_exclusive_bounded(&waiter, Duration::from_millis(20)).unwrap_err();
        assert!(matches!(error, Error::Io(error) if error.kind() == std::io::ErrorKind::TimedOut));
        drop(holder);
        lock_exclusive_bounded(&waiter, Duration::from_millis(20)).unwrap();
    }

    #[test]
    fn fence_diagnostics_use_typed_sites_and_ignore_body_words() {
        use crate::error::StandbyAdmissionCheck as Check;
        for (check, source) in [
            (
                Check::ActOrderContinuity,
                "standby candidate fails act-order/continuity fence",
            ),
            (
                Check::ScalarRollbackContinuity,
                "standby candidate fails scalar rollback/continuity fence",
            ),
            (
                Check::CurrentGeneration,
                "standby current pointer digest mismatch",
            ),
            (
                Check::SuccessorPreservation,
                "standby candidate does not preserve content_events",
            ),
            (
                Check::Integrity,
                "standby snapshot integrity or foreign-key validation failed",
            ),
            (
                Check::Conformance,
                "standby snapshot conformance failed: body=route origin consumer secret",
            ),
        ] {
            let error = classify_install_error(Error::engine(source).at_standby_check(check));
            assert_eq!(error.check, Some(check.token()));
            assert_eq!(sanitize_retained_detail(error.check), check.token());
            assert!(!safe_diagnostic(&error).contains("secret"));
        }
        let arbitrary =
            classify_install_error(Error::engine("row body=route origin consumer DDL rollback"));
        assert_eq!(arbitrary.check, Some(INSTALL_VERIFY_CHECK));
        assert_eq!(arbitrary.class, RefreshFailureClass::Verification);
    }

    /// Sentinel: sinks must never emit raw source text. The hostile source
    /// below carries a live-credential shape, a private record body and a
    /// conformance-style row dump with multibyte content; the safe
    /// diagnostic, the persisted state and the CLI triple must contain none
    /// of it — only allowlisted class, safe-message and fence identifiers.
    /// Multibyte content also proves no byte bounding is attempted anywhere.
    #[test]
    fn refresh_sinks_render_only_allowlisted_identifiers() {
        let hostile = format!(
            "bearer=live-credential-9f8e7d6c row 0: live={{\"body\":\"private record body 🔐🔐\"}} rebuilt=<none> {}",
            "🔐".repeat(2000),
        );
        let error = classify_install_error(Error::engine(hostile.clone()));
        assert_eq!(error.class, RefreshFailureClass::Verification);
        assert_eq!(error.check, Some("install-fence:verify"));
        let diagnosis = safe_diagnostic(&error);
        for leak in [
            "live-credential-9f8e7d6c",
            "private record body",
            "live={",
            "🔐",
            hostile.as_str(),
        ] {
            assert!(!diagnosis.contains(leak), "sink leak: {leak}");
        }
        for expected in [
            "class=Verification",
            "downloaded snapshot was not admitted",
            "check=install-fence:verify",
        ] {
            assert!(diagnosis.contains(expected), "missing: {expected}");
        }
        // The fence-needle path reports its static identifier, still leak-free.
        let fenced = classify_install_error(
            Error::engine(format!(
                "installed standby consumer mismatch; credential={hostile}"
            ))
            .at_standby_check(crate::error::StandbyAdmissionCheck::Consumer),
        );
        assert_eq!(fenced.class, RefreshFailureClass::Compatibility);
        assert_eq!(fenced.check, Some("install-fence:consumer"));
        assert!(!safe_diagnostic(&fenced).contains("live-credential-9f8e7d6c"));
        // An auth-flavored hostile source is equally contained.
        let auth = AttemptError::new(
            RefreshFailureClass::Authentication,
            "hosted snapshot authentication was refused",
            Error::auth(hostile.clone()),
        );
        assert!(!safe_diagnostic(&auth).contains("live-credential-9f8e7d6c"));
        // The persisted projection carries only the fence identifier.
        let state = StandbyRefreshState {
            last_full_failure_class: Some(error.class),
            last_full_failure: Some(error.safe_message.into()),
            last_full_failure_detail: Some(error.check.unwrap_or("unclassified").into()),
            ..Default::default()
        };
        let serialized = serde_json::to_string(&state).unwrap();
        assert!(!serialized.contains("live-credential-9f8e7d6c"));
        assert!(!serialized.contains("private record body"));
        assert!(serialized.contains("install-fence:verify"));
    }
    #[cfg(not(feature = "v2-kernel-probe"))]
    #[tokio::test]
    async fn default_build_pauses_v2_before_any_full_download_cold_and_warm() {
        for warm in [false, true] {
            let client = Arc::new(AlwaysFailClient {
                class: RefreshFailureClass::Network,
                calls: AtomicUsize::new(0),
            });
            let (_directory, mut controller) = controller_with_client(client.clone());
            let v1 = crate::create_database(":memory:").await.unwrap();
            let origin = crate::identity::database_id(&v1).await.unwrap();
            controller.runtime.origin_database_id = origin.clone();
            controller.store = GenerationStore::open(
                &controller.runtime.replica_root,
                "route-1",
                Some(origin.clone()),
            )
            .unwrap();
            controller.observed = crate::standby::generation_store::tests::observed();
            controller.delta_enabled = true;
            if warm {
                let (snapshot, manifest) = crate::standby::generation_store::tests::stage(
                    &controller.store,
                    &v1,
                    "default-pause",
                )
                .await;
                controller
                    .store
                    .install_staged(&snapshot, &manifest, &controller.observed)
                    .await
                    .unwrap();
            }
            let (v2, _) = Box::pin(crate::kernel::create_v2_database(
                ":memory:",
                "account",
                "Owner",
                "acct:pause",
            ))
            .await
            .unwrap();
            let mut head = serde_json::to_value(
                super::super::delta_transport::observe_authority_act_head(&v2, "route-1")
                    .await
                    .unwrap(),
            )
            .unwrap();
            // A legitimate imported workspace retains its v1 source origin.
            head["head"]["origin_database_id"] = json!(origin);
            let (port, server) = serve_one_head_refusal("200 OK", json!({"jsonrpc":"2.0","id":1,"result":{"isError":false,"content":[],"structuredContent":head}})).await;
            controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
            let reason = "engine v2 requires v2-kernel-probe build";
            let outcome = controller.refresh_once(RefreshCause::Scheduled).await;
            if warm {
                assert!(
                    matches!(outcome.unwrap(), StandbyRefreshOutcome::Deferred { reason: actual, .. } if actual == reason)
                );
                assert_eq!(
                    controller.state().unwrap().last_deferral.as_deref(),
                    Some(reason)
                );
            } else {
                assert!(outcome.unwrap_err().to_string().contains(reason));
                assert_eq!(
                    controller.state().unwrap().last_failure.as_deref(),
                    Some(reason)
                );
            }
            assert_eq!(client.calls.load(Ordering::SeqCst), 0);
            assert!(controller.state().unwrap().last_full_refresh_at.is_none());
            server.await.unwrap();
            v1.close().await;
            v2.close().await;
        }
    }
    #[tokio::test]
    async fn full_mcp_page_records_update_before_generic_http_refusal() {
        let app = Router::new().fallback(axum::routing::any(|headers:HeaderMap| async move {
            assert_eq!(headers[crate::client_compatibility::HEADER],crate::client_compatibility::advertisement());
            (StatusCode::UPGRADE_REQUIRED,Json(json!({"error_code":"client_update_required","outcome":"refused","applied":false})))
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/mcp/db", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = HttpSnapshotPageClient::new().unwrap();
        let error = client
            .page(
                endpoint,
                "secret".into(),
                SnapshotPageRequest {
                    export_id: None,
                    offset: 0,
                    length: 1,
                    standby_consumer: Some(consumer()),
                },
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.class, RefreshFailureClass::Compatibility);
        assert_eq!(client.compatibility.status()["status"], "demand_recorded");
        server.abort();
    }
}
