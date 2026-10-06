//! Live tabs M2 server core, increment 1 (task `61e11ad`, design `ee12faf` rev 3).
//!
//! Host-neutral subscription primitives: tunables, id-less frame shapes and
//! the stable `need-closed` reason mapping. The connection registry,
//! scheduler and emit gate build on this in later increments of this file.
//! Transport wiring (the `/events` handler and SSE sink) is intentionally
//! absent here: `held/hosting/src/hosting/realtime.rs` is owned by the
//! parallel `e7d2c04` slice until the orchestrator says its fix landed.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::Instant;

/// Design §2.2: caps count the caller's own subscriptions only.
pub const MAX_SUBSCRIPTIONS_PER_CONNECTION: usize = 32;
/// Design §2.2: per account per database.
pub const MAX_SUBSCRIPTIONS_PER_ACCOUNT_DB: usize = 64;
/// Design §2.4: gate-forcing triggers skip this.
pub const DEBOUNCE_MS: u64 = 250;
/// Design §2.4: per-connection token bucket refill rate.
pub const BUDGET_PERMITS_PER_SEC: u32 = 20;
/// Design §2.4: bucket burst capacity.
pub const BUDGET_BURST: u32 = 40;
/// Design §2.4: bounded per-connection sink.
pub const SINK_CAPACITY: usize = 16;
/// Design §3: cap applies to `result` alone.
pub const RESULT_FRAME_CAP_BYTES: usize = 256 * 1024;
/// M1 server-owned clock cadence. The first due time is independently
/// jittered within this window for each time-dependent subscription.
/// Content-wake latency has its own, shorter target; clock-only eligibility
/// changes wait for this cadence plus polling and the shared budget.
pub const CLOCK_TICK_MS: u64 = 60_000;
/// How often the scheduler checks internal per-subscription due times.
pub const CLOCK_POLL_MS: u64 = 1_000;

/// Stable per-id phase inside the 60 s interval. Subscription ids are
/// CSPRNG-minted, so independent tabs do not phase-align on a host timer.
/// Delays span 1..=60,000 ms, so a new subscription may tick soon after
/// activation while the CSPRNG phases keep unrelated tabs spread out.
fn clock_initial_delay_ms(id: &SubscriptionId) -> u64 {
    let prefix = id.as_str().get(..16).unwrap_or_default();
    let seed = u64::from_str_radix(prefix, 16).unwrap_or_default();
    1 + seed % CLOCK_TICK_MS
}

/// Wire versions (design §3).
pub const STREAM_FRAME_VERSION: &str = "native.need-stream.v1";
pub const NEED_FRAME_VERSION: &str = "native.need-revision.v1";

/// Id-less `stream` frame announced on every connect (design §2.2, §3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamFrame {
    pub version: String,
    pub connection: String,
}

impl StreamFrame {
    pub fn new(connection: impl Into<String>) -> Self {
        Self {
            version: STREAM_FRAME_VERSION.to_string(),
            connection: connection.into(),
        }
    }
}

/// Revision pointer carried on `need` frames (design §3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeedRevisionPointer {
    pub revision_digest: String,
    pub rows_sha256: String,
}

/// Id-less `need` frame (design §3). `result` is `None` when the serialized
/// body is at/over the frame cap; the digest still covers the full rows.
/// `as_of_ms` is the delivered evaluation's stamp — the maximum of its
/// per-need statement clocks — and travels only with a delivered body: an
/// over-cap frame carries `result: None` with `as_of_ms: None`, and the host
/// re-reads for rows (design §3). A stamp without rows would name an
/// evaluation the host cannot render.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeedFrame {
    pub version: String,
    pub subscription: String,
    pub delivery: u64,
    pub revision: NeedRevisionPointer,
    pub result: Option<serde_json::Value>,
    pub as_of_ms: Option<i64>,
}

/// Changed keyed result. `key` is the opaque variant handle supplied on the
/// governed read, not raw params; the wire remains exactly four fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeedKeyedFrame {
    pub subscription: String,
    pub delivery: u64,
    pub key: String,
    pub at_revision: String,
}

/// Id-less `need-stale` frame listing one connection's stale subscriptions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeedStaleFrame {
    pub version: String,
    pub subscriptions: Vec<String>,
}

/// Stable `need-closed` wire reasons (design §2.5). Closed set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NeedClosedReason {
    AccessLost,
    Disabled,
    Removed,
    Reinstalled,
    AdoptionChanged,
    SourceChanged,
    UndeclaredNeed,
    Unsubscribed,
}

/// Id-less `need-closed` frame (design §3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeedClosedFrame {
    pub version: String,
    pub subscription: String,
    pub reason: NeedClosedReason,
}

/// Map a `live_read` internal refusal code to the stable wire reason
/// (design §2.5). Unmapped codes default to `access_lost` so the wire set
/// stays closed. Parameter/SQL-shape refusals cannot occur on a re-run of
/// already-accepted params; they map here only as a label.
pub fn closed_reason_for_refusal(code: &str) -> NeedClosedReason {
    match code {
        "unauthorized" | "archived" | "missing" | "wrong_record_type" => {
            NeedClosedReason::AccessLost
        }
        "disabled" => NeedClosedReason::Disabled,
        "removed" | "missing_install" => NeedClosedReason::Removed,
        "cas_mismatch" => NeedClosedReason::Reinstalled,
        "adoption_unverified" | "declaration_mismatch" => NeedClosedReason::AdoptionChanged,
        "digest_mismatch" | "source_revision_unresolved" | "not_renderable" => {
            NeedClosedReason::SourceChanged
        }
        "undeclared_need" => NeedClosedReason::UndeclaredNeed,
        _ => NeedClosedReason::AccessLost,
    }
}

/// Decide whether a `need` delivery carries its body or `null` under the
/// frame cap (design §3). A `null` delivery still advances the baseline and
/// `delivery`, so the host never loops.
pub fn result_for_frame_cap(result: serde_json::Value) -> Option<serde_json::Value> {
    let bytes = serde_json::to_vec(&result).unwrap_or_default().len();
    if bytes < RESULT_FRAME_CAP_BYTES {
        Some(result)
    } else {
        None
    }
}

/// Scheduler wake taxonomy (design §2.5–2.6, hook list §6). `Tick` is the M1
/// slot (no timer wired until then); `Resync`/`Subscribe` are synchronous
/// paths that reuse the dirty/re-run machinery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerKind {
    Content,
    Grant,
    Control,
    Demotion,
    Tick,
    Resync,
    Subscribe,
}

/// What a trigger demands of the scheduler: debounced coalescing, or an
/// immediate gate-forcing re-check. Package scoping narrows control wakes;
/// `None` means every subscription on the database (or connection).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WakeEffect {
    Debounced,
    GateForcing { package: Option<String> },
}

/// The §2.5 wiring table as data. Content is debounced; grant, control and
/// demotion force the gate with no debounce. Control events stay internal —
/// no count or timing derived from them may reach a frame.
pub fn wake_effect(trigger: TriggerKind) -> WakeEffect {
    match trigger {
        TriggerKind::Content => WakeEffect::Debounced,
        TriggerKind::Grant | TriggerKind::Demotion | TriggerKind::Tick => {
            WakeEffect::GateForcing { package: None }
        }
        TriggerKind::Control => WakeEffect::GateForcing { package: None },
        TriggerKind::Resync | TriggerKind::Subscribe => WakeEffect::GateForcing { package: None },
    }
}

/// Per-connection token bucket (design §2.4): 20 re-runs/second, burst 40.
/// Dirty subscriptions beyond budget are served round-robin; never dropped.
#[derive(Clone, Debug)]
pub struct TokenBucket {
    pub permits_per_sec: f64,
    pub burst: f64,
    available: f64,
    last_refill_ms: u64,
}

impl TokenBucket {
    pub fn new() -> Self {
        Self {
            permits_per_sec: BUDGET_PERMITS_PER_SEC as f64,
            burst: BUDGET_BURST as f64,
            available: BUDGET_BURST as f64,
            last_refill_ms: 0,
        }
    }

    /// Refill from `now_ms` (monotonic millis) and take one permit if any.
    pub fn take(&mut self, now_ms: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.last_refill_ms) as f64 / 1000.0;
        self.available = (self.available + elapsed * self.permits_per_sec).min(self.burst);
        self.last_refill_ms = now_ms;
        if self.available >= 1.0 {
            self.available -= 1.0;
            true
        } else {
            false
        }
    }
}

impl Default for TokenBucket {
    fn default() -> Self {
        Self::new()
    }
}

/// Bounded-sink send outcome (design §2.4). The scheduler `try_send`s:
/// `Full` marks the subscription stale, `Closed` means the connection is
/// gone. The content pump is never blocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkOutcome {
    Sent,
    Stale,
    Closed,
}

/// Map a `try_send` result to the sink outcome. Pure so the rule is unit
/// pinned; the scheduler holds no sink lock across the send.
pub fn sink_outcome<T>(
    result: Result<(), tokio::sync::mpsc::error::TrySendError<T>>,
) -> SinkOutcome {
    match result {
        Ok(()) => SinkOutcome::Sent,
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => SinkOutcome::Stale,
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => SinkOutcome::Closed,
    }
}

/// Surface-level gate pin for the emit gate (design §2.3): the install and
/// source values the re-run read, re-checked without row reads before any
/// `need` frame. Any drift closes the subscription instead of emitting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateSnapshot {
    pub install_event_id: String,
    pub status: String,
    pub adoption: String,
    pub declaration_digest: String,
    pub bundle_sha256: String,
    pub source_event_id: String,
    pub source_revision: String,
    pub runtime: Option<String>,
}

#[cfg(test)]
impl GateSnapshot {
    pub fn test_snapshot() -> Self {
        Self {
            install_event_id: "event-1".to_string(),
            status: "active".to_string(),
            adoption: "verified".to_string(),
            declaration_digest: "decl-1".to_string(),
            bundle_sha256: "bundle-1".to_string(),
            source_event_id: "source-1".to_string(),
            source_revision: "rev-1".to_string(),
            runtime: Some("native.html.v1".to_string()),
        }
    }
}

/// Compare the emit-time re-check against the re-run's pin. `None` holds
/// the gates; `Some` is the `need-closed` reason. Install moves map to
/// `reinstalled`, status to `disabled`/`removed`, adoption and declaration
/// drift to `adoption_changed`, source drift to `source_changed`. A fresh
/// refusal maps through the shared refusal table (view loss included).
pub fn gate_drift_reason(stored: &GateSnapshot, fresh: &GateSnapshot) -> Option<NeedClosedReason> {
    if fresh.install_event_id != stored.install_event_id {
        return Some(NeedClosedReason::Reinstalled);
    }
    if fresh.status != stored.status {
        return Some(match fresh.status.as_str() {
            "disabled" => NeedClosedReason::Disabled,
            "removed" => NeedClosedReason::Removed,
            _ => NeedClosedReason::AccessLost,
        });
    }
    if fresh.adoption != stored.adoption || fresh.declaration_digest != stored.declaration_digest {
        return Some(NeedClosedReason::AdoptionChanged);
    }
    if fresh.bundle_sha256 != stored.bundle_sha256
        || fresh.source_event_id != stored.source_event_id
        || fresh.source_revision != stored.source_revision
        || fresh.runtime != stored.runtime
    {
        return Some(NeedClosedReason::SourceChanged);
    }
    None
}
/// Opaque stream connection token: 128 bits from a CSPRNG (design §2.2).
/// Compared in constant time; never logged (see redacted `Debug`).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ConnectionToken([u8; 16]);

impl ConnectionToken {
    pub fn mint() -> Self {
        Self(rand::random())
    }

    /// Constant-time equality over the raw bytes (no early exit).
    pub fn equals_ct(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (left, right)| acc | (left ^ right))
            == 0
    }

    /// Opaque wire form for the `stream` frame and the `subscribe`/`live_unsubscribe`
    /// tool arguments: hex of the raw bytes. The host passes it back verbatim.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Parse the wire form. Malformed input is `None` — the tool layer maps
    /// it to `stream_unknown` (subscribe) or success-with-no-effect
    /// (unsubscribe), never a new error.
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != 32 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (index, chunk) in text.as_bytes().chunks(2).enumerate() {
            bytes[index] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl std::fmt::Debug for ConnectionToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConnectionToken(redacted)")
    }
}

/// Opaque subscription id: random per subscribe, never a counter, never
/// reused across connections (design §2.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubscriptionId(String);

impl SubscriptionId {
    fn mint() -> Self {
        let bytes: [u8; 16] = rand::random();
        Self(
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Accept an id back from the host (resync/unsubscribe arguments).
    /// Opaque: unknown ids simply miss in the registry, never error.
    pub fn from_wire(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

/// Host-neutral surface binding (design §2.1). Alpha uses
/// `{kind: "alpha_tab", package, install_event_id}`; later kinds add no
/// alpha-only fields to the frames.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SurfaceBinding {
    pub kind: String,
    pub package: String,
    pub install_event_id: String,
}

impl SurfaceBinding {
    pub fn alpha_tab(package: impl Into<String>, install_event_id: impl Into<String>) -> Self {
        Self {
            kind: "alpha_tab".to_string(),
            package: package.into(),
            install_event_id: install_event_id.into(),
        }
    }
}

/// Canonical digest over subscription params: same need with different
/// params is a different subscription (design §2.1). Absent params digest
/// as JSON null, so omitted and explicit-null agree.
pub fn params_digest(params: Option<&serde_json::Value>) -> String {
    let value = params.cloned().unwrap_or(serde_json::Value::Null);
    crate::canonical_json::digest_json(&value)
}

/// Subscribe-time refusal. Unknown/closed tokens and account/database
/// mismatches share `stream_unknown`; over-cap shares `subscription_limit`.
/// The ordinary read in the same call still succeeds (tool layer).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubscribeRefusal {
    StreamUnknown,
    SubscriptionLimit,
}

impl SubscribeRefusal {
    /// Stable wire/tool code for the refusal. Unknown/closed tokens and
    /// account/database mismatches share `stream_unknown`.
    pub fn as_code(&self) -> &'static str {
        match self {
            SubscribeRefusal::StreamUnknown => "stream_unknown",
            SubscribeRefusal::SubscriptionLimit => "subscription_limit",
        }
    }
}

/// Outcome of one serialized emit attempt. `Gone` covers every silent
/// drop: unknown token/id, inactive lifecycle, baseline drift (teardown
/// or a newer computation won), and revoked access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmitDisposition {
    Sent,
    Stale,
    Closed,
    NoSink,
    Gone,
}

/// Outcome of one serialized close. `Staled` means the `need-closed`
/// frame was dropped on a full sink: the id is tombstoned on the
/// connection and the record removed, so the next `need-stale` flush
/// still names it and the host's re-read refusal teaches the closure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseDisposition {
    Sent,
    Staled,
    Silent,
}

/// Fresh access/footing probe for one SSE connection, installed by the
/// stream layer (design §2.3: the emit gate re-checks *current* access).
/// Captures its own bearer/session context; answers `None` when stream
/// access is lost or `Some(is_member)` with the current catalog footing.
/// The registry's `access_valid`/`is_member` copies are only as fresh as the
/// SSE loop's last check, so the scheduler never treats them as proof of
/// current authority — they remain as the teardown fast-path inside the
/// serialized send.
pub type AccessHook = std::sync::Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<bool>> + Send>>
        + Send
        + Sync,
>;

/// One frame on a connection's bounded sink. The SSE stream `select!`s on
/// this alongside its existing receivers; all three are id-less (design §3).
#[derive(Clone, Debug)]
pub enum NeedSinkFrame {
    Need(NeedFrame),
    Keyed(NeedKeyedFrame),
    Stale(NeedStaleFrame),
    Closed(NeedClosedFrame),
}

/// One dirty subscription awaiting a re-run, in dirtied order. `forcing`
/// wakes (grant, control, demotion) skip the debounce; content wakes do not.
/// An entry already queued is upgraded to forcing rather than duplicated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirtyEntry {
    pub id: SubscriptionId,
    pub forcing: bool,
}

/// One registered SSE connection: the token's account/database binding plus
/// its subscription ids. Subscriptions are ephemeral: closing the connection
/// drops them all, never persisted, never resumed (design §2.2).
struct ConnectionEntry {
    account_id: String,
    database_id: String,
    subscriptions: std::collections::HashMap<SubscriptionId, SubscriptionRecord>,
    /// Flush trigger (§2.4): set when a send marked a subscription stale.
    /// The SSE stream (after yielding any need frame) and the scheduler (on
    /// its next wake for the connection) enqueue one `need-stale` listing
    /// only this connection's stale subscriptions when the channel has spare
    /// capacity, then clear the flag.
    stale_pending: bool,
    /// Current catalog footing for re-runs under the viewer's authority.
    /// Set at registration from the SSE layer's admission and refreshed by
    /// the stream's role-change detector; guests evaluate with their own
    /// account grants only, never the members baseline.
    is_member: bool,
    /// Bounded per-connection sink (`SINK_CAPACITY`). Registered by the SSE
    /// layer; the scheduler clones the sender and `try_send`s outside the
    /// registry lock. Dropped with the entry on teardown.
    sink: Option<tokio::sync::mpsc::Sender<NeedSinkFrame>>,
    /// Per-connection token bucket (§2.4) and dirtied-order queue.
    bucket: TokenBucket,
    dirty_queue: std::collections::VecDeque<DirtyEntry>,
    /// Emit-gate copy of the SSE stream's access verdict. Set false by the
    /// stream when `access_still_valid` returns `None`, just before the
    /// stream ends; the atomic send checks it under the same lock teardown
    /// takes, so a revoked connection never emits. True until then — the
    /// residual polling window is documented at the scheduler.
    access_valid: bool,
    /// Closure tombstones: subscription ids whose `need-closed` frame was
    /// dropped on a full sink. They survive `unsubscribe` (unlike the
    /// per-record `stale` flag) and ride the next `need-stale` flush for
    /// this connection only; the host's re-read refusal teaches the closure.
    closed_tombstones: Vec<SubscriptionId>,
    /// Fresh authority probe installed by the SSE stream at connect. The
    /// scheduler awaits it on every re-run and emit; `None` here means the
    /// standalone/test fallback to the registry footing.
    access_hook: Option<AccessHook>,
}

impl std::fmt::Debug for ConnectionEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionEntry")
            .field("account_id", &self.account_id)
            .field("database_id", &self.database_id)
            .field("subscriptions", &self.subscriptions)
            .field("stale_pending", &self.stale_pending)
            .field("is_member", &self.is_member)
            .field("bucket", &self.bucket)
            .field("dirty_queue", &self.dirty_queue)
            .field("access_valid", &self.access_valid)
            .field("closed_tombstones", &self.closed_tombstones)
            .field("access_hook_present", &self.access_hook.is_some())
            .finish_non_exhaustive()
    }
}

/// Atomic-subscribe lifecycle (design §2.2): registered as pending before
/// evaluation, then activated with the evaluated baseline. A trigger firing
/// between those steps sets `dirty`, and the tool layer runs one immediate
/// re-run instead of missing the write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscriptionLifecycle {
    Pending,
    Active,
}

/// Per-subscription push state. `delivery` counts emitted `need` frames from
/// 0 (the initial `live_read`); gaps are impossible — it counts emissions,
/// not computations (design §2.4). Latest-wins and the sink live above this
/// registry; the emit gate reads `baseline`/`delivery` under the same lock
/// teardown takes (grabbed by the caller holding the registry lock).
#[derive(Clone, Debug)]
pub struct SubscriptionRecord {
    pub binding: SurfaceBinding,
    pub need: String,
    pub params_digest: String,
    pub lifecycle: SubscriptionLifecycle,
    pub baseline: Option<String>,
    /// Only Graph neighbour reads under this pin, never a package-visible
    /// table-touch flag. Dropped automatically with the subscription.
    pub keyed: crate::keyed_freshness::KeyedFreshness,
    pub keyed_dirty: bool,
    pub delivery: u64,
    pub dirty: bool,
    /// Sink-backpressure mark: the subscription's frame was dropped on a
    /// full channel. The host re-reads it with `if_revision`, missing nothing.
    pub stale: bool,
    /// Internal M1 clock schedule. Never enters a frame or digest.
    pub time_dependent: bool,
    pub next_clock_at: Option<Instant>,
    /// Internal due-work audit, independent of the coalesced trigger kind.
    pub clock_schedule_epoch: u64,
    pub clock_due_generation: u64,
    pub clock_evaluated_generation: u64,
    pub clock_last_due_at: Option<Instant>,
    pub clock_budget_deferred: bool,
    /// Exact hidden `now_ms()` binds of the evaluation which established the
    /// held baseline. Server-only; never a frame or digest field.
    pub clock_bindings: Option<std::collections::BTreeMap<String, i64>>,
    /// Independently clocked activity relations cannot be faithfully
    /// replayed by pinning only `now_ms()`.
    pub clock_replay_safe: bool,
    /// An evaluation has cleared `dirty` but has not yet finished. Probes
    /// must exclude this interval even though the dirty queue is empty.
    /// Owned only by the push scheduler's RunObservation.
    pub in_flight: bool,
    /// The subscribe handler's immediate catch-up read has consumed dirty
    /// state and is still awaiting its snapshot. It has a separate owner so
    /// it cannot clear a concurrent scheduler run's marker.
    pub catchup_in_flight: bool,
    /// M3 internal attribution only. No part is serialized to clients.
    pub dirty_since: Option<Instant>,
    pub dirty_trigger: Option<crate::need_metrics::Trigger>,
    pub saw_content_event: bool,
    pub pending_acts: std::collections::VecDeque<i64>,
    pub unknown_act_pending: bool,
    pub last_counted_act: Option<i64>,
}

fn clock_unserved_periods(record: &SubscriptionRecord) -> u64 {
    record
        .clock_due_generation
        .saturating_sub(record.clock_evaluated_generation)
}

fn clock_unpolled_due_periods(record: &SubscriptionRecord, now: Instant) -> u64 {
    let Some(due) = record.next_clock_at else {
        return 0;
    };
    if !record.time_dependent || due > now {
        return 0;
    }
    (now.duration_since(due).as_millis() / u128::from(CLOCK_TICK_MS) + 1).min(u128::from(u64::MAX))
        as u64
}

fn oldest_due_age_ms(now: Instant, last_due: Instant, older_periods: u64) -> u128 {
    let offset = u128::from(older_periods) * u128::from(CLOCK_TICK_MS);
    if now >= last_due {
        now.duration_since(last_due)
            .as_millis()
            .saturating_add(offset)
    } else {
        offset.saturating_sub(last_due.duration_since(now).as_millis())
    }
}

#[derive(Debug)]
pub struct DirtyMeasurement {
    pub trigger: crate::need_metrics::Trigger,
    pub since: Instant,
    pub content_acts: Vec<i64>,
    pub unknown_act: bool,
    /// Due work present when this scheduler run began. Later ticks remain
    /// pending even if this run completes successfully.
    pub clock_schedule_epoch: u64,
    pub clock_due_generation: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClockDueAudit {
    pub due_periods: u64,
    pub covered_periods: u64,
    pub covering_evaluations: u64,
    /// Completed snapshot evaluations that were at least one period late for
    /// the oldest due generation they covered. Not a delivery count.
    pub late_covering_evaluations: u64,
    pub max_cover_lateness_ms: u64,
    pub budget_deferral_attempts: u64,
    pub removed_unserved_periods: u64,
    pub retired_unserved_periods: u64,
    pub removed_unpolled_due_periods: u64,
    pub retired_unpolled_due_periods: u64,
    pub time_dependent_subscriptions: u64,
    /// Due by wall clock but not yet reached by the one-second poll.
    pub unpolled_due_subscriptions: u64,
    pub unpolled_due_periods: u64,
    pub pending_subscriptions: u64,
    pub pending_periods: u64,
    /// Pending or unpolled for at least one full period beyond the oldest due.
    pub overdue_subscriptions: u64,
    pub budget_deferred_subscriptions: u64,
}

/// Token-keyed subscription registry (design §2.2). Host-neutral and
/// transport-free: the SSE layer owns token minting/announcement and calls
/// `remove_connection` from its drop guard; the tool layer resolves tokens
/// here. It lives on `RealtimeHub`, so `attach` (hub reuse) and
/// `refresh_pool` (pool swap) preserve it. Outstanding scheduler/sink seams:
/// `mark_dirty` wake sources (content/grant/control/demotion), the emit gate
/// re-check, and the bounded-`mpsc` sink with `need-stale` flush — the
/// `/events` handler side stays untouched until `e7d2c04` lands.
#[derive(Debug, Default)]
pub struct NeedRegistry {
    connections: std::collections::HashMap<ConnectionToken, ConnectionEntry>,
    per_account_db: std::collections::HashMap<(String, String), usize>,
    /// Set before hub fan-out, so debounce cannot race the scheduler's
    /// receipt of the content broadcast.
    last_content_event_at: Option<Instant>,
    pending_act_overflows: u64,
    teardown_pending_act_drops: u64,
    clock_audit: ClockDueAudit,
}

impl NeedRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a connection for `(account_id, database_id)`, returning its
    /// token. Called by the SSE layer on connect (after the `stream` frame),
    /// with the admission-time catalog footing: re-runs evaluate with the
    /// viewer's current authority, so the footing must be exact from the
    /// start — a member default would leak, a guest default would starve.
    pub fn register_connection(
        &mut self,
        account_id: impl Into<String>,
        database_id: impl Into<String>,
        is_member: bool,
    ) -> ConnectionToken {
        let token = ConnectionToken::mint();
        self.connections.insert(
            token.clone(),
            ConnectionEntry {
                account_id: account_id.into(),
                database_id: database_id.into(),
                subscriptions: std::collections::HashMap::new(),
                stale_pending: false,
                is_member,
                sink: None,
                bucket: TokenBucket::new(),
                dirty_queue: std::collections::VecDeque::new(),
                access_valid: true,
                closed_tombstones: Vec::new(),
                access_hook: None,
            },
        );
        token
    }

    /// Drop-guard path: remove the connection and all its subscriptions,
    /// releasing its per-account/database cap share.
    pub fn remove_connection(&mut self, token: &ConnectionToken) -> bool {
        let removed_at = Instant::now();
        let Some(entry) = self.connections.remove(token) else {
            return false;
        };
        let key = (entry.account_id, entry.database_id);
        let count = entry.subscriptions.len();
        self.teardown_pending_act_drops += entry
            .subscriptions
            .values()
            .map(|record| record.pending_acts.len() as u64 + u64::from(record.unknown_act_pending))
            .sum::<u64>();
        self.clock_audit.removed_unserved_periods += entry
            .subscriptions
            .values()
            .map(clock_unserved_periods)
            .sum::<u64>();
        self.clock_audit.removed_unpolled_due_periods += entry
            .subscriptions
            .values()
            .map(|record| clock_unpolled_due_periods(record, removed_at))
            .sum::<u64>();
        self.per_account_db
            .entry(key)
            .and_modify(|held| *held = held.saturating_sub(count));
        true
    }

    /// Retire every connection and subscription (hub terminalize path).
    /// Subscriptions are ephemeral, so hub teardown drops them outright.
    pub fn clear(&mut self) {
        let removed_at = Instant::now();
        self.teardown_pending_act_drops += self
            .connections
            .values()
            .flat_map(|entry| entry.subscriptions.values())
            .map(|record| record.pending_acts.len() as u64 + u64::from(record.unknown_act_pending))
            .sum::<u64>();
        self.clock_audit.removed_unserved_periods += self
            .connections
            .values()
            .flat_map(|entry| entry.subscriptions.values())
            .map(clock_unserved_periods)
            .sum::<u64>();
        self.clock_audit.removed_unpolled_due_periods += self
            .connections
            .values()
            .flat_map(|entry| entry.subscriptions.values())
            .map(|record| clock_unpolled_due_periods(record, removed_at))
            .sum::<u64>();
        self.connections.clear();
        self.per_account_db.clear();
    }

    fn find(&self, token: &ConnectionToken) -> Option<&ConnectionEntry> {
        // Tokens are hashable randoms; still compare in constant time so a
        // timing probe cannot distinguish near-miss from far-miss lookups.
        self.connections
            .iter()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))
    }

    /// Register a **pending** subscription on `token` as `(caller_account,
    /// caller_database)` — step 1 of the §2.2 atomic subscribe. From this
    /// moment every trigger sets its dirty flag (via `mark_dirty`). The
    /// token's account/database must match the tool call's, else
    /// `stream_unknown`; closed/unknown tokens get the same answer. Over the
    /// caps the newest subscribe is refused with `subscription_limit` and
    /// nothing is evicted. Caps count the caller's own subscriptions only.
    pub fn subscribe_pending(
        &mut self,
        token: &ConnectionToken,
        caller_account: &str,
        caller_database: &str,
        binding: SurfaceBinding,
        need: &str,
        params_digest: &str,
    ) -> Result<SubscriptionId, SubscribeRefusal> {
        let entry = self.find(token).ok_or(SubscribeRefusal::StreamUnknown)?;
        if entry.account_id != caller_account || entry.database_id != caller_database {
            return Err(SubscribeRefusal::StreamUnknown);
        }
        if entry.subscriptions.len() >= MAX_SUBSCRIPTIONS_PER_CONNECTION {
            return Err(SubscribeRefusal::SubscriptionLimit);
        }
        let key = (entry.account_id.clone(), entry.database_id.clone());
        if self.per_account_db.get(&key).copied().unwrap_or(0) >= MAX_SUBSCRIPTIONS_PER_ACCOUNT_DB {
            return Err(SubscribeRefusal::SubscriptionLimit);
        }
        let id = SubscriptionId::mint();
        // Re-resolve mutably (keys are unique randoms; no aliasing).
        let entry = self
            .connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))
            .expect("token found above");
        entry.subscriptions.insert(
            id.clone(),
            SubscriptionRecord {
                binding,
                need: need.to_string(),
                params_digest: params_digest.to_string(),
                lifecycle: SubscriptionLifecycle::Pending,
                baseline: None,
                keyed: crate::keyed_freshness::KeyedFreshness::default(),
                keyed_dirty: false,
                delivery: 0,
                dirty: false,
                stale: false,
                time_dependent: false,
                next_clock_at: None,
                clock_schedule_epoch: 0,
                clock_due_generation: 0,
                clock_evaluated_generation: 0,
                clock_last_due_at: None,
                clock_budget_deferred: false,
                clock_bindings: None,
                clock_replay_safe: true,
                in_flight: false,
                catchup_in_flight: false,
                dirty_since: None,
                dirty_trigger: None,
                saw_content_event: false,
                pending_acts: std::collections::VecDeque::new(),
                unknown_act_pending: false,
                last_counted_act: None,
            },
        );
        self.per_account_db
            .entry(key)
            .and_modify(|held| *held += 1)
            .or_insert(1);
        Ok(id)
    }

    /// Install the evaluated `revision_digest` as the baseline, set
    /// `delivery = 0` and mark the subscription active — step 3 of the §2.2
    /// atomic subscribe. Returns whether the subscription was dirtied during
    /// evaluation (step 4: one immediate re-run). `None` means the stream
    /// or subscription disappeared while evaluation was in flight.
    /// Compatibility path for clock-free tests; clears any clock schedule.
    /// Clock-dependent subscriptions must use `activate_with_clock`.
    pub fn activate(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        baseline: &str,
    ) -> Option<bool> {
        self.activate_with_clock(token, id, baseline, false)
    }

    /// Activate with the evaluated snapshot's server-detected clock flag.
    /// Re-activation after the atomic subscribe re-run keeps the first due
    /// time, so a burst of writes cannot indefinitely postpone a clock tick.
    pub fn activate_with_clock(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        baseline: &str,
        time_dependent: bool,
    ) -> Option<bool> {
        self.activate_with_evaluation(token, id, baseline, time_dependent, None)
    }

    /// Activate with the exact per-need clocks retained for private replay.
    pub fn activate_with_evaluation(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        baseline: &str,
        time_dependent: bool,
        clocks: Option<std::collections::BTreeMap<String, i64>>,
    ) -> Option<bool> {
        self.activate_with_probe_safety(token, id, baseline, time_dependent, clocks, true)
    }

    pub fn activate_with_probe_safety(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        baseline: &str,
        time_dependent: bool,
        clocks: Option<std::collections::BTreeMap<String, i64>>,
        clock_replay_safe: bool,
    ) -> Option<bool> {
        let activated_at = Instant::now();
        let retired = self.record(token, id).map_or(0, |record| {
            if record.time_dependent && !time_dependent {
                clock_unserved_periods(record)
            } else {
                0
            }
        });
        let retired_unpolled = self.record(token, id).map_or(0, |record| {
            if record.time_dependent && !time_dependent {
                clock_unpolled_due_periods(record, activated_at)
            } else {
                0
            }
        });
        self.clock_audit.retired_unserved_periods += retired;
        self.clock_audit.retired_unpolled_due_periods += retired_unpolled;
        let record = self.record_mut(token, id)?;
        record.lifecycle = SubscriptionLifecycle::Active;
        record.baseline = Some(baseline.to_string());
        record.delivery = 0;
        if record.time_dependent != time_dependent {
            record.clock_schedule_epoch = record.clock_schedule_epoch.saturating_add(1);
        }
        record.time_dependent = time_dependent;
        if !time_dependent {
            record.clock_due_generation = 0;
            record.clock_evaluated_generation = 0;
            record.clock_last_due_at = None;
            record.clock_budget_deferred = false;
        }
        record.clock_bindings = clocks;
        record.clock_replay_safe = clock_replay_safe;
        record.next_clock_at = if time_dependent {
            record
                .next_clock_at
                .or_else(|| Some(activated_at + Duration::from_millis(clock_initial_delay_ms(id))))
        } else {
            None
        };
        Some(std::mem::replace(&mut record.dirty, false))
    }

    /// Advance the replay clock after a digest-equal re-run. Its baseline
    /// remains unchanged, but the most recent statement clocks move on.
    pub fn note_quiet_evaluation(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        expected_baseline: &str,
        clocks: Option<std::collections::BTreeMap<String, i64>>,
        clock_replay_safe: bool,
    ) -> bool {
        let Some(record) = self.record_mut(token, id) else {
            return false;
        };
        if record.lifecycle != SubscriptionLifecycle::Active
            || record.baseline.as_deref() != Some(expected_baseline)
        {
            return false;
        }
        record.clock_bindings = clocks;
        record.clock_replay_safe = clock_replay_safe;
        true
    }

    pub fn finish_rerun(&mut self, token: &ConnectionToken, id: &SubscriptionId) {
        if let Some(record) = self.record_mut(token, id) {
            record.in_flight = false;
        }
    }

    pub fn finish_catchup(&mut self, token: &ConnectionToken, id: &SubscriptionId) {
        if let Some(record) = self.record_mut(token, id) {
            record.catchup_in_flight = false;
        }
    }

    /// Mark only clock-dependent subscriptions whose own due time has
    /// elapsed. Each id has an independent phase; the scheduler's dedicated
    /// one-second poll scans this state and sends no broadcast or frame.
    /// Missed periods coalesce into one forcing re-run through the ordinary
    /// per-connection budget and dirty queue.
    pub fn mark_due_clock_ticks(&mut self, now: Instant) -> usize {
        let mut marked = 0;
        let mut due_periods = 0;
        for entry in self.connections.values_mut() {
            for (id, record) in &mut entry.subscriptions {
                if record.lifecycle != SubscriptionLifecycle::Active || !record.time_dependent {
                    continue;
                }
                let Some(due) = record.next_clock_at else {
                    continue;
                };
                if due > now {
                    continue;
                }
                let elapsed_ms = now.duration_since(due).as_millis();
                let periods = (elapsed_ms / u128::from(CLOCK_TICK_MS) + 1) as u64;
                record.clock_due_generation = record.clock_due_generation.saturating_add(periods);
                record.clock_last_due_at = Some(
                    due + Duration::from_millis(
                        periods.saturating_sub(1).saturating_mul(CLOCK_TICK_MS),
                    ),
                );
                due_periods += periods;
                record.next_clock_at =
                    Some(due + Duration::from_millis(periods.saturating_mul(CLOCK_TICK_MS)));
                record.dirty = true;
                record.dirty_since.get_or_insert(now);
                record
                    .dirty_trigger
                    .get_or_insert(crate::need_metrics::Trigger::Tick);
                if let Some(queued) = entry.dirty_queue.iter_mut().find(|queued| queued.id == *id) {
                    queued.forcing = true;
                } else {
                    entry.dirty_queue.push_back(DirtyEntry {
                        id: id.clone(),
                        forcing: true,
                    });
                }
                marked += 1;
            }
        }
        self.clock_audit.due_periods += due_periods;
        marked
    }

    /// Snapshot of clock work due at or before `now`. No per-subscription id
    /// leaves the registry and no current-time digest is treated as a miss.
    pub fn clock_due_audit(&self, now: Instant) -> ClockDueAudit {
        let mut audit = self.clock_audit;
        for record in self
            .connections
            .values()
            .flat_map(|entry| entry.subscriptions.values())
        {
            audit.time_dependent_subscriptions += u64::from(record.time_dependent);
            let pending = clock_unserved_periods(record);
            let unpolled_age_ms = record.next_clock_at.and_then(|due| {
                (record.time_dependent && now >= due).then(|| now.duration_since(due).as_millis())
            });
            if let Some(age_ms) = unpolled_age_ms {
                audit.unpolled_due_subscriptions += 1;
                audit.unpolled_due_periods += (age_ms / u128::from(CLOCK_TICK_MS) + 1) as u64;
            }
            let mut overdue = unpolled_age_ms.is_some_and(|age| age >= u128::from(CLOCK_TICK_MS));
            if pending > 0 {
                audit.pending_subscriptions += 1;
                audit.pending_periods += pending;
                audit.budget_deferred_subscriptions += u64::from(record.clock_budget_deferred);
            }
            if let Some(last_due) = record.clock_last_due_at.filter(|_| pending > 0) {
                let oldest_age_ms = oldest_due_age_ms(now, last_due, pending.saturating_sub(1));
                overdue |= oldest_age_ms >= u128::from(CLOCK_TICK_MS);
            }
            audit.overdue_subscriptions += u64::from(overdue);
        }
        audit
    }

    /// A failed shared-budget permit while clock work is outstanding. Count
    /// attempts and mark this subscription until a covering evaluation ends.
    pub fn note_clock_budget_deferred(&mut self, token: &ConnectionToken, id: &SubscriptionId) {
        let Some(record) = self.record_mut(token, id) else {
            return;
        };
        if clock_unserved_periods(record) > 0 {
            record.clock_budget_deferred = true;
            self.clock_audit.budget_deferral_attempts += 1;
        }
    }

    /// A successful snapshot evaluation covers only due periods captured at
    /// its start. It does not assert delivery or retire later due ticks.
    pub fn note_clock_snapshot_evaluated(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        captured_epoch: u64,
        captured_generation: u64,
        completed_at: Instant,
    ) {
        let Some(record) = self.record_mut(token, id) else {
            return;
        };
        if record.clock_schedule_epoch != captured_epoch {
            return;
        }
        let covered_through = captured_generation.min(record.clock_due_generation);
        let newly_covered = covered_through.saturating_sub(record.clock_evaluated_generation);
        if newly_covered == 0 {
            return;
        }
        let lateness_ms = record.clock_last_due_at.map(|last_due| {
            oldest_due_age_ms(
                completed_at,
                last_due,
                record
                    .clock_due_generation
                    .saturating_sub(record.clock_evaluated_generation)
                    .saturating_sub(1),
            )
        });
        record.clock_evaluated_generation = covered_through;
        record.clock_budget_deferred = false;
        self.clock_audit.covered_periods += newly_covered;
        self.clock_audit.covering_evaluations += 1;
        if let Some(lateness_ms) = lateness_ms {
            self.clock_audit.late_covering_evaluations +=
                u64::from(lateness_ms >= u128::from(CLOCK_TICK_MS));
            self.clock_audit.max_cover_lateness_ms = self
                .clock_audit
                .max_cover_lateness_ms
                .max(lateness_ms.min(u128::from(u64::MAX)) as u64);
        }
    }

    #[cfg(test)]
    pub(crate) fn set_clock_due_for_test(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        due: Instant,
    ) {
        self.record_mut(token, id)
            .expect("test subscription exists")
            .next_clock_at = Some(due);
    }

    /// Remove a pending entry after a refused evaluation (step 2 fallout),
    /// releasing its cap share. Unknown ids are a no-op.
    pub fn remove_pending(&mut self, token: &ConnectionToken, id: &SubscriptionId) {
        if self
            .record(token, id)
            .is_some_and(|record| record.lifecycle == SubscriptionLifecycle::Pending)
        {
            self.unsubscribe(token, id);
        }
    }

    /// Wake path: mark one subscription dirty (trigger fired). Pending and
    /// active entries both record it; `activate` consumes the flag set
    /// during evaluation. Returns whether the id exists.
    pub fn mark_dirty(&mut self, token: &ConnectionToken, id: &SubscriptionId) -> bool {
        let Some(record) = self.record_mut(token, id) else {
            return false;
        };
        record.dirty = true;
        record.dirty_since.get_or_insert_with(Instant::now);
        record
            .dirty_trigger
            .get_or_insert(crate::need_metrics::Trigger::Retry);
        true
    }

    /// Snapshot probe for the emit gate and scheduler: baseline, delivery,
    /// lifecycle and dirty flag. Reads under the caller's registry lock.
    pub fn subscription_state(
        &self,
        token: &ConnectionToken,
        id: &SubscriptionId,
    ) -> Option<SubscriptionRecord> {
        self.record(token, id).cloned()
    }

    /// Associate a completed governed keyed read with the caller's active
    /// snapshot pin. A guessed token/id, another account, or an old install
    /// cannot attach a fingerprint. `None` means no tracking was admitted;
    /// the ordinary read result remains available as a pull read.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_keyed_read(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        account_id: &str,
        database_id: &str,
        package: &str,
        install_event_id: &str,
        fingerprint: crate::keyed_freshness::KeyedFingerprint,
    ) -> Option<bool> {
        let entry = self
            .connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))?;
        if entry.account_id != account_id || entry.database_id != database_id || !entry.access_valid
        {
            return None;
        }
        let record = entry.subscriptions.get_mut(id)?;
        if record.lifecycle != SubscriptionLifecycle::Active
            || record.binding != SurfaceBinding::alpha_tab(package, install_event_id)
        {
            return None;
        }
        let key = fingerprint.key.clone();
        record.keyed.admit(fingerprint);
        let evicted = record.keyed.evicted(&key);
        // The read may have raced a commit before its fingerprint was
        // registered, when no variant existed to mark keyed_dirty. Queue
        // one silent catch-up comparison after admission; only a genuine
        // viewer-result diff can emit a hint.
        record.keyed_dirty = true;
        self.enqueue_dirty_with_trigger(token, id, true, crate::need_metrics::Trigger::Subscribe);
        Some(evicted)
    }

    /// Record one emitted `need` frame: `delivery` rises by 1 and the
    /// baseline advances to the delivered digest. A `null` (over-cap)
    /// delivery still advances both, so the host never loops. Dirtiness set
    /// meanwhile is kept — latest-wins sends only the newest frame, and the
    /// next pass picks up whatever arrived after this computation.
    pub fn note_emitted(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        baseline: &str,
    ) -> bool {
        let Some(record) = self.record_mut(token, id) else {
            return false;
        };
        record.delivery += 1;
        record.baseline = Some(baseline.to_string());
        true
    }

    /// Sink `Full` path: mark the subscription stale and raise the
    /// connection's flush flag. Its frame is dropped; the host re-reads with
    /// `if_revision` and misses nothing.
    pub fn mark_stale(&mut self, token: &ConnectionToken, id: &SubscriptionId) -> bool {
        let Some(entry) = self
            .connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))
        else {
            return false;
        };
        let Some(record) = entry.subscriptions.get_mut(id) else {
            return false;
        };
        record.stale = true;
        entry.stale_pending = true;
        true
    }

    /// Flush path (§2.4): drain this connection's stale ids and clear its
    /// flag. Includes closure tombstones (ids already unsubscribed whose
    /// `need-closed` was dropped on a full sink), so a closure is never
    /// lost: the host re-reads each listed id and the refusal teaches it.
    /// Names only this connection's ids, and only when the channel has
    /// spare capacity.
    pub fn take_stale_ids(&mut self, token: &ConnectionToken) -> Vec<SubscriptionId> {
        let Some(entry) = self
            .connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))
        else {
            return Vec::new();
        };
        entry.stale_pending = false;
        let mut ids: Vec<SubscriptionId> = entry
            .subscriptions
            .iter_mut()
            .filter_map(|(id, record)| {
                std::mem::replace(&mut record.stale, false).then(|| id.clone())
            })
            .collect();
        ids.append(&mut entry.closed_tombstones);
        ids
    }

    /// Whether a `need-stale` flush is owed on this connection.
    pub fn stale_pending(&self, token: &ConnectionToken) -> bool {
        self.find(token).is_some_and(|entry| entry.stale_pending)
    }

    /// Mark the connection's access verdict from the SSE stream's
    /// `access_still_valid` check. False just before the stream ends; the
    /// atomic send refuses while false, so teardown wins even before the
    /// drop guard removes the connection.
    pub fn set_access_valid(&mut self, token: &ConnectionToken, valid: bool) -> bool {
        let Some(entry) = self
            .connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))
        else {
            return false;
        };
        entry.access_valid = valid;
        true
    }

    /// Install the connection's fresh authority probe, called by the SSE
    /// layer at connect with a closure capturing that stream's session.
    /// Replaces any previous hook.
    pub fn register_access_hook(&mut self, token: &ConnectionToken, hook: AccessHook) -> bool {
        let Some(entry) = self
            .connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))
        else {
            return false;
        };
        entry.access_hook = Some(hook);
        true
    }

    /// Clone the connection's authority probe for one check. The scheduler
    /// awaits it outside the registry lock.
    pub fn access_hook(&self, token: &ConnectionToken) -> Option<AccessHook> {
        self.find(token)?.access_hook.clone()
    }

    /// Force a gate re-check on every subscription of one connection
    /// (design §2.5 demotion row): the stream's role-change detector calls
    /// this alongside `set_connection_member`, so a demotion narrows the
    /// next evaluation on that connection before any frame is written.
    /// Returns the number of subscriptions marked.
    pub fn mark_connection_forcing(&mut self, token: &ConnectionToken) -> usize {
        let Some(entry) = self
            .connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))
        else {
            return 0;
        };
        let ids: Vec<SubscriptionId> = entry.subscriptions.keys().cloned().collect();
        let mut marked = 0;
        for id in ids {
            let Some(record) = entry.subscriptions.get_mut(&id) else {
                continue;
            };
            record.dirty = true;
            record.dirty_since.get_or_insert_with(Instant::now);
            record.dirty_trigger = Some(crate::need_metrics::Trigger::Demotion);
            if record.lifecycle == SubscriptionLifecycle::Pending {
                marked += 1;
                continue;
            }
            if let Some(queued) = entry.dirty_queue.iter_mut().find(|queued| queued.id == id) {
                queued.forcing = true;
            } else {
                entry
                    .dirty_queue
                    .push_back(DirtyEntry { id, forcing: true });
            }
            marked += 1;
        }
        marked
    }

    /// Restore ids to the stale set after a flush send hit a full sink:
    /// live records regain their flag, already-removed ids regain a
    /// tombstone (deduped), and the flush flag is raised again. The next
    /// pass retries instead of dropping the notification.
    pub fn restore_stale_ids(&mut self, token: &ConnectionToken, ids: Vec<SubscriptionId>) {
        let Some(entry) = self
            .connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))
        else {
            return;
        };
        for id in ids {
            if let Some(record) = entry.subscriptions.get_mut(&id) {
                record.stale = true;
            } else if !entry.closed_tombstones.contains(&id) {
                entry.closed_tombstones.push(id);
            }
        }
        entry.stale_pending = true;
    }

    /// Serialized `need` send (design §2.3): the final active/baseline/access
    /// check, the synchronous `try_send`, and the delivery/baseline update
    /// all happen under this one registry lock — the same lock `unsubscribe`
    /// and `remove_connection` take — with no await inside. A concurrent
    /// teardown therefore cannot lose to a stale frame: either this sends
    /// first or teardown removed the record first and this reports `Gone`.
    /// `try_send` never blocks, so holding the mutex across it is safe.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_need(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        compared_baseline: Option<&str>,
        digest: &str,
        rows_sha256: &str,
        result: serde_json::Value,
        as_of_ms: Option<i64>,
    ) -> EmitDisposition {
        self.emit_need_with_clocks(
            token,
            id,
            compared_baseline,
            digest,
            rows_sha256,
            result,
            as_of_ms,
            None,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn emit_need_with_clocks(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        compared_baseline: Option<&str>,
        digest: &str,
        rows_sha256: &str,
        result: serde_json::Value,
        as_of_ms: Option<i64>,
        clocks: Option<std::collections::BTreeMap<String, i64>>,
        clock_replay_safe: bool,
    ) -> EmitDisposition {
        let Some(entry) = self
            .connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))
        else {
            return EmitDisposition::Gone;
        };
        let Some(record) = entry.subscriptions.get_mut(id) else {
            return EmitDisposition::Gone;
        };
        if record.lifecycle != SubscriptionLifecycle::Active {
            return EmitDisposition::Gone;
        }
        if !entry.access_valid {
            return EmitDisposition::Gone;
        }
        if record.baseline.as_deref() != compared_baseline {
            return EmitDisposition::Gone;
        }
        let Some(sender) = entry.sink.clone() else {
            return EmitDisposition::NoSink;
        };
        let delivery = record.delivery + 1;
        let body = result_for_frame_cap(result);
        // M1 slice 1: the stamp travels only with a delivered body. An
        // over-cap frame advances the baseline and `delivery` with
        // `result: None`, and nulls the stamp with it — the host re-reads
        // for the rows, and a stamp without rows would name an evaluation
        // the host cannot render (design §5: `as_of_ms` is only ever sent
        // with a delivered result).
        let as_of_ms = body.as_ref().and(as_of_ms);
        let frame = NeedSinkFrame::Need(NeedFrame {
            version: NEED_FRAME_VERSION.to_string(),
            subscription: id.as_str().to_string(),
            delivery,
            revision: NeedRevisionPointer {
                revision_digest: digest.to_string(),
                rows_sha256: rows_sha256.to_string(),
            },
            result: body,
            as_of_ms,
        });
        match sink_outcome(sender.try_send(frame)) {
            SinkOutcome::Sent => {
                record.delivery = delivery;
                record.baseline = Some(digest.to_string());
                record.clock_bindings = clocks;
                record.clock_replay_safe = clock_replay_safe;
                EmitDisposition::Sent
            }
            SinkOutcome::Stale => {
                record.stale = true;
                entry.stale_pending = true;
                EmitDisposition::Stale
            }
            SinkOutcome::Closed => EmitDisposition::Closed,
        }
    }

    /// Atomic post-diff hint. A table touch never reaches this method; the
    /// caller supplies the viewer-scoped re-read revision, and the stored
    /// fingerprint must differ. An identical result leaves the counter,
    /// fingerprint and sink untouched. Concurrent re-reads are fenced by
    /// `compared_revision` under this same registry lock.
    pub fn emit_keyed_hint(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        key: &str,
        params_digest: &str,
        compared_revision: &str,
        at_revision: &str,
    ) -> EmitDisposition {
        let Some(entry) = self
            .connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))
        else {
            return EmitDisposition::Gone;
        };
        let Some(record) = entry.subscriptions.get_mut(id) else {
            return EmitDisposition::Gone;
        };
        if !entry.access_valid
            || record.lifecycle != SubscriptionLifecycle::Active
            || record.dirty
            || record.keyed.revision(key, params_digest) != Some(compared_revision)
            || !record.keyed.changed(key, params_digest, at_revision)
        {
            return EmitDisposition::Gone;
        }
        let Some(sender) = entry.sink.clone() else {
            return EmitDisposition::NoSink;
        };
        let frame = NeedSinkFrame::Keyed(NeedKeyedFrame {
            subscription: id.as_str().to_string(),
            delivery: record.delivery + 1,
            key: crate::keyed_freshness::variant_handle(key, params_digest),
            at_revision: at_revision.to_string(),
        });
        match sink_outcome(sender.try_send(frame)) {
            SinkOutcome::Sent => {
                record.delivery += 1;
                let prior = record
                    .keyed
                    .variants_for(key)
                    .find(|item| item.params_digest == params_digest)
                    .cloned();
                if let Some(variant) = prior {
                    record
                        .keyed
                        .admit(crate::keyed_freshness::KeyedFingerprint {
                            revision: at_revision.to_string(),
                            ..variant
                        });
                }
                EmitDisposition::Sent
            }
            SinkOutcome::Stale => {
                record.stale = true;
                entry.stale_pending = true;
                EmitDisposition::Stale
            }
            SinkOutcome::Closed => EmitDisposition::Closed,
        }
    }

    /// Outcome of one serialized close. `Staled` means the `need-closed`
    /// frame was dropped on a full sink: the id is tombstoned on the
    /// connection and the record removed, so the next `need-stale` flush
    /// still names it and the host's re-read refusal teaches the closure.
    /// Serialized `need-closed` send: the frame (or its tombstone) and the
    /// record removal happen under this one registry lock with no await
    /// inside, so the closure can never be lost between send and teardown.
    /// Unknown ids are `Silent` with no effect. Idempotent: a second close
    /// of the same id is `Silent`.
    pub fn close_subscription(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        reason: NeedClosedReason,
    ) -> CloseDisposition {
        let removed_at = Instant::now();
        let Some(entry) = self
            .connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))
        else {
            return CloseDisposition::Silent;
        };
        if !entry.subscriptions.contains_key(id) {
            return CloseDisposition::Silent;
        }
        let disposition = match entry.sink.clone() {
            None => CloseDisposition::Silent,
            Some(sender) => {
                let frame = NeedSinkFrame::Closed(NeedClosedFrame {
                    version: NEED_FRAME_VERSION.to_string(),
                    subscription: id.as_str().to_string(),
                    reason,
                });
                match sink_outcome(sender.try_send(frame)) {
                    SinkOutcome::Sent => CloseDisposition::Sent,
                    SinkOutcome::Stale => {
                        entry.closed_tombstones.push(id.clone());
                        entry.stale_pending = true;
                        CloseDisposition::Staled
                    }
                    SinkOutcome::Closed => CloseDisposition::Silent,
                }
            }
        };
        // End the entry borrow before touching the cap table: remove the
        // record and release its per-account/database share.
        let key = (entry.account_id.clone(), entry.database_id.clone());
        if let Some(record) = entry.subscriptions.remove(id) {
            self.teardown_pending_act_drops +=
                record.pending_acts.len() as u64 + u64::from(record.unknown_act_pending);
            self.clock_audit.removed_unserved_periods += clock_unserved_periods(&record);
            self.clock_audit.removed_unpolled_due_periods +=
                clock_unpolled_due_periods(&record, removed_at);
        }
        entry.dirty_queue.retain(|queued| queued.id != *id);
        self.per_account_db
            .entry(key)
            .and_modify(|held| *held = held.saturating_sub(1));
        disposition
    }

    /// Register the connection's bounded sink, called by the SSE layer with
    /// the channel the stream `select!`s on. Replaces any previous sender.
    pub fn register_sink(
        &mut self,
        token: &ConnectionToken,
        sender: tokio::sync::mpsc::Sender<NeedSinkFrame>,
    ) -> bool {
        let Some(entry) = self
            .connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))
        else {
            return false;
        };
        entry.sink = Some(sender);
        true
    }

    /// Clone the connection's sink sender for one send. The scheduler sends
    /// outside the registry lock; outcomes map through `sink_outcome`.
    pub fn sink_sender(
        &self,
        token: &ConnectionToken,
    ) -> Option<tokio::sync::mpsc::Sender<NeedSinkFrame>> {
        self.find(token)?.sink.clone()
    }

    /// Refresh the connection's catalog footing from the stream's
    /// role-change detector. Re-runs build their `Caller` from this, so a
    /// demotion narrows the next evaluation before any frame is written.
    pub fn set_connection_member(&mut self, token: &ConnectionToken, is_member: bool) -> bool {
        let Some(entry) = self
            .connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))
        else {
            return false;
        };
        entry.is_member = is_member;
        true
    }

    /// The account and current footing a re-run evaluates under.
    pub fn connection_footing(&self, token: &ConnectionToken) -> Option<(String, bool)> {
        self.find(token)
            .map(|entry| (entry.account_id.clone(), entry.is_member))
    }

    /// Take one budget permit for a connection at `now_ms`. Deferred
    /// subscriptions stay queued in dirtied order — never dropped silently.
    pub fn try_take_budget(&mut self, token: &ConnectionToken, now_ms: u64) -> bool {
        self.connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))
            .is_some_and(|entry| entry.bucket.take(now_ms))
    }

    /// Connection tokens in registry order. The scheduler rotates its start
    /// index across passes for inter-connection fairness.
    pub fn connection_tokens(&self) -> Vec<ConnectionToken> {
        self.connections.keys().cloned().collect()
    }

    /// Queue one subscription for re-run in dirtied order, upgrading to
    /// forcing when already queued. No-op for unknown or inactive ids.
    /// Returns whether the id is now queued.
    pub fn enqueue_dirty(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        forcing: bool,
    ) -> bool {
        self.enqueue_dirty_with_trigger(token, id, forcing, crate::need_metrics::Trigger::Retry)
    }

    pub fn enqueue_dirty_with_trigger(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        forcing: bool,
        trigger: crate::need_metrics::Trigger,
    ) -> bool {
        let Some(entry) = self
            .connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))
        else {
            return false;
        };
        let Some(record) = entry.subscriptions.get_mut(id) else {
            return false;
        };
        if record.lifecycle != SubscriptionLifecycle::Active {
            return false;
        }
        record.dirty = true;
        record.dirty_since.get_or_insert_with(Instant::now);
        record.dirty_trigger.get_or_insert(trigger);
        if let Some(queued) = entry.dirty_queue.iter_mut().find(|queued| queued.id == *id) {
            queued.forcing = queued.forcing || forcing;
        } else {
            entry.dirty_queue.push_back(DirtyEntry {
                id: id.clone(),
                forcing,
            });
        }
        true
    }

    /// Pop the oldest dirtied subscription on one connection. The scheduler
    /// rotates across connections; each connection's own order is the order
    /// its subscriptions were dirtied (design §2.4 round-robin).
    pub fn pop_dirty(&mut self, token: &ConnectionToken) -> Option<DirtyEntry> {
        self.connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))?
            .dirty_queue
            .pop_front()
    }

    /// Look at the oldest dirtied subscription without popping, so budget
    /// and debounce checks run before the entry (and its permit) is spent.
    pub fn peek_dirty(&self, token: &ConnectionToken) -> Option<DirtyEntry> {
        self.find(token)?.dirty_queue.front().cloned()
    }

    /// Clear a subscription's dirty flag as its re-run starts. Triggers
    /// firing mid-run re-set it through `mark_dirty`/`enqueue_dirty` for
    /// the next pass (one in flight plus a flag, design §2.4).
    pub fn clear_dirty(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
    ) -> Option<DirtyMeasurement> {
        self.clear_dirty_for_owner(token, id, false)
    }

    pub fn clear_dirty_for_catchup(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
    ) -> Option<DirtyMeasurement> {
        self.clear_dirty_for_owner(token, id, true)
    }

    fn clear_dirty_for_owner(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        catchup: bool,
    ) -> Option<DirtyMeasurement> {
        let record = self.record_mut(token, id)?;
        record.dirty = false;
        record.keyed_dirty = false;
        if catchup {
            record.catchup_in_flight = true;
        } else {
            record.in_flight = true;
        }
        let trigger = record
            .dirty_trigger
            .take()
            .unwrap_or(crate::need_metrics::Trigger::Retry);
        let since = record.dirty_since.take().unwrap_or_else(Instant::now);
        record.saw_content_event = false;
        let content_acts = record.pending_acts.drain(..).collect();
        let unknown_act = std::mem::take(&mut record.unknown_act_pending);
        Some(DirtyMeasurement {
            trigger,
            since,
            content_acts,
            unknown_act,
            clock_schedule_epoch: record.clock_schedule_epoch,
            clock_due_generation: record.clock_due_generation,
        })
    }

    /// Transfer a failed scheduler run's drained work back to the same active
    /// subscription, merging later wakes. Clock generations stay in the record:
    /// completed SQL covers its captured generation, not a delivery or later tick.
    pub(crate) fn restore_rerun_work(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        work: &DirtyMeasurement,
        forcing: bool,
        keyed_dirty: bool,
        saw_content_event: bool,
    ) -> bool {
        let mut overflow = 0;
        let Some(record) = self.record_mut(token, id) else {
            return false;
        };
        if record.lifecycle != SubscriptionLifecycle::Active {
            return false;
        }
        record.keyed_dirty |= keyed_dirty;
        record.saw_content_event |= saw_content_event;
        record.unknown_act_pending |= work.unknown_act;
        let mut acts = std::collections::VecDeque::new();
        for act in work.content_acts.iter().chain(record.pending_acts.iter()) {
            if !acts.contains(act) {
                acts.push_back(*act);
            }
        }
        while acts.len() > crate::need_metrics::COMMIT_WINDOW {
            acts.pop_front();
            overflow += 1;
        }
        record.pending_acts = acts;
        record.dirty_since = Some(
            record
                .dirty_since
                .map_or(work.since, |since| since.min(work.since)),
        );
        if !record
            .dirty_trigger
            .is_some_and(|trigger| trigger.is_forcing())
        {
            record.dirty_trigger = Some(work.trigger);
        }
        self.pending_act_overflows += overflow;
        self.enqueue_dirty_with_trigger(token, id, forcing, work.trigger)
    }

    pub fn subscription_count(&self) -> usize {
        self.connections
            .values()
            .map(|entry| entry.subscriptions.len())
            .sum()
    }

    /// One clean active sample for M3's out-of-band digest probe. The
    /// scheduler re-checks this state after evaluating and discards races.
    pub fn probe_candidate(
        &self,
        cursor: usize,
    ) -> Option<(ConnectionToken, SubscriptionId, SubscriptionRecord)> {
        let eligible = self.probe_eligible_count();
        if eligible == 0 {
            return None;
        }
        self.connections
            .iter()
            .flat_map(|(token, entry)| {
                entry.subscriptions.iter().filter_map(move |(id, record)| {
                    (record.lifecycle == SubscriptionLifecycle::Active
                        // Clock-dependent rows may validly change before
                        // their next jittered tick. A 60 s content probe
                        // cannot call that an overdue push.
                        && !record.time_dependent
                        && record.clock_replay_safe
                        && !record.dirty
                        && !record.in_flight
                        && !record.catchup_in_flight
                        && !record.stale
                        && !entry.dirty_queue.iter().any(|queued| queued.id == *id))
                    .then_some((token, id, record))
                })
            })
            .nth(cursor % eligible)
            .map(|(token, id, record)| (token.clone(), id.clone(), record.clone()))
    }

    pub fn probe_eligible_count(&self) -> usize {
        self.connections
            .values()
            .map(|entry| {
                entry
                    .subscriptions
                    .iter()
                    .filter(|(id, record)| {
                        record.lifecycle == SubscriptionLifecycle::Active
                            && !record.time_dependent
                            && record.clock_replay_safe
                            && !record.dirty
                            && !record.in_flight
                            && !record.catchup_in_flight
                            && !record.stale
                            && !entry.dirty_queue.iter().any(|queued| &queued.id == *id)
                    })
                    .count()
            })
            .sum()
    }

    /// Clock-bearing samples replay at their stored statement clocks. They
    /// are counted separately from clock-free probes so a zero mismatch has
    /// an explicit eligible denominator.
    pub fn probe_clock_candidate(
        &self,
        cursor: usize,
    ) -> Option<(ConnectionToken, SubscriptionId, SubscriptionRecord)> {
        let eligible = self.probe_clock_eligible_count();
        if eligible == 0 {
            return None;
        }
        self.connections
            .iter()
            .flat_map(|(token, entry)| {
                entry.subscriptions.iter().filter_map(move |(id, record)| {
                    (record.lifecycle == SubscriptionLifecycle::Active
                        && record.time_dependent
                        && record.clock_replay_safe
                        && record
                            .clock_bindings
                            .as_ref()
                            .is_some_and(|c| !c.is_empty())
                        && !record.dirty
                        && !record.in_flight
                        && !record.catchup_in_flight
                        && !record.stale
                        && !entry.dirty_queue.iter().any(|queued| queued.id == *id))
                    .then_some((token, id, record))
                })
            })
            .nth(cursor % eligible)
            .map(|(token, id, record)| (token.clone(), id.clone(), record.clone()))
    }

    pub fn probe_clock_eligible_count(&self) -> usize {
        self.connections
            .values()
            .map(|entry| {
                entry
                    .subscriptions
                    .iter()
                    .filter(|(id, record)| {
                        record.lifecycle == SubscriptionLifecycle::Active
                            && record.time_dependent
                            && record.clock_replay_safe
                            && record
                                .clock_bindings
                                .as_ref()
                                .is_some_and(|c| !c.is_empty())
                            && !record.dirty
                            && !record.in_flight
                            && !record.catchup_in_flight
                            && !record.stale
                            && !entry.dirty_queue.iter().any(|queued| &queued.id == *id)
                    })
                    .count()
            })
            .sum()
    }

    /// Explicit denominator exclusion for snapshots with a second,
    /// execution-owned clock in `agent_activity` or its claims relation.
    pub fn probe_activity_excluded_count(&self) -> usize {
        self.connections
            .values()
            .map(|entry| {
                entry
                    .subscriptions
                    .values()
                    .filter(|record| {
                        record.lifecycle == SubscriptionLifecycle::Active
                            && !record.clock_replay_safe
                    })
                    .count()
            })
            .sum()
    }

    /// Recheck the sample under the registry lock after its async replay.
    pub fn probe_clock_sample_still_eligible(
        &self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        sampled: &SubscriptionRecord,
    ) -> bool {
        let Some(entry) = self.find(token) else {
            return false;
        };
        let Some(current) = entry.subscriptions.get(id) else {
            return false;
        };
        current.lifecycle == SubscriptionLifecycle::Active
            && current.time_dependent
            && !current.dirty
            && !current.in_flight
            && !current.catchup_in_flight
            && !current.stale
            && !entry.dirty_queue.iter().any(|queued| queued.id == *id)
            && current.baseline == sampled.baseline
            && current.delivery == sampled.delivery
            && current.clock_bindings == sampled.clock_bindings
            && current.clock_replay_safe == sampled.clock_replay_safe
    }

    /// A durable content-log row arrived at the hub. Return target count and
    /// newly queued count; their difference is coalescing, not an avoided
    /// query/row scan. This is called once before broadcast fan-out.
    pub fn mark_content_event(&mut self) -> (usize, usize, usize) {
        let (targets, queued, pending, _) = self.mark_content_event_with_act(None);
        (targets, queued, pending)
    }

    /// Known acts are counted once per subscription even when a transaction
    /// spans tail pages. Pending acts are drained only when an actual
    /// scheduler evaluation starts; a write during that evaluation belongs
    /// to the next one. NULL acts are explicitly unknown.
    pub fn mark_content_event_with_act(
        &mut self,
        act: Option<i64>,
    ) -> (usize, usize, usize, usize) {
        self.mark_content_event_with_act_and_type(act, None)
    }

    /// The event type is internal scheduling context only. Unknown types
    /// conservatively compare every retained key; known disjoint tables may
    /// skip expensive SQL, but can never themselves emit a hint.
    pub fn mark_content_event_with_act_and_type(
        &mut self,
        act: Option<i64>,
        event_type: Option<&str>,
    ) -> (usize, usize, usize, usize) {
        let targets = self.subscription_count();
        let pending = self
            .connections
            .values()
            .flat_map(|entry| entry.subscriptions.values())
            .filter(|record| record.lifecycle == SubscriptionLifecycle::Pending)
            .count();
        let queued_before: usize = self
            .connections
            .values()
            .map(|entry| entry.dirty_queue.len())
            .sum();
        let now = Instant::now();
        self.last_content_event_at = Some(now);
        let mut distinct_act_targets = 0;
        for entry in self.connections.values_mut() {
            for record in entry.subscriptions.values_mut() {
                record.dirty_since.get_or_insert(now);
                if !record
                    .dirty_trigger
                    .is_some_and(|trigger| trigger.is_forcing())
                {
                    record.dirty_trigger = Some(crate::need_metrics::Trigger::Content);
                }
                record.saw_content_event = true;
                record.keyed_dirty |= record.keyed.variants().any(|variant| {
                    variant.relations.iter().any(|relation| match event_type {
                        Some(kind) if kind.starts_with("link.") => {
                            relation == "links" || relation == "records"
                        }
                        Some(kind) if kind.starts_with("record.") || kind.starts_with("facet.") => {
                            relation == "records" || relation == "facet_values"
                        }
                        _ => true,
                    })
                });
                if let Some(act) = act {
                    if record.last_counted_act != Some(act) {
                        record.last_counted_act = Some(act);
                        distinct_act_targets += 1;
                    }
                    if record.pending_acts.back() != Some(&act) {
                        if record.pending_acts.len() == crate::need_metrics::COMMIT_WINDOW {
                            record.pending_acts.pop_front();
                            self.pending_act_overflows += 1;
                        }
                        record.pending_acts.push_back(act);
                    }
                } else {
                    record.unknown_act_pending = true;
                }
            }
        }
        self.mark_all_dirty();
        let queued_after: usize = self
            .connections
            .values()
            .map(|entry| entry.dirty_queue.len())
            .sum();
        (
            targets,
            queued_after.saturating_sub(queued_before),
            pending,
            distinct_act_targets,
        )
    }

    pub fn act_attribution_losses(&self) -> (u64, u64) {
        (self.pending_act_overflows, self.teardown_pending_act_drops)
    }

    pub fn last_content_event_at(&self) -> Option<Instant> {
        self.last_content_event_at
    }

    /// Queued depth on one connection (budget-deferral probe).
    pub fn dirty_len(&self, token: &ConnectionToken) -> usize {
        self.find(token)
            .map(|entry| entry.dirty_queue.len())
            .unwrap_or(0)
    }

    /// Content wake (§2.5): mark every subscription dirty, debounced once
    /// active. Pending entries keep only the flag for subscribe's immediate
    /// re-run; the scheduler must not evaluate them before activation.
    /// First implementation re-runs everything on every trigger; M4 may
    /// filter by read set. Tabs cannot tell the difference.
    pub fn mark_all_dirty(&mut self) -> usize {
        let mut marked = 0;
        for entry in self.connections.values_mut() {
            let ids: Vec<SubscriptionId> = entry.subscriptions.keys().cloned().collect();
            for id in ids {
                let Some(record) = entry.subscriptions.get_mut(&id) else {
                    continue;
                };
                record.dirty = true;
                if record.lifecycle == SubscriptionLifecycle::Pending {
                    marked += 1;
                    continue;
                }
                if !entry.dirty_queue.iter().any(|queued| queued.id == id) {
                    entry
                        .dirty_queue
                        .push_back(DirtyEntry { id, forcing: false });
                    marked += 1;
                }
            }
        }
        marked
    }

    /// Gate-forcing wake (§2.5) for grant/control/demotion: every
    /// subscription, or only `package`'s when the event names one. The
    /// broadcast vector never names a package, so callers pass `None` and
    /// re-check all — contract-compliant, since the contract never says
    /// which writes cause a re-run.
    pub fn mark_forcing(&mut self, package: Option<&str>) -> usize {
        self.mark_forcing_with_trigger(package, crate::need_metrics::Trigger::Control)
    }

    pub fn mark_forcing_with_trigger(
        &mut self,
        package: Option<&str>,
        trigger: crate::need_metrics::Trigger,
    ) -> usize {
        let mut marked = 0;
        for entry in self.connections.values_mut() {
            let ids: Vec<SubscriptionId> = entry
                .subscriptions
                .iter()
                .filter(|(_, record)| package.is_none_or(|name| record.binding.package == name))
                .map(|(id, _)| id.clone())
                .collect();
            for id in ids {
                let Some(record) = entry.subscriptions.get_mut(&id) else {
                    continue;
                };
                record.dirty = true;
                record.dirty_since.get_or_insert_with(Instant::now);
                record.dirty_trigger = Some(trigger);
                if record.lifecycle == SubscriptionLifecycle::Pending {
                    marked += 1;
                    continue;
                }
                if let Some(queued) = entry.dirty_queue.iter_mut().find(|queued| queued.id == id) {
                    queued.forcing = true;
                } else {
                    entry
                        .dirty_queue
                        .push_back(DirtyEntry { id, forcing: true });
                }
                marked += 1;
            }
        }
        marked
    }

    fn record(&self, token: &ConnectionToken, id: &SubscriptionId) -> Option<&SubscriptionRecord> {
        self.find(token)?.subscriptions.get(id)
    }

    fn record_mut(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
    ) -> Option<&mut SubscriptionRecord> {
        self.connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))?
            .subscriptions
            .get_mut(id)
    }

    /// Idempotent, connection-scoped unsubscribe: unknown ids succeed with no
    /// effect and can never touch another connection's subscriptions.
    pub fn unsubscribe(&mut self, token: &ConnectionToken, id: &SubscriptionId) -> bool {
        let removed_at = Instant::now();
        let Some(entry) = self
            .connections
            .iter_mut()
            .find_map(|(candidate, entry)| candidate.equals_ct(token).then_some(entry))
        else {
            return false;
        };
        let Some(record) = entry.subscriptions.remove(id) else {
            return false;
        };
        self.teardown_pending_act_drops +=
            record.pending_acts.len() as u64 + u64::from(record.unknown_act_pending);
        self.clock_audit.removed_unserved_periods += clock_unserved_periods(&record);
        self.clock_audit.removed_unpolled_due_periods +=
            clock_unpolled_due_periods(&record, removed_at);
        entry.dirty_queue.retain(|queued| queued.id != *id);
        let key = (entry.account_id.clone(), entry.database_id.clone());
        self.per_account_db
            .entry(key)
            .and_modify(|held| *held = held.saturating_sub(1));
        true
    }

    /// Subscription count on one connection (cap accounting probe).
    pub fn connection_subscription_count(&self, token: &ConnectionToken) -> usize {
        self.find(token)
            .map(|entry| entry.subscriptions.len())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn binding() -> SurfaceBinding {
        SurfaceBinding::alpha_tab("agent.attention-cockpit", "event-1")
    }

    #[test]
    fn closed_reasons_cover_the_wire_table() {
        assert_eq!(
            closed_reason_for_refusal("cas_mismatch"),
            NeedClosedReason::Reinstalled
        );
        assert_eq!(
            closed_reason_for_refusal("undeclared_need"),
            NeedClosedReason::UndeclaredNeed
        );
        assert_eq!(
            closed_reason_for_refusal("removed"),
            NeedClosedReason::Removed
        );
        assert_eq!(
            closed_reason_for_refusal("missing_install"),
            NeedClosedReason::Removed
        );
        // Unmapped internal codes default closed, never leak a new wire value.
        assert_eq!(
            closed_reason_for_refusal("invalid_params"),
            NeedClosedReason::AccessLost
        );
        assert_eq!(closed_reason_for_refusal(""), NeedClosedReason::AccessLost);
    }

    #[test]
    fn frame_cap_applies_to_result_alone() {
        let small = json!({"records": []});
        assert!(result_for_frame_cap(small.clone()).is_some());
        let big = json!({"records": ["x".repeat(RESULT_FRAME_CAP_BYTES)]});
        assert!(result_for_frame_cap(big).is_none());
    }

    #[test]
    fn tokens_are_unique_and_constant_time_compared() {
        let left = ConnectionToken::mint();
        let same = left.clone();
        let other = ConnectionToken::mint();
        assert!(left.equals_ct(&same));
        assert_ne!(left, other);
        assert_eq!(format!("{left:?}"), "ConnectionToken(redacted)");
    }

    #[test]
    fn params_digest_distinguishes_subscriptions() {
        let none = params_digest(None);
        let empty = params_digest(Some(&json!({})));
        let filled = params_digest(Some(&json!({"query": "a"})));
        let filled_again = params_digest(Some(&json!({"query": "a"})));
        assert_ne!(empty, filled);
        assert_eq!(filled, filled_again);
        assert_eq!(none, params_digest(Some(&serde_json::Value::Null)));
    }

    #[test]
    fn cross_account_and_unknown_tokens_are_stream_unknown() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let digest = params_digest(None);
        assert_eq!(
            registry.subscribe_pending(
                &token,
                "bea",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest
            ),
            Err(SubscribeRefusal::StreamUnknown)
        );
        assert_eq!(
            registry.subscribe_pending(
                &token,
                "alice",
                "db-2",
                binding(),
                "attention.query.v1",
                &digest
            ),
            Err(SubscribeRefusal::StreamUnknown)
        );
        assert_eq!(
            registry.subscribe_pending(
                &ConnectionToken::mint(),
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest
            ),
            Err(SubscribeRefusal::StreamUnknown)
        );
    }

    #[test]
    fn per_connection_cap_refuses_the_newest_subscribe() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let digest = params_digest(None);
        for _ in 0..MAX_SUBSCRIPTIONS_PER_CONNECTION {
            registry
                .subscribe_pending(
                    &token,
                    "alice",
                    "db-1",
                    binding(),
                    "attention.query.v1",
                    &digest,
                )
                .unwrap();
        }
        assert_eq!(
            registry.subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest
            ),
            Err(SubscribeRefusal::SubscriptionLimit)
        );
        assert_eq!(
            registry.connection_subscription_count(&token),
            MAX_SUBSCRIPTIONS_PER_CONNECTION
        );
    }

    #[test]
    fn unsubscribe_is_idempotent_and_connection_scoped() {
        let mut registry = NeedRegistry::new();
        let first = registry.register_connection("alice", "db-1", true);
        let second = registry.register_connection("alice", "db-1", true);
        let digest = params_digest(None);
        let id = registry
            .subscribe_pending(
                &first,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest,
            )
            .unwrap();
        // Another connection's id has no effect here.
        assert!(!registry.unsubscribe(&second, &id));
        assert_eq!(registry.connection_subscription_count(&first), 1);
        assert!(registry.unsubscribe(&first, &id));
        // Second call succeeds with no effect.
        assert!(!registry.unsubscribe(&first, &id));
        // Closing the connection drops everything and frees the cap share.
        let replacement = registry
            .subscribe_pending(
                &first,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest,
            )
            .unwrap();
        assert!(registry.remove_connection(&first));
        assert!(!registry.remove_connection(&first));
        assert!(!registry.unsubscribe(&first, &replacement));
        assert_eq!(registry.connection_subscription_count(&second), 0);
    }

    #[test]
    fn subscription_ids_are_opaque_and_unique() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let digest = params_digest(None);
        let first = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest,
            )
            .unwrap();
        let second = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest,
            )
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(first.as_str().len(), 32);
    }

    #[test]
    fn token_hex_round_trips_and_rejects_garbage() {
        let token = ConnectionToken::mint();
        let text = token.to_hex();
        assert_eq!(text.len(), 32);
        let parsed = ConnectionToken::from_hex(&text).unwrap();
        assert!(token.equals_ct(&parsed));
        assert!(ConnectionToken::from_hex("").is_none());
        assert!(ConnectionToken::from_hex(&text[..31]).is_none());
        assert!(ConnectionToken::from_hex(&("zz".to_owned() + &text[2..])).is_none());
    }

    #[test]
    fn atomic_subscribe_installs_baseline_and_reports_dirtied() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let digest = params_digest(None);
        let id = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest,
            )
            .unwrap();
        let pending = registry.subscription_state(&token, &id).unwrap();
        assert_eq!(pending.lifecycle, SubscriptionLifecycle::Pending);
        assert_eq!(pending.baseline, None);
        assert_eq!(pending.delivery, 0);
        // Trigger during evaluation shows up at activation.
        assert!(registry.mark_dirty(&token, &id));
        assert_eq!(registry.activate(&token, &id, "digest-1"), Some(true));
        let active = registry.subscription_state(&token, &id).unwrap();
        assert_eq!(active.lifecycle, SubscriptionLifecycle::Active);
        assert_eq!(active.baseline.as_deref(), Some("digest-1"));
        assert!(!active.dirty);
        // Quiet activation reports clean.
        assert_eq!(registry.activate(&token, &id, "digest-2"), Some(false));
        registry.remove_connection(&token);
        assert_eq!(registry.activate(&token, &id, "digest-3"), None);
        // Unknown ids never alarm.
        assert!(!registry.mark_dirty(&token, &SubscriptionId("nope".into())));
    }

    #[test]
    fn activity_exclusion_and_catchup_marker_have_distinct_probe_accounting() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let id = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &params_digest(None),
            )
            .unwrap();
        let clocks = Some(std::collections::BTreeMap::from([(
            "lane.clock".to_string(),
            10,
        )]));
        registry.activate_with_probe_safety(&token, &id, "held", true, clocks.clone(), false);
        assert_eq!(registry.probe_activity_excluded_count(), 1);
        assert_eq!(registry.probe_clock_eligible_count(), 0);
        registry.activate_with_probe_safety(&token, &id, "held", true, clocks, true);
        assert_eq!(registry.probe_activity_excluded_count(), 0);
        assert_eq!(registry.probe_clock_eligible_count(), 1);
        registry.mark_dirty(&token, &id);
        registry.clear_dirty_for_catchup(&token, &id).unwrap();
        assert_eq!(registry.probe_clock_eligible_count(), 0);
        assert!(
            registry
                .subscription_state(&token, &id)
                .unwrap()
                .catchup_in_flight
        );
        registry.finish_catchup(&token, &id);
        assert_eq!(registry.probe_clock_eligible_count(), 1);
        let clockfree = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &params_digest(None),
            )
            .unwrap();
        registry.activate_with_probe_safety(&token, &clockfree, "other", false, None, false);
        assert_eq!(registry.probe_activity_excluded_count(), 1);
        assert_eq!(registry.probe_eligible_count(), 0);
    }

    #[test]
    fn clock_due_times_are_per_subscription_and_coalesce_missed_periods() {
        assert_eq!(
            clock_initial_delay_ms(&SubscriptionId::from_wire(
                "00000000000000010000000000000000"
            )),
            2
        );
        assert_eq!(
            clock_initial_delay_ms(&SubscriptionId::from_wire(
                "00000000000000020000000000000000"
            )),
            3
        );
        // Real mints always land inside the window: desynchronized by
        // construction, bounded by it. (Exact spread is probabilistic, so
        // only the bounds are pinned here.)
        for _ in 0..8 {
            let delay = clock_initial_delay_ms(&SubscriptionId::from_wire(format!(
                "{:032x}",
                rand::random::<u128>()
            )));
            assert!((1..=CLOCK_TICK_MS).contains(&delay));
        }
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let digest = params_digest(None);
        let clock = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "sql.snapshot.v1",
                &digest,
            )
            .unwrap();
        let free = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest,
            )
            .unwrap();
        assert_eq!(
            registry.activate_with_clock(&token, &clock, "clock-0", true),
            Some(false)
        );
        assert_eq!(
            registry.activate_with_clock(&token, &free, "free-0", false),
            Some(false)
        );
        let due = registry
            .subscription_state(&token, &clock)
            .unwrap()
            .next_clock_at
            .unwrap();
        assert!(registry
            .subscription_state(&token, &free)
            .unwrap()
            .next_clock_at
            .is_none());
        assert_eq!(
            registry.mark_due_clock_ticks(due - Duration::from_millis(1)),
            0
        );
        assert_eq!(registry.mark_due_clock_ticks(due), 1);
        assert_eq!(registry.peek_dirty(&token).unwrap().id, clock);
        assert!(registry.peek_dirty(&token).unwrap().forcing);
        assert_eq!(registry.mark_due_clock_ticks(due), 0);
        let next = registry
            .subscription_state(&token, &clock)
            .unwrap()
            .next_clock_at
            .unwrap();
        assert_eq!(next - due, Duration::from_millis(CLOCK_TICK_MS));
        // A stalled scheduler skips old intervals and queues one re-run.
        assert_eq!(
            registry.mark_due_clock_ticks(due + Duration::from_millis(3 * CLOCK_TICK_MS)),
            1
        );
        let next = registry
            .subscription_state(&token, &clock)
            .unwrap()
            .next_clock_at
            .unwrap();
        assert_eq!(next - due, Duration::from_millis(4 * CLOCK_TICK_MS));
        assert_eq!(registry.dirty_len(&token), 1);
        assert!(registry.unsubscribe(&token, &clock));
        assert_eq!(registry.dirty_len(&token), 0);
        assert_eq!(
            registry.mark_due_clock_ticks(next + Duration::from_millis(CLOCK_TICK_MS)),
            0
        );
        assert!(registry.subscription_state(&token, &free).is_some());
        assert!(registry.mark_dirty(&token, &free));
        registry.enqueue_dirty(&token, &free, true);
        assert_eq!(registry.dirty_len(&token), 1);
        registry.close_subscription(&token, &free, NeedClosedReason::Disabled);
        assert_eq!(registry.dirty_len(&token), 0);
    }

    #[test]
    fn production_wakes_reach_pending_without_queueing_until_activation() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let digest = params_digest(None);
        let pending = |registry: &mut NeedRegistry| {
            registry
                .subscribe_pending(
                    &token,
                    "alice",
                    "db-1",
                    binding(),
                    "attention.query.v1",
                    &digest,
                )
                .unwrap()
        };
        let content = pending(&mut registry);
        assert_eq!(registry.mark_all_dirty(), 1);
        assert_eq!(registry.dirty_len(&token), 0);
        assert_eq!(registry.activate(&token, &content, "first"), Some(true));

        let grant = pending(&mut registry);
        assert!(registry.mark_forcing(None) >= 1);
        assert_eq!(registry.activate(&token, &grant, "second"), Some(true));

        let demotion = pending(&mut registry);
        assert!(registry.mark_connection_forcing(&token) >= 1);
        assert_eq!(registry.activate(&token, &demotion, "third"), Some(true));

        // A second write during the immediate re-run remains in the active
        // queue, even if baseline installation consumed its dirty flag.
        registry.mark_all_dirty();
        assert_eq!(registry.activate(&token, &demotion, "fourth"), Some(true));
        assert!(registry.enqueue_dirty(&token, &demotion, true));
        assert!(registry.dirty_len(&token) >= 1);
    }

    #[test]
    fn refused_evaluation_releases_the_pending_cap_share() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let digest = params_digest(None);
        let id = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest,
            )
            .unwrap();
        registry.remove_pending(&token, &id);
        assert_eq!(registry.connection_subscription_count(&token), 0);
        assert!(registry.subscription_state(&token, &id).is_none());
        // Active entries are never swept by the pending path.
        let kept = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest,
            )
            .unwrap();
        registry.activate(&token, &kept, "digest-1");
        registry.remove_pending(&token, &kept);
        assert_eq!(registry.connection_subscription_count(&token), 1);
    }

    #[test]
    fn wake_table_matches_section_2_5() {
        assert_eq!(wake_effect(TriggerKind::Content), WakeEffect::Debounced);
        assert_eq!(
            wake_effect(TriggerKind::Grant),
            WakeEffect::GateForcing { package: None }
        );
        assert_eq!(
            wake_effect(TriggerKind::Control),
            WakeEffect::GateForcing { package: None }
        );
        assert_eq!(
            wake_effect(TriggerKind::Demotion),
            WakeEffect::GateForcing { package: None }
        );
        // M1 clock ticks force the gate like any other time-driven wake:
        // they skip the content debounce and go through budget + digest.
        assert_eq!(
            wake_effect(TriggerKind::Tick),
            WakeEffect::GateForcing { package: None }
        );
    }

    #[test]
    fn token_bucket_refills_at_configured_rate() {
        let mut bucket = TokenBucket::new();
        for _ in 0..BUDGET_BURST {
            assert!(bucket.take(0));
        }
        assert!(!bucket.take(0));
        // 20 permits/sec: half a second restores 10.
        for _ in 0..10 {
            assert!(bucket.take(500));
        }
        assert!(!bucket.take(500));
        // Burst caps accumulation, however long the idle.
        assert!(bucket.take(60_000));
    }

    #[test]
    fn sink_outcomes_map_try_send_exactly() {
        assert_eq!(sink_outcome::<u8>(Ok(())), SinkOutcome::Sent);
        let (full_tx, _full_rx) = tokio::sync::mpsc::channel::<u8>(1);
        full_tx.try_send(1).unwrap();
        assert_eq!(
            sink_outcome(full_tx.try_send(2).map(|_| ())),
            SinkOutcome::Stale
        );
        let (closed_tx, closed_rx) = tokio::sync::mpsc::channel::<u8>(1);
        drop(closed_rx);
        assert_eq!(
            sink_outcome(closed_tx.try_send(1).map(|_| ())),
            SinkOutcome::Closed
        );
    }

    #[test]
    fn gate_drift_maps_to_the_wire_reasons() {
        let held = GateSnapshot::test_snapshot();
        assert_eq!(gate_drift_reason(&held, &held), None);
        let mut moved = held.clone();
        moved.install_event_id = "event-2".to_string();
        assert_eq!(
            gate_drift_reason(&held, &moved),
            Some(NeedClosedReason::Reinstalled)
        );
        let mut moved = held.clone();
        moved.status = "disabled".to_string();
        assert_eq!(
            gate_drift_reason(&held, &moved),
            Some(NeedClosedReason::Disabled)
        );
        let mut moved = held.clone();
        moved.status = "removed".to_string();
        assert_eq!(
            gate_drift_reason(&held, &moved),
            Some(NeedClosedReason::Removed)
        );
        let mut moved = held.clone();
        moved.adoption = "caller_asserted".to_string();
        assert_eq!(
            gate_drift_reason(&held, &moved),
            Some(NeedClosedReason::AdoptionChanged)
        );
        let mut moved = held.clone();
        moved.bundle_sha256 = "bundle-2".to_string();
        assert_eq!(
            gate_drift_reason(&held, &moved),
            Some(NeedClosedReason::SourceChanged)
        );
        let mut moved = held.clone();
        moved.runtime = None;
        assert_eq!(
            gate_drift_reason(&held, &moved),
            Some(NeedClosedReason::SourceChanged)
        );
    }

    #[test]
    fn stale_flush_names_only_that_connection_and_emissions_advance() {
        let mut registry = NeedRegistry::new();
        let first = registry.register_connection("alice", "db-1", true);
        let second = registry.register_connection("alice", "db-1", true);
        let digest = params_digest(None);
        let id = registry
            .subscribe_pending(
                &first,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest,
            )
            .unwrap();
        registry.activate(&first, &id, "digest-1");
        assert!(registry.note_emitted(&first, &id, "digest-1"));
        let state = registry.subscription_state(&first, &id).unwrap();
        assert_eq!(state.delivery, 1);
        assert!(registry.mark_stale(&first, &id));
        assert!(registry.stale_pending(&first));
        assert!(!registry.stale_pending(&second));
        let flushed = registry.take_stale_ids(&first);
        assert_eq!(flushed, vec![id]);
        assert!(!registry.stale_pending(&first));
        assert!(registry.take_stale_ids(&second).is_empty());
    }

    #[test]
    fn dirty_queue_orders_and_upgrades() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let digest = params_digest(None);
        let first = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest,
            )
            .unwrap();
        let second = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest,
            )
            .unwrap();
        registry.activate(&token, &first, "digest-1");
        // Pending entries never queue.
        assert!(!registry.enqueue_dirty(&token, &second, false));
        assert!(registry.enqueue_dirty(&token, &first, false));
        assert_eq!(registry.dirty_len(&token), 1);
        // Re-enqueue upgrades to forcing instead of duplicating.
        assert!(registry.enqueue_dirty(&token, &first, true));
        assert_eq!(registry.dirty_len(&token), 1);
        let entry = registry.pop_dirty(&token).unwrap();
        assert_eq!(
            entry,
            DirtyEntry {
                id: first,
                forcing: true
            }
        );
        assert_eq!(registry.dirty_len(&token), 0);
    }

    #[test]
    fn content_acts_and_events_coalesce_into_one_measured_rerun() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let id = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &params_digest(None),
            )
            .unwrap();
        registry.activate(&token, &id, "held");
        assert_eq!(registry.subscription_count(), 1);
        assert_eq!(registry.mark_content_event_with_act(Some(1)), (1, 1, 0, 1));
        assert_eq!(registry.mark_content_event_with_act(Some(1)), (1, 0, 0, 0));
        assert_eq!(registry.mark_content_event_with_act(Some(2)), (1, 0, 0, 1));
        assert_eq!(registry.dirty_len(&token), 1);
        registry.pop_dirty(&token).unwrap();
        let measured = registry.clear_dirty(&token, &id).unwrap();
        assert_eq!(measured.trigger, crate::need_metrics::Trigger::Content);
        assert_eq!(measured.content_acts, vec![1, 2]);
        assert!(registry.probe_candidate(0).is_none());
        registry.finish_rerun(&token, &id);
        assert!(registry.probe_candidate(0).is_some());
        assert!(registry
            .clear_dirty(&token, &id)
            .unwrap()
            .content_acts
            .is_empty());
    }

    #[test]
    fn write_during_evaluation_is_attributed_to_the_next_rerun() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let id = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &params_digest(None),
            )
            .unwrap();
        registry.activate(&token, &id, "held");
        registry.mark_content_event_with_act(Some(11));
        registry.pop_dirty(&token).unwrap();
        let running = registry.clear_dirty(&token, &id).unwrap();
        assert_eq!(running.content_acts, vec![11]);
        registry.mark_content_event_with_act(Some(12));
        registry.pop_dirty(&token).unwrap();
        let next = registry.clear_dirty(&token, &id).unwrap();
        assert_eq!(next.content_acts, vec![12]);
    }

    #[test]
    fn subscription_arriving_between_rows_of_one_act_counts_once() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let first = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &params_digest(None),
            )
            .unwrap();
        registry.activate(&token, &first, "held");
        assert_eq!(registry.mark_content_event_with_act(Some(31)).3, 1);
        let second = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &params_digest(None),
            )
            .unwrap();
        registry.activate(&token, &second, "held");
        assert_eq!(registry.mark_content_event_with_act(Some(31)).3, 1);
        assert_eq!(registry.mark_content_event_with_act(Some(31)).3, 0);
    }

    #[test]
    fn teardown_and_overflow_are_explicit_attribution_losses() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let id = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &params_digest(None),
            )
            .unwrap();
        registry.activate(&token, &id, "held");
        for act in 1..=(crate::need_metrics::COMMIT_WINDOW as i64 + 1) {
            registry.mark_content_event_with_act(Some(act));
        }
        assert_eq!(registry.act_attribution_losses(), (1, 0));
        assert!(registry.unsubscribe(&token, &id));
        assert_eq!(
            registry.act_attribution_losses(),
            (1, crate::need_metrics::COMMIT_WINDOW as u64)
        );
    }

    #[test]
    fn pending_subscription_keeps_pre_fanout_content_wake_on_activation() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let id = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &params_digest(None),
            )
            .unwrap();
        assert_eq!(registry.mark_content_event(), (1, 0, 1));
        assert_eq!(registry.dirty_len(&token), 0);
        assert_eq!(
            registry.activate(&token, &id, "first-evaluation"),
            Some(true)
        );
        assert!(registry.enqueue_dirty_with_trigger(
            &token,
            &id,
            true,
            crate::need_metrics::Trigger::Subscribe,
        ));
        assert_eq!(registry.dirty_len(&token), 1);
        let measurement = registry.clear_dirty(&token, &id).unwrap();
        assert_eq!(measurement.trigger, crate::need_metrics::Trigger::Content);
    }

    #[test]
    fn clock_due_audit_survives_content_coalescing_and_midrun_tick() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let id = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &params_digest(None),
            )
            .unwrap();
        registry.activate_with_clock(&token, &id, "held", true);
        let first_due = registry
            .subscription_state(&token, &id)
            .unwrap()
            .next_clock_at
            .unwrap();
        let before_poll =
            registry.clock_due_audit(first_due + Duration::from_millis(CLOCK_TICK_MS));
        assert_eq!(before_poll.unpolled_due_subscriptions, 1);
        assert_eq!(before_poll.unpolled_due_periods, 2);
        assert_eq!(before_poll.pending_periods, 0);
        assert_eq!(before_poll.overdue_subscriptions, 1);
        registry.mark_content_event_with_act(Some(1));
        assert_eq!(registry.mark_due_clock_ticks(first_due), 1);
        let first = registry.clear_dirty(&token, &id).unwrap();
        assert_eq!(first.trigger, crate::need_metrics::Trigger::Content);
        assert_eq!(first.clock_due_generation, 1);

        // A second due time fires while the first snapshot is in flight.
        let second_due = first_due + Duration::from_millis(CLOCK_TICK_MS);
        assert_eq!(registry.mark_due_clock_ticks(second_due), 1);
        registry.note_clock_snapshot_evaluated(
            &token,
            &id,
            first.clock_schedule_epoch,
            first.clock_due_generation,
            Instant::now(),
        );
        let audit = registry.clock_due_audit(second_due);
        assert_eq!(audit.due_periods, 2);
        assert_eq!(audit.covered_periods, 1);
        assert_eq!(audit.covering_evaluations, 1);
        assert_eq!(audit.time_dependent_subscriptions, 1);
        assert_eq!(audit.pending_subscriptions, 1);
        assert_eq!(audit.pending_periods, 1);
        assert_eq!(audit.overdue_subscriptions, 0);
        assert_eq!(
            registry
                .clock_due_audit(second_due + Duration::from_millis(CLOCK_TICK_MS))
                .overdue_subscriptions,
            1
        );

        let second = registry.clear_dirty(&token, &id).unwrap();
        assert_eq!(second.clock_due_generation, 2);
        registry.note_clock_snapshot_evaluated(
            &token,
            &id,
            second.clock_schedule_epoch,
            second.clock_due_generation,
            Instant::now(),
        );
        let audit = registry.clock_due_audit(second_due);
        assert_eq!(audit.covered_periods, 2);
        assert_eq!(audit.covering_evaluations, 2);
        assert_eq!(audit.pending_periods, 0);
    }

    #[test]
    fn clock_due_audit_tracks_budget_deferral_and_teardown() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let id = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &params_digest(None),
            )
            .unwrap();
        registry.activate_with_clock(&token, &id, "held", true);
        let due = registry
            .subscription_state(&token, &id)
            .unwrap()
            .next_clock_at
            .unwrap();
        registry.mark_due_clock_ticks(due);
        registry.note_clock_budget_deferred(&token, &id);
        registry.note_clock_budget_deferred(&token, &id);
        let audit = registry.clock_due_audit(due);
        assert_eq!(audit.time_dependent_subscriptions, 1);
        assert_eq!(audit.budget_deferral_attempts, 2);
        assert_eq!(audit.budget_deferred_subscriptions, 1);
        assert_eq!(audit.pending_periods, 1);
        registry.unsubscribe(&token, &id);
        let audit = registry.clock_due_audit(due);
        assert_eq!(audit.time_dependent_subscriptions, 0);
        assert_eq!(audit.pending_periods, 0);
        assert_eq!(audit.removed_unserved_periods, 1);

        let unpolled = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &params_digest(None),
            )
            .unwrap();
        registry.activate_with_clock(&token, &unpolled, "held", true);
        registry.set_clock_due_for_test(&token, &unpolled, Instant::now() - Duration::from_secs(1));
        registry.unsubscribe(&token, &unpolled);
        let audit = registry.clock_due_audit(Instant::now());
        assert_eq!(audit.removed_unpolled_due_periods, 1);
    }

    #[test]
    fn old_clock_schedule_run_cannot_cover_reactivated_schedule() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let id = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &params_digest(None),
            )
            .unwrap();
        registry.activate_with_clock(&token, &id, "held", true);
        let first_due = registry
            .subscription_state(&token, &id)
            .unwrap()
            .next_clock_at
            .unwrap();
        registry.mark_due_clock_ticks(first_due);
        let old_run = registry.clear_dirty(&token, &id).unwrap();
        registry.activate_with_clock(&token, &id, "changed", false);
        assert_eq!(
            registry.clock_due_audit(first_due).retired_unserved_periods,
            1
        );
        registry.activate_with_clock(&token, &id, "changed", true);
        let new_due = registry
            .subscription_state(&token, &id)
            .unwrap()
            .next_clock_at
            .unwrap();
        registry.mark_due_clock_ticks(new_due);
        registry.note_clock_snapshot_evaluated(
            &token,
            &id,
            old_run.clock_schedule_epoch,
            old_run.clock_due_generation,
            Instant::now(),
        );
        let audit = registry.clock_due_audit(new_due);
        assert_eq!(audit.covered_periods, 0);
        assert_eq!(audit.pending_periods, 1);
    }

    #[test]
    fn late_multi_period_clock_coverage_survives_quiet_report_interval() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let id = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &params_digest(None),
            )
            .unwrap();
        registry.activate_with_clock(&token, &id, "held", true);
        let now = Instant::now();
        registry.set_clock_due_for_test(
            &token,
            &id,
            now - Duration::from_millis(2 * CLOCK_TICK_MS + 1_000),
        );
        assert_eq!(registry.mark_due_clock_ticks(now), 1);
        let work = registry.clear_dirty(&token, &id).unwrap();
        assert_eq!(work.clock_due_generation, 3);
        registry.note_clock_snapshot_evaluated(
            &token,
            &id,
            work.clock_schedule_epoch,
            work.clock_due_generation,
            Instant::now(),
        );
        let audit = registry.clock_due_audit(Instant::now());
        assert_eq!(audit.due_periods, 3);
        assert_eq!(audit.covered_periods, 3);
        assert_eq!(audit.covering_evaluations, 1);
        assert_eq!(audit.late_covering_evaluations, 1);
        assert!(audit.max_cover_lateness_ms >= 2 * CLOCK_TICK_MS);
        assert_eq!(audit.pending_periods, 0);
        assert_eq!(audit.overdue_subscriptions, 0);
    }

    #[test]
    fn subscribe_catchup_consumes_only_pre_reread_acts() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let id = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &params_digest(None),
            )
            .unwrap();
        registry.mark_content_event_with_act(Some(101));
        assert_eq!(registry.activate(&token, &id, "first"), Some(true));
        let catchup = registry.clear_dirty(&token, &id).unwrap();
        assert_eq!(catchup.content_acts, vec![101]);
        // A second commit during the synchronous reread survives its second
        // activation and belongs to the next push scheduler run.
        registry.mark_content_event_with_act(Some(102));
        assert_eq!(registry.activate(&token, &id, "catchup"), Some(true));
        registry.enqueue_dirty_with_trigger(
            &token,
            &id,
            true,
            crate::need_metrics::Trigger::Subscribe,
        );
        let later = registry.clear_dirty(&token, &id).unwrap();
        assert_eq!(later.content_acts, vec![102]);
    }

    #[test]
    fn later_content_preserves_queued_forcing_trigger_attribution() {
        use crate::need_metrics::Trigger;

        for trigger in [
            Trigger::Grant,
            Trigger::Control,
            Trigger::Demotion,
            Trigger::Resync,
        ] {
            let mut registry = NeedRegistry::new();
            let token = registry.register_connection("alice", "db-1", true);
            let id = registry
                .subscribe_pending(
                    &token,
                    "alice",
                    "db-1",
                    binding(),
                    "attention.query.v1",
                    &params_digest(None),
                )
                .unwrap();
            registry.activate(&token, &id, "held");
            assert!(registry.enqueue_dirty_with_trigger(&token, &id, true, trigger));
            assert_eq!(registry.mark_content_event(), (1, 0, 0));
            assert!(registry.pop_dirty(&token).unwrap().forcing);
            let measured = registry.clear_dirty(&token, &id).unwrap();
            assert_eq!(measured.trigger, trigger);
        }
    }

    #[test]
    fn wake_paths_mark_the_documented_scope() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let digest = params_digest(None);
        let attention = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest,
            )
            .unwrap();
        let other = SurfaceBinding {
            kind: "alpha_tab".to_string(),
            package: "other.pkg".to_string(),
            install_event_id: "event-9".to_string(),
        };
        let search = registry
            .subscribe_pending(&token, "alice", "db-1", other, "records.search.v1", &digest)
            .unwrap();
        registry.activate(&token, &attention, "digest-1");
        registry.activate(&token, &search, "digest-2");
        assert_eq!(registry.mark_all_dirty(), 2);
        assert_eq!(registry.dirty_len(&token), 2);
        // Drain, then a package-scoped forcing wake names one.
        assert!(registry.pop_dirty(&token).is_some());
        assert!(registry.pop_dirty(&token).is_some());
        assert_eq!(registry.mark_forcing(Some("other.pkg")), 1);
        let entry = registry.pop_dirty(&token).unwrap();
        assert_eq!(entry.id, search);
        assert!(entry.forcing);
        assert_eq!(registry.mark_forcing(None), 2);
    }

    #[test]
    fn sink_and_footing_follow_the_connection() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", false);
        assert_eq!(
            registry.connection_footing(&token),
            Some(("alice".to_string(), false))
        );
        assert!(registry.set_connection_member(&token, true));
        assert_eq!(
            registry.connection_footing(&token),
            Some(("alice".to_string(), true))
        );
        assert!(registry
            .connection_footing(&ConnectionToken::mint())
            .is_none());
        let (sender, _receiver) = tokio::sync::mpsc::channel(SINK_CAPACITY);
        assert!(registry.register_sink(&token, sender));
        assert!(registry.sink_sender(&token).is_some());
        assert!(!registry.register_sink(&ConnectionToken::mint(), tokio::sync::mpsc::channel(1).0));
        // Budget is per connection: exhaust the burst, then defer.
        for _ in 0..BUDGET_BURST {
            assert!(registry.try_take_budget(&token, 0));
        }
        assert!(!registry.try_take_budget(&token, 0));
        assert!(!registry.connection_tokens().is_empty());
    }

    #[test]
    fn connection_forcing_and_stale_restore_stay_scoped() {
        let mut registry = NeedRegistry::new();
        let first = registry.register_connection("alice", "db-1", true);
        let second = registry.register_connection("alice", "db-1", true);
        let digest = params_digest(None);
        let id = registry
            .subscribe_pending(
                &first,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest,
            )
            .unwrap();
        registry.activate(&first, &id, "digest-1");
        // Per-connection forcing touches only that connection.
        assert_eq!(registry.mark_connection_forcing(&first), 1);
        assert_eq!(registry.dirty_len(&first), 1);
        assert_eq!(registry.dirty_len(&second), 0);
        assert_eq!(
            registry.mark_connection_forcing(&ConnectionToken::mint()),
            0
        );
        // Restoring a flushed set re-arms live flags and tombstones.
        let (sender, _receiver) = tokio::sync::mpsc::channel(SINK_CAPACITY);
        assert!(registry.register_sink(&first, sender));
        assert!(registry.mark_stale(&first, &id));
        let ids = registry.take_stale_ids(&first);
        assert_eq!(ids, vec![id.clone()]);
        registry.restore_stale_ids(&first, ids);
        assert!(registry.stale_pending(&first));
        assert_eq!(registry.take_stale_ids(&first), vec![id.clone()]);
        // Unknown connections restore to nothing.
        registry.restore_stale_ids(&ConnectionToken::mint(), vec![id]);
    }

    fn active_subscription(registry: &mut NeedRegistry, token: &ConnectionToken) -> SubscriptionId {
        let digest = params_digest(None);
        let id = registry
            .subscribe_pending(
                token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest,
            )
            .unwrap();
        registry.activate(token, &id, "digest-1");
        id
    }

    #[test]
    fn atomic_emit_sends_and_advances_under_one_lock() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let id = active_subscription(&mut registry, &token);
        let (sender, mut receiver) = tokio::sync::mpsc::channel(SINK_CAPACITY);
        assert!(registry.register_sink(&token, sender));
        let disposition = registry.emit_need(
            &token,
            &id,
            Some("digest-1"),
            "digest-2",
            "rows-2",
            json!({"records": []}),
            Some(1_700_000_000_000),
        );
        assert_eq!(disposition, EmitDisposition::Sent);
        let state = registry.subscription_state(&token, &id).unwrap();
        assert_eq!(state.delivery, 1);
        assert_eq!(state.baseline.as_deref(), Some("digest-2"));
        let frame = receiver.try_recv().unwrap();
        let NeedSinkFrame::Need(need) = frame else {
            panic!("expected a need frame");
        };
        assert_eq!(need.as_of_ms, Some(1_700_000_000_000));
    }

    #[test]
    fn keyed_hint_is_result_diff_only_and_isolated_by_params() {
        use crate::keyed_freshness::{KeyedFingerprint, GRAPH_NEIGHBOURS_KEY};
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let id = active_subscription(&mut registry, &token);
        let (sender, mut receiver) = tokio::sync::mpsc::channel(SINK_CAPACITY);
        assert!(registry.register_sink(&token, sender));
        for seed in ["seed1", "seed2"] {
            assert_eq!(
                registry.admit_keyed_read(
                    &token,
                    &id,
                    "alice",
                    "db-1",
                    "agent.attention-cockpit",
                    "event-1",
                    KeyedFingerprint {
                        key: GRAPH_NEIGHBOURS_KEY.to_string(),
                        params: json!({"seed_id": seed}),
                        params_digest: seed.to_string(),
                        revision: "visible-a".to_string(),
                        relations: ["records".to_string(), "links".to_string()].into(),
                    },
                ),
                Some(false)
            );
        }
        registry.clear_dirty(&token, &id).unwrap();
        // Hidden-only writes have the same viewer result: no frame, counter,
        // or fingerprint movement. The paired visible leg prevents vacuity.
        for _ in 0..3 {
            assert_eq!(
                registry.emit_keyed_hint(
                    &token,
                    &id,
                    GRAPH_NEIGHBOURS_KEY,
                    "seed2",
                    "visible-a",
                    "visible-a"
                ),
                EmitDisposition::Gone
            );
        }
        assert!(receiver.try_recv().is_err());
        let quiet = registry.subscription_state(&token, &id).unwrap();
        assert_eq!(quiet.delivery, 0);
        assert_eq!(
            quiet.keyed.revision(GRAPH_NEIGHBOURS_KEY, "seed2"),
            Some("visible-a")
        );
        assert_eq!(
            registry.emit_keyed_hint(
                &token,
                &id,
                GRAPH_NEIGHBOURS_KEY,
                "seed2",
                "visible-a",
                "visible-b"
            ),
            EmitDisposition::Sent
        );
        let NeedSinkFrame::Keyed(hint) = receiver.try_recv().unwrap() else {
            panic!("keyed hint expected")
        };
        assert_eq!(
            hint.key,
            crate::keyed_freshness::variant_handle(GRAPH_NEIGHBOURS_KEY, "seed2")
        );
        assert_eq!(hint.at_revision, "visible-b");
        assert_eq!(hint.delivery, 1);
        let state = registry.subscription_state(&token, &id).unwrap();
        assert_eq!(
            state.keyed.revision(GRAPH_NEIGHBOURS_KEY, "seed1"),
            Some("visible-a")
        );
        assert_eq!(
            state.keyed.revision(GRAPH_NEIGHBOURS_KEY, "seed2"),
            Some("visible-b")
        );
        assert_eq!(
            registry.emit_keyed_hint(
                &token,
                &id,
                GRAPH_NEIGHBOURS_KEY,
                "seed2",
                "visible-a",
                "visible-c"
            ),
            EmitDisposition::Gone
        );
        registry.unsubscribe(&token, &id);
        assert_eq!(
            registry.emit_keyed_hint(
                &token,
                &id,
                GRAPH_NEIGHBOURS_KEY,
                "seed2",
                "visible-b",
                "visible-c"
            ),
            EmitDisposition::Gone
        );
    }

    #[test]
    fn keyed_table_filter_only_schedules_intersecting_known_events() {
        use crate::keyed_freshness::{KeyedFingerprint, GRAPH_NEIGHBOURS_KEY};
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let id = active_subscription(&mut registry, &token);
        registry
            .admit_keyed_read(
                &token,
                &id,
                "alice",
                "db-1",
                "agent.attention-cockpit",
                "event-1",
                KeyedFingerprint {
                    key: GRAPH_NEIGHBOURS_KEY.to_string(),
                    params: json!({"seed_id":"one"}),
                    params_digest: "one".into(),
                    revision: "same".into(),
                    relations: ["links".to_string()].into(),
                },
            )
            .unwrap();
        registry.clear_dirty(&token, &id).unwrap();
        registry.mark_content_event_with_act_and_type(None, Some("record.updated"));
        assert!(
            !registry
                .subscription_state(&token, &id)
                .unwrap()
                .keyed_dirty
        );
        registry.mark_content_event_with_act_and_type(None, Some("link.added"));
        assert!(
            registry
                .subscription_state(&token, &id)
                .unwrap()
                .keyed_dirty
        );
    }

    #[test]
    fn atomic_emit_drops_on_drift_revocation_or_teardown() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let id = active_subscription(&mut registry, &token);
        let (sender, _receiver) = tokio::sync::mpsc::channel(SINK_CAPACITY);
        assert!(registry.register_sink(&token, sender));
        // Baseline drift (a newer computation or teardown won): silent.
        assert_eq!(
            registry.emit_need(
                &token,
                &id,
                Some("digest-0"),
                "digest-2",
                "rows-2",
                json!({}),
                None
            ),
            EmitDisposition::Gone
        );
        // Revoked access: silent, even on the compared baseline.
        assert!(registry.set_access_valid(&token, false));
        assert_eq!(
            registry.emit_need(
                &token,
                &id,
                Some("digest-1"),
                "digest-2",
                "rows-2",
                json!({}),
                None
            ),
            EmitDisposition::Gone
        );
        assert!(registry.set_access_valid(&token, true));
        // Unknown id after unsubscribe: silent.
        assert!(registry.unsubscribe(&token, &id));
        assert_eq!(
            registry.emit_need(
                &token,
                &id,
                Some("digest-1"),
                "digest-2",
                "rows-2",
                json!({}),
                None
            ),
            EmitDisposition::Gone
        );
    }

    #[test]
    fn full_sink_close_tombstones_and_flush_names_it() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let id = active_subscription(&mut registry, &token);
        // Capacity-1 sink, pre-filled: both the close frame and any later
        // frame are dropped on Full.
        let (sender, _receiver) = tokio::sync::mpsc::channel::<NeedSinkFrame>(1);
        sender
            .try_send(NeedSinkFrame::Stale(NeedStaleFrame {
                version: NEED_FRAME_VERSION.to_string(),
                subscriptions: Vec::new(),
            }))
            .unwrap();
        assert!(registry.register_sink(&token, sender));
        assert_eq!(
            registry.close_subscription(&token, &id, NeedClosedReason::AccessLost),
            CloseDisposition::Staled
        );
        // The record is gone, but the flush still names the closed id on
        // this connection only — the host's re-read refusal teaches it.
        assert!(registry.subscription_state(&token, &id).is_none());
        assert!(registry.stale_pending(&token));
        assert_eq!(registry.take_stale_ids(&token), vec![id.clone()]);
        assert!(!registry.stale_pending(&token));
        // Second close of the same id is silent and idempotent.
        assert_eq!(
            registry.close_subscription(&token, &id, NeedClosedReason::AccessLost),
            CloseDisposition::Silent
        );
    }

    #[test]
    fn closed_reasons_cover_every_scheduler_refusal() {
        // View loss and unmapped internals default closed, never a new wire value.
        for code in ["unauthorized", "archived", "missing", "wrong_record_type"] {
            assert_eq!(
                closed_reason_for_refusal(code),
                NeedClosedReason::AccessLost,
                "{code}"
            );
        }
        assert_eq!(
            closed_reason_for_refusal("disabled"),
            NeedClosedReason::Disabled
        );
        for code in ["removed", "missing_install"] {
            assert_eq!(
                closed_reason_for_refusal(code),
                NeedClosedReason::Removed,
                "{code}"
            );
        }
        assert_eq!(
            closed_reason_for_refusal("cas_mismatch"),
            NeedClosedReason::Reinstalled
        );
        for code in ["adoption_unverified", "declaration_mismatch"] {
            assert_eq!(
                closed_reason_for_refusal(code),
                NeedClosedReason::AdoptionChanged,
                "{code}"
            );
        }
        for code in [
            "digest_mismatch",
            "source_revision_unresolved",
            "not_renderable",
        ] {
            assert_eq!(
                closed_reason_for_refusal(code),
                NeedClosedReason::SourceChanged,
                "{code}"
            );
        }
        assert_eq!(
            closed_reason_for_refusal("undeclared_need"),
            NeedClosedReason::UndeclaredNeed
        );
        // Parameter/SQL-shape refusals cannot occur on a re-run of
        // already-accepted params; they map only as a closed label.
        for code in ["invalid_params", "unknown_need", ""] {
            assert_eq!(
                closed_reason_for_refusal(code),
                NeedClosedReason::AccessLost,
                "{code}"
            );
        }
    }

    #[test]
    fn gate_drift_covers_removed_adoption_and_source() {
        let held = GateSnapshot::test_snapshot();
        let mut moved = held.clone();
        moved.status = "removed".to_string();
        assert_eq!(
            gate_drift_reason(&held, &moved),
            Some(NeedClosedReason::Removed)
        );
        let mut moved = held.clone();
        moved.declaration_digest = "decl-2".to_string();
        assert_eq!(
            gate_drift_reason(&held, &moved),
            Some(NeedClosedReason::AdoptionChanged)
        );
        for case in [
            ("bundle", "bundle-2"),
            ("source_event", "source-2"),
            ("source_revision", "rev-2"),
        ] {
            let mut moved = held.clone();
            match case.0 {
                "bundle" => moved.bundle_sha256 = case.1.to_string(),
                "source_event" => moved.source_event_id = case.1.to_string(),
                _ => moved.source_revision = case.1.to_string(),
            }
            assert_eq!(
                gate_drift_reason(&held, &moved),
                Some(NeedClosedReason::SourceChanged),
                "{}",
                case.0
            );
        }
    }

    #[test]
    fn params_digest_keys_distinct_subscriptions() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let search = params_digest(Some(&json!({"query": "Visible", "limit": 5})));
        let other = params_digest(Some(&json!({"query": "Other", "limit": 5})));
        assert_ne!(search, other);
        let first = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &search,
            )
            .unwrap();
        let second = registry
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &other,
            )
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(
            registry
                .subscription_state(&token, &first)
                .unwrap()
                .params_digest,
            search
        );
        assert_eq!(
            registry
                .subscription_state(&token, &second)
                .unwrap()
                .params_digest,
            other
        );
        assert_eq!(registry.connection_subscription_count(&token), 2);
    }

    #[test]
    fn per_account_cap_spans_connections() {
        let mut registry = NeedRegistry::new();
        let digest = params_digest(None);
        let first = registry.register_connection("alice", "db-1", true);
        let second = registry.register_connection("alice", "db-1", true);
        for index in 0..MAX_SUBSCRIPTIONS_PER_ACCOUNT_DB {
            let token = if index % 2 == 0 { &first } else { &second };
            registry
                .subscribe_pending(
                    token,
                    "alice",
                    "db-1",
                    binding(),
                    "attention.query.v1",
                    &digest,
                )
                .unwrap();
        }
        assert_eq!(
            registry.subscribe_pending(
                &first,
                "alice",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest
            ),
            Err(SubscribeRefusal::SubscriptionLimit)
        );
        // Another account's share is unaffected.
        let other = registry.register_connection("bea", "db-1", true);
        assert!(registry
            .subscribe_pending(
                &other,
                "bea",
                "db-1",
                binding(),
                "attention.query.v1",
                &digest
            )
            .is_ok());
    }

    #[test]
    fn full_sink_need_marks_stale_for_reread() {
        let mut registry = NeedRegistry::new();
        let token = registry.register_connection("alice", "db-1", true);
        let id = active_subscription(&mut registry, &token);
        let (sender, _receiver) = tokio::sync::mpsc::channel::<NeedSinkFrame>(1);
        sender
            .try_send(NeedSinkFrame::Stale(NeedStaleFrame {
                version: NEED_FRAME_VERSION.to_string(),
                subscriptions: Vec::new(),
            }))
            .unwrap();
        assert!(registry.register_sink(&token, sender));
        assert_eq!(
            registry.emit_need(
                &token,
                &id,
                Some("digest-1"),
                "digest-2",
                "rows-2",
                json!({"records": []}),
                None,
            ),
            EmitDisposition::Stale
        );
        // The frame is dropped but nothing is lost: the stale flag and flush
        // name the id, and the baseline is untouched so the host's
        // `if_revision` re-read still observes the missed digest.
        let state = registry.subscription_state(&token, &id).unwrap();
        assert!(state.stale);
        assert_eq!(state.baseline.as_deref(), Some("digest-1"));
        assert_eq!(state.delivery, 0);
        assert!(registry.stale_pending(&token));
        assert_eq!(registry.take_stale_ids(&token), vec![id]);
    }
}
