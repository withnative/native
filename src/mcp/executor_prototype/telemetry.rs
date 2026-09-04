//! Privacy-safe operational telemetry for controlled executor dogfood.
//!
//! This is deliberately separate from fixture tracing. The sink receives only
//! bytes produced from the closed types below; callers cannot attach arbitrary
//! JSON, diagnostics, arguments, results, identifiers, or plan evidence.

use std::collections::HashSet;
use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use chrono::{SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

pub const DEFAULT_RETENTION_DAYS: u16 = 7;
const MAX_RETENTION_DAYS: u16 = 30;
const TELEMETRY_SCHEMA: &str = "native.mcp-executor-telemetry.v1";
const DELIVERY_QUEUE_CAPACITY: usize = 1_024;

/// Delivery boundary for the allowlist-only serialized event.
///
/// Implementations must not retry or persist a rejected payload. Returning an
/// error increments the process health counter but never changes an executor
/// response or plan transition.
pub trait ExecutorTelemetrySink: Send + Sync {
    fn emit(&self, event: &[u8]) -> std::io::Result<()>;
}

/// The hosted structured-log boundary: exactly one JSON object per stderr
/// line. Platform retention is configured outside the process.
#[derive(Debug, Default)]
pub struct StructuredLogTelemetrySink;

impl ExecutorTelemetrySink for StructuredLogTelemetrySink {
    fn emit(&self, event: &[u8]) -> std::io::Result<()> {
        std::str::from_utf8(event)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let mut stderr = std::io::stderr().lock();
        stderr.write_all(event)?;
        stderr.write_all(b"\n")
    }
}

/// Process-scoped telemetry state shared by every HTTP router instance.
///
/// The HMAC key is generated in memory and is neither logged nor persisted.
/// Correlations are consequently unlinkable across process restarts.
pub struct ExecutorTelemetryContext {
    delivery: mpsc::SyncSender<DeliveryMessage>,
    delivery_health: Arc<DeliveryHealth>,
    hmac_key: Zeroizing<[u8; 32]>,
    delivery_order: Mutex<()>,
    next_sequence: AtomicU64,
    next_request: AtomicU64,
    hosted_manifests: Mutex<HashSet<String>>,
    hosted_sessions: Mutex<HashSet<String>>,
    retention_days: u16,
}

#[derive(Default)]
struct DeliveryHealth {
    dropped_total: AtomicU64,
    dropped_pending: AtomicU64,
}

enum DeliveryMessage {
    Event(Vec<u8>),
    Flush(mpsc::SyncSender<()>),
}

impl ExecutorTelemetryContext {
    pub fn new(sink: Arc<dyn ExecutorTelemetrySink>, retention_days: u16) -> Result<Arc<Self>> {
        if !(1..=MAX_RETENTION_DAYS).contains(&retention_days) {
            return Err(Error::engine(format!(
                "executor telemetry retention must be between 1 and {MAX_RETENTION_DAYS} days"
            )));
        }
        let delivery_health = Arc::new(DeliveryHealth::default());
        let worker_health = delivery_health.clone();
        let (delivery, receiver) = mpsc::sync_channel(DELIVERY_QUEUE_CAPACITY);
        std::thread::Builder::new()
            .name("mcp-executor-telemetry".into())
            .spawn(move || delivery_worker(receiver, sink, worker_health))
            .map_err(|error| {
                Error::engine(format!("start executor telemetry delivery worker: {error}"))
            })?;
        Ok(Arc::new(Self {
            delivery,
            delivery_health,
            hmac_key: Zeroizing::new(rand::random()),
            delivery_order: Mutex::new(()),
            next_sequence: AtomicU64::new(1),
            next_request: AtomicU64::new(1),
            hosted_manifests: Mutex::new(HashSet::new()),
            hosted_sessions: Mutex::new(HashSet::new()),
            retention_days,
        }))
    }

    pub fn structured_log() -> Result<Arc<Self>> {
        Self::new(Arc::new(StructuredLogTelemetrySink), DEFAULT_RETENTION_DAYS)
    }

    pub fn health(&self) -> ExecutorTelemetryHealth {
        ExecutorTelemetryHealth {
            dropped_event_count: self.delivery_health.dropped_total.load(Ordering::Relaxed),
            recovery_pending: self.delivery_health.dropped_pending.load(Ordering::Relaxed) > 0,
            retention_days: self.retention_days,
        }
    }

    /// Wait until every event already accepted by the bounded queue has made
    /// one sink-delivery attempt. This is for tests and controlled shutdown;
    /// request handling never calls it.
    pub fn flush(&self) -> Result<()> {
        let (done, acknowledgement) = mpsc::sync_channel(0);
        self.delivery
            .send(DeliveryMessage::Flush(done))
            .map_err(|_| Error::engine("executor telemetry delivery worker stopped"))?;
        acknowledgement
            .recv()
            .map_err(|_| Error::engine("executor telemetry delivery worker stopped"))
    }

    pub(crate) fn observe_hosted_authorization_denied(
        &self,
        manifest_sha256: Option<&str>,
        server_revision: &str,
    ) {
        let denied_attempt = Uuid::new_v4().to_string();
        let session = SessionContext {
            correlation: self.correlation("session", &denied_attempt),
            surface: TelemetrySurface::Executor,
            manifest_sha256: manifest_sha256
                .filter(|digest| valid_sha256(digest))
                .map(str::to_owned),
            server_revision: normalize_revision(server_revision),
            engine: TelemetryEngine::Hosted,
            transport: TelemetryTransport::Http,
        };
        self.deliver(
            &session,
            EventSpec {
                phase: TelemetryPhase::AuthorizationChecked,
                outcome: TelemetryOutcome::Rejected,
                error_class: Some(TelemetryErrorClass::AuthorizationDenied),
                ..EventSpec::default()
            },
        );
    }

    pub(super) fn bind(
        self: &Arc<Self>,
        raw_session_binding: &str,
        manifest_sha256: &str,
        server_revision: &str,
        engine: TelemetryEngine,
        transport: TelemetryTransport,
    ) -> BoundExecutorTelemetry {
        BoundExecutorTelemetry {
            context: self.clone(),
            session: SessionContext {
                correlation: self.correlation("session", raw_session_binding),
                surface: TelemetrySurface::Executor,
                manifest_sha256: valid_sha256(manifest_sha256).then(|| manifest_sha256.to_owned()),
                server_revision: normalize_revision(server_revision),
                engine,
                transport,
            },
        }
    }

    /// Bind one principal-neutral hosted runtime/lens catalogue. A shared
    /// context may construct multiple routers, but each exact manifest emits
    /// `manifest_loaded` only once for the process.
    pub(crate) fn bind_hosted_manifest(
        self: &Arc<Self>,
        manifest_sha256: &str,
        manifest_bytes: usize,
    ) -> BoundExecutorTelemetry {
        let binding = format!("hosted-manifest:{manifest_sha256}");
        let telemetry = self.bind(
            &binding,
            manifest_sha256,
            crate::FULL_GIT_SHA,
            TelemetryEngine::Hosted,
            TelemetryTransport::Http,
        );
        let first = self
            .hosted_manifests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(binding);
        if first {
            telemetry.manifest_loaded(manifest_bytes, 0);
        }
        telemetry
    }

    fn correlation(&self, domain: &str, raw_identifier: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key[..])
            .expect("HMAC accepts every fixed-size process key");
        mac.update(domain.as_bytes());
        mac.update(&[0]);
        mac.update(raw_identifier.as_bytes());
        let digest = hex::encode(mac.finalize().into_bytes());
        format!("h1_{}", &digest[..32])
    }

    fn next_request_correlation(&self) -> String {
        let request = self.next_request.fetch_add(1, Ordering::Relaxed);
        self.correlation("request", &request.to_string())
    }

    fn event(&self, session: &SessionContext, spec: EventSpec) -> TelemetryEvent {
        TelemetryEvent {
            schema: TELEMETRY_SCHEMA,
            observed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            sequence: self.next_sequence.fetch_add(1, Ordering::Relaxed),
            event_id: Uuid::new_v4().to_string(),
            session: session.clone(),
            request: spec.request,
            phase: spec.phase,
            outcome: spec.outcome,
            error_class: spec.error_class,
            flags: spec.flags,
            counts: spec.counts,
            latency_bucket: spec.latency_bucket,
            sizes: spec.sizes,
        }
    }

    fn deliver(&self, session: &SessionContext, spec: EventSpec) {
        let _order = self
            .delivery_order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pending = self
            .delivery_health
            .dropped_pending
            .swap(0, Ordering::AcqRel);
        if pending > 0 {
            let recovery = self.event(
                session,
                EventSpec {
                    phase: TelemetryPhase::TelemetryDropped,
                    outcome: TelemetryOutcome::Dropped,
                    error_class: Some(TelemetryErrorClass::TelemetryDelivery),
                    flags: TelemetryFlags {
                        telemetry_dropped: true,
                        ..TelemetryFlags::default()
                    },
                    counts: TelemetryCounts {
                        dropped_event_bucket: dropped_bucket(
                            self.delivery_health.dropped_total.load(Ordering::Relaxed),
                        ),
                        ..TelemetryCounts::default()
                    },
                    ..EventSpec::default()
                },
            );
            if !self.enqueue(&recovery) {
                saturating_add(&self.delivery_health.dropped_pending, pending);
            }
        }

        let event = self.event(session, spec);
        self.enqueue(&event);
    }

    fn enqueue(&self, event: &TelemetryEvent) -> bool {
        let Ok(bytes) = serde_json::to_vec(event) else {
            record_delivery_drop(&self.delivery_health, 1);
            return false;
        };
        if self
            .delivery
            .try_send(DeliveryMessage::Event(bytes))
            .is_err()
        {
            record_delivery_drop(&self.delivery_health, 1);
            return false;
        }
        true
    }
}

fn delivery_worker(
    receiver: mpsc::Receiver<DeliveryMessage>,
    sink: Arc<dyn ExecutorTelemetrySink>,
    health: Arc<DeliveryHealth>,
) {
    while let Ok(message) = receiver.recv() {
        match message {
            DeliveryMessage::Event(event) => {
                if sink.emit(&event).is_err() {
                    record_delivery_drop(&health, 1);
                }
            }
            DeliveryMessage::Flush(done) => {
                let _ = done.send(());
            }
        }
    }
}

fn record_delivery_drop(health: &DeliveryHealth, count: u64) {
    saturating_add(&health.dropped_total, count);
    saturating_add(&health.dropped_pending, count);
}

fn saturating_add(counter: &AtomicU64, amount: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(amount))
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryEngine {
    Sqlite,
    #[cfg(feature = "postgres")]
    Postgres,
    #[cfg(feature = "turso-local")]
    TursoLocal,
    Hosted,
    // Kept in the versioned vocabulary for future adapters that cannot yet
    // report a qualified engine. Current constructors are exhaustive.
    #[allow(dead_code)]
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryTransport {
    Stdio,
    Http,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TelemetrySurface {
    Executor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TelemetryPhase {
    SessionStarted,
    ManifestLoaded,
    AuthorizationChecked,
    OperationSelected,
    ContractLoaded,
    ValidationCompleted,
    RepairReturned,
    PlanPrepared,
    PlanRevalidated,
    PlanClaimed,
    DispatchBegun,
    DispatchCompleted,
    PlanCompleted,
    ReplayReturned,
    OperationUnavailable,
    TelemetryDropped,
    // HTTP is request-scoped and has no truthful session-close boundary yet.
    // A future process lifecycle hook may emit this optional schema event.
    #[allow(dead_code)]
    SessionEnded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TelemetryOutcome {
    Started,
    Succeeded,
    Rejected,
    Repaired,
    Unavailable,
    Replayed,
    Indeterminate,
    Dropped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TelemetryErrorClass {
    SelectionError,
    ContractUnavailable,
    SchemaValidation,
    RuntimeValidation,
    AuthorizationDenied,
    ExecutionError,
    PlanExpired,
    PlanStale,
    PlanConflict,
    PlanIndeterminate,
    TelemetryDelivery,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExecutorTelemetryHealth {
    pub dropped_event_count: u64,
    pub recovery_pending: bool,
    pub retention_days: u16,
}

#[derive(Clone)]
pub(crate) struct BoundExecutorTelemetry {
    context: Arc<ExecutorTelemetryContext>,
    session: SessionContext,
}

impl BoundExecutorTelemetry {
    pub(crate) fn authorization_accepted(&self) {
        self.emit(EventSpec {
            phase: TelemetryPhase::AuthorizationChecked,
            outcome: TelemetryOutcome::Succeeded,
            ..EventSpec::default()
        });
    }
    pub(super) fn session_started(&self) {
        self.emit(EventSpec {
            phase: TelemetryPhase::SessionStarted,
            outcome: TelemetryOutcome::Started,
            ..EventSpec::default()
        });
    }

    pub(super) fn manifest_loaded(&self, manifest_bytes: usize, elapsed_ms: u64) {
        self.emit(EventSpec {
            phase: TelemetryPhase::ManifestLoaded,
            outcome: TelemetryOutcome::Succeeded,
            latency_bucket: latency_bucket(elapsed_ms),
            sizes: TelemetrySizes {
                contract_bytes: size_bucket(manifest_bytes),
                ..TelemetrySizes::default()
            },
            ..EventSpec::default()
        });
    }

    pub(super) fn authenticated_initialize(&self) {
        if self.session.transport == TelemetryTransport::Http
            && self
                .context
                .hosted_sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(self.session.correlation.clone())
        {
            self.session_started();
        }
    }

    pub(super) fn request(
        &self,
        executor: Option<&str>,
        operation: Option<&str>,
        raw_plan_id: Option<&str>,
    ) -> TelemetryRequest {
        TelemetryRequest {
            correlation: self.context.next_request_correlation(),
            plan_correlation: raw_plan_id.map(|plan_id| self.context.correlation("plan", plan_id)),
            executor: canonical_name(executor, false),
            operation: canonical_name(operation, true),
        }
    }

    pub(super) fn with_plan_correlation(
        &self,
        mut request: TelemetryRequest,
        raw_plan_id: &str,
    ) -> TelemetryRequest {
        request.plan_correlation = Some(self.context.correlation("plan", raw_plan_id));
        request
    }

    pub(super) fn emit(&self, spec: EventSpec) {
        self.context.deliver(&self.session, spec);
    }

    #[cfg(test)]
    pub(super) fn session_correlation(&self) -> &str {
        &self.session.correlation
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct SessionContext {
    correlation: String,
    surface: TelemetrySurface,
    manifest_sha256: Option<String>,
    server_revision: String,
    engine: TelemetryEngine,
    transport: TelemetryTransport,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(super) struct TelemetryRequest {
    correlation: String,
    plan_correlation: Option<String>,
    executor: String,
    operation: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(super) struct TelemetryFlags {
    pub repair_returned: bool,
    pub repair_retry: bool,
    pub described_before: bool,
    pub unreachable_advertised: bool,
    pub replayed: bool,
    pub stale_plan: bool,
    pub duplicate_effect_attempt: bool,
    pub telemetry_dropped: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(super) struct TelemetryCounts {
    pub attempt_bucket: &'static str,
    pub dispatch_count_bucket: &'static str,
    pub repair_count_bucket: &'static str,
    pub dropped_event_bucket: &'static str,
}

impl Default for TelemetryCounts {
    fn default() -> Self {
        Self {
            attempt_bucket: "0",
            dispatch_count_bucket: "0",
            repair_count_bucket: "0",
            dropped_event_bucket: "0",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(super) struct TelemetrySizes {
    pub request_bytes: &'static str,
    pub result_bytes: &'static str,
    pub contract_bytes: &'static str,
}

impl Default for TelemetrySizes {
    fn default() -> Self {
        Self {
            request_bytes: "not_measured",
            result_bytes: "not_measured",
            contract_bytes: "not_measured",
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct EventSpec {
    pub request: Option<TelemetryRequest>,
    pub phase: TelemetryPhase,
    pub outcome: TelemetryOutcome,
    pub error_class: Option<TelemetryErrorClass>,
    pub flags: TelemetryFlags,
    pub counts: TelemetryCounts,
    pub latency_bucket: &'static str,
    pub sizes: TelemetrySizes,
}

impl Default for EventSpec {
    fn default() -> Self {
        Self {
            request: None,
            phase: TelemetryPhase::SessionStarted,
            outcome: TelemetryOutcome::Started,
            error_class: None,
            flags: TelemetryFlags::default(),
            counts: TelemetryCounts::default(),
            latency_bucket: "not_measured",
            sizes: TelemetrySizes::default(),
        }
    }
}

#[derive(Serialize)]
struct TelemetryEvent {
    schema: &'static str,
    observed_at: String,
    sequence: u64,
    event_id: String,
    session: SessionContext,
    request: Option<TelemetryRequest>,
    phase: TelemetryPhase,
    outcome: TelemetryOutcome,
    error_class: Option<TelemetryErrorClass>,
    flags: TelemetryFlags,
    counts: TelemetryCounts,
    latency_bucket: &'static str,
    sizes: TelemetrySizes,
}

pub(super) fn latency_bucket(elapsed_ms: u64) -> &'static str {
    match elapsed_ms {
        0..=9 => "lt_10ms",
        10..=49 => "10_49ms",
        50..=199 => "50_199ms",
        200..=999 => "200_999ms",
        1_000..=4_999 => "1_4s",
        5_000..=14_999 => "5_14s",
        _ => "15s_plus",
    }
}

pub(super) fn size_bucket(bytes: usize) -> &'static str {
    match bytes {
        0 => "0",
        1..=255 => "1_255",
        256..=1_023 => "256_1023",
        1_024..=4_095 => "1k_4k",
        4_096..=16_383 => "4k_16k",
        _ => "16k_plus",
    }
}

pub(super) fn attempt_bucket(attempts: u64) -> &'static str {
    match attempts {
        0 => "0",
        1 => "1",
        2 => "2",
        3 => "3",
        _ => "4_plus",
    }
}

pub(super) fn dispatch_bucket(dispatches: u64) -> &'static str {
    match dispatches {
        0 => "0",
        1 => "1",
        _ => "2_plus",
    }
}

pub(super) fn repair_bucket(repairs: u64) -> &'static str {
    match repairs {
        0 => "0",
        1 => "1",
        2 => "2",
        _ => "3_plus",
    }
}

fn dropped_bucket(dropped: u64) -> &'static str {
    match dropped {
        0 => "0",
        1 => "1",
        2 => "2",
        _ => "3_plus",
    }
}

fn canonical_name(value: Option<&str>, operation: bool) -> String {
    let Some(value) = value else {
        return "unknown".into();
    };
    let max = if operation { 96 } else { 64 };
    let valid = !value.is_empty()
        && value.len() <= max
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b'_'
                || operation && byte == b'.'
        });
    if valid {
        value.into()
    } else {
        "unknown".into()
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn normalize_revision(value: &str) -> String {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        value.into()
    } else {
        "0".repeat(40)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlations_are_domain_separated_restart_local_and_delivery_is_fail_open() {
        assert!(ExecutorTelemetryContext::new(Arc::new(TestTelemetrySink::default()), 0,).is_err());
        assert!(ExecutorTelemetryContext::new(
            Arc::new(TestTelemetrySink::default()),
            MAX_RETENTION_DAYS + 1,
        )
        .is_err());
        let sink = Arc::new(TestTelemetrySink::default());
        let context = ExecutorTelemetryContext::new(sink.clone(), DEFAULT_RETENTION_DAYS).unwrap();
        let bound = context.bind(
            "raw account and database",
            &"a".repeat(64),
            &"b".repeat(40),
            TelemetryEngine::Hosted,
            TelemetryTransport::Http,
        );
        let request = bound.request(
            Some("records_delete"),
            Some("delete_record"),
            Some("raw-plan-id"),
        );
        assert_ne!(
            request.correlation,
            request.plan_correlation.clone().unwrap()
        );
        assert!(!request.correlation.contains("raw"));
        assert!(!bound.session_correlation().contains("account"));

        sink.fail_next(1);
        bound.emit(EventSpec {
            request: Some(request.clone()),
            phase: TelemetryPhase::OperationSelected,
            outcome: TelemetryOutcome::Succeeded,
            ..EventSpec::default()
        });
        context.flush().unwrap();
        assert_eq!(context.health().dropped_event_count, 1);

        bound.emit(EventSpec {
            request: Some(request),
            phase: TelemetryPhase::ValidationCompleted,
            outcome: TelemetryOutcome::Succeeded,
            ..EventSpec::default()
        });
        context.flush().unwrap();
        let events = sink.events();
        assert_eq!(events.len(), 2);
        let recovery: serde_json::Value = serde_json::from_slice(&events[0]).unwrap();
        let delivered: serde_json::Value = serde_json::from_slice(&events[1]).unwrap();
        assert_eq!(recovery["phase"], "telemetry_dropped");
        assert_eq!(recovery["request"], serde_json::Value::Null);
        assert_eq!(recovery["counts"]["dropped_event_bucket"], "1");
        assert_eq!(delivered["phase"], "validation_completed");

        let (entered, entered_rx) = mpsc::sync_channel(1);
        let (release, release_rx) = mpsc::sync_channel(0);
        let blocking = Arc::new(BlockingSink {
            entered,
            release: Mutex::new(release_rx),
            blocked: std::sync::atomic::AtomicBool::new(false),
        });
        let bounded = ExecutorTelemetryContext::new(blocking, DEFAULT_RETENTION_DAYS).unwrap();
        let bounded_session = bounded.bind(
            "bounded-delivery",
            &"c".repeat(64),
            &"d".repeat(40),
            TelemetryEngine::Sqlite,
            TelemetryTransport::Stdio,
        );
        bounded_session.session_started();
        entered_rx.recv().unwrap();
        for _ in 0..=DELIVERY_QUEUE_CAPACITY {
            bounded_session.manifest_loaded(1, 1);
        }
        assert!(bounded.health().dropped_event_count > 0);
        release.send(()).unwrap();
        bounded.flush().unwrap();
    }
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct TestTelemetrySink {
    fail_next: AtomicU64,
    events: std::sync::Mutex<Vec<Vec<u8>>>,
}

#[cfg(test)]
impl TestTelemetrySink {
    pub(super) fn events(&self) -> Vec<Vec<u8>> {
        self.events.lock().unwrap().clone()
    }

    pub(super) fn fail_next(&self, count: u64) {
        self.fail_next.store(count, Ordering::Relaxed);
    }
}

#[cfg(test)]
impl ExecutorTelemetrySink for TestTelemetrySink {
    fn emit(&self, event: &[u8]) -> std::io::Result<()> {
        if self
            .fail_next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(std::io::Error::other("injected telemetry sink failure"));
        }
        self.events.lock().unwrap().push(event.to_vec());
        Ok(())
    }
}

#[cfg(test)]
struct BlockingSink {
    entered: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
    blocked: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl ExecutorTelemetrySink for BlockingSink {
    fn emit(&self, _event: &[u8]) -> std::io::Result<()> {
        if !self
            .blocked
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            self.entered.send(()).map_err(std::io::Error::other)?;
            self.release
                .lock()
                .unwrap()
                .recv()
                .map_err(std::io::Error::other)?;
        }
        Ok(())
    }
}
