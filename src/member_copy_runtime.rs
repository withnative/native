//! D2 member-copy runtime composition.
//!
//! Owns the serialized background controller, the session snapshot reconcile,
//! and shutdown, over the actual-client core APIs (`member_copy_driver`,
//! `member_copy_serving::ReceiptEligibility`, `member_copy_transport`,
//! `member_copy_client`).
//!
//! Ownership: one `Arc<tokio::sync::Mutex<MemberCopyDriver>>` is shared by the
//! controller and the background refresh task; the async mutex serializes
//! driver access only. The session mutex is never held across an `await`.
//!
//! Rules (root decisions a2ba962/f4d2e11):
//! - Publish only under the driver's pure `ReceiptEligibility::HeldValidated`.
//! - `NotServable` retires captured leases (`driver.recover_if_eligible` /
//!   `quiesce`) BEFORE `session.clear`; held files are kept.
//! - A `MetadataRefreshed`/`Admitted`/`Unchanged` republishes the owner-derived
//!   snapshot (fresh serving gate).
//! - Startup publishes a validated held copy offline before the network await.
//! - Background refresh is serialized, coalesced, missed-tick `Delay`, one
//!   immediate follow-up (no burst), bounded attempt, network-recovery probe,
//!   and at most one genuine account-change follow-up.
//! - Shutdown stops, waits for the in-flight bounded attempt, then quiesces.
//! - Cadence is runtime-private constants (no new config surface).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{watch, Mutex};

use crate::error::Result;
use crate::mcp::member_stdio::{MemberServedSnapshot, MemberStdioSession};
use crate::mcp::registry::ToolRegistry;
use crate::mcp::ExposureProfile;
use crate::mcp::{register_builtin_tools, register_surface_tools};
use crate::member_copy_driver::{MemberCopyDriver, RefreshDisposition};
use crate::member_copy_lifecycle::{CopyStatus, RemovedCause};
use crate::member_copy_serving::ReceiptEligibility;

const MEMBER_COPY_SCHEDULE_INTERVAL: Duration = Duration::from_secs(120);
const MEMBER_COPY_MANUAL_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MEMBER_COPY_ATTEMPT_BUDGET: Duration = Duration::from_secs(270);
const MEMBER_COPY_NETWORK_RECOVERY_PROBE: Duration = Duration::from_secs(10);

struct BackgroundRefresh {
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl BackgroundRefresh {
    async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = self.task.await;
    }
}

pub struct MemberCopyRuntime {
    driver: Arc<Mutex<MemberCopyDriver>>,
    profile: ExposureProfile,
    session: Arc<MemberStdioSession>,
    refresh: Option<BackgroundRefresh>,
}

impl MemberCopyRuntime {
    /// `profile` is the CLI-selected MCP surface profile, propagated into the
    /// no-held surface and every newly gated serving registry.
    pub fn new(driver: MemberCopyDriver, profile: ExposureProfile) -> Self {
        let surface = Arc::new(member_registry(profile));
        let session = Arc::new(MemberStdioSession::new(surface));
        Self {
            driver: Arc::new(Mutex::new(driver)),
            profile,
            session,
            refresh: None,
        }
    }

    pub fn session(&self) -> Arc<MemberStdioSession> {
        self.session.clone()
    }

    /// Startup: publish a validated held copy offline (no network) before the
    /// bounded network await; a changed/missing selection publishes nothing.
    pub async fn publish_offline_held_if_eligible(&mut self) -> Result<()> {
        self.reconcile_snapshot().await
    }

    /// One bounded, serialized refresh bracketed by eligibility reconciles.
    /// The pre-reconcile retires/clears a `NotServable` selection before the
    /// network await; the post-reconcile ALWAYS runs (including on `Err`/
    /// `TimedOut`), so an unchanged valid receipt keeps or republishes the
    /// safely reopened held copy.
    pub async fn refresh_and_publish(&mut self) -> Result<RefreshDisposition> {
        self.reconcile_snapshot().await?;
        let disposition = {
            let mut driver = self.driver.lock().await;
            driver.refresh_bounded(MEMBER_COPY_ATTEMPT_BUDGET).await
        };
        self.reconcile_snapshot().await?;
        disposition
    }

    /// Publish or clear from the driver's pure eligibility. `recover_if_eligible`
    /// retires the owner (files kept) on `NotServable` or a failed guarded read
    /// before returning.
    pub async fn reconcile_snapshot(&mut self) -> Result<()> {
        reconcile_with(&self.driver, &self.session, self.profile).await
    }

    /// Serve stdin: offline publish, start the serialized background refresh,
    /// serve until EOF, then stop and quiesce.
    pub async fn run_stdio(&mut self) -> Result<()> {
        self.publish_offline_held_if_eligible().await?;
        self.start_background_refresh();
        let served = self.session.serve_stdio().await;
        self.shutdown().await;
        served
    }

    /// Deterministic test seam: inject the poll/schedule cadence.
    fn start_background_refresh(&mut self) {
        self.start_background_refresh_with(
            MEMBER_COPY_MANUAL_POLL_INTERVAL,
            MEMBER_COPY_SCHEDULE_INTERVAL,
        );
    }

    fn start_background_refresh_with(&mut self, poll: Duration, schedule: Duration) {
        let (shutdown, mut receiver) = watch::channel(false);
        let driver = self.driver.clone();
        let session = self.session.clone();
        let profile = self.profile;
        let task = tokio::spawn(async move {
            let mut poll = tokio::time::interval(poll);
            poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Immediate first attempt, then an absolute-deadline cadence.
            let mut scheduled = tokio::time::Instant::now();
            let mut network_probe_at: Option<tokio::time::Instant> = None;
            let mut last_monotonic = tokio::time::Instant::now();
            let mut last_wall = std::time::SystemTime::now();
            loop {
                tokio::select! {
                    // Biased: a shutdown request always wins over a ready tick,
                    // so stop cannot race a new attempt into existence.
                    biased;
                    changed = receiver.changed() => {
                        if changed.is_err() || *receiver.borrow() { break; }
                    }
                    _ = poll.tick() => {
                        // Re-check after winning the tick: never start an attempt
                        // once stop was requested.
                        if *receiver.borrow() { break; }
                        let now = tokio::time::Instant::now();
                        let wall = std::time::SystemTime::now();
                        let monotonic_elapsed = now.saturating_duration_since(last_monotonic);
                        let wall_elapsed = wall.duration_since(last_wall).unwrap_or_default();
                        let woke = wake_detected(wall_elapsed, monotonic_elapsed);
                        last_monotonic = now;
                        last_wall = wall;
                        if !refresh_due(now, scheduled, network_probe_at) && !woke { continue; }
                        // Pre-retire/clear a NotServable selection BEFORE the
                        // network await, so a stale snapshot never serves during
                        // the attempt.
                        let _ = reconcile_with(&driver, &session, profile).await;
                        let Some(mut disposition) =
                            refresh_unless_stopping(&driver, &receiver).await
                        else {
                            break;
                        };
                        // A genuine account change is two-step: exactly ONE
                        // immediate follow-up per AccountChanged attempt; later
                        // account switches get their own. Retain the FINAL
                        // attempt result for the probe/reconcile decisions. A
                        // stop that arrives while the follow-up waits on the
                        // driver lock skips the follow-up and keeps the first
                        // result.
                        if matches!(
                            &disposition,
                            Ok(RefreshDisposition::Removed { cause })
                                if *cause == RemovedCause::AccountChanged
                        ) {
                            if let Some(followup) =
                                refresh_unless_stopping(&driver, &receiver).await
                            {
                                disposition = followup;
                            }
                        }
                        let completed = tokio::time::Instant::now();
                        // ALWAYS re-evaluate/reconcile after the attempt,
                        // including Err/TimedOut: an unchanged valid receipt
                        // stays servable.
                        let _ = reconcile_with(&driver, &session, profile).await;
                        scheduled = next_scheduled_deadline(scheduled, completed, schedule);
                        // A network error OR a budget timeout is probe-worthy:
                        // the outcome is unknown, so retry sooner than the full
                        // cadence. The FINAL attempt result (after any account
                        // follow-up) is used.
                        network_probe_at =
                            match &disposition {
                                Err(_) | Ok(RefreshDisposition::TimedOut) => {
                                    Some(completed + MEMBER_COPY_NETWORK_RECOVERY_PROBE)
                                }
                                _ => None,
                            };
                    }
                }
            }
        });
        self.refresh = Some(BackgroundRefresh { shutdown, task });
    }

    /// Request stop, wait for the in-flight bounded attempt (never dropped
    /// mid-admission), then quiesce the owner and clear the session.
    pub async fn shutdown(&mut self) {
        if let Some(refresh) = self.refresh.take() {
            refresh.stop().await;
        }
        let mut driver = self.driver.lock().await;
        driver.quiesce().await;
        let status = driver.serving().lifecycle_status();
        drop(driver);
        self.session.clear(status);
    }

    pub fn status(&self) -> CopyStatus {
        self.session.status()
    }
}

/// Pure wake/schedule seam: is a refresh attempt due at `now`?
fn refresh_due(
    now: tokio::time::Instant,
    scheduled: tokio::time::Instant,
    network_probe_at: Option<tokio::time::Instant>,
) -> bool {
    now >= scheduled || network_probe_at.is_some_and(|at| now >= at)
}

/// Pure wake/schedule seam: the next absolute deadline after an attempt. A
/// deadline missed while the attempt ran yields exactly ONE immediate
/// follow-up, never a catch-up burst.
fn next_scheduled_deadline(
    previous: tokio::time::Instant,
    completed: tokio::time::Instant,
    schedule: Duration,
) -> tokio::time::Instant {
    let next = previous + schedule;
    if next <= completed {
        completed
    } else {
        next
    }
}

/// Pure wake seam: a large wall-vs-monotonic gap indicates the host slept.
fn wake_detected(wall_elapsed: Duration, monotonic_elapsed: Duration) -> bool {
    wall_elapsed.saturating_sub(monotonic_elapsed) > Duration::from_secs(5)
}

/// Acquire the driver lock, then check the stop flag **immediately before** the
/// bounded attempt. `None` means stop was already requested, so no fresh
/// refresh may start. This closes the window where a stop arriving during the
/// pre-reconcile/lock awaits could otherwise begin an attempt; the biased
/// select and the tick pre-check remain as the outer guard.
async fn refresh_unless_stopping(
    driver: &Arc<Mutex<MemberCopyDriver>>,
    receiver: &watch::Receiver<bool>,
) -> Option<Result<RefreshDisposition>> {
    let mut guard = driver.lock().await;
    if *receiver.borrow() {
        return None;
    }
    Some(guard.refresh_bounded(MEMBER_COPY_ATTEMPT_BUDGET).await)
}

async fn reconcile_with(
    driver: &Arc<Mutex<MemberCopyDriver>>,
    session: &Arc<MemberStdioSession>,
    profile: ExposureProfile,
) -> Result<()> {
    let mut guard = driver.lock().await;
    // `recover_if_eligible` is the ONLY recovery seam: it re-reads the current
    // selection, quiesces on NotServable or a failed guarded read (files kept),
    // and reactivates a Ready held copy under a validated selection.
    let eligibility = guard
        .recover_if_eligible()
        .await
        .unwrap_or(ReceiptEligibility::NotServable);
    let owner = guard.serving();
    let status = owner.lifecycle_status();
    // `held_receipt_eligibility` checks receipt/pins/fingerprint ONLY, so it can
    // be HeldValidated on `Locked` while the owner is inactive. Publishing also
    // requires an actually serving owner with a readable status; otherwise the
    // session clears and answers the typed no-held refusal (e.g. `copy_locked`).
    // Never treat HeldValidated as permission to read, and never let the
    // constructor's inactive-owner refusal become a CLI exit.
    let readable = matches!(
        status,
        CopyStatus::Ready { .. } | CopyStatus::Refreshing { .. }
    );
    let snapshot =
        if eligibility == ReceiptEligibility::HeldValidated && owner.is_serving() && readable {
            MemberServedSnapshot::from_serving(owner, member_registry(profile)).ok()
        } else {
            None
        };
    drop(guard);
    match snapshot {
        Some(snapshot) => {
            session.publish(status, snapshot);
        }
        None => {
            session.clear(status);
        }
    }
    Ok(())
}

fn member_registry(profile: ExposureProfile) -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    registry.set_exposure_profile(profile);
    register_builtin_tools(&mut registry).expect("builtin registration");
    register_surface_tools(&mut registry).expect("surface registration");
    registry
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;

    use futures::future::BoxFuture;
    use serde_json::json;
    use sha2::Digest as _;

    use super::*;
    use crate::mcp::registry::{Caller, EngineHandle};
    use crate::member_copy_admission::validate_manifest;
    use crate::member_copy_driver::MemberCopyDeviceConfig;
    use crate::member_copy_producer::{
        build_member_copy, MemberCopy, MemberCopyRequest as ProducerRequest,
    };
    use crate::member_copy_transport::{
        CredentialSelection, MemberCopyAnswer, MemberCopyAttempt, MemberCopyChunk,
        MemberCopyContext, MemberCopyRequest, MemberCopyTransport,
    };
    use crate::member_offline_fixtures::{two_caller, ACCT_B};
    use crate::replica_generation::ReplicaGenerationManifest;
    use crate::standby_snapshot::{
        StandbyConsumerIdentity, StandbyConsumerPlatform, STANDBY_CONSUMER_CONTRACT,
    };

    const SCOPE_A: &str = "scope-a";

    fn device_consumer() -> StandbyConsumerIdentity {
        StandbyConsumerIdentity {
            contract: STANDBY_CONSUMER_CONTRACT.to_owned(),
            version: 1,
            platform: StandbyConsumerPlatform::LinuxX8664,
            source_sha: "a".repeat(40),
            artifact_sha256: "b".repeat(64),
            engine_schema_version: 1,
            ddl_sha256: "c".repeat(64),
        }
    }

    fn write_credential(root: &Path, token: &str) {
        let path = root.join("credential");
        fs::write(&path, token).expect("credential");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        }
    }

    fn config(root: &Path, origin: &str, token: &str) -> MemberCopyDeviceConfig {
        write_credential(root, token);
        MemberCopyDeviceConfig {
            contract: "native.member-copy-device.v1".to_owned(),
            version: 1,
            hosted_origin: "http://127.0.0.1:0".to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            origin_database_id: Some(origin.to_owned()),
            credential_file: root.join("credential"),
            copy_root: root.join("copy"),
        }
    }

    async fn world() -> (crate::db::Db, String) {
        let world = two_caller::build().await;
        let origin: String =
            sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
                .fetch_one(world.db.pool())
                .await
                .expect("origin");
        (world.db, origin)
    }

    async fn produce(db: &crate::db::Db, scope: &str, ordinal: i64, out: &Path) -> MemberCopy {
        build_member_copy(
            db,
            ProducerRequest {
                member_account: ACCT_B.to_owned(),
                scope_ref: scope.to_owned(),
                hosted_route_database_id: "route-test".to_owned(),
                ordinal,
                consumer: device_consumer(),
                out_path: out.to_path_buf(),
            },
        )
        .await
        .expect("produce member copy")
    }

    fn replace_answer(manifest: &ReplicaGenerationManifest, handle: &str) -> MemberCopyAnswer {
        let json = serde_json::to_vec(manifest).expect("manifest");
        let facts = validate_manifest(&json).expect("manifest validates");
        MemberCopyAnswer::Replace {
            generation_id: facts.generation_id,
            scope_ref: facts.scope_ref,
            scope_changed: false,
            ordinal: facts.ordinal,
            content_digest: facts.content_digest,
            download_handle: handle.to_owned(),
            manifest: manifest.clone(),
        }
    }

    /// In-memory transport over the real f7 trait: `request(req, &selection)`
    /// returns an attempt with a sealed context; `read_range(&context, ..)`
    /// serves the pinned bytes. A deterministic barrier blocks an attempt so a
    /// test can drive shutdown/cadence.
    struct ScriptedTransport {
        account: StdMutex<String>,
        answers: StdMutex<VecDeque<MemberCopyAnswer>>,
        bytes: StdMutex<HashMap<String, Vec<u8>>>,
        requests: AtomicUsize,
        fail_requests: AtomicBool,
        block_requests: AtomicBool,
        // Semaphore permits are stored, so a release fired before the blocked
        // future polls `acquire` is not lost (unlike `Notify::notify_waiters`).
        entered: tokio::sync::Semaphore,
        release: tokio::sync::Semaphore,
        /// Signalled once per completed request, so a test can wait for an
        /// attempt to finish without a sleep/poll loop.
        completed: tokio::sync::Semaphore,
    }

    impl ScriptedTransport {
        fn new(account: &str) -> Self {
            Self {
                account: StdMutex::new(account.to_owned()),
                answers: StdMutex::new(VecDeque::new()),
                bytes: StdMutex::new(HashMap::new()),
                requests: AtomicUsize::new(0),
                fail_requests: AtomicBool::new(false),
                block_requests: AtomicBool::new(false),
                entered: tokio::sync::Semaphore::new(0),
                release: tokio::sync::Semaphore::new(0),
                completed: tokio::sync::Semaphore::new(0),
            }
        }
        fn push(&self, answer: MemberCopyAnswer) {
            self.answers.lock().unwrap().push_back(answer);
        }
        fn serve(&self, handle: &str, bytes: Vec<u8>) {
            self.bytes.lock().unwrap().insert(handle.to_owned(), bytes);
        }
        fn requests(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }
        fn context_for(
            &self,
            answer: &MemberCopyAnswer,
            selection: &CredentialSelection,
        ) -> Option<MemberCopyContext> {
            match answer {
                MemberCopyAnswer::Current {
                    scope_ref,
                    manifest,
                    ..
                }
                | MemberCopyAnswer::Replace {
                    scope_ref,
                    manifest,
                    ..
                } => Some(MemberCopyContext::new(
                    self.account.lock().unwrap().clone(),
                    "http://127.0.0.1:0".to_owned(),
                    "route-test".to_owned(),
                    manifest.origin_database_id.clone(),
                    manifest.consumer.clone(),
                    scope_ref.clone(),
                    selection.clone(),
                )),
                _ => None,
            }
        }
    }

    impl MemberCopyTransport for ScriptedTransport {
        fn request(
            &self,
            _request: MemberCopyRequest,
            selection: &CredentialSelection,
        ) -> BoxFuture<'_, Result<MemberCopyAttempt>> {
            let selection = selection.clone();
            Box::pin(async move {
                self.requests.fetch_add(1, Ordering::SeqCst);
                if self.fail_requests.load(Ordering::SeqCst) {
                    return Err(crate::error::Error::engine("scripted network failure"));
                }
                if self.block_requests.load(Ordering::SeqCst) {
                    // Stored permits: entering is observable even if the test
                    // acquires after this point, and a release fired before the
                    // blocked future polls `acquire` is never lost.
                    self.entered.add_permits(1);
                    let _permit = self
                        .release
                        .acquire()
                        .await
                        .expect("release semaphore is never closed");
                }
                let answer = self
                    .answers
                    .lock()
                    .unwrap()
                    .pop_front()
                    .ok_or_else(|| crate::error::Error::engine("no scripted answer"))?;
                let context = self.context_for(&answer, &selection);
                self.completed.add_permits(1);
                Ok(MemberCopyAttempt { answer, context })
            })
        }

        fn read_range(
            &self,
            _context: &MemberCopyContext,
            handle: &str,
            start: u64,
            end: u64,
        ) -> BoxFuture<'_, Result<MemberCopyChunk>> {
            let handle = handle.to_owned();
            Box::pin(async move {
                let bytes = self
                    .bytes
                    .lock()
                    .unwrap()
                    .get(&handle)
                    .cloned()
                    .ok_or_else(|| crate::error::Error::engine("no bytes for handle"))?;
                let end = end.min(bytes.len() as u64 - 1);
                Ok(MemberCopyChunk::Bytes {
                    bytes: bytes[start as usize..=end as usize].to_vec(),
                    start,
                    end,
                    total_size: bytes.len() as u64,
                    sha256: hex::encode(sha2::Sha256::digest(&bytes)),
                })
            })
        }
    }

    async fn driver_for(
        dir: &Path,
        origin: &str,
        token: &str,
        transport: Arc<ScriptedTransport>,
    ) -> MemberCopyDriver {
        MemberCopyDriver::new(config(dir, origin, token), device_consumer(), transport)
            .await
            .expect("driver")
    }

    /// Admit one real generation and return the runtime (serving, published).
    /// Admit one real generation and return the runtime, its transport, and the
    /// **authenticated origin** it admitted under. Reopen tests must reuse this
    /// origin, never a fresh `world()` (a new in-memory world has a different
    /// origin and would only exercise an origin mismatch).
    async fn admitted_runtime(dir: &Path) -> (MemberCopyRuntime, Arc<ScriptedTransport>, String) {
        let (db, origin) = world().await;
        let out = dir.join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let transport = Arc::new(ScriptedTransport::new(ACCT_B));
        transport.push(replace_answer(&copy.manifest, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        let driver = driver_for(dir, &origin, "test-bearer", transport.clone()).await;
        let mut runtime = MemberCopyRuntime::new(driver, ExposureProfile::Complete);
        let disposition = runtime.refresh_and_publish().await.expect("refresh");
        assert!(matches!(disposition, RefreshDisposition::Admitted { .. }));
        (runtime, transport, origin)
    }

    /// Capture the **actual** serving gate the runtime published — the owner's
    /// admitted `Db` + bound account installed into a separate real registry —
    /// under the driver lock. This is a captured old gate, not the dynamic
    /// session cell, so it can prove the owner's lease retirement after a
    /// selection change.
    async fn capture_served_gate(
        runtime: &MemberCopyRuntime,
    ) -> (Arc<ToolRegistry>, crate::db::Db, Caller) {
        let guard = runtime.driver.lock().await;
        let owner = guard.serving();
        let db = owner.database().expect("served db");
        let account = owner.account_token().expect("bound account");
        let mut registry = member_registry(runtime.profile);
        assert!(owner.install_into(&mut registry), "serving gate installed");
        (
            Arc::new(registry),
            db,
            Caller::authenticated(account).with_channel(crate::provenance::Channel::Mcp),
        )
    }

    /// Non-vacuous old-gate read: propagate the handler outcome (not just the
    /// outer dispatch) and require the visible record to be found.
    async fn old_gate_read(
        registry: &Arc<ToolRegistry>,
        db: &crate::db::Db,
        caller: &Caller,
    ) -> Result<()> {
        let call = registry
            .call_engine_detailed(
                EngineHandle::Sqlite(db.clone()),
                caller.clone(),
                "get_record",
                json!({ "ids": [two_caller::SHARED_CHILD] }),
            )
            .await?;
        let result = call.outcome?;
        let status = result.structured["records"]
            .as_array()
            .and_then(|records| {
                records
                    .iter()
                    .find(|record| record["id"] == json!(two_caller::SHARED_CHILD))
            })
            .and_then(|record| record["status"].as_str());
        assert_eq!(
            status,
            Some("found"),
            "the captured old gate must serve the visible record"
        );
        Ok(())
    }

    fn record_status(body: &serde_json::Value, id: &str) -> Option<String> {
        body["result"]["structuredContent"]["records"]
            .as_array()?
            .iter()
            .find(|item| item["id"] == json!(id))
            .and_then(|item| item["status"].as_str())
            .map(str::to_owned)
    }

    #[tokio::test]
    async fn runtime_admits_publishes_and_quiesces_on_shutdown() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut runtime, _transport, _origin) = admitted_runtime(dir.path()).await;

        let served = runtime
            .session()
            .handle_message(json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "get_record",
                    "arguments": { "ids": [two_caller::SHARED_CHILD], "format": "json" } },
            }))
            .await
            .expect("response");
        assert_eq!(
            record_status(&served, two_caller::SHARED_CHILD).as_deref(),
            Some("found")
        );

        runtime.shutdown().await;
        let refused = runtime
            .session()
            .handle_message(json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": { "name": "get_record",
                    "arguments": { "ids": [two_caller::SHARED_CHILD], "format": "json" } },
            }))
            .await
            .expect("response");
        assert_eq!(
            refused["result"]["structuredContent"]["error_code"],
            json!("copy_unavailable")
        );
    }

    #[tokio::test]
    async fn runtime_clears_the_snapshot_on_removed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (db, origin) = world().await;
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let transport = Arc::new(ScriptedTransport::new(ACCT_B));
        // First admit, then a second refresh is Revoked.
        transport.push(replace_answer(&copy.manifest, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        transport.push(MemberCopyAnswer::Revoked {
            cause: crate::member_copy_lifecycle::RevokedCause::SessionRevoked,
        });
        let driver = driver_for(dir.path(), &origin, "test-bearer", transport.clone()).await;
        let mut runtime = MemberCopyRuntime::new(driver, ExposureProfile::Complete);
        let _ = runtime.refresh_and_publish().await.expect("admit");
        let disposition = runtime.refresh_and_publish().await.expect("revoke");
        assert!(matches!(disposition, RefreshDisposition::Removed { .. }));
        assert!(!runtime.session().has_snapshot());

        let body = runtime
            .session()
            .handle_message(json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "get_record", "arguments": { "ids": ["x"] } },
            }))
            .await
            .expect("response");
        assert_eq!(
            body["result"]["structuredContent"]["error_code"],
            json!("copy_removed")
        );
    }

    #[tokio::test]
    async fn runtime_publishes_validated_held_copy_offline_before_network() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (runtime, transport, origin) = admitted_runtime(dir.path()).await;
        let requests_after_admit = transport.requests();
        // Release the owner authority lock before reopening the same copy root.
        drop(runtime);

        // Reopen with the same credential and a network-failing transport: the
        // held copy must publish offline with zero further requests.
        let reopening = Arc::new(ScriptedTransport::new(ACCT_B));
        reopening.fail_requests.store(true, Ordering::SeqCst);
        let driver = driver_for(dir.path(), &origin, "test-bearer", reopening.clone()).await;
        let mut runtime = MemberCopyRuntime::new(driver, ExposureProfile::Complete);
        runtime
            .publish_offline_held_if_eligible()
            .await
            .expect("offline publish");
        assert_eq!(reopening.requests(), 0, "no network before the await");
        let _ = requests_after_admit;

        let served = runtime
            .session()
            .handle_message(json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "get_record",
                    "arguments": { "ids": [two_caller::SHARED_CHILD], "format": "json" } },
            }))
            .await
            .expect("response");
        assert_eq!(
            record_status(&served, two_caller::SHARED_CHILD).as_deref(),
            Some("found")
        );
    }

    #[tokio::test]
    async fn runtime_never_publishes_old_copy_on_changed_or_missing_selection() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (runtime, _transport, origin) = admitted_runtime(dir.path()).await;
        drop(runtime);

        // Rotate the credential file to a different bearer, then reopen: the
        // held receipt fingerprint no longer matches, so nothing publishes.
        let rotated = Arc::new(ScriptedTransport::new(ACCT_B));
        let driver = driver_for(dir.path(), &origin, "different-bearer", rotated.clone()).await;
        let mut runtime = MemberCopyRuntime::new(driver, ExposureProfile::Complete);
        runtime.reconcile_snapshot().await.expect("reconcile");
        assert!(!runtime.session().has_snapshot());

        let body = runtime
            .session()
            .handle_message(json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "get_record", "arguments": { "ids": ["x"] } },
            }))
            .await
            .expect("response");
        assert_eq!(
            body["result"]["structuredContent"]["error_code"],
            json!("copy_unavailable")
        );
    }

    #[tokio::test]
    async fn runtime_keeps_held_copy_on_network_failure_with_valid_receipt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut runtime, transport, _origin) = admitted_runtime(dir.path()).await;
        transport.fail_requests.store(true, Ordering::SeqCst);

        // A network-failing refresh must not clear a held copy whose selection
        // is still valid.
        let disposition = runtime.refresh_and_publish().await;
        assert!(disposition.is_err(), "the attempt itself fails");
        let served = runtime
            .session()
            .handle_message(json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "get_record",
                    "arguments": { "ids": [two_caller::SHARED_CHILD], "format": "json" } },
            }))
            .await
            .expect("response");
        assert_eq!(
            record_status(&served, two_caller::SHARED_CHILD).as_deref(),
            Some("found")
        );
    }

    #[tokio::test]
    async fn shutdown_waits_for_serialized_refresh_then_quiesces() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (db, origin) = world().await;
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let transport = Arc::new(ScriptedTransport::new(ACCT_B));
        transport.push(replace_answer(&copy.manifest, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        transport.block_requests.store(true, Ordering::SeqCst);
        let driver = driver_for(dir.path(), &origin, "test-bearer", transport.clone()).await;
        let mut runtime = MemberCopyRuntime::new(driver, ExposureProfile::Complete);

        // Production cadence: the immediate first poll tick enters the attempt;
        // no tiny-interval clock injection. The semaphore handshake is the
        // behavior clock; the timeouts are guards only.
        runtime.start_background_refresh();
        let _ = tokio::time::timeout(Duration::from_secs(5), transport.entered.acquire())
            .await
            .expect("guard: attempt entered")
            .expect("entered semaphore is never closed");
        let shutdown = tokio::spawn(async move {
            // `shutdown` is on `&mut self`; run it on the runtime task.
            runtime.shutdown().await;
        });
        // Stored permit: the release cannot be lost even if it fires before the
        // blocked future polls `acquire`.
        transport.release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(5), shutdown)
            .await
            .expect("guard: shutdown waited for the attempt")
            .expect("shutdown task");
    }

    /// A stop request while the task is idle between attempts must not start a
    /// new attempt (biased select + post-tick re-check).
    #[tokio::test]
    async fn shutdown_while_idle_does_not_start_another_attempt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (db, origin) = world().await;
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let transport = Arc::new(ScriptedTransport::new(ACCT_B));
        transport.push(replace_answer(&copy.manifest, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        let driver = driver_for(dir.path(), &origin, "test-bearer", transport.clone()).await;
        let mut runtime = MemberCopyRuntime::new(driver, ExposureProfile::Complete);

        runtime.start_background_refresh();
        // Wait for the immediate first attempt to complete (no sleep/poll loop).
        let _ = tokio::time::timeout(Duration::from_secs(5), transport.completed.acquire())
            .await
            .expect("guard: first attempt completed")
            .expect("completed semaphore is never closed");
        let before = transport.requests();
        runtime.shutdown().await;
        assert_eq!(
            transport.requests(),
            before,
            "no new attempt may start after stop"
        );
    }

    /// Under-lock stop discriminator (no sleeps, no hooks): while the helper
    /// waits on the driver lock with stop still false, a stop arriving before
    /// the lock is released must yield `None` and start no transport request.
    /// The pre-fix (check-before-await) helper would start a request.
    #[tokio::test]
    async fn refresh_unless_stopping_does_not_start_after_stop_during_lock_wait() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (db, origin) = world().await;
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let transport = Arc::new(ScriptedTransport::new(ACCT_B));
        transport.push(replace_answer(&copy.manifest, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        let driver = driver_for(dir.path(), &origin, "test-bearer", transport.clone()).await;
        let runtime = MemberCopyRuntime::new(driver, ExposureProfile::Complete);
        let (shutdown, receiver) = watch::channel(false);

        // Hold the driver lock so the helper blocks in `driver.lock().await`.
        let guard = runtime.driver.lock().await;
        let mut helper = Box::pin(refresh_unless_stopping(&runtime.driver, &receiver));
        assert!(
            futures::poll!(helper.as_mut()).is_pending(),
            "the helper must be waiting on the driver lock"
        );
        // Stop arrives while the helper waits; release the lock.
        shutdown.send(true).expect("send stop");
        drop(guard);
        assert!(
            helper.await.is_none(),
            "no attempt may start once stop was requested"
        );
        assert_eq!(transport.requests(), 0, "the transport must not be called");
    }

    /// A valid receipt on a `Locked` copy is HeldValidated but the owner is
    /// inactive: the runtime must clear and answer the typed no-held
    /// `copy_locked`, never attempt `from_serving` and never exit.
    #[tokio::test]
    async fn runtime_locked_valid_receipt_serves_no_held_copy_locked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (db, origin) = world().await;
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let transport = Arc::new(ScriptedTransport::new(ACCT_B));
        transport.push(replace_answer(&copy.manifest, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        transport.push(MemberCopyAnswer::Locked);
        let driver = driver_for(dir.path(), &origin, "test-bearer", transport.clone()).await;
        let mut runtime = MemberCopyRuntime::new(driver, ExposureProfile::Complete);
        let _ = runtime.refresh_and_publish().await.expect("admit");
        let disposition = runtime.refresh_and_publish().await.expect("locked");
        assert!(matches!(disposition, RefreshDisposition::Locked));
        assert!(!runtime.session().has_snapshot());

        let body = runtime
            .session()
            .handle_message(json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "get_record", "arguments": { "ids": ["x"] } },
            }))
            .await
            .expect("response");
        assert_eq!(
            body["result"]["structuredContent"]["error_code"],
            json!("copy_locked")
        );
    }

    /// A Ready copy quiesced by a transient NotServable (A -> B) recovers ONLY
    /// through `recover_if_eligible` once the selection is valid again (B -> A),
    /// reinstalling a fresh serving gate.
    #[tokio::test]
    async fn runtime_recovers_a_quiesced_ready_copy_under_a_valid_selection() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (runtime, _transport, origin) = admitted_runtime(dir.path()).await;
        drop(runtime);

        // Reopen with a different bearer: not servable, owner quiesced.
        let transport = Arc::new(ScriptedTransport::new(ACCT_B));
        let driver = driver_for(dir.path(), &origin, "different-bearer", transport).await;
        let mut runtime = MemberCopyRuntime::new(driver, ExposureProfile::Complete);
        runtime.reconcile_snapshot().await.expect("not servable");
        assert!(!runtime.session().has_snapshot());

        // Rotate the credential file back to the originally admitted bearer.
        write_credential(dir.path(), "test-bearer");
        runtime.reconcile_snapshot().await.expect("recover");
        assert!(runtime.session().has_snapshot());
        let served = runtime
            .session()
            .handle_message(json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "get_record",
                    "arguments": { "ids": [two_caller::SHARED_CHILD], "format": "json" } },
            }))
            .await
            .expect("response");
        assert_eq!(
            record_status(&served, two_caller::SHARED_CHILD).as_deref(),
            Some("found")
        );
    }

    /// Rotation on the **existing** owner: the pre-rotation session handle must
    /// refuse after reconcile clears (no second owner is opened).
    /// Rotation on the **existing** owner: a captured real old gate (owner Db +
    /// bound account in a separate registry) admits before, and refuses typed
    /// `CopyUnavailable` after the owner retires its leases. The dynamic session
    /// cell refusal is asserted too.
    #[tokio::test]
    async fn runtime_rotated_selection_refuses_on_the_existing_owner() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut runtime, _transport, _origin) = admitted_runtime(dir.path()).await;
        let captured_session = runtime.session();
        let (old_registry, old_db, old_caller) = capture_served_gate(&runtime).await;

        assert!(
            old_gate_read(&old_registry, &old_db, &old_caller)
                .await
                .is_ok(),
            "the captured old gate admits before rotation"
        );

        // Rotate the credential file on the SAME owner and reconcile: the owner
        // quiesces and retires the old leases.
        write_credential(dir.path(), "rotated-bearer");
        runtime.reconcile_snapshot().await.expect("reconcile");

        assert!(
            matches!(
                old_gate_read(&old_registry, &old_db, &old_caller).await,
                Err(crate::error::Error::CopyUnavailable)
            ),
            "the captured old gate must refuse typed after rotation"
        );
        assert!(!runtime.session().has_snapshot());
        let session_refusal = captured_session
            .handle_message(json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "get_record", "arguments": { "ids": ["x"] } },
            }))
            .await
            .expect("response");
        assert_eq!(
            session_refusal["result"]["structuredContent"]["error_code"],
            json!("copy_unavailable")
        );
    }

    /// Missing selection on the **existing** owner: deleting the credential file
    /// retires the old gate and clears the session.
    #[tokio::test]
    async fn runtime_missing_selection_refuses_on_the_existing_owner() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut runtime, _transport, _origin) = admitted_runtime(dir.path()).await;
        let (old_registry, old_db, old_caller) = capture_served_gate(&runtime).await;
        assert!(old_gate_read(&old_registry, &old_db, &old_caller)
            .await
            .is_ok());

        std::fs::remove_file(dir.path().join("credential")).expect("remove credential");
        runtime.reconcile_snapshot().await.expect("reconcile");

        assert!(
            matches!(
                old_gate_read(&old_registry, &old_db, &old_caller).await,
                Err(crate::error::Error::CopyUnavailable)
            ),
            "the captured old gate must refuse typed after a missing selection"
        );
        assert!(!runtime.session().has_snapshot());
    }

    /// Pure schedule seam: an attempt that overruns several intervals yields
    /// exactly one immediate follow-up, never a catch-up burst.
    #[test]
    fn schedule_skips_missed_ticks_without_burst() {
        let t0 = tokio::time::Instant::now();
        let schedule = Duration::from_secs(120);
        // Attempt completed well past several deadlines.
        let completed = t0 + Duration::from_secs(500);
        let next = next_scheduled_deadline(t0, completed, schedule);
        assert_eq!(next, completed, "one immediate follow-up, not a burst");
        // The very next attempt that fits keeps the absolute deadline.
        let fits = t0 + Duration::from_secs(10);
        assert_eq!(next_scheduled_deadline(t0, fits, schedule), t0 + schedule);
    }

    #[test]
    fn refresh_due_uses_deadline_and_network_probe() {
        let t0 = tokio::time::Instant::now();
        assert!(!refresh_due(t0, t0 + Duration::from_secs(10), None));
        assert!(refresh_due(
            t0 + Duration::from_secs(10),
            t0 + Duration::from_secs(10),
            None
        ));
        assert!(refresh_due(t0, t0 + Duration::from_secs(10), Some(t0),));
    }

    #[test]
    fn wake_detected_only_for_a_large_wall_gap() {
        assert!(!wake_detected(
            Duration::from_secs(6),
            Duration::from_secs(6)
        ));
        assert!(wake_detected(
            Duration::from_secs(600),
            Duration::from_secs(6)
        ));
    }
}
