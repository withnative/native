//! The required background audit and the serving deadline (design record
//! 5065900 §5, slice 6). Disposable databases; aged verdicts are written
//! directly, so nothing here sleeps for an interval.
use super::set_path::{refresh_v2, serve_as};
use super::*;
use crate::standby::generation_store::kernel_in_place::at_rest::{
    AtRestRecord, FAIL_AT_REST_WRITE,
};
use crate::standby::generation_store::kernel_in_place::audit::{
    AuditRecord, AuditResult, AUDIT_CACHE_INVALID, AUDIT_FAILED, AUDIT_VERIFIED,
    FORCE_INFRASTRUCTURE_ERROR, PIN_SEAM,
};
use crate::standby::StandbyStatusProvider;
use chrono::{Duration as Age, Utc};

const N: u64 = 900;

/// Audits required at N for this test. Both the store and the controller's
/// config carry it: each refresh re-applies the config's interval to the
/// store, so pinning only the store would fall back to the default.
fn pin_audit_interval(s: &mut Setup) {
    s.controller.config.kernel_audit_interval_seconds = Some(N);
    s.controller
        .store
        .set_audit_interval(Some(Duration::from_secs(N)));
}

/// A set-path setup (second DDL, accumulator) with audits required at N.
async fn audited() -> Setup {
    let mut s = setup().await;
    pin_audit_interval(&mut s);
    refresh_v2(&mut s).await;
    s
}

async fn provider(
    s: &Setup,
) -> (
    StandbyStatusProvider,
    Box<crate::standby::ActivatedGeneration>,
) {
    let outcome = s
        .controller
        .store
        .activate_for_startup(&s.controller.observed)
        .await
        .unwrap();
    let StandbyStartupOutcome::Serving(active) = outcome else {
        panic!("the advanced copy must serve")
    };
    (
        StandbyStatusProvider::for_serving(
            s.controller.runtime.clone(),
            s.controller.store.clone(),
            s.controller.observed.clone(),
            &active,
            true,
            true,
        ),
        active,
    )
}

fn audit_of(s: &Setup) -> Option<AuditRecord> {
    s.controller.store.generation_audit(&s.current.id)
}

/// Age the verdict by `age` (it stays a success) without waiting.
fn age_verdict(s: &Setup, age: Age, outcome: &str) {
    let ordinal = audit_of(s).map_or(0, |record| record.ordinal);
    s.controller.store.write_audit_unchecked(&AuditRecord {
        generation_id: s.current.id.clone(),
        ordinal,
        snapshot_acquired_at: (Utc::now() - age)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        outcome: outcome.to_owned(),
    });
}

fn state_of(provider: &StandbyStatusProvider) -> (String, Option<u64>) {
    let audit = provider
        .response_context()
        .serving_audit
        .expect("an in-place copy with audits required reports its audit");
    (audit.state.to_owned(), audit.age_seconds)
}

#[tokio::test]
async fn a_copy_not_advanced_in_place_or_without_the_flag_reports_no_audit() {
    let mut s = setup().await;
    pin_audit_interval(&mut s);
    // Not advanced in place yet: nothing to audit, nothing to gate.
    let (provider, active) = provider(&s).await;
    assert!(provider.response_context().serving_audit.is_none());
    drop(active);
    refresh_v2(&mut s).await;
    let (provider, _active) = provider_for(&s).await;
    assert_eq!(state_of(&provider).0, "current");
    // Audits not required (the flag is off): the field is absent, and so is it
    // from the serialised disclosure, byte for byte as before.
    s.controller.store.set_audit_interval(None);
    let context = provider.response_context();
    assert!(context.serving_audit.is_none());
    assert!(serde_json::to_value(&context)
        .unwrap()
        .get("serving_audit")
        .is_none());
    s.hosted.close().await;
}

async fn provider_for(
    s: &Setup,
) -> (
    StandbyStatusProvider,
    Box<crate::standby::ActivatedGeneration>,
) {
    provider(s).await
}

#[tokio::test]
async fn a_generation_is_unaudited_until_its_base_receipt() {
    let mut s = setup().await;
    pin_audit_interval(&mut s);
    assert!(audit_of(&s).is_none(), "a new generation starts unaudited");
    // The first in-place apply anchors a base receipt, which is an audit.
    refresh_v2(&mut s).await;
    let record = audit_of(&s).expect("the base receipt audits");
    assert_eq!(record.outcome, AUDIT_VERIFIED);
    assert_eq!(record.generation_id, s.current.id);
    // Scoped to its generation: another id's record says nothing about this one.
    let foreign = "f".repeat(64);
    assert!(s.controller.store.generation_audit(&foreign).is_none());
    // A missing or unreadable record counts as unaudited.
    let (provider, _active) = provider(&s).await;
    s.controller.store.remove_audit(&s.current.id);
    assert_eq!(state_of(&provider), ("unaudited".to_owned(), None));
    s.controller.store.write_audit_unchecked(&AuditRecord {
        generation_id: "0".repeat(64),
        ordinal: 0,
        snapshot_acquired_at: "not a time".into(),
        outcome: AUDIT_VERIFIED.into(),
    });
    assert_eq!(state_of(&provider).0, "unaudited");
    s.hosted.close().await;
}

#[tokio::test]
async fn corruption_after_an_audit_with_later_audits_stalled_ends_online_serving_after_2n() {
    let s = audited().await;
    let (provider, _active) = provider(&s).await;
    // An audit just passed.
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Verified)
    );
    assert_eq!(state_of(&provider).0, "current");
    // Corruption lands afterwards; the head does not move and the audits stall.
    s.corrupt("UPDATE kernel_records SET created_at='2031-01-01T00:00:00Z' WHERE rowid=(SELECT MIN(rowid) FROM kernel_records)")
        .await;
    for (age, expected) in [
        (Age::seconds(N as i64 * 2 - 5), "current"),
        (Age::seconds(N as i64 * 2 + 5), "overdue"),
    ] {
        age_verdict(&s, age, AUDIT_VERIFIED);
        let context = provider.response_context();
        let audit = context.serving_audit.clone().unwrap();
        assert_eq!(audit.state, expected, "{audit:?}");
        // Online: the read is forwarded to hosted once the audit is overdue.
        let online = crate::node::pre_read_act(&context, 0, u64::MAX);
        assert_eq!(online.is_some(), expected == "current", "{audit:?}");
        // Offline: the copy keeps serving, and the age is disclosed as a
        // machine field next to the serving age.
        assert_eq!(
            context.mode,
            crate::standby::StandbyStatusMode::Standby,
            "an overdue audit never stops offline serving"
        );
        let disclosed = serde_json::to_value(&context).unwrap();
        assert!(
            disclosed["serving_audit"]["age_seconds"].as_u64().unwrap() >= age.num_seconds() as u64
        );
        assert_eq!(disclosed["serving_audit"]["state"], expected);
        assert!(disclosed["freshness"]["age_seconds"].is_number());
    }
    // The audit that was starved finds the damage; the copy is then also
    // ineligible online until a whole snapshot replaces it.
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Failed)
    );
    let context = provider.response_context();
    assert_eq!(context.serving_audit.as_ref().unwrap().state, "failed");
    assert!(crate::node::pre_read_act(&context, 0, u64::MAX).is_none());
    assert!(
        s.controller
            .store
            .generation_head(&s.current.id)
            .unwrap()
            .unwrap()
            .full_refresh_required
    );
    s.hosted.close().await;
}

#[tokio::test]
async fn an_infrastructure_error_never_refreshes_eligibility() {
    let s = audited().await;
    age_verdict(&s, Age::seconds(N as i64 * 2 + 60), AUDIT_VERIFIED);
    let before = s.controller.store.raw_audit_bytes(&s.current.id).unwrap();
    FORCE_INFRASTRUCTURE_ERROR.with(|flag| flag.set(true));
    assert!(s.controller.audit_once().await.is_err());
    assert_eq!(
        s.controller.store.raw_audit_bytes(&s.current.id).unwrap(),
        before,
        "an infrastructure error leaves the last verdict as it was"
    );
    let (provider, _active) = provider(&s).await;
    // (Admission just now was itself an audit; age the record again, then ask.)
    age_verdict(&s, Age::seconds(N as i64 * 2 + 60), AUDIT_VERIFIED);
    assert_eq!(state_of(&provider).0, "overdue");
    // The next healthy audit does refresh it.
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Verified)
    );
    assert_eq!(state_of(&provider).0, "current");
    s.hosted.close().await;
}

#[tokio::test]
async fn an_aborted_transaction_never_refreshes_eligibility_but_a_committed_scan_does() {
    let mut s = setup().await;
    pin_audit_interval(&mut s);
    // A first-DDL copy (version-1 deltas): every apply scans the whole database.
    first_in_place_delta(&mut s, 1).await;
    age_verdict(&s, Age::seconds(N as i64 * 2 + 60), AUDIT_VERIFIED);
    let stale = s.controller.store.raw_audit_bytes(&s.current.id).unwrap();
    // A full-scan apply that aborts before commit publishes nothing.
    s.hosted_adds_records(1).await;
    s.controller.kernel_in_place_crash = Some(InPlaceCrash::BeforeCommit);
    let server = s.serve(1).await;
    assert!(s.refresh().await.is_err());
    server.await.unwrap();
    assert_eq!(
        s.controller.store.raw_audit_bytes(&s.current.id).unwrap(),
        stale,
        "an aborted transaction must not refresh serving eligibility"
    );
    // The same apply, committed, is an audit.
    s.controller.kernel_in_place_crash = None;
    s.forget_rest();
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    let record = audit_of(&s).unwrap();
    assert_eq!(record.outcome, AUDIT_VERIFIED);
    assert!(
        record.acquired().unwrap() > Utc::now() - Age::seconds(60),
        "{record:?}"
    );
    s.hosted.close().await;
}

#[tokio::test]
async fn a_cache_invalid_result_passes_and_marks_the_cache() {
    let s = audited().await;
    s.corrupt("UPDATE kernel_standby_projection_set SET value = zeroblob(384) WHERE name='kernel_records'")
        .await;
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::CacheInvalid)
    );
    let record = audit_of(&s).unwrap();
    assert_eq!(record.outcome, AUDIT_CACHE_INVALID);
    assert!(record.passed(), "rows match the receipt: the copy passes");
    assert!(s.controller.store.accumulator_marked_invalid(&s.current.id));
    assert!(
        !s.controller
            .store
            .generation_head(&s.current.id)
            .unwrap()
            .unwrap()
            .full_refresh_required
    );
    // The next writer reseeds, and the next audit clears the marker.
    refresh_v2(&mut { s }).await;
}

#[tokio::test]
async fn a_mismatch_injection_leads_to_refusal() {
    let mut s = audited().await;
    s.corrupt_projection().await;
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Failed)
    );
    let record = audit_of(&s).unwrap();
    assert_eq!(
        (record.outcome.as_str(), record.passed()),
        (AUDIT_FAILED, false)
    );
    // Today's Full-failure handling: the next refresh asks for a whole snapshot.
    s.forget_rest();
    s.hosted_adds_records(1).await;
    let server = serve_as(&mut s, 1, AuthorityFault::AdvertiseV2).await;
    let outcome = s.refresh().await;
    server.abort();
    assert!(
        matches!(outcome, Ok(StandbyDeltaOutcome::FullRefreshRequired { .. })),
        "{outcome:?}"
    );
    s.hosted.close().await;
}

#[tokio::test]
async fn a_full_check_is_an_audit_and_an_audit_changes_nothing_in_the_database() {
    let s = audited().await;
    let before = std::fs::read(&s.current.snapshot_path).unwrap();
    let wal = {
        let mut path = s.current.snapshot_path.clone().into_os_string();
        path.push("-wal");
        std::path::PathBuf::from(path)
    };
    let wal_before = std::fs::read(&wal).ok();
    s.controller.store.remove_audit(&s.current.id);
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Verified)
    );
    assert!(audit_of(&s).is_some());
    // Read-only: the main file and the WAL are byte for byte as they were.
    assert_eq!(std::fs::read(&s.current.snapshot_path).unwrap(), before);
    // (Opening a read-only WAL connection may create an empty `-wal` file.)
    assert_eq!(
        std::fs::read(&wal).ok().unwrap_or_default(),
        wal_before.unwrap_or_default()
    );
    // A restart's Full check also writes the record. (With a qualifying
    // at-rest record the restart is trusted and runs no Full check, so the
    // immediate post-start audit is what renews online eligibility instead.)
    s.controller.store.remove_at_rest(&s.current.id);
    s.controller.store.remove_audit(&s.current.id);
    s.assert_startup_serves().await;
    let _ = s
        .controller
        .store
        .activate_for_startup(&s.controller.observed)
        .await;
    assert!(audit_of(&s).is_some());
    s.hosted.close().await;
}

#[tokio::test]
async fn the_audit_loop_audits_on_its_schedule_independently_of_attempts() {
    let mut s = audited().await;
    // N = 1 s for the loop (the config validation floor does not apply to a
    // struct built in a test). The first audit is due at once (no verdict).
    s.controller.config.kernel_audit_interval_seconds = Some(1);
    s.controller.store.remove_audit(&s.current.id);
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let controller = s.controller;
    let id = s.current.id.clone();
    let runner = async { controller.run_audit_loop(shutdown).await };
    let waiter = async {
        let started = std::time::Instant::now();
        let mut first = None;
        loop {
            if let Some(record) = controller.store.generation_audit(&id) {
                match &first {
                    None => first = Some(record.snapshot_acquired_at.clone()),
                    Some(earlier) if &record.snapshot_acquired_at != earlier => break,
                    _ => {}
                }
            }
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "no second audit"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        stop.send(true).unwrap();
    };
    tokio::join!(runner, waiter);
    s.hosted.close().await;
}

#[test]
fn the_audit_interval_is_bounded_and_defaults_to_six_hours_with_the_flag() {
    use crate::standby::StandbyRefreshConfig;
    let mut config = StandbyRefreshConfig {
        contract: "native.standby-refresh-config.v1".into(),
        version: 1,
        hosted_origin: "http://localhost".into(),
        credential_file: "/nonexistent/credential".into(),
        refresh_interval_seconds: None,
        full_refresh_min_interval_seconds: None,
        full_refresh_repair_retry_seconds: None,
        kernel_in_place_deltas: false,
        kernel_audit_interval_seconds: None,
        projection_proof_interval_seconds: None,
    };
    // Off: no audits, whatever the interval says.
    assert_eq!(config.audit_interval(), None);
    config.kernel_audit_interval_seconds = Some(120);
    assert_eq!(config.audit_interval(), None);
    // On: six hours by default, or as configured.
    config.kernel_in_place_deltas = true;
    config.kernel_audit_interval_seconds = None;
    assert_eq!(
        config.audit_interval(),
        Some(Duration::from_secs(6 * 60 * 60))
    );
    config.kernel_audit_interval_seconds = Some(120);
    assert_eq!(config.audit_interval(), Some(Duration::from_secs(120)));
    // Bounds (the credential path is irrelevant to what fails first).
    for (seconds, ok) in [
        (59, false),
        (60, true),
        (900, true),
        (86_400, true),
        (86_401, false),
    ] {
        config.kernel_audit_interval_seconds = Some(seconds);
        let outcome = config.validate();
        if ok {
            // Only the credential path can still fail.
            assert!(
                outcome.is_ok()
                    || !format!("{outcome:?}").contains("kernel_audit_interval_seconds"),
                "{seconds}: {outcome:?}"
            );
        } else {
            assert!(
                format!("{outcome:?}").contains("kernel_audit_interval_seconds"),
                "{seconds}: {outcome:?}"
            );
        }
    }
}

fn pin_seam() -> (
    std::sync::Arc<tokio::sync::Notify>,
    std::sync::Arc<tokio::sync::Notify>,
) {
    let seam = (
        std::sync::Arc::new(tokio::sync::Notify::new()),
        std::sync::Arc::new(tokio::sync::Notify::new()),
    );
    PIN_SEAM.with(|slot| *slot.borrow_mut() = Some(seam.clone()));
    seam
}

/// The time on the record is when the snapshot was PINNED. Everything else the
/// check does (several reads, then digesting the rows) happens afterwards and
/// may take long: a stall right after the pin must not move the time.
#[tokio::test]
async fn the_recorded_time_is_the_pin_time_not_the_time_the_work_got_done() {
    let s = audited().await;
    s.controller.store.remove_audit(&s.current.id);
    let (reached, proceed) = pin_seam();
    let audit = s.controller.audit_once();
    let driver = async {
        reached.notified().await;
        let at_pin = Utc::now();
        tokio::time::sleep(Duration::from_millis(400)).await;
        proceed.notify_one();
        at_pin
    };
    let (result, at_pin) = tokio::join!(audit, driver);
    assert_eq!(result.unwrap(), Some(AuditResult::Verified));
    let acquired = audit_of(&s).unwrap().acquired().unwrap();
    assert!(
        acquired <= at_pin + Age::milliseconds(2),
        "{acquired} vs {at_pin}"
    );
    assert!(
        at_pin - acquired < Age::milliseconds(300),
        "the stall after the pin was counted: {acquired} vs {at_pin}"
    );
    s.hosted.close().await;
}

/// A verifier that pinned clean rows and finished late must not erase a
/// failure published by a newer snapshot.
#[tokio::test]
async fn a_late_success_cannot_erase_a_newer_failure() {
    let s = audited().await;
    let (provider, _active) = provider(&s).await;
    let (reached, proceed) = pin_seam();
    // Verifier A (a Full check) pins clean rows and is held there.
    let verifier = s
        .controller
        .store
        .admit_kernel_in_place(&s.current, IntegrityDepth::Full);
    let driver = async {
        reached.notified().await;
        // Corruption lands, and the background audit (a later snapshot) finds it.
        s.corrupt("UPDATE kernel_records SET created_at='2031-01-01T00:00:00Z' WHERE rowid=(SELECT MIN(rowid) FROM kernel_records)")
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let found = s.controller.audit_once().await.unwrap();
        // Now the older verifier finishes, with a clean verdict of its own.
        proceed.notify_one();
        found
    };
    let (verified, found) = tokio::join!(verifier, driver);
    assert!(verified.is_ok(), "its own snapshot was clean");
    assert_eq!(found, Some(AuditResult::Failed));
    assert_eq!(
        audit_of(&s).unwrap().outcome,
        AUDIT_FAILED,
        "the failure stands"
    );
    assert_eq!(state_of(&provider).0, "failed");
    // The gate also treats a copy flagged for a whole snapshot as not current,
    // whatever the verdict file says.
    s.controller.store.write_audit_unchecked(&AuditRecord {
        generation_id: s.current.id.clone(),
        ordinal: 0,
        snapshot_acquired_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        outcome: AUDIT_VERIFIED.into(),
    });
    assert_eq!(
        state_of(&provider).0,
        "failed",
        "full_refresh_required is set"
    );
    s.hosted.close().await;
}

#[tokio::test]
async fn ordering_is_strictly_by_acquisition_time_and_a_failure_wins_a_tie() {
    let s = audited().await;
    let store = &s.controller.store;
    let id = &s.current.id;
    let t = Utc::now();
    store.write_audit(id, 1, t, AUDIT_VERIFIED).unwrap();
    // Older success: ignored. Same-instant failure: replaces. Same-instant
    // success after a failure: ignored. Strictly newer success: replaces.
    store
        .write_audit(id, 2, t - Age::seconds(5), AUDIT_FAILED)
        .unwrap();
    assert_eq!(audit_of(&s).unwrap().outcome, AUDIT_VERIFIED);
    store.write_audit(id, 3, t, AUDIT_FAILED).unwrap();
    assert_eq!(audit_of(&s).unwrap().outcome, AUDIT_FAILED);
    store.write_audit(id, 4, t, AUDIT_VERIFIED).unwrap();
    assert_eq!(audit_of(&s).unwrap().outcome, AUDIT_FAILED);
    store
        .write_audit(id, 5, t + Age::seconds(1), AUDIT_VERIFIED)
        .unwrap();
    assert_eq!(audit_of(&s).unwrap().outcome, AUDIT_VERIFIED);
    s.hosted.close().await;
}

/// Online eligibility rests on a success this process observed, on the
/// monotonic clock: setting the wall clock back cannot restore it.
#[tokio::test]
async fn a_clock_rollback_does_not_restore_online_eligibility() {
    let s = audited().await;
    let (provider, _active) = provider(&s).await;
    let now = Utc::now();
    assert_eq!(state_of(&provider).0, "current");
    // The last success is 40 minutes old: past 2N (30 minutes).
    age_verdict(&s, Age::minutes(40), AUDIT_VERIFIED);
    for (label, clock) in [
        ("an honest clock", now),
        // The clock was set back 20 minutes: the record now looks 20 minutes old.
        ("rolled back 20 minutes", now - Age::minutes(20)),
        // Set back an hour: the record is in the future and is ignored.
        ("rolled back an hour", now - Age::hours(1)),
    ] {
        let context = provider.response_context_at(clock);
        let audit = context.serving_audit.clone().unwrap();
        assert_ne!(audit.state, "current", "{label}: {audit:?}");
        assert!(
            crate::node::pre_read_act(&context, 0, u64::MAX).is_none(),
            "{label}: online must stay forwarded"
        );
        assert_eq!(context.mode, crate::standby::StandbyStatusMode::Standby);
    }
    // After a restart the new process has observed nothing: a fresh record is
    // not enough, but its own startup Full check is.
    age_verdict(&s, Age::minutes(1), AUDIT_VERIFIED);
    assert_eq!(state_of(&provider).0, "current");
    s.controller.store.forget_audit_observations();
    assert_eq!(state_of(&provider).0, "unaudited");
    let _ = s
        .controller
        .store
        .activate_for_startup(&s.controller.observed)
        .await
        .unwrap();
    assert_eq!(state_of(&provider).0, "current");
    s.hosted.close().await;
}

/// A copy the audit has not vouched for is still SERVED (offline, and an
/// explicit `native/route: local`), but its disclosure says so as machine
/// fields and a degraded reason, so the caller can decide.
#[tokio::test]
async fn a_copy_the_audit_has_not_vouched_for_is_disclosed_not_refused() {
    let s = audited().await;
    let (provider, _active) = provider(&s).await;
    let context = provider.response_context();
    assert!(context
        .degraded_reasons
        .iter()
        .all(|r| !r.starts_with("audit_")));
    for (setup, state, reason) in [
        (
            Some((Age::minutes(40), AUDIT_VERIFIED)),
            "overdue",
            "audit_overdue",
        ),
        (None, "unaudited", "audit_unaudited"),
        (
            Some((Age::minutes(1), AUDIT_FAILED)),
            "failed",
            "audit_failed",
        ),
    ] {
        match setup {
            Some((age, outcome)) => age_verdict(&s, age, outcome),
            None => s.controller.store.remove_audit(&s.current.id),
        }
        let context = provider.response_context();
        assert_eq!(context.serving_audit.as_ref().unwrap().state, state);
        assert!(
            context.degraded_reasons.contains(&reason),
            "{reason}: {context:?}"
        );
        assert!(context.freshness_degraded);
        assert_eq!(
            context.mode,
            crate::standby::StandbyStatusMode::Standby,
            "served, not refused"
        );
        let disclosed = serde_json::to_value(&context).unwrap();
        assert_eq!(disclosed["serving_audit"]["state"], state);
        assert!(disclosed["serving_audit"]["interval_seconds"].is_number());
        assert!(crate::node::pre_read_act(&context, 0, u64::MAX).is_none());
    }
    s.hosted.close().await;
}

// ---- the local at-rest record (design record 983490f, slice S2) ----

fn at_rest_of(s: &Setup) -> Option<AtRestRecord> {
    s.controller.store.generation_at_rest(&s.current.id)
}

/// The last receipt as the database itself has it: ordinal, chain hash and
/// which receipts DDL it carries.
async fn receipts_of(s: &Setup) -> (i64, String, &'static str) {
    let mut conn = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&s.current.snapshot_path)
            .read_only(true),
    )
    .await
    .unwrap();
    let (ordinal, chain): (i64, String) = sqlx::query_as(
        "SELECT ordinal, chain_sha256 FROM kernel_standby_apply_receipts ORDER BY ordinal DESC LIMIT 1",
    )
    .fetch_one(&mut conn)
    .await
    .unwrap();
    let ddl: String = sqlx::query_scalar(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='kernel_standby_apply_receipts'",
    )
    .fetch_one(&mut conn)
    .await
    .unwrap();
    conn.close().await.unwrap();
    let label = if ddl == crate::standby::generation_store::kernel_in_place::RECEIPTS_DDL_V2 {
        "v2"
    } else {
        "v1"
    };
    (ordinal, chain, label)
}

/// Damage one page of an INDEX, not any table row: fold the WAL into the main
/// file, then drop the last entry from an index leaf page. Every table row,
/// event, blob and receipt stays as it was; only SQLite's own structure is
/// wrong. Returns the index damaged.
async fn damage_an_index_page(s: &Setup) -> String {
    let mut conn = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&s.current.snapshot_path)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal),
    )
    .await
    .unwrap();
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&mut conn)
        .await
        .unwrap();
    let page_size: i64 = sqlx::query_scalar("PRAGMA page_size")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    let indexes: Vec<(String, i64)> = sqlx::query_as(
        "SELECT name, rootpage FROM sqlite_schema WHERE type='index' AND rootpage>1 ORDER BY name",
    )
    .fetch_all(&mut conn)
    .await
    .unwrap();
    conn.close().await.unwrap();
    let mut bytes = std::fs::read(&s.current.snapshot_path).unwrap();
    for (name, root) in indexes {
        let at = (root as usize - 1) * page_size as usize;
        // 0x0a: a leaf page of an index b-tree. Its cell count is 2 bytes at 3.
        if bytes[at] != 0x0a {
            continue;
        }
        let cells = u16::from_be_bytes([bytes[at + 3], bytes[at + 4]]);
        if cells < 2 {
            continue;
        }
        bytes[at + 3..at + 5].copy_from_slice(&(cells - 1).to_be_bytes());
        std::fs::write(&s.current.snapshot_path, bytes).unwrap();
        return name;
    }
    panic!("no single-page index with entries to damage");
}

#[tokio::test]
async fn a_passing_audit_writes_an_at_rest_record_anchored_to_the_receipts() {
    let s = audited().await;
    // Base creation and the apply-time check are weaker evidence: they wrote
    // the online-eligibility record, and no at-rest record.
    assert!(audit_of(&s).is_some());
    assert!(
        at_rest_of(&s).is_none(),
        "a weaker success writes no at-rest record"
    );
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Verified)
    );
    let record = at_rest_of(&s).expect("a passing audit records it");
    let (ordinal, chain, ddl) = receipts_of(&s).await;
    assert!(record.passed());
    assert_eq!(
        (
            record.kind.as_str(),
            record.coverage,
            record.trust_rule_version
        ),
        ("at-rest-audit", 1, 1)
    );
    assert_eq!(record.generation_id, s.current.id);
    assert!(ordinal >= 1, "the fixture applied a delta");
    assert_eq!(
        (
            record.ordinal,
            record.chain_sha256.as_str(),
            record.receipts_ddl.as_str()
        ),
        (ordinal, chain.as_str(), ddl)
    );
    assert_eq!(ddl, "v2", "the set path moved the copy to the second DDL");
    assert!(record.acquired().is_some());
    s.hosted.close().await;
}

#[tokio::test]
async fn index_page_corruption_fails_the_audit_and_writes_a_failed_record() {
    let s = audited().await;
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Verified)
    );
    assert!(at_rest_of(&s).unwrap().passed());
    let index = damage_an_index_page(&s).await;
    // What the audit judged before this slice cannot see the damage: the rows,
    // events, blobs and receipts are all intact.
    s.controller
        .store
        .check_in_place_integrity(&s.current, IntegrityDepth::Full)
        .await
        .unwrap_or_else(|error| panic!("receipt Full alone must pass ({index}): {error}"));
    let (checked, _) = s
        .controller
        .store
        .check_in_place_at_rest_acquired(&s.current)
        .await;
    let error = checked.unwrap_err().to_string();
    assert!(error.contains("quick_check"), "{index}: {error}");
    // The scheduled audit fails, and its failure replaces the standing pass.
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Failed)
    );
    let record = at_rest_of(&s).unwrap();
    assert!(!record.passed(), "{record:?}");
    assert_eq!(record.kind, "at-rest-audit");
    assert_eq!(audit_of(&s).unwrap().outcome, AUDIT_FAILED);
    s.hosted.close().await;
}

#[tokio::test]
async fn a_foreign_key_violation_fails_the_audit_and_writes_a_failed_record() {
    let s = audited().await;
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Verified)
    );
    s.plant_orphan().await;
    // The named check fails first (it is cheap, so it runs before the long
    // receipt check), not a digest mismatch behind it.
    let (checked, _) = s
        .controller
        .store
        .check_in_place_at_rest_acquired(&s.current)
        .await;
    let error = checked.unwrap_err().to_string();
    assert!(error.contains("foreign-key"), "{error}");
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Failed)
    );
    assert!(!at_rest_of(&s).unwrap().passed());
    s.hosted.close().await;
}

#[tokio::test]
async fn a_later_weak_success_leaves_the_passing_record_unchanged() {
    let s = audited().await;
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Verified)
    );
    let passed = s.controller.store.raw_at_rest_bytes(&s.current.id).unwrap();
    let eligibility = audit_of(&s).unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    // `admit_kernel_in_place` at Full succeeds and refreshes the online
    // eligibility record with a LATER snapshot...
    s.controller
        .store
        .admit_kernel_in_place(&s.current, IntegrityDepth::Full)
        .await
        .unwrap();
    assert!(audit_of(&s).unwrap().acquired() > eligibility.acquired());
    // ...but never the at-rest record.
    assert_eq!(
        s.controller.store.raw_at_rest_bytes(&s.current.id).unwrap(),
        passed
    );
    s.hosted.close().await;
}

#[tokio::test]
async fn a_full_scan_apply_and_a_base_receipt_never_write_a_passing_at_rest_record() {
    let mut s = setup().await;
    pin_audit_interval(&mut s);
    // First-DDL copy: the base receipt and every apply scan the whole database.
    first_in_place_delta(&mut s, 1).await;
    let eligibility = audit_of(&s).unwrap();
    assert_eq!(eligibility.outcome, AUDIT_VERIFIED);
    assert!(
        at_rest_of(&s).is_none(),
        "base + full-scan success: no record"
    );
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Verified)
    );
    let passed = s.controller.store.raw_at_rest_bytes(&s.current.id).unwrap();
    // Another full-scan apply refreshes online eligibility, not the at-rest record.
    s.hosted_adds_records(1).await;
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    assert!(audit_of(&s).unwrap().acquired() > eligibility.acquired());
    assert_eq!(
        s.controller.store.raw_at_rest_bytes(&s.current.id).unwrap(),
        passed
    );
    s.hosted.close().await;
}

#[tokio::test]
async fn a_weak_writer_failure_writes_a_failed_at_rest_record() {
    // A failed admission (the weak writer) revokes a standing pass at once.
    let s = audited().await;
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Verified)
    );
    assert!(at_rest_of(&s).unwrap().passed());
    s.corrupt_projection().await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert!(s
        .controller
        .store
        .admit_kernel_in_place(&s.current, IntegrityDepth::Full)
        .await
        .is_err());
    let record = at_rest_of(&s).unwrap();
    assert!(!record.passed(), "{record:?}");
    s.hosted.close().await;

    // An in-place apply that refuses on the receipts does the same, even though
    // it never reached a verdict of its own.
    let mut s = audited().await;
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Verified)
    );
    s.corrupt("UPDATE kernel_standby_apply_receipts SET fixed_sha256=printf('%x', instr('0123456789abcdef', substr(fixed_sha256,1,1)) % 16) || substr(fixed_sha256,2) WHERE ordinal=(SELECT MAX(ordinal) FROM kernel_standby_apply_receipts)")
        .await;
    s.forget_rest();
    s.hosted_adds_records(1).await;
    let server = serve_as(&mut s, 1, AuthorityFault::AdvertiseV2).await;
    let _ = s.refresh().await;
    server.abort();
    assert!(!at_rest_of(&s).unwrap().passed());
    s.hosted.close().await;
}

#[tokio::test]
async fn an_error_saving_the_at_rest_record_leaves_no_passing_record_and_eligibility_still_advances(
) {
    let s = audited().await;
    age_verdict(&s, Age::seconds(N as i64 * 2 + 60), AUDIT_VERIFIED);
    let before = audit_of(&s).unwrap();
    FAIL_AT_REST_WRITE.with(|flag| flag.set(true));
    // The audit itself passed: its result and today's success handling stand.
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Verified)
    );
    assert!(at_rest_of(&s).is_none(), "no passing at-rest record exists");
    assert!(
        audit_of(&s).unwrap().acquired() > before.acquired(),
        "the online-eligibility record still advanced"
    );
    let (provider, _active) = provider(&s).await;
    assert_eq!(state_of(&provider).0, "current");
    // The next healthy audit writes it.
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Verified)
    );
    assert!(at_rest_of(&s).unwrap().passed());
    s.hosted.close().await;
}

#[tokio::test]
async fn an_infrastructure_error_writes_no_at_rest_record() {
    let s = audited().await;
    FORCE_INFRASTRUCTURE_ERROR.with(|flag| flag.set(true));
    assert!(s.controller.audit_once().await.is_err());
    assert!(at_rest_of(&s).is_none());
    s.hosted.close().await;
}

#[tokio::test]
async fn the_first_audit_after_a_restart_or_a_ddl_change_is_due_at_once() {
    let s = audited().await;
    let n = Duration::from_secs(N);
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Verified)
    );
    // This process has just seen an audit pass: the next one waits its interval.
    let wait = s.controller.next_audit_delay(n).await;
    assert!(wait > Duration::from_secs(N - 30) && wait <= n, "{wait:?}");
    // A restart: a fresh process has observed nothing, whatever the record says.
    s.controller.store.forget_audit_observations();
    assert_eq!(s.controller.next_audit_delay(n).await, Duration::ZERO);
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Verified)
    );
    assert!(s.controller.next_audit_delay(n).await > Duration::from_secs(N - 30));
    // A receipts-DDL change since the record was written (an upgrade rewrote
    // the chain): due at once even though this process has seen a success.
    let mut record = at_rest_of(&s).unwrap();
    assert_eq!(record.receipts_ddl, "v2");
    record.receipts_ddl = "v1".into();
    std::fs::write(
        s.controller.store.at_rest_file(&s.current.id),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    assert_eq!(s.controller.next_audit_delay(n).await, Duration::ZERO);
    // No at-rest record at all: due at once.
    s.controller.store.remove_at_rest(&s.current.id);
    assert_eq!(s.controller.next_audit_delay(n).await, Duration::ZERO);
    s.hosted.close().await;
}

#[tokio::test]
async fn a_copy_whose_latest_verdict_is_a_failure_is_not_audited_in_a_tight_loop() {
    let s = audited().await;
    s.corrupt_projection().await;
    assert_eq!(
        s.controller.audit_once().await.unwrap(),
        Some(AuditResult::Failed)
    );
    // It waits for a whole snapshot; the audit schedule does not spin on it.
    assert!(
        s.controller.next_audit_delay(Duration::from_secs(N)).await > Duration::from_secs(N - 30)
    );
    s.hosted.close().await;
}
