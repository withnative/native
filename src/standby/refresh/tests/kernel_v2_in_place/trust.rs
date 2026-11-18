//! Trusting an in-place-advanced copy by what was checked as it was applied
//! (design record 983490f, slice S3). A restart, a rebind or a handoff skips
//! the whole-file pass only when a qualifying at-rest audit record, a
//! strengthened Light check and the receipt suffix all agree; every doubt
//! takes today's full path. Disposable databases only.
use super::set_path::refresh_v2;
use super::*;
use crate::standby::generation_store::kernel_in_place::at_rest::{
    AtRestEvidence, TRUST_RULE_VERSION,
};
use crate::standby::generation_store::test_diagnostics::{Capture, LOG_CAPTURE_LOCK};
use tracing::instrument::WithSubscriber;

const N: u64 = 900;

/// A set-path copy with one delta applied, audited once: a qualifying record.
pub(crate) async fn audited_and_recorded() -> Setup {
    let mut s = setup().await;
    // The config too: each refresh re-applies its interval to the store.
    s.controller.config.kernel_audit_interval_seconds = Some(N);
    s.controller
        .store
        .set_audit_interval(Some(Duration::from_secs(N)));
    refresh_v2(&mut s).await;
    assert!(s.controller.audit_once().await.unwrap().is_some());
    assert!(s
        .controller
        .store
        .generation_at_rest(&s.current.id)
        .unwrap()
        .passed());
    s
}

fn phase_ran(logs: &str, phase: &str) -> bool {
    logs.lines().any(|line| {
        line.contains("standby phase finished") && line.contains(&format!("phase=\"{phase}\""))
    })
}

fn trusted_ok(logs: &str) -> bool {
    logs.lines().any(|line| {
        line.contains("standby phase finished")
            && line.contains("phase=\"startup-trusted-at-rest\"")
            && line.contains("ok=true")
    })
}

/// A cold start, with its verification phases captured.
async fn restart(s: &Setup) -> (bool, String) {
    let _guard = LOG_CAPTURE_LOCK.lock().await;
    let logs = Capture::default();
    let store = s.restarted_store();
    let outcome = store
        .activate_for_startup(&s.controller.observed)
        .with_subscriber(logs.subscriber())
        .await;
    (
        matches!(outcome, Ok(StandbyStartupOutcome::Serving(_))),
        logs.output(),
    )
}

async fn trusted(s: &Setup) -> bool {
    s.restarted_store()
        .trusted_for_use(&s.current.id, &s.controller.observed)
        .await
}

fn at_rest_path(s: &Setup) -> std::path::PathBuf {
    s.controller.store.at_rest_file(&s.current.id)
}

fn edit_at_rest(s: &Setup, edit: impl FnOnce(&mut serde_json::Value)) {
    let path = at_rest_path(s);
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    edit(&mut value);
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

#[tokio::test]
async fn a_restart_with_a_qualifying_record_runs_no_whole_file_pass() {
    let s = audited_and_recorded().await;
    assert!(trusted(&s).await);
    let (serving, logs) = restart(&s).await;
    assert!(serving, "{logs}");
    assert!(trusted_ok(&logs), "{logs}");
    // Honest accounting: a trusted pass logs under its own phase and reason,
    // and is not a full verification pass (that line is where the status
    // counters are fed from).
    assert!(
        logs.lines()
            .any(|line| line.contains("phase=\"startup-generation-trusted\"")
                && line.contains("reason=\"startup\"")
                && line.contains("ok=true")),
        "{logs}"
    );
    assert!(
        !logs.contains("phase=\"startup-generation-verify\""),
        "{logs}"
    );
    for full in [
        "startup-snapshot",
        "advanced-consistent-copy",
        "sqlite-quick-check-foreign-keys",
        "kernel-in-place-integrity",
    ] {
        assert!(!phase_ran(&logs, full), "{full} ran:\n{logs}");
    }
    // Deltas applied since the audit are checked as a suffix, and still trusted.
    let mut s = s;
    refresh_v2(&mut s).await;
    let (serving, logs) = restart(&s).await;
    assert!(serving && trusted_ok(&logs), "{logs}");
    assert!(!phase_ran(&logs, "startup-snapshot"));
    s.hosted.close().await;
}

#[tokio::test]
async fn without_a_qualifying_record_the_full_pass_runs_exactly_as_before() {
    let s = audited_and_recorded().await;
    let legacy = serde_json::json!({
        "generation_id": s.current.id, "ordinal": 1, "outcome": "verified",
        "snapshot_acquired_at": chrono::Utc::now().to_rfc3339(),
    });
    type Case = (&'static str, Box<dyn Fn(&Setup)>);
    let cases: Vec<Case> = vec![
        (
            "no record",
            Box::new(|s| s.controller.store.remove_at_rest(&s.current.id)),
        ),
        (
            "a legacy-kind record",
            Box::new(move |s| fs::write(at_rest_path(s), legacy.to_string()).unwrap()),
        ),
        (
            "an unknown rule version",
            Box::new(|s| {
                edit_at_rest(s, |v| {
                    v["trust_rule_version"] = (TRUST_RULE_VERSION + 1).into()
                })
            }),
        ),
        (
            "another coverage",
            Box::new(|s| edit_at_rest(s, |v| v["coverage"] = 0.into())),
        ),
        (
            "a failed record",
            Box::new(|s| {
                s.controller.store.remove_at_rest(&s.current.id);
                s.controller
                    .store
                    .write_at_rest_failed(&s.current.id, chrono::Utc::now())
                    .unwrap()
            }),
        ),
        (
            "a foreign generation's record",
            Box::new(|s| edit_at_rest(s, |v| v["generation_id"] = "0".repeat(64).into())),
        ),
    ];
    for (name, damage) in cases {
        let s = audited_and_recorded().await;
        damage(&s);
        assert!(!trusted(&s).await, "{name}");
        let (serving, logs) = restart(&s).await;
        assert!(
            serving,
            "{name}: the full pass still serves a sound copy\n{logs}"
        );
        assert!(!trusted_ok(&logs), "{name}");
        assert!(phase_ran(&logs, "startup-snapshot"), "{name}:\n{logs}");
        assert!(phase_ran(&logs, "kernel-in-place-integrity"), "{name}");
        assert!(
            logs.contains("phase=\"startup-generation-verify\"")
                && logs.contains("reason=\"startup\""),
            "{name}: a full pass is counted and labelled\n{logs}"
        );
        s.hosted.close().await;
    }
    s.hosted.close().await;
}

#[tokio::test]
async fn a_known_failed_copy_at_cold_start_takes_the_full_path() {
    let s = audited_and_recorded().await;
    // A definite damage signal on the sidecar, whatever the record says.
    let generation = s.current.clone();
    let mut head = s
        .controller
        .store
        .generation_head(&generation.id)
        .unwrap()
        .unwrap();
    head.full_refresh_required = true;
    // (Write the flag without the failed-record side effect of the helper, so
    // the sidecar alone is what blocks trust.)
    s.controller.store.write_head_for_test(&head);
    assert!(s
        .controller
        .store
        .generation_at_rest(&generation.id)
        .unwrap()
        .passed());
    assert!(!trusted(&s).await);
    let (_serving, logs) = restart(&s).await;
    assert!(!trusted_ok(&logs));
    assert!(phase_ran(&logs, "startup-snapshot"), "{logs}");
    // A failed legacy audit record is a damage signal too.
    let s2 = audited_and_recorded().await;
    s2.controller
        .store
        .write_audit(
            &s2.current.id,
            -1,
            chrono::Utc::now() + chrono::Duration::seconds(5),
            "failed",
        )
        .unwrap();
    assert!(!trusted(&s2).await);
    s.hosted.close().await;
    s2.hosted.close().await;
}

#[tokio::test]
async fn never_advanced_copies_still_take_the_byte_hash() {
    let s = setup().await;
    // Even a planted passing record cannot excuse a copy that was never
    // advanced: its manifest hash is all that identifies the bytes.
    s.controller
        .store
        .write_at_rest_passed(
            &s.current.id,
            chrono::Utc::now(),
            &AtRestEvidence {
                ordinal: 0,
                chain_sha256: "0".repeat(64),
                receipts_ddl: ReceiptsDdl::V2,
            },
        )
        .unwrap();
    assert!(!trusted(&s).await);
    let (serving, logs) = restart(&s).await;
    assert!(serving, "{logs}");
    assert!(!trusted_ok(&logs));
    assert!(
        phase_ran(&logs, "byte-manifest-consumer-identity"),
        "{logs}"
    );
    s.hosted.close().await;
}

#[tokio::test]
async fn an_older_database_restored_under_the_same_generation_refuses() {
    let mut s = audited_and_recorded().await;
    let saved = s._directory.path().join("saved.db");
    {
        let mut conn = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&s.current.snapshot_path)
                .read_only(true),
        )
        .await
        .unwrap();
        sqlx::query("VACUUM INTO ?")
            .bind(saved.to_string_lossy().as_ref())
            .execute(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();
    }
    // Advance, audit again: the record now names a later receipt.
    refresh_v2(&mut s).await;
    assert!(s.controller.audit_once().await.unwrap().is_some());
    assert!(trusted(&s).await);
    let record = s
        .controller
        .store
        .generation_at_rest(&s.current.id)
        .unwrap();
    // Restore the older database behind the sidecar and the record.
    for suffix in ["-wal", "-shm"] {
        let mut name = s.current.snapshot_path.clone().into_os_string();
        name.push(suffix);
        let _ = fs::remove_file(name);
    }
    fs::copy(&saved, &s.current.snapshot_path).unwrap();
    set_mode(&s.current.snapshot_path, 0o600).unwrap();
    assert!(!trusted(&s).await);
    // Even with the sidecar rewound to match, the record is ahead of the
    // database: the audited receipt is missing.
    let mut head = s
        .controller
        .store
        .generation_head(&s.current.id)
        .unwrap()
        .unwrap();
    head.head_act = s.current.manifest.head_act.unwrap();
    s.controller.store.write_head_for_test(&head);
    assert!(!trusted(&s).await, "{record:?}");
    s.hosted.close().await;
}

#[tokio::test]
async fn a_receipt_tampered_after_the_anchor_refuses() {
    // The chain link breaks: the stored hash no longer matches the fields.
    let mut s = audited_and_recorded().await;
    refresh_v2(&mut s).await;
    assert!(trusted(&s).await, "the suffix is sound before the tamper");
    s.corrupt("UPDATE kernel_standby_apply_receipts SET delta_sha256=printf('%x', instr('0123456789abcdef', substr(delta_sha256,1,1)) % 16) || substr(delta_sha256,2) WHERE ordinal=(SELECT MAX(ordinal) FROM kernel_standby_apply_receipts)")
        .await;
    assert!(!trusted(&s).await, "broken link");
    let (_serving, logs) = restart(&s).await;
    assert!(phase_ran(&logs, "startup-snapshot"), "{logs}");
    s.hosted.close().await;
}

/// Only the per-receipt predicates can refuse here: the chain is recomputed
/// after the tamper, so every link is valid.
#[tokio::test]
async fn a_suffix_receipt_that_breaks_the_predicates_refuses_even_with_a_valid_chain() {
    for tamper in [
        "UPDATE kernel_standby_apply_receipts SET from_act=from_act+1 WHERE ordinal=(SELECT MAX(ordinal) FROM kernel_standby_apply_receipts)",
        "UPDATE kernel_standby_apply_receipts SET content_seq_from=content_seq_from+1 WHERE ordinal=(SELECT MAX(ordinal) FROM kernel_standby_apply_receipts)",
    ] {
        let mut s = audited_and_recorded().await;
        refresh_v2(&mut s).await;
        assert!(trusted(&s).await);
        s.corrupt(tamper).await;
        rechain_receipts(&s.current.snapshot_path, &s.current, |_| ReceiptsDdl::V2)
            .await
            .unwrap();
        assert!(!trusted(&s).await, "{tamper}");
        s.hosted.close().await;
    }
}

/// The anchor's contents are authenticated by re-deriving its link, not just
/// by comparing its stored hash with the record.
#[tokio::test]
async fn an_anchor_receipt_edited_under_its_stored_hash_refuses() {
    let s = audited_and_recorded().await;
    assert!(trusted(&s).await);
    s.corrupt("UPDATE kernel_standby_apply_receipts SET delta_sha256=printf('%x', instr('0123456789abcdef', substr(delta_sha256,1,1)) % 16) || substr(delta_sha256,2) WHERE ordinal=(SELECT MAX(ordinal) FROM kernel_standby_apply_receipts)")
        .await;
    // The stored chain hash still equals the record's; only the contents moved.
    assert!(!trusted(&s).await);
    s.hosted.close().await;
}

/// A failure published after the first reads but before the verdict is used
/// must not be missed.
#[tokio::test]
async fn a_failure_published_during_the_check_is_not_missed() {
    use crate::standby::generation_store::kernel_in_place::trust::REREAD_SEAM;
    for case in [
        "failed at-rest record",
        "damage flag",
        "failed legacy audit",
    ] {
        let s = audited_and_recorded().await;
        let reached = std::sync::Arc::new(tokio::sync::Notify::new());
        let proceed = std::sync::Arc::new(tokio::sync::Notify::new());
        REREAD_SEAM.with(|seam| *seam.borrow_mut() = Some((reached.clone(), proceed.clone())));
        let store = s.restarted_store();
        let check = store.trusted_state(&s.current);
        let publish = async {
            reached.notified().await;
            match case {
                "failed at-rest record" => s
                    .controller
                    .store
                    .write_at_rest_failed(&s.current.id, chrono::Utc::now())
                    .unwrap(),
                "damage flag" => {
                    let mut head = s
                        .controller
                        .store
                        .generation_head(&s.current.id)
                        .unwrap()
                        .unwrap();
                    head.full_refresh_required = true;
                    s.controller.store.write_head_for_test(&head);
                }
                _ => s
                    .controller
                    .store
                    .write_audit(
                        &s.current.id,
                        -1,
                        chrono::Utc::now() + chrono::Duration::seconds(5),
                        "failed",
                    )
                    .unwrap(),
            }
            proceed.notify_one();
        };
        let (verdict, ()) = tokio::join!(check, publish);
        assert!(!verdict, "{case}");
        s.hosted.close().await;
    }
}

/// A caller that did not opt into trust always gets the full checks, even for
/// a copy a trusting caller would accept, and even when a trusted receipt
/// already exists. A trusted result is never reused where a full one is needed.
#[tokio::test]
async fn a_caller_that_did_not_opt_in_always_runs_the_full_checks() {
    let s = audited_and_recorded().await;
    let mut next = s.controller.observed.clone();
    next.source_sha = "8".repeat(40);
    next.artifact_sha256 = "7".repeat(64);
    let store = s.restarted_store();
    let id = s.current.id.clone();
    // A retention-style call on a rebind-eligible, trusted copy: full phases,
    // full receipt, a stamp that counts as a whole-file proof.
    {
        let _guard = LOG_CAPTURE_LOCK.lock().await;
        let logs = Capture::default();
        store
            .verify_plain_for_test(&id, &next)
            .with_subscriber(logs.subscriber())
            .await
            .unwrap();
        let logs = logs.output();
        assert!(!trusted_ok(&logs), "{logs}");
        assert!(phase_ran(&logs, "startup-snapshot"), "{logs}");
        assert!(phase_ran(&logs, "kernel-in-place-integrity"), "{logs}");
    }
    let receipt = store.consumer_rebind(&id, &next).unwrap().unwrap();
    assert!(receipt
        .checks_passed
        .iter()
        .any(|check| check == "sqlite-quick-check-foreign-keys"));
    assert_eq!(store.stamps_for_test(&id, &next), (Some(true), Some(true)));
    s.hosted.close().await;

    // A trusting pass leaves a stamp that is NOT a whole-file proof, and a
    // later plain call still runs everything (it reuses nothing of it), even
    // though a trusted rebind receipt is already there.
    let s = audited_and_recorded().await;
    let store = s.restarted_store();
    let id = s.current.id.clone();
    {
        let _guard = LOG_CAPTURE_LOCK.lock().await;
        let logs = Capture::default();
        store
            .verify_trusting_for_test(&id, &next)
            .with_subscriber(logs.subscriber())
            .await
            .unwrap();
        let logs = logs.output();
        assert!(trusted_ok(&logs), "{logs}");
        assert!(!phase_ran(&logs, "startup-snapshot"), "{logs}");
    }
    assert!(store
        .consumer_rebind(&id, &next)
        .unwrap()
        .unwrap()
        .checks_passed
        .last()
        .unwrap()
        .starts_with("trusted-at-rest:"));
    assert_eq!(
        store.stamps_for_test(&id, &next),
        (None, Some(true)),
        "trusted: status may show it, retention may not rely on it"
    );
    {
        let _guard = LOG_CAPTURE_LOCK.lock().await;
        let logs = Capture::default();
        store
            .verify_plain_for_test(&id, &next)
            .with_subscriber(logs.subscriber())
            .await
            .unwrap();
        let logs = logs.output();
        assert!(!trusted_ok(&logs), "{logs}");
        assert!(phase_ran(&logs, "startup-snapshot"), "{logs}");
    }
    assert_eq!(store.stamps_for_test(&id, &next), (Some(true), Some(true)));
    s.hosted.close().await;
}
#[tokio::test]
async fn the_audited_receipt_must_still_have_its_recorded_chain_hash() {
    let s = audited_and_recorded().await;
    s.corrupt("UPDATE kernel_standby_apply_receipts SET chain_sha256=printf('%x', instr('0123456789abcdef', substr(chain_sha256,1,1)) % 16) || substr(chain_sha256,2) WHERE ordinal=(SELECT MAX(ordinal) FROM kernel_standby_apply_receipts)")
        .await;
    assert!(!trusted(&s).await);
    s.hosted.close().await;
}

#[tokio::test]
async fn a_changed_derived_table_refuses_where_plain_light_does_not() {
    let s = audited_and_recorded().await;
    s.corrupt("INSERT INTO content_event_heads(event_id) VALUES('forged-head')")
        .await;
    // Today's Light does not look at derived tables...
    s.restarted_store()
        .check_in_place_integrity(&s.current, IntegrityDepth::Light)
        .await
        .expect("plain Light passes");
    // ...the strengthened check does.
    assert!(!trusted(&s).await);
    s.hosted.close().await;
}

#[tokio::test]
async fn a_wrong_origin_or_checkpoint_identity_refuses() {
    let s = audited_and_recorded().await;
    assert!(s.restarted_store().trusted_state(&s.current).await);
    let mut other = s.current.clone();
    other.manifest.origin_database_id = format!("ndb_{}", "1".repeat(32));
    assert!(!s.restarted_store().trusted_state(&other).await, "origin");
    let mut other = s.current.clone();
    other.manifest.kernel_v2.as_mut().unwrap().genesis_event_id =
        "00000000-0000-4000-8000-000000000000".into();
    assert!(!s.restarted_store().trusted_state(&other).await, "genesis");
    let mut other = s.current.clone();
    other.manifest.kernel_v2.as_mut().unwrap().schema_sha256 = "f".repeat(64);
    assert!(!s.restarted_store().trusted_state(&other).await, "schema");
    s.hosted.close().await;
}

#[tokio::test]
async fn a_qualifying_record_never_waives_account_or_consumer_binding() {
    let s = audited_and_recorded().await;
    assert!(trusted(&s).await);
    // A consumer the copy was never bound to, with no rebind receipt: refused,
    // and startup for it takes the full path.
    let mut stranger = s.controller.observed.clone();
    stranger.source_sha = "9".repeat(40);
    stranger.artifact_sha256 = "6".repeat(64);
    let mut other_platform = s.controller.observed.clone();
    other_platform.platform = match other_platform.platform {
        crate::standby_snapshot::StandbyConsumerPlatform::MacosArm64 => {
            crate::standby_snapshot::StandbyConsumerPlatform::LinuxX8664
        }
        _ => crate::standby_snapshot::StandbyConsumerPlatform::MacosArm64,
    };
    assert!(
        !s.restarted_store()
            .trusted_for_use(&s.current.id, &other_platform)
            .await
    );
    assert!(
        !s.restarted_store()
            .trusted_for_use(&s.current.id, &stranger)
            .await
    );
    // Another account: a store configured for a different origin does not
    // even recognise the generation.
    let foreign = GenerationStore::open(
        &s.controller.runtime.replica_root,
        "route-1",
        Some(format!("ndb_{}", "2".repeat(32))),
    )
    .unwrap();
    assert!(
        !foreign
            .trusted_for_use(&s.current.id, &s.controller.observed)
            .await
    );
    // Another route likewise.
    let other_route = GenerationStore::open(
        &s.controller.runtime.replica_root,
        "route-2",
        Some(s.controller.runtime.origin_database_id.clone()),
    )
    .unwrap();
    assert!(
        !other_route
            .trusted_for_use(&s.current.id, &s.controller.observed)
            .await
    );
    s.hosted.close().await;
}

#[tokio::test]
async fn a_same_format_rebind_of_a_trusted_copy_skips_the_whole_file_pass_and_binds() {
    let s = audited_and_recorded().await;
    let mut next = s.controller.observed.clone();
    next.source_sha = "8".repeat(40);
    next.artifact_sha256 = "7".repeat(64);
    let store = s.restarted_store();
    let (verified, logs) = {
        let _guard = LOG_CAPTURE_LOCK.lock().await;
        let logs = Capture::default();
        let verified = store
            .ensure_consumer_binding_depth(&s.current.id, &next, true)
            .with_subscriber(logs.subscriber())
            .await
            .unwrap();
        (verified, logs.output())
    };
    assert_eq!(verified, (true, true));
    // Immediately afterwards the stamp is not a whole-file proof.
    assert_eq!(
        store.stamps_for_test(&s.current.id, &next),
        (None, Some(true))
    );
    assert!(trusted_ok(&logs), "{logs}");
    assert!(!phase_ran(&logs, "startup-snapshot"), "{logs}");
    // It bound, and the receipt says what actually ran: the trust and the
    // audited ordinal, not the byte or SQLite health checks.
    let receipt = store
        .consumer_rebind(&s.current.id, &next)
        .unwrap()
        .expect("a trusted rebind still binds");
    let ordinal = s
        .controller
        .store
        .generation_at_rest(&s.current.id)
        .unwrap()
        .ordinal;
    assert_eq!(
        receipt.checks_passed.last().unwrap(),
        &format!("trusted-at-rest:{ordinal}")
    );
    for ran_not in [
        "checkpoint-bytes-or-consistent-copy",
        "sqlite-quick-check-foreign-keys",
    ] {
        assert!(!receipt.checks_passed.iter().any(|check| check == ran_not));
    }
    s.hosted.close().await;

    // Without a qualifying record the rebind runs every check as before.
    let s = audited_and_recorded().await;
    s.controller.store.remove_at_rest(&s.current.id);
    let store = s.restarted_store();
    let _guard = LOG_CAPTURE_LOCK.lock().await;
    let logs = Capture::default();
    store
        .ensure_consumer_binding_depth(&s.current.id, &next, true)
        .with_subscriber(logs.subscriber())
        .await
        .unwrap();
    let logs = logs.output();
    assert!(!trusted_ok(&logs));
    assert!(phase_ran(&logs, "startup-snapshot"), "{logs}");
    assert!(phase_ran(&logs, "kernel-in-place-integrity"), "{logs}");
    // The full rebind records the full list.
    let receipt = store
        .consumer_rebind(&s.current.id, &next)
        .unwrap()
        .unwrap();
    assert!(receipt
        .checks_passed
        .iter()
        .any(|check| check == "sqlite-quick-check-foreign-keys"));
    s.hosted.close().await;
}

/// Prepare takes the same at-rest trust as the node's own rebind: no whole-file
/// pass, a receipt that says exactly that, and nothing else written beside a
/// serving process (head sidecar, audit, accumulator marker).
#[tokio::test]
async fn prepare_trusts_an_audited_copy_and_writes_only_a_truthful_receipt() {
    let s = audited_and_recorded().await;
    let mut next = s.controller.observed.clone();
    next.source_sha = "8".repeat(40);
    next.artifact_sha256 = "7".repeat(64);
    let store = s.restarted_store();
    let before = super::sidecars(&s);
    let (prepared, logs) = {
        let _guard = LOG_CAPTURE_LOCK.lock().await;
        let logs = Capture::default();
        let prepared = store
            .prepare_consumer_binding(&next)
            .with_subscriber(logs.subscriber())
            .await
            .unwrap();
        (prepared, logs.output())
    };
    assert_eq!(prepared.outcome, crate::standby::PreparedOutcome::Verified);
    assert!(prepared.trusted_at_rest);
    assert!(!phase_ran(&logs, "startup-snapshot"), "{logs}");
    let after = super::sidecars(&s);
    for (path, bytes) in &before {
        assert_eq!(after.get(path), Some(bytes), "{} changed", path.display());
    }
    assert_eq!(after.len(), before.len() + 1);
    let receipt = store
        .consumer_rebind(&s.current.id, &next)
        .unwrap()
        .expect("prepare bound the consumer");
    assert!(receipt
        .checks_passed
        .last()
        .unwrap()
        .starts_with("trusted-at-rest:"));
    assert!(!receipt
        .checks_passed
        .iter()
        .any(|check| check == "sqlite-quick-check-foreign-keys"));
    // A second run reuses it.
    let again = store.prepare_consumer_binding(&next).await.unwrap();
    assert_eq!(
        again.outcome,
        crate::standby::PreparedOutcome::ReceiptReused
    );
    s.hosted.close().await;
}

#[tokio::test]
async fn a_rebind_of_a_copy_tampered_after_the_audit_still_refuses() {
    let mut s = audited_and_recorded().await;
    refresh_v2(&mut s).await;
    s.corrupt("UPDATE kernel_standby_apply_receipts SET from_act=from_act+1 WHERE ordinal=(SELECT MAX(ordinal) FROM kernel_standby_apply_receipts)")
        .await;
    let mut next = s.controller.observed.clone();
    next.source_sha = "8".repeat(40);
    next.artifact_sha256 = "7".repeat(64);
    let store = s.restarted_store();
    assert!(store
        .ensure_consumer_binding_depth(&s.current.id, &next, true)
        .await
        .is_err());
    assert!(store
        .consumer_rebind(&s.current.id, &next)
        .ok()
        .flatten()
        .is_none());
    s.hosted.close().await;
}

// ---- S3 part 2: routine operation on the current copy ----

async fn captured<T>(work: impl std::future::Future<Output = T>) -> (T, String) {
    let _guard = LOG_CAPTURE_LOCK.lock().await;
    let logs = Capture::default();
    let value = work.with_subscriber(logs.subscriber()).await;
    (value, logs.output())
}

fn whole_file_phases(logs: &str) -> Vec<&'static str> {
    [
        "startup-snapshot",
        "advanced-consistent-copy",
        "sqlite-quick-check-foreign-keys",
        "kernel-in-place-integrity",
    ]
    .into_iter()
    .filter(|phase| phase_ran(logs, phase))
    .collect()
}

fn pass_line<'a>(logs: &'a str, phase: &str, id: &str) -> Option<&'a str> {
    logs.lines().find(|line| {
        line.contains(&format!("phase=\"{phase}\""))
            && line.contains(&format!("generation_id=\"{id}\""))
    })
}

#[tokio::test]
async fn a_qualifying_current_copy_goes_through_a_sweep_and_a_deferred_check_without_a_full_pass() {
    let s = audited_and_recorded().await;
    let store = s.restarted_store();
    let observed = s.controller.observed.clone();
    let id = s.current.id.clone();
    let (swept, logs) = captured(async {
        let swept = store.sweep_for_test(&observed).await;
        let deferred = store
            .deferred_handoff_check_for_test(&s.current, &observed)
            .await;
        (swept, deferred)
    })
    .await;
    swept.0.unwrap();
    swept.1.unwrap();
    assert!(
        whole_file_phases(&logs).is_empty(),
        "{:?}\n{logs}",
        whole_file_phases(&logs)
    );
    assert!(trusted_ok(&logs), "{logs}");
    let line =
        pass_line(&logs, "startup-generation-trusted", &id).expect("a trusted pass is logged");
    assert!(line.contains("ok=true"), "{line}");
    assert!(
        pass_line(&logs, "startup-generation-verify", &id).is_none(),
        "no pass was counted as a full verification:\n{logs}"
    );
    // The trusted stamp is "already verified" for the current copy: a second
    // sweep does not run the trust check again...
    let ran = |logs: &str| logs.matches("phase=\"startup-trusted-at-rest\"").count();
    let (again, more) = captured(store.sweep_for_test(&observed)).await;
    again.unwrap();
    assert_eq!(ran(&more), 0, "{more}");
    // ...and a refresh finishing does not reschedule a sweep for it.
    let (_, rescheduled) = captured(async {
        drop(store.retry_verification_after_refresh(&observed));
        store.maintenance_idle().await;
    })
    .await;
    assert!(
        !rescheduled.contains("background-retention"),
        "{rescheduled}"
    );
    // Retention's own strict view is unchanged: not a whole-file proof.
    assert_eq!(store.stamps_for_test(&id, &observed), (None, Some(true)));
    s.hosted.close().await;
}

#[tokio::test]
async fn a_copy_that_does_not_qualify_still_runs_the_full_pass_in_a_sweep() {
    type Damage = Box<dyn Fn(&Setup)>;
    let cases: Vec<(&str, Damage)> = vec![
        (
            "no record",
            Box::new(|s| s.controller.store.remove_at_rest(&s.current.id)),
        ),
        (
            "a failed record",
            Box::new(|s| {
                s.controller.store.remove_at_rest(&s.current.id);
                s.controller
                    .store
                    .write_at_rest_failed(&s.current.id, chrono::Utc::now())
                    .unwrap()
            }),
        ),
        (
            "a damage flag",
            Box::new(|s| {
                let mut head = s
                    .controller
                    .store
                    .generation_head(&s.current.id)
                    .unwrap()
                    .unwrap();
                head.full_refresh_required = true;
                s.controller.store.write_head_for_test(&head);
            }),
        ),
    ];
    for (name, damage) in cases {
        let s = audited_and_recorded().await;
        damage(&s);
        let store = s.restarted_store();
        let observed = s.controller.observed.clone();
        let id = s.current.id.clone();
        let (swept, logs) = captured(async {
            let swept = store.sweep_for_test(&observed).await;
            let deferred = store
                .deferred_handoff_check_for_test(&s.current, &observed)
                .await;
            (swept, deferred)
        })
        .await;
        swept.0.unwrap();
        let _ = swept.1;
        assert!(!trusted_ok(&logs), "{name}\n{logs}");
        assert!(phase_ran(&logs, "startup-snapshot"), "{name}\n{logs}");
        assert!(
            pass_line(&logs, "startup-generation-verify", &id)
                .is_some_and(|line| line.contains("reason=\"maintenance_recheck\"")
                    || line.contains("reason=\"handoff\"")),
            "{name}: counted and labelled\n{logs}"
        );
        s.hosted.close().await;
    }
}

/// Priors stay on the plain verifier even when they are advanced and carry a
/// qualifying record: retention's deletion floor needs a whole-file proof.
#[tokio::test]
async fn an_advanced_prior_in_a_sweep_still_gets_the_plain_verifier() {
    use crate::standby::generation_store::kernel_in_place::RECHECKPOINT_OVERRIDE;
    let mut s = audited_and_recorded().await;
    let prior = s.current.id.clone();
    // Re-checkpoint: the advanced, audited copy becomes a prior.
    s.hosted_adds_records(1).await;
    RECHECKPOINT_OVERRIDE.with(|cell| cell.set(Some((1, i64::MAX))));
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    RECHECKPOINT_OVERRIDE.with(|cell| cell.set(None));
    let current = s
        .controller
        .store
        .current_for_head_probe()
        .unwrap()
        .unwrap();
    assert_ne!(current.id, prior);
    assert!(s
        .controller
        .store
        .generation_at_rest(&prior)
        .unwrap()
        .passed());
    let store = s.restarted_store();
    let observed = s.controller.observed.clone();
    let (swept, logs) = captured(store.sweep_for_test(&observed)).await;
    swept.unwrap();
    let line = pass_line(&logs, "startup-generation-verify", &prior)
        .unwrap_or_else(|| panic!("the prior takes a counted full pass:\n{logs}"));
    assert!(line.contains("reason=\"retention\""), "{line}");
    assert!(
        pass_line(&logs, "startup-generation-trusted", &prior).is_none(),
        "{logs}"
    );
    assert!(phase_ran(&logs, "kernel-in-place-integrity"), "{logs}");
    // Serving and deletion rules are unchanged: current is still the new
    // checkpoint and nothing was pruned (three generations or fewer).
    assert_eq!(
        store.current_for_head_probe().unwrap().unwrap().id,
        current.id
    );
    assert!(s.current.snapshot_path.exists(), "the prior was not pruned");
    s.hosted.close().await;
}

#[tokio::test]
async fn the_refresh_controller_rebinds_a_qualifying_serving_copy_without_a_full_pass() {
    let mut s = audited_and_recorded().await;
    let mut next = s.controller.observed.clone();
    next.source_sha = "8".repeat(40);
    next.artifact_sha256 = "7".repeat(64);
    s.controller.observed = next.clone();
    s.hosted_adds_records(1).await;
    let server = s.serve(1).await;
    let (_outcome, logs) = captured(s.refresh()).await;
    server.abort();
    assert!(trusted_ok(&logs), "{logs}");
    let receipt = s
        .controller
        .store
        .consumer_rebind(&s.current.id, &next)
        .unwrap()
        .expect("the serving copy was re-bound");
    assert!(
        receipt
            .checks_passed
            .last()
            .unwrap()
            .starts_with("trusted-at-rest:"),
        "{:?}",
        receipt.checks_passed
    );
    s.hosted.close().await;
}

/// The handoff's predecessor recheck, reached without a matching live
/// predecessor (its fallback branch).
#[tokio::test]
async fn the_predecessor_recheck_fallback_trusts_only_a_qualifying_current_copy() {
    // Qualifying: the trusted phase, labelled, and no whole-file phase.
    let s = audited_and_recorded().await;
    let id = s.current.id.clone();
    let observed = s.controller.observed.clone();
    let store = s.restarted_store();
    let (result, logs) = captured(store.predecessor_fallback_for_test(&id, &observed)).await;
    result.unwrap();
    assert!(trusted_ok(&logs), "{logs}");
    assert!(whole_file_phases(&logs).is_empty(), "{logs}");
    let line = pass_line(&logs, "startup-generation-trusted", &id).expect("logged as trusted");
    assert!(line.contains("reason=\"predecessor_recheck\""), "{line}");
    assert!(
        pass_line(&logs, "startup-generation-verify", &id).is_none(),
        "{logs}"
    );
    s.hosted.close().await;

    // Not qualifying: the full pass, counted under the same label.
    for name in ["no record", "a failed record"] {
        let s = audited_and_recorded().await;
        s.controller.store.remove_at_rest(&s.current.id);
        if name == "a failed record" {
            s.controller
                .store
                .write_at_rest_failed(&s.current.id, chrono::Utc::now())
                .unwrap();
        }
        let id = s.current.id.clone();
        let store = s.restarted_store();
        let (result, logs) =
            captured(store.predecessor_fallback_for_test(&id, &s.controller.observed)).await;
        result.unwrap();
        assert!(!trusted_ok(&logs), "{name}\n{logs}");
        assert!(phase_ran(&logs, "startup-snapshot"), "{name}\n{logs}");
        assert!(
            phase_ran(&logs, "kernel-in-place-integrity"),
            "{name}\n{logs}"
        );
        assert!(
            pass_line(&logs, "startup-generation-verify", &id)
                .is_some_and(|line| line.contains("reason=\"predecessor_recheck\"")),
            "{name}\n{logs}"
        );
        s.hosted.close().await;
    }

    // Never advanced: still the byte hash, even with a planted passing record.
    let s = setup().await;
    s.controller
        .store
        .write_at_rest_passed(
            &s.current.id,
            chrono::Utc::now(),
            &AtRestEvidence {
                ordinal: 0,
                chain_sha256: "0".repeat(64),
                receipts_ddl: ReceiptsDdl::V2,
            },
        )
        .unwrap();
    let id = s.current.id.clone();
    let store = s.restarted_store();
    let (result, logs) =
        captured(store.predecessor_fallback_for_test(&id, &s.controller.observed)).await;
    result.unwrap();
    assert!(!trusted_ok(&logs), "{logs}");
    assert!(
        phase_ran(&logs, "byte-manifest-consumer-identity"),
        "{logs}"
    );
    s.hosted.close().await;
}
