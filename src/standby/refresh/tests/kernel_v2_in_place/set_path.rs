//! The set path of an in-place apply (design record 5065900, slice 5 / N2).
//! Disposable databases and localhost HTTP only.
use super::*;
use crate::kernel::projection_capture::Anomaly;
use crate::standby::generation_store::kernel_in_place::set_path::{
    FORCE_ANOMALY, FORCE_COMPOSE_ERROR, FORCE_N1,
};
use serde_json::{json, Value};

/// Serve `refreshes` delta-only attempts (a head probe and a delta each, one
/// more call for a refused version-2 request) from a hosted of this kind.
pub(super) async fn serve_as(
    s: &mut Setup,
    calls: usize,
    fault: AuthorityFault,
) -> tokio::task::JoinHandle<()> {
    let (port, server) = serve_authority_act_calls_with(s.hosted.clone(), calls, fault).await;
    s.controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    server
}

/// One refresh against a hosted that offers version 2; returns the replay
/// record the attempt left, then forgets the cooldown so the next can run.
pub(super) async fn refresh_v2(s: &mut Setup) -> Value {
    s.hosted_adds_records(1).await;
    refresh_as(s, 2, AuthorityFault::AdvertiseV2).await
}

/// Nothing about the projection proof is due: the next follow takes the
/// proof-less version 3 delta a version-3 host offers.
pub(super) fn proof_not_due(s: &Setup) {
    let mut audit = s.controller.proof_audit.lock().unwrap();
    audit.last = Some(std::time::Instant::now());
    audit.trouble = false;
}

fn proof_state(s: &Setup) -> (Option<std::time::Instant>, bool) {
    let audit = s.controller.proof_audit.lock().unwrap();
    (audit.last, audit.trouble)
}

/// One refresh against a hosted that also offers version 3 (no projection
/// digest) with no audit due. Today's hosted advertises at most `[1, 2]`; this
/// scripts the host a later increment will make.
pub(super) async fn refresh_v3(s: &mut Setup) -> Value {
    proof_not_due(s);
    s.hosted_adds_records(1).await;
    refresh_as(s, 2, AuthorityFault::AdvertiseV3).await
}

pub(super) async fn refresh_as(s: &mut Setup, calls: usize, fault: AuthorityFault) -> Value {
    let server = serve_as(s, calls, fault).await;
    advanced(s).await;
    server.await.unwrap();
    let record = replay_record(&s.controller);
    s.forget_rest();
    record
}

async fn receipt_rows(s: &Setup) -> Vec<(i64, String, bool, bool)> {
    let mut conn = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&s.current.snapshot_path)
            .read_only(true),
    )
    .await
    .unwrap();
    let has_set: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('kernel_standby_apply_receipts') WHERE name='projection_set_sha256')",
    )
    .fetch_one(&mut conn)
    .await
    .unwrap();
    let set_column = if has_set {
        "projection_set_sha256"
    } else {
        "NULL"
    };
    let rows: Vec<(i64, String, Option<String>, Option<String>)> = sqlx::query_as(&format!(
        "SELECT ordinal,kind,projection_sha256,{set_column} FROM kernel_standby_apply_receipts ORDER BY ordinal",
    ))
    .fetch_all(&mut conn)
    .await
    .unwrap();
    conn.close().await.unwrap();
    rows.into_iter()
        .map(|(o, k, v1, set)| (o, k, v1.is_some(), set.is_some()))
        .collect()
}

async fn kinds(s: &Setup) -> Vec<String> {
    receipt_rows(s)
        .await
        .into_iter()
        .map(|(_, kind, _, _)| kind)
        .collect()
}

async fn accumulator_ordinals(s: &Setup) -> Vec<i64> {
    let mut conn = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&s.current.snapshot_path)
            .read_only(true),
    )
    .await
    .unwrap();
    let ordinals = sqlx::query_scalar(
        "SELECT DISTINCT ordinal FROM kernel_standby_projection_set ORDER BY ordinal",
    )
    .fetch_all(&mut conn)
    .await
    .unwrap_or_default();
    conn.close().await.unwrap();
    ordinals
}

fn count_phase(record: &Value, phase: &str) -> usize {
    phase_names(record)
        .iter()
        .filter(|name| name.as_str() == phase)
        .count()
}

/// The copy proves itself from its own receipts, the accumulator is current,
/// and a restart serves it.
pub(super) async fn assert_proved(s: &Setup) {
    assert!(
        matches!(
            full_state(s).await.unwrap(),
            InPlaceState::Sound {
                accumulator: AccumulatorStatus::Valid,
                ..
            }
        ),
        "{:?}",
        full_state(s).await
    );
    s.assert_startup_serves().await;
}

pub(super) async fn assert_equals_hosted(s: &Setup) {
    let reader = s.reader().await;
    assert_eq!(
        crate::kernel::dump_all_kernel_tables(&reader)
            .await
            .unwrap(),
        crate::kernel::dump_all_kernel_tables(&s.hosted)
            .await
            .unwrap()
    );
    reader.close().await;
}

fn counters(record: &Value) -> Value {
    record["set_path"]["counters"].clone()
}

#[tokio::test]
async fn a_valid_accumulator_takes_the_set_path_and_skips_the_whole_database_scan() {
    let mut s = setup().await;
    let record = refresh_v2(&mut s).await;
    // The first delta of the generation anchors a second-DDL base that already
    // holds the accumulator, so even it takes the fast path.
    assert_eq!(record["last_set_path"], "fast");
    assert_eq!(record["last_path"], "in_place");
    assert_eq!(
        count_phase(&record, "apply_projection_digest"),
        0,
        "{:?}",
        phase_names(&record)
    );
    assert_eq!(count_phase(&record, "apply_full_scan"), 0);
    assert_eq!(count_phase(&record, "apply_capture_finish"), 1);
    assert!(record["set_path"]["capture"]["touches"].as_u64().unwrap() > 0);
    assert_eq!(
        kinds(&s).await,
        ["base", "delta-set"],
        "a delta-set receipt certifies the set digest only"
    );
    assert_eq!(
        receipt_rows(&s).await.last().unwrap(),
        &(1, "delta-set".to_owned(), false, true)
    );
    assert_eq!(accumulator_ordinals(&s).await, [1]);
    assert_proved(&s).await;
    assert_equals_hosted(&s).await;
    // And again: the cache composed forward is still exactly the rows' digest.
    let record = refresh_v2(&mut s).await;
    assert_eq!(record["last_set_path"], "fast");
    assert_eq!(record["set_path"]["counters"]["fast"], 2);
    assert_eq!(accumulator_ordinals(&s).await, [2]);
    assert_proved(&s).await;
    assert_equals_hosted(&s).await;
    s.hosted.close().await;
}

#[tokio::test]
async fn a_capture_anomaly_falls_back_to_exactly_one_full_scan_and_reseeds() {
    let mut s = setup().await;
    refresh_v2(&mut s).await;
    FORCE_ANOMALY.with(|slot| *slot.borrow_mut() = Some(Anomaly::TooManyTouches));
    let record = refresh_v2(&mut s).await;
    assert_eq!(record["last_set_path"], "anomaly:too_many_touches");
    assert_eq!(count_phase(&record, "apply_full_scan"), 1);
    assert_eq!(count_phase(&record, "apply_projection_digest"), 0);
    // A full-scan receipt records both digests; the accumulator was reseeded.
    assert_eq!(
        receipt_rows(&s).await.last().unwrap(),
        &(2, "delta".to_owned(), true, true)
    );
    assert_eq!(accumulator_ordinals(&s).await, [2]);
    assert_eq!(counters(&record)["anomaly"], 1);
    assert_proved(&s).await;
    // The very next delta is fast again.
    let record = refresh_v2(&mut s).await;
    assert_eq!(record["last_set_path"], "fast");
    assert_proved(&s).await;
    assert_equals_hosted(&s).await;
    s.hosted.close().await;
}

#[tokio::test]
async fn a_composed_mismatch_reseeds_and_two_of_them_switch_the_set_path_off() {
    let mut s = setup().await;
    refresh_v2(&mut s).await;
    for expected in 1..=2 {
        FORCE_COMPOSE_ERROR.with(|flag| flag.set(true));
        let record = refresh_v2(&mut s).await;
        let label = record["last_set_path"].as_str().unwrap().to_owned();
        assert!(label.starts_with("mismatch_reseeded:"), "{label}");
        assert_eq!(count_phase(&record, "apply_full_scan"), 1);
        assert_eq!(counters(&record)["mismatch_reseeded"], expected);
        assert_proved(&s).await;
    }
    // Suppressed for the rest of the generation: each later delta takes its one
    // full scan without attempting the fast path.
    for _ in 0..2 {
        let record = refresh_v2(&mut s).await;
        assert_eq!(record["last_set_path"], "skipped:suppressed");
        assert_eq!(record["set_path"]["suppressed"], true);
        assert_eq!(count_phase(&record, "apply_full_scan"), 1);
        assert_eq!(count_phase(&record, "apply_capture_arm"), 0);
        assert_proved(&s).await;
    }
    assert_equals_hosted(&s).await;
    s.hosted.close().await;
}

#[tokio::test]
async fn divergence_costs_one_scan_and_routes_to_a_whole_snapshot() {
    let mut s = setup().await;
    refresh_v2(&mut s).await;
    let reader = s.reader().await;
    let before = read_state(&reader).await;
    let id = crate::kernel::create_record_as(&s.hosted, &s.admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    // Corrupt only the hosted projection: its digests cannot be reproduced.
    sqlx::query("UPDATE kernel_records SET created_at='2030-01-01T00:00:00Z' WHERE id=?")
        .bind(id)
        .execute(s.hosted.write_pool())
        .await
        .unwrap();
    let server = serve_as(&mut s, 2, AuthorityFault::AdvertiseV2).await;
    assert!(matches!(
        s.refresh().await.unwrap(),
        StandbyDeltaOutcome::FullRefreshRequired {
            reason: DeltaFallbackClass::ProjectionDivergence
        }
    ));
    server.await.unwrap();
    let record = replay_record(&s.controller);
    assert_eq!(record["last_set_path"], "divergence");
    assert_eq!(count_phase(&record, "apply_full_scan"), 1, "no second scan");
    assert_eq!(counters(&record)["divergence"], 1);
    // Rolled back: nothing committed.
    assert_eq!(read_state(&reader).await, before);
    assert_eq!(kinds(&s).await, ["base", "delta-set"]);
    assert_proved(&s).await;
    reader.close().await;
    s.hosted.close().await;
}

#[tokio::test]
async fn a_corrupt_accumulator_over_healthy_rows_reseeds_and_commits() {
    let mut s = setup().await;
    refresh_v2(&mut s).await;
    // Damage the cache: the rows and the receipt are untouched.
    s.corrupt("UPDATE kernel_standby_projection_set SET value = zeroblob(384) WHERE name='kernel_records'")
        .await;
    assert!(matches!(
        full_state(&s).await.unwrap(),
        InPlaceState::Sound {
            accumulator: AccumulatorStatus::Invalid,
            ..
        }
    ));
    let record = refresh_v2(&mut s).await;
    assert_eq!(record["last_set_path"], "skipped:accumulator_invalid");
    assert_eq!(count_phase(&record, "apply_full_scan"), 1);
    assert_eq!(
        receipt_rows(&s).await.last().unwrap(),
        &(2, "delta".to_owned(), true, true)
    );
    assert_proved(&s).await;
    // Wrong ordinal: same result.
    s.corrupt("UPDATE kernel_standby_projection_set SET ordinal = 99")
        .await;
    let record = refresh_v2(&mut s).await;
    assert_eq!(record["last_set_path"], "skipped:accumulator_invalid");
    assert_proved(&s).await;
    // Gone entirely: the same again, with its own cause.
    s.corrupt("DELETE FROM kernel_standby_projection_set").await;
    let record = refresh_v2(&mut s).await;
    assert_eq!(record["last_set_path"], "skipped:no_accumulator");
    assert_proved(&s).await;
    assert_equals_hosted(&s).await;
    s.hosted.close().await;
}

/// A titled record gives later deltas something to UPDATE, so the capture has
/// real base images to compose.
async fn titled_world(s: &Setup) -> String {
    let definition = br#"{"family":"test.setpath","version":1,"interpreter":"native.defn/4","primary_type":"Fixture","kinds":[{"token":"note","fields":[{"name":"title","type":"text","required":false}],"identity":{"mode":"record"},"links":[],"maturity":"current","description":"Fixture."}]}"#;
    let revision =
        crate::kernel::install_definition_as(&s.hosted, &s.admin, "test.setpath", 1, definition)
            .await
            .unwrap();
    crate::kernel::adopt_definition_as(&s.hosted, &s.admin, "test.setpath", Some(&revision))
        .await
        .unwrap();
    crate::kernel::create_as(
        &s.hosted,
        &s.admin,
        "test.setpath",
        "note",
        json!({"title": "first"}).as_object().unwrap(),
        crate::events::KERNEL_ROOT_ID,
    )
    .await
    .unwrap()
}

async fn retitle(s: &Setup, id: &str, title: &str) {
    crate::kernel::revise_as(
        &s.hosted,
        &s.admin,
        id,
        json!({"title": title}).as_object().unwrap(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn an_update_composes_from_real_base_images() {
    let mut s = setup().await;
    let id = titled_world(&s).await;
    let server = serve_as(&mut s, 2, AuthorityFault::AdvertiseV2).await;
    advanced(&s).await;
    server.await.unwrap();
    s.forget_rest();
    retitle(&s, &id, "second").await;
    let server = serve_as(&mut s, 2, AuthorityFault::AdvertiseV2).await;
    advanced(&s).await;
    server.await.unwrap();
    let record = replay_record(&s.controller);
    s.forget_rest();
    assert_eq!(record["last_set_path"], "fast", "{record}");
    assert!(
        record["set_path"]["capture"]["old_images"]
            .as_u64()
            .unwrap()
            > 0,
        "an UPDATE reads real base images: {record}"
    );
    assert_proved(&s).await;
    assert_equals_hosted(&s).await;
    s.hosted.close().await;
}

/// A home, a record in the root, applied to the node; then the record's
/// `created_at` is damaged locally. Returns (home, record).
async fn damaged_record(s: &mut Setup) -> (String, String) {
    let home = crate::kernel::create_home(&s.hosted, crate::events::KERNEL_ROOT_ID, None, &s.admin)
        .await
        .unwrap();
    let id = crate::kernel::create_record_as(&s.hosted, &s.admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let server = serve_as(s, 2, AuthorityFault::AdvertiseV2).await;
    advanced(s).await;
    server.await.unwrap();
    s.forget_rest();
    s.corrupt(&format!(
        "UPDATE kernel_records SET created_at='2031-01-01T00:00:00Z' WHERE id='{id}'"
    ))
    .await;
    (home, id)
}

/// Damage in a row the delta touches WITHOUT changing it (a re-home to the
/// current home; A to B to A within one delta) is equivalent to an untouched
/// row: the base and final images are equal, so the delta cancels, the fast
/// path commits, and the next Full check refuses. This is the accepted bound
/// of the fast path, not a gap in the Full check.
#[tokio::test]
async fn damage_in_a_row_touched_without_net_change_commits_and_the_full_check_refuses() {
    let mut s = setup().await;
    let (home, id) = damaged_record(&mut s).await;
    // Re-home to the home it already has.
    crate::kernel::rehome_record_as(&s.hosted, &s.admin, &id, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let record = refresh_as(&mut s, 2, AuthorityFault::AdvertiseV2).await;
    assert_eq!(record["last_set_path"], "fast", "{record}");
    assert!(full_state(&s).await.is_err(), "the next Full check refuses");
    s.hosted.close().await;
    drop(home);
}

#[tokio::test]
async fn damage_in_a_row_changed_and_changed_back_in_one_delta_is_the_same_bound() {
    let mut s = setup().await;
    let (home, id) = damaged_record(&mut s).await;
    // A to B to A inside one delta.
    crate::kernel::rehome_record_as(&s.hosted, &s.admin, &id, &home)
        .await
        .unwrap();
    crate::kernel::rehome_record_as(&s.hosted, &s.admin, &id, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let record = refresh_as(&mut s, 2, AuthorityFault::AdvertiseV2).await;
    assert_eq!(record["last_set_path"], "fast", "{record}");
    assert!(record["set_path"]["capture"]["touches"].as_u64().unwrap() > 0);
    assert!(full_state(&s).await.is_err(), "the next Full check refuses");
    s.hosted.close().await;
}

/// The companion: the same damage, but the delta changes that row (a re-home
/// to another home). It cannot hide: the composed digest differs from
/// hosted's, the one full scan sees the damage, and the apply refuses.
#[tokio::test]
async fn the_same_damage_in_a_row_the_delta_changes_falls_back_and_refuses() {
    let mut s = setup().await;
    let (home, id) = damaged_record(&mut s).await;
    let reader = s.reader().await;
    let before = read_state(&reader).await;
    crate::kernel::rehome_record_as(&s.hosted, &s.admin, &id, &home)
        .await
        .unwrap();
    let server = serve_as(&mut s, 2, AuthorityFault::AdvertiseV2).await;
    let outcome = s.refresh().await.unwrap();
    server.await.unwrap();
    let record = replay_record(&s.controller);
    assert!(
        matches!(
            outcome,
            StandbyDeltaOutcome::FullRefreshRequired {
                reason: DeltaFallbackClass::ProjectionDivergence
            }
        ),
        "{outcome:?} {record}"
    );
    assert_eq!(record["last_set_path"], "divergence", "{record}");
    assert_eq!(count_phase(&record, "apply_full_scan"), 1);
    assert_eq!(read_state(&reader).await, before, "nothing was committed");
    reader.close().await;
    s.hosted.close().await;
}

#[tokio::test]
async fn damage_the_delta_does_not_touch_is_the_audit_s_to_find_not_the_apply_s() {
    let mut s = setup().await;
    refresh_v2(&mut s).await;
    s.corrupt("UPDATE kernel_records SET created_at='2031-01-01T00:00:00Z' WHERE rowid=(SELECT MIN(rowid) FROM kernel_records)")
        .await;
    // Damage in a row whose content the delta does not change commits on the
    // fast path; the next Full check compares the rows with the receipt and
    // refuses.
    let record = refresh_v2(&mut s).await;
    assert_eq!(record["last_set_path"], "fast");
    assert!(full_state(&s).await.is_err());
    s.hosted.close().await;
}

#[tokio::test]
async fn hosted_going_v2_then_v1_then_v2_keeps_the_cache_current() {
    let mut s = setup().await;
    let record = refresh_v2(&mut s).await;
    assert_eq!(record["last_set_path"], "fast");
    // Hosted downgraded: a version-1 delta. One full dual scan, the derived set
    // digest recorded, the accumulator reseeded.
    s.hosted_adds_records(1).await;
    let record = refresh_as(&mut s, 2, AuthorityFault::None).await;
    assert_eq!(record["last_set_path"], "skipped:v1_delta");
    assert_eq!(count_phase(&record, "apply_full_scan"), 1);
    assert_eq!(
        receipt_rows(&s).await.last().unwrap(),
        &(2, "delta".to_owned(), true, true)
    );
    assert_proved(&s).await;
    // Hosted upgraded again: straight back to the fast path.
    let record = refresh_v2(&mut s).await;
    assert_eq!(record["last_set_path"], "fast");
    assert_eq!(kinds(&s).await, ["base", "delta-set", "delta", "delta-set"]);
    assert_proved(&s).await;
    assert_equals_hosted(&s).await;
    s.hosted.close().await;
}

#[tokio::test]
async fn node_n2_then_n1_then_n2_invalidates_and_reseeds_the_cache() {
    let mut s = setup().await;
    assert_eq!(refresh_v2(&mut s).await["last_set_path"], "fast");
    // The previous release applies a delta to this generation: v1 digest only,
    // and the cache emptied in the same transaction.
    FORCE_N1.with(|flag| flag.set(true));
    s.hosted_adds_records(1).await;
    let record = refresh_as(&mut s, 2, AuthorityFault::AdvertiseV2).await;
    FORCE_N1.with(|flag| flag.set(false));
    assert!(record["last_set_path"].is_null());
    assert_eq!(
        receipt_rows(&s).await.last().unwrap(),
        &(2, "delta".to_owned(), true, false)
    );
    assert!(accumulator_ordinals(&s).await.is_empty());
    assert!(matches!(
        full_state(&s).await.unwrap(),
        InPlaceState::Sound {
            accumulator: AccumulatorStatus::Absent,
            ..
        }
    ));
    // This release again: one full scan reseeds, then it is fast.
    let record = refresh_v2(&mut s).await;
    assert_eq!(record["last_set_path"], "skipped:no_accumulator");
    assert_proved(&s).await;
    assert_eq!(refresh_v2(&mut s).await["last_set_path"], "fast");
    assert_proved(&s).await;
    assert_equals_hosted(&s).await;
    s.hosted.close().await;
}

#[tokio::test]
async fn a_mixed_fleet_falls_back_to_version_1_and_a_first_ddl_copy_moves_up_on_the_first_v2_delta()
{
    let mut s = setup().await;
    // The head advertises version 2 but the replica refuses the field: the
    // transport retries at version 1. A first-DDL copy behaves exactly as ever.
    s.hosted_adds_records(1).await;
    let record = refresh_as(&mut s, 3, AuthorityFault::MixedFleet).await;
    assert!(record["last_set_path"].is_null());
    assert_eq!(kinds(&s).await, ["base", "delta"]);
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT sql FROM sqlite_schema WHERE name='kernel_standby_apply_receipts'"
        )
        .fetch_one(
            &mut sqlx::SqliteConnection::connect_with(
                &sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&s.current.snapshot_path)
                    .read_only(true)
            )
            .await
            .unwrap()
        )
        .await
        .unwrap(),
        crate::standby::generation_store::kernel_in_place::RECEIPTS_DDL
    );
    s.full_check().await.unwrap();
    // The first version-2 delta moves the chain to the second DDL (verified
    // link by link, then re-linked) and reseeds through one full scan.
    let record = refresh_v2(&mut s).await;
    assert_eq!(record["last_set_path"], "skipped:no_accumulator");
    assert_eq!(kinds(&s).await, ["base", "delta", "delta"]);
    assert_proved(&s).await;
    assert_eq!(refresh_v2(&mut s).await["last_set_path"], "fast");
    // A mixed-fleet tick on a second-DDL copy is a version-1 full scan.
    s.hosted_adds_records(1).await;
    let record = refresh_as(&mut s, 3, AuthorityFault::MixedFleet).await;
    assert_eq!(record["last_set_path"], "skipped:v1_delta");
    assert_proved(&s).await;
    assert_equals_hosted(&s).await;
    s.hosted.close().await;
}

// ---- every existing crash point, with set-path receipts ----

async fn recovers_after(point: InPlaceCrash) {
    let mut s = setup().await;
    s.hosted_adds_records(1).await;
    let hosted = read_state(&s.hosted).await;
    s.controller.kernel_in_place_crash = Some(point);
    let server = serve_as(&mut s, 2, AuthorityFault::AdvertiseV2).await;
    assert!(s.refresh().await.is_err());
    server.await.unwrap();
    s.controller.kernel_in_place_crash = None;
    s.forget_rest();
    match point {
        InPlaceCrash::AfterMarkBeforeBaseReceipt => {
            // Marked advanced and never anchored: unproved, whole snapshot.
            assert!(s.full_check().await.is_err());
            let server = serve_as(&mut s, 1, AuthorityFault::AdvertiseV2).await;
            assert!(matches!(
                s.refresh().await.unwrap(),
                StandbyDeltaOutcome::FullRefreshRequired { .. }
            ));
            server.await.unwrap();
        }
        InPlaceCrash::AfterBaseReceipt | InPlaceCrash::BeforeCommit => {
            // Only the (second-DDL, accumulator-seeded) base committed.
            assert_eq!(kinds(&s).await, ["base"]);
            assert_eq!(accumulator_ordinals(&s).await, [0]);
            s.full_check().await.unwrap();
            let record = refresh_as(&mut s, 2, AuthorityFault::AdvertiseV2).await;
            assert_eq!(record["last_set_path"], "fast");
            assert_eq!(kinds(&s).await, ["base", "delta-set"]);
            assert_eq!(s.head_act(), hosted.0);
            assert_proved(&s).await;
            assert_equals_hosted(&s).await;
        }
        InPlaceCrash::AfterCommitBeforeSidecar | InPlaceCrash::AfterSidecar => {
            // The receipt and the accumulator committed with the data.
            assert_eq!(kinds(&s).await, ["base", "delta-set"]);
            assert_eq!(accumulator_ordinals(&s).await, [1]);
            assert_proved(&s).await;
            // The next delta composes forward from the committed cache.
            let record = refresh_v2(&mut s).await;
            assert_eq!(record["last_set_path"], "fast");
            assert_proved(&s).await;
            assert_equals_hosted(&s).await;
        }
    }
    s.hosted.close().await;
}

#[tokio::test]
async fn crash_after_marking_before_the_base_receipt_with_set_path_receipts() {
    recovers_after(InPlaceCrash::AfterMarkBeforeBaseReceipt).await;
}

#[tokio::test]
async fn crash_after_the_base_receipt_with_set_path_receipts() {
    recovers_after(InPlaceCrash::AfterBaseReceipt).await;
}

#[tokio::test]
async fn crash_before_commit_with_set_path_receipts() {
    recovers_after(InPlaceCrash::BeforeCommit).await;
}

#[tokio::test]
async fn crash_after_commit_before_the_sidecar_with_set_path_receipts() {
    recovers_after(InPlaceCrash::AfterCommitBeforeSidecar).await;
}

#[tokio::test]
async fn crash_after_the_sidecar_with_set_path_receipts() {
    recovers_after(InPlaceCrash::AfterSidecar).await;
}

// ---- wire version 3: the set digest alone ----

#[tokio::test]
async fn a_version_3_delta_takes_the_set_path_with_no_comparison_and_certifies_its_own_digest() {
    let mut s = setup().await;
    let record = refresh_v3(&mut s).await;
    assert_eq!(record["last_set_path"], "fast");
    assert_eq!(count_phase(&record, "apply_full_scan"), 0);
    assert_eq!(count_phase(&record, "apply_projection_digest"), 0);
    assert_eq!(
        receipt_rows(&s).await.last().unwrap(),
        &(1, "delta-set".to_owned(), false, true)
    );
    assert_proved(&s).await;
    assert_equals_hosted(&s).await;
    let record = refresh_v3(&mut s).await;
    assert_eq!(record["last_set_path"], "fast");
    assert_eq!(accumulator_ordinals(&s).await, [2]);
    assert_proved(&s).await;
    assert_equals_hosted(&s).await;
    s.hosted.close().await;
}

#[tokio::test]
async fn a_version_3_full_scan_compares_nothing_records_its_own_digest_and_reseeds() {
    let mut s = setup().await;
    refresh_v3(&mut s).await;
    FORCE_ANOMALY.with(|slot| *slot.borrow_mut() = Some(Anomaly::TooManyTouches));
    let record = refresh_v3(&mut s).await;
    assert_eq!(record["last_set_path"], "anomaly:too_many_touches");
    assert_eq!(count_phase(&record, "apply_full_scan"), 1);
    // Hosted attested no digest: the receipt certifies this node's own set
    // digest and no ordered one.
    assert_eq!(
        receipt_rows(&s).await.last().unwrap(),
        &(2, "delta-set".to_owned(), false, true)
    );
    assert_eq!(accumulator_ordinals(&s).await, [2]);
    assert_proved(&s).await;
    assert_eq!(refresh_v3(&mut s).await["last_set_path"], "fast");
    assert_proved(&s).await;
    assert_equals_hosted(&s).await;
    s.hosted.close().await;
}

#[tokio::test]
async fn a_first_ddl_copy_moves_up_on_its_first_version_3_delta() {
    let mut s = setup().await;
    // A version-1 tick (mixed fleet) leaves the original receipts DDL.
    s.hosted_adds_records(1).await;
    refresh_as(&mut s, 3, AuthorityFault::MixedFleet).await;
    assert_eq!(kinds(&s).await, ["base", "delta"]);
    let record = refresh_v3(&mut s).await;
    assert_eq!(record["last_set_path"], "skipped:no_accumulator");
    assert_eq!(kinds(&s).await, ["base", "delta", "delta-set"]);
    assert_eq!(
        receipt_rows(&s).await.last().unwrap(),
        &(2, "delta-set".to_owned(), false, true)
    );
    assert_proved(&s).await;
    s.full_check().await.unwrap();
    assert_eq!(refresh_v3(&mut s).await["last_set_path"], "fast");
    assert_equals_hosted(&s).await;
    s.hosted.close().await;
}

#[tokio::test]
async fn a_host_that_cannot_read_version_3_steps_the_node_down_to_version_2() {
    let mut s = setup().await;
    proof_not_due(&s);
    s.hosted_adds_records(1).await;
    // Head, the refused version-3 request, then the version-2 retry.
    let record = refresh_as(&mut s, 3, AuthorityFault::RefuseV3).await;
    assert_eq!(record["last_set_path"], "fast");
    assert_eq!(
        receipt_rows(&s).await.last().unwrap(),
        &(1, "delta-set".to_owned(), false, true)
    );
    assert_proved(&s).await;
    assert_equals_hosted(&s).await;
    s.hosted.close().await;
}

/// Rollback: the previous release's reader and writer meet a chain whose last
/// receipt a version-3 FULL SCAN wrote. That receipt is the shape the set path
/// already wrote (`delta-set`, no v1 digest, a set digest) with the accumulator
/// reseeded at its ordinal, so the unchanged chain reader accepts it, and the
/// previous release (N1) can apply a version-1 delta on top and empty the cache.
#[tokio::test]
async fn a_version_3_full_scan_receipt_is_readable_and_extendable_by_the_previous_release() {
    let mut s = setup().await;
    refresh_v3(&mut s).await;
    let fast = receipt_rows(&s).await.last().unwrap().clone();
    FORCE_ANOMALY.with(|slot| *slot.borrow_mut() = Some(Anomaly::TooManyTouches));
    let record = refresh_v3(&mut s).await;
    assert_eq!(record["last_set_path"], "anomaly:too_many_touches");
    let scanned = receipt_rows(&s).await.last().unwrap().clone();
    // Same kind and same digests present as the fast path's receipt.
    assert_eq!(
        (&scanned.1, scanned.2, scanned.3),
        (&fast.1, fast.2, fast.3)
    );
    assert_eq!(accumulator_ordinals(&s).await, [scanned.0]);
    // The chain reader that predates version 3 is this one: nothing in the
    // reader changed, and it accepts the chain.
    s.full_check().await.unwrap();
    assert_proved(&s).await;
    // The previous release applies a version-1 delta on top of it.
    FORCE_N1.with(|flag| flag.set(true));
    s.hosted_adds_records(1).await;
    refresh_as(&mut s, 2, AuthorityFault::AdvertiseV2).await;
    FORCE_N1.with(|flag| flag.set(false));
    assert_eq!(
        receipt_rows(&s).await.last().unwrap(),
        &(3, "delta".to_owned(), true, false)
    );
    assert!(accumulator_ordinals(&s).await.is_empty());
    s.full_check().await.unwrap();
    // And this release comes back with one full scan, then the fast path.
    assert_eq!(
        refresh_v3(&mut s).await["last_set_path"],
        "skipped:no_accumulator"
    );
    assert_eq!(refresh_v3(&mut s).await["last_set_path"], "fast");
    assert_equals_hosted(&s).await;
    s.hosted.close().await;
}

// ---- the projection-proof audit: version 3 carries none, so ask for one ----

#[tokio::test]
async fn the_first_follow_after_a_start_asks_for_the_proof_then_version_3_resumes() {
    let mut s = setup().await;
    assert_eq!(proof_state(&s), (None, false));
    s.hosted_adds_records(1).await;
    let record = refresh_as(&mut s, 2, AuthorityFault::AdvertiseV3).await;
    // Served and checked with the proof (version 2), not version 3.
    assert_eq!(record["last_set_path"], "fast");
    let (audited, trouble) = proof_state(&s);
    assert!(audited.is_some() && !trouble);
    // Not due again: the next follow is the proof-less version 3, which does
    // not restart the interval.
    s.hosted_adds_records(1).await;
    refresh_as(&mut s, 2, AuthorityFault::AdvertiseV3).await;
    assert_eq!(proof_state(&s).0, audited);
    assert_proved(&s).await;
    assert_equals_hosted(&s).await;
    s.hosted.close().await;
}

#[tokio::test]
async fn the_audit_comes_round_again_at_the_configured_interval() {
    let mut s = setup().await;
    proof_not_due(&s);
    let fresh = proof_state(&s).0;
    // Within the interval (default thirty minutes): version 3, no new audit.
    s.hosted_adds_records(1).await;
    refresh_as(&mut s, 2, AuthorityFault::AdvertiseV3).await;
    assert_eq!(proof_state(&s).0, fresh);
    // Past it: the follow carries the proof, which restarts the interval.
    s.controller.proof_audit.lock().unwrap().last =
        Some(std::time::Instant::now() - std::time::Duration::from_secs(31 * 60));
    let stale = proof_state(&s).0;
    s.hosted_adds_records(1).await;
    refresh_as(&mut s, 2, AuthorityFault::AdvertiseV3).await;
    let (after, trouble) = proof_state(&s);
    assert_ne!(after, stale);
    assert!(after.unwrap().elapsed() < std::time::Duration::from_secs(60) && !trouble);
    // A shorter configured interval brings it forward.
    s.controller.config.projection_proof_interval_seconds = Some(60);
    s.controller.proof_audit.lock().unwrap().last =
        Some(std::time::Instant::now() - std::time::Duration::from_secs(120));
    let stale = proof_state(&s).0;
    s.hosted_adds_records(1).await;
    refresh_as(&mut s, 2, AuthorityFault::AdvertiseV3).await;
    assert_ne!(proof_state(&s).0, stale);
    s.hosted.close().await;
}

#[tokio::test]
async fn an_apply_anomaly_brings_the_next_audit_forward() {
    let mut s = setup().await;
    proof_not_due(&s);
    let fresh = proof_state(&s).0;
    FORCE_ANOMALY.with(|slot| *slot.borrow_mut() = Some(Anomaly::TooManyTouches));
    s.hosted_adds_records(1).await;
    let record = refresh_as(&mut s, 2, AuthorityFault::AdvertiseV3).await;
    assert_eq!(record["last_set_path"], "anomaly:too_many_touches");
    // Nothing was checked against a proof, and the next follow will be.
    assert_eq!(proof_state(&s), (fresh, true));
    s.hosted_adds_records(1).await;
    refresh_as(&mut s, 2, AuthorityFault::AdvertiseV3).await;
    let (after, trouble) = proof_state(&s);
    assert_ne!(after, fresh);
    assert!(!trouble);
    assert_proved(&s).await;
    assert_equals_hosted(&s).await;
    s.hosted.close().await;
}

/// The trade: a hosted projection the events cannot reproduce goes unnoticed
/// by version 3, and the audit's version-2 delta finds it and takes the
/// existing whole-snapshot repair. Reads are never held for it.
#[tokio::test]
async fn a_divergence_the_audit_finds_takes_the_existing_whole_snapshot_repair() {
    let mut s = setup().await;
    proof_not_due(&s);
    let id = crate::kernel::create_record_as(&s.hosted, &s.admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    sqlx::query("UPDATE kernel_records SET created_at='2030-01-01T00:00:00Z' WHERE id=?")
        .bind(id)
        .execute(s.hosted.write_pool())
        .await
        .unwrap();
    // Version 3 applies: nothing to compare.
    let record = refresh_as(&mut s, 2, AuthorityFault::AdvertiseV3).await;
    assert_eq!(record["last_set_path"], "fast");
    assert!(!proof_state(&s).1);
    // The audit falls due; its delta carries the proof and it does not match.
    let reader = s.reader().await;
    let before = read_state(&reader).await;
    s.controller.proof_audit.lock().unwrap().last = None;
    s.hosted_adds_records(1).await;
    let server = serve_as(&mut s, 2, AuthorityFault::AdvertiseV3).await;
    assert!(matches!(
        s.refresh().await.unwrap(),
        StandbyDeltaOutcome::FullRefreshRequired {
            reason: DeltaFallbackClass::ProjectionDivergence
        }
    ));
    server.await.unwrap();
    // Rolled back: the audit's delta committed nothing; trouble is flagged.
    assert_eq!(read_state(&reader).await, before);
    assert!(proof_state(&s).1);
    reader.close().await;
    s.hosted.close().await;
}

// ---- the audit does not wait for a write ----

/// Plant a divergence on hosted that no event explains: its projection of a
/// record the node already folded now differs from a replay of the events.
async fn plant_idle_divergence(s: &mut Setup) {
    proof_not_due(s);
    let id = crate::kernel::create_record_as(&s.hosted, &s.admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    // Version 3 carries the record to the node (nothing to compare).
    let record = refresh_as(s, 2, AuthorityFault::AdvertiseV3).await;
    assert_eq!(record["last_set_path"], "fast");
    // Writes are now idle: no event follows the corruption.
    sqlx::query("UPDATE kernel_records SET created_at='2030-01-01T00:00:00Z' WHERE id=?")
        .bind(id)
        .execute(s.hosted.write_pool())
        .await
        .unwrap();
}

#[tokio::test]
async fn an_audit_that_falls_due_at_an_unchanged_head_still_catches_a_divergence() {
    let mut s = setup().await;
    plant_idle_divergence(&mut s).await;
    let reader = s.reader().await;
    let before = read_state(&reader).await;
    // Not due: the head is unchanged, so one head probe and nothing else.
    proof_not_due(&s);
    let server = serve_as(&mut s, 1, AuthorityFault::AdvertiseV3).await;
    assert!(matches!(
        s.refresh().await.unwrap(),
        StandbyDeltaOutcome::Unchanged { .. }
    ));
    server.await.unwrap();
    s.forget_rest();
    // Due: a zero-act delta that carries the proof is requested and compared.
    s.controller.proof_audit.lock().unwrap().last = None;
    let server = serve_as(&mut s, 2, AuthorityFault::AdvertiseV3).await;
    assert!(matches!(
        s.refresh().await.unwrap(),
        StandbyDeltaOutcome::FullRefreshRequired {
            reason: DeltaFallbackClass::ProjectionDivergence
        }
    ));
    server.await.unwrap();
    assert_eq!(read_state(&reader).await, before);
    assert!(proof_state(&s).1, "trouble keeps the audit due");
    reader.close().await;
    s.hosted.close().await;
}

#[tokio::test]
async fn a_clean_audit_at_an_unchanged_head_checks_the_projection_and_restarts_the_interval() {
    let mut s = setup().await;
    proof_not_due(&s);
    s.hosted_adds_records(1).await;
    refresh_as(&mut s, 2, AuthorityFault::AdvertiseV3).await;
    s.controller.proof_audit.lock().unwrap().last = None;
    let server = serve_as(&mut s, 2, AuthorityFault::AdvertiseV3).await;
    assert!(matches!(
        s.refresh().await.unwrap(),
        StandbyDeltaOutcome::Unchanged { .. }
    ));
    server.await.unwrap();
    let (audited, trouble) = proof_state(&s);
    assert!(audited.is_some() && !trouble);
    assert_proved(&s).await;
    s.hosted.close().await;
}

// ---- recovery makes an audit due, until a proof checks out ----

#[tokio::test]
async fn reseeding_an_invalid_accumulator_makes_the_next_follow_an_audit() {
    let mut s = setup().await;
    refresh_v3(&mut s).await;
    s.corrupt("UPDATE kernel_standby_projection_set SET value = zeroblob(384) WHERE name='kernel_records'")
        .await;
    let record = refresh_v3(&mut s).await;
    assert_eq!(record["last_set_path"], "skipped:accumulator_invalid");
    let (audited, trouble) = proof_state(&s);
    assert!(trouble, "an unplanned reseed is trouble");
    // The next follow carries the proof and, checked, clears it.
    s.hosted_adds_records(1).await;
    refresh_as(&mut s, 2, AuthorityFault::AdvertiseV3).await;
    let (after, trouble) = proof_state(&s);
    assert!(!trouble && after != audited && after.is_some());
    assert_proved(&s).await;
    assert_equals_hosted(&s).await;
    s.hosted.close().await;
}
