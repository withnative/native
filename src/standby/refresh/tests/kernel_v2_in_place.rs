//! Opt-in in-place application of small kernel-v2 deltas (epic c15a932).
//! Disposable databases and localhost HTTP only.
use super::kernel_v2_refresh::{fixture, phase_names, replay_record};
use super::*;
use crate::standby::generation_store::kernel_in_place::{
    convert_to_n2_shape, convert_to_n2_shape_with, rechain_receipts, AccumulatorStatus,
    InPlaceCrash, InPlaceState, IntegrityDepth, ReceiptsDdl,
};
use crate::standby::StandbyStartupOutcome;
use std::collections::HashSet;
use std::sync::atomic::AtomicBool;

type State = (i64, i64, i64, i64);

pub(crate) struct Setup {
    _directory: tempfile::TempDir,
    controller: StandbyRefreshController,
    hosted: crate::Db,
    admin: String,
    /// The live serving-reader lock the in-place gate requires.
    _reader_lock: File,
    current: InstalledGeneration,
}

impl Setup {
    pub(crate) fn store(&self) -> &GenerationStore {
        &self.controller.store
    }

    pub(crate) fn observed(&self) -> &crate::standby_snapshot::ObservedInstalledConsumerIdentity {
        &self.controller.observed
    }

    pub(crate) fn current(&self) -> &InstalledGeneration {
        &self.current
    }

    /// Close the hosted database; dropping the setup then cleans the directory.
    pub(crate) async fn finish(self) {
        self.hosted.close().await;
    }
}

pub(crate) async fn setup() -> Setup {
    let (directory, mut controller, hosted, admin, _client) = fixture().await;
    controller.config.kernel_in_place_deltas = true;
    let current = controller.store.current_for_head_probe().unwrap().unwrap();
    let reader_lock = controller.store.hold_serving_reader(&current.id).unwrap();
    controller
        .store
        .record_serving_reader(&current.id, &controller.observed)
        .unwrap();
    Setup {
        _directory: directory,
        controller,
        hosted,
        admin,
        _reader_lock: reader_lock,
        current,
    }
}

impl Setup {
    pub(crate) async fn hosted_adds_records(&self, count: usize) {
        for _ in 0..count {
            crate::kernel::create_record_as(
                &self.hosted,
                &self.admin,
                crate::events::KERNEL_ROOT_ID,
            )
            .await
            .unwrap();
        }
    }

    /// Serve `refreshes` delta-only attempts (a head probe and a delta each).
    pub(crate) async fn serve(&mut self, refreshes: usize) -> tokio::task::JoinHandle<()> {
        self.serve_calls(2 * refreshes).await
    }

    async fn serve_calls(&mut self, calls: usize) -> tokio::task::JoinHandle<()> {
        let (port, server) = serve_authority_act_calls(self.hosted.clone(), calls).await;
        self.controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        server
    }

    fn forget_rest(&self) {
        let _ = fs::remove_file(self.controller.refresh_dir.join("kernel-replay.json"));
    }

    async fn reader(&self) -> crate::Db {
        crate::db::open_kernel_v2_standby_read_only(self.current.snapshot_path.to_str().unwrap())
            .await
            .unwrap()
    }

    /// The head record's act; a checkpoint with no record holds its manifest's.
    fn head_act(&self) -> i64 {
        self.controller
            .store
            .generation_head(&self.current.id)
            .unwrap()
            .map_or_else(
                || self.current.manifest.head_act.unwrap(),
                |head| head.head_act,
            )
    }

    /// One delta-only refresh, started only once the previous attempt's
    /// background maintenance has finished. That pass (scheduled when any
    /// refresh returns) re-checks the current generation under the shared
    /// `attempt.lock`, so a back-to-back refresh would otherwise race it and
    /// legitimately return `refresh_in_progress` instead of what it is testing.
    pub(crate) async fn refresh(&self) -> Result<StandbyDeltaOutcome> {
        self.controller.store.maintenance_idle().await;
        self.controller.refresh_delta_only().await
    }

    /// How many deltas the database's own receipts say were applied in place.
    async fn applied(&self) -> i64 {
        let mut conn = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&self.current.snapshot_path)
                .read_only(true),
        )
        .await
        .unwrap();
        let count = sqlx::query_scalar(
            "SELECT COUNT(*) FROM kernel_standby_apply_receipts WHERE kind='delta'",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap_or(0);
        conn.close().await.unwrap();
        count
    }

    /// Run SQL directly against the live file, as corruption or tampering.
    pub(crate) async fn corrupt(&self, sql: &str) {
        let mut conn = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&self.current.snapshot_path)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal),
        )
        .await
        .unwrap();
        sqlx::query(sql).execute(&mut conn).await.unwrap();
        conn.close().await.unwrap();
    }

    /// Tamper with canonical event rows: an adversary first removes the
    /// append-only triggers that guard them against ordinary writers.
    async fn corrupt_events(&self, sql: &str) {
        let mut conn = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&self.current.snapshot_path)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal),
        )
        .await
        .unwrap();
        // Lift the append-only triggers for the write and put them back
        // verbatim, so the schema (and every schema check) is unchanged and
        // only the data check can notice.
        let triggers: Vec<(String, String)> = sqlx::query_as(
            "SELECT name,sql FROM sqlite_schema WHERE type='trigger' AND tbl_name='content_events'",
        )
        .fetch_all(&mut conn)
        .await
        .unwrap();
        for (name, _) in &triggers {
            sqlx::query(&format!("DROP TRIGGER \"{name}\""))
                .execute(&mut conn)
                .await
                .unwrap();
        }
        sqlx::query(sql).execute(&mut conn).await.unwrap();
        for (_, ddl) in &triggers {
            sqlx::query(ddl).execute(&mut conn).await.unwrap();
        }
        conn.close().await.unwrap();
    }

    /// Remove every row of the first populated projection table, with
    /// constraints and triggers out of the way: projection-only corruption.
    async fn corrupt_projection(&self) {
        let mut conn = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&self.current.snapshot_path)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .foreign_keys(false),
        )
        .await
        .unwrap();
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name LIKE 'kernel_%' AND name NOT LIKE 'kernel_search_fts%' AND name NOT IN ('kernel_blobs','kernel_standby_apply_receipts','kernel_mcp_write_receipts') ORDER BY name",
        )
        .fetch_all(&mut conn)
        .await
        .unwrap();
        for table in tables {
            let rows: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM \"{table}\""))
                .fetch_one(&mut conn)
                .await
                .unwrap();
            if rows == 0 {
                continue;
            }
            let triggers: Vec<String> = sqlx::query_scalar(
                "SELECT name FROM sqlite_schema WHERE type='trigger' AND tbl_name=?",
            )
            .bind(&table)
            .fetch_all(&mut conn)
            .await
            .unwrap();
            for trigger in triggers {
                sqlx::query(&format!("DROP TRIGGER \"{trigger}\""))
                    .execute(&mut conn)
                    .await
                    .unwrap();
            }
            sqlx::query(&format!("DELETE FROM \"{table}\""))
                .execute(&mut conn)
                .await
                .unwrap();
            conn.close().await.unwrap();
            return;
        }
        panic!("no populated projection table");
    }

    /// Plant a foreign-key violation (an orphan row) with enforcement off.
    async fn plant_orphan(&self) {
        let mut conn = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&self.current.snapshot_path)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .foreign_keys(false),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO kernel_attachment_blobs VALUES('no-such-record','no-such-blob','{}')",
        )
        .execute(&mut conn)
        .await
        .unwrap();
        conn.close().await.unwrap();
    }

    async fn full_check(&self) -> Result<()> {
        self.restarted_store()
            .check_in_place_integrity(&self.current, IntegrityDepth::Full)
            .await
            .map(|_| ())
    }

    /// A cold store on the same root, as after a process restart.
    pub(crate) fn restarted_store(&self) -> GenerationStore {
        GenerationStore::open(
            &self.controller.runtime.replica_root,
            "route-1",
            Some(self.controller.runtime.origin_database_id.clone()),
        )
        .unwrap()
    }

    async fn assert_startup_serves(&self) {
        let store = self.restarted_store();
        let outcome = store.activate_for_startup(&self.controller.observed).await;
        assert!(
            matches!(outcome, Ok(StandbyStartupOutcome::Serving(_))),
            "startup verification of the advanced copy failed: {:?}",
            outcome.err()
        );
    }
}

/// One consistent snapshot: head act, content events, meta events, records.
async fn read_state(db: &crate::Db) -> State {
    let mut tx = db.pool().begin().await.unwrap();
    let state = read_state_on(&mut tx).await;
    tx.rollback().await.unwrap();
    state
}

async fn read_state_on(conn: &mut sqlx::SqliteConnection) -> State {
    sqlx::query_as(
        "SELECT (SELECT next_act FROM act_state WHERE singleton=1),
                (SELECT COUNT(*) FROM content_events),
                (SELECT COUNT(*) FROM meta_events),
                (SELECT COUNT(*) FROM kernel_records)",
    )
    .fetch_one(conn)
    .await
    .unwrap()
}

async fn journal_mode(path: &Path) -> String {
    let mut conn = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .read_only(true),
    )
    .await
    .unwrap();
    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    conn.close().await.unwrap();
    mode
}

async fn advanced(setup: &Setup) {
    let outcome = tokio::time::timeout(Duration::from_secs(60), setup.refresh())
        .await
        .expect("in-place delta must not wait on readers")
        .unwrap();
    assert!(
        matches!(outcome, StandbyDeltaOutcome::Advanced { .. }),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn in_place_small_delta_advances_the_serving_file_and_keeps_its_generation() {
    let mut s = setup().await;
    let reader = s.reader().await;
    let before = read_state(&reader).await;
    s.hosted_adds_records(1).await;
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();

    // Same generation, same file: no new checkpoint was published.
    let after = s
        .controller
        .store
        .current_for_head_probe()
        .unwrap()
        .unwrap();
    assert_eq!(after.id, s.current.id);
    // The serving handle opened before the apply sees the new state.
    let hosted = read_state(&s.hosted).await;
    assert_ne!(read_state(&reader).await, before);
    assert_eq!(read_state(&reader).await, hosted);
    assert_eq!(
        crate::kernel::dump_all_kernel_tables(&s.hosted)
            .await
            .unwrap(),
        crate::kernel::dump_all_kernel_tables(&reader)
            .await
            .unwrap()
    );
    // The head record follows the database, the chain records the delta, and
    // the file is WAL.
    let head = s
        .controller
        .store
        .generation_head(&s.current.id)
        .unwrap()
        .unwrap();
    assert!(head.advanced_in_place());
    assert_eq!(head.head_act, hosted.0);
    assert_eq!(s.applied().await, 1);
    assert_eq!(journal_mode(&s.current.snapshot_path).await, "wal");
    // Bookkeeping: path, outcome and phases.
    let record = replay_record(&s.controller);
    assert_eq!(record["last_path"], "in_place");
    assert_eq!(record["last_outcome"], "completed_small");
    assert_eq!(record["last_rest_millis"], record["last_wall_millis"]);
    let names = phase_names(&record);
    for want in [
        "in_place_lease",
        "in_place_open_writer",
        "apply_projection_digest",
        "apply_commit",
        "in_place_sidecars",
    ] {
        assert!(names.contains(&want.to_owned()), "{want} in {names:?}");
    }
    assert!(!names.contains(&"prepare_copy".to_owned()));
    assert!(!names.contains(&"publish_pointer".to_owned()));
    // A cold restart verifies the advanced WAL copy (shape, state, integrity).
    s.assert_startup_serves().await;
    reader.close().await;
    s.hosted.close().await;
}

#[tokio::test]
async fn reader_holding_a_transaction_keeps_the_old_snapshot_across_an_in_place_apply() {
    let mut s = setup().await;
    // The first in-place apply switches the file to WAL, which (once) needs a
    // moment with no read transaction open. Every later apply never waits.
    s.hosted_adds_records(1).await;
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    s.forget_rest();
    let reader = s.reader().await;
    let mut tx = reader.pool().begin().await.unwrap();
    let old = read_state_on(&mut tx).await;
    s.hosted_adds_records(2).await;
    let server = s.serve(1).await;
    // The commit must not wait for the open reader (the writer's busy timeout
    // would be a minute); `advanced` fails the test if it does.
    advanced(&s).await;
    server.await.unwrap();
    let hosted = read_state(&s.hosted).await;
    assert_ne!(old, hosted);
    assert_eq!(read_state_on(&mut tx).await, old, "snapshot isolation");
    assert_eq!(read_state_on(&mut tx).await, old);
    tx.rollback().await.unwrap();
    assert_eq!(read_state(&reader).await, hosted);
    reader.close().await;
    s.hosted.close().await;
}

#[tokio::test]
async fn concurrent_readers_only_ever_see_a_whole_head() {
    let mut s = setup().await;
    let reader = s.reader().await;
    let mut allowed: HashSet<State> = HashSet::new();
    allowed.insert(read_state(&reader).await);
    let stop = Arc::new(AtomicBool::new(false));
    let mut readers = Vec::new();
    for _ in 0..4 {
        let db = reader.clone();
        let stop = stop.clone();
        readers.push(tokio::spawn(async move {
            let mut seen = HashSet::new();
            while !stop.load(Ordering::SeqCst) {
                seen.insert(read_state(&db).await);
                tokio::task::yield_now().await;
            }
            seen
        }));
    }
    let server = s.serve(3).await;
    for round in 0..3 {
        // A different amount of work each time, so each head is distinct.
        s.hosted_adds_records(round + 1).await;
        allowed.insert(read_state(&s.hosted).await);
        advanced(&s).await;
        s.forget_rest();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    server.await.unwrap();
    stop.store(true, Ordering::SeqCst);
    let mut seen = HashSet::new();
    for task in readers {
        seen.extend(task.await.unwrap());
    }
    assert!(
        seen.is_subset(&allowed),
        "a reader saw a state that is no head: {:?}",
        seen.difference(&allowed).collect::<Vec<_>>()
    );
    assert_eq!(read_state(&reader).await, read_state(&s.hosted).await);
    assert_eq!(s.applied().await, 3);
    reader.close().await;
    s.hosted.close().await;
}

/// Invariants that must hold after a crash at any point: the head record and
/// the chain never lead the database, and a cold start still serves.
async fn assert_sidecars_not_ahead(s: &Setup) -> State {
    let store = s.restarted_store();
    let reader = s.reader().await;
    let db_state = read_state(&reader).await;
    reader.close().await;
    let head = store.generation_head(&s.current.id).unwrap().map_or_else(
        || s.current.manifest.head_act.unwrap(),
        |head| head.head_act,
    );
    assert!(
        head <= db_state.0,
        "head record {} leads database {}",
        head,
        db_state.0
    );
    // The in-database receipts continue the database (light) and, where the
    // copy was advanced in place, the full check passes too.
    let generation = store.current_for_head_probe().unwrap().unwrap();
    store
        .check_in_place_integrity(&generation, IntegrityDepth::Full)
        .await
        .expect("receipts verify after a crash");
    s.assert_startup_serves().await;
    db_state
}

#[tokio::test]
async fn crash_before_commit_leaves_the_old_head_and_recovers() {
    let mut s = setup().await;
    let old = assert_sidecars_not_ahead(&s).await;
    s.hosted_adds_records(1).await;
    s.controller.kernel_in_place_crash = Some(InPlaceCrash::BeforeCommit);
    let server = s.serve(1).await;
    assert!(s.refresh().await.is_err());
    server.await.unwrap();
    // Nothing was committed anywhere.
    assert_eq!(assert_sidecars_not_ahead(&s).await, old);
    assert_eq!(s.head_act(), old.0);
    assert_eq!(s.applied().await, 0);
    // Recovery: the same delta applies cleanly on the next attempt.
    s.controller.kernel_in_place_crash = None;
    s.forget_rest();
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    assert_eq!(
        assert_sidecars_not_ahead(&s).await,
        read_state(&s.hosted).await
    );
    assert_eq!(s.head_act(), read_state(&s.hosted).await.0);
    s.hosted.close().await;
}

#[tokio::test]
async fn crash_after_commit_before_sidecar_leaves_the_sidecar_behind_and_heals() {
    let mut s = setup().await;
    let old = assert_sidecars_not_ahead(&s).await;
    s.hosted_adds_records(1).await;
    let hosted = read_state(&s.hosted).await;
    s.controller.kernel_in_place_crash = Some(InPlaceCrash::AfterCommitBeforeSidecar);
    let server = s.serve(1).await;
    assert!(s.refresh().await.is_err());
    server.await.unwrap();
    // The database is at N+1, the sidecar still says N: behind, never ahead.
    assert_eq!(s.head_act(), old.0);
    assert_eq!(s.applied().await, 1, "the receipt committed with the data");
    // Startup verification proves the copy from its own receipts and repairs
    // the lagging sidecar from the database.
    assert_eq!(assert_sidecars_not_ahead(&s).await, hosted);
    assert_eq!(s.head_act(), hosted.0);
    // Recovery 1: nothing new upstream. (No audit is due: this test is about
    // the crash, and an idle audit would be a second call.)
    s.controller.kernel_in_place_crash = None;
    s.controller.proof_audit.lock().unwrap().last = Some(std::time::Instant::now());
    s.forget_rest();
    let server = s.serve_calls(1).await;
    assert!(matches!(
        s.refresh().await.unwrap(),
        StandbyDeltaOutcome::Unchanged { .. }
    ));
    server.await.unwrap();
    assert_eq!(s.head_act(), hosted.0);
    // Recovery 2: the receipt committed with the fold, so there is no gap to
    // distrust. The next delta applies in place on the same receipt chain.
    s.hosted_adds_records(1).await;
    s.forget_rest();
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    assert_eq!(replay_record(&s.controller)["last_path"], "in_place");
    assert_eq!(s.applied().await, 2);
    assert_eq!(s.head_act(), read_state(&s.hosted).await.0);
    s.full_check().await.unwrap();
    s.assert_startup_serves().await;
    s.hosted.close().await;
}

#[tokio::test]
async fn crash_after_sidecar_is_a_complete_advance() {
    let mut s = setup().await;
    s.hosted_adds_records(1).await;
    let hosted = read_state(&s.hosted).await;
    s.controller.kernel_in_place_crash = Some(InPlaceCrash::AfterSidecar);
    let server = s.serve(1).await;
    assert!(s.refresh().await.is_err());
    server.await.unwrap();
    assert_eq!(assert_sidecars_not_ahead(&s).await, hosted);
    assert_eq!(s.head_act(), hosted.0);
    assert_eq!(s.applied().await, 1);
    // Restart: unchanged upstream is a no-op, and a further delta still
    // applies in place on the same chain. (No audit is due here either.)
    s.controller.kernel_in_place_crash = None;
    s.controller.proof_audit.lock().unwrap().last = Some(std::time::Instant::now());
    s.forget_rest();
    let server = s.serve_calls(1).await;
    assert!(matches!(
        s.refresh().await.unwrap(),
        StandbyDeltaOutcome::Unchanged { .. }
    ));
    server.await.unwrap();
    s.hosted_adds_records(1).await;
    s.forget_rest();
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    assert_eq!(replay_record(&s.controller)["last_path"], "in_place");
    assert_eq!(s.applied().await, 2);
    s.assert_startup_serves().await;
    s.hosted.close().await;
}

#[tokio::test]
async fn digest_mismatch_rolls_back_the_serving_copy_and_requests_a_whole_snapshot() {
    let mut s = setup().await;
    let reader = s.reader().await;
    let before_tables = crate::kernel::dump_all_kernel_tables(&reader)
        .await
        .unwrap();
    let before = read_state(&reader).await;
    let id = crate::kernel::create_record_as(&s.hosted, &s.admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    // Corrupt only the hosted projection: coordinates agree, digest cannot.
    sqlx::query("UPDATE kernel_records SET created_at='2030-01-01T00:00:00Z' WHERE id=?")
        .bind(id)
        .execute(s.hosted.write_pool())
        .await
        .unwrap();
    let server = s.serve(1).await;
    assert!(matches!(
        s.refresh().await.unwrap(),
        StandbyDeltaOutcome::FullRefreshRequired {
            reason: DeltaFallbackClass::ProjectionDivergence
        }
    ));
    server.await.unwrap();
    // Rolled back: same bytes as seen by readers, same sidecars, same file.
    assert_eq!(read_state(&reader).await, before);
    assert_eq!(
        crate::kernel::dump_all_kernel_tables(&reader)
            .await
            .unwrap(),
        before_tables
    );
    assert_eq!(s.head_act(), before.0);
    assert_eq!(s.applied().await, 0);
    assert_eq!(
        s.controller
            .store
            .current_for_head_probe()
            .unwrap()
            .unwrap()
            .id,
        s.current.id
    );
    let record = replay_record(&s.controller);
    assert_eq!(record["last_outcome"], "failed");
    assert_eq!(record["last_path"], "in_place");
    assert!(record["last_rest_millis"].as_u64().unwrap() >= 60_000);
    s.assert_startup_serves().await;
    reader.close().await;
    s.hosted.close().await;
}

#[tokio::test]
async fn large_delta_takes_the_staged_path_even_from_an_advanced_copy() {
    let mut s = setup().await;
    // First an in-place advance, so the base is a WAL copy.
    s.hosted_adds_records(1).await;
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    assert_eq!(replay_record(&s.controller)["last_path"], "in_place");
    // Then a large delta: staged copy-and-publish, consistent with the WAL.
    s.hosted_adds_records(super::super::super::kernel_v2_delta::SMALL_DELTA_MAX_EVENTS)
        .await;
    s.forget_rest();
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    let record = replay_record(&s.controller);
    assert_eq!(record["last_path"], "staged");
    assert_eq!(record["last_in_place_skip"], "delta_not_small");
    assert_eq!(record["last_outcome"], "completed_large");
    let next = s
        .controller
        .store
        .current_for_head_probe()
        .unwrap()
        .unwrap();
    assert_ne!(next.id, s.current.id);
    let reopened =
        crate::db::open_kernel_v2_standby_read_only(next.snapshot_path.to_str().unwrap())
            .await
            .unwrap();
    assert_eq!(
        crate::kernel::dump_all_kernel_tables(&s.hosted)
            .await
            .unwrap(),
        crate::kernel::dump_all_kernel_tables(&reopened)
            .await
            .unwrap()
    );
    assert_eq!(
        s.controller
            .store
            .generation_head(&next.id)
            .unwrap()
            .unwrap()
            .materialization,
        StandbyGenerationMaterialization::Snapshot
    );
    reopened.close().await;
    s.hosted.close().await;
}

#[tokio::test]
async fn a_reader_that_is_not_this_build_keeps_the_staged_path() {
    let mut s = setup().await;
    // Replace the reader marker with another build's.
    let mut other = s.controller.observed.clone();
    other.source_sha = "9".repeat(40);
    s.controller
        .store
        .record_serving_reader(&s.current.id, &other)
        .unwrap();
    s.hosted_adds_records(1).await;
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    let record = replay_record(&s.controller);
    assert_eq!(record["last_path"], "staged");
    assert_eq!(record["last_in_place_skip"], "reader_not_upgraded");
    // The serving file was never touched.
    assert_eq!(journal_mode(&s.current.snapshot_path).await, "delete");
    assert_eq!(s.applied().await, 0);
    assert!(!s
        .controller
        .store
        .generation_head(&s.current.id)
        .unwrap()
        .is_some_and(|head| head.advanced_in_place()));
    s.hosted.close().await;
}

#[tokio::test]
async fn the_flag_is_off_by_default() {
    let mut s = setup().await;
    s.controller.config.kernel_in_place_deltas = false;
    s.hosted_adds_records(1).await;
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    let record = replay_record(&s.controller);
    assert_eq!(record["last_path"], "staged");
    assert!(record["last_in_place_skip"].is_null());
    assert_eq!(journal_mode(&s.current.snapshot_path).await, "delete");
    s.hosted.close().await;
}

#[tokio::test]
async fn a_head_record_ahead_of_its_database_requests_a_whole_snapshot() {
    let mut s = setup().await;
    s.hosted_adds_records(1).await;
    // Forge a head that leads the file.
    s.controller
        .store
        .record_synced(&s.current, 1_000_000, &now())
        .unwrap();
    let server = s.serve(1).await;
    assert!(matches!(
        s.refresh().await.unwrap(),
        StandbyDeltaOutcome::FullRefreshRequired {
            reason: DeltaFallbackClass::UntrustedLocalBase
        }
    ));
    // Only the head probe was served; no delta was fetched or applied.
    server.abort();
    s.hosted.close().await;
}

async fn count_of(db: &crate::Db, table: &str) -> i64 {
    let mut tx = db.pool().begin().await.unwrap();
    let n = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    n
}

async fn first_in_place_delta(s: &mut Setup, records: usize) {
    s.hosted_adds_records(records).await;
    let server = s.serve(1).await;
    advanced(s).await;
    server.await.unwrap();
    s.forget_rest();
}

fn not_serving(outcome: crate::Result<StandbyStartupOutcome>) -> bool {
    !matches!(outcome, Ok(StandbyStartupOutcome::Serving(_)))
}

/// Files the serving process owns beside the database, with their bytes.
fn sidecars(s: &Setup) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    let root = s.controller.runtime.replica_root.join("accepted");
    let mut out = std::collections::BTreeMap::new();
    for dir in ["heads", "audits"] {
        for entry in fs::read_dir(root.join(dir)).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                out.insert(path.clone(), fs::read(&path).unwrap());
            }
        }
    }
    out
}

/// `--standby-prepare-consumer` beside a live serving process that has already
/// advanced the copy in place: it verifies the advanced copy and publishes the
/// receipt, and leaves the head sidecar, audit record and the original
/// consumer's reader marker exactly as the serving process left them. The
/// serving process keeps applying deltas, and the new build then starts.
#[tokio::test]
async fn prepare_beside_a_serving_process_leaves_its_sidecars_and_deltas_alone() {
    let mut s = setup().await;
    first_in_place_delta(&mut s, 1).await;
    let mut next = s.controller.observed.clone();
    next.source_sha = "8".repeat(40);
    next.artifact_sha256 = "7".repeat(64);
    let store = s.restarted_store();
    let before = sidecars(&s);

    let prepared = store.prepare_consumer_binding(&next).await.unwrap();
    assert_eq!(prepared.generation_id, s.current.id);
    assert_eq!(prepared.outcome, crate::standby::PreparedOutcome::Verified);

    let after = sidecars(&s);
    for (path, bytes) in &before {
        assert_eq!(after.get(path), Some(bytes), "{} changed", path.display());
    }
    let added: Vec<_> = after.keys().filter(|p| !before.contains_key(*p)).collect();
    assert_eq!(added.len(), 1, "{added:?}");
    assert!(added[0]
        .file_name()
        .unwrap()
        .to_string_lossy()
        .contains("consumer-rebind-"));
    assert!(s
        .controller
        .store
        .served_by_build(&s.current.id, &s.controller.observed.source_sha));

    // The serving process still advances the same file after the prepare.
    s.hosted_adds_records(1).await;
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    s.forget_rest();

    // The new build starts on the prepared copy, and the receipt is reused.
    let receipt_path = s
        .controller
        .runtime
        .replica_root
        .join("accepted/heads")
        .join(format!(
            "{}.consumer-rebind-{}.json",
            s.current.id, next.artifact_sha256
        ));
    let receipt = fs::read(&receipt_path).unwrap();
    let outcome = s.restarted_store().activate_for_startup(&next).await;
    assert!(
        matches!(outcome, Ok(StandbyStartupOutcome::Serving(_))),
        "{:?}",
        outcome.err()
    );
    assert_eq!(fs::read(&receipt_path).unwrap(), receipt);
    s.hosted.close().await;
}

/// The first in-place delta waits on no one: while a prepare is hashing the
/// not-yet-advanced checkpoint (shared checkpoint lease), the delta is refused
/// the in-place path, changes nothing, and applies once the prepare is done.
#[tokio::test]
async fn a_first_delta_during_prepare_defers_then_applies_after_it() {
    let mut s = setup().await;
    let mut next = s.controller.observed.clone();
    next.source_sha = "8".repeat(40);
    next.artifact_sha256 = "7".repeat(64);
    let store = s.restarted_store();
    let (entered, resume) = store.pause_next_rebind();
    let base_act = s.head_act();
    let before = fs::read(&s.current.snapshot_path).unwrap();
    s.hosted_adds_records(1).await;
    let server = s.serve(1).await;

    let prepare = store.prepare_consumer_binding(&next);
    let overlap = async {
        entered.notified().await;
        let outcome = s.refresh().await;
        // Nothing moved while the checkpoint was held: same bytes, same head,
        // still a checkpoint, no in-place chain started.
        assert_eq!(fs::read(&s.current.snapshot_path).unwrap(), before);
        assert_eq!(s.head_act(), base_act);
        assert!(!store
            .generation_head(&s.current.id)
            .unwrap()
            .is_some_and(|head| head.advanced_in_place()));
        resume.notify_one();
        outcome
    };
    let (prepared, outcome) = tokio::join!(prepare, overlap);
    server.abort();
    let prepared = prepared.unwrap();
    assert_eq!(prepared.outcome, crate::standby::PreparedOutcome::Verified);
    assert!(
        matches!(
            outcome,
            Ok(StandbyDeltaOutcome::Deferred {
                reason: "checkpoint_being_verified"
            })
        ),
        "the first in-place delta must defer under a held checkpoint: {outcome:?}"
    );
    s.forget_rest();

    // With the prepare finished, the same delta now applies in place.
    let current = s
        .controller
        .store
        .current_for_head_probe()
        .unwrap()
        .unwrap();
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    assert!(s.head_act() > base_act);
    assert_eq!(
        s.controller
            .store
            .current_for_head_probe()
            .unwrap()
            .unwrap()
            .id,
        current.id
    );
    s.full_check().await.unwrap();
    s.assert_startup_serves().await;
    s.hosted.close().await;
}

#[tokio::test]
async fn a_restored_database_is_refused_at_rebinding_while_sidecars_say_newer() {
    let mut s = setup().await;
    first_in_place_delta(&mut s, 1).await;
    // Save the database as it stands at N (a consistent copy, receipts and all).
    let saved = s._directory.path().join("saved-at-n.db");
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
    let at_n = s.head_act();
    // Advance to N+1: the head sidecar now says N+1.
    first_in_place_delta(&mut s, 1).await;
    assert!(s.head_act() > at_n);
    // Restore the database to N behind the sidecar's back.
    for suffix in ["-wal", "-shm"] {
        let mut name = s.current.snapshot_path.clone().into_os_string();
        name.push(suffix);
        let _ = fs::remove_file(name);
    }
    fs::copy(&saved, &s.current.snapshot_path).unwrap();
    set_mode(&s.current.snapshot_path, 0o600).unwrap();
    // A compatible new build rebinds: it must verify, not wave the copy in.
    let mut next = s.controller.observed.clone();
    next.source_sha = "8".repeat(40);
    next.artifact_sha256 = "7".repeat(64);
    let store = s.restarted_store();
    assert!(store
        .ensure_consumer_binding(&s.current.id, &next)
        .await
        .is_err());
    assert!(store
        .consumer_rebind(&s.current.id, &next)
        .ok()
        .flatten()
        .is_none());
    assert!(not_serving(store.activate_for_startup(&next).await));
    // The refresh tick refuses it too and asks for a whole snapshot.
    let server = s.serve_calls(1).await;
    assert!(matches!(
        s.refresh().await.unwrap(),
        StandbyDeltaOutcome::FullRefreshRequired { .. }
    ));
    server.await.unwrap();
    s.hosted.close().await;
}

/// The restart fast path advertises a copy's act from its head sidecar, so a
/// sidecar ahead of a restored older database must keep the copy off the fast
/// path (the cheap in-place check runs before publication); a sound advanced
/// copy still takes it.
#[tokio::test]
async fn fast_restart_refuses_a_restored_database_behind_newer_sidecars() {
    let mut s = setup().await;
    first_in_place_delta(&mut s, 1).await;
    let fast = s
        .restarted_store()
        .activate_for_startup_fast(&s.controller.observed)
        .await
        .unwrap();
    assert!(fast.is_some(), "a sound advanced copy takes the fast path");
    drop(fast);
    let saved = s._directory.path().join("saved-at-n.db");
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
    let at_n = s.head_act();
    first_in_place_delta(&mut s, 1).await;
    assert!(s.head_act() > at_n);
    for suffix in ["-wal", "-shm"] {
        let mut name = s.current.snapshot_path.clone().into_os_string();
        name.push(suffix);
        let _ = fs::remove_file(name);
    }
    fs::copy(&saved, &s.current.snapshot_path).unwrap();
    set_mode(&s.current.snapshot_path, 0o600).unwrap();
    let store = s.restarted_store();
    let fast = store
        .activate_for_startup_fast(&s.controller.observed)
        .await
        .unwrap();
    assert!(
        fast.is_none(),
        "a head record ahead of its database must not be advertised early"
    );
    // The full path then refuses it as before.
    assert!(not_serving(
        store.activate_for_startup(&s.controller.observed).await
    ));
    s.hosted.close().await;
}

#[tokio::test]
async fn tampering_with_canonical_event_rows_is_caught_by_the_receipts() {
    for victim in ["MAX(seq)", "MIN(seq)+1"] {
        let mut s = setup().await;
        first_in_place_delta(&mut s, 2).await;
        s.full_check().await.unwrap();
        // Rewrite one stored event row (a delta row, then a checkpoint row)
        // without touching any coordinate or the projection.
        s.corrupt_events(&format!(
            "UPDATE content_events SET created_at='2031-01-01T00:00:00Z' WHERE seq=(SELECT {victim} FROM content_events)"
        ))
        .await;
        assert!(s.full_check().await.is_err(), "{victim}");
        assert!(not_serving(
            s.restarted_store()
                .activate_for_startup(&s.controller.observed)
                .await
        ));
        s.hosted.close().await;
    }
}

#[tokio::test]
async fn tampering_with_blob_bytes_is_caught_by_their_content_address() {
    let mut s = setup().await;
    let bytes = vec![7_u8; 4096];
    sqlx::query("INSERT INTO kernel_blobs VALUES(?,?,?,NULL)")
        .bind(crate::standby_snapshot::sha256_bytes(&bytes))
        .bind(bytes.as_slice())
        .bind(bytes.len() as i64)
        .execute(s.hosted.write_pool())
        .await
        .unwrap();
    first_in_place_delta(&mut s, 1).await;
    s.full_check().await.unwrap();
    // Same key, same length, different bytes.
    s.corrupt("UPDATE kernel_blobs SET bytes=zeroblob(4096) WHERE size_bytes=4096")
        .await;
    assert!(s.full_check().await.is_err());
    assert!(not_serving(
        s.restarted_store()
            .activate_for_startup(&s.controller.observed)
            .await
    ));
    s.hosted.close().await;
}

#[tokio::test]
async fn missing_or_corrupt_receipts_refuse_in_place_serving_and_force_a_whole_snapshot() {
    // Digest damage rotates the first hex digit, so it always changes the value.
    // Overwriting a fixed prefix ('ab', 'cd') was a no-op whenever the digest
    // already began with it, about 1 in 256 runs per case.
    for (damage, light_catches) in [
        ("DROP TABLE kernel_standby_apply_receipts", true),
        (
            "DELETE FROM kernel_standby_apply_receipts WHERE ordinal=(SELECT MAX(ordinal) FROM kernel_standby_apply_receipts)",
            true,
        ),
        (
            "UPDATE kernel_standby_apply_receipts SET chain_sha256=printf('%x', instr('0123456789abcdef', substr(chain_sha256,1,1)) % 16) || substr(chain_sha256,2) WHERE ordinal=0",
            false,
        ),
        (
            "UPDATE kernel_standby_apply_receipts SET projection_sha256=printf('%x', instr('0123456789abcdef', substr(projection_sha256,1,1)) % 16) || substr(projection_sha256,2) WHERE ordinal=1",
            false,
        ),
    ] {
        let mut s = setup().await;
        first_in_place_delta(&mut s, 1).await;
        s.full_check().await.unwrap();
        s.corrupt(damage).await;
        // Startup verification and audit always see it.
        assert!(s.full_check().await.is_err(), "{damage}");
        assert!(not_serving(
            s.restarted_store()
                .activate_for_startup(&s.controller.observed)
                .await
        ));
        // The tick's cheap check sees what it can; the rest waits for the
        // next full check, and the copy is never repaired from local state.
        let light = s
            .restarted_store()
            .check_in_place_integrity(&s.current, IntegrityDepth::Light)
            .await;
        assert_eq!(light.is_err(), light_catches, "{damage}");
        if light_catches {
            let server = s.serve_calls(1).await;
            assert!(matches!(
                s.refresh().await.unwrap(),
                StandbyDeltaOutcome::FullRefreshRequired { .. }
            ));
            server.await.unwrap();
            assert!(s
                .controller
                .store
                .generation_head(&s.current.id)
                .unwrap()
                .unwrap()
                .full_refresh_required);
        }
        s.hosted.close().await;
    }
}

#[tokio::test]
async fn recheckpoint_limits_are_evaluated_even_when_no_delta_is_pending() {
    use crate::standby::generation_store::kernel_in_place::RECHECKPOINT_OVERRIDE;
    let mut s = setup().await;
    first_in_place_delta(&mut s, 1).await;
    let sound = InPlaceState::Sound {
        applied: 1,
        db_head_act: 0,
        accumulator: AccumulatorStatus::NotChecked,
    };
    let store = &s.controller.store;
    assert_eq!(store.kernel_recheckpoint_due(&s.current, sound), None);
    RECHECKPOINT_OVERRIDE.with(|cell| cell.set(Some((u64::MAX, -1))));
    assert_eq!(
        store.kernel_recheckpoint_due(&s.current, sound),
        Some("recheckpoint_age")
    );
    // Count limit, and nothing new upstream: the tick still re-checkpoints.
    RECHECKPOINT_OVERRIDE.with(|cell| cell.set(Some((1, i64::MAX))));
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    RECHECKPOINT_OVERRIDE.with(|cell| cell.set(None));
    let record = replay_record(&s.controller);
    assert_eq!(record["last_path"], "staged");
    assert_eq!(record["last_in_place_skip"], "recheckpoint_delta_count");
    let next = s
        .controller
        .store
        .current_for_head_probe()
        .unwrap()
        .unwrap();
    assert_ne!(next.id, s.current.id);
    let reopened =
        crate::db::open_kernel_v2_standby_read_only(next.snapshot_path.to_str().unwrap())
            .await
            .unwrap();
    assert_eq!(
        crate::kernel::dump_all_kernel_tables(&s.hosted)
            .await
            .unwrap(),
        crate::kernel::dump_all_kernel_tables(&reopened)
            .await
            .unwrap()
    );
    // The new checkpoint is a fresh file: no receipts, not advanced.
    assert_eq!(
        count_table(&reopened, "kernel_standby_apply_receipts").await,
        None
    );
    reopened.close().await;
    s.hosted.close().await;
}

async fn count_table(db: &crate::Db, table: &str) -> Option<i64> {
    sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(db.pool())
        .await
        .ok()
}

#[tokio::test]
async fn one_composed_read_sees_one_state_across_an_in_place_apply() {
    let mut s = setup().await;
    first_in_place_delta(&mut s, 1).await;
    let reader = s.reader().await;
    let before = read_state(&reader).await;

    // Control: two queries on separate pool snapshots with an apply between
    // them see a state that never existed.
    s.hosted_adds_records(2).await;
    let server = s.serve(1).await;
    let records = count_of(&reader, "kernel_records").await;
    advanced(&s).await;
    server.await.unwrap();
    s.forget_rest();
    let events = count_of(&reader, "content_events").await;
    let after = read_state(&reader).await;
    assert_ne!((before.3, before.1), (records, events));
    assert_ne!((after.3, after.1), (records, events));

    // Guarded: the same composed read, with the apply landing mid-operation,
    // is re-run and returns one coherent state.
    let before = after;
    s.hosted_adds_records(2).await;
    let server = s.serve(1).await;
    let first_run = std::sync::atomic::AtomicBool::new(true);
    let runs = std::sync::atomic::AtomicUsize::new(0);
    let seen = crate::standby::stable_read::stable(&reader, || async {
        runs.fetch_add(1, Ordering::SeqCst);
        let records = count_of(&reader, "kernel_records").await;
        if first_run.swap(false, Ordering::SeqCst) {
            advanced(&s).await;
        }
        let events = count_of(&reader, "content_events").await;
        (records, events)
    })
    .await
    .expect("a single apply does not exhaust the retries");
    server.await.unwrap();
    let after = read_state(&reader).await;
    assert_eq!(runs.load(Ordering::SeqCst), 2, "moved once, re-run once");
    assert_ne!(before, after);
    assert_eq!(seen, (after.3, after.1));
    reader.close().await;
    s.hosted.close().await;
}

// ---- second receipts DDL and the accumulator cache (design record 5065900) ----

async fn n2_shaped() -> Setup {
    let mut s = setup().await;
    first_in_place_delta(&mut s, 1).await;
    convert_to_n2_shape(&s.current.snapshot_path, &s.current)
        .await
        .unwrap();
    s
}

async fn scalar_i64(s: &Setup, sql: &str) -> i64 {
    let mut conn = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&s.current.snapshot_path)
            .read_only(true),
    )
    .await
    .unwrap();
    let n = sqlx::query_scalar(sql)
        .fetch_one(&mut conn)
        .await
        .unwrap_or(-1);
    conn.close().await.unwrap();
    n
}

async fn full_state(s: &Setup) -> crate::Result<InPlaceState> {
    s.restarted_store()
        .check_in_place_integrity(&s.current, IntegrityDepth::Full)
        .await
}

async fn last_receipt_shape(s: &Setup) -> (String, Option<String>, Option<String>) {
    let mut conn = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&s.current.snapshot_path)
            .read_only(true),
    )
    .await
    .unwrap();
    let row = sqlx::query_as(
        "SELECT kind,projection_sha256,projection_set_sha256 FROM kernel_standby_apply_receipts ORDER BY ordinal DESC LIMIT 1",
    )
    .fetch_one(&mut conn)
    .await
    .unwrap();
    conn.close().await.unwrap();
    row
}

#[tokio::test]
async fn a_set_digest_shaped_generation_opens_here_and_a_delta_invalidates_its_accumulator() {
    let mut s = n2_shaped().await;
    // It opens: both receipts DDLs and the cache table are accepted by the
    // schema inventory, the second link format verifies, the newest receipt's
    // set digest matches the rows and the populated cache matches too.
    assert!(matches!(
        full_state(&s).await.unwrap(),
        InPlaceState::Sound {
            accumulator: AccumulatorStatus::Valid,
            ..
        }
    ));
    let (kind, v1, set) = last_receipt_shape(&s).await;
    assert_eq!(
        (kind.as_str(), v1.is_none(), set.is_some()),
        ("delta-set", true, true)
    );
    assert!(scalar_i64(&s, "SELECT COUNT(*) FROM kernel_standby_projection_set").await > 0);
    s.assert_startup_serves().await;
    // A delta applied here writes a first-kind receipt (set digest NULL) and
    // empties the cache in the same transaction.
    s.hosted_adds_records(1).await;
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    // This release also proves the set digest: a version-1 delta on a
    // second-DDL copy is one full dual scan that records both digests and
    // reseeds the cache (the previous release emptied it instead).
    let (kind, v1, set) = last_receipt_shape(&s).await;
    assert_eq!(
        (kind.as_str(), v1.is_some(), set.is_some()),
        ("delta", true, true)
    );
    assert!(scalar_i64(&s, "SELECT COUNT(*) FROM kernel_standby_projection_set").await > 0);
    assert_eq!(
        scalar_i64(&s, "SELECT COUNT(*) FROM kernel_standby_apply_receipts").await,
        4 - 1
    );
    // Before any further delta: the receipt with a NULL set digest verifies on
    // the v1 digest alone, over the unbroken second-format chain.
    assert!(matches!(
        full_state(&s).await.unwrap(),
        InPlaceState::Sound {
            accumulator: AccumulatorStatus::Valid,
            ..
        }
    ));
    s.assert_startup_serves().await;
    // ...and it still catches projection damage on v1.
    s.corrupt_projection().await;
    assert!(full_state(&s).await.is_err());
    s.hosted.close().await;
}

#[tokio::test]
async fn the_staged_recheckpoint_removes_the_accumulator_with_the_receipts() {
    use crate::standby::generation_store::kernel_in_place::RECHECKPOINT_OVERRIDE;
    let mut s = n2_shaped().await;
    RECHECKPOINT_OVERRIDE.with(|cell| cell.set(Some((1, i64::MAX))));
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    RECHECKPOINT_OVERRIDE.with(|cell| cell.set(None));
    let next = s
        .controller
        .store
        .current_for_head_probe()
        .unwrap()
        .unwrap();
    assert_ne!(next.id, s.current.id);
    let reopened =
        crate::db::open_kernel_v2_standby_read_only(next.snapshot_path.to_str().unwrap())
            .await
            .unwrap();
    for table in [
        "kernel_standby_apply_receipts",
        "kernel_standby_projection_set",
    ] {
        let present: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?)",
        )
        .bind(table)
        .fetch_one(reopened.pool())
        .await
        .unwrap();
        assert!(!present, "{table} must not survive a re-checkpoint");
    }
    reopened.close().await;
    s.hosted.close().await;
}

#[tokio::test]
async fn tampering_with_the_set_digest_or_the_kind_breaks_the_second_format_chain() {
    for tamper in [
        // The certified set digest changes: the first nibble is advanced by one,
        // so the digest is always different (still a well-formed digest).
        "UPDATE kernel_standby_apply_receipts SET projection_set_sha256=printf('%x', instr('0123456789abcdef', substr(projection_set_sha256,1,1)) % 16) || substr(projection_set_sha256,2) WHERE kind='delta-set'",
        // The kind changes and a v1 digest is supplied so the receipt still
        // certifies something: only the chain can notice.
        "UPDATE kernel_standby_apply_receipts SET kind='delta', projection_sha256=printf('%064d',7) WHERE kind='delta-set'",
        // The set digest is dropped for a v1 digest.
        "UPDATE kernel_standby_apply_receipts SET projection_set_sha256=NULL, projection_sha256=printf('%064d',7) WHERE kind='delta-set'",
    ] {
        let s = n2_shaped().await;
        s.corrupt(tamper).await;
        let error = full_state(&s).await.unwrap_err().to_string();
        assert!(error.contains("chain"), "{tamper}: {error}");
        assert!(not_serving(
            s.restarted_store()
                .activate_for_startup(&s.controller.observed)
                .await
        ));
        s.hosted.close().await;
    }
}

#[tokio::test]
async fn a_damaged_accumulator_at_the_right_ordinal_passes_and_is_marked_invalid() {
    let s = n2_shaped().await;
    s.corrupt("UPDATE kernel_standby_projection_set SET value=zeroblob(384) WHERE name=(SELECT MIN(name) FROM kernel_standby_projection_set)")
        .await;
    // Cache-versus-rows: the copy passes, and the cache is reported invalid.
    assert!(matches!(
        full_state(&s).await.unwrap(),
        InPlaceState::Sound {
            accumulator: AccumulatorStatus::Invalid,
            ..
        }
    ));
    assert!(!s.controller.store.accumulator_marked_invalid(&s.current.id));
    // Startup admits the copy and leaves the marker for the cache's writer.
    s.assert_startup_serves().await;
    assert!(s.controller.store.accumulator_marked_invalid(&s.current.id));
    // A wrong ordinal and a missing table are the same finding.
    s.corrupt("UPDATE kernel_standby_projection_set SET ordinal=ordinal+1")
        .await;
    assert!(matches!(
        full_state(&s).await.unwrap(),
        InPlaceState::Sound {
            accumulator: AccumulatorStatus::Invalid,
            ..
        }
    ));
    // Receipt-versus-rows is different: damage to the rows refuses.
    s.corrupt_projection().await;
    assert!(full_state(&s).await.is_err());
    s.hosted.close().await;
}

// Exercise the accepted source verifier using real authenticated transport and
// actual in-place fold receipts, rather than a raw native coordinate fixture.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn working_source_snapshot_keeps_verified_current_cut_and_rejects_forged_chain() {
    use crate::standby::generation_store::kernel_in_place::verify_working_source_on;
    let mut s = setup().await;
    let checkpoint = s.current.manifest.kernel_v2.as_ref().unwrap().clone();
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&s.current.snapshot_path)
        .read_only(true);
    let mut connection = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    // No-advance uses the actual verified checkpoint, not an invented head.
    let head = s.controller.store.generation_head(&s.current.id).unwrap();
    let mut snapshot = connection.begin().await.unwrap();
    assert_eq!(
        verify_working_source_on(&mut snapshot, &s.current, head.as_ref())
            .await
            .unwrap(),
        checkpoint
    );
    snapshot.rollback().await.unwrap();
    // The real writer has marked Delta, but has not opened/committed its base
    // receipt. Source admission must wait, not inspect that transient state.
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let store = s.controller.store.clone();
    let id = s.current.id.clone();
    let current = s.current.clone();
    store.pause_working_transition_for_test(entered.clone(), release.clone());
    let refresh = tokio::spawn(async move {
        first_in_place_delta(&mut s, 1).await;
        s
    });
    tokio::time::timeout(Duration::from_secs(10), entered.notified())
        .await
        .unwrap();
    let marked = store.generation_head(&id).unwrap();
    assert!(marked.as_ref().unwrap().advanced_in_place());
    let mut transient = connection.begin().await.unwrap();
    let error = verify_working_source_on(&mut transient, &current, marked.as_ref())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("advanced without apply receipts"),
        "{error}"
    );
    transient.rollback().await.unwrap();
    use std::{future::Future, task::Poll};
    let mut cancelled = Box::pin(store.working_source_checkpoint(&id));
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(cancelled.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(cancelled); // caller cancellation leaves no blocking worker/held guard.
    let mut admission = Box::pin(store.working_source_checkpoint(&id));
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(admission.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    release.notify_one();
    let checkpoint_guard = tokio::time::timeout(Duration::from_secs(10), admission)
        .await
        .unwrap()
        .unwrap();
    let mut s = refresh.await.unwrap();
    let head = s.controller.store.generation_head(&s.current.id).unwrap();
    let mut snapshot = connection.begin().await.unwrap();
    let cut = verify_working_source_on(&mut snapshot, &s.current, head.as_ref())
        .await
        .unwrap();
    assert!(cut.head_act > checkpoint.head_act);
    assert!(cut.content_event_seq > checkpoint.content_event_seq);
    // WAL is installed now; releasing this fence cannot invalidate the pin.
    drop(checkpoint_guard);
    assert_eq!(s.current.manifest.kernel_v2.as_ref().unwrap(), &checkpoint);
    // Holding the actual source Tx pins the cut even when genuine refresh
    // advances the physical accepted file. No rollback/re-BEGIN substitution.
    s.hosted_adds_records(1).await;
    s.forget_rest();
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    assert_eq!(
        crate::standby::kernel_v2::coordinates(&mut snapshot)
            .await
            .unwrap(),
        cut
    );
    assert_eq!(
        verify_working_source_on(&mut snapshot, &s.current, head.as_ref())
            .await
            .unwrap(),
        cut
    );
    snapshot.rollback().await.unwrap();
    let head = s.controller.store.generation_head(&s.current.id).unwrap();
    let mut snapshot = connection.begin().await.unwrap();
    let later = verify_working_source_on(&mut snapshot, &s.current, head.as_ref())
        .await
        .unwrap();
    assert!(later.head_act > cut.head_act);
    snapshot.rollback().await.unwrap();
    connection.close().await.unwrap();
    // Coordinates alone still match: forged or discontinuous receipts refuse
    // under the SAME actual transaction, with each corruption rolled back.
    let mut writer = sqlx::SqliteConnection::connect_with(&options.read_only(false))
        .await
        .unwrap();
    for tamper in [
        "UPDATE kernel_standby_apply_receipts SET chain_sha256=printf('%064d',7) WHERE ordinal=1",
        "UPDATE kernel_standby_apply_receipts SET from_act=from_act+1 WHERE ordinal=1",
    ] {
        let mut snapshot = writer.begin().await.unwrap();
        sqlx::query(tamper).execute(&mut *snapshot).await.unwrap();
        assert_eq!(
            crate::standby::kernel_v2::coordinates(&mut snapshot)
                .await
                .unwrap(),
            later
        );
        let error = verify_working_source_on(&mut snapshot, &s.current, head.as_ref())
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("receipt chain is broken"),
            "{error}"
        );
        snapshot.rollback().await.unwrap();
    }
    writer.close().await.unwrap();
    s.hosted.close().await;
    // An interrupted first transition releases the lock, but still must NOT
    // turn a Delta marker without its base receipt into trusted coordinates.
    let mut interrupted = setup().await;
    interrupted.hosted_adds_records(1).await;
    interrupted.controller.kernel_in_place_crash = Some(InPlaceCrash::AfterMarkBeforeBaseReceipt);
    let server = interrupted.serve(1).await;
    assert!(interrupted.refresh().await.is_err());
    server.await.unwrap();
    let guard = interrupted
        .controller
        .store
        .working_source_checkpoint(&interrupted.current.id)
        .await
        .unwrap();
    let head = interrupted
        .controller
        .store
        .generation_head(&interrupted.current.id)
        .unwrap();
    let mut connection = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&interrupted.current.snapshot_path)
            .read_only(true),
    )
    .await
    .unwrap();
    let mut snapshot = connection.begin().await.unwrap();
    assert_eq!(
        crate::standby::kernel_v2::coordinates(&mut snapshot)
            .await
            .unwrap(),
        *interrupted.current.manifest.kernel_v2.as_ref().unwrap()
    );
    let error = verify_working_source_on(&mut snapshot, &interrupted.current, head.as_ref())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("advanced without apply receipts"),
        "{error}"
    );
    snapshot.rollback().await.unwrap();
    drop(guard);
    connection.close().await.unwrap();
    interrupted.hosted.close().await;
}

#[tokio::test]
async fn first_ddl_generations_are_untouched_by_the_second_ddl_support() {
    let mut s = setup().await;
    first_in_place_delta(&mut s, 1).await;
    // Still the original table text, no cache table, and a receipt that
    // certifies the v1 digest in the original link format.
    let sql: String = {
        let mut conn = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&s.current.snapshot_path)
                .read_only(true),
        )
        .await
        .unwrap();
        let sql = sqlx::query_scalar(
            "SELECT sql FROM sqlite_schema WHERE name='kernel_standby_apply_receipts'",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        conn.close().await.unwrap();
        sql
    };
    assert_eq!(
        sql,
        crate::standby::generation_store::kernel_in_place::RECEIPTS_DDL
    );
    assert!(matches!(
        full_state(&s).await.unwrap(),
        InPlaceState::Sound {
            accumulator: AccumulatorStatus::Absent,
            ..
        }
    ));
    assert_eq!(
        scalar_i64(
            &s,
            "SELECT COUNT(*) FROM sqlite_schema WHERE name='kernel_standby_projection_set'"
        )
        .await,
        0
    );
    s.hosted_adds_records(1).await;
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    s.full_check().await.unwrap();
    s.hosted.close().await;
}

#[tokio::test]
async fn a_malformed_accumulator_is_a_cache_problem_not_a_refusal() {
    for damage in [
        "UPDATE kernel_standby_projection_set SET rows='broken'",
        "UPDATE kernel_standby_projection_set SET value=X'00ff'",
        "UPDATE kernel_standby_projection_set SET value='not a blob'",
        "UPDATE kernel_standby_projection_set SET name=NULL WHERE name=(SELECT MIN(name) FROM kernel_standby_projection_set)",
        "UPDATE kernel_standby_projection_set SET schema_sha256=NULL WHERE 0",
        "UPDATE kernel_standby_projection_set SET ordinal='x'",
    ] {
        let s = n2_shaped().await;
        s.corrupt(damage).await;
        assert!(
            matches!(
                full_state(&s).await.unwrap(),
                InPlaceState::Sound {
                    accumulator: AccumulatorStatus::Invalid | AccumulatorStatus::Valid,
                    ..
                }
            ),
            "{damage}"
        );
        if !damage.ends_with("WHERE 0") {
            assert!(matches!(
                full_state(&s).await.unwrap(),
                InPlaceState::Sound {
                    accumulator: AccumulatorStatus::Invalid,
                    ..
                }
            ));
        }
        s.assert_startup_serves().await;
        s.hosted.close().await;
    }
}

#[tokio::test]
async fn an_audit_marks_a_cache_damaged_after_startup_and_a_delta_clears_the_stale_marker() {
    let mut s = n2_shaped().await;
    s.assert_startup_serves().await;
    assert!(!s.controller.store.accumulator_marked_invalid(&s.current.id));
    // Damaged after startup: only a later check can see it.
    s.corrupt("UPDATE kernel_standby_projection_set SET value=zeroblob(384) WHERE name=(SELECT MIN(name) FROM kernel_standby_projection_set)")
        .await;
    let outcome = s
        .restarted_store()
        .audit_current(&s.controller.observed)
        .await
        .unwrap();
    assert!(outcome.passed, "the rows are sound; only the cache is not");
    assert!(s.controller.store.accumulator_marked_invalid(&s.current.id));
    // A delta applied here empties the cache; the marker no longer describes
    // anything and is removed.
    s.hosted_adds_records(1).await;
    let server = s.serve(1).await;
    advanced(&s).await;
    server.await.unwrap();
    assert!(!s.controller.store.accumulator_marked_invalid(&s.current.id));
    // And a marker left behind another way is cleared by the next full check
    // that finds the cache empty (absent).
    s.controller
        .store
        .mark_accumulator_invalid(&s.current.id)
        .unwrap();
    s.restarted_store()
        .audit_current(&s.controller.observed)
        .await
        .unwrap();
    assert!(!s.controller.store.accumulator_marked_invalid(&s.current.id));
    s.hosted.close().await;
}

#[tokio::test]
async fn a_historical_null_cannot_become_a_dash_or_a_non_hex_value() {
    for replacement in ["'-'", "'zz'", "''", "upper(printf('%064x', 255))"] {
        let mut s = n2_shaped().await;
        // Two ordinary deltas, so the NULL set digest below is HISTORICAL.
        for _ in 0..2 {
            s.hosted_adds_records(1).await;
            let server = s.serve(1).await;
            advanced(&s).await;
            server.await.unwrap();
            s.forget_rest();
        }
        full_state(&s).await.unwrap();
        s.corrupt(&format!(
            "UPDATE kernel_standby_apply_receipts SET projection_set_sha256={replacement} WHERE ordinal=2"
        ))
        .await;
        // Detected as it stands (chain or digest shape)...
        assert!(full_state(&s).await.is_err(), "{replacement}");
        // ...and still detected when the chain is recomputed around it: the
        // stored digest must itself be 64 lowercase hex characters.
        rechain_receipts(&s.current.snapshot_path, &s.current, |_| ReceiptsDdl::V2)
            .await
            .unwrap();
        assert!(full_state(&s).await.is_err(), "{replacement} rechained");
        s.hosted.close().await;
    }
}

#[tokio::test]
async fn a_chain_cannot_mix_link_formats() {
    // A downgrade within one chain: the newest receipt linked the old way.
    let s = n2_shaped().await;
    full_state(&s).await.unwrap();
    rechain_receipts(&s.current.snapshot_path, &s.current, |ordinal| {
        if ordinal == 0 {
            ReceiptsDdl::V2
        } else {
            ReceiptsDdl::V1
        }
    })
    .await
    .unwrap();
    let error = full_state(&s).await.unwrap_err().to_string();
    assert!(error.contains("chain"), "{error}");
    // The other way round: the old table with new-format links from the start.
    let t = setup().await;
    let mut t = t;
    first_in_place_delta(&mut t, 1).await;
    full_state(&t).await.unwrap();
    rechain_receipts(&t.current.snapshot_path, &t.current, |_| ReceiptsDdl::V2)
        .await
        .unwrap();
    assert!(full_state(&t).await.is_err());
    // Restoring the right format restores the chain: the refusals were the
    // format and nothing else.
    rechain_receipts(&t.current.snapshot_path, &t.current, |_| ReceiptsDdl::V1)
        .await
        .unwrap();
    full_state(&t).await.unwrap();
    s.hosted.close().await;
    t.hosted.close().await;
}

#[tokio::test]
async fn a_receipt_certifying_both_digests_refuses_when_either_one_mismatches() {
    let flip = |column: &str| {
        format!(
            "UPDATE kernel_standby_apply_receipts SET {column}=printf('%x', instr('0123456789abcdef', substr({column},1,1)) % 16) || substr({column},2) WHERE kind='delta-set'"
        )
    };
    // Both certified and both right: accepted.
    let s = n2_shaped_with(true).await;
    full_state(&s).await.unwrap();
    s.hosted.close().await;
    // Exactly one wrong, chain recomputed around it so only the digest
    // comparison can refuse: each is refused, naming that digest.
    for (column, expected) in [
        ("projection_sha256", "projection differs"),
        ("projection_set_sha256", "projection set digest differs"),
    ] {
        let s = n2_shaped_with(true).await;
        s.corrupt(&flip(column)).await;
        rechain_receipts(&s.current.snapshot_path, &s.current, |_| ReceiptsDdl::V2)
            .await
            .unwrap();
        let error = full_state(&s).await.unwrap_err().to_string();
        assert!(error.contains(expected), "{column}: {error}");
        s.hosted.close().await;
    }
}

async fn n2_shaped_with(certify_v1_too: bool) -> Setup {
    let mut s = setup().await;
    first_in_place_delta(&mut s, 1).await;
    convert_to_n2_shape_with(&s.current.snapshot_path, &s.current, certify_v1_too)
        .await
        .unwrap();
    s
}

/// Measurement harness, not a regression test. It builds a large synthetic
/// kernel-v2 base (set `TMPDIR` to a scratch directory with room for ~5 copies),
/// installs it twice, and applies identical small deltas to a staged-path
/// controller and an in-place controller in lockstep, printing per-phase
/// timings. Run with:
///
/// ```text
/// C15A932_RECORDS=20000 C15A932_BLOB_MIB=2800 C15A932_ROUNDS=3 \
///   cargo test --features v2-kernel-probe --lib measure_staged_vs_in_place \
///   -- --ignored --nocapture
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; builds multi-gigabyte scratch databases"]
async fn measure_staged_vs_in_place_on_a_large_base() {
    fn env(name: &str, default: usize) -> usize {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }
    let records = env("C15A932_RECORDS", 2000);
    let blob_mib = env("C15A932_BLOB_MIB", 64);
    let rounds = env("C15A932_ROUNDS", 3);
    let delta_records = env("C15A932_DELTA_RECORDS", 10);
    let started = std::time::Instant::now();
    let scratch = tempfile::tempdir().unwrap();
    let hosted_path = scratch.path().join("hosted.db");
    let (hosted, admin) = crate::kernel::create_v2_database(
        hosted_path.to_str().unwrap(),
        "account",
        "Owner",
        "acct:fixture",
    )
    .await
    .unwrap();
    for _ in 0..records {
        crate::kernel::create_record_as(&hosted, &admin, crate::events::KERNEL_ROOT_ID)
            .await
            .unwrap();
    }
    // Unbound 1 MiB blobs stand in for attachment bytes (HQ: 1,092 blobs).
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    for _ in 0..blob_mib {
        let mut bytes = vec![0_u8; 1024 * 1024];
        for chunk in bytes.chunks_mut(8) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let word = seed.to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        sqlx::query("INSERT INTO kernel_blobs VALUES(?,?,?,NULL)")
            .bind(crate::standby_snapshot::sha256_bytes(&bytes))
            .bind(bytes.as_slice())
            .bind(bytes.len() as i64)
            .execute(hosted.write_pool())
            .await
            .unwrap();
    }
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM content_events),(SELECT COUNT(*) FROM kernel_records)",
    )
    .fetch_one(hosted.pool())
    .await
    .unwrap();
    println!(
        "MEASURE base built in {:?}: {} content events, {} records, {} MiB blobs",
        started.elapsed(),
        counts.0,
        counts.1,
        blob_mib
    );

    // Controller A (staged, flag off): install the base through the real path.
    let client = Arc::new(AlwaysFailClient {
        class: RefreshFailureClass::Network,
        calls: AtomicUsize::new(0),
    });
    let (dir_a, mut a) = controller_with_client(client.clone());
    let head = super::super::super::delta_transport::observe_authority_act_head(&hosted, "route-1")
        .await
        .unwrap();
    a.runtime.origin_database_id = head.head().origin_database_id().into();
    a.observed = crate::standby::generation_store::tests::observed();
    a.store = GenerationStore::open(
        &a.runtime.replica_root,
        "route-1",
        Some(a.runtime.origin_database_id.clone()),
    )
    .unwrap();
    let (snapshot, manifest) =
        crate::standby::generation_store::tests::stage(&a.store, &hosted, "measure").await;
    let installed = a
        .store
        .install_staged(&snapshot, &manifest, &a.observed)
        .await
        .unwrap();
    a.delta_enabled = true;
    println!(
        "MEASURE base installed at {:?}: {} bytes",
        started.elapsed(),
        fs::metadata(&installed.snapshot_path).unwrap().len()
    );

    // Controller B (in place): an identical copy of A's replica root.
    let (dir_b, mut b) = controller_with_client(client);
    fs::remove_dir_all(&b.runtime.replica_root).unwrap();
    assert!(std::process::Command::new("cp")
        .arg("-a")
        .arg(&a.runtime.replica_root)
        .arg(&b.runtime.replica_root)
        .status()
        .unwrap()
        .success());
    b.runtime.origin_database_id = a.runtime.origin_database_id.clone();
    b.observed = a.observed.clone();
    b.store = GenerationStore::open(
        &b.runtime.replica_root,
        "route-1",
        Some(b.runtime.origin_database_id.clone()),
    )
    .unwrap();
    b.delta_enabled = true;
    b.config.kernel_in_place_deltas = true;
    let current_b = b.store.current_for_head_probe().unwrap().unwrap();
    let _reader_lock = b.store.hold_serving_reader(&current_b.id).unwrap();
    b.store
        .record_serving_reader(&current_b.id, &b.observed)
        .unwrap();
    let reader =
        crate::db::open_kernel_v2_standby_read_only(current_b.snapshot_path.to_str().unwrap())
            .await
            .unwrap();
    // Controller C (in place, set path): the same copy again, offered
    // version-2 deltas by a hosted whose flag is on.
    let (dir_c, mut c) = controller_with_client(Arc::new(AlwaysFailClient {
        class: RefreshFailureClass::Network,
        calls: AtomicUsize::new(0),
    }));
    fs::remove_dir_all(&c.runtime.replica_root).unwrap();
    assert!(std::process::Command::new("cp")
        .arg("-a")
        .arg(&a.runtime.replica_root)
        .arg(&c.runtime.replica_root)
        .status()
        .unwrap()
        .success());
    c.runtime.origin_database_id = a.runtime.origin_database_id.clone();
    c.observed = a.observed.clone();
    c.store = GenerationStore::open(
        &c.runtime.replica_root,
        "route-1",
        Some(c.runtime.origin_database_id.clone()),
    )
    .unwrap();
    c.delta_enabled = true;
    c.config.kernel_in_place_deltas = true;
    let current_c = c.store.current_for_head_probe().unwrap().unwrap();
    let _reader_lock_c = c.store.hold_serving_reader(&current_c.id).unwrap();
    c.store
        .record_serving_reader(&current_c.id, &c.observed)
        .unwrap();
    println!("MEASURE all controllers ready at {:?}", started.elapsed());

    for round in 1..=rounds {
        // The qualification workload: ten records and one unbound 4 KiB blob
        // (C15A932_DELTA_RECORDS varies the record count).
        for _ in 0..delta_records {
            crate::kernel::create_record_as(&hosted, &admin, crate::events::KERNEL_ROOT_ID)
                .await
                .unwrap();
        }
        let bytes = vec![round as u8; 4096];
        sqlx::query("INSERT INTO kernel_blobs VALUES(?,?,?,NULL)")
            .bind(crate::standby_snapshot::sha256_bytes(&bytes))
            .bind(bytes.as_slice())
            .bind(bytes.len() as i64)
            .execute(hosted.write_pool())
            .await
            .unwrap();
        let before_tables = crate::kernel::projection_dump::dump(&reader).await.unwrap();
        for (label, controller) in [
            ("staged", &mut a),
            ("in_place", &mut b),
            ("set_path", &mut c),
        ] {
            let _ = fs::remove_file(controller.refresh_dir.join("kernel-replay.json"));
            let fault = if label == "set_path" {
                AuthorityFault::AdvertiseV2
            } else {
                AuthorityFault::None
            };
            let (port, server) = serve_authority_act_calls_with(hosted.clone(), 2, fault).await;
            controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
            let begun = std::time::Instant::now();
            let outcome = controller.refresh_delta_only().await.unwrap();
            let wall = begun.elapsed();
            assert!(
                matches!(outcome, StandbyDeltaOutcome::Advanced { .. }),
                "{outcome:?}"
            );
            server.await.unwrap();
            let record = replay_record(controller);
            if label == "in_place" {
                let tables: Vec<String> = record["last_digest_tables"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .take(8)
                    .map(|t| format!("{}:{}rows:{}us", t["table"], t["rows"], t["micros"]))
                    .collect();
                println!("MEASURE round={round} digest_tables={tables:?}");
            }
            println!(
                "MEASURE round={round} path={label} end_to_end_ms={} replay_ms={} rest_ms={} set_path={} phases={}",
                wall.as_millis(),
                record["last_wall_millis"],
                record["last_rest_millis"],
                record["last_set_path"],
                record["last_phases"]
            );
            if label == "set_path" {
                println!(
                    "MEASURE round={round} set_path_report={}",
                    record["set_path"]
                );
            }
        }
        // Which projection tables this delta actually changed, and what each
        // costs to digest (rows, microseconds), slowest first.
        let after_tables = crate::kernel::projection_dump::dump(&reader).await.unwrap();
        let touched: Vec<String> = after_tables
            .tables
            .iter()
            .filter(|table| {
                before_tables
                    .tables
                    .iter()
                    .find(|old| old.name == table.name)
                    .is_none_or(|old| old.sha256 != table.sha256)
            })
            .map(|table| format!("{}(+{})", table.name, table.rows))
            .collect();
        println!("MEASURE round={round} touched_tables={touched:?}");
        // The serving reader on B follows without being reopened.
        assert_eq!(read_state(&reader).await, read_state(&hosted).await);
    }
    // What `derived_digest` and `fixed_digest` cost on this base: the design
    // flags that the former grows with the number of records. Each runs twice
    // per apply (the prior-state check and the receipt).
    {
        use crate::standby::generation_store::kernel_in_place::{derived_digest, fixed_digest};
        let mut conn = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&current_c.snapshot_path)
                .read_only(true),
        )
        .await
        .unwrap();
        let heads: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_event_heads")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        let started = std::time::Instant::now();
        derived_digest(&mut conn).await.unwrap();
        let derived = started.elapsed();
        let started = std::time::Instant::now();
        fixed_digest(&mut conn).await.unwrap();
        println!(
            "MEASURE derived_digest_ms={:.2} fixed_digest_ms={:.2} content_event_heads_rows={heads}",
            derived.as_secs_f64() * 1000.0,
            started.elapsed().as_secs_f64() * 1000.0
        );
        conn.close().await.unwrap();
    }
    // G4: the required audit's duration on this base, alone and while the
    // writer keeps applying deltas, and how far the WAL grows meanwhile (the
    // audit's open read snapshot pins the WAL against checkpoints).
    {
        use crate::standby::generation_store::kernel_in_place::audit::AuditResult;
        let wal = {
            let mut path = current_c.snapshot_path.clone().into_os_string();
            path.push("-wal");
            std::path::PathBuf::from(path)
        };
        let wal_bytes = || fs::metadata(&wal).map_or(0, |m| m.len());
        c.store.set_audit_interval(Some(Duration::from_secs(900)));
        let started = std::time::Instant::now();
        let alone = c
            .store
            .run_required_audit(&current_c, &c.observed)
            .await
            .unwrap();
        println!(
            "MEASURE G4 audit_alone_ms={} result={alone:?} wal_bytes_after={}",
            started.elapsed().as_millis(),
            wal_bytes()
        );
        assert_eq!(alone, AuditResult::Verified);
        // Under write load: refreshes of 128 records each, while audits run
        // back to back, sampling the WAL every 20 ms.
        let refreshes = 6_usize;
        let (port, server) = serve_authority_act_calls_with(
            hosted.clone(),
            2 * refreshes,
            AuthorityFault::AdvertiseV2,
        )
        .await;
        c.config.hosted_origin = format!("http://127.0.0.1:{port}");
        let done = std::sync::atomic::AtomicBool::new(false);
        let load = async {
            for _ in 0..refreshes {
                for _ in 0..128 {
                    crate::kernel::create_record_as(&hosted, &admin, crate::events::KERNEL_ROOT_ID)
                        .await
                        .unwrap();
                }
                let _ = fs::remove_file(c.refresh_dir.join("kernel-replay.json"));
                let outcome = c.refresh_delta_only().await.unwrap();
                assert!(
                    matches!(outcome, StandbyDeltaOutcome::Advanced { .. }),
                    "{outcome:?}"
                );
            }
            done.store(true, std::sync::atomic::Ordering::SeqCst);
        };
        let audits = async {
            let mut durations = Vec::new();
            while !done.load(std::sync::atomic::Ordering::SeqCst) {
                let started = std::time::Instant::now();
                let result = c.store.run_required_audit(&current_c, &c.observed).await;
                durations.push((started.elapsed().as_millis(), format!("{result:?}")));
            }
            durations
        };
        let sampler = async {
            let mut peak = 0_u64;
            while !done.load(std::sync::atomic::Ordering::SeqCst) {
                peak = peak.max(wal_bytes());
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            peak
        };
        let ((), durations, peak) = tokio::join!(load, audits, sampler);
        server.await.unwrap();
        println!(
            "MEASURE G4 audits_under_load={durations:?} wal_peak_bytes={peak} journal_size_limit_bytes=67108864 four_times_limit_bytes=268435456"
        );
    }
    // What the removed per-delta whole-database foreign-key scan cost.
    let started = std::time::Instant::now();
    let violated: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)")
            .fetch_one(reader.pool())
            .await
            .unwrap();
    assert!(!violated);
    println!("MEASURE fk_scan_ms={}", started.elapsed().as_millis());
    // Startup, rebinding and audit pay for the full check, not the apply.
    let started = std::time::Instant::now();
    b.store
        .check_in_place_integrity(&current_b, IntegrityDepth::Full)
        .await
        .unwrap();
    println!("MEASURE full_check_ms={}", started.elapsed().as_millis());
    let mut next = b.observed.clone();
    next.source_sha = "8".repeat(40);
    next.artifact_sha256 = "7".repeat(64);
    let started = std::time::Instant::now();
    b.store
        .ensure_consumer_binding(&current_b.id, &next)
        .await
        .unwrap();
    println!("MEASURE rebinding_ms={}", started.elapsed().as_millis());
    reader.close().await;
    hosted.close().await;
    drop((dir_a, dir_b, dir_c, scratch));
}

#[tokio::test]
async fn a_stamp_that_cannot_be_read_is_never_treated_as_unchanged() {
    use crate::standby::stable_read::{stable, StableReadError};
    let s = setup().await;
    // Before: the pool is gone, so the first stamp fails and nothing runs.
    let gone = s.reader().await;
    gone.close().await;
    let ran = AtomicUsize::new(0);
    let result = stable(&gone, || async {
        ran.fetch_add(1, Ordering::SeqCst);
        1
    })
    .await;
    assert!(matches!(result, Err(StableReadError::Unstamped(_))));
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    // After: the first stamp reads, the operation (standing for a read across
    // a commit) loses the pool, and the final stamp fails: not served.
    let db = s.reader().await;
    let result = stable(&db, || async {
        db.close().await;
        7
    })
    .await;
    assert!(matches!(result, Err(StableReadError::Unstamped(_))));
    // A copy never advanced in place stamps successfully (ordinal -1); only
    // that one condition is tolerated.
    let fresh = s.reader().await;
    assert_eq!(
        crate::standby::stable_read::version_stamp(&fresh)
            .await
            .unwrap()
            .1,
        -1
    );
    fresh.close().await;
    s.hosted.close().await;
}

#[tokio::test]
async fn a_first_write_interrupted_after_marking_is_unproved_even_with_matching_coordinates() {
    let mut s = setup().await;
    s.hosted_adds_records(1).await;
    s.controller.kernel_in_place_crash = Some(InPlaceCrash::AfterMarkBeforeBaseReceipt);
    let server = s.serve(1).await;
    assert!(s.refresh().await.is_err());
    server.await.unwrap();
    // Marked advanced, no receipts, database still equal to its checkpoint.
    assert!(s
        .controller
        .store
        .generation_head(&s.current.id)
        .unwrap()
        .unwrap()
        .advanced_in_place());
    assert!(s.full_check().await.is_err());
    assert!(not_serving(
        s.restarted_store()
            .activate_for_startup(&s.controller.observed)
            .await
    ));
    s.forget_rest();
    s.controller.kernel_in_place_crash = None;
    let server = s.serve_calls(1).await;
    let outcome = s.refresh().await.unwrap();
    assert!(
        matches!(outcome, StandbyDeltaOutcome::FullRefreshRequired { .. }),
        "{outcome:?}"
    );
    server.await.unwrap();
    s.hosted.close().await;
}

#[tokio::test]
async fn a_corrupt_projection_is_caught_between_the_base_receipt_and_the_first_delta() {
    let mut s = setup().await;
    s.hosted_adds_records(1).await;
    s.controller.kernel_in_place_crash = Some(InPlaceCrash::AfterBaseReceipt);
    let server = s.serve(1).await;
    assert!(s.refresh().await.is_err());
    server.await.unwrap();
    assert_eq!(s.applied().await, 0, "only the base receipt exists");
    // Clean base-only state verifies, and startup serves it.
    s.full_check().await.unwrap();
    s.assert_startup_serves().await;
    // Corrupt the projection without touching any coordinate.
    s.corrupt_projection().await;
    assert!(s.full_check().await.is_err());
    assert!(not_serving(
        s.restarted_store()
            .activate_for_startup(&s.controller.observed)
            .await
    ));
    s.hosted.close().await;
}

#[tokio::test]
async fn a_recheckpoint_refuses_to_launder_a_corrupt_inherited_blob() {
    use crate::standby::generation_store::kernel_in_place::RECHECKPOINT_OVERRIDE;
    let mut s = setup().await;
    let bytes = vec![9_u8; 4096];
    sqlx::query("INSERT INTO kernel_blobs VALUES(?,?,?,NULL)")
        .bind(crate::standby_snapshot::sha256_bytes(&bytes))
        .bind(bytes.as_slice())
        .bind(bytes.len() as i64)
        .execute(s.hosted.write_pool())
        .await
        .unwrap();
    first_in_place_delta(&mut s, 1).await;
    s.corrupt("UPDATE kernel_blobs SET bytes=zeroblob(4096) WHERE size_bytes=4096")
        .await;
    // The tick's cheap check cannot see it; the re-checkpoint must.
    RECHECKPOINT_OVERRIDE.with(|cell| cell.set(Some((1, i64::MAX))));
    let server = s.serve(1).await;
    let outcome = s.refresh().await.unwrap();
    server.abort();
    RECHECKPOINT_OVERRIDE.with(|cell| cell.set(None));
    assert!(
        matches!(outcome, StandbyDeltaOutcome::FullRefreshRequired { .. }),
        "{outcome:?}"
    );
    // Nothing was published, and a hosted whole snapshot is required.
    assert_eq!(
        s.controller
            .store
            .current_for_head_probe()
            .unwrap()
            .unwrap()
            .id,
        s.current.id
    );
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
async fn excluded_tables_are_covered_by_the_receipts() {
    // (damage, caught by the cheap per-tick check too?)
    for (damage, light_catches) in [
        (
            "UPDATE act_cutover SET last_legacy_seq=1 WHERE domain='meta_events'",
            true,
        ),
        (
            "UPDATE content_event_causal_cutover SET last_legacy_local_seq=1",
            true,
        ),
        ("DELETE FROM content_event_heads", false),
        ("UPDATE act_state SET next_act=next_act", false),
    ] {
        let mut s = setup().await;
        first_in_place_delta(&mut s, 1).await;
        s.full_check().await.unwrap();
        if damage.contains("act_state") {
            // A no-op write is not damage: the digest must not flap.
            s.corrupt(damage).await;
            s.full_check().await.unwrap();
            s.hosted.close().await;
            continue;
        }
        s.corrupt(damage).await;
        assert!(s.full_check().await.is_err(), "{damage}");
        assert!(not_serving(
            s.restarted_store()
                .activate_for_startup(&s.controller.observed)
                .await
        ));
        let light = s
            .restarted_store()
            .check_in_place_integrity(&s.current, IntegrityDepth::Light)
            .await;
        assert_eq!(light.is_err(), light_catches, "{damage}");
        s.hosted.close().await;
    }
}

#[tokio::test]
async fn a_recheckpoint_refuses_to_launder_edited_excluded_tables() {
    use crate::standby::generation_store::kernel_in_place::RECHECKPOINT_OVERRIDE;
    let mut s = setup().await;
    first_in_place_delta(&mut s, 1).await;
    s.corrupt("DELETE FROM content_event_heads").await;
    // The tick's cheap check cannot see the head set; the staged
    // pre-verification must.
    RECHECKPOINT_OVERRIDE.with(|cell| cell.set(Some((1, i64::MAX))));
    let server = s.serve(1).await;
    let outcome = s.refresh().await.unwrap();
    server.await.unwrap();
    RECHECKPOINT_OVERRIDE.with(|cell| cell.set(None));
    assert!(
        matches!(outcome, StandbyDeltaOutcome::FullRefreshRequired { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        s.controller
            .store
            .current_for_head_probe()
            .unwrap()
            .unwrap()
            .id,
        s.current.id
    );
    // The cutover rows are caught by the same pre-verification on a copy.
    s.controller.store.require_full_refresh(&s.current).ok();
    let copy = s._directory.path().join("base-copy.db");
    {
        let mut conn = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&s.current.snapshot_path)
                .read_only(true),
        )
        .await
        .unwrap();
        sqlx::query("VACUUM INTO ?")
            .bind(copy.to_string_lossy().as_ref())
            .execute(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();
    }
    assert!(s
        .restarted_store()
        .verify_advanced_copy(&copy, &s.current)
        .await
        .is_err());
    s.hosted.close().await;
}

#[tokio::test]
async fn a_bogus_inherited_row_is_not_certified_by_the_next_delta() {
    let mut s = setup().await;
    first_in_place_delta(&mut s, 1).await;
    // Slip a row into the head set after a successful apply.
    s.corrupt("INSERT INTO content_event_heads(event_id) VALUES ('bogus-head')")
        .await;
    s.hosted_adds_records(1).await;
    s.forget_rest();
    let server = s.serve(1).await;
    let before = read_state(&s.reader().await).await;
    let outcome = s.refresh().await;
    server.abort();
    // The valid delta is refused before any mutation; a whole snapshot is
    // required, the database is untouched and nothing was recorded.
    assert!(
        matches!(outcome, Ok(StandbyDeltaOutcome::FullRefreshRequired { .. })),
        "{outcome:?}"
    );
    assert_eq!(read_state(&s.reader().await).await, before);
    assert_eq!(s.applied().await, 1);
    assert!(s.full_check().await.is_err());
    s.hosted.close().await;
}

#[tokio::test]
async fn a_foreign_key_violation_in_an_untouched_row_is_refused_at_every_full_check() {
    use crate::standby::generation_store::kernel_in_place::{
        prove_advanced_copy, RECHECKPOINT_OVERRIDE,
    };
    let mut s = setup().await;
    first_in_place_delta(&mut s, 1).await;
    s.full_check().await.unwrap();
    // NOTE: the fixture cannot express an orphan that leaves every digest
    // equal: admission refuses a base with a violation, and a local edit
    // changes the projection digest. So the orphan below also changes the
    // projection. The assertions attribute the refusal to the FK step by
    // ordering: it runs before the digest comparisons on the re-checkpoint
    // path, and the error names it.
    s.plant_orphan().await;
    // Startup, rebinding and audit run the foreign-key check once, inside the
    // consistent-copy verification that precedes the receipt check.
    assert!(not_serving(
        s.restarted_store()
            .activate_for_startup(&s.controller.observed)
            .await
    ));
    let copy = s._directory.path().join("orphan-copy.db");
    {
        let mut conn = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&s.current.snapshot_path)
                .read_only(true),
        )
        .await
        .unwrap();
        sqlx::query("VACUUM INTO ?")
            .bind(copy.to_string_lossy().as_ref())
            .execute(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();
    }
    let error = prove_advanced_copy(&copy, &s.current).await.unwrap_err();
    assert!(error.to_string().contains("foreign-key"), "{error}");
    // The per-tick check is O(1) and does not scan; the re-checkpoint's
    // pre-verification of its inherited base does, and refuses.
    RECHECKPOINT_OVERRIDE.with(|cell| cell.set(Some((1, i64::MAX))));
    let server = s.serve(1).await;
    let outcome = s.refresh().await.unwrap();
    server.await.unwrap();
    RECHECKPOINT_OVERRIDE.with(|cell| cell.set(None));
    assert!(
        matches!(outcome, StandbyDeltaOutcome::FullRefreshRequired { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        s.controller
            .store
            .current_for_head_probe()
            .unwrap()
            .unwrap()
            .id,
        s.current.id
    );
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
async fn a_staged_foreign_key_violation_is_caught_at_publication_and_never_served() {
    // Staged path (flag off). The same orphan is in the hosted database and in
    // the local base, so every digest agrees and the fold applies; the
    // violation is only caught by the publication verification.
    let mut s = setup().await;
    s.controller.config.kernel_in_place_deltas = false;
    {
        let dir = s.current.snapshot_path.parent().unwrap();
        set_mode(dir, 0o700).unwrap();
        set_mode(&s.current.snapshot_path, 0o600).unwrap();
        let mut local = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&s.current.snapshot_path)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Delete)
                .foreign_keys(false),
        )
        .await
        .unwrap();
        let mut hosted = s.hosted.write_pool().acquire().await.unwrap();
        for conn in [&mut local, &mut *hosted] {
            sqlx::query("PRAGMA foreign_keys=OFF")
                .execute(&mut *conn)
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO kernel_attachment_blobs VALUES('no-such-record','no-such-blob','{}')",
            )
            .execute(&mut *conn)
            .await
            .unwrap();
        }
        sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&mut *hosted)
            .await
            .unwrap();
        drop(hosted);
        local.close().await.unwrap();
        // Back to the published shape a checkpoint must have.
        set_mode(&s.current.snapshot_path, 0o400).unwrap();
        set_mode(dir, 0o500).unwrap();
    }
    s.hosted_adds_records(1).await;
    let server = s.serve(1).await;
    let outcome = s.refresh().await.unwrap();
    server.await.unwrap();
    // Handled like an apply failure: a whole snapshot is requested (subject to
    // the FULL cooldown), nothing is published or served, and the attempt
    // keeps the one-minute rest, so there is no tight loop.
    assert!(
        matches!(
            outcome,
            StandbyDeltaOutcome::FullRefreshRequired {
                reason: DeltaFallbackClass::IntegrityOrApplyRefusal
            }
        ),
        "{outcome:?}"
    );
    let record = replay_record(&s.controller);
    assert_eq!(record["last_outcome"], "failed");
    assert!(record["last_rest_millis"].as_u64().unwrap() >= 60_000);
    let names = phase_names(&record);
    assert!(names.contains(&"apply_commit".to_owned()), "{names:?}");
    assert!(names.contains(&"prepare_manifest".to_owned()), "{names:?}");
    assert!(!names.contains(&"publish_pointer".to_owned()), "{names:?}");
    assert_eq!(
        s.controller
            .store
            .current_for_head_probe()
            .unwrap()
            .unwrap()
            .id,
        s.current.id
    );
    s.hosted.close().await;
}
mod set_path;
pub(crate) mod trust;
// The gate (`node::pre_read_act`) belongs to the executor prototype.
#[cfg(feature = "mcp-executor-prototype")]
mod audit;
