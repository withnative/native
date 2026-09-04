#![cfg(feature = "turso-tests")]

//! Characterization of Turso 0.7.2 `PRAGMA wal_checkpoint(TRUNCATE)` semantics.
//!
//! This is a tripwire, not an exploration. The "quiesce for copy" seam (task
//! 8bcb06b) is built on the behaviours asserted below, and every one of them
//! is specific to the Turso-local quiescence path asserted below. If Turso
//! changes any of them, this file must fail loudly before a durability claim
//! is made on top of the new behaviour.
//!
//! The three facts that matter:
//!
//! 1. The triple is `(busy, log, checkpointed)`, but **only `busy` is
//!    meaningful**. `log` and `checkpointed` are hardcoded zeros, not frame
//!    counts, so SQLite's `log_frames == checkpointed` test is vacuously true
//!    on Turso and proves nothing.
//! 2. A contended checkpoint reports `busy = 1` with **NULL** counters. The
//!    NULL is load-bearing: a strict `(i64, i64, i64)` decode errors on that
//!    row rather than silently accepting it, which is a second guard.
//! 3. `PRAGMA integrity_check` is unusable as a copy gate in either engine,
//!    because of Turso's engine-native FTS overlay.
//!
//! Deliberately **not** asserted, first observation: on 17 Aug 2026 a live
//! writer issuing ordinary `INSERT` statements was seen to contend with a
//! concurrent checkpoint in exactly the same way an explicit open
//! `BEGIN IMMEDIATE` does — every contended checkpoint returned the same
//! `(1, NULL, NULL)` triple, and no other triple was ever observed. That is not
//! asserted here because demonstrating it requires *winning a race*: the test
//! would have to observe contention, and a loaded or slow CI runner that
//! happens not to interleave would turn a scheduling artifact into a red
//! release lane. The `BEGIN IMMEDIATE` case below proves the same property
//! deterministically, so the suite depends on that one instead.
//!
//! Deliberately **not** asserted, second observation: on 17 Aug 2026 a
//! 115-checkpoint race loop
//! took 24 byte copies while writes and checkpoints contended, and all 24
//! verified with monotonically advancing record counts — no tearing observed.
//! That is an absence of evidence, not a property: 104 of those 115 checkpoints
//! returned `busy = 1` and did nothing, so the main file is mutated only in
//! rare, brief windows and the race was barely exercised. A timing-dependent
//! test asserting "copies are never torn" would be both flaky and a false
//! durability claim, so the observation lives in this comment instead.

use native_ce::mcp::{
    register_builtin_tools, register_surface_tools, Caller, EngineHandle, ToolRegistry,
};
use native_ce::turso_local::{register_turso_local_tools, TursoLocalRuntimeConfig};
use serde_json::json;
use turso::{Connection, Value};

/// A quiesced, successful checkpoint. The zeros in `log`/`checkpointed` are
/// constants, not counts — see
/// `quiesced_checkpoint_counters_are_hardcoded_not_frame_counts`.
fn clean_triple() -> Vec<Vec<Value>> {
    vec![vec![
        Value::Integer(0),
        Value::Integer(0),
        Value::Integer(0),
    ]]
}

/// A contended checkpoint: it did not run, and the counters are NULL.
fn busy_triple() -> Vec<Vec<Value>> {
    vec![vec![Value::Integer(1), Value::Null, Value::Null]]
}

fn column_names() -> Vec<String> {
    ["busy", "log", "checkpointed"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
struct CheckpointResult {
    column_names: Vec<String>,
    column_count: usize,
    rows: Vec<Vec<Value>>,
}

async fn checkpoint_truncate(connection: &Connection) -> CheckpointResult {
    let mut rows = connection
        .query("PRAGMA wal_checkpoint(TRUNCATE)", ())
        .await
        .expect("wal_checkpoint(TRUNCATE) must execute");
    let column_names = rows.column_names();
    let column_count = rows.column_count();
    let mut collected = Vec::new();
    while let Some(row) = rows.next().await.expect("checkpoint row") {
        collected.push(
            (0..row.column_count())
                .map(|index| row.get_value(index).unwrap())
                .collect(),
        );
    }
    CheckpointResult {
        column_names,
        column_count,
        rows: collected,
    }
}

/// Every file name directly inside `directory`, sorted.
fn directory_entries(directory: &std::path::Path) -> Vec<String> {
    let mut entries = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

/// The WAL sidecar Turso keeps beside a database file, named the same way
/// `turso_local::wal_sidecar_path` names it.
fn wal_sidecar(database_path: &std::path::Path) -> std::path::PathBuf {
    let mut sidecar = database_path.as_os_str().to_os_string();
    sidecar.push("-wal");
    std::path::PathBuf::from(sidecar)
}

fn sha256_of(path: &std::path::Path) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(std::fs::read(path).unwrap()))
}

fn file_len(path: &std::path::Path) -> u64 {
    std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)
}

async fn raw_local(path: &std::path::Path) -> (turso::Database, Connection) {
    let database = turso::Builder::new_local(path.to_str().unwrap())
        .experimental_index_method(true)
        .build()
        .await
        .unwrap();
    let connection = database.connect().unwrap();
    (database, connection)
}

// ---------------------------------------------------------------------------
// The result triple
// ---------------------------------------------------------------------------

#[tokio::test]
async fn quiesced_checkpoint_reports_zero_busy_and_truncates_the_wal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("shape.db");
    let wal = directory.path().join("shape.db-wal");
    let (_database, connection) = raw_local(&path).await;

    connection
        .execute(
            "CREATE TABLE probe(id INTEGER PRIMARY KEY, payload TEXT)",
            (),
        )
        .await
        .unwrap();
    for index in 0..256 {
        connection
            .execute(
                "INSERT INTO probe VALUES(?, ?)",
                (index, format!("payload-{index}-{}", "x".repeat(200))),
            )
            .await
            .unwrap();
    }

    let mut journal = connection.query("PRAGMA journal_mode", ()).await.unwrap();
    assert_eq!(
        journal.next().await.unwrap().unwrap().get_value(0).unwrap(),
        Value::Text("wal".to_string()),
        "the characterization below only holds in WAL mode"
    );
    let main_before = file_len(&path);
    assert!(
        file_len(&wal) > 0,
        "256 inserts must leave frames in the WAL to checkpoint"
    );

    let result = checkpoint_truncate(&connection).await;
    assert_eq!(result.column_names, column_names());
    assert_eq!(result.column_count, 3);
    assert_eq!(result.rows, clean_triple());

    // The checkpoint is real even though the counters are not.
    assert_eq!(
        file_len(&wal),
        0,
        "TRUNCATE must leave a zero-length WAL sidecar"
    );
    assert!(
        file_len(&path) > main_before,
        "checkpointed frames must land in the main file"
    );
}

#[tokio::test]
async fn quiesced_checkpoint_counters_are_hardcoded_not_frame_counts() {
    // If `log`/`checkpointed` were frame counts, these three cases could not
    // possibly report the same values: 256 rows to fold, nothing to fold, and a
    // database that has never been written at all. They do. This is why
    // SQLite's `log_frames == checkpointed` assertion must NOT be ported.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("counters.db");
    let (_database, connection) = raw_local(&path).await;
    connection
        .execute(
            "CREATE TABLE probe(id INTEGER PRIMARY KEY, payload TEXT)",
            (),
        )
        .await
        .unwrap();
    for index in 0..256 {
        connection
            .execute("INSERT INTO probe VALUES(?, ?)", (index, "y".repeat(200)))
            .await
            .unwrap();
    }
    let after_writes = checkpoint_truncate(&connection).await;
    let immediate_repeat = checkpoint_truncate(&connection).await;

    let untouched_directory = tempfile::tempdir().unwrap();
    let (_untouched, untouched_connection) =
        raw_local(&untouched_directory.path().join("untouched.db")).await;
    let untouched = checkpoint_truncate(&untouched_connection).await;

    assert_eq!(after_writes.rows, clean_triple());
    assert_eq!(immediate_repeat.rows, after_writes.rows);
    assert_eq!(untouched.rows, after_writes.rows);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn contended_checkpoint_reports_busy_with_null_counters() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("busy.db");
    let (database, writer) = raw_local(&path).await;
    writer
        .execute(
            "CREATE TABLE probe(id INTEGER PRIMARY KEY, payload TEXT)",
            (),
        )
        .await
        .unwrap();
    let checkpointer = database.connect().unwrap();

    // Deterministic contention: an uncommitted write transaction held open on
    // another connection for the whole duration of the checkpoint. The NULLs
    // are the load-bearing part — a strict `(i64, i64, i64)` decode of this row
    // fails outright, so a caller cannot mistake a refused checkpoint for a
    // completed one even if it forgets to test `busy`.
    writer.execute("BEGIN IMMEDIATE", ()).await.unwrap();
    writer
        .execute("INSERT INTO probe VALUES(1, 'held-open')", ())
        .await
        .unwrap();
    let held = checkpoint_truncate(&checkpointer).await;
    assert_eq!(held.column_names, column_names());
    assert_eq!(held.rows, busy_triple());
    assert!(matches!(held.rows[0][1], Value::Null));
    assert!(matches!(held.rows[0][2], Value::Null));
    writer.execute("ROLLBACK", ()).await.unwrap();

    // A checkpoint with no writer in flight, on the same connection pair, is
    // clean — so `busy` genuinely discriminates rather than always being 1.
    assert_eq!(
        checkpoint_truncate(&checkpointer).await.rows,
        clean_triple()
    );
}

// ---------------------------------------------------------------------------
// What a byte copy of the runtime file is worth
// ---------------------------------------------------------------------------

fn config(directory: &std::path::Path, logical_database_id: &str) -> TursoLocalRuntimeConfig {
    TursoLocalRuntimeConfig::from_json(
        &serde_json::to_vec(&json!({
            "format":"native.turso-local-runtime.v1",
            "logical_database_id":logical_database_id,
            "data_directory":directory,
        }))
        .unwrap(),
    )
    .unwrap()
}

fn probe_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    register_turso_local_tools(&mut registry).unwrap();
    registry
}

/// Fixture families for the checkpoint seeds. Record ids must now be canonical
/// v4 UUIDs, so each family owns a hex slot in the id counter field and each
/// seeded record takes a counter inside that slot. The values only have to stay
/// distinct and deterministic; no assertion reads their text.
const FAMILY_LIVE: u16 = 0x001;
const FAMILY_AFTER: u16 = 0x002;
const FAMILY_DEST: u16 = 0x003;
const FAMILY_OWN: u16 = 0x004;
const FAMILY_STOCK: u16 = 0x005;
const FAMILY_TORN: u16 = 0x006;
const FAMILY_INTEGRITY: u16 = 0x007;
const FAMILY_LOAD: u16 = 0x008;
const FAMILY_CHURN: u16 = 0x009;
const FAMILY_ARTIFACT: u16 = 0x00a;

fn checkpoint_record_id(family: u16, index: usize) -> String {
    format!("70250000-0000-4000-8000-003{family:03x}{index:06x}")
}

async fn seed_records(engine: &EngineHandle, family: u16, count: usize) -> Vec<String> {
    let registry = probe_registry();
    let mut ids = Vec::new();
    for index in 0..count {
        let id = checkpoint_record_id(family, index);
        registry
            .call_engine(
                engine.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id": id,
                    "type": "Document",
                    "kind": "note",
                    "name": format!("checkpoint characterization {index}"),
                    "body": "w".repeat(512),
                    "reason": "Seed the checkpoint characterization.",
                }),
            )
            .await
            .unwrap();
        ids.push(id);
    }
    ids
}

fn copy_database_file(source: &std::path::Path, destination: &std::path::Path) {
    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
    std::fs::copy(source, destination).unwrap();
}

/// Every gate the repo already applies to an existing Turso-local file: the
/// stock-SQLite read-only `user_version` preflight (`preflight_existing_runtime`),
/// `TursoLocalRuntimeConfig::open` → `validate_runtime` (schema version,
/// `_native_turso_runtime` profile marker carrying the logical database id,
/// physical overlays, genesis), and logical identity on the seeded record ids.
async fn verify_copy(
    directory: &std::path::Path,
    logical_database_id: &str,
    expected_ids: &[String],
) -> Result<(), String> {
    let copy_config = config(directory, logical_database_id);
    let path = copy_config.database_path();

    let connection = rusqlite::Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("stock sqlite could not open the copy: {error}"))?;
    match connection.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0)) {
        Ok(version) if version == native_ce::CURRENT_ENGINE_SCHEMA_VERSION => {}
        Ok(version) => return Err(format!("preflight user_version = {version}")),
        Err(error) => return Err(format!("preflight failed: {error}")),
    }
    drop(connection);

    let reopened = copy_config
        .open()
        .await
        .map_err(|error| format!("Turso-local gates rejected the copy: {error}"))?;
    let engine = EngineHandle::TursoLocal(reopened.clone());
    let fetched = probe_registry()
        .call_engine(
            engine.clone(),
            Caller::local(),
            "get_record",
            json!({ "ids": expected_ids }),
        )
        .await;
    drop(engine);
    let rendered = serde_json::to_string(
        &fetched.map_err(|error| format!("get_record failed against the copy: {error}"))?,
    )
    .unwrap();
    drop(reopened);
    let missing = expected_ids
        .iter()
        .filter(|id| !rendered.contains(&format!("\"{id}\"")))
        .count();
    if missing != 0 {
        return Err(format!("copy is missing {missing} seeded records"));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_checkpointed_copy_taken_from_a_live_handle_passes_every_runtime_gate() {
    // This exercises the real seam, `TursoLocalDb::copy_quiesced_into`, rather
    // than the second-raw-handle workaround it replaced. The distinction
    // matters: a test that kept opening its own `turso::Builder` handle would
    // keep passing while quietly becoming a test of the bypass.
    let logical = "checkpoint-semantics-live-copy";
    let directory = tempfile::tempdir().unwrap();
    let source_config = config(directory.path(), logical);
    let db = source_config.open().await.unwrap();
    let source_path = source_config.database_path();
    let wal_path = wal_sidecar(&source_path);
    let engine = EngineHandle::TursoLocal(db.clone());
    let ids = seed_records(&engine, FAMILY_LIVE, 16).await;
    assert!(file_len(&wal_path) > 0, "seeding must leave WAL frames");

    // Taken with the production handle still open and still owning the file.
    let copy_root = tempfile::tempdir().unwrap();
    let live = copy_root.path().join("live");
    let receipt = db
        .copy_quiesced_into(&live)
        .await
        .expect("a quiesced copy from a live handle must succeed");

    assert_eq!(
        receipt.database_path,
        config(&live, logical).database_path()
    );
    assert_eq!(receipt.verification.logical_database_id, logical);
    assert_eq!(
        receipt.verification.schema_version,
        native_ce::CURRENT_ENGINE_SCHEMA_VERSION
    );
    assert_eq!(receipt.verification.profile_revision, 4);
    assert!(receipt.verification.byte_len > 0);
    assert!(
        receipt.checkpoint_attempts >= 1,
        "the receipt must record how many checkpoint attempts quiescence needed"
    );
    assert_eq!(
        receipt.verification.sha256,
        sha256_of(&receipt.database_path),
        "the receipt must attest the bytes that are actually on disk"
    );
    assert_eq!(
        file_len(&wal_path),
        0,
        "the seam must leave the source checkpointed"
    );

    // The receipt is not self-certification: re-run the canonical verification
    // independently, and prove the seeded records actually came across.
    let independent = config(&live, logical).verify_copy().await;
    assert!(
        independent.is_ok(),
        "the artifact must verify on its own: {independent:?}"
    );
    let identity = verify_copy(&live, logical, &ids).await;
    assert!(
        identity.is_ok(),
        "the copy must carry the seeded records: {identity:?}"
    );

    // The live runtime is unharmed and still writable afterwards.
    let after = seed_records(&engine, FAMILY_AFTER, 2).await;
    assert_eq!(after.len(), 2);

    drop(engine);
    drop(db);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_seam_refuses_destinations_that_would_endanger_the_live_database() {
    let logical = "checkpoint-semantics-destinations";
    let directory = tempfile::tempdir().unwrap();
    let source_config = config(directory.path(), logical);
    let db = source_config.open().await.unwrap();
    let engine = EngineHandle::TursoLocal(db.clone());
    seed_records(&engine, FAMILY_DEST, 2).await;

    // Into the live data directory: would collide with the running runtime's
    // own file and ownership lock.
    let into_self = db.copy_quiesced_into(directory.path()).await;
    assert_eq!(
        into_self.unwrap_err().to_string(),
        "Turso-local quiesced copy destination must be outside the live data directory"
    );
    // A nested subdirectory of the live data directory is refused for the same
    // reason: sweeping the data directory would sweep the backup with it.
    let nested = directory.path().join("nested");
    let into_nested = db.copy_quiesced_into(&nested).await;
    assert_eq!(
        into_nested.unwrap_err().to_string(),
        "Turso-local quiesced copy destination must be outside the live data directory"
    );

    // Refuses to overwrite an artifact that is already there.
    let copy_root = tempfile::tempdir().unwrap();
    let once = copy_root.path().join("once");
    db.copy_quiesced_into(&once).await.unwrap();
    let twice = db.copy_quiesced_into(&once).await;
    assert!(
        twice
            .unwrap_err()
            .to_string()
            .starts_with("refusing to overwrite "),
        "a second copy must not clobber the first"
    );

    drop(engine);
    drop(db);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_seam_preserves_exclusive_ownership_of_both_files() {
    let logical = "checkpoint-semantics-ownership";
    let directory = tempfile::tempdir().unwrap();
    let source_config = config(directory.path(), logical);
    let db = source_config.open().await.unwrap();
    let engine = EngineHandle::TursoLocal(db.clone());
    seed_records(&engine, FAMILY_OWN, 4).await;

    let copy_root = tempfile::tempdir().unwrap();
    let backup = copy_root.path().join("backup");
    db.copy_quiesced_into(&backup).await.unwrap();

    // The live runtime still owns its file: a second opener fails closed, and
    // taking a copy did not release or transfer that ownership.
    let second_owner = source_config.open().await;
    assert_eq!(
        second_owner.unwrap_err().to_string(),
        "Turso-local database is already owned by another runtime process"
    );

    // Verification released the copy's lock, so the artifact is openable — but
    // only once at a time, exactly like the original.
    let restored = config(&backup, logical).open().await.unwrap();
    let contended = config(&backup, logical).open().await;
    assert_eq!(
        contended.unwrap_err().to_string(),
        "Turso-local database is already owned by another runtime process"
    );
    drop(restored);

    drop(engine);
    drop(db);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_verified_copy_is_refused_as_a_stock_sqlite_ownership_artifact() {
    // Acceptance: nothing may advertise a Turso file as stock SQLite unless the
    // profile's quiesced-and-unencrypted clause is satisfied, enforced by a
    // check rather than by prose.
    //
    // The measured answer is that quiesced-and-unencrypted is necessary but not
    // sufficient. The file carries the stock SQLite header and its
    // `user_version` is readable, but stock SQLite reports `DatabaseCorrupt`
    // when preparing *any* schema-touching statement, because it cannot parse
    // the engine-native FTS entries in `sqlite_schema`. So the artifact is a
    // valid Turso-local restore source and is *not* a stock SQLite file, and
    // the API says so from a live stock-SQLite execution rather than from the
    // profile text.
    let logical = "checkpoint-semantics-stock-refusal";
    let directory = tempfile::tempdir().unwrap();
    let source_config = config(directory.path(), logical);
    let db = source_config.open().await.unwrap();
    let engine = EngineHandle::TursoLocal(db.clone());
    seed_records(&engine, FAMILY_STOCK, 4).await;

    let copy_root = tempfile::tempdir().unwrap();
    let backup = copy_root.path().join("backup");
    let receipt = db.copy_quiesced_into(&backup).await.unwrap();

    let refusal = receipt
        .verification
        .stock_sqlite_ownership_refusal
        .as_deref()
        .expect("a Turso runtime file must be refused as a stock SQLite artifact");
    assert!(
        refusal.contains("stock sqlite cannot read this file's schema"),
        "unexpected refusal: {refusal}"
    );
    assert!(
        refusal.contains("__turso_internal_fts"),
        "the refusal must name the blocking object: {refusal}"
    );

    // The header is present and the header-level preflight works, which is
    // exactly why a prose-only claim would have looked satisfied.
    let bytes = std::fs::read(&receipt.database_path).unwrap();
    assert_eq!(&bytes[..16], b"SQLite format 3\0");

    drop(engine);
    drop(db);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verification_refuses_to_fabricate_the_artifact_it_is_verifying() {
    // `open` treats a missing or zero-length file as a fresh database and
    // installs a schema into it. Verification that reopened without pre-checks
    // would therefore "verify" a backup that was never taken.
    let logical = "checkpoint-semantics-fabrication";
    let empty = tempfile::tempdir().unwrap();
    let missing = config(empty.path(), logical).verify_copy().await;
    assert_eq!(
        missing.unwrap_err().to_string(),
        "copied Turso-local database is not readable"
    );
    assert!(
        !config(empty.path(), logical).database_path().exists(),
        "a failed verification must not create a database"
    );

    let zero_length = tempfile::tempdir().unwrap();
    let path = config(zero_length.path(), logical).database_path();
    std::fs::write(&path, b"").unwrap();
    let empty_file = config(zero_length.path(), logical).verify_copy().await;
    assert_eq!(
        empty_file.unwrap_err().to_string(),
        "copied Turso-local database is empty"
    );

    let garbage = tempfile::tempdir().unwrap();
    let path = config(garbage.path(), logical).database_path();
    std::fs::write(&path, b"not a database at all, but long enough").unwrap();
    let not_sqlite = config(garbage.path(), logical).verify_copy().await;
    assert_eq!(
        not_sqlite.unwrap_err().to_string(),
        "copied Turso-local database does not carry the SQLite file header"
    );

    // A real SQLite database that is not a Turso-local runtime is refused at
    // the preflight, and the failure path must not leave its scratch
    // directory — or anything else — behind next to the artifact.
    let foreign = tempfile::tempdir().unwrap();
    let foreign_config = config(foreign.path(), logical);
    let foreign_path = foreign_config.database_path();
    let plain = rusqlite::Connection::open(&foreign_path).unwrap();
    plain
        .execute("CREATE TABLE unrelated(id INTEGER PRIMARY KEY)", ())
        .unwrap();
    drop(plain);
    let name = foreign_path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let before = directory_entries(foreign.path());
    let refused = foreign_config.verify_copy().await;
    assert_eq!(
        refused.unwrap_err().to_string(),
        format!(
            "Turso-local schema version 0 is not supported (required current version {})",
            native_ce::CURRENT_ENGINE_SCHEMA_VERSION
        )
    );
    assert!(before.contains(&name));
    assert_eq!(
        directory_entries(foreign.path()),
        before,
        "a failed verification must leave no scratch directory behind"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_uncheckpointed_live_copy_fails_closed_at_user_version_zero() {
    // Without a checkpoint the difference is not merely detectable: the copy is
    // rejected by the very first gate, because even the schema install lives
    // only in the WAL and the main file still reads `user_version = 0`. This is
    // the property that makes a checkpoint the load-bearing step rather than an
    // optimisation.
    let logical = "checkpoint-semantics-uncheckpointed";
    let directory = tempfile::tempdir().unwrap();
    let source_config = config(directory.path(), logical);
    let db = source_config.open().await.unwrap();
    let engine = EngineHandle::TursoLocal(db.clone());
    let ids = seed_records(&engine, FAMILY_TORN, 8).await;

    let copy_root = tempfile::tempdir().unwrap();
    let destination = copy_root.path().join("uncheckpointed");
    copy_database_file(
        &source_config.database_path(),
        &config(&destination, logical).database_path(),
    );
    let verdict = verify_copy(&destination, logical, &ids).await;
    assert_eq!(
        verdict,
        Err("preflight user_version = 0".to_string()),
        "an un-checkpointed live copy must fail closed at the preflight"
    );

    drop(engine);
    drop(db);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integrity_check_is_not_a_usable_gate_for_a_turso_runtime_file() {
    // Recorded so nobody rebuilds the SQLite drill's final `integrity_check ==
    // "ok"` step on Turso. This is measured on a *pristine* file: a clean,
    // checkpointed database with the handle already dropped. Both engines
    // report a problem, and neither problem is real — Turso's engine-native FTS
    // overlay is simply not describable in stock SQLite's schema grammar, and
    // Turso's own checker miscounts its entries.
    let logical = "checkpoint-semantics-integrity";
    let directory = tempfile::tempdir().unwrap();
    let source_config = config(directory.path(), logical);
    let db = source_config.open().await.unwrap();
    let engine = EngineHandle::TursoLocal(db.clone());
    seed_records(&engine, FAMILY_INTEGRITY, 4).await;
    let path = source_config.database_path();
    drop(engine);
    drop(db);

    let (sidecar, sidecar_connection) = raw_local(&path).await;
    assert_eq!(
        checkpoint_truncate(&sidecar_connection).await.rows,
        clean_triple()
    );

    let mut rows = sidecar_connection
        .query("PRAGMA integrity_check", ())
        .await
        .unwrap();
    let mut turso_lines = Vec::new();
    while let Some(row) = rows.next().await.unwrap() {
        turso_lines.push(match row.get_value(0).unwrap() {
            Value::Text(text) => text,
            other => panic!("unexpected integrity_check value {other:?}"),
        });
    }
    drop(rows);
    drop(sidecar_connection);
    drop(sidecar);
    assert!(
        !turso_lines.is_empty()
            && turso_lines
                .iter()
                .all(|line| line.contains("wrong # of entries in index __turso_internal_fts")),
        "turso's own integrity_check is not 'ok' on a pristine runtime file: {turso_lines:?}"
    );

    let stock = rusqlite::Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let stock_error = stock
        .query_row("PRAGMA integrity_check", (), |row| row.get::<_, String>(0))
        .expect_err("stock sqlite cannot parse the turso FTS overlay");
    let stock_error = stock_error.to_string();
    assert!(
        stock_error.contains("malformed database schema")
            && stock_error.contains("__turso_internal_fts"),
        "unexpected stock-sqlite integrity_check failure: {stock_error}"
    );

    // The header-level preflight the repo actually uses is unaffected.
    let version: i64 = stock
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, native_ce::CURRENT_ENGINE_SCHEMA_VERSION);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_seam_keeps_taking_good_copies_while_writers_are_running() {
    // The property under test is the *absence* of contention, which the write
    // gate guarantees, not the presence of it — so unlike a test that has to
    // win a race to see anything, this one is decisive. Every domain write
    // reaches the file through `run_db_write`/`run_db_write_with_disposition`,
    // both of which hold the same gate this seam holds. If a copy ever fails
    // closed here, the gate is not the sufficient seam we believe it is, and a
    // red lane is the correct outcome rather than a scheduling artifact.
    let logical = "checkpoint-semantics-under-load";
    let directory = tempfile::tempdir().unwrap();
    let source_config = config(directory.path(), logical);
    let db = source_config.open().await.unwrap();
    let engine = EngineHandle::TursoLocal(db.clone());
    let seeded = seed_records(&engine, FAMILY_LOAD, 4).await;

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer_stop = stop.clone();
    let writer_engine = engine.clone();
    let writers = tokio::spawn(async move {
        let registry = probe_registry();
        let mut index = 0usize;
        while !writer_stop.load(std::sync::atomic::Ordering::Relaxed) {
            let _ = registry
                .call_engine(
                    writer_engine.clone(),
                    Caller::local(),
                    "create_record",
                    json!({
                        "id": checkpoint_record_id(FAMILY_CHURN, index),
                        "type": "Document",
                        "kind": "note",
                        "name": format!("churn {index}"),
                        "body": "q".repeat(4096),
                        "reason": "Churn the database during a quiesced copy.",
                    }),
                )
                .await;
            index += 1;
        }
        index
    });

    let copy_root = tempfile::tempdir().unwrap();
    let mut byte_lens = Vec::new();
    let mut attempts: Vec<u32> = Vec::new();
    for attempt in 0..6 {
        let destination = copy_root.path().join(format!("load-{attempt}"));
        let receipt = db
            .copy_quiesced_into(&destination)
            .await
            .unwrap_or_else(|error| panic!("copy {attempt} failed while writers ran: {error}"));
        byte_lens.push(receipt.verification.byte_len);
        attempts.push(receipt.checkpoint_attempts);
        // Each artifact carries at least the records that were already settled
        // before the writers started.
        let identity = verify_copy(&destination, logical, &seeded).await;
        assert!(identity.is_ok(), "copy {attempt}: {identity:?}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let churned = writers.await.unwrap();
    assert!(
        churned > 0,
        "the writers must actually have run for this to mean anything"
    );
    assert!(byte_lens.iter().all(|len| *len > 0));
    assert!(
        attempts.iter().all(|count| *count >= 1),
        "every copy records its checkpoint attempts: {attempts:?}"
    );

    drop(engine);
    drop(db);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verification_leaves_the_artifact_byte_for_byte_untouched() {
    // A drill has to record the digest of the artifact it verified and keep
    // those exact bytes. That is only possible because verification runs
    // against a discarded duplicate: opening the artifact itself would write an
    // ownership lock, a WAL and a shared-memory sidecar beside it, so the
    // digest would attest either unverified bytes or bytes no restore sees.
    let logical = "checkpoint-semantics-artifact-state";
    let directory = tempfile::tempdir().unwrap();
    let source_config = config(directory.path(), logical);
    let db = source_config.open().await.unwrap();
    let engine = EngineHandle::TursoLocal(db.clone());
    let ids = seed_records(&engine, FAMILY_ARTIFACT, 6).await;

    let copy_root = tempfile::tempdir().unwrap();
    let backup = copy_root.path().join("backup");
    let receipt = db.copy_quiesced_into(&backup).await.unwrap();
    drop(engine);
    drop(db);

    let artifact = receipt.database_path.clone();
    let name = artifact.file_name().unwrap().to_string_lossy().into_owned();

    // The destination holds the database and nothing else: no lock, no WAL, no
    // shm, and no leftover scratch directory from verification.
    assert_eq!(
        directory_entries(&backup),
        vec![name.clone()],
        "a verified artifact directory must contain only the database"
    );
    assert_eq!(
        std::fs::metadata(&artifact).unwrap().len(),
        receipt.verification.byte_len
    );

    // The recorded digest is the digest of the bytes on disk, and re-verifying
    // does not disturb them.
    let digest = sha256_of(&artifact);
    assert_eq!(receipt.verification.sha256, digest);
    let again = config(&backup, logical).verify_copy().await.unwrap();
    assert_eq!(again.sha256, digest, "re-verification must agree");
    assert_eq!(
        sha256_of(&artifact),
        digest,
        "verification must leave the artifact byte-for-byte identical"
    );
    assert_eq!(
        directory_entries(&backup),
        vec![name],
        "re-verification must not leave scratch state behind"
    );

    // Self-containment the hard way: the database file alone, moved to an empty
    // directory, is still a complete and verifiable artifact.
    let alone = copy_root.path().join("alone");
    let alone_config = config(&alone, logical);
    std::fs::create_dir_all(&alone).unwrap();
    std::fs::copy(&artifact, alone_config.database_path()).unwrap();
    let verdict = alone_config.verify_copy().await;
    assert!(
        verdict.is_ok(),
        "the database file alone must be a complete artifact: {verdict:?}"
    );
    assert_eq!(verdict.unwrap().sha256, digest);
    let identity = verify_copy(&alone, logical, &ids).await;
    assert!(identity.is_ok(), "{identity:?}");
}
