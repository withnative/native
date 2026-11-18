use super::*;
use crate::mcp::{Caller, ToolRegistry};
use sqlx::Connection;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

#[derive(Default)]
struct Pause {
    entered: Notify,
    release: Notify,
    first: AtomicBool,
    abort: AtomicBool,
}
tokio::task_local! { static PAUSE: Arc<Pause>; }
pub(super) async fn checkpoint() -> Result<()> {
    let pause = PAUSE.try_with(Arc::clone).ok();
    if let Some(pause) = pause {
        if !pause.first.swap(true, Ordering::SeqCst) {
            pause.entered.notify_one();
            pause.release.notified().await;
            if pause.abort.load(Ordering::SeqCst) {
                return Err(Error::engine("test transaction rollback"));
            }
        }
    }
    Ok(())
}
fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    registry
}
fn command() -> Value {
    json!({"id":Uuid::new_v4().to_string(),"type":"Document","kind":"note","name":"held", "body":"original draft", "idempotency_key":"held-key", "reason":"held test", "sources":[]})
}
async fn verified(db: &Db, operation: &str, args: &Value) -> VerifiedHeldCommand {
    // Isolated test fixture only; no production construction or authentication.
    {
        VerifiedHeldCommand::for_test_command(
            &crate::identity::database_id(db).await.unwrap(),
            "local",
            operation,
            args,
            None,
            None,
        )
        .unwrap()
    }
}
async fn cancel(db: &Db, verified: &VerifiedHeldCommand) -> Result<StagedCancellation> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let staged = cancel_in(&mut tx, verified).await?;
    tx.commit().await?;
    Ok(staged)
}
async fn invoke(db: &Db, op: &str, args: Value) -> Result<Value> {
    registry().call(db.clone(), Caller::local(), op, args).await
}
async fn content_count(db: &Db, id: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM content_events WHERE record_id=?")
        .bind(id)
        .fetch_one(db.write_pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn cancellation_commit_fences_actual_create_and_changed_meaning_without_effects() {
    let db = crate::create_database(":memory:").await.unwrap();
    let args = command();
    let v = verified(&db, "create_record", &args).await;
    let first = cancel(&db, &v).await.unwrap();
    assert_eq!(cancel(&db, &v).await.unwrap(), first);
    assert!(matches!(first, StagedCancellation::Cancelled { .. }));
    assert!(invoke(&db, "create_record", args.clone())
        .await
        .unwrap_err()
        .to_string()
        .contains(CANCELLED));
    let mut changed = args.clone();
    changed["body"] = json!("changed");
    assert!(invoke(&db, "create_record", changed)
        .await
        .unwrap_err()
        .to_string()
        .contains(MISMATCH));
    // Deliberately skip keyed lookup to prove the output-attestation backstop
    // also rejects an ordinary non-interaction dispatch and rolls effects back.
    let caller = Caller::local();
    ProvenanceDispatch::from_caller(&caller, "create_record", &args, None)
        .scope(async {
            let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
            let draft = reserve_action_attestation().unwrap();
            let event = crate::store::append_in(
                &db,
                &mut tx,
                crate::store::AppendSpec {
                    record_id: args["id"].as_str().unwrap().into(),
                    event_type: "record.created".into(),
                    payload: json!({"type":"Document","kind":"note","name":"bypass"}),
                    actor: Some("local".into()),
                },
                &mut crate::act::ActAllocation::new(),
            )
            .await
            .unwrap();
            assert!(issue_action_attestation_in(&mut tx, draft, &[event])
                .await
                .unwrap_err()
                .to_string()
                .contains(CANCELLED));
            tx.rollback().await.unwrap();
        })
        .await;
    assert_eq!(content_count(&db, args["id"].as_str().unwrap()).await, 0);
    assert_eq!(content_count(&db, args["id"].as_str().unwrap()).await, 0);
    assert!(crate::provenance::state_violations(&db)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn actual_writer_transaction_wins_then_cancel_reports_saved_and_replay_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let db = crate::create_database(dir.path().join("writer.db").to_str().unwrap())
        .await
        .unwrap();
    let args = command();
    let v = verified(&db, "create_record", &args).await;
    let pause = Arc::new(Pause::default());
    let worker = {
        let db = db.clone();
        let args = args.clone();
        let p = pause.clone();
        tokio::spawn(PAUSE.scope(p, async move { invoke(&db, "create_record", args).await }))
    };
    pause.entered.notified().await; // actual keyed lookup inside handler BEGIN IMMEDIATE
    let (began, waiting) = tokio::sync::oneshot::channel();
    let cancelling = {
        let db = db.clone();
        tokio::spawn(async move {
            began.send(()).unwrap();
            cancel(&db, &v).await
        })
    };
    waiting.await.unwrap();
    pause.release.notify_one();
    let receipt = worker.await.unwrap().unwrap();
    assert!(matches!(
        cancelling.await.unwrap().unwrap(),
        StagedCancellation::AlreadySaved { .. }
    ));
    let replay = invoke(&db, "create_record", args.clone()).await.unwrap();
    assert_eq!(receipt["id"], replay["id"]);
    assert_eq!(content_count(&db, args["id"].as_str().unwrap()).await, 1);
}

#[tokio::test]
async fn actual_writer_rollback_lets_waiting_cancellation_win() {
    let dir = tempfile::tempdir().unwrap();
    let db = crate::create_database(dir.path().join("rollback.db").to_str().unwrap())
        .await
        .unwrap();
    let args = command();
    let v = verified(&db, "create_record", &args).await;
    let pause = Arc::new(Pause::default());
    pause.abort.store(true, Ordering::SeqCst);
    let worker = {
        let db = db.clone();
        let args = args.clone();
        tokio::spawn(PAUSE.scope(pause.clone(), async move {
            invoke(&db, "create_record", args).await
        }))
    };
    pause.entered.notified().await;
    let (began, waiting) = tokio::sync::oneshot::channel();
    let cancelling = {
        let db = db.clone();
        tokio::spawn(async move {
            began.send(()).unwrap();
            cancel(&db, &v).await
        })
    };
    waiting.await.unwrap();
    pause.release.notify_one();
    assert!(worker.await.unwrap().is_err());
    assert!(matches!(
        cancelling.await.unwrap().unwrap(),
        StagedCancellation::Cancelled { .. }
    ));
    assert!(invoke(&db, "create_record", args.clone())
        .await
        .unwrap_err()
        .to_string()
        .contains(CANCELLED));
    assert_eq!(content_count(&db, args["id"].as_str().unwrap()).await, 0);
}

#[tokio::test]
async fn cancellation_writer_wins_or_rolls_back_before_actual_delayed_command() {
    for commit in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::create_database(dir.path().join("cancel-first.db").to_str().unwrap())
            .await
            .unwrap();
        let args = command();
        let v = verified(&db, "create_record", &args).await;
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        assert!(matches!(
            cancel_in(&mut tx, &v).await.unwrap(),
            StagedCancellation::Cancelled { .. }
        ));
        let (began, waiting) = tokio::sync::oneshot::channel();
        let worker = {
            let db = db.clone();
            let args = args.clone();
            tokio::spawn(async move {
                began.send(()).unwrap();
                invoke(&db, "create_record", args).await
            })
        };
        waiting.await.unwrap();
        if commit {
            tx.commit().await.unwrap();
        } else {
            tx.rollback().await.unwrap();
        }
        let answer = worker.await.unwrap();
        assert_eq!(answer.is_err(), commit);
        if commit {
            assert!(answer.unwrap_err().to_string().contains(CANCELLED));
        }
        assert_eq!(
            content_count(&db, args["id"].as_str().unwrap()).await,
            i64::from(!commit)
        );
    }
}

#[tokio::test]
async fn append_guard_and_issued_noop_attestation_are_both_fenced() {
    let db = crate::create_database(":memory:").await.unwrap();
    let create = command();
    let id = invoke(&db, "create_record", create).await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let append =
        json!({"id":id,"body_append":" held", "idempotency_key":"append-key", "reason":"append"});
    let v = verified(&db, "update_record", &append).await;
    let _committed = cancel(&db, &v).await.unwrap();
    assert!(invoke(&db, "update_record", append.clone())
        .await
        .unwrap_err()
        .to_string()
        .contains(CANCELLED));
    assert_eq!(content_count(&db, &id).await, 1);
    // Defence at issuance also covers a path which skipped the keyed lookup.
    let caller = Caller::local();
    let dispatch = ProvenanceDispatch::from_caller(&caller, "update_record", &append, None);
    dispatch
        .scope(async {
            let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
            let result = crate::mcp::tools::keyed_replay::anchor_noop_in(&mut tx).await;
            assert!(result.unwrap_err().to_string().contains(CANCELLED));
            tx.rollback().await.unwrap();
        })
        .await;
}

#[tokio::test]
async fn identity_intent_app_and_origin_mismatches_do_not_disclose_saved_or_cancelled() {
    let db = crate::create_database(":memory:").await.unwrap();
    let args = command();
    let original = verified(&db, "create_record", &args).await;
    let _committed = cancel(&db, &original).await.unwrap();
    for field in ["intent", "app", "origin"] {
        let mut e = original.0.clone();
        match field {
            "intent" => e.intent_digest = Some(digest_json(&json!("other"))),
            "app" => e.app_context_digest = digest_json(&json!("other")),
            _ => e.origin_db_id = crate::identity::mint_database_id(),
        };
        assert_eq!(
            cancel(&db, &VerifiedHeldCommand(e))
                .await
                .unwrap_err()
                .to_string(),
            MISMATCH
        );
    }
    // A different principal cannot inspect the original outcome. It addresses
    // a distinct identity and receives no original event/attestation handle.
    let mut e = original.0.clone();
    e.principal = "other".into();
    let other = cancel(&db, &VerifiedHeldCommand(e)).await.unwrap();
    assert_ne!(other, cancel(&db, &original).await.unwrap());
    // Canonically applied path has the same comparison and no receipt leak.
    let mut fresh = command();
    fresh["idempotency_key"] = json!("applied-key");
    invoke(&db, "create_record", fresh.clone()).await.unwrap();
    let mut e = verified(&db, "create_record", &fresh).await.0;
    e.app_context_digest = digest_json(&json!("wrong-app"));
    assert_eq!(
        cancel(&db, &VerifiedHeldCommand(e))
            .await
            .unwrap_err()
            .to_string(),
        MISMATCH
    );
}

#[tokio::test]
async fn lost_reply_restart_and_sqlite_backup_retain_fence_but_foreign_import_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.db");
    let db = crate::create_database(path.to_str().unwrap())
        .await
        .unwrap();
    let args = command();
    let v = verified(&db, "create_record", &args).await;
    let receipt = cancel(&db, &v).await.unwrap(); // discard this acknowledgement, as after a lost reply
    let backup = dir.path().join("backup.db");
    sqlx::query("VACUUM INTO ?")
        .bind(backup.to_str().unwrap())
        .execute(db.write_pool())
        .await
        .unwrap();
    let bundle = crate::interchange::export_canonical_interchange(&db)
        .await
        .unwrap();
    db.close().await;
    for path in [&path, &backup] {
        let reopened = crate::open_existing_database(path.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(cancel(&reopened, &v).await.unwrap(), receipt);
        assert!(invoke(&reopened, "create_record", args.clone())
            .await
            .unwrap_err()
            .to_string()
            .contains(CANCELLED));
        assert!(crate::provenance::state_violations(&reopened)
            .await
            .unwrap()
            .is_empty());
        reopened.close().await;
    }
    let imported = crate::interchange::import_canonical_interchange(
        &bundle,
        &dir.path().join("foreign.db"),
        crate::interchange::ImportContinuity::ForeignBoundary,
    )
    .await
    .unwrap();
    let anchors: i64 =
        sqlx::query_scalar("SELECT count(*) FROM provenance_local_command_cancellations")
            .fetch_one(imported.write_pool())
            .await
            .unwrap();
    assert_eq!(anchors, 0);
    let evidence: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM control_events WHERE type='held_command.cancelled.v1'",
    )
    .fetch_one(imported.write_pool())
    .await
    .unwrap();
    assert_eq!(evidence, 1);
    assert!(invoke(&imported, "create_record", args.clone())
        .await
        .is_ok());
    assert!(crate::provenance::state_violations(&imported)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn guarded_readonly_and_strict_portability_refuse_without_false_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("read.db");
    let db = crate::create_database(path.to_str().unwrap())
        .await
        .unwrap();
    let v = verified(&db, "create_record", &command()).await;
    // A SQLite read-only connection cannot insert/commit a fence; caller must
    // not translate this error into cancellation. No alternate writer opened.
    use sqlx::Connection;
    let opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&path)
        .read_only(true);
    let mut conn = sqlx::SqliteConnection::connect_with(&opts).await.unwrap();
    let mut tx = conn.begin().await.unwrap();
    assert!(cancel_in(&mut tx, &v).await.is_err());
    tx.rollback().await.unwrap();
    crate::storage_profile::update_portability_policy(
        &db,
        crate::storage_profile::PortabilityPolicyUpdate {
            if_policy_revision: 0,
            enforcement: crate::storage_profile::PortabilityEnforcement::Strict,
            target_profiles: vec![crate::storage_profile::StorageTarget {
                id: "postgres-server".into(),
                revision: 5,
                mode: "network".into(),
            }],
            allow_conversions: vec![],
        },
    )
    .await
    .unwrap();
    assert!(cancel(&db, &v)
        .await
        .unwrap_err()
        .to_string()
        .contains("strict_portability_blocked"));
    let error = crate::storage_profile::with_operation(
        &db,
        "held_command.cancel",
        Some("native.held-command-cancellation.v1"),
        async { cancel(&db, &v).await },
    )
    .await;
    assert!(error
        .unwrap_err()
        .to_string()
        .contains("strict_portability_blocked"));
    let broad = crate::storage_profile::with_operation(
        &db,
        "update_record",
        Some("native.guarded-write.v1"),
        async { cancel(&db, &v).await },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        broad.contains("native.held-command-cancellation.v1"),
        "{broad}"
    );
    let anchors: i64 =
        sqlx::query_scalar("SELECT count(*) FROM provenance_local_command_cancellations")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
    assert_eq!(anchors, 0);
}

#[tokio::test]
async fn identity_preserving_v2_import_refuses_fences_before_target_or_resume() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.db");
    let db = crate::create_database(source.to_str().unwrap())
        .await
        .unwrap();
    crate::authorization::replace_explicit_policy(
        &db,
        "local",
        "native:root",
        vec![
            crate::authorization::AllowEntry::account(
                "local",
                crate::authorization::Capability::Manage,
            ),
            crate::authorization::AllowEntry::members(crate::authorization::Capability::Edit),
        ],
    )
    .await
    .unwrap();
    let args = command();
    let note = invoke(&db, "create_record", args).await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let origin = crate::identity::database_id(&db).await.unwrap();
    let members = dir.path().join("members.txt");
    std::fs::write(&members, "local\n").unwrap();
    let target = dir.path().join("target.db");
    let options = |target: std::path::PathBuf, resume| crate::v1_import::Options {
        source: source.clone(),
        target,
        seeds: vec![note.clone()],
        all: false,
        history: false,
        resume,
        members_file: Some(members.clone()),
    };
    let initial = crate::v1_import::cutover::snapshot_digest(&source)
        .await
        .unwrap();
    let report = crate::v1_import::run(options(target.clone(), false))
        .await
        .unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    let mut imported = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&target)
            .read_only(true),
    )
    .await
    .unwrap();
    let head: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1")
        .fetch_one(&mut imported).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&head).unwrap()["origin"],
        origin
    );
    sqlx::Connection::close(imported).await.unwrap();
    let target_before = crate::v1_import::cutover::snapshot_digest(&target)
        .await
        .unwrap();
    // A real canonical fence, committed after a previously successful capture.
    let mut pending = command();
    pending["idempotency_key"] = json!("pending-v2-conversion");
    let v = verified(&db, "create_record", &pending).await;
    assert!(matches!(
        cancel(&db, &v).await.unwrap(),
        StagedCancellation::Cancelled { .. }
    ));
    // The owned v2 target cannot issue a positive legacy cancellation result,
    // even though its captured source origin is the same logical database.
    let v2 = crate::kernel::open_v2_database(target.to_str().unwrap())
        .await
        .unwrap();
    let mut tx = crate::db::begin_write(v2.write_pool()).await.unwrap();
    assert!(cancel_in(&mut tx, &v).await.is_err());
    tx.rollback().await.unwrap();
    v2.close().await;
    let source_before = crate::v1_import::cutover::snapshot_digest(&source)
        .await
        .unwrap();
    assert_ne!(initial, source_before);
    // Existing receipt binding must catch a cancellation committed after the
    // import's source snapshot; a loose preflight count is not publication proof.
    let error = crate::v1_import::cutover::attach_receipt(
        &report, &source, &target, &initial, false, false, false,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("source changed during import"), "{error}");
    let fresh = dir.path().join("fresh.db");
    for (path, resume) in [(fresh.clone(), false), (target.clone(), true)] {
        let error = crate::v1_import::run(options(path, resume))
            .await
            .err()
            .expect("v2 conversion must refuse local cancellation authority")
            .to_string();
        assert!(
            error.contains("cannot discard local command cancellation authority"),
            "{error}"
        );
    }
    assert!(!fresh.exists());
    assert!(!dir.path().join("fresh.db.import.lock").exists());
    assert_eq!(
        target_before,
        crate::v1_import::cutover::snapshot_digest(&target)
            .await
            .unwrap()
    );
    assert_eq!(
        source_before,
        crate::v1_import::cutover::snapshot_digest(&source)
            .await
            .unwrap()
    );
}
