//! Root-only gateway signatures; genuine requester fixtures live in Hosting.
use super::*;
use crate::mcp::registry::{HeldLocalEvidence, HeldLocalOutcome};
use crate::provenance::cancellation::lookup::test_control;
#[tokio::test]
async fn local_evidence_lookup_production_snapshot_corruption_and_restart() {
    loader_cases(&["lookup", "lookup_restart"]).await;
}
async fn read(
    r: &ToolRegistry,
    b: &DeploymentMutationBarrier,
    p: &WriterPause,
    db: &Db,
    packet: &[u8],
) -> Result<Option<HeldLocalEvidence>> {
    r.lookup_held_stop_evidence_with_persistence(
        db.clone(),
        packet,
        lease(b),
        p.try_begin().unwrap(),
    )
    .await
}
async fn counts(db: &Db) -> Vec<i64> {
    let mut result = Vec::new();
    for table in [
        "content_events",
        "relationship_events",
        "control_events",
        "provenance_action_attestations",
        "provenance_local_command_cancellations",
        "act_state",
    ] {
        result.push(
            sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
        );
    }
    result.push(
        sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton=1")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
    );
    result
}
/// Explicit noncooperating corruption fixture. Restore exact trigger SQL before
/// qualification so rejection cannot merely be attributed to a missing guard.
async fn corrupt(db: &Db, statement: &str) {
    use sqlx::Connection;
    let mut c = db.write_pool().acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&mut *c)
        .await
        .unwrap();
    let mut tx = c.begin().await.unwrap();
    let triggers: Vec<(String, String)> =
        sqlx::query_as("SELECT name,sql FROM sqlite_schema WHERE type='trigger'")
            .fetch_all(&mut *tx)
            .await
            .unwrap();
    for (name, _) in &triggers {
        sqlx::query(&format!("DROP TRIGGER \"{}\"", name.replace('"', "\"\"")))
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    sqlx::raw_sql(statement).execute(&mut *tx).await.unwrap();
    for (_, sql) in &triggers {
        sqlx::raw_sql(sql).execute(&mut *tx).await.unwrap();
    }
    tx.commit().await.unwrap();
    sqlx::query("PRAGMA foreign_keys=ON")
        .execute(&mut *c)
        .await
        .unwrap();
    assert!(crate::db::validate_engine_shape_on(&mut c, 94)
        .await
        .unwrap());
}
pub(super) async fn exercise(
    case: &str,
    scope: &request::Scope,
    db: &Db,
    r: &ToolRegistry,
    b: &DeploymentMutationBarrier,
    p: &WriterPause,
) {
    let c = claims(scope, "lookup-original", "create_record");
    let bytes = sign(c.clone());
    let before = counts(db).await;
    if case == "lookup_restart" {
        let proof = read(r, b, p, db, &bytes).await.unwrap().unwrap();
        assert!(matches!(
            proof.outcome(),
            HeldLocalOutcome::Cancelled { .. }
        ));
        assert_eq!(proof.database_handle(), db.handle_id());
        assert_eq!(counts(db).await, before);
        return;
    }
    assert!(read(r, b, p, db, &bytes).await.unwrap().is_none());
    assert_eq!(counts(db).await, before);
    // Genuine unchanged multi-target update issues an empty anchor. Neither
    // that batch form nor an empty scalar append is eligible for V2 STOP.
    let mut ordinary = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut ordinary).unwrap();
    crate::mcp::register_surface_tools(&mut ordinary).unwrap();
    let created=ordinary.call(db.clone(),crate::mcp::Caller::local(),"create_record",json!({"type":"Document","kind":"note","name":"ordinary no-op","body":"kept","reason":"Ordinary no-op fixture."})).await.unwrap();
    let second=ordinary.call(db.clone(),crate::mcp::Caller::local(),"create_record",json!({"type":"Document","kind":"note","name":"second ordinary no-op","body":"kept","reason":"Ordinary no-op fixture."})).await.unwrap();
    for id in [&created["id"], &second["id"]] {
        ordinary.call(db.clone(),crate::mcp::Caller::local(),"update_record",json!({"id":id,"facets":{"colour":"blue"},"reason":"Seed genuine multi-target no-op."})).await.unwrap();
    }
    let unchanged=ordinary.call(db.clone(),crate::mcp::Caller::local(),"update_record",json!({"ids":[created["id"],second["id"]],"facets":{"colour":"blue"},"reason":"Genuine multi-target no-op","idempotency_key":"ordinary-noop"})).await.unwrap();
    assert_eq!(unchanged["changed"], json!(0));
    assert_eq!(unchanged["unchanged"], json!(2));
    let row=sqlx::query("SELECT schema_version,issuer,command_identity_digest,output_event_set_digest FROM provenance_action_attestations a WHERE operation='update_record' AND NOT EXISTS(SELECT 1 FROM provenance_action_outputs o WHERE o.action_attestation_id=a.id)").fetch_one(db.write_pool()).await.unwrap();
    assert!(is_empty_keyed_anchor_shape(
        row.try_get("schema_version").unwrap(),
        "update_record",
        &row.try_get::<String, _>("issuer").unwrap(),
        row.try_get::<Option<String>, _>("command_identity_digest")
            .unwrap()
            .as_deref(),
        &row.try_get::<String, _>("output_event_set_digest").unwrap()
    ));
    let ineligible = sign(claims_with_append(
        scope,
        "ineligible-noop",
        "update_record",
        Some(""),
    ));
    assert!(read(r, b, p, db, &ineligible).await.is_err());
    // A restored BEFORE-outcome image must stay unknown, not inherit a journal claim.
    let dir = tempfile::tempdir().unwrap();
    let pre = dir.path().join("before.db");
    sqlx::query("VACUUM INTO ?")
        .bind(pre.to_str().unwrap())
        .execute(db.write_pool())
        .await
        .unwrap();
    // Read snapshot wins first. The later STOP cannot turn that miss into
    // cancellation evidence; only the subsequent fresh lookup sees its COMMIT.
    let snapshot_pause = Arc::new(test_control::Pause::default());
    let lookup = test_control::AFTER_READ.scope(snapshot_pause.clone(), read(r, b, p, db, &bytes));
    tokio::pin!(lookup);
    tokio::select! {_=&mut lookup=>panic!("lookup read barrier"),_=snapshot_pause.entered.notified()=>{}}
    let entering = Arc::new(Notify::new());
    let later = crate::db::with_before_begin_write_notification(
        entering.clone(),
        invoke(r, b, p, db, &bytes),
    );
    tokio::pin!(later);
    tokio::select! {_=&mut later=>panic!("STOP cannot pass held writer snapshot"),_=entering.notified()=>{}}
    snapshot_pause.release.notify_one();
    assert!(lookup.await.unwrap().is_none());
    later.await.unwrap();
    let after = counts(db).await;
    let proof = read(r, b, p, db, &bytes).await.unwrap().unwrap();
    assert!(matches!(
        proof.outcome(),
        HeldLocalOutcome::Cancelled { .. }
    ));
    assert_eq!(
        proof.binding(),
        &wire::observation_binding(&c, &bytes).unwrap()
    );
    assert_eq!(proof.database_handle(), db.handle_id());
    assert_eq!(counts(db).await, after);
    let predb = crate::open_existing_database(pre.to_str().unwrap())
        .await
        .unwrap();
    assert!(read(r, b, p, &predb, &bytes).await.unwrap().is_none());
    predb.close().await;
    // Same-origin qualified copy retains authority; raw bitcopies cannot be
    // distinguished by origin/anchors alone. The handle ID is process-local.
    let backup = dir.path().join("backup.db");
    sqlx::query("VACUUM INTO ?")
        .bind(backup.to_str().unwrap())
        .execute(db.write_pool())
        .await
        .unwrap();
    let copy = crate::open_existing_database(backup.to_str().unwrap())
        .await
        .unwrap();
    let proof = read(r, b, p, &copy, &bytes).await.unwrap().unwrap();
    assert_ne!(proof.database_handle(), db.handle_id());
    assert_eq!(proof.database_handle(), copy.handle_id());
    copy.close().await;
    let bundle = crate::interchange::export_canonical_interchange(db)
        .await
        .unwrap();
    let foreign = crate::interchange::import_canonical_interchange(
        &bundle,
        &dir.path().join("foreign.db"),
        crate::interchange::ImportContinuity::ForeignBoundary,
    )
    .await
    .unwrap();
    // Portable evidence retains history, not receiver-local authority.
    for table in [
        "provenance_local_command_cancellations",
        "provenance_local_attestation_authority",
    ] {
        let anchors: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(foreign.write_pool())
            .await
            .unwrap();
        assert_eq!(anchors, 0, "foreign import must not mint local authority");
    }
    let foreign_before = counts(&foreign).await;
    assert!(
        read(r, b, p, &foreign, &bytes).await.unwrap().is_none(),
        "portable history cannot yield positive local evidence"
    );
    assert_eq!(counts(&foreign).await, foreign_before);
    foreign.close().await;
    for (n,sql) in [
        "UPDATE provenance_local_command_cancellations SET action_digest=printf('%064d',1)",
        "UPDATE provenance_local_attestation_authority SET principal=(SELECT principal FROM provenance_local_command_cancellations LIMIT 1),operation=(SELECT operation FROM provenance_local_command_cancellations LIMIT 1),command_identity_digest=(SELECT command_identity_digest FROM provenance_local_command_cancellations LIMIT 1) WHERE operation='update_record' AND command_identity_digest IS NOT NULL",
        "UPDATE control_events SET actor='wrong' WHERE type='held_command.cancelled.v1'",
        "UPDATE control_events SET idempotency_key='wrong' WHERE type='held_command.cancelled.v1'",
        "UPDATE control_events SET payload='{}' WHERE type='held_command.cancelled.v1'",
        "DELETE FROM control_event_applications WHERE event_id IN(SELECT event_id FROM provenance_local_command_cancellations)",
        "DELETE FROM control_events WHERE type='held_command.cancelled.v1'",
    ].iter().enumerate() {
        let path=dir.path().join(format!("corrupt-{n}.db"));sqlx::query("VACUUM INTO ?").bind(path.to_str().unwrap()).execute(db.write_pool()).await.unwrap();
        let copy=crate::open_existing_database(path.to_str().unwrap()).await.unwrap();corrupt(&copy,sql).await;let bad=counts(&copy).await;
        assert!(read(r,b,p,&copy,&bytes).await.is_err(),"{sql}");assert_eq!(counts(&copy).await,bad);copy.close().await;
    }
    let readonly = crate::db::open_existing_database_standby_read_only(backup.to_str().unwrap())
        .await
        .unwrap();
    assert!(read(r, b, p, &readonly, &bytes).await.is_err());
    readonly.close().await;
    assert!(r
        .lookup_held_stop_evidence_with_persistence(
            db.clone(),
            &bytes,
            lease(b),
            WriterPause::new().try_begin().unwrap()
        )
        .await
        .is_err());
    assert!(ToolRegistry::new()
        .lookup_held_stop_evidence_with_persistence(
            db.clone(),
            &bytes,
            lease(b),
            p.try_begin().unwrap()
        )
        .await
        .is_err());
    let fleet = match b
        .admit(
            &crate::DeploymentReadOnlyOperation::server("held_command.author_stop"),
            OperationAccess::Mutation,
        )
        .unwrap()
    {
        DeploymentAdmission::Writable(v) => v,
        _ => unreachable!(),
    };
    assert!(r
        .lookup_held_stop_evidence_with_persistence(
            db.clone(),
            &bytes,
            fleet,
            p.try_begin().unwrap()
        )
        .await
        .is_err());
    // Lookup owns a real writer snapshot, and pre-admitted work still drains.
    let pause = Arc::new(test_control::Pause::default());
    let future = test_control::AFTER_READ.scope(pause.clone(), read(r, b, p, db, &bytes));
    tokio::pin!(future);
    tokio::select! {_=&mut future=>panic!("lookup snapshot barrier"),_=pause.entered.notified()=>{}}
    p.pause();
    assert!(p.try_begin().is_none());
    pause.release.notify_one();
    assert!(future.await.unwrap().is_some());
    p.resume();
    // Expiry AFTER all reads must refuse before rollback publishes a positive.
    let mut short = claims(scope, "lookup-original", "create_record");
    short.deadline = chrono::Utc::now().timestamp_millis() + 1500;
    let deadline = short.deadline;
    let packet = sign(short);
    let pause = Arc::new(test_control::Pause::default());
    let future = test_control::AFTER_READ.scope(pause.clone(), read(r, b, p, db, &packet));
    tokio::pin!(future);
    tokio::select! {_=&mut future=>panic!("lookup expiry barrier"),_=pause.entered.notified()=>{}}
    tokio::time::sleep(std::time::Duration::from_millis(
        (deadline - chrono::Utc::now().timestamp_millis() + 1).max(1) as u64,
    ))
    .await;
    pause.release.notify_one();
    assert!(future.await.is_err());
    // Expiry behind another actual writer cannot be treated as a historical auth grant.
    let mut short = claims(scope, "lookup-original", "create_record");
    short.deadline = chrono::Utc::now().timestamp_millis() + 1500;
    let deadline = short.deadline;
    let packet = sign(short);
    let blocker = crate::db::begin_write(db.write_pool()).await.unwrap();
    let entered = Arc::new(Notify::new());
    let task = crate::db::with_before_begin_write_notification(
        entered.clone(),
        read(r, b, p, db, &packet),
    );
    tokio::pin!(task);
    tokio::select! {_=&mut task=>panic!("writer must block"),_=entered.notified()=>{}}
    tokio::time::sleep(std::time::Duration::from_millis(
        (deadline - chrono::Utc::now().timestamp_millis() + 1).max(1) as u64,
    ))
    .await;
    blocker.rollback().await.unwrap();
    assert!(task.await.is_err());
    assert_eq!(counts(db).await, after);
}
