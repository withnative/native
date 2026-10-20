use super::*;

async fn seed(f: &Fixture) {
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    // Use a private artifact to prove that bringing executable bytes into the
    // carrier does not widen its visibility. Fixtures exercise custody; these
    // are deliberately not declarations of executable admission.
    source.execute(r#"
      UPDATE records SET kind='artifact',body='<html>retained source</html>' WHERE id='secret';
      INSERT INTO facet_values VALUES('secret','runtime','native.html.v1',NULL,NULL,'2026-01-01T00:00:00Z');
      INSERT INTO facet_observations VALUES('secret','runtime','2026-01-01T00:00:00Z',1);
      CREATE TABLE IF NOT EXISTS artifact_source_attestations(artifact_id TEXT,attestation_event_id TEXT,source_event_id TEXT,descriptor TEXT);
      INSERT INTO artifact_source_attestations VALUES('secret','attestation','source','{ "spelling" : 1 }');
      CREATE TABLE IF NOT EXISTS artifact_module_grants(artifact_id TEXT,subject_kind TEXT,subject_record_id TEXT,subject_event_id TEXT,capability TEXT,scope_sha256 TEXT);
      CREATE TABLE IF NOT EXISTS module_releases(module_record_id TEXT,publication_event_id TEXT);
      CREATE TABLE IF NOT EXISTS module_release_imports(consumer_publication_event_id TEXT,ordinal INTEGER);
      CREATE TABLE IF NOT EXISTS artifact_inputs(artifact_id TEXT,port_name TEXT,collection_id TEXT);
      INSERT INTO artifact_inputs VALUES('secret','items','private');
      CREATE TABLE IF NOT EXISTS alpha_tab_orders(account_id TEXT PRIMARY KEY,tab_order TEXT,event_id TEXT);
      CREATE TABLE IF NOT EXISTS alpha_tab_installs(artifact_id TEXT,account_id TEXT,package TEXT,consented_source_revision TEXT,event_id TEXT,status TEXT,adoption TEXT);
      INSERT INTO alpha_tab_installs VALUES('secret','account-a','test.docs','source','install','installed','shell_adopt.v1');
      CREATE TABLE IF NOT EXISTS canvas_objects(canvas_id TEXT,object_id TEXT,geometry_seq INTEGER,content_seq INTEGER,props TEXT,x REAL);
      INSERT INTO canvas_objects VALUES('note','card',100,101,'{ "record_id" : "secret" }',0.12345678901234566);
      CREATE TABLE IF NOT EXISTS canvas_batches(canvas_id TEXT,batch_id TEXT,event_id TEXT,event_seq INTEGER,actor TEXT,ops_sha256 TEXT);
      INSERT INTO canvas_batches VALUES('note','batch','batch-event',101,'account-a','original-digest');
      CREATE TABLE IF NOT EXISTS control_events(seq INTEGER PRIMARY KEY,id TEXT,subject_id TEXT,type TEXT,payload TEXT,actor TEXT,created_at TEXT);
      INSERT INTO control_events VALUES(1,'install','account-a','alpha_tab.installed','{"artifact_id":"secret","account_id":"account-a"}','account-a','2026-01-01T00:00:00Z');
      INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES
        ('attestation','secret','artifact.source_attested.v1','{}','account-a','2026-01-01T00:00:00Z'),
        ('source','secret','record.updated','{ "body" : "<html>retained source</html>" }','account-a','2026-01-01T00:00:00Z'),
        ('batch-event','note','canvas.batch.committed.v1','{"retained":true}','account-a','2026-01-01T00:00:00Z');
    "#).await.unwrap();
}

#[tokio::test]
async fn custody_preserves_artifacts_pins_installs_and_canvas_without_activation() {
    let f = Fixture::new().await;
    seed(&f).await;
    let report = run(f.options(&["secret", "note"], false)).await.unwrap();
    assert!(
        report.review.is_empty(),
        "{}",
        serde_json::to_string(&report.review).unwrap()
    );
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    assert_eq!(report.app_state.retained_rows["canvas_objects"], 1);
    assert_eq!(report.app_state.retained_rows["canvas_batches"], 1);
    assert_eq!(report.app_state.retained_rows["alpha_tab_installs"], 1);
    assert_eq!(report.app_state.created, 2);
    assert_eq!(report.app_state.verified, 2);
    assert_eq!(report.app_state.missing_source_events, 0);
    assert_eq!(report.app_state.missing_control_events, 0);
    assert!(!report.app_state.executable_on_kernel_v2);
    assert!(report.app_state.capture_complete);
    assert!(report.app_state.largest_capsule_bytes > 0);
    let db = f.db().await;
    let a = &report.principals["account-a"];
    let b = &report.principals["account-b"];
    let artifact = k::read_record_as(&db, a, "secret").await.unwrap().unwrap();
    assert_eq!(
        artifact.body.as_deref(),
        Some("<html>retained source</html>")
    );
    assert!(k::read_record_as(&db, b, "secret").await.unwrap().is_none());
    let raw: String =
        sqlx::query_scalar("SELECT payload FROM kernel_app_state WHERE record_id='secret'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let state: k::app_state::RetainedAppState = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        state.artifact_source_attestations[0]["descriptor"],
        "{ \"spelling\" : 1 }"
    );
    assert_eq!(
        state.alpha_tab_installs[0]["consented_source_revision"],
        "source"
    );
    assert_eq!(state.control_events["install"]["actor"], "account-a");
    assert_eq!(
        state.source_events["source"]["payload"],
        "{ \"body\" : \"<html>retained source</html>\" }"
    );
    let raw: String =
        sqlx::query_scalar("SELECT payload FROM kernel_app_state WHERE record_id='note'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let canvas: k::app_state::RetainedAppState = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        canvas.canvas_objects[0]["x"]["native.v1.sqlite.real_bits"],
        format!("{:016x}", 0.12345678901234566_f64.to_bits())
    );
    let history = k::history_as(&db, a, "secret").await.unwrap();
    assert!(!history
        .iter()
        .any(|row| row.event_type == k::app_state::IMPORTED_EVENT));
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    db.write_pool()
        .execute("DROP TABLE kernel_app_state")
        .await
        .unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
    let resumed = run(f.options(&["secret", "note"], true)).await.unwrap();
    assert_eq!(resumed.app_state.created, 0);
    assert_eq!(resumed.app_state.updated, 0);
    assert_eq!(resumed.app_state.verified, 2);
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source
        .execute("DELETE FROM content_events WHERE id='attestation'")
        .await
        .unwrap();
    source.close().await.unwrap();
    let incomplete = run(f.options(&["secret", "note"], true)).await.unwrap();
    assert!(!incomplete.app_state.capture_complete);
    assert!(incomplete
        .refusals
        .iter()
        .any(|issue| issue.reason.contains("incomplete app custody")));
    assert_eq!(incomplete.app_state.bearers_with_evidence_gaps, 1);
    let db = f.db().await;
    let raw: String =
        sqlx::query_scalar("SELECT payload FROM kernel_app_state WHERE record_id='secret'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let retained: k::app_state::RetainedAppState = serde_json::from_str(&raw).unwrap();
    let custody = retained.custody.unwrap();
    assert_eq!(custody.missing_source_events, vec!["attestation"]);
    assert_eq!(custody.closure_admission, "not_evaluated");
    db.close().await;
}

#[tokio::test]
async fn custody_resume_removes_stale_rows_and_refuses_an_unprivileged_writer() {
    let f = Fixture::new().await;
    seed(&f).await;
    let report = run(f.options(&["secret", "note"], false)).await.unwrap();
    assert!(
        report.review.is_empty(),
        "{}",
        serde_json::to_string(&report.review).unwrap()
    );
    let db = f.db().await;
    assert!(k::app_state::import_as(
        &db,
        &report.principals["account-a"],
        "secret",
        "test-origin",
        &Default::default()
    )
    .await
    .is_err());
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let host: String =
        sqlx::query_scalar("SELECT principal_id FROM kernel_principals WHERE auth_binding=?")
            .bind(k::HOST_IMPORT_BINDING)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(k::app_state::import_as(
        &db,
        &host,
        "secret",
        "different-origin",
        &Default::default()
    )
    .await
    .is_err());
    assert!(
        k::app_state::import_as(&db, &host, "missing", "test-origin", &Default::default())
            .await
            .is_err()
    );
    let wrong_bearer = k::app_state::RetainedAppState {
        artifact_inputs: vec![json!({"artifact_id":"other","port_name":"x"})],
        ..Default::default()
    };
    assert!(
        k::app_state::import_as(&db, &host, "secret", "test-origin", &wrong_bearer)
            .await
            .is_err()
    );
    assert_eq!(
        before,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    );
    let revision = k::read_record_as(&db, &report.principals["account-a"], "secret")
        .await
        .unwrap()
        .unwrap()
        .revision;
    let raw: String =
        sqlx::query_scalar("SELECT payload FROM kernel_app_state WHERE record_id='secret'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let mut retained: k::app_state::RetainedAppState = serde_json::from_str(&raw).unwrap();
    let mut regressed = retained.clone();
    regressed.custody.as_mut().unwrap().content_frontier = -1;
    assert!(
        k::app_state::import_as(&db, &host, "secret", "test-origin", &regressed)
            .await
            .is_err()
    );
    retained.artifact_inputs.clear();
    assert_eq!(
        k::app_state::import_as(&db, &host, "secret", "test-origin", &retained)
            .await
            .unwrap(),
        k::ImportResult::Updated
    );
    assert_eq!(
        k::read_record_as(&db, &report.principals["account-a"], "secret")
            .await
            .unwrap()
            .unwrap()
            .revision,
        revision
    );
    assert!(
        !k::history_as(&db, &report.principals["account-a"], "secret")
            .await
            .unwrap()
            .iter()
            .any(|row| row.event_type == k::app_state::IMPORTED_EVENT)
    );
    db.close().await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source.execute("DROP TABLE canvas_batches").await.unwrap();
    source.close().await.unwrap();
    let skipped = run(f.options(&["secret", "note"], true)).await.unwrap();
    assert_eq!(skipped.app_state.missing_tables, vec!["canvas_batches"]);
    assert_eq!(skipped.app_state.updated, 0);
    assert!(!skipped.app_state.capture_complete);
    assert!(skipped
        .refusals
        .iter()
        .any(|issue| issue.reason.contains("incomplete app custody")));
    let db = f.db().await;
    let rows: i64 = sqlx::query_scalar("SELECT json_array_length(json_extract(payload,'$.canvas_batches')) FROM kernel_app_state WHERE record_id='note'").fetch_one(db.pool()).await.unwrap();
    assert_eq!(rows, 1);
    db.close().await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source
        .execute("CREATE TABLE canvas_batches(canvas_id TEXT,batch_id TEXT,event_id TEXT,event_seq INTEGER,actor TEXT,ops_sha256 TEXT)")
        .await
        .unwrap();
    source.execute("DELETE FROM artifact_inputs; DELETE FROM alpha_tab_installs; DELETE FROM canvas_objects; DELETE FROM canvas_batches").await.unwrap();
    source.close().await.unwrap();
    let resumed = run(f.options(&["secret", "note"], true)).await.unwrap();
    assert_eq!(resumed.app_state.updated, 2);
    let db = f.db().await;
    let raw: String =
        sqlx::query_scalar("SELECT payload FROM kernel_app_state WHERE record_id='note'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(serde_json::from_str::<k::app_state::RetainedAppState>(&raw)
        .unwrap()
        .is_empty());
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn custody_private_app_history_never_advances_a_public_artifact() {
    let f = Fixture::new().await;
    seed(&f).await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source.execute(r#"
      DELETE FROM canvas_objects; DELETE FROM canvas_batches;
      UPDATE records SET kind='artifact',body='<html>public app</html>' WHERE id='note';
      INSERT INTO facet_values VALUES('note','runtime','native.html.v1',NULL,NULL,'2026-01-01T00:00:00Z');
      INSERT INTO facet_observations VALUES('note','runtime','2026-01-01T00:00:00Z',1);
      INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('public-source','note','record.updated','{"body":"<html>public app</html>"}','account-a','2026-01-01T00:00:00Z');
      INSERT INTO control_events VALUES(2,'public-install','account-a','alpha_tab.installed','{"artifact_id":"note","account_id":"account-a"}','account-a','2026-02-01T00:00:00Z');
      INSERT INTO alpha_tab_installs VALUES('note','account-a','test.public','public-source','public-install','installed','shell_adopt.v1');
    "#).await.unwrap();
    source.close().await.unwrap();
    let mut options = f.options(&["secret", "note"], false);
    options.history = true;
    let first = run(options).await.unwrap();
    assert!(first.refusals.is_empty() && first.review.is_empty());
    let db = f.db().await;
    let before = ordinary_kernel_call(&db, "account-b", "get_record", json!({"ids":["note"]}))
        .await
        .unwrap();
    assert_eq!(before["records"][0]["status"], "found");
    let clocks = ordinary_kernel_call(&db, "account-b", "query_sql", json!({"sql":"SELECT updated_at,updated_at_ms,(SELECT max(local_seq) FROM content_events WHERE record_id='note') AS pulse FROM records WHERE id='note'"})).await.unwrap();
    assert_eq!(clocks["rows"].as_array().unwrap().len(), 1);
    assert!(!clocks["rows"][0]["updated_at"].is_null());
    let history =
        ordinary_kernel_call(&db, "account-b", "get_history", json!({"record_id":"note"}))
            .await
            .unwrap();
    assert!(!history.to_string().contains("public-install"));
    let (anchor, payload): (String, String) =
        sqlx::query_as("SELECT record_id,payload FROM content_events WHERE id='public-install'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(anchor.starts_with("kernel:app-custody:control:"));
    assert!(
        ordinary_kernel_call(&db, "account-b", "get_history", json!({"record_id":anchor}))
            .await
            .is_err()
    );
    let mut legacy: k::LegacyEvent = serde_json::from_value(
        serde_json::from_str::<serde_json::Value>(&payload).unwrap()["legacy"].clone(),
    )
    .unwrap();
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_principals VALUES(?,'account','Old colliding entity','fixture-collision')")
        .bind(&anchor).execute(&mut *tx).await.unwrap();
    let canonical = crate::conformance::rebuild::read_all_events(&mut tx)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.id == "public-install")
        .unwrap();
    let error = k::hq::project(&mut tx, &canonical).await.unwrap_err();
    assert!(
        error.to_string().contains("aggregate id collision"),
        "{error}"
    );
    tx.rollback().await.unwrap();
    legacy.id = "wrong-public-placement".into();
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert!(k::import_event_as(&db, &host, "note", &legacy)
        .await
        .is_err());
    for source in [
        None,
        Some(json!({"stream":"content_events","origin":"test-origin"})),
        Some(json!({"stream":"control_events"})),
    ] {
        legacy.source = source;
        assert!(k::import_event_as(&db, &host, "note", &legacy)
            .await
            .is_err());
    }
    db.close().await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source.execute(r#"
      INSERT INTO control_events VALUES(3,'public-remove','account-a','alpha_tab.removed','{"artifact_id":"note","account_id":"account-a"}','account-a','2026-03-01T00:00:00Z');
      INSERT INTO control_events VALUES(4,'public-binding','account-a','instruction_binding.created','{"source_record_id":"note","scope_kind":"account","scope_id":"account-a"}','account-a','2026-03-02T00:00:00Z');
      UPDATE alpha_tab_installs SET status='removed',event_id='public-remove' WHERE package='test.public';
    "#).await.unwrap();
    source.close().await.unwrap();
    let mut options = f.options(&["secret", "note"], true);
    options.history = true;
    let resumed = run(options).await.unwrap();
    assert!(resumed.refusals.is_empty() && resumed.review.is_empty());
    let db = f.db().await;
    let after = ordinary_kernel_call(&db, "account-b", "get_record", json!({"ids":["note"]}))
        .await
        .unwrap();
    assert_eq!(
        before, after,
        "foreign account install history must not change public artifact clocks or shape"
    );
    let after_history =
        ordinary_kernel_call(&db, "account-b", "get_history", json!({"record_id":"note"}))
            .await
            .unwrap();
    assert_eq!(history, after_history);
    let after_clocks = ordinary_kernel_call(&db, "account-b", "query_sql", json!({"sql":"SELECT updated_at,updated_at_ms,(SELECT max(local_seq) FROM content_events WHERE record_id='note') AS pulse FROM records WHERE id='note'"})).await.unwrap();
    // The query snapshot cursor is global; these clocks are record-scoped.
    assert_eq!(clocks["columns"], after_clocks["columns"]);
    assert_eq!(clocks["rows"], after_clocks["rows"]);
    let projected = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn custody_old_app_history_replays_but_requires_a_fresh_import() {
    use sha2::{Digest, Sha256};
    let f = Fixture::new().await;
    seed(&f).await;
    let first = run(f.options(&["secret", "note"], false)).await.unwrap();
    assert!(first.refusals.is_empty());
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    let raw:String=sqlx::query_scalar("SELECT json_object('seq',seq,'id',id,'subject_id',subject_id,'type',type,'payload',payload,'actor',actor,'created_at',created_at) FROM control_events WHERE id='install'").fetch_one(&mut source).await.unwrap();
    let row: serde_json::Value = serde_json::from_str(&raw).unwrap();
    source.close().await.unwrap();
    let legacy = k::LegacyEvent {
        source: Some(
            json!({"origin":"test-origin","stream":"control_events","metadata":{"seq":1,"subject_id":"account-a"},"subjects":["secret"],"row_sha256":format!("{:x}",Sha256::digest(serde_json::to_vec(&row).unwrap()))}),
        ),
        id: "install".into(),
        event_type: "alpha_tab.installed".into(),
        payload: serde_json::from_str(row["payload"].as_str().unwrap()).unwrap(),
        created_at: row["created_at"].as_str().unwrap().into(),
        actor: Some("account-a".into()),
        run_key: None,
    };
    let db = f.db().await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    // Reconstruct the old canonical format with its real import witness. The
    // current high-level importer refuses to create this placement.
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    crate::store::append_kernel_import_receipts_in(
        &db,
        &mut tx,
        &host,
        &[("secret", "install")],
        &mut acts,
    )
    .await
    .unwrap();
    let mut event = crate::events::EventRow {
        local_seq: -1,
        id: legacy.id.clone(),
        record_id: "secret".into(),
        event_type: "kernel.legacy_recorded.v1".into(),
        payload: Some(serde_json::to_string(&json!({"legacy":legacy,"facet":null})).unwrap()),
        actor: Some("v1:account-a".into()),
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: legacy.created_at.clone(),
        causal_envelope: crate::events::CausalEnvelopeV1::legacy_unknown(),
        act: None,
    };
    crate::store::append_kernel_legacy_in(&mut tx, &mut event, &mut acts)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    assert_eq!(
        k::import_event_as(&db, &host, "secret", &legacy)
            .await
            .unwrap(),
        k::ImportResult::Unchanged
    );
    db.close().await;
    for history in [false, true] {
        let mut options = f.options(&["secret", "note"], true);
        options.history = history;
        let error = run(options).await.err().unwrap();
        assert!(
            error.to_string().contains("fresh custody-isolated target"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn custody_large_historical_closures_preserve_exact_bytes_and_replay() {
    let f = Fixture::new().await;
    seed(&f).await;
    let report = run(f.options(&["secret", "note"], false)).await.unwrap();
    assert!(report.refusals.is_empty());
    let db = f.db().await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let raw: String =
        sqlx::query_scalar("SELECT payload FROM kernel_app_state WHERE record_id='secret'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let mut state: k::app_state::RetainedAppState = serde_json::from_str(&raw).unwrap();
    let text = "preserved source ".repeat(600_000);
    state.source_events.insert(
        "large-source".into(),
        json!({"id":"large-source","payload":text}),
    );
    assert!(serde_json::to_vec(&state).unwrap().len() > 8 * 1024 * 1024);
    assert_eq!(
        k::app_state::import_as(&db, &host, "secret", "test-origin", &state)
            .await
            .unwrap(),
        k::ImportResult::Updated
    );
    assert_eq!(
        k::app_state::import_as(&db, &host, "secret", "test-origin", &state)
            .await
            .unwrap(),
        k::ImportResult::Unchanged
    );
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    let raw: String =
        sqlx::query_scalar("SELECT payload FROM kernel_app_state WHERE record_id='secret'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let restored: k::app_state::RetainedAppState = serde_json::from_str(&raw).unwrap();
    assert_eq!(restored.source_events["large-source"]["payload"], text);
    db.close().await;
}

#[tokio::test]
async fn custody_ambiguous_control_accounts_are_quarantined_per_event() {
    let mut legacy = k::LegacyEvent {
        id: "one".into(),
        event_type: "instruction_binding.created".into(),
        payload: json!({"account_id":"a", "scope_kind":"account", "scope_id":"b"}),
        actor: None,
        run_key: None,
        created_at: "2026-01-01".into(),
        source: Some(json!({"stream":"control_events","origin":"test-origin"})),
    };
    let first = k::app_state::history_aggregate(&legacy).unwrap().unwrap();
    legacy.id = "two".into();
    assert_ne!(
        first,
        k::app_state::history_aggregate(&legacy).unwrap().unwrap()
    );
    legacy.payload = json!({"scope_kind":"account","scope_id":" "});
    let blank = k::app_state::history_aggregate(&legacy).unwrap().unwrap();
    legacy.id = "three".into();
    assert_ne!(
        blank,
        k::app_state::history_aggregate(&legacy).unwrap().unwrap()
    );
    legacy.payload = json!({"scope_kind":"account","scope_id":"a","account_id":"a"});
    let agreed = k::app_state::history_aggregate(&legacy).unwrap().unwrap();
    legacy.id = "four".into();
    assert_eq!(
        agreed,
        k::app_state::history_aggregate(&legacy).unwrap().unwrap()
    );
}

#[tokio::test]
async fn custody_orders_are_account_private_and_resume_tracks_deletion() {
    let f = Fixture::new().await;
    seed(&f).await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source
        .execute(r#"INSERT INTO alpha_tab_orders VALUES('account-a','["test.docs"]','install');"#)
        .await
        .unwrap();
    let first = run(f.options(&["secret", "note"], false)).await.unwrap();
    assert!(first.app_state.capture_complete);
    assert_eq!(first.app_state.source_rows["alpha_tab_orders"], 1);
    assert_eq!(first.app_state.retained_rows["alpha_tab_orders"], 1);
    assert_eq!(first.app_state.created, 3);
    let db = f.db().await;
    let row = k::app_state::account_order_as(&db, &first.principals["account-a"])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row["tab_order"], "[\"test.docs\"]");
    assert!(
        k::app_state::account_order_as(&db, &first.principals["account-b"])
            .await
            .unwrap()
            .is_none()
    );
    source
        .execute("DELETE FROM alpha_tab_orders; DELETE FROM records WHERE id='secret'")
        .await
        .unwrap();
    let next = run(f.options(&["secret", "note"], true)).await.unwrap();
    assert!(next.app_state.capture_complete);
    assert!(
        k::app_state::account_order_as(&db, &first.principals["account-a"])
            .await
            .unwrap()
            .is_none()
    );
    let raw: String =
        sqlx::query_scalar("SELECT payload FROM kernel_app_state WHERE record_id='secret'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(
        serde_json::from_str::<k::app_state::RetainedAppState>(&raw)
            .unwrap()
            .source_deleted
    );
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn custody_unknown_source_table_blocks_before_target_writes() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source
        .execute("CREATE TABLE unreviewed_domain_state(value TEXT)")
        .await
        .unwrap();
    let report = run(f.options(&["note"], false)).await.unwrap();
    assert_eq!(
        report.table_coverage.unclassified,
        vec!["unreviewed_domain_state"]
    );
    assert!(!report.refusals.is_empty());
    assert!(!f.target.exists());
}

async fn native_install_fixture(f: &Fixture) -> (Db, super::super::Report) {
    native_install_fixture_with_body(f, "<html>retained source</html>").await
}

async fn native_install_fixture_with_body(f: &Fixture, body: &str) -> (Db, super::super::Report) {
    seed(f).await;
    let declaration = json!({"contract":"native.app.v2","needs":[],"effects":[]});
    let declaration_digest =
        crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&declaration).unwrap();
    let digest = crate::mcp::tools::alpha_tabs::alpha_tab_digest(
        &crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(body),
        &declaration_digest,
        "native.html.v1",
    );
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE records SET body=? WHERE id='secret'")
        .bind(body)
        .execute(&mut source)
        .await
        .unwrap();
    sqlx::query("UPDATE content_events SET payload=? WHERE id='source'")
        .bind(json!({"body":body}).to_string())
        .execute(&mut source)
        .await
        .unwrap();
    source.execute("ALTER TABLE alpha_tab_installs ADD COLUMN version TEXT; ALTER TABLE alpha_tab_installs ADD COLUMN digest TEXT; ALTER TABLE alpha_tab_installs ADD COLUMN declaration_digest TEXT; ALTER TABLE alpha_tab_installs ADD COLUMN consented_declaration TEXT; ALTER TABLE alpha_tab_installs ADD COLUMN adoption_provenance TEXT;").await.unwrap();
    sqlx::query("UPDATE alpha_tab_installs SET package='agent.docs',version='0.8.2',digest=?,declaration_digest=?,consented_declaration=?")
        .bind(&digest).bind(&declaration_digest).bind(declaration.to_string()).execute(&mut source).await.unwrap();
    let evidence = json!({"account_id":"account-a","package":"agent.docs","version":"0.8.2","digest":digest,"artifact_id":"secret","consented_source_revision":"source","declaration_digest":declaration_digest,"consented_declaration":declaration,"adoption":"shell_adopt.v1"});
    sqlx::query("UPDATE control_events SET type='alpha_tab.adopted',payload=? WHERE id='install'")
        .bind(evidence.to_string())
        .execute(&mut source)
        .await
        .unwrap();
    source.execute("INSERT INTO alpha_tab_installs(artifact_id,account_id,package,consented_source_revision,event_id,status,adoption,version,digest,declaration_digest,consented_declaration,adoption_provenance) SELECT artifact_id,'account-b',package,consented_source_revision,'install-b',status,adoption,version,digest,declaration_digest,consented_declaration,adoption_provenance FROM alpha_tab_installs WHERE account_id='account-a'").await.unwrap();
    let mut other_evidence = evidence.clone();
    other_evidence["account_id"] = json!("account-b");
    sqlx::query("INSERT INTO control_events(seq,id,subject_id,type,payload,actor,created_at) VALUES(2,'install-b','account-b','alpha_tab.adopted',?,'account-b','2026-01-01T00:00:00Z')").bind(other_evidence.to_string()).execute(&mut source).await.unwrap();
    source.execute("INSERT INTO alpha_tab_installs(artifact_id,account_id,package,consented_source_revision,event_id,status,adoption,version,digest,declaration_digest,consented_declaration,adoption_provenance) SELECT artifact_id,'account-c',package,consented_source_revision,'install-c',status,adoption,version,digest,declaration_digest,consented_declaration,adoption_provenance FROM alpha_tab_installs WHERE account_id='account-a'").await.unwrap();
    let mut unmapped = evidence.clone();
    unmapped["account_id"] = json!("account-c");
    sqlx::query("INSERT INTO control_events(seq,id,subject_id,type,payload,actor,created_at) VALUES(3,'install-c','account-c','alpha_tab.adopted',?,'account-c','2026-01-01T00:00:00Z')").bind(unmapped.to_string()).execute(&mut source).await.unwrap();
    source
        .execute("UPDATE content_events SET type='record.created' WHERE id='source'")
        .await
        .unwrap();
    source.close().await.unwrap();
    let report = run(f.options(&["secret", "note"], false)).await.unwrap();
    assert!(report.refusals.is_empty());
    assert!(report.review.is_empty());
    (f.db().await, report)
}

async fn app_activation_proof(db: &Db) -> k::app_installs::VerifiedFrozenApps {
    let raw: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1").fetch_one(db.pool()).await.unwrap();
    let seq: i64 =
        sqlx::query_scalar("SELECT event_seq FROM kernel_app_state WHERE record_id='secret'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    // SAFETY: synthetic fixture is frozen and verified; no concurrent importer.
    unsafe {
        k::app_installs::VerifiedFrozenApps::from_verified_import_unchecked(
            serde_json::from_str(&raw).unwrap(),
            "ab".repeat(32),
            BTreeMap::from([("secret".into(), seq)]),
        )
    }
}
async fn app_roster(db: &Db, account: &str, accounts: &[&str]) {
    let account = account.to_owned();
    let users = accounts
        .iter()
        .map(|s| (s.to_string(), format!("{s}@example.test")))
        .collect();
    k::hosted_identity::reconcile_hosted_caller(db, |_| async move {
        // SAFETY: complete synthetic catalogue with IDs matching fixture bindings.
        Ok(unsafe {
            k::hosted_identity::VerifiedHostedMembership::from_catalog_unchecked(
                account,
                users,
                BTreeMap::new(),
            )
        })
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_apps_activate_exact_pins_remove_without_source_access_and_rebuild() {
    let f = Fixture::new().await;
    let (db, report) = native_install_fixture(&f).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let a = &report.principals["account-a"];
    let b = &report.principals["account-b"];
    let before = k::read_record_as(&db, a, "secret")
        .await
        .unwrap()
        .unwrap()
        .revision;
    assert!(
        k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
            .await
            .unwrap_err()
            .to_string()
            .contains("hosted identity activation required")
    );
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let installed: (String,bool,String) = sqlx::query_as("SELECT generation,executable,json_extract(row_json,'$.version') FROM kernel_app_installs WHERE principal=?").bind(a).fetch_one(db.pool()).await.unwrap();
    assert_eq!(installed, ("install".into(), true, "0.8.2".into()));
    assert!(k::app_installs::remove_as(&db, b, "agent.docs", "install")
        .await
        .is_err());
    assert!(k::read_record_as(&db, b, "secret").await.unwrap().is_none());
    k::app_installs::remove_as(&db, b, "agent.docs", "install-b")
        .await
        .unwrap();
    assert!(k::history_as(&db, b, "kernel:app-installs:activation")
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        before,
        k::read_record_as(&db, a, "secret")
            .await
            .unwrap()
            .unwrap()
            .revision
    );
    assert!(k::app_state::import_as(
        &db,
        &host,
        "secret",
        "test-origin",
        &k::app_state::RetainedAppState::default()
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("source import is closed"));
    let removed = k::app_installs::remove_as(&db, a, "agent.docs", "install")
        .await
        .unwrap();
    assert_eq!(
        removed,
        k::app_installs::remove_as(&db, a, "agent.docs", "install")
            .await
            .unwrap()
    );
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let state: (String, bool) =
        sqlx::query_as("SELECT status,executable FROM kernel_app_installs WHERE principal=?")
            .bind(a)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(state, ("removed".into(), false));
    // An account first admitted after activation cannot acquire old consent
    // when the install projection is later recovered from the immutable log.
    app_roster(&db, "account-c", &["account-a", "account-b", "account-c"]).await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM kernel_app_installs")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        2
    );
    let dump = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(dump, k::dump_all_kernel_tables(&db).await.unwrap());
    sqlx::query("DROP TABLE kernel_app_installs; DROP TABLE kernel_app_consent_revocations")
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut tx = db.write_pool().begin().await.unwrap();
    k::app_installs::ensure_schema(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(dump, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn native_apps_offboarding_before_activation_never_restores_old_consent() {
    let f = Fixture::new().await;
    let (db, report) = native_install_fixture(&f).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    app_roster(&db, "account-b", &["account-b"]).await;
    // SAFETY: synthetic host operation fences a and protects b as recipient.
    let operation = unsafe {
        k::hosted_identity::offboarding::VerifiedOffboarding::from_catalog_unchecked(
            uuid::Uuid::new_v4().to_string(),
            "account-b".into(),
            "account-a".into(),
            "account-b".into(),
            "fixture offboarding".into(),
        )
    };
    k::hosted_identity::offboarding::apply(&db, operation)
        .await
        .unwrap();
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let state: (String, bool, String) = sqlx::query_as(
        "SELECT status,executable,refusal FROM kernel_app_installs WHERE principal=?",
    )
    .bind(&report.principals["account-a"])
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(state, ("removed".into(), false, "offboarded".into()));
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn native_apps_bad_evidence_is_atomic_and_changed_activation_refuses() {
    let f = Fixture::new().await;
    let (db, _) = native_install_fixture(&f).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let head:String=sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1").fetch_one(db.pool()).await.unwrap();
    // SAFETY: deliberately incorrect synthetic witness must be rejected.
    let wrong = unsafe {
        k::app_installs::VerifiedFrozenApps::from_verified_import_unchecked(
            serde_json::from_str(&head).unwrap(),
            "ab".repeat(32),
            BTreeMap::from([("secret".into(), 1)]),
        )
    };
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    assert!(k::app_installs::activate_as(&db, &host, wrong)
        .await
        .is_err());
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let seq: i64 =
        sqlx::query_scalar("SELECT event_seq FROM kernel_app_state WHERE record_id='secret'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    // SAFETY: a changed verification receipt is a negative retry fixture.
    let changed = unsafe {
        k::app_installs::VerifiedFrozenApps::from_verified_import_unchecked(
            serde_json::from_str(&head).unwrap(),
            "cd".repeat(32),
            BTreeMap::from([("secret".into(), seq)]),
        )
    };
    assert!(k::app_installs::activate_as(&db, &host, changed)
        .await
        .unwrap_err()
        .to_string()
        .contains("activation evidence changed"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM content_events WHERE type='kernel.app_installs_activated.v1'"
        )
        .fetch_one(db.pool())
        .await
        .unwrap(),
        1
    );
}

#[tokio::test]
async fn native_apps_frozen_sources_are_independent_of_consent_and_follow_current_view() {
    let f = Fixture::new().await;
    let (db, report) = native_install_fixture(&f).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let a = &report.principals["account-a"];
    let b = &report.principals["account-b"];
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let original = k::app_installs::frozen_sources_as(&db, a).await.unwrap();
    assert_eq!(original.len(), 1);
    assert_eq!(original[0]["package"], "agent.docs");
    assert_eq!(original[0]["version"], "0.8.2");
    assert!(!original[0].to_string().contains("account-a"));
    assert!(k::app_installs::frozen_sources_as(&db, b)
        .await
        .unwrap()
        .is_empty());
    k::app_installs::remove_as(&db, a, "agent.docs", "install")
        .await
        .unwrap();
    k::app_installs::remove_as(&db, b, "agent.docs", "install-b")
        .await
        .unwrap();
    assert_eq!(
        original,
        k::app_installs::frozen_sources_as(&db, a).await.unwrap()
    );
    k::rehome_record_as(&db, a, "secret", KERNEL_ROOT_ID)
        .await
        .unwrap();
    app_roster(&db, "account-c", &["account-a", "account-b", "account-c"]).await;
    let c = k::resolve_principal_by_binding(&db, "account-c")
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(
        original,
        k::app_installs::frozen_sources_as(&db, &c).await.unwrap()
    );
    let own_installs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kernel_app_installs WHERE principal=?")
            .bind(&c)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(own_installs, 0, "source visibility does not create consent");
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    sqlx::query("DROP TABLE kernel_app_package_sources")
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut tx = db.write_pool().begin().await.unwrap();
    k::app_installs::ensure_schema(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    assert!(k::app_installs::frozen_sources_as(&db, &c).await.is_err());
}

#[tokio::test]
async fn native_apps_frozen_sources_keep_distinct_full_pins_and_original_consent_text() {
    let f = Fixture::new().await;
    let (db, _) = native_install_fixture(&f).await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    let declaration = json!({"contract":"native.app.v2","needs":[],"effects":[]});
    let original_text = serde_json::to_string_pretty(&declaration).unwrap();
    source.execute("UPDATE records SET kind='artifact',body='<html>retained source</html>' WHERE id='note'; INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('source-note','note','record.created','{\"body\":\"<html>retained source</html>\"}','account-a','2026-01-01T00:00:00Z');").await.unwrap();
    source.execute("INSERT INTO facet_values VALUES('note','runtime','native.html.v1',NULL,NULL,'2026-01-01T00:00:00Z'); INSERT INTO facet_observations VALUES('note','runtime','2026-01-01T00:00:00Z',1);").await.unwrap();
    let raw: String = sqlx::query_scalar("SELECT payload FROM control_events WHERE id='install-b'")
        .fetch_one(&mut source)
        .await
        .unwrap();
    let mut payload: Value = serde_json::from_str(&raw).unwrap();
    payload["artifact_id"] = json!("note");
    payload["consented_source_revision"] = json!("source-note");
    sqlx::query("INSERT INTO control_events VALUES(4,'install-b2','account-b','alpha_tab.updated',?,'account-b','2026-01-02T00:00:00Z')")
        .bind(payload.to_string()).execute(&mut source).await.unwrap();
    sqlx::query("UPDATE alpha_tab_installs SET artifact_id='note',consented_source_revision='source-note',event_id='install-b2',consented_declaration=? WHERE account_id='account-b'")
        .bind(&original_text).execute(&mut source).await.unwrap();
    source.close().await.unwrap();
    let report = run(f.options(&["secret", "note"], true)).await.unwrap();
    assert!(
        report.refusals.is_empty() && report.review.is_empty(),
        "{}",
        serde_json::to_string(&report).unwrap()
    );
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let head:String=sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1").fetch_one(db.pool()).await.unwrap();
    let capsules: Vec<(String, i64)> = sqlx::query_as(
        "SELECT record_id,event_seq FROM kernel_app_state WHERE record_id IN ('secret','note')",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    // SAFETY: two verified synthetic frozen sources with identical code/version,
    // distinct artifact/revision pins and independently owned consent witnesses.
    let proof = unsafe {
        k::app_installs::VerifiedFrozenApps::from_verified_import_unchecked(
            serde_json::from_str(&head).unwrap(),
            "ab".repeat(32),
            capsules.into_iter().collect(),
        )
    };
    k::app_installs::activate_as(&db, &host, proof)
        .await
        .unwrap();
    let a = k::app_installs::frozen_sources_as(&db, &report.principals["account-a"])
        .await
        .unwrap();
    let b = k::app_installs::frozen_sources_as(&db, &report.principals["account-b"])
        .await
        .unwrap();
    assert_eq!(
        a.len(),
        2,
        "identical code/version does not collapse distinct source pins"
    );
    assert_eq!(
        b.len(),
        1,
        "another account's private source remains undisclosed"
    );
    assert_eq!(b[0]["artifact_id"], "note");
    let retained:String=sqlx::query_scalar("SELECT json_extract(row_json,'$.consented_declaration') FROM kernel_app_installs WHERE principal=?")
        .bind(&report.principals["account-b"]).fetch_one(db.pool()).await.unwrap();
    assert_eq!(
        retained, original_text,
        "source canonicalization must not rewrite imported consent"
    );
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

fn frozen_install_request(pin: &serde_json::Value) -> k::app_installs::InstallRequest {
    k::app_installs::InstallRequest {
        package: pin["package"].as_str().unwrap().into(),
        version: pin["version"].as_str().unwrap().into(),
        digest: pin["digest"].as_str().unwrap().into(),
        artifact_id: pin["artifact_id"].as_str().unwrap().into(),
        source_revision: pin["source_revision"].as_str().unwrap().into(),
        declaration: serde_json::from_str(pin["consented_declaration"].as_str().unwrap()).unwrap(),
        reason: "Install this frozen app for my HQ account".into(),
        request: None,
        idempotency_key: Some("stage-frozen-docs".into()),
        expected_install_event_id: None,
    }
}

#[tokio::test]
async fn native_apps_new_member_staging_is_personal_pending_and_replayable() {
    let f = Fixture::new().await;
    let (db, report) = native_install_fixture(&f).await;
    let a = &report.principals["account-a"];
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let private_home = k::read_record_as(&db, a, "secret")
        .await
        .unwrap()
        .unwrap()
        .home_id;
    k::rehome_record_as(&db, a, "secret", KERNEL_ROOT_ID)
        .await
        .unwrap();
    app_roster(&db, "account-c", &["account-a", "account-b", "account-c"]).await;
    let c = k::resolve_principal_by_binding(&db, "account-c")
        .await
        .unwrap()
        .unwrap()
        .0;
    let pin = k::app_installs::frozen_sources_as(&db, &c)
        .await
        .unwrap()
        .remove(0);
    let request = frozen_install_request(&pin);
    let before = k::read_record_as(&db, a, "secret").await.unwrap().unwrap();
    let accepted = k::app_installs::install_as(&db, &c, request.clone())
        .await
        .unwrap();
    assert!(accepted.changed);
    let (adoption, executable, generation): (String, bool, String) = sqlx::query_as("SELECT json_extract(row_json,'$.adoption'),executable,generation FROM kernel_app_installs WHERE principal=? AND package='agent.docs'")
        .bind(&c).fetch_one(db.pool()).await.unwrap();
    assert_eq!(adoption, "caller_asserted");
    assert!(!executable, "staging alone cannot authorize an app");
    assert_eq!(generation, accepted.generation);
    let retry = k::app_installs::install_as(&db, &c, request.clone())
        .await
        .unwrap();
    assert!(!retry.changed);
    assert_eq!(retry.generation, generation);
    let mut changed = request.clone();
    changed.reason = "Another intent".into();
    assert!(k::app_installs::install_as(&db, &c, changed).await.is_err());
    let original: String = sqlx::query_scalar(
        "SELECT generation FROM kernel_app_installs WHERE principal=? AND package='agent.docs'",
    )
    .bind(a)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        original, "install",
        "another member's pin and consent are unchanged"
    );
    assert_eq!(
        before,
        k::read_record_as(&db, a, "secret").await.unwrap().unwrap()
    );
    let projected = k::dump_all_kernel_tables(&db).await.unwrap();
    sqlx::query("DROP TABLE kernel_app_install_outcomes")
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut tx = db.write_pool().begin().await.unwrap();
    k::app_installs::ensure_schema(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&db).await.unwrap());
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&db).await.unwrap());
    // A retry must regain current membership and source View, not reuse consent.
    ordinary_kernel_call(&db, "account-a", "archive_record", json!({"id":"secret","archived":true,"reason":"Retire app source","idempotency_key":"retire-source"}))
        .await.unwrap();
    assert!(k::app_installs::install_as(&db, &c, request.clone())
        .await
        .is_err());
    ordinary_kernel_call(&db, "account-a", "archive_record", json!({"id":"secret","archived":false,"reason":"Restore app source","idempotency_key":"restore-source"}))
        .await.unwrap();
    k::rehome_record_as(&db, a, "secret", &private_home)
        .await
        .unwrap();
    assert!(k::app_installs::install_as(&db, &c, request).await.is_err());
}

#[tokio::test]
async fn native_apps_first_roster_exclusion_cannot_become_imported_consent_on_join() {
    let f = Fixture::new().await;
    let (db, report) = native_install_fixture(&f).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let b = &report.principals["account-b"];
    app_roster(&db, "account-a", &["account-a"]).await;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    app_roster(&db, "account-b", &["account-a", "account-b"]).await;
    let state: (String, bool) = sqlx::query_as("SELECT status,executable FROM kernel_app_installs WHERE principal=? AND package='agent.docs'").bind(b).fetch_one(db.pool()).await.unwrap();
    assert_eq!(state, ("removed".into(), false));
    let projected = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn native_apps_equivalent_declaration_key_order_shares_frozen_source() {
    let f = Fixture::new().await;
    let (db, _) = native_install_fixture(&f).await;
    let original = r#"{ "effects": [], "needs": [], "contract": "native.app.v2" }"#;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    let raw: String = sqlx::query_scalar("SELECT payload FROM control_events WHERE id='install-b'")
        .fetch_one(&mut source)
        .await
        .unwrap();
    let mut payload: Value = serde_json::from_str(&raw).unwrap();
    payload["consented_declaration"] = serde_json::from_str(original).unwrap();
    sqlx::query("INSERT INTO control_events VALUES(4,'install-b2','account-b','alpha_tab.updated',?,'account-b','2026-01-02T00:00:00Z')")
        .bind(payload.to_string()).execute(&mut source).await.unwrap();
    sqlx::query("UPDATE alpha_tab_installs SET event_id='install-b2',consented_declaration=? WHERE account_id='account-b'")
        .bind(original).execute(&mut source).await.unwrap();
    source.close().await.unwrap();
    let report = run(f.options(&["secret", "note"], true)).await.unwrap();
    assert!(report.refusals.is_empty() && report.review.is_empty());
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_app_package_sources")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(
        count, 1,
        "equivalent declarations must share one frozen full pin"
    );
    let retained: String = sqlx::query_scalar("SELECT json_extract(row_json,'$.consented_declaration') FROM kernel_app_installs WHERE principal=?")
        .bind(&report.principals["account-b"]).fetch_one(db.pool()).await.unwrap();
    assert_eq!(retained, original);
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn native_apps_offboarding_advances_generation_and_rejoin_cannot_restore_it() {
    let f = Fixture::new().await;
    let (db, report) = native_install_fixture(&f).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let closed = k::workspace_metadata::import_as(
        &db,
        &host,
        k::workspace_metadata::WorkspaceMetadata {
            name: "fixture".into(),
            source_root_id: crate::schema::ROOT_RECORD_ID.into(),
            summary: None,
        },
    )
    .await
    .unwrap_err();
    assert!(closed.to_string().contains("source import"), "{closed}");
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    app_roster(&db, "account-b", &["account-b"]).await;
    // SAFETY: synthetic host operation fences a and protects b as recipient.
    let operation = unsafe {
        k::hosted_identity::offboarding::VerifiedOffboarding::from_catalog_unchecked(
            uuid::Uuid::new_v4().to_string(),
            "account-b".into(),
            "account-a".into(),
            "account-b".into(),
            "fixture offboarding".into(),
        )
    };
    k::hosted_identity::offboarding::apply(&db, operation)
        .await
        .unwrap();
    let generation: String = sqlx::query_scalar("SELECT id FROM content_events WHERE type='kernel.hosted_offboarding.v1' ORDER BY seq DESC LIMIT 1").fetch_one(db.pool()).await.unwrap();
    assert_ne!(generation, "install");
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let state: (String, String, bool, String) = sqlx::query_as(
        "SELECT generation,status,executable,refusal FROM kernel_app_installs WHERE principal=?",
    )
    .bind(&report.principals["account-a"])
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        state,
        (generation, "removed".into(), false, "offboarded".into())
    );
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn native_apps_deleted_custody_cannot_activate_source_or_consent() {
    let f = Fixture::new().await;
    let (db, _) = native_install_fixture(&f).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let (origin, raw): (String, String) =
        sqlx::query_as("SELECT origin,payload FROM kernel_app_state WHERE record_id='secret'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let mut state: k::app_state::RetainedAppState = serde_json::from_str(&raw).unwrap();
    state.source_deleted = true;
    k::app_state::import_as(&db, &host, "secret", &origin, &state)
        .await
        .unwrap();
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let sources: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_app_package_sources")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(sources, 0);
    let executable: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_app_installs WHERE executable=1 OR refusal IS NOT 'unsupported_on_v2'").fetch_one(db.pool()).await.unwrap();
    assert_eq!(executable, 0);
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

fn native_app_hosted_caller(
    account: &str,
    pin: &k::app_installs::InstallRequest,
    adopting: bool,
) -> crate::mcp::registry::Caller {
    use crate::mcp::registry::{Caller, VerifiedAlphaTabPreview};
    let caller = Caller::authenticated(account).with_hosting_context(account, "hq-fixture");
    // SAFETY: this synthetic caller represents a verified same-origin cookie
    // request; no public tool arguments can construct this session authority.
    let caller = unsafe { caller.with_verified_hosting_session("fixture-cookie-session") };
    let authority = VerifiedAlphaTabPreview::for_pin(
        account,
        &pin.package,
        &pin.version,
        &pin.digest,
        &pin.artifact_id,
        &pin.source_revision,
        crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&pin.declaration).unwrap(),
        vec![],
        vec![],
    );
    if adopting {
        caller.with_verified_alpha_tab_adopt(authority)
    } else {
        caller.with_verified_alpha_tab_preview(authority)
    }
}

#[tokio::test]
async fn native_apps_hosted_review_adopts_new_member_with_live_delivery_guards() {
    let f = Fixture::new().await;
    let body = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Review fixture</title></head><body><main>Sample only</main></body></html>"#;
    let (db, report) = native_install_fixture_with_body(&f, body).await;
    let a = &report.principals["account-a"];
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    k::rehome_record_as(&db, a, "secret", KERNEL_ROOT_ID)
        .await
        .unwrap();
    app_roster(&db, "account-c", &["account-a", "account-b", "account-c"]).await;
    let c = k::resolve_principal_by_binding(&db, "account-c")
        .await
        .unwrap()
        .unwrap()
        .0;
    let pins = k::app_installs::frozen_sources_as(&db, &c).await.unwrap();
    assert_eq!(pins.len(), 1);
    let mut pin = k::app_installs::InstallRequest {
        package: pins[0]["package"].as_str().unwrap().into(),
        version: pins[0]["version"].as_str().unwrap().into(),
        digest: pins[0]["digest"].as_str().unwrap().into(),
        artifact_id: "secret".into(),
        source_revision: "source".into(),
        declaration: serde_json::from_str(pins[0]["consented_declaration"].as_str().unwrap())
            .unwrap(),
        reason: "Review the frozen app independently".into(),
        request: None,
        idempotency_key: Some("member-install".into()),
        expected_install_event_id: None,
    };
    let staged = k::app_installs::install_as(&db, &c, pin.clone())
        .await
        .unwrap();
    let entry = k::app_installs::inspect_as(&db, &c, &pin.package)
        .await
        .unwrap();
    assert_eq!(entry["install"]["adoption"], "caller_asserted");
    assert_eq!(
        entry["install"]["launch_binding"]["delivery"],
        "reusable.v1"
    );
    assert_eq!(entry["install"]["resolves"], false);
    pin.expected_install_event_id = Some(staged.generation.clone());
    pin.idempotency_key = None;
    let preview_caller = native_app_hosted_caller("account-c", &pin, false);
    assert!(k::app_installs::preview_as(
        &db,
        &c,
        &crate::mcp::registry::Caller::authenticated("account-c"),
        pin.clone()
    )
    .await
    .is_err());
    let preview = k::app_installs::preview_as(&db, &c, &preview_caller, pin.clone())
        .await
        .unwrap();
    assert_eq!(preview.body, body);
    let mut tx = db.write_pool().begin().await.unwrap();
    assert!(k::app_installs::bundle_source_on(
        &mut tx,
        &preview_caller,
        &pin.package,
        &staged.generation,
        &pin.digest,
        None
    )
    .await
    .is_err());
    assert_eq!(
        k::app_installs::bundle_source_on(
            &mut tx,
            &preview_caller,
            &pin.package,
            &staged.generation,
            &pin.digest,
            Some(&preview.receipt.receipt_id)
        )
        .await
        .unwrap()
        .0,
        body
    );
    tx.rollback().await.unwrap();
    let mut adopt = k::app_installs::AdoptRequest {
        pin: pin.clone(),
        receipt_id: preview.receipt.receipt_id.clone(),
        nonce: preview.receipt.nonce.clone(),
        preview_session: preview.receipt.preview_session.clone(),
    };
    adopt.pin.idempotency_key = Some("member-adopt".into());
    let adopt_caller = native_app_hosted_caller("account-c", &pin, true);
    let app_caller = adopt_caller.clone().with_host_asserted_app(
        crate::mcp::app_attribution::AppAttribution::new(
            &pin.package,
            &pin.version,
            &staged.generation,
        )
        .unwrap(),
    );
    assert!(
        k::app_installs::adopt_as(&db, &c, &app_caller, adopt.clone())
            .await
            .is_err()
    );

    // A current roster drop must revoke admission even without offboarding.
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    assert!(
        k::app_installs::adopt_as(&db, &c, &adopt_caller, adopt.clone())
            .await
            .is_err()
    );
    app_roster(&db, "account-c", &["account-a", "account-b", "account-c"]).await;
    let adopted = k::app_installs::adopt_as(&db, &c, &adopt_caller, adopt.clone())
        .await
        .unwrap();
    assert!(adopted.outcome.changed);
    assert_ne!(adopted.outcome.generation, staged.generation);
    assert_eq!(adopted.install["adoption"], "shell_adopt.v1");
    let retry = k::app_installs::adopt_as(&db, &c, &adopt_caller, adopt.clone())
        .await
        .unwrap();
    assert!(!retry.outcome.changed);
    assert_eq!(retry.outcome.generation, adopted.outcome.generation);
    let mut tx = db.write_pool().begin().await.unwrap();
    assert!(k::app_installs::bundle_source_on(
        &mut tx,
        &preview_caller,
        &pin.package,
        &staged.generation,
        &pin.digest,
        Some(&preview.receipt.receipt_id)
    )
    .await
    .is_err());
    assert_eq!(
        k::app_installs::bundle_source_on(
            &mut tx,
            &adopt_caller,
            &pin.package,
            &adopted.outcome.generation,
            &pin.digest,
            None
        )
        .await
        .unwrap()
        .0,
        body
    );
    tx.rollback().await.unwrap();
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let mut tx = db.write_pool().begin().await.unwrap();
    assert!(k::app_installs::bundle_source_on(
        &mut tx,
        &adopt_caller,
        &pin.package,
        &adopted.outcome.generation,
        &pin.digest,
        None
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    assert!(k::app_installs::adopt_as(&db, &c, &adopt_caller, adopt)
        .await
        .is_err());
    app_roster(&db, "account-c", &["account-a", "account-b", "account-c"]).await;
    // Losing source View blocks URL reads; withdrawal remains available.
    k::rehome_record_as(&db, a, "secret", &report.homes["private"])
        .await
        .unwrap();
    let mut tx = db.write_pool().begin().await.unwrap();
    assert!(k::app_installs::bundle_source_on(
        &mut tx,
        &adopt_caller,
        &pin.package,
        &adopted.outcome.generation,
        &pin.digest,
        None
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    k::app_installs::remove_as(&db, &c, &pin.package, &adopted.outcome.generation)
        .await
        .unwrap();
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn native_apps_cold_bundle_handle_is_physically_read_only_and_never_prepares() {
    let f = Fixture::new().await;
    let (db, report) = native_install_fixture(&f).await;
    assert!(crate::db::open_marked_v2_database_read_only_at(&f.source)
        .await
        .is_err());
    // Import already prepares its target. Model an older/incomplete marked
    // generation separately, without changing the valid serving fixture.
    let unprepared_path = f._dir.path().join("unprepared.db");
    let (unprepared, _) = k::create_v2_database(
        unprepared_path.to_str().unwrap(),
        "account",
        "Cold-open fixture",
        "cold-open-account",
    )
    .await
    .unwrap();
    sqlx::query("DROP TABLE kernel_app_install_outcomes")
        .execute(unprepared.write_pool())
        .await
        .unwrap();
    unprepared.close().await;
    assert!(
        crate::db::open_marked_v2_database_read_only_at(&unprepared_path)
            .await
            .is_err()
    );
    let mut observer = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&unprepared_path)
            .read_only(true),
    )
    .await
    .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM sqlite_schema WHERE name='kernel_app_install_outcomes'"
        )
        .fetch_one(&mut observer)
        .await
        .unwrap(),
        0,
        "cold admission must not recreate a missing projection"
    );
    observer.close().await.unwrap();
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let cold = crate::db::open_marked_v2_database_read_only_at(&f.target)
        .await
        .unwrap();
    assert_eq!(
        k::read_record_as(&cold, &report.principals["account-a"], "secret")
            .await
            .unwrap(),
        k::read_record_as(&db, &report.principals["account-a"], "secret")
            .await
            .unwrap()
    );
    for pool in [cold.pool(), cold.write_pool(), cold.governed_pool()] {
        // query_only is toggleable; physical SQLITE_OPEN_READONLY is not.
        let mut connection = pool.acquire().await.unwrap();
        sqlx::query("PRAGMA query_only=OFF")
            .execute(&mut *connection)
            .await
            .unwrap();
        let error = sqlx::query("DELETE FROM kernel_app_state")
            .execute(&mut *connection)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("8")
        );
    }
    cold.close().await;
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn native_apps_delivery_refuses_an_unavailable_frozen_kit() {
    let f = Fixture::new().await;
    let body = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Unavailable kit</title><script type="application/json" id="native-app-kit">{"schema":"native.app-kit.v1","major":65535}</script></head><body><main>Review</main></body></html>"#;
    let manifest = crate::artifact_html::validate_cached(body).unwrap();
    assert!(manifest.require_available_kit().is_err());
    let (db, report) = native_install_fixture_with_body(&f, body).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let pins = k::app_installs::frozen_sources_as(&db, &report.principals["account-a"])
        .await
        .unwrap();
    let pin = k::app_installs::InstallRequest {
        package: "agent.docs".into(),
        version: "0.8.2".into(),
        digest: pins[0]["digest"].as_str().unwrap().into(),
        artifact_id: "secret".into(),
        source_revision: "source".into(),
        declaration: serde_json::from_str(pins[0]["consented_declaration"].as_str().unwrap())
            .unwrap(),
        reason: "Review frozen kit compatibility".into(),
        request: None,
        idempotency_key: None,
        expected_install_event_id: Some("install".into()),
    };
    let caller = native_app_hosted_caller("account-a", &pin, false);
    assert!(k::app_installs::preview_as(
        &db,
        &report.principals["account-a"],
        &caller,
        pin.clone()
    )
    .await
    .is_err());
    let mut tx = db.write_pool().begin().await.unwrap();
    assert!(k::app_installs::bundle_source_on(
        &mut tx,
        &caller,
        &pin.package,
        "install",
        &pin.digest,
        None
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn native_app_writes_use_user_authority_and_atomic_private_attribution() {
    use crate::mcp::{
        app_attribution::AppAttribution,
        registry::{Caller, EngineHandle, ToolRegistry},
    };
    let f = Fixture::new().await;
    let body = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>App action</title></head><body><main>Sample</main></body></html>"#;
    let (db, report) = native_install_fixture_with_body(&f, body).await;
    let actor = &report.principals["account-a"];
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let caller = Caller::authenticated("account-a")
        .with_host_asserted_app(AppAttribution::new("agent.docs", "0.8.2", "install").unwrap());
    let note = k::read_record_as(&db, actor, "note")
        .await
        .unwrap()
        .unwrap();
    let args = json!({"id":"note", "body_set":"saved by a native app", "if_body_digest":crate::mcp::tools::lifecycle::body_digest(note.body.as_deref()), "idempotency_key":"app-save", "reason":"Save a guarded app draft"});
    let source_before = k::read_record_as(&db, actor, "secret")
        .await
        .unwrap()
        .unwrap();
    let before_refusal = k::dump_all_kernel_tables(&db).await.unwrap();
    assert!(registry.call_engine(EngineHandle::KernelV2(db.clone()), caller.clone(), "update_record", json!({"id":"secret", "body_set":"unattested replacement", "if_body_digest":crate::mcp::tools::lifecycle::body_digest(source_before.body.as_deref()), "reason":"Must refuse an unattested artifact write"})).await.is_err());
    assert_eq!(
        before_refusal,
        k::dump_all_kernel_tables(&db).await.unwrap(),
        "a refused artifact write leaves neither effects nor attribution"
    );
    let saved = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller.clone(),
            "update_record",
            args.clone(),
        )
        .await
        .unwrap();
    assert_eq!(saved["app_attribution"]["package"], "agent.docs");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_app_actions")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);
    let outputs: String = sqlx::query_scalar("SELECT outputs_json FROM kernel_app_actions")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let outputs: Vec<Value> = serde_json::from_str(&outputs).unwrap();
    assert!(!outputs.is_empty());
    let (admission_act, completion_act): (i64, i64) = sqlx::query_as("SELECT s.act,c.act FROM kernel_app_actions a JOIN content_events s ON s.id=a.admitted_event_id JOIN content_events c ON c.id=a.event_id WHERE a.event_id=?")
        .bind(saved["app_attribution"]["event_id"].as_str().unwrap()).fetch_one(db.pool()).await.unwrap();
    assert_eq!(admission_act, completion_act);
    assert!(
        saved.get("act").is_none(),
        "non-owner counter fencing must remain intact"
    );
    for output in outputs {
        let (written_by, act): (String, i64) =
            sqlx::query_as("SELECT actor,act FROM content_events WHERE id=?")
                .bind(output["event_id"].as_str().unwrap())
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(&written_by, actor);
        assert_eq!(act, admission_act);
    }
    let retry = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller.clone(),
            "update_record",
            args.clone(),
        )
        .await
        .unwrap();
    assert_eq!(retry, saved);
    assert!(
        registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                Caller::authenticated("account-a"),
                "update_record",
                args.clone()
            )
            .await
            .is_err(),
        "ordinary calls cannot replay an app receipt"
    );
    let raw_intent: String = sqlx::query_scalar("SELECT request_json FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation='update_record' AND operation_key='app-save'").bind(actor).fetch_one(db.pool()).await.unwrap();
    let mut forged: Value = serde_json::from_str(&raw_intent).unwrap();
    forged["idempotency_key"] = json!("app-save");
    assert!(
        registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                Caller::authenticated("account-a"),
                "update_record",
                forged
            )
            .await
            .is_err(),
        "tool arguments cannot spoof the stored app identity envelope"
    );
    let before_noop = k::read_record_as(&db, actor, "note")
        .await
        .unwrap()
        .unwrap();
    let noop = registry.call_engine(EngineHandle::KernelV2(db.clone()), caller.clone(), "update_record", json!({"id":"note", "body_set":before_noop.body, "if_body_digest":crate::mcp::tools::lifecycle::body_digest(before_noop.body.as_deref()), "idempotency_key":"app-noop", "reason":"Confirm an already saved draft"})).await.unwrap();
    assert_eq!(noop["changed"], false);
    assert_eq!(noop["effect"], "unchanged");
    assert!(
        noop.get("write_receipt").is_none(),
        "private admission is not a data write receipt"
    );
    assert_eq!(
        before_noop.revision,
        k::read_record_as(&db, actor, "note")
            .await
            .unwrap()
            .unwrap()
            .revision
    );
    let noop_outputs: String =
        sqlx::query_scalar("SELECT outputs_json FROM kernel_app_actions WHERE event_id=?")
            .bind(noop["app_attribution"]["event_id"].as_str().unwrap())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&noop_outputs).unwrap(),
        json!([])
    );
    let source_after = k::read_record_as(&db, actor, "secret")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        source_before.revision, source_after.revision,
        "private app actions cannot advance the public source clock"
    );
    let read = json!({"ids":["note"], "children_limit":0, "include_history_summary":false, "include_citations":false, "include_suggestions":false});
    let mut held_slots = Vec::new();
    for _ in 0..4 {
        held_slots.push(db.write_pool().acquire().await.unwrap());
    }
    let read_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        registry.call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller.clone(),
            "get_record",
            read.clone(),
        ),
    )
    .await
    .expect("an app read must complete with only one available pool slot");
    assert!(read_result.is_ok(), "{read_result:?}");
    drop(held_slots);
    app_roster(&db, "account-b", &["account-b"]).await;
    assert!(registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller.clone(),
            "get_record",
            read.clone()
        )
        .await
        .is_err());
    assert!(
        registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                caller.clone(),
                "update_record",
                args.clone()
            )
            .await
            .is_err(),
        "a retained executable bit cannot override a roster drop"
    );
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    assert_eq!(
        registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                caller.clone(),
                "update_record",
                args.clone()
            )
            .await
            .unwrap(),
        saved
    );
    let sql = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller.clone(),
            "query_sql",
            json!({"sql":"SELECT id FROM records WHERE id = 'note'"}),
        )
        .await
        .unwrap();
    assert!(sql.to_string().contains("note"));
    let note = k::read_record_as(&db, actor, "note")
        .await
        .unwrap()
        .unwrap();
    let ordinary_args = json!({"id":"note", "body_set":"saved by the user", "if_body_digest":crate::mcp::tools::lifecycle::body_digest(note.body.as_deref()), "idempotency_key":"user-save", "reason":"Save a user draft"});
    let ordinary = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("account-a"),
            "update_record",
            ordinary_args.clone(),
        )
        .await
        .unwrap();
    assert!(ordinary.get("app_attribution").is_none());
    assert!(
        registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                caller.clone(),
                "update_record",
                ordinary_args
            )
            .await
            .is_err(),
        "apps cannot replay ordinary user receipts"
    );
    // Ordinary user authority can archive the app source. Both reads and
    // already accepted success receipts must then refuse app admission.
    registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("account-a"),
            "archive_record",
            json!({"id":"secret", "reason":"Retire the source"}),
        )
        .await
        .unwrap();
    assert!(registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller.clone(),
            "get_record",
            read
        )
        .await
        .is_err());
    assert!(registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller,
            "update_record",
            args
        )
        .await
        .is_err());
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(before.app_actions.len(), 2);
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(
        before,
        k::dump_all_kernel_tables(&db).await.unwrap(),
        "historical action witnesses survive current source revocation"
    );
    db.close().await;
}

#[tokio::test]
async fn native_app_transaction_refuses_removal_after_dispatch_preflight() {
    use crate::mcp::{app_attribution::AppAttribution, registry::Caller};
    let f = Fixture::new().await;
    let body = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Consent race</title></head><body><main>Sample</main></body></html>"#;
    let (db, report) = native_install_fixture_with_body(&f, body).await;
    let actor = &report.principals["account-a"];
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let app = AppAttribution::new("agent.docs", "0.8.2", "install").unwrap();
    k::app_installs::admit_account_app_as(&db, "account-a", &app)
        .await
        .unwrap();
    let caller = Caller::authenticated("account-a").with_host_asserted_app(app);
    let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
        &caller,
        "update_record",
        &json!({"id":"note"}),
        None,
    );
    k::app_installs::remove_as(&db, actor, "agent.docs", "install")
        .await
        .unwrap();
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    dispatch
        .scope(async {
            assert!(
                k::read_record_as(&db, actor, "note").await.is_err(),
                "read snapshots must not reuse dispatch preflight consent"
            );
            let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
            let result = k::app_installs::start_app_action_in(
                &db,
                &mut tx,
                actor,
                "update_record",
                "ab".repeat(32),
                None,
                &mut crate::act::ActAllocation::new(),
            )
            .await;
            assert!(
                result.is_err(),
                "removal between dispatch preflight and mutation must refuse"
            );
            tx.rollback().await.unwrap();
        })
        .await;
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn native_apps_hosted_review_uses_h3_catalogue_to_imported_account_mapping() {
    let f = Fixture::new().await;
    let body = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Mapped review</title></head><body><main>Sample</main></body></html>"#;
    let (db, report) = native_install_fixture_with_body(&f, body).await;
    let a = &report.principals["account-a"];
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::hosted_identity::import_accounts(
        &db,
        &host,
        vec![("mapped@example.test".into(), "account-a".into())],
    )
    .await
    .unwrap();
    let admitted = k::hosted_identity::reconcile_hosted_caller(&db, |_| async {
        // SAFETY: complete synthetic catalogue, independently named from the
        // imported binding; its verified email pins the existing principal.
        Ok(unsafe {
            k::hosted_identity::VerifiedHostedMembership::from_catalog_unchecked(
                "catalogue-user".into(),
                BTreeMap::from([("catalogue-user".into(), "mapped@example.test".into())]),
                BTreeMap::new(),
            )
        })
    })
    .await
    .unwrap();
    assert_eq!(admitted.credential(), "account-a");
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let pins = k::app_installs::frozen_sources_as(&db, a).await.unwrap();
    let pin = k::app_installs::InstallRequest {
        package: "agent.docs".into(),
        version: "0.8.2".into(),
        digest: pins[0]["digest"].as_str().unwrap().into(),
        artifact_id: "secret".into(),
        source_revision: "source".into(),
        declaration: serde_json::from_str(pins[0]["consented_declaration"].as_str().unwrap())
            .unwrap(),
        reason: "Review through the pinned imported identity".into(),
        request: None,
        idempotency_key: None,
        expected_install_event_id: Some("install".into()),
    };
    let caller = native_app_hosted_caller("account-a", &pin, false)
        .with_hosting_context("catalogue-user", "hq-fixture");
    // SAFETY: the synthetic same-origin cookie belongs to the freshly
    // admitted catalogue identity, whose binding was resolved above.
    let caller = unsafe { caller.with_verified_hosting_session("fixture-cookie-session") };
    let mut tx = db.write_pool().begin().await.unwrap();
    assert_eq!(
        k::app_installs::bundle_source_on(
            &mut tx,
            &caller,
            &pin.package,
            "install",
            &pin.digest,
            None
        )
        .await
        .unwrap()
        .0,
        body
    );
    tx.rollback().await.unwrap();
    let preview = k::app_installs::preview_as(&db, a, &caller, pin.clone())
        .await
        .unwrap();
    assert_eq!(preview.receipt.account_id, "account-a");
    let wrong = caller
        .clone()
        .with_hosting_context("other-catalogue-user", "hq-fixture");
    // SAFETY: deliberately mismatched catalogue identity models a bad trusted
    // adapter; kernel mapping admission must independently refuse it.
    let wrong = unsafe { wrong.with_verified_hosting_session("fixture-cookie-session") };
    assert!(k::app_installs::preview_as(&db, a, &wrong, pin.clone())
        .await
        .is_err());
    let adopting = native_app_hosted_caller("account-a", &pin, true)
        .with_hosting_context("catalogue-user", "hq-fixture");
    // SAFETY: same verified synthetic cookie and exact pin as the preview.
    let adopting = unsafe { adopting.with_verified_hosting_session("fixture-cookie-session") };
    let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
        &adopting,
        "manage_alpha_tabs",
        &json!({"action":"adopt","package":"agent.docs"}),
        None,
    );
    // Hosted dispatch owns a provenance scope, but native consent must never
    // query or create v1 provenance tables while committing its kernel facts.
    let result = dispatch
        .scope(k::app_installs::adopt_as(
            &db,
            a,
            &adopting,
            k::app_installs::AdoptRequest {
                pin,
                receipt_id: preview.receipt.receipt_id,
                nonce: preview.receipt.nonce,
                preview_session: preview.receipt.preview_session,
            },
        ))
        .await
        .unwrap();
    assert_eq!(result.install["adoption"], "shell_adopt.v1");
    assert_ne!(result.outcome.generation, "install");
    db.close().await;
}

async fn native_data_fixture() -> (Fixture, Db, super::super::Report) {
    let f = Fixture::new().await;
    let body = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Declared data</title></head><body><main>Sample</main></body></html>"#;
    let (db, report) = native_install_fixture_with_body(&f, body).await;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    (f, db, report)
}

fn native_data_request() -> crate::realtime::v2::AppDataRequest {
    crate::realtime::v2::AppDataRequest {
        package: "agent.docs".into(),
        expected_install_event_id: "install".into(),
        need: None,
        params: json!({}),
    }
}

#[tokio::test]
async fn native_app_data_rechecks_roster_source_and_declared_needs() {
    use crate::mcp::{kernel_v2::NativeAppDataNeeds, Caller};
    use crate::realtime::v2::AppDataNeeds;
    let (_f, db, report) = native_data_fixture().await;
    let evaluator = NativeAppDataNeeds;
    // Scheduler callers have no transport cookie/catalogue context.
    let caller = Caller::authenticated("account-a");
    let request = native_data_request();
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let evaluated = evaluator.evaluate(&db, &caller, &request).await.unwrap();
    assert_eq!(evaluated.gate.principal, report.principals["account-a"]);
    assert!(evaluated.gate.executable);
    assert_eq!(evaluated.gate.surface.adoption, "shell_adopt.v1");
    assert_eq!(evaluated.result["input"]["records"], json!([]));
    assert_eq!(evaluated.result["input"]["inputs"], json!({}));
    assert!(!evaluated.time_dependent);
    assert_eq!(
        evaluated.gate,
        evaluator.revalidate(&db, &caller, &request).await.unwrap()
    );
    assert_eq!(
        before,
        k::dump_all_kernel_tables(&db).await.unwrap(),
        "evaluation is read only"
    );
    for changed in [
        crate::realtime::v2::AppDataRequest {
            need: Some("undeclared.sql".into()),
            ..request.clone()
        },
        crate::realtime::v2::AppDataRequest {
            params: json!({"record":"secret"}),
            ..request.clone()
        },
        crate::realtime::v2::AppDataRequest {
            expected_install_event_id: "stale".into(),
            ..request.clone()
        },
    ] {
        assert!(evaluator.evaluate(&db, &caller, &changed).await.is_err());
        assert!(evaluator.revalidate(&db, &caller, &changed).await.is_err());
    }
    let wrong_app = caller.clone().with_host_asserted_app(
        crate::mcp::app_attribution::AppAttribution::new("agent.spaces", "0.7.0", "install")
            .unwrap(),
    );
    assert!(evaluator.evaluate(&db, &wrong_app, &request).await.is_err());
    assert!(evaluator
        .evaluate(&db, &Caller::authenticated("account-b"), &request)
        .await
        .is_err());
    app_roster(&db, "account-b", &["account-b"]).await;
    let retained: bool =
        sqlx::query_scalar("SELECT executable FROM kernel_app_installs WHERE principal=?")
            .bind(&report.principals["account-a"])
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(retained, "a roster update does not run offboarding cleanup");
    assert!(evaluator.evaluate(&db, &caller, &request).await.is_err());
    assert!(evaluator.revalidate(&db, &caller, &request).await.is_err());
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    assert_eq!(
        evaluated.gate,
        evaluator.revalidate(&db, &caller, &request).await.unwrap()
    );
    assert_eq!(
        evaluated.result,
        evaluator
            .evaluate(&db, &caller, &request)
            .await
            .unwrap()
            .result,
        "unrelated roster positions do not become data revision clocks"
    );
    ordinary_kernel_call(
        &db,
        "account-a",
        "archive_record",
        json!({"id":"secret","archived":true,"reason":"Retire source"}),
    )
    .await
    .unwrap();
    assert!(evaluator.evaluate(&db, &caller, &request).await.is_err());
    assert!(evaluator.revalidate(&db, &caller, &request).await.is_err());
    db.close().await;
}

#[tokio::test]
async fn native_app_data_subscription_pins_gate_and_cleans_failed_admission() {
    use crate::mcp::{kernel_v2::NativeAppDataNeeds, Caller, EngineHandle, ToolRegistry};
    use crate::need_subscriptions::SubscriptionId;
    use crate::realtime::RealtimeHub;
    let (_f, db, _report) = native_data_fixture().await;
    let (db, hub) = RealtimeHub::attach(db, None).await.unwrap();
    hub.refresh_scheduler_handle(&db);
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let caller = Caller::authenticated("account-a");
    let base =
        json!({"action":"live_read","package":"agent.docs","expected_install_event_id":"install"});
    let call = |caller: Caller, args: Value| {
        registry.call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller,
            "manage_alpha_tabs",
            args,
        )
    };
    assert!(call(caller.clone(), base.clone())
        .await
        .unwrap_err()
        .to_string()
        .contains("evaluator_unavailable"));
    hub.set_app_data_needs(std::sync::Arc::new(NativeAppDataNeeds));
    let token = hub.need_registry().lock().unwrap().register_connection(
        "account-a",
        hub.database_identity(),
        true,
    );
    let mut args = base.clone();
    args["subscribe"] = json!({"stream":token.to_hex()});
    let read = call(caller.clone(), args.clone()).await.unwrap();
    let id = SubscriptionId::from_wire(read["subscription"]["id"].as_str().unwrap());
    let state = hub
        .need_registry()
        .lock()
        .unwrap()
        .subscription_state(&token, &id)
        .unwrap();
    assert!(
        state.app_data_gate.is_some(),
        "W6c's immutable gate is pinned before activation"
    );
    assert!(!state.clock_replay_safe);
    // A drop and rejoin entirely between frame checks is not represented in
    // the pinned gate. This is acceptable only for today's rows=[] snapshot.
    let first_check = hub
        .check_app_data_subscription(&Caller::authenticated("account-a"), &token, &id)
        .await
        .unwrap();
    assert_eq!(first_check.result["input"]["records"], json!([]));
    app_roster(&db, "account-b", &["account-b"]).await;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let second_check = hub
        .check_app_data_subscription(&Caller::authenticated("account-a"), &token, &id)
        .await
        .unwrap();
    assert_eq!(first_check.gate, second_check.gate);
    assert_eq!(first_check.result, second_check.result);
    assert_eq!(second_check.result["input"]["records"], json!([]));
    let unchanged = call(caller.clone(), {
        let mut args = base.clone();
        args["if_revision"] = read["revision"]["revision_digest"].clone();
        args
    })
    .await
    .unwrap();
    assert_eq!(unchanged["unchanged"], true);
    assert!(unchanged.get("input").is_none());
    // Another member cannot unsubscribe a connection they do not own.
    call(
        Caller::authenticated("account-b"),
        json!({"action":"live_unsubscribe","stream":token.to_hex(),"subscription":id.as_str()}),
    )
    .await
    .unwrap();
    assert!(hub
        .need_registry()
        .lock()
        .unwrap()
        .subscription_state(&token, &id)
        .is_some());
    // A malformed stream only refuses subscription; the authorized pull succeeds.
    let mut malformed = base.clone();
    malformed["subscribe"] = json!({"stream":"bad-token"});
    let pull = call(caller.clone(), malformed).await.unwrap();
    assert!(pull.get("subscription").is_none());
    assert_eq!(pull["subscribe_refused"], "stream_unknown");
    // Admission registered a pending slot, but source failure must release it.
    ordinary_kernel_call(
        &db,
        "account-a",
        "archive_record",
        json!({"id":"secret","archived":true,"reason":"Revoke source"}),
    )
    .await
    .unwrap();
    assert!(call(caller.clone(), args).await.is_err());
    assert!(hub
        .check_app_data_subscription(&caller, &token, &id)
        .await
        .is_err());
    assert!(hub
        .need_registry()
        .lock()
        .unwrap()
        .subscription_state(&token, &id)
        .is_none());
    // Existing W6c quotas prove failed pending admission left no invisible slot.
    assert_eq!(
        hub.need_registry()
            .lock()
            .unwrap()
            .connection_subscription_count(&token),
        0
    );
    db.close().await;
}

#[tokio::test]
async fn native_app_data_offboarding_cannot_resurrect_consent_on_rejoin() {
    use crate::mcp::{kernel_v2::NativeAppDataNeeds, Caller};
    use crate::realtime::v2::AppDataNeeds;
    let (_f, db, _report) = native_data_fixture().await;
    let caller = Caller::authenticated("account-a");
    let request = native_data_request();
    assert!(NativeAppDataNeeds
        .evaluate(&db, &caller, &request)
        .await
        .is_ok());
    app_roster(&db, "account-b", &["account-b"]).await;
    // SAFETY: synthetic current catalogue fences a, with b as recipient.
    let operation = unsafe {
        k::hosted_identity::offboarding::VerifiedOffboarding::from_catalog_unchecked(
            uuid::Uuid::new_v4().to_string(),
            "account-b".into(),
            "account-a".into(),
            "account-b".into(),
            "fixture offboarding".into(),
        )
    };
    k::hosted_identity::offboarding::apply(&db, operation)
        .await
        .unwrap();
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    assert!(NativeAppDataNeeds
        .evaluate(&db, &caller, &request)
        .await
        .is_err());
    assert!(NativeAppDataNeeds
        .revalidate(&db, &caller, &request)
        .await
        .is_err());
    db.close().await;
}
