use super::*;

// Trusted test ingress mints the same exact invocation binding as hosted H2.
fn gesture_caller(caller: crate::mcp::Caller, request: &Value) -> crate::mcp::Caller {
    use crate::awareness::{
        effect_gesture_binding_ids, EffectGestureKind, HumanInteractionTokenIssuer,
        EFFECT_GESTURE_ACTION,
    };
    let invocation: native_artifact_runtime::artifact_intents::ArtifactInvocation =
        serde_json::from_value(request.clone()).unwrap();
    let issuer = HumanInteractionTokenIssuer::random("w7-native-intent-audit");
    let kind = EffectGestureKind::Click;
    let ids = effect_gesture_binding_ids(
        caller.credential(),
        &invocation.artifact_id,
        invocation
            .alpha_install_guard
            .as_ref()
            .map(|guard| ("alpha", guard.package.as_str())),
        invocation
            .alpha_install_guard
            .as_ref()
            .map(|guard| guard.expected_install_event_id.as_str()),
        &invocation.entry_id,
        &invocation.slots.values().cloned().collect::<Vec<_>>(),
        &invocation.idempotency_key,
        &crate::mcp::tools::artifact_interactions::invocation_values_digest(&invocation),
        kind,
    );
    let token = issuer
        .issue(caller.credential(), EFFECT_GESTURE_ACTION, &ids, 300)
        .unwrap();
    caller
        .with_effect_gesture_token(&issuer, token, kind)
        .with_effect_gesture_enforcement(true)
}

async fn assert_gesture_origin(db: &Db, key: &str) {
    let payload: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE json_extract(payload,'$.origin.idempotency_key')=? ORDER BY seq DESC LIMIT 1")
        .bind(key).fetch_one(db.pool()).await.unwrap();
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(
        payload["origin"]["gesture_evidence"],
        json!({"kind":"click","verifier":"effect_gesture.v1"})
    );
}

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
async fn native_app_artifact_and_attachment_reads_use_current_consent_and_data_visibility() {
    let f = Fixture::new().await;
    native_install_source(&f, r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Reader</title></head><body><main>Sample</main></body></html>"#).await;
    let body = r#"export const nativeArtifact = {
        schema: 'native.mdx.artifact.v2', inputs: {}, module_inputs: {}, capability_requests: [],
        interactions: [{ id: 'create_task', label: 'Create task', effect: 'record.create',
            create: { destination: { from: 'literal', record_id: 'private' }, shape: {
                type: { source: { from: 'literal', value: 'WorkItem' }, domain: { kind: 'enum', values: ['WorkItem'] } },
                kind: { source: { from: 'literal', value: 'task' }, domain: { kind: 'enum', values: ['task'] } },
                fields: { name: { label: 'Title', source: { from: 'input', input: 'title' }, domain: { kind: 'string', min_length: 1, max_length: 80 } } }
            } }
        }]
    }

<p>Visible artifact</p>"#;
    let attested = crate::mcp::tools::artifacts::artifact_source_attestation_payload(
        "note",
        "reader-attestation",
        "created:note",
        body,
        json!({"artifact_ports":{},"imports":[],"module_inputs":{},"capability_requests":[]}),
    )
    .unwrap();
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    // Both users can run the same frozen app, while its data artifact is
    // independently private. The attachment uploader has no extra View.
    source.execute("UPDATE records SET home_id='native:root',policy_anchor_id='native:root' WHERE id='secret'; DELETE FROM links WHERE source_id='secret' AND relationship='part_of'; DELETE FROM canvas_objects; DELETE FROM canvas_batches;
        UPDATE records SET kind='artifact',home_id='private',policy_anchor_id='private',owner_id='person-a' WHERE id='note';
        ALTER TABLE artifact_source_attestations ADD COLUMN source_sha256 TEXT; ALTER TABLE artifact_source_attestations ADD COLUMN attestation_sha256 TEXT; ALTER TABLE artifact_source_attestations ADD COLUMN event_seq INTEGER; ALTER TABLE artifact_source_attestations ADD COLUMN created_at TEXT;
        INSERT INTO facet_values VALUES('note','runtime','native.mdx.v2',NULL,NULL,'2026-01-01T00:00:00Z'); INSERT INTO facet_observations VALUES('note','runtime','2026-01-01T00:00:00Z',1);").await.unwrap();
    sqlx::query("UPDATE records SET body=? WHERE id='note'")
        .bind(body)
        .execute(&mut source)
        .await
        .unwrap();
    sqlx::query("UPDATE content_events SET payload=? WHERE id='created:note'")
        .bind(json!({"body":body}).to_string())
        .execute(&mut source)
        .await
        .unwrap();
    let seq: i64 = sqlx::query_scalar("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('reader-attestation','note','artifact.source_attested',?,'account-a','2026-02-02T00:00:00Z') RETURNING seq")
        .bind(serde_json::to_string(&attested).unwrap()).fetch_one(&mut source).await.unwrap();
    sqlx::query("INSERT INTO artifact_source_attestations(artifact_id,attestation_event_id,source_event_id,source_sha256,descriptor,attestation_sha256,event_seq,created_at) VALUES('note','reader-attestation','created:note',?,?,?,?,?)")
        .bind(native_artifact_runtime::mdx::sha256_hex(body.as_bytes()))
        .bind(serde_json::to_string(&attested.artifact_source).unwrap()).bind(&attested.attestation_sha256)
        .bind(seq).bind("2026-02-02T00:00:00Z").execute(&mut source).await.unwrap();
    source.close().await.unwrap();
    add_derived_attachment(&f, "reader-attachment", "note", "person-b").await;
    let mut options = f.options(&["secret", "note", "reader-attachment"], false);
    options.history = true;
    let report = run(options).await.unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    assert!(report.app_state.capture_complete);
    let db = f.db().await;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let head: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1").fetch_one(db.pool()).await.unwrap();
    let capsule: i64 =
        sqlx::query_scalar("SELECT event_seq FROM kernel_app_state WHERE record_id='note'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    // SAFETY: this synthetic source is frozen and completely captured.
    let proof = unsafe {
        k::artifact_closures::VerifiedArtifactClosure::from_verified_import_unchecked(
            serde_json::from_str(&head).unwrap(),
            "ab".repeat(32),
            "note".into(),
            capsule,
        )
    };
    k::artifact_closures::activate_as(&db, &host, proof)
        .await
        .unwrap();
    let mut registry = crate::mcp::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let caller = |account: &str, generation: &str| {
        crate::mcp::Caller::authenticated(account).with_host_asserted_app(
            crate::mcp::app_attribution::AppAttribution::new("agent.docs", "0.8.2", generation)
                .unwrap(),
        )
    };
    let engine = || crate::mcp::EngineHandle::KernelV2(db.clone());
    let a = caller("account-a", "install");
    let b = caller("account-b", "install-b");
    // Prove B's install admission succeeds independently of data visibility.
    let source_read = registry
        .call_engine(engine(), b.clone(), "get_record", json!({"ids":["secret"]}))
        .await
        .unwrap();
    assert_eq!(source_read["records"][0]["status"], "found");
    let before: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let rendered = registry
        .call_engine(engine(), a.clone(), "render_artifact", json!({"id":"note"}))
        .await
        .unwrap();
    assert_eq!(rendered["status"], "rendered", "{rendered}");
    assert_eq!(rendered["plan"]["kind"], "safe_tree");
    let hidden = registry
        .call_engine(engine(), b.clone(), "render_artifact", json!({"id":"note"}))
        .await
        .unwrap();
    assert_eq!(hidden["status"], "error");
    assert_eq!(hidden["diagnostic"]["code"], "artifact_unavailable");
    assert!(hidden.get("plan").is_none());
    assert!(!hidden.to_string().contains("Visible artifact"));
    let read = registry
        .call_engine(
            engine(),
            a.clone(),
            "read_attachment",
            json!({"attachment_id":"reader-attachment"}),
        )
        .await
        .unwrap();
    assert_eq!(read["content"], "Derivedneedle bytes");
    for tool in ["read_attachment", "manage_attachments"] {
        let args = if tool == "read_attachment" {
            json!({"attachment_id":"reader-attachment"})
        } else {
            json!({"action":"inspect","attachment_id":"reader-attachment"})
        };
        assert!(
            registry
                .call_engine(engine(), b.clone(), tool, args)
                .await
                .is_err(),
            "{tool} must use bearer-derived View"
        );
    }
    let listed = registry
        .call_engine(
            engine(),
            a.clone(),
            "manage_attachments",
            json!({"action":"list","record_id":"note"}),
        )
        .await
        .unwrap();
    assert_eq!(listed["attachments"].as_array().unwrap().len(), 1);
    assert!(registry
        .call_engine(
            engine(),
            b.clone(),
            "manage_attachments",
            json!({"action":"list","record_id":"note"})
        )
        .await
        .is_err());
    assert_eq!(
        before,
        sqlx::query_scalar::<_, i64>("SELECT max(seq) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    );
    // The app invokes an exact attested interaction as the user, with
    // attribution and effects in the same transaction. Its installation does
    // not grant access to another member's private artifact or destination.
    let invocation = json!({
        "version":"native.artifact-invocation.v1", "artifact_id":"note",
        "entry_id":"create_task", "source_digest":native_artifact_runtime::mdx::sha256_hex(body.as_bytes()),
        "values":{"title":"Created by an app interaction"}, "idempotency_key":"app-interaction"
    });
    assert!(registry
        .call_engine(
            engine(),
            b,
            "invoke_artifact_interaction",
            invocation.clone()
        )
        .await
        .is_err());
    assert_eq!(
        before,
        sqlx::query_scalar::<_, i64>("SELECT max(seq) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    );
    let committed = registry
        .call_engine(
            engine(),
            gesture_caller(a.clone(), &invocation),
            "invoke_artifact_interaction",
            invocation.clone(),
        )
        .await
        .unwrap();
    assert_eq!(committed["status"], "committed", "{committed}");
    assert_gesture_origin(&db, "app-interaction").await;
    assert_eq!(committed["app_attribution"]["package"], "agent.docs");
    let created_id = committed["changes"][0]["record_id"].as_str().unwrap();
    assert!(
        k::read_record_as(&db, &report.principals["account-a"], created_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        k::read_record_as(&db, &report.principals["account-b"], created_id)
            .await
            .unwrap()
            .is_none()
    );
    let (admitted_act, finished_act, author, created_act):(i64,i64,String,i64) = sqlx::query_as(
        "SELECT s.act,c.act,e.actor,e.act FROM kernel_app_actions a JOIN content_events s ON s.id=a.admitted_event_id JOIN content_events c ON c.id=a.event_id JOIN content_events e ON e.record_id=? AND e.type='kernel.record_created.v1' WHERE a.event_id=?"
    ).bind(created_id).bind(committed["app_attribution"]["event_id"].as_str().unwrap()).fetch_one(db.pool()).await.unwrap();
    assert_eq!(author, report.principals["account-a"]);
    assert_eq!(admitted_act, finished_act);
    assert_eq!(admitted_act, created_act);
    let committed_head: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let retry = registry
        .call_engine(
            engine(),
            a.clone(),
            "invoke_artifact_interaction",
            invocation.clone(),
        )
        .await
        .unwrap();
    assert_eq!(retry, committed);
    assert_eq!(
        committed_head,
        sqlx::query_scalar::<_, i64>("SELECT max(seq) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    );
    // The same user without this app's claim cannot replay the app receipt.
    let plain = registry
        .call_engine(
            engine(),
            crate::mcp::Caller::authenticated("account-a"),
            "invoke_artifact_interaction",
            invocation.clone(),
        )
        .await
        .unwrap();
    assert_eq!(plain["error"]["code"], "idempotency_conflict");
    // Adapter-only named-input fixture, as in the user-intent probe: current
    // app consent is still admitted by the production registry on every call.
    let facet_body = r#"export const nativeArtifact = {
        schema: 'native.mdx.artifact.v2',
        inputs: { items: { envelope: 'native.collection-envelope.v1', required: true, expose_to_root: true } },
        module_inputs: {}, capability_requests: [{ capability: 'input.read', scope: { port: 'items' } }],
        interactions: [
          { id: 'set_effort', label: 'Set effort', effect: 'facet.set',
            slots: { record: { domain: { kind: 'bound_input', port: 'items' } } },
            facet: 'effort', value: { from: 'literal', value: 'small' } },
          { id: 'unset_effort', label: 'Unset effort', effect: 'facet.unset',
            slots: { record: { domain: { kind: 'bound_input', port: 'items' } } }, facet: 'effort' },
          { id: 'start', label: 'Start', effect: 'facet.set',
            slots: { record: { domain: { kind: 'bound_input', port: 'items' } } },
            facet: 'lifecycle', value: { from: 'literal', value: 'in_progress' } }
        ]
    }

<p>Facet audit</p>"#;
    let scope = json!({"artifact_port":"items"});
    let scope_sha = native_artifact_runtime::mdx::sha256_hex(
        &native_artifact_runtime::mdx_v2::canonical_json_bytes(&scope),
    );
    sqlx::query("UPDATE kernel_artifact_closures SET source_body=?,source_sha256=?,bindings=?,grants=? WHERE artifact_id='note'")
        .bind(facet_body).bind(native_artifact_runtime::mdx::sha256_hex(facet_body.as_bytes()))
        .bind(json!([{"port_name":"items","collection_id":"private","event_seq":1}]).to_string())
        .bind(json!([{"subject_kind":"artifact_source","subject_record_id":"note","subject_event_id":"created:note","capability":"input.read","scope_sha256":scope_sha,"scope":scope.to_string()}]).to_string())
        .execute(db.write_pool()).await.unwrap();
    sqlx::query("UPDATE kernel_record_bodies SET body=? WHERE record_id='note'")
        .bind(facet_body)
        .execute(db.write_pool())
        .await
        .unwrap();
    for entry in ["set_effort", "unset_effort", "start"] {
        let facet = if entry == "start" {
            "lifecycle"
        } else {
            "effort"
        };
        let plan = registry
            .call_engine(engine(), a.clone(), "render_artifact", json!({"id":"note"}))
            .await
            .unwrap();
        assert_eq!(plan["status"], "rendered", "{plan}");
        let request = json!({"version":"native.artifact-invocation.v1","artifact_id":"note",
            "entry_id":entry,"source_digest":native_artifact_runtime::mdx::sha256_hex(facet_body.as_bytes()),
            "slots":{"record":created_id},"observed":{created_id:{facet:plan["plan"]["observed"][created_id][facet]}},
            "idempotency_key":format!("app-{entry}-audit")});
        let receipt = registry
            .call_engine(
                engine(),
                gesture_caller(a.clone(), &request),
                "invoke_artifact_interaction",
                request,
            )
            .await
            .unwrap();
        assert_eq!(receipt["status"], "committed", "{receipt}");
        assert_eq!(receipt["app_attribution"]["package"], "agent.docs");
        assert_gesture_origin(&db, &format!("app-{entry}-audit")).await;
        let (actor,effect_act,app_act):(String,i64,i64)=sqlx::query_as("SELECT e.actor,e.act,a.act FROM content_events e JOIN content_events a ON a.id=? WHERE json_extract(e.payload,'$.origin.idempotency_key')=?")
            .bind(receipt["app_attribution"]["event_id"].as_str().unwrap()).bind(format!("app-{entry}-audit")).fetch_one(db.pool()).await.unwrap();
        assert_eq!(actor, report.principals["account-a"]);
        assert_eq!(effect_act, app_act);
        if entry == "start" {
            let stored = k::read_record_as(&db, &report.principals["account-a"], created_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.fields["lifecycle"], "in_progress");
            assert!(receipt["changes"][0]["version"]
                .as_str()
                .unwrap()
                .starts_with("rec:"));
        }
    }
    k::app_installs::remove_as(
        &db,
        &report.principals["account-a"],
        "agent.docs",
        "install",
    )
    .await
    .unwrap();
    for (tool, args) in [
        ("invoke_artifact_interaction", invocation),
        ("render_artifact", json!({"id":"note"})),
        (
            "read_attachment",
            json!({"attachment_id":"reader-attachment"}),
        ),
        (
            "manage_attachments",
            json!({"action":"list","record_id":"note"}),
        ),
    ] {
        assert!(
            registry
                .call_engine(engine(), a.clone(), tool, args)
                .await
                .is_err(),
            "{tool} must refuse after removal, including a warm render cache"
        );
    }
}

#[tokio::test]
async fn native_artifact_borne_attachment_imports_with_bearer_visibility_on_every_surface() {
    let f = Fixture::new().await;
    seed(&f).await;
    // Its stale public policy and different uploader must not override the
    // private artifact's terminal-bearer authority.
    add_derived_attachment(&f, "artifact-attachment", "secret", "person-b").await;
    let mut options = f.options(&["secret", "note", "artifact-attachment"], false);
    options.history = true;
    let report = run(options).await.unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    assert_eq!(report.imported["Document/artifact"], 1);
    assert_eq!(report.imported["Document/attachment"], 1);
    assert!(report.verified_ids.iter().any(|id| id == "secret"));
    assert!(report
        .verified_ids
        .iter()
        .any(|id| id == "artifact-attachment"));
    assert!(report.app_state.capture_complete);
    assert_eq!(
        report.app_state.retained_rows["artifact_source_attestations"],
        1
    );
    let db = f.db().await;
    assert_private_derived_surfaces(&db, "artifact-attachment", "secret").await;
    for (account, visible) in [("account-a", true), ("account-b", false)] {
        let artifact = ordinary_kernel_call(&db, account, "get_record", json!({"ids":["secret"]}))
            .await
            .unwrap();
        assert_eq!(
            artifact["records"][0]["status"],
            if visible { "found" } else { "not_found" }
        );
        let incoming = ordinary_kernel_call(
            &db,
            account,
            "manage_links",
            json!({"action":"list","record_id":"secret"}),
        )
        .await;
        if visible {
            assert!(incoming.unwrap()["links_in"]
                .as_array()
                .unwrap()
                .iter()
                .any(|link| link["source_id"] == "artifact-attachment"));
        } else if let Ok(incoming) = incoming {
            assert!(incoming["links_in"].as_array().unwrap().is_empty());
        }
    }
    let read = ordinary_kernel_call(
        &db,
        "account-a",
        "read_attachment",
        json!({"attachment_id":"artifact-attachment"}),
    )
    .await
    .unwrap();
    assert_eq!(read["content"], "Derivedneedle bytes");
    assert!(ordinary_kernel_call(
        &db,
        "account-b",
        "read_attachment",
        json!({"attachment_id":"artifact-attachment"})
    )
    .await
    .is_err());
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    assert_private_derived_surfaces(&db, "artifact-attachment", "secret").await;
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

pub(super) async fn native_install_source(f: &Fixture, body: &str) {
    native_install_source_with_pin(f, body, "agent.docs", "0.8.2").await;
}

async fn native_install_source_with_pin(f: &Fixture, body: &str, package: &str, version: &str) {
    native_install_declared_source(
        f,
        body,
        package,
        version,
        &json!({"contract":"native.app.v2","needs":[],"effects":[]}),
    )
    .await;
}

async fn native_install_declared_source(
    f: &Fixture,
    body: &str,
    package: &str,
    version: &str,
    declaration: &Value,
) {
    seed(f).await;
    let declaration_digest =
        crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(declaration).unwrap();
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
    sqlx::query("UPDATE alpha_tab_installs SET package=?,version=?,digest=?,declaration_digest=?,consented_declaration=?")
        .bind(package).bind(version).bind(&digest).bind(&declaration_digest).bind(declaration.to_string()).execute(&mut source).await.unwrap();
    let evidence = json!({"account_id":"account-a","package":package,"version":version,"digest":digest,"artifact_id":"secret","consented_source_revision":"source","declaration_digest":declaration_digest,"consented_declaration":declaration,"adoption":"shell_adopt.v1"});
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
}

async fn native_install_fixture_with_body(f: &Fixture, body: &str) -> (Db, super::super::Report) {
    native_install_source(f, body).await;
    let report = run(f.options(&["secret", "note"], false)).await.unwrap();
    assert!(report.refusals.is_empty());
    assert!(report.review.is_empty());
    (f.db().await, report)
}

pub(super) async fn app_activation_proof(db: &Db) -> k::app_installs::VerifiedFrozenApps {
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

#[tokio::test]
async fn native_artifact_closure_requires_exact_attested_source_and_replays() {
    let f = Fixture::new().await;
    let body = "export const nativeArtifact = { schema: 'native.mdx.artifact.v2', inputs: {}, module_inputs: {}, capability_requests: [] }\n\n<p>Ready</p>";
    let digest = native_artifact_runtime::mdx::sha256_hex(body.as_bytes());
    let attested = crate::mcp::tools::artifacts::artifact_source_attestation_payload(
        "secret",
        "mdx-attestation",
        "created:secret",
        body,
        json!({"artifact_ports":{},"imports":[],"module_inputs":{},"capability_requests":[]}),
    )
    .unwrap();
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source.execute("ALTER TABLE artifact_source_attestations ADD COLUMN source_sha256 TEXT; ALTER TABLE artifact_source_attestations ADD COLUMN attestation_sha256 TEXT; ALTER TABLE artifact_source_attestations ADD COLUMN event_seq INTEGER; ALTER TABLE artifact_source_attestations ADD COLUMN created_at TEXT;").await.unwrap();
    sqlx::query("UPDATE records SET kind='artifact',body=? WHERE id='secret'")
        .bind(body)
        .execute(&mut source)
        .await
        .unwrap();
    sqlx::query("UPDATE content_events SET payload=? WHERE id='created:secret'")
        .bind(json!({"body":body}).to_string())
        .execute(&mut source)
        .await
        .unwrap();
    source.execute("INSERT INTO facet_values VALUES('secret','runtime','native.mdx.v2',NULL,NULL,'2026-01-01T00:00:00Z'); INSERT INTO facet_observations VALUES('secret','runtime','2026-01-01T00:00:00Z',1);").await.unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('mdx-attestation','secret','artifact.source_attested',?,'account-a','2026-02-02T00:00:00Z')")
        .bind(serde_json::to_string(&attested).unwrap()).execute(&mut source).await.unwrap();
    let seq: i64 = sqlx::query_scalar("SELECT seq FROM content_events WHERE id='mdx-attestation'")
        .fetch_one(&mut source)
        .await
        .unwrap();
    sqlx::query("INSERT INTO artifact_source_attestations(artifact_id,attestation_event_id,source_event_id,source_sha256,descriptor,attestation_sha256,event_seq,created_at) VALUES('secret','mdx-attestation','created:secret',?,?,?,?,?)")
        .bind(&digest)
        .bind(serde_json::to_string(&attested.artifact_source).unwrap())
        .bind(&attested.attestation_sha256)
        .bind(seq)
        .bind("2026-02-02T00:00:00Z")
        .execute(&mut source).await.unwrap();
    source.execute("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id,deleted_at) VALUES('private-task','WorkItem','task','zzz private task','Private work','private','person-a','open','', '2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'private',NULL); INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('created:private-task','private-task','record.created','{}','account-a','2026-01-01T00:00:00Z');").await.unwrap();
    source.execute("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id,deleted_at) VALUES('hidden-child','WorkItem','task','Never expose this child','Hidden child body','private','person-a','open','', '2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'hidden-child',NULL); INSERT INTO record_policies VALUES('hidden-child'); INSERT INTO policy_entries VALUES('hidden-child','account','account-a','manage'); INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('created:hidden-child','hidden-child','record.created','{}','account-a','2026-01-01T00:00:00Z');").await.unwrap();
    source.close().await.unwrap();
    let mut options = f.options(&["secret", "private-task", "hidden-child", "note"], false);
    options.history = true;
    let report = run(options).await.unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    let db = f.db().await;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let head: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1")
        .fetch_one(db.pool()).await.unwrap();
    let capsule_seq: i64 =
        sqlx::query_scalar("SELECT event_seq FROM kernel_app_state WHERE record_id='secret'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let proof = || unsafe {
        k::artifact_closures::VerifiedArtifactClosure::from_verified_import_unchecked(
            serde_json::from_str(&head).unwrap(),
            "ab".repeat(32),
            "secret".into(),
            capsule_seq,
        )
    };
    k::artifact_closures::activate_as(&db, &host, proof())
        .await
        .unwrap();
    k::artifact_closures::activate_as(&db, &host, proof())
        .await
        .unwrap();
    let member = k::resolve_principal_by_binding(&db, "account-a")
        .await
        .unwrap()
        .unwrap()
        .0;
    let rendered = crate::mcp::kernel_v2::artifacts::render(&db, &member, json!({"id":"secret"}))
        .await
        .unwrap();
    assert_eq!(rendered["status"], "rendered");
    assert_eq!(rendered["plan"]["kind"], "safe_tree");
    assert_eq!(rendered["plan"]["provenance"]["record_id"], "secret");
    assert_eq!(rendered["plan"]["provenance"]["body_sha256"], digest);
    assert!(rendered["plan"]["provenance"]["render_sha256"]
        .as_str()
        .is_some_and(|value| value.len() == 64));
    assert_eq!(rendered["plan"]["cache"]["state"], "miss");
    let other = k::resolve_principal_by_binding(&db, "account-b")
        .await
        .unwrap()
        .unwrap()
        .0;
    let hidden = crate::mcp::kernel_v2::artifacts::render(&db, &other, json!({"id":"secret"}))
        .await
        .unwrap();
    assert_eq!(hidden["status"], "error");
    assert_eq!(hidden["diagnostic"]["code"], "artifact_unavailable");
    let before: (String,String,String) = sqlx::query_as("SELECT source_event_id,source_sha256,source_body FROM kernel_artifact_closures WHERE artifact_id='secret'")
        .fetch_one(db.pool()).await.unwrap();
    assert_eq!(before, ("created:secret".into(), digest, body.into()));
    k::replay_all_projections(&db).await.unwrap();
    let after: (String,String,String) = sqlx::query_as("SELECT source_event_id,source_sha256,source_body FROM kernel_artifact_closures WHERE artifact_id='secret'")
        .fetch_one(db.pool()).await.unwrap();
    assert_eq!(after, before);
    // Adapter-only fixture: replace the already verified projection with a
    // synthetic named-input closure. The activation test above separately
    // proves that ordinary callers cannot create this projection.
    let input_body = "export const nativeArtifact = { schema: 'native.mdx.artifact.v2', inputs: { items: { envelope: 'native.collection-envelope.v1', required: true, expose_to_root: true } }, module_inputs: {}, capability_requests: [{ capability: 'input.read', scope: { port: 'items' } }] }\n\n<p>{native.inputs.items.records.length}</p>";
    let input_digest = native_artifact_runtime::mdx::sha256_hex(input_body.as_bytes());
    let scope = json!({"artifact_port":"items"});
    let scope_sha = native_artifact_runtime::mdx::sha256_hex(
        &native_artifact_runtime::mdx_v2::canonical_json_bytes(&scope),
    );
    sqlx::query("UPDATE kernel_artifact_closures SET source_body=?,source_sha256=?,bindings=?,grants=? WHERE artifact_id='secret'")
        .bind(input_body).bind(&input_digest)
        .bind(json!([{"port_name":"items","collection_id":"private","event_seq":1}]).to_string())
        .bind(json!([{"subject_kind":"artifact_source","subject_record_id":"secret","subject_event_id":"created:secret","capability":"input.read","scope_sha256":scope_sha,"scope":scope.to_string()}]).to_string())
        .execute(db.write_pool()).await.unwrap();
    sqlx::query("UPDATE kernel_record_bodies SET body=? WHERE record_id='secret'")
        .bind(input_body)
        .execute(db.write_pool())
        .await
        .unwrap();
    let with_input = crate::mcp::kernel_v2::artifacts::render(&db, &member, json!({"id":"secret"}))
        .await
        .unwrap();
    assert_eq!(with_input["status"], "rendered", "{with_input:#}");
    assert_eq!(with_input["input"]["ports"], json!(["items"]));
    // A deterministic write during compilation must invalidate only actual
    // inputs, not every render in a busy workspace.
    for (id, expected) in [("note", "rendered"), ("private-task", "error")] {
        let captured = std::sync::Arc::new(tokio::sync::Notify::new());
        let resume = std::sync::Arc::new(tokio::sync::Notify::new());
        let rendering = crate::mcp::kernel_v2::artifacts::RENDER_PAUSE.scope(
            (captured.clone(), resume.clone()),
            crate::mcp::kernel_v2::artifacts::render(&db, &member, json!({"id":"secret"})),
        );
        let write = async {
            captured.notified().await;
            let outcome = ordinary_kernel_call(&db, "account-a", "update_record", json!({
                "id":id,"name":"Changed during compilation","reason":"Exercise render dependencies",
                "idempotency_key":format!("render-concurrent-{id}")
            })).await;
            resume.notify_one();
            outcome.unwrap();
        };
        let (rendered, ()) = tokio::join!(rendering, write);
        let rendered = rendered.unwrap();
        assert_eq!(rendered["status"], expected, "{id}: {rendered:#}");
        if expected == "error" {
            assert_eq!(rendered["diagnostic"]["code"], "artifact_snapshot_changed");
        }
    }

    let changed = sqlx::query("UPDATE kernel_record_fields SET value_json='\"query\"' WHERE record_id='private' AND name='v1_kind'")
        .execute(db.write_pool()).await.unwrap();
    assert_eq!(changed.rows_affected(), 1);
    sqlx::query("INSERT INTO kernel_facets(record_id,key,value,value_num,vocab_ref,as_of,event_seq) VALUES('private','query',?,NULL,NULL,'2026-01-01T00:00:00Z',1)")
        .bind(json!({"v":"0.2","query":{"steps":[{"step":"filter","home_id":"private","types":["Document"]}],"order":"name_asc"}}).to_string())
        .execute(db.write_pool()).await.unwrap();
    let saved_query =
        crate::mcp::kernel_v2::artifacts::render(&db, &member, json!({"id":"secret"}))
            .await
            .unwrap();
    assert_eq!(saved_query["status"], "rendered", "{saved_query:#}");
    let relation_body = input_body
        .replace(
            "native.collection-envelope.v1",
            "native.relation-envelope.v1",
        )
        .replace(
            "native.inputs.items.records.length",
            "native.inputs.items.relation.rows.length",
        );
    sqlx::query("UPDATE kernel_artifact_closures SET source_body=?,source_sha256=? WHERE artifact_id='secret'")
        .bind(&relation_body)
        .bind(native_artifact_runtime::mdx::sha256_hex(relation_body.as_bytes()))
        .execute(db.write_pool()).await.unwrap();
    sqlx::query("UPDATE kernel_record_bodies SET body=? WHERE record_id='secret'")
        .bind(&relation_body)
        .execute(db.write_pool())
        .await
        .unwrap();
    let relation = crate::mcp::kernel_v2::artifacts::render(&db, &member, json!({"id":"secret"}))
        .await
        .unwrap();
    assert_eq!(relation["status"], "rendered", "{relation:#}");
    let columns = json!([
        {"name":"id","type":"identifier","nullable":false},
        {"name":"name","type":"text","nullable":true}
    ]);
    let schema_sha = native_artifact_runtime::mdx::sha256_hex(
        &native_artifact_runtime::mdx_v2::canonical_json_bytes(&columns),
    );
    let records_relation = crate::query::sql_contract::LOGICAL_RELATIONS
        .iter()
        .find(|relation| relation.name == "records")
        .unwrap();
    let governed = json!({
        "v":"1.1","kind":"governed_sql",
        "profile":{"id":"sqlite-local","revision":1},
        "catalog_revision":crate::query::sql_contract::LOGICAL_CATALOG_REVISION,
        "relations":{"records":{"identity":records_relation.identity,"semantic_version":records_relation.semantic_version}},
        "sql":"SELECT id,name FROM records WHERE id='secret' ORDER BY id ASC",
        "parameters":[],
        "output":{"columns":columns,"schema_sha256":schema_sha,"row_identity":["id"],"order":[{"column":"id","direction":"asc"}]},
        "bounds":{"rows":10}
    });
    sqlx::query("UPDATE kernel_facets SET value=? WHERE record_id='private' AND key='query'")
        .bind(governed.to_string())
        .execute(db.write_pool())
        .await
        .unwrap();
    let governed_body = relation_body.replace(
        "required: true",
        &format!("schema_sha256: '{schema_sha}', required: true"),
    );
    sqlx::query("UPDATE kernel_artifact_closures SET source_body=?,source_sha256=? WHERE artifact_id='secret'")
        .bind(&governed_body)
        .bind(native_artifact_runtime::mdx::sha256_hex(governed_body.as_bytes()))
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query("UPDATE kernel_record_bodies SET body=? WHERE record_id='secret'")
        .bind(&governed_body)
        .execute(db.write_pool())
        .await
        .unwrap();
    let governed_result =
        crate::mcp::kernel_v2::artifacts::render(&db, &member, json!({"id":"secret"}))
            .await
            .unwrap();
    assert_eq!(governed_result["status"], "rendered", "{governed_result:#}");
    // One transient governed-query timeout gets a fresh bounded attempt;
    // repeated timeouts stop after two attempts instead of looping forever.
    let (retried, attempts) = crate::mcp::kernel_v2::sql::with_stored_timeouts(
        1,
        crate::mcp::kernel_v2::artifacts::render(&db, &member, json!({"id":"secret"})),
    )
    .await;
    assert_eq!(retried.unwrap()["status"], "rendered");
    assert_eq!(attempts, 3, "two capture attempts plus input revalidation");
    let (refused, attempts) = crate::mcp::kernel_v2::sql::with_stored_timeouts(
        usize::MAX,
        crate::mcp::kernel_v2::artifacts::render(&db, &member, json!({"id":"secret"})),
    )
    .await;
    assert_eq!(refused.unwrap()["status"], "error");
    assert_eq!(attempts, 2, "the retry must be bounded");
    // Rendering, including governed SQL staging, needs no write-pool slot.
    // Holding every slot makes accidental writer-pool acquisition fail within
    // the deadline instead of silently serializing readers behind writers.
    let mut held_writers = Vec::new();
    for _ in 0..db.write_pool().options().get_max_connections() {
        held_writers.push(db.write_pool().acquire().await.unwrap());
    }
    let without_writer = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::mcp::kernel_v2::artifacts::render(&db, &member, json!({"id":"secret"})),
    )
    .await
    .expect("render must not borrow a writer")
    .unwrap();
    assert_eq!(without_writer["status"], "rendered", "{without_writer:#}");
    // Fill the snapshot pool before every governed query, on both capture and
    // revalidation. A nested acquisition from that same pool would deadlock.
    let readers = db.pool().options().get_max_connections() as usize;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(readers));
    let concurrent = futures::future::join_all((0..readers).map(|_| {
        crate::mcp::kernel_v2::artifacts::GOVERNED_QUERY_PAUSE.scope(
            barrier.clone(),
            crate::mcp::kernel_v2::artifacts::render(&db, &member, json!({"id":"secret"})),
        )
    }));
    let concurrent = tokio::time::timeout(std::time::Duration::from_secs(30), concurrent)
        .await
        .expect("concurrent renders must not reacquire their snapshot pool");
    for rendered in concurrent {
        let rendered = rendered.unwrap();
        assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    }
    drop(held_writers);

    let captured = std::sync::Arc::new(tokio::sync::Notify::new());
    let resume = std::sync::Arc::new(tokio::sync::Notify::new());
    let rendering = crate::mcp::kernel_v2::artifacts::RENDER_PAUSE.scope(
        (captured.clone(), resume.clone()),
        crate::mcp::kernel_v2::artifacts::render(&db, &member, json!({"id":"secret"})),
    );
    let write = async {
        captured.notified().await;
        let outcome = ordinary_kernel_call(&db, "account-a", "update_record", json!({
            "id":"note","name":"Another unrelated write","reason":"Exercise governed row revalidation",
            "idempotency_key":"governed-concurrent-note"
        })).await;
        resume.notify_one();
        outcome.unwrap();
    };
    let (rendered, ()) = tokio::join!(rendering, write);
    assert_eq!(rendered.unwrap()["status"], "rendered");

    let styled_body = governed_body.replace(
        "\n\n<p>",
        "\nexport const nativeStyles = \".card { color: red }\"\n\n<p>",
    );
    let parsed_styles = native_artifact_runtime::mdx_v2::parse_artifact(&styled_body).unwrap();
    let style = parsed_styles.styles.unwrap();
    sqlx::query("UPDATE kernel_artifact_closures SET source_body=?,source_sha256=? WHERE artifact_id='secret'")
        .bind(&styled_body)
        .bind(native_artifact_runtime::mdx::sha256_hex(styled_body.as_bytes()))
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query("UPDATE kernel_record_bodies SET body=? WHERE record_id='secret'")
        .bind(&styled_body)
        .execute(db.write_pool())
        .await
        .unwrap();
    let styled = crate::mcp::kernel_v2::artifacts::render_with_database(
        &db,
        &member,
        Some("hq"),
        json!({"id":"secret"}),
    )
    .await
    .unwrap();
    assert_eq!(styled["status"], "rendered", "{styled:#}");
    assert_eq!(
        styled["plan"]["provenance"]["body_sha256"],
        native_artifact_runtime::mdx::sha256_hex(styled_body.as_bytes())
    );
    assert_eq!(styled["plan"]["styles"]["digest"], style.sha256);
    assert_eq!(
        styled["plan"]["styles"]["href"],
        format!(
            "/workbench/databases/hq/artifacts/secret/styles/{}.css",
            style.sha256
        )
    );
    assert_eq!(
        crate::mcp::kernel_v2::artifacts::stylesheet(&db, &member, "secret", &style.sha256)
            .await
            .unwrap(),
        Some(style.css)
    );
    assert!(
        crate::mcp::kernel_v2::artifacts::stylesheet(&db, &other, "secret", &style.sha256)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        crate::mcp::kernel_v2::artifacts::stylesheet(&db, &member, "secret", &"0".repeat(64))
            .await
            .unwrap()
            .is_none()
    );
    // A declared control must not make the entire document unreadable while
    // its v2 write transaction is unavailable, and it must not look enabled.
    let interactive_body = input_body.replace(
        "module_inputs: {},",
        r#"module_inputs: {}, interactions: [{
            id: 'set_effort', label: 'Set effort', effect: 'facet.set',
            slots: {
                record: { domain: { kind: 'bound_input', port: 'items' } },
                choice: { domain: { kind: 'values', values: ['small', 'large'] } }
            },
            facet: 'effort', value: { from: 'slot', slot: 'choice' }
        }],"#,
    );
    sqlx::query("UPDATE kernel_artifact_closures SET source_body=?,source_sha256=? WHERE artifact_id='secret'")
        .bind(&interactive_body)
        .bind(native_artifact_runtime::mdx::sha256_hex(interactive_body.as_bytes()))
        .execute(db.write_pool()).await.unwrap();
    sqlx::query("UPDATE kernel_record_bodies SET body=? WHERE record_id='secret'")
        .bind(&interactive_body)
        .execute(db.write_pool())
        .await
        .unwrap();
    // Restore a folder Collection; the fixture's saved-query relation body is
    // intentionally not the declaration being exercised here.
    sqlx::query("UPDATE kernel_record_fields SET value_json='\"folder\"' WHERE record_id='private' AND name='v1_kind'")
        .execute(db.write_pool()).await.unwrap();
    let interactive =
        crate::mcp::kernel_v2::artifacts::render(&db, &member, json!({"id":"secret"}))
            .await
            .unwrap();
    assert_eq!(interactive["status"], "rendered", "{interactive:#}");
    assert_eq!(interactive["plan"]["interactions"][0]["id"], "set_effort");
    assert_eq!(
        interactive["plan"]["interaction_availability"]["supported_entries"],
        json!(["set_effort"])
    );
    let target = interactive["plan"]["interaction_availability"]["records_by_port"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|id| id.as_str() == Some("private-task"))
        .unwrap()
        .as_str()
        .unwrap();
    let observed = interactive["plan"]["observed"][target]["effort"]
        .as_str()
        .unwrap();
    let mut observed_map = serde_json::Map::new();
    observed_map.insert(target.to_owned(), json!({"effort":observed}));
    let request = json!({
        "version":"native.artifact-invocation.v1","artifact_id":"secret",
        "entry_id":"set_effort","source_digest":native_artifact_runtime::mdx::sha256_hex(interactive_body.as_bytes()),
        "slots":{"record":target},"values":{"choice":"small"},
        "observed":observed_map,"idempotency_key":"facet-probe",
    });
    let committed = crate::mcp::kernel_v2::intents::invoke(
        &db,
        &gesture_caller(crate::mcp::Caller::authenticated("account-a"), &request),
        &member,
        request.clone(),
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");
    assert_eq!(committed["changes"][0]["record_id"], target);
    assert_eq!(committed["changes"][0]["after"], "small");
    assert_gesture_origin(&db, "facet-probe").await;
    let committed_head: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let replay = crate::mcp::kernel_v2::intents::invoke(
        &db,
        &crate::mcp::Caller::local(),
        &member,
        request.clone(),
    )
    .await
    .unwrap();
    assert_eq!(replay, committed);
    let replay_head: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(replay_head, committed_head);
    let mut reused = request.clone();
    reused["values"]["choice"] = json!("large");
    let reused_result =
        crate::mcp::kernel_v2::intents::invoke(&db, &crate::mcp::Caller::local(), &member, reused)
            .await
            .unwrap();
    assert_eq!(reused_result["error"]["code"], "idempotency_conflict");
    let mut stale = request.clone();
    stale["idempotency_key"] = json!("facet-stale");
    stale["values"]["choice"] = json!("large");
    let conflicted =
        crate::mcp::kernel_v2::intents::invoke(&db, &crate::mcp::Caller::local(), &member, stale)
            .await
            .unwrap();
    assert_eq!(conflicted["status"], "conflict", "{conflicted:#}");
    assert_eq!(
        conflicted["current_version"],
        committed["changes"][0]["version"]
    );
    let mut outside = request.clone();
    outside["idempotency_key"] = json!("facet-outside");
    outside["slots"]["record"] = json!("outside-bound-input");
    let outside_result =
        crate::mcp::kernel_v2::intents::invoke(&db, &crate::mcp::Caller::local(), &member, outside)
            .await
            .unwrap();
    assert_eq!(outside_result["status"], "rejected");
    assert_eq!(outside_result["error"]["code"], "outside_bound_input");
    let hidden = crate::mcp::kernel_v2::intents::invoke(
        &db,
        &crate::mcp::Caller::local(),
        &other,
        request.clone(),
    )
    .await;
    assert!(hidden.is_err());
    // View on an artifact/input collection grants neither Edit nor View on
    // a record with its own boundary, even when filed inside that collection.
    let private_home = k::hq::v1_import_home_id("private");
    k::replace_home_policy(
        &db,
        &member,
        &private_home,
        &[(&member, "manage"), (&other, "view")],
    )
    .await
    .unwrap();
    let visible = crate::mcp::kernel_v2::artifacts::render(&db, &other, json!({"id":"secret"}))
        .await
        .unwrap();
    assert_eq!(visible["status"], "rendered", "{visible:#}");
    assert!(!visible.to_string().contains("hidden-child"));
    assert!(!visible.to_string().contains("Never expose this child"));
    assert!(k::read_record_as(&db, &other, "private-task")
        .await
        .unwrap()
        .is_some());
    assert!(
        k::read_record_as(&db, &member, "hidden-child")
            .await
            .unwrap()
            .is_some(),
        "the hidden child is retained and readable by its owner"
    );
    assert!(k::read_record_as(&db, &other, "hidden-child")
        .await
        .unwrap()
        .is_none());
    let mut view_only = request.clone();
    view_only["idempotency_key"] = json!("facet-view-only");
    view_only["observed"] = visible["plan"]["observed"].clone();
    let view_only = crate::mcp::kernel_v2::intents::invoke(
        &db,
        &crate::mcp::Caller::local(),
        &other,
        view_only,
    )
    .await;
    assert!(view_only.is_err(), "View must never imply Edit");
    let mut hidden_child = request.clone();
    hidden_child["idempotency_key"] = json!("facet-hidden-child");
    hidden_child["slots"]["record"] = json!("hidden-child");
    hidden_child["observed"] = json!({"hidden-child":{"effort":"obs:0"}});
    let hidden_child = crate::mcp::kernel_v2::intents::invoke(
        &db,
        &crate::mcp::Caller::local(),
        &other,
        hidden_child,
    )
    .await
    .unwrap();
    assert_eq!(hidden_child["error"]["code"], "outside_bound_input");
    k::replace_home_policy(&db, &member, &private_home, &[(&member, "manage")])
        .await
        .unwrap();
    // A retained attestation is not authority to invoke after a type change.
    sqlx::query("UPDATE kernel_record_fields SET value_json='\"note\"' WHERE record_id='secret' AND name='v1_kind'").execute(db.write_pool()).await.unwrap();
    let mut changed_kind = request.clone();
    changed_kind["idempotency_key"] = json!("facet-changed-kind");
    let changed_kind = crate::mcp::kernel_v2::intents::invoke(
        &db,
        &crate::mcp::Caller::local(),
        &member,
        changed_kind,
    )
    .await
    .unwrap();
    assert_eq!(changed_kind["error"]["code"], "artifact_source_unavailable");
    sqlx::query("UPDATE kernel_record_fields SET value_json='\"artifact\"' WHERE record_id='secret' AND name='v1_kind'").execute(db.write_pool()).await.unwrap();
    // Governed inputs must also work inside the invocation's write transaction,
    // without borrowing a second write connection or losing its row authority.
    let governed_interactive = interactive_body
        .replacen("inputs: {", &format!("inputs: {{ stats: {{ envelope: 'native.relation-envelope.v1', schema_sha256: '{schema_sha}', required: true, expose_to_root: true }},"), 1)
        .replace("capability_requests: [", "capability_requests: [{ capability: 'input.read', scope: { port: 'stats' } },")
        .replace("native.inputs.items.records.length", "native.inputs.items.records.length + native.inputs.stats.relation.rows.length");
    native_artifact_runtime::mdx_v2::parse_artifact(&governed_interactive)
        .expect("the fixture preserves the v1 collection-operand / relation-context contract");
    let original_grants: String = sqlx::query_scalar(
        "SELECT grants FROM kernel_artifact_closures WHERE artifact_id='secret'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let mut invocation_grants: Vec<Value> = serde_json::from_str(&original_grants).unwrap();
    let stats_scope = json!({"artifact_port":"stats"});
    invocation_grants.push(json!({
        "subject_kind":"artifact_source","subject_record_id":"secret","subject_event_id":"created:secret",
        "capability":"input.read","scope_sha256":native_artifact_runtime::mdx::sha256_hex(&native_artifact_runtime::mdx_v2::canonical_json_bytes(&stats_scope)),
        "scope":stats_scope.to_string()
    }));
    let mut invoked_query = governed.clone();
    invoked_query["sql"] = json!(format!(
        "SELECT id,name FROM records WHERE id='{target}' ORDER BY id ASC"
    ));
    sqlx::query("UPDATE kernel_record_fields SET value_json='\"query\"' WHERE record_id='folder' AND name='v1_kind'").execute(db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_facets(record_id,key,value,value_num,vocab_ref,as_of,event_seq) VALUES('folder','query',?,NULL,NULL,'2026-01-01T00:00:00Z',1)")
        .bind(invoked_query.to_string())
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query("UPDATE kernel_artifact_closures SET source_body=?,source_sha256=?,bindings=?,grants=? WHERE artifact_id='secret'")
        .bind(&governed_interactive).bind(native_artifact_runtime::mdx::sha256_hex(governed_interactive.as_bytes()))
        .bind(json!([{ "port_name":"items", "collection_id":"private", "event_seq":1 }, { "port_name":"stats", "collection_id":"folder", "event_seq":1 }]).to_string())
        .bind(serde_json::to_string(&invocation_grants).unwrap()).execute(db.write_pool()).await.unwrap();
    sqlx::query("UPDATE kernel_record_bodies SET body=? WHERE record_id='secret'")
        .bind(&governed_interactive)
        .execute(db.write_pool())
        .await
        .unwrap();
    let governed_plan =
        crate::mcp::kernel_v2::artifacts::render(&db, &member, json!({"id":"secret"}))
            .await
            .unwrap();
    assert_eq!(governed_plan["status"], "rendered", "{governed_plan:#}");
    let mut governed_request = request.clone();
    governed_request["idempotency_key"] = json!("facet-governed-input");
    governed_request["source_digest"] = json!(native_artifact_runtime::mdx::sha256_hex(
        governed_interactive.as_bytes()
    ));
    governed_request["observed"] = json!({target:governed_plan["plan"]["observed"][target]});
    governed_request["values"]["choice"] = json!("large");
    let mut other_writers = Vec::new();
    for _ in 1..db.write_pool().options().get_max_connections() {
        other_writers.push(db.write_pool().acquire().await.unwrap());
    }
    let governed_commit = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::mcp::kernel_v2::intents::invoke(
            &db,
            &gesture_caller(
                crate::mcp::Caller::authenticated("account-a"),
                &governed_request,
            ),
            &member,
            governed_request.clone(),
        ),
    )
    .await
    .expect("invoke must need only its own ordinary writer slot")
    .unwrap();
    drop(other_writers);
    assert_eq!(
        governed_commit["status"], "committed",
        "{governed_commit:#}"
    );
    assert_gesture_origin(&db, "facet-governed-input").await;
    sqlx::query("UPDATE kernel_record_fields SET value_json='\"folder\"' WHERE record_id='folder' AND name='v1_kind'").execute(db.write_pool()).await.unwrap();
    sqlx::query("DELETE FROM kernel_facets WHERE record_id='folder' AND key='query'")
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query(
        "UPDATE kernel_artifact_closures SET bindings=?,grants=? WHERE artifact_id='secret'",
    )
    .bind(json!([{ "port_name":"items", "collection_id":"private", "event_seq":1 }]).to_string())
    .bind(&original_grants)
    .execute(db.write_pool())
    .await
    .unwrap();
    // Unset carries the same verified audit origin as set.
    let unset_body = interactive_body
        .replace("effect: 'facet.set'", "effect: 'facet.unset'")
        .replace(", value: { from: 'slot', slot: 'choice' }", "")
        .replace(
            ",\n                choice: { domain: { kind: 'values', values: ['small', 'large'] } }",
            "",
        );
    sqlx::query("UPDATE kernel_artifact_closures SET source_body=?,source_sha256=? WHERE artifact_id='secret'")
        .bind(&unset_body).bind(native_artifact_runtime::mdx::sha256_hex(unset_body.as_bytes()))
        .execute(db.write_pool()).await.unwrap();
    sqlx::query("UPDATE kernel_record_bodies SET body=? WHERE record_id='secret'")
        .bind(&unset_body)
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut unset_request = request.clone();
    unset_request["source_digest"] = json!(native_artifact_runtime::mdx::sha256_hex(
        unset_body.as_bytes()
    ));
    unset_request["values"] = json!({});
    unset_request["idempotency_key"] = json!("facet-unset-audit");
    unset_request["observed"][target]["effort"] = governed_commit["changes"][0]["version"].clone();
    let unset_result = crate::mcp::kernel_v2::intents::invoke(
        &db,
        &gesture_caller(
            crate::mcp::Caller::authenticated("account-a"),
            &unset_request,
        ),
        &member,
        unset_request,
    )
    .await
    .unwrap();
    assert_eq!(unset_result["status"], "committed", "{unset_result:#}");
    assert_gesture_origin(&db, "facet-unset-audit").await;
    let lifecycle_body = input_body.replace(
        "module_inputs: {},",
        r#"module_inputs: {}, interactions: [{
            id: 'start', label: 'Start', effect: 'facet.set',
            slots: { record: { domain: { kind: 'bound_input', port: 'items' } } },
            facet: 'lifecycle', value: { from: 'literal', value: 'in_progress' }
        }],"#,
    );
    sqlx::query("UPDATE kernel_artifact_closures SET source_body=?,source_sha256=? WHERE artifact_id='secret'")
        .bind(&lifecycle_body)
        .bind(native_artifact_runtime::mdx::sha256_hex(lifecycle_body.as_bytes()))
        .execute(db.write_pool()).await.unwrap();
    sqlx::query("UPDATE kernel_record_bodies SET body=? WHERE record_id='secret'")
        .bind(&lifecycle_body)
        .execute(db.write_pool())
        .await
        .unwrap();
    let lifecycle_plan =
        crate::mcp::kernel_v2::artifacts::render(&db, &member, json!({"id":"secret"}))
            .await
            .unwrap();
    assert_eq!(lifecycle_plan["status"], "rendered", "{lifecycle_plan:#}");
    assert_eq!(
        lifecycle_plan["plan"]["interaction_availability"]["supported_entries"],
        json!(["start"])
    );
    let lifecycle_token = lifecycle_plan["plan"]["observed"]["private-task"]["lifecycle"]
        .as_str()
        .unwrap();
    assert!(lifecycle_token.starts_with("rec:"));
    let lifecycle_request = json!({
        "version":"native.artifact-invocation.v1","artifact_id":"secret",
        "entry_id":"start","source_digest":native_artifact_runtime::mdx::sha256_hex(lifecycle_body.as_bytes()),
        "slots":{"record":"private-task"},"observed":{"private-task":{"lifecycle":lifecycle_token}},
        "idempotency_key":"lifecycle-probe",
    });
    let lifecycle_result = crate::mcp::kernel_v2::intents::invoke(
        &db,
        &gesture_caller(
            crate::mcp::Caller::authenticated("account-a"),
            &lifecycle_request,
        ),
        &member,
        lifecycle_request.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        lifecycle_result["status"], "committed",
        "{lifecycle_result:#}"
    );
    assert_gesture_origin(&db, "lifecycle-probe").await;
    assert!(lifecycle_result["changes"][0]["version"]
        .as_str()
        .unwrap()
        .starts_with("rec:"));
    assert_eq!(
        k::read_record_as(&db, &member, "private-task")
            .await
            .unwrap()
            .unwrap()
            .fields["lifecycle"],
        "in_progress"
    );
    let create_body = input_body.replace(
        "module_inputs: {},",
        r#"module_inputs: {}, interactions: [{
            id: 'create_task', label: 'Create task', effect: 'record.create',
            create: { destination: { from: 'bound_input', port: 'items' }, shape: {
                type: { source: { from: 'literal', value: 'WorkItem' }, domain: { kind: 'enum', values: ['WorkItem'] } },
                kind: { source: { from: 'literal', value: 'task' }, domain: { kind: 'enum', values: ['task'] } },
                fields: { name: { label: 'Title', source: { from: 'input', input: 'title' }, domain: { kind: 'string', min_length: 1, max_length: 80 } } },
                facets: { stage: { source: { from: 'literal', value: 'new' }, domain: { kind: 'enum', values: ['new'] } } }
            } }
        }],"#,
    );
    sqlx::query("UPDATE kernel_artifact_closures SET source_body=?,source_sha256=? WHERE artifact_id='secret'")
        .bind(&create_body)
        .bind(native_artifact_runtime::mdx::sha256_hex(create_body.as_bytes()))
        .execute(db.write_pool()).await.unwrap();
    sqlx::query("UPDATE kernel_record_bodies SET body=? WHERE record_id='secret'")
        .bind(&create_body)
        .execute(db.write_pool())
        .await
        .unwrap();
    let create_plan =
        crate::mcp::kernel_v2::artifacts::render(&db, &member, json!({"id":"secret"}))
            .await
            .unwrap();
    assert_eq!(create_plan["status"], "rendered", "{create_plan:#}");
    assert_eq!(
        create_plan["plan"]["interaction_availability"]["supported_entries"],
        json!(["create_task"])
    );
    assert_eq!(
        create_plan["plan"]["interaction_availability"]["create_destinations"]["create_task"],
        "private"
    );
    let create_request = json!({
        "version":"native.artifact-invocation.v1","artifact_id":"secret",
        "entry_id":"create_task","source_digest":native_artifact_runtime::mdx::sha256_hex(create_body.as_bytes()),
        "values":{"title":"Created from MDX"},"idempotency_key":"create-probe",
    });
    let created = crate::mcp::kernel_v2::intents::invoke(
        &db,
        &gesture_caller(
            crate::mcp::Caller::authenticated("account-a"),
            &create_request,
        ),
        &member,
        create_request.clone(),
    )
    .await
    .unwrap();
    assert_eq!(created["status"], "committed", "{created:#}");
    let created_id = created["changes"][0]["record_id"].as_str().unwrap();
    assert!(k::read_record_as(&db, &member, created_id)
        .await
        .unwrap()
        .is_some());
    let created_payload: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id=? AND type='kernel.record_created.v1'",
    )
    .bind(created_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let created_payload: serde_json::Value = serde_json::from_str(&created_payload).unwrap();
    assert_eq!(created_payload["origin"]["artifact_id"], "secret");
    assert_eq!(
        created_payload["origin"]["source_event_id"],
        "created:secret"
    );
    assert_eq!(created_payload["origin"]["entry_id"], "create_task");
    assert_gesture_origin(&db, "create-probe").await;
    assert_eq!(created_payload["origin"]["idempotency_key"], "create-probe");
    let create_head: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let create_retry = crate::mcp::kernel_v2::intents::invoke(
        &db,
        &crate::mcp::Caller::local(),
        &member,
        create_request.clone(),
    )
    .await
    .unwrap();
    assert_eq!(create_retry, created);
    let retry_head: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(retry_head, create_head);
    let mut invalid_create = create_request.clone();
    invalid_create["idempotency_key"] = json!("invalid-create");
    invalid_create["values"]["title"] = json!("");
    let invalid_create_result = crate::mcp::kernel_v2::intents::invoke(
        &db,
        &crate::mcp::Caller::local(),
        &member,
        invalid_create,
    )
    .await
    .unwrap();
    assert_eq!(invalid_create_result["status"], "rejected");
    assert_eq!(
        invalid_create_result["error"]["code"],
        "value_outside_domain"
    );
    sqlx::query("UPDATE kernel_artifact_closures SET grants='[]' WHERE artifact_id='secret'")
        .execute(db.write_pool())
        .await
        .unwrap();
    let without_grant =
        crate::mcp::kernel_v2::artifacts::render(&db, &member, json!({"id":"secret"}))
            .await
            .unwrap();
    assert_eq!(
        without_grant["diagnostic"]["code"],
        "named_input_unavailable"
    );
    assert!(
        crate::mcp::kernel_v2::intents::invoke(
            &db,
            &crate::mcp::Caller::local(),
            &member,
            create_request,
        )
        .await
        .is_err(),
        "revoked grant must precede keyed success replay"
    );
    let old_source_retry =
        crate::mcp::kernel_v2::intents::invoke(&db, &crate::mcp::Caller::local(), &member, request)
            .await
            .unwrap();
    assert_eq!(old_source_retry["status"], "rejected");
    assert_eq!(old_source_retry["error"]["code"], "stale_source_digest");
}
pub(super) async fn app_roster(db: &Db, account: &str, accounts: &[&str]) {
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

// Use an executable frozen install, exercising the same acts-as-user admission
// as Whiteboard; the operation is intentionally not package-specific.
async fn canvas_app_call(db: &Db, args: Value) -> crate::Result<Value> {
    canvas_app_tool(db, "manage_canvas", args).await
}

async fn canvas_app_tool(db: &Db, tool: &str, args: Value) -> crate::Result<Value> {
    use crate::mcp::{Caller, EngineHandle, ToolRegistry};
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry)?;
    crate::mcp::tools::register_surface_tools(&mut registry)?;
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry)?;
    let caller = Caller::authenticated("account-a").with_host_asserted_app(
        crate::mcp::app_attribution::AppAttribution::new("agent.docs", "0.8.2", "install").unwrap(),
    );
    registry
        .call_engine(EngineHandle::KernelV2(db.clone()), caller, tool, args)
        .await
}

#[tokio::test]
async fn frozen_canvas_activation_retains_source_clock_and_rebuilds_exact_scene() {
    let f = Fixture::new().await;
    native_install_source(&f, r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Canvas app</title></head><body><main>Sample</main></body></html>"#).await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source
        .execute("UPDATE records SET kind='canvas' WHERE id='note'; DROP TABLE canvas_objects; DROP TABLE canvas_batches;")
        .await
        .unwrap();
    source.execute("CREATE TABLE canvas_objects(canvas_id TEXT,object_id TEXT,kind TEXT,x REAL,y REAL,w REAL,h REAL,z TEXT,parent_id TEXT,props TEXT,deleted INTEGER,geometry_seq INTEGER,content_seq INTEGER,created_seq INTEGER); CREATE TABLE canvas_batches(canvas_id TEXT,batch_id TEXT,actor TEXT,event_id TEXT,event_seq INTEGER,ops_sha256 TEXT,origin_kind TEXT);").await.unwrap();
    let seq: i64 = sqlx::query_scalar("SELECT seq FROM content_events WHERE id='batch-event'")
        .fetch_one(&mut source)
        .await
        .unwrap();
    let mut ops = vec![crate::canvas::Op::Create {
        object: crate::canvas::NewObject {
            id: "note-object".into(),
            kind: crate::canvas::ObjectKind::Note,
            x: 0.125,
            y: 2.0,
            w: 100.0,
            h: 50.0,
            z: "a".into(),
            parent: None,
            props: serde_json::from_value(json!({"text":"hello"})).unwrap(),
        },
    }];
    ops.push(crate::canvas::Op::Create {
        object: crate::canvas::NewObject {
            id: "private-card".into(),
            kind: crate::canvas::ObjectKind::RecordCard,
            x: 1.0,
            y: 2.0,
            w: 100.0,
            h: 50.0,
            z: "b".into(),
            parent: None,
            props: serde_json::from_value(json!({"record_id":"secret"})).unwrap(),
        },
    });
    let batch = crate::canvas::StoredBatch {
        version: crate::canvas::BATCH_VERSION.into(),
        batch_id: "batch".into(),
        base_version: None,
        origin: crate::canvas::Origin {
            kind: crate::canvas::OriginKind::Agent,
            gesture: None,
            undo_of: None,
            note: None,
        },
        ops_sha256: crate::canvas::ops_digest(&ops).unwrap(),
        ops,
        pre_images: Default::default(),
        detached: Vec::new(),
    };
    sqlx::query("UPDATE content_events SET payload=? WHERE id='batch-event'")
        .bind(serde_json::to_string(&batch).unwrap())
        .execute(&mut source)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO canvas_batches VALUES('note','batch','account-a','batch-event',?,?,'agent')",
    )
    .bind(seq)
    .bind(&batch.ops_sha256)
    .execute(&mut source)
    .await
    .unwrap();
    sqlx::query("INSERT INTO canvas_objects VALUES('note','note-object','note',0.125,2.0,100.0,50.0,'a',NULL,'{\"text\":\"hello\"}',0,?,?,?)")
        .bind(seq).bind(seq).bind(seq).execute(&mut source).await.unwrap();
    sqlx::query("INSERT INTO canvas_objects VALUES('note','private-card','record_card',1.0,2.0,100.0,50.0,'b',NULL,'{\"record_id\":\"secret\"}',0,?,?,?)")
        .bind(seq).bind(seq).bind(seq).execute(&mut source).await.unwrap();
    let mut second = batch.clone();
    second.batch_id = "batch-2".into();
    second.ops = vec![crate::canvas::Op::Create {
        object: crate::canvas::NewObject {
            id: "second-note".into(),
            kind: crate::canvas::ObjectKind::Note,
            x: 3.0,
            y: 2.0,
            w: 100.0,
            h: 50.0,
            z: "c".into(),
            parent: None,
            props: serde_json::from_value(json!({"text":"second"})).unwrap(),
        },
    }];
    second.ops_sha256 = crate::canvas::ops_digest(&second.ops).unwrap();
    let second_seq: i64 = sqlx::query_scalar("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('batch-event-2','note','canvas.batch.committed.v1',?,'account-a','2026-01-01T00:00:00Z') RETURNING seq")
        .bind(serde_json::to_string(&second).unwrap()).fetch_one(&mut source).await.unwrap();
    sqlx::query("INSERT INTO canvas_batches VALUES('note','batch-2','account-a','batch-event-2',?,?,'agent')")
        .bind(second_seq).bind(&second.ops_sha256).execute(&mut source).await.unwrap();
    sqlx::query("INSERT INTO canvas_objects VALUES('note','second-note','note',3.0,2.0,100.0,50.0,'c',NULL,'{\"text\":\"second\"}',0,?,?,?)")
        .bind(second_seq).bind(second_seq).bind(second_seq).execute(&mut source).await.unwrap();
    // The global allocation floor also includes unrelated source events. It
    // must never masquerade as this canvas's actual scene head.
    source.execute("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('unrelated-after-canvas','secret','record.updated','{}','account-a','2026-01-01T00:00:00Z')").await.unwrap();
    source.close().await.unwrap();

    let report = run(f.options(&["secret", "note"], false)).await.unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    assert!(report.app_state.capture_complete);
    let db = f.db().await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let head: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1")
        .fetch_one(db.pool()).await.unwrap();
    let capsule_seq: i64 =
        sqlx::query_scalar("SELECT event_seq FROM kernel_app_state WHERE record_id='note'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    // SAFETY: this fixture's complete source was frozen before hosted roster activation.
    let proof = || unsafe {
        k::canvas_v2::VerifiedFrozenCanvas::from_verified_import_unchecked(
            "note".into(),
            serde_json::from_str(&head).unwrap(),
            "a".repeat(64),
            capsule_seq,
        )
    };
    sqlx::query("INSERT INTO kernel_records(id,home_id,owner_id,created_seq,created_at) SELECT 'kernel:canvas:note',home_id,owner_id,created_seq,created_at FROM kernel_records WHERE id='note'")
        .execute(db.write_pool()).await.unwrap();
    assert!(k::canvas_v2::activate_as(&db, &host, proof())
        .await
        .unwrap_err()
        .to_string()
        .contains("aggregate id collision"));
    sqlx::query("DELETE FROM kernel_records WHERE id='kernel:canvas:note'")
        .execute(db.write_pool())
        .await
        .unwrap();
    assert!(ordinary_kernel_call(
        &db,
        "account-a",
        "read_canvas",
        json!({"action":"get_scene","canvas_id":"note"})
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("not activated"));
    // A retained shell with a source tombstone is never eligible for activation.
    sqlx::query("INSERT INTO kernel_import_tombstones(record_id,deleted_at,event_seq) VALUES('note','2026-01-01T00:00:00Z',1)")
        .execute(db.write_pool()).await.unwrap();
    assert!(k::canvas_v2::activate_as(&db, &host, proof())
        .await
        .unwrap_err()
        .to_string()
        .contains("not a live"));
    let activated: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kernel_canvas_activations WHERE canvas_id='note'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(activated, 0);
    sqlx::query("DELETE FROM kernel_import_tombstones WHERE record_id='note'")
        .execute(db.write_pool())
        .await
        .unwrap();
    k::canvas_v2::activate_as(&db, &host, proof())
        .await
        .unwrap();
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let scene =
        crate::canvas::load_scene(&mut db.write_pool().acquire().await.unwrap(), "note", true)
            .await
            .unwrap();
    assert_eq!(scene.len(), 3);
    assert_eq!(scene[0].x.to_bits(), 0.125_f64.to_bits());
    assert_eq!(scene[0].geometry_seq, seq);
    assert_eq!(
        crate::canvas::current_version(&mut db.write_pool().acquire().await.unwrap(), "note")
            .await
            .unwrap()
            .0,
        second_seq
    );
    for account in ["account-a", "account-b"] {
        let scene = ordinary_kernel_call(
            &db,
            account,
            "read_canvas",
            json!({"action":"get_scene","canvas_id":"note"}),
        )
        .await
        .unwrap();
        assert_eq!(scene["canvas_version"], format!("canvas:{second_seq}"));
        assert_eq!(scene["live_objects"], 3);
        let card = &scene["objects"][1];
        assert_eq!(card["versions"]["geometry"], format!("canvas:{seq}"));
        assert_eq!(
            card["props"]["record_id"],
            if account == "account-a" {
                "secret"
            } else {
                "withheld"
            }
        );
        if account == "account-a" {
            assert_eq!(card["record"]["id"], "secret");
        } else {
            assert!(card.get("record").is_none());
        }
        let changes = ordinary_kernel_call(
            &db,
            account,
            "read_canvas",
            json!({"action":"changes","canvas_id":"note","after":"canvas:0","limit":1}),
        )
        .await
        .unwrap();
        assert_eq!(changes["batches"].as_array().unwrap().len(), 1);
        assert_eq!(changes["batches"][0]["event_seq"], seq);
        assert_eq!(changes["batches"][0]["event_id"], "batch-event");
        assert_eq!(
            changes["batches"][0]["ops"][1]["object"]["props"]["record_id"],
            if account == "account-a" {
                "secret"
            } else {
                "withheld"
            }
        );
        assert_eq!(changes["more"], true);
        // The saved bundle advances by event_seq, ignoring next_after.
        let page_two = ordinary_kernel_call(&db, account, "read_canvas",
            json!({"action":"changes","canvas_id":"note","after":format!("canvas:{seq}"),"limit":1})).await.unwrap();
        assert_eq!(page_two["batches"][0]["event_seq"], second_seq);
        assert_eq!(page_two["more"], false);
        let caught_up = ordinary_kernel_call(
            &db,
            account,
            "read_canvas",
            json!({"action":"changes","canvas_id":"note","after":format!("canvas:{second_seq}")}),
        )
        .await
        .unwrap();
        assert!(caught_up["batches"].as_array().unwrap().is_empty());
        assert_eq!(caught_up["next_after"], format!("canvas:{second_seq}"));
        let described = ordinary_kernel_call(
            &db,
            account,
            "read_canvas",
            json!({"action":"describe","canvas_id":"note"}),
        )
        .await
        .unwrap();
        if account == "account-b" {
            assert!(!described.to_string().contains("secret"));
        }
        assert!(ordinary_kernel_call(
            &db,
            account,
            "read_canvas",
            json!({"action":"get_scene","canvas_id":"secret"})
        )
        .await
        .is_err());
    }
    let original_envelope = json!({"version":crate::canvas::BATCH_VERSION,"canvas_id":"note",
        "batch_id":batch.batch_id,"origin":batch.origin,"ops":batch.ops});
    let before_retry: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let replayed = canvas_app_call(
        &db,
        json!({"action":"commit_batch","batch":original_envelope}),
    )
    .await
    .unwrap();
    assert_eq!(replayed["outcome"], "replayed");
    assert_eq!(replayed["event_id"], "batch-event");
    assert_eq!(replayed["canvas_version"], format!("canvas:{seq}"));
    assert_eq!(
        before_retry,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    );
    let frozen: Value = serde_json::from_str(&head).unwrap();
    let floor = frozen["seq"].as_i64().unwrap();
    let patch = json!({"version":crate::canvas::BATCH_VERSION,"canvas_id":"note","batch_id":"native-geometry",
        "base_version":format!("canvas:{second_seq}"),"origin":{"kind":"agent","note":"Move the note"},
        "ops":[{"op":"patch","id":"note-object","expected":{"geometry":format!("canvas:{seq}")},"set":{"x":0.5}}]});
    let committed = canvas_app_call(&db, json!({"action":"commit_batch","batch":patch}))
        .await
        .unwrap();
    assert_eq!(committed["outcome"], "committed", "{committed}");
    assert_eq!(committed["app_attribution"]["package"], "agent.docs");
    assert_eq!(committed["app_attribution"]["install_event_id"], "install");
    let event_ids = [
        &committed["event_id"],
        &committed["app_attribution"]["admitted_event_id"],
        &committed["app_attribution"]["event_id"],
    ];
    let expected_actor = &report.principals["account-a"];
    let mut stored_act = None;
    for event_id in event_ids {
        let (actor, act): (String, i64) =
            sqlx::query_as("SELECT actor,act FROM content_events WHERE id=?")
                .bind(event_id.as_str().unwrap())
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(
            &actor, expected_actor,
            "the app must act as its authenticated user"
        );
        if let Some(expected) = stored_act {
            assert_eq!(
                act, expected,
                "admission, effect and attribution must share one act"
            );
        } else {
            stored_act = Some(act);
        }
    }
    assert!(
        committed.get("act").is_none(),
        "non-owner transports must retain counter redaction"
    );
    let app_scene = canvas_app_tool(
        &db,
        "read_canvas",
        json!({"action":"get_scene","canvas_id":"note"}),
    )
    .await
    .unwrap();
    assert_eq!(app_scene["objects"][0]["x"], 0.5);
    assert_eq!(app_scene["canvas_version"], committed["canvas_version"]);
    let position = floor + committed["write_receipt"]["event"]["seq"].as_i64().unwrap();
    assert!(position > floor);
    assert_eq!(committed["canvas_version"], format!("canvas:{position}"));
    assert_eq!(
        committed["objects"]["note-object"]["geometry"],
        format!("canvas:{position}")
    );
    assert_eq!(
        committed["objects"]["note-object"]["content"],
        format!("canvas:{seq}")
    );
    let mut stale = patch.clone();
    stale["batch_id"] = json!("stale-geometry");
    let before_conflict: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let conflict = canvas_app_call(&db, json!({"action":"commit_batch","batch":stale}))
        .await
        .unwrap();
    assert_eq!(conflict["outcome"], "conflict", "{conflict}");
    assert_eq!(
        conflict["conflicts"][0]["current"]["geometry"],
        format!("canvas:{position}")
    );
    let replayed = canvas_app_call(&db, json!({"action":"commit_batch","batch":patch}))
        .await
        .unwrap();
    assert_eq!(replayed["outcome"], "replayed");
    assert_eq!(replayed["event_id"], committed["event_id"]);
    assert_eq!(replayed["app_attribution"], committed["app_attribution"]);
    assert_eq!(replayed["objects"], committed["objects"]);
    let mut reused = patch;
    reused["ops"][0]["set"]["x"] = json!(0.75);
    let rejected = canvas_app_call(&db, json!({"action":"commit_batch","batch":reused}))
        .await
        .unwrap();
    assert_eq!(rejected["outcome"], "rejected");
    assert_eq!(rejected["error"]["code"], "batch_id_reused");
    assert_eq!(
        before_conflict,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    );
    let content = json!({"version":crate::canvas::BATCH_VERSION,"canvas_id":"note","batch_id":"native-content",
        "origin":{"kind":"agent"},"ops":[{"op":"patch","id":"note-object",
        "expected":{"content":format!("canvas:{seq}")},"set":{"props":{"text":"saved"}}}]});
    let saved = canvas_app_call(&db, json!({"action":"commit_batch","batch":content}))
        .await
        .unwrap();
    assert_eq!(saved["outcome"], "committed", "{saved}");
    assert_eq!(
        saved["objects"]["note-object"]["geometry"],
        format!("canvas:{position}")
    );
    let native_feed = ordinary_kernel_call(
        &db,
        "account-b",
        "read_canvas",
        json!({"action":"changes","canvas_id":"note","after":format!("canvas:{second_seq}")}),
    )
    .await
    .unwrap();
    let batches = native_feed["batches"].as_array().unwrap();
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0]["event_seq"], position);
    assert_eq!(batches[1]["canvas_version"], saved["canvas_version"]);
    assert!(batches[1]["event_seq"].as_i64().unwrap() > position);
    let home = k::read_record_as(&db, &report.principals["account-a"], "note")
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let fresh = ordinary_kernel_call(
        &db,
        "account-a",
        "create_record",
        json!({"type":"Document","kind":"canvas","name":"Fresh board","home_id":home}),
    )
    .await
    .unwrap();
    let fresh_id = fresh["id"].as_str().unwrap();
    let import_error = run(f.options(&["note"], true))
        .await
        .err()
        .expect("post-activation import must refuse");
    assert!(
        import_error.to_string().contains("activation"),
        "{import_error}"
    );
    let created: i64 = sqlx::query_scalar("SELECT created_seq FROM kernel_records WHERE id=?")
        .bind(fresh_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    // Simulate a future host path assigning a post-roster position without
    // the corresponding native creation event. It must still need activation.
    sqlx::query("UPDATE kernel_records SET created_seq=? WHERE id=?")
        .bind(created + 1)
        .bind(fresh_id)
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut snapshot = db.pool().acquire().await.unwrap();
    assert_eq!(
        k::canvas_v2::ready_on(&mut snapshot, fresh_id, i64::MAX)
            .await
            .unwrap(),
        None
    );
    drop(snapshot);
    sqlx::query("UPDATE kernel_records SET created_seq=? WHERE id=?")
        .bind(created)
        .bind(fresh_id)
        .execute(db.write_pool())
        .await
        .unwrap();
    let empty = ordinary_kernel_call(
        &db,
        "account-a",
        "read_canvas",
        json!({"action":"get_scene","canvas_id":fresh_id}),
    )
    .await
    .unwrap();
    assert_eq!(empty["canvas_version"], "canvas:0");
    assert!(empty["objects"].as_array().unwrap().is_empty());
    let new_batch = json!({"version":crate::canvas::BATCH_VERSION,"canvas_id":fresh_id,"batch_id":"fresh-board-batch",
        "origin":{"kind":"agent"},"ops":[{"op":"create","object":{"id":"note-object","kind":"note", "x":1.0,"y":2.0,"w":100.0,"h":50.0,"z":"a","parent":null,"props":{"text":"new board"}}}]});
    let fresh_saved = canvas_app_call(&db, json!({"action":"commit_batch","batch":new_batch}))
        .await
        .unwrap();
    assert_eq!(fresh_saved["outcome"], "committed", "{fresh_saved}");
    let fresh_position = floor
        + fresh_saved["write_receipt"]["event"]["seq"]
            .as_i64()
            .unwrap();
    assert_eq!(
        fresh_saved["canvas_version"],
        format!("canvas:{fresh_position}")
    );
    assert!(fresh_position > position);

    let mut user_batch = new_batch.clone();
    user_batch["batch_id"] = json!("ordinary-user-batch");
    user_batch["ops"][0]["object"]["id"] = json!("ordinary-user-object");
    let user_saved = ordinary_kernel_call(
        &db,
        "account-a",
        "manage_canvas",
        json!({"action":"commit_batch","batch":user_batch}),
    )
    .await
    .unwrap();
    assert_eq!(user_saved["outcome"], "committed");
    assert!(user_saved.get("app_attribution").is_none());
    let borrowed = canvas_app_call(&db, json!({"action":"commit_batch","batch":user_batch}))
        .await
        .unwrap();
    assert_eq!(borrowed["outcome"], "rejected");
    assert_eq!(borrowed["error"]["code"], "batch_id_reused");
    assert!(borrowed.get("app_attribution").is_none());
    // Promotion keeps the existing v1 plan contract, but all native effects
    // and app attribution share one act. A stale plan cannot mint anything.
    let promotion = json!({"action":"promote","canvas_id":fresh_id,"dry_run":true,
        "items":[{"object_id":"note-object","type":"WorkItem","kind":"task","name":"Promoted card"}],
        "reason":"Promote a canvas note"});
    let planned = canvas_app_call(&db, promotion.clone()).await.unwrap();
    assert_eq!(planned["outcome"], "planned", "{planned}");
    assert_eq!(planned["items"][0]["status"], "would_accept");
    let mut commit_promotion = promotion.clone();
    commit_promotion["dry_run"] = json!(false);
    commit_promotion["plan_digest"] = planned["plan_digest"].clone();
    let move_batch = json!({"version":crate::canvas::BATCH_VERSION,"canvas_id":fresh_id,"batch_id":"move-before-promotion",
        "origin":{"kind":"agent"},"ops":[{"op":"patch","id":"note-object",
            "expected":{"geometry":fresh_saved["objects"]["note-object"]["geometry"]},"set":{"x":4.0}}]});
    assert_eq!(
        canvas_app_call(&db, json!({"action":"commit_batch","batch":move_batch}))
            .await
            .unwrap()["outcome"],
        "committed"
    );
    let pre_stale = k::dump_all_kernel_tables(&db).await.unwrap();
    let error = canvas_app_call(&db, commit_promotion.clone())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("revision conflict"), "{error}");
    assert_eq!(pre_stale, k::dump_all_kernel_tables(&db).await.unwrap());
    let fresh_plan = canvas_app_call(&db, promotion.clone()).await.unwrap();
    commit_promotion["plan_digest"] = fresh_plan["plan_digest"].clone();
    let promoted = canvas_app_call(&db, commit_promotion.clone())
        .await
        .unwrap();
    assert_eq!(promoted["outcome"], "committed", "{promoted}");
    assert_eq!(promoted["app_attribution"]["package"], "agent.docs");
    let promoted_id = promoted["promoted"][0]["record_id"].as_str().unwrap();
    let promoted_record = k::read_record_as(&db, &report.principals["account-a"], promoted_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(promoted_record.fields["title"], "Promoted card");
    let provenance: String = sqlx::query_scalar(
        "SELECT value FROM kernel_facets WHERE record_id=? AND key='canvas.promoted_from'",
    )
    .bind(promoted_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let provenance: Value = serde_json::from_str(&provenance).unwrap();
    assert_eq!(provenance["canvas_id"], fresh_id);
    assert_eq!(provenance["batch_event_id"], promoted["event_id"]);
    let (promotion_seq,promotion_act,creator,create_act):(i64,i64,String,i64) = sqlx::query_as(
        "SELECT b.seq,b.act,c.actor,c.act FROM content_events b JOIN content_events c ON c.record_id=? AND c.type='kernel.record_created.v1' WHERE b.id=?"
    ).bind(promoted_id).bind(promoted["event_id"].as_str().unwrap()).fetch_one(db.pool()).await.unwrap();
    assert_eq!(promotion_act, create_act);
    assert_eq!(creator, report.principals["account-a"]);
    assert_eq!(
        promoted["canvas_version"],
        format!("canvas:{}", floor + promotion_seq)
    );
    let scene = canvas_app_tool(
        &db,
        "read_canvas",
        json!({"action":"get_scene","canvas_id":fresh_id}),
    )
    .await
    .unwrap();
    let card = scene["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["id"] == "note-object")
        .unwrap();
    assert_eq!(card["kind"], "record_card");
    assert_eq!(card["props"]["record_id"], promoted_id);
    assert!(card["props"].get("text").is_none());
    let before_duplicate = k::dump_all_kernel_tables(&db).await.unwrap();
    assert!(canvas_app_call(&db, commit_promotion.clone())
        .await
        .unwrap_err()
        .to_string()
        .contains("revision conflict"));
    assert_eq!(
        before_duplicate,
        k::dump_all_kernel_tables(&db).await.unwrap()
    );
    let actor = &report.principals["account-a"];
    k::app_installs::remove_as(&db, actor, "agent.docs", "install")
        .await
        .unwrap();
    assert!(
        canvas_app_call(&db, json!({"action":"commit_batch","batch":content}))
            .await
            .is_err(),
        "a revoked app cannot replay a success receipt"
    );
    assert!(
        canvas_app_call(&db, commit_promotion).await.is_err(),
        "removed apps cannot promote"
    );
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn native_apps_frozen_slack_pins_preserve_generations_and_rebuild() {
    // Public pin names and the exact empty declaration shape come from the
    // frozen source census. Bodies and all identities below are synthetic.
    for version in ["0.4.1", "0.5.7"] {
        let f = Fixture::new().await;
        native_install_source_with_pin(
            &f,
            "<html>Frozen messaging fixture</html>",
            "agent.slack-workspace-v2",
            version,
        )
        .await;
        let report = run(f.options(&["secret", "note"], false)).await.unwrap();
        assert!(report.refusals.is_empty());
        assert!(report.review.is_empty());
        let db = f.db().await;
        let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
            .await
            .unwrap()
            .unwrap()
            .0;
        app_roster(&db, "account-a", &["account-a", "account-b"]).await;
        k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
            .await
            .unwrap();
        let rows: Vec<(String,String,String,bool,String)> = sqlx::query_as(
            "SELECT package,json_extract(row_json,'$.version'),generation,executable,json_extract(row_json,'$.adoption') FROM kernel_app_installs ORDER BY generation")
            .fetch_all(db.pool()).await.unwrap();
        assert_eq!(
            rows,
            vec![
                (
                    "agent.slack-workspace-v2".into(),
                    version.into(),
                    "install".into(),
                    true,
                    "shell_adopt.v1".into()
                ),
                (
                    "agent.slack-workspace-v2".into(),
                    version.into(),
                    "install-b".into(),
                    true,
                    "shell_adopt.v1".into()
                )
            ]
        );
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
            .await
            .unwrap();
        k::replay_all_projections(&db).await.unwrap();
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
        db.close().await;
    }
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
    let (needs, effects) = k::app_installs::declarations::consent_names(&pin.declaration).unwrap();
    let authority = VerifiedAlphaTabPreview::for_pin(
        account,
        &pin.package,
        &pin.version,
        &pin.digest,
        &pin.artifact_id,
        &pin.source_revision,
        crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&pin.declaration).unwrap(),
        needs,
        effects,
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

#[tokio::test]
async fn frozen_promotion_batch_imports_activates_withholds_and_replays() {
    let f = Fixture::new().await;
    seed(&f).await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("UPDATE records SET kind='canvas' WHERE id='note'; DROP TABLE canvas_objects; DROP TABLE canvas_batches; CREATE TABLE canvas_objects(canvas_id TEXT,object_id TEXT,kind TEXT,x REAL,y REAL,w REAL,h REAL,z TEXT,parent_id TEXT,props TEXT,deleted INTEGER,geometry_seq INTEGER,content_seq INTEGER,created_seq INTEGER); CREATE TABLE canvas_batches(canvas_id TEXT,batch_id TEXT,actor TEXT,event_id TEXT,event_seq INTEGER,ops_sha256 TEXT,origin_kind TEXT); INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id) SELECT 'promoted-task',type,kind,'Frozen promoted task','', 'private','person-a',lifecycle,summary,created_at,updated_at,0,'private' FROM records WHERE id='task'; INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('created:promoted-task','promoted-task','record.created','{}','account-a','2026-01-01T00:00:00Z')").await.unwrap();
    let seq: i64 = sqlx::query_scalar("SELECT seq FROM content_events WHERE id='batch-event'")
        .fetch_one(&mut source)
        .await
        .unwrap();
    let initial_ops: Vec<crate::canvas::Op> = serde_json::from_value(json!([{"op":"create","object":{"id":"promoted-object","kind":"note","x":0.125,"y":2.0,"w":100.0,"h":50.0,"z":"a","props":{"text":"Frozen note"}}},{"op":"create","object":{"id":"unpromoted-object","kind":"note","x":3.0,"y":2.0,"w":100.0,"h":50.0,"z":"b","props":{"text":"Next note"}}}])).unwrap();
    let initial = crate::canvas::StoredBatch {
        version: crate::canvas::BATCH_VERSION.into(),
        batch_id: "batch".into(),
        base_version: None,
        origin: crate::canvas::Origin {
            kind: crate::canvas::OriginKind::Agent,
            gesture: None,
            undo_of: None,
            note: None,
        },
        ops_sha256: crate::canvas::ops_digest(&initial_ops).unwrap(),
        ops: initial_ops,
        pre_images: Default::default(),
        detached: Vec::new(),
    };
    sqlx::query("UPDATE content_events SET payload=? WHERE id='batch-event'")
        .bind(serde_json::to_string(&initial).unwrap())
        .execute(&mut source)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO canvas_batches VALUES('note','batch','account-a','batch-event',?,?,'agent')",
    )
    .bind(seq)
    .bind(&initial.ops_sha256)
    .execute(&mut source)
    .await
    .unwrap();
    let promoted_from =
        json!({"object_id":"promoted-object","attestation_id":"frozen-promotion-attestation"});
    let ops: Vec<crate::canvas::Op> = serde_json::from_value(json!([{"op":"patch","id":"promoted-object","expected":{"content":format!("canvas:{seq}")},"set":{"kind":"record_card","props":{"text":null,"record_id":"promoted-task","promoted_from":promoted_from}}}])).unwrap();
    let promotion = crate::canvas::StoredBatch {
        version:crate::canvas::BATCH_VERSION.into(),batch_id:"frozen-promotion".into(),base_version:Some(format!("canvas:{seq}")),
        origin:crate::canvas::Origin{kind:crate::canvas::OriginKind::Promotion,gesture:None,undo_of:None,note:Some("Promote frozen note".into())},
        ops_sha256:crate::canvas::ops_digest(&ops).unwrap(),ops,
        pre_images:serde_json::from_value(json!({"promoted-object":{"geometry":seq,"content":seq,"props":{"text":"Frozen note","record_id":null,"promoted_from":null}}})).unwrap(),detached:Vec::new(),
    };
    let promotion_seq:i64=sqlx::query_scalar("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('frozen-promotion-event','note','canvas.batch.committed.v1',?,'account-a','2026-01-02T00:00:00Z') RETURNING seq").bind(serde_json::to_string(&promotion).unwrap()).fetch_one(&mut source).await.unwrap();
    sqlx::query("INSERT INTO canvas_batches VALUES('note','frozen-promotion','account-a','frozen-promotion-event',?,?,'promotion')").bind(promotion_seq).bind(&promotion.ops_sha256).execute(&mut source).await.unwrap();
    let props = json!({"record_id":"promoted-task","promoted_from":promoted_from});
    sqlx::query("INSERT INTO canvas_objects VALUES('note','promoted-object','record_card',0.125,2.0,100.0,50.0,'a',NULL,?,0,?,?,?)").bind(String::from_utf8(crate::canonical_json::canonical_json(&props)).unwrap()).bind(seq).bind(promotion_seq).bind(seq).execute(&mut source).await.unwrap();
    sqlx::query("INSERT INTO canvas_objects VALUES('note','unpromoted-object','note',3.0,2.0,100.0,50.0,'b',NULL,'{\"text\":\"Next note\"}',0,?,?,?)").bind(seq).bind(seq).bind(seq).execute(&mut source).await.unwrap();
    let v1_default_home: String = sqlx::query_scalar("SELECT home_id FROM records WHERE id='note'")
        .fetch_one(&mut source)
        .await
        .unwrap();
    assert_eq!(v1_default_home, "folder");
    source.close().await.unwrap();
    let report = run(f.options(&["secret", "note", "promoted-task"], false))
        .await
        .unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    assert!(report.app_state.capture_complete);
    let db = f.db().await;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let head:String=sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1").fetch_one(db.pool()).await.unwrap();
    let capsule_seq: i64 =
        sqlx::query_scalar("SELECT event_seq FROM kernel_app_state WHERE record_id='note'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    // SAFETY: the complete fixture is frozen and its retained ledger was verified.
    let proof = unsafe {
        k::canvas_v2::VerifiedFrozenCanvas::from_verified_import_unchecked(
            "note".into(),
            serde_json::from_str(&head).unwrap(),
            "a".repeat(64),
            capsule_seq,
        )
    };
    k::canvas_v2::activate_as(&db, &host, proof).await.unwrap();
    for account in ["account-a", "account-b"] {
        let scene = ordinary_kernel_call(
            &db,
            account,
            "read_canvas",
            json!({"action":"get_scene","canvas_id":"note"}),
        )
        .await
        .unwrap();
        assert_eq!(scene["live_objects"], 2);
        assert_eq!(scene["objects"][0]["kind"], "record_card");
        assert_eq!(
            scene["objects"][0]["props"]["record_id"],
            if account == "account-a" {
                "promoted-task"
            } else {
                "withheld"
            }
        );
        let changes = ordinary_kernel_call(
            &db,
            account,
            "read_canvas",
            json!({"action":"changes","canvas_id":"note","after":format!("canvas:{seq}")}),
        )
        .await
        .unwrap();
        assert_eq!(changes["batches"].as_array().unwrap().len(), 1);
        assert_eq!(changes["batches"][0]["event_seq"], promotion_seq);
        assert_eq!(changes["batches"][0]["origin"]["kind"], "promotion");
        if account == "account-b" {
            assert!(!scene.to_string().contains("promoted-task"));
            assert!(!changes.to_string().contains("promoted-task"));
        }
    }
    // HQ's four live canvases all file in folder Collections. This fixture
    // also separates the filing folder from the canvas's policy anchor.
    let request = json!({"action":"promote","canvas_id":"note","dry_run":true,"reason":"Test default placement",
        "items":[{"object_id":"unpromoted-object","type":"WorkItem","kind":"task","name":"Default-home task"}]});
    let plan = ordinary_kernel_call(&db, "account-a", "manage_canvas", request.clone())
        .await
        .unwrap();
    let mut commit = request;
    commit["dry_run"] = json!(false);
    commit["plan_digest"] = plan["plan_digest"].clone();
    let receipt = ordinary_kernel_call(&db, "account-a", "manage_canvas", commit)
        .await
        .unwrap();
    assert_eq!(receipt["outcome"], "committed", "{receipt}");
    let id = receipt["promoted"][0]["record_id"].as_str().unwrap();
    let record = ordinary_kernel_call(&db, "account-a", "get_record", json!({"ids":[id]}))
        .await
        .unwrap();
    assert_eq!(record["records"][0]["home_id"], v1_default_home);
    assert_eq!(
        k::read_record_as(&db, &report.principals["account-a"], id)
            .await
            .unwrap()
            .unwrap()
            .home_id,
        report.homes["folder"]
    );
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn imported_app_custody_standby_delta_matches_hosted_and_full_replay() {
    use crate::mcp::{
        app_attribution::AppAttribution,
        registry::{Caller, EngineHandle, ToolRegistry},
    };
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source
        .execute("UPDATE database_identity SET origin_db_id='ndb_0123456789abcdef0123456789abcdef'")
        .await
        .unwrap();
    source.close().await.unwrap();
    let body = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Standby app</title></head><body><main>Sample</main></body></html>"#;
    let (db, report) = native_install_fixture_with_body(&f, body).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let dump = crate::standby::kernel_v2_tests::assert_projection_delta_equivalence(&db, || async {
        let (origin, raw): (String, String) = sqlx::query_as("SELECT origin,payload FROM kernel_app_state WHERE record_id='secret'").fetch_one(db.pool()).await.unwrap();
        let mut state: k::app_state::RetainedAppState = serde_json::from_str(&raw).unwrap();
        state.artifact_inputs.push(json!({"artifact_id":"secret","port_name":"standby-fixture","collection_id":"private"}));
        k::app_state::import_as(&db, &host, "secret", &origin, &state).await.unwrap();
        k::import_event_as(&db, &host, "secret", &k::LegacyEvent {
            source: Some(json!({"origin":"fixture","stream":"content_events","subjects":["secret"],"metadata":{"record_id":"secret"}})),
            id:"standby-legacy-sql".into(), event_type:"record.updated".into(), payload:json!({"record_id":"secret"}),
            created_at:"2026-01-02T00:00:00Z".into(),actor:Some("account-a".into()),run_key:Some("legacy-run".into()),
        }).await.unwrap();
        // The cursor is local maintenance metadata, outside the projection
        // digest. A stale host must refuse serving until explicit preparation;
        // repairing that cursor must not change the digest or force a FULL.
        let before = k::projection_dump::dump(&db).await.unwrap();
        sqlx::query("UPDATE kernel_legacy_sql_progress SET scanned_seq=0").execute(db.write_pool()).await.unwrap();
        assert_eq!(before, k::projection_dump::dump(&db).await.unwrap());
        let refusal = k::verify_v2_ready(&db).await.unwrap_err();
        assert!(refusal.to_string().contains("legacy SQL projection needs catchup"));
        k::prepare_v2_database(&db).await.unwrap();
        k::verify_v2_ready(&db).await.unwrap();
        assert_eq!(before, k::projection_dump::dump(&db).await.unwrap());
        app_roster(&db, "account-a", &["account-a", "account-b"]).await;
        k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await).await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
        let caller = Caller::authenticated("account-a").with_host_asserted_app(AppAttribution::new("agent.docs", "0.8.2", "install").unwrap());
        let note = k::read_record_as(&db, &report.principals["account-a"], "note").await.unwrap().unwrap();
        registry.call_engine(EngineHandle::KernelV2(db.clone()),caller,"update_record",json!({"id":"note","body_set":"standby app write","if_body_digest":crate::mcp::tools::lifecycle::body_digest(note.body.as_deref()),"idempotency_key":"standby-app-save","reason":"Verify retained app action replay"})).await.unwrap();
        k::app_installs::remove_for_user_as(&db, &report.principals["account-a"], "agent.docs", "install", "Verify removal outcome replay".into(), Some("standby-remove".into())).await.unwrap();
        app_roster(&db, "account-b", &["account-b"]).await;
        // SAFETY: complete synthetic host roster, protecting b as recipient.
        let operation = unsafe { k::hosted_identity::offboarding::VerifiedOffboarding::from_catalog_unchecked(
            uuid::Uuid::new_v4().to_string(), "account-b".into(), "account-a".into(), "account-b".into(), "Verify revocation replay".into(),
        ) };
        k::hosted_identity::offboarding::apply(&db, operation).await.unwrap();
    }).await;
    for name in [
        "kernel_app_state",
        "kernel_app_installs",
        "kernel_app_package_sources",
        "kernel_app_consent_revocations",
        "kernel_app_install_outcomes",
        "kernel_app_actions",
        "kernel_legacy_sql_events",
    ] {
        assert!(
            dump.tables.iter().any(|t| t.name == name && t.rows > 0),
            "nonempty projection coverage: {name}"
        );
    }
    assert!(!dump
        .tables
        .iter()
        .any(|t| t.name == "kernel_legacy_sql_progress"));
    let before = k::projection_dump::dump(&db).await.unwrap();
    sqlx::query("UPDATE kernel_legacy_sql_events SET actor='changed-fixture-author' WHERE source_id='standby-legacy-sql'").execute(db.write_pool()).await.unwrap();
    assert_ne!(
        before.sha256,
        k::projection_dump::dump(&db).await.unwrap().sha256,
        "legacy SQL content remains in digest"
    );
    db.close().await;
}

#[tokio::test]
async fn native_app_query_record_rechecks_consent_roster_source_and_visibility() {
    use crate::mcp::{app_attribution::AppAttribution, Caller, EngineHandle, ToolRegistry};
    let f = Fixture::new().await;
    let (db, report) = native_install_fixture_with_body(&f, r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>App reader</title></head><body><main>Sample</main></body></html>"#).await;
    let a = &report.principals["account-a"];
    let b = &report.principals["account-b"];
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let source = k::read_record_as(&db, a, "secret").await.unwrap().unwrap();
    k::replace_home_policy(&db, a, &source.home_id, &[(b, "view")])
        .await
        .unwrap();
    let hidden_home = k::create_home(&db, &source.home_id, Some(&[]), a)
        .await
        .unwrap();
    let hidden = k::create_record_as(&db, a, &hidden_home).await.unwrap();
    for id in ["note", &hidden] {
        for (key, value) in [("runtime", "native.mdx.v2"), ("score", "12")] {
            k::observe_facet_as(
                &db,
                a,
                id,
                &k::FacetObservation {
                    key: key.into(),
                    value: Some(value.into()),
                    value_num: if key == "score" { Some(12.0) } else { None },
                    vocab_ref: None,
                    as_of: "2026-10-21T00:00:00Z".into(),
                },
                None,
            )
            .await
            .unwrap();
        }
    }
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
    let caller = |account: &str, generation: &str| {
        Caller::authenticated(account)
            .with_host_asserted_app(AppAttribution::new("agent.docs", "0.8.2", generation).unwrap())
    };
    let queries = [
        json!({"steps":[{"step":"filter","ids":["note",hidden]}],"limit":500}),
        json!({"steps":[{"step":"filter","ids":["note",hidden],"facets":[{"key":"runtime","in":["native.mdx.v1","native.mdx.v2"]}]}],"order":"name_asc","limit":500}),
        json!({"steps":[{"step":"filter","ids":["missing"]}],"order":"name_asc","limit":500}),
    ];
    for facet in [
        json!({"key":"runtime","in":["native.mdx.v1","native.mdx.v2"]}),
        json!({"key":"runtime","eq":"native.mdx.v2"}),
        json!({"key":"runtime"}),
        json!({"key":"runtime","ne":"native.mdx.v1"}),
        json!({"key":"score","gte":10,"lte":15}),
    ] {
        let result = registry.call_engine(EngineHandle::KernelV2(db.clone()), caller("account-b", "install-b"), "query_record",
            json!({"steps":[{"step":"filter","ids":["note",hidden],"facets":[facet]}],"order":"name_asc","limit":500})).await.unwrap();
        assert_eq!(result["total"], 1, "{result:#}");
        assert_eq!(result["records"][0]["id"], "note");
    }
    let empty = registry.call_engine(EngineHandle::KernelV2(db.clone()), caller("account-b", "install-b"), "query_record",
        json!({"steps":[{"step":"filter","facets":[{"key":"runtime","in":[]}]}],"order":"name_asc"})).await.unwrap();
    assert_eq!(empty["total"], 0);
    assert!(registry.call_engine(EngineHandle::KernelV2(db.clone()), caller("account-b", "install-b"), "query_record",
        json!({"steps":[{"step":"filter","facets":[{"key":"runtime","eq":12}]}],"order":"name_asc"})).await.is_err(), "v1 rejects numeric equality in its string-exact lane");
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    for args in &queries {
        let direct = registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                Caller::authenticated("account-b"),
                "query_record",
                args.clone(),
            )
            .await
            .unwrap();
        let app = registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                caller("account-b", "install-b"),
                "query_record",
                args.clone(),
            )
            .await
            .unwrap();
        assert_eq!(app["records"], direct["records"]);
        assert!(!app["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == hidden));
    }
    let owner = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("account-a"),
            "query_record",
            queries[1].clone(),
        )
        .await
        .unwrap();
    assert!(
        owner["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == hidden),
        "the hidden fixture is queryable by its owner"
    );
    assert_eq!(
        before,
        k::dump_all_kernel_tables(&db).await.unwrap(),
        "reads append no action attribution or content facts"
    );
    let query = queries[1].clone();
    assert!(registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller("account-b", "stale-generation"),
            "query_record",
            query.clone()
        )
        .await
        .is_err());
    app_roster(&db, "account-a", &["account-a"]).await;
    assert!(registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller("account-b", "install-b"),
            "query_record",
            query.clone()
        )
        .await
        .is_err());
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller("account-b", "install-b"),
            "query_record",
            query.clone(),
        )
        .await
        .unwrap();
    k::app_installs::remove_as(&db, b, "agent.docs", "install-b")
        .await
        .unwrap();
    assert!(registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller("account-b", "install-b"),
            "query_record",
            query.clone()
        )
        .await
        .is_err());
    ordinary_kernel_call(
        &db,
        "account-a",
        "archive_record",
        json!({"id":"secret","reason":"Retire source"}),
    )
    .await
    .unwrap();
    assert!(registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller("account-a", "install"),
            "query_record",
            query
        )
        .await
        .is_err());
    db.close().await;
}

const OPERATOR_APP_BODY: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Declared data</title></head><body><main>Sample</main></body></html>"#;

// Operator preflight uses real imported capsules and the normal H3 mapping.
async fn operator_app_fixture(
    change: Option<(&str, Value)>,
) -> (Fixture, Db, super::super::Report) {
    let f = Fixture::new().await;
    native_install_source(&f, OPERATOR_APP_BODY).await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source
        .execute("DELETE FROM alpha_tab_installs WHERE account_id='account-c'")
        .await
        .unwrap();
    if let Some((field, value)) = &change {
        // Fields are fixed test literals, never operator inputs.
        sqlx::query(&format!(
            "UPDATE alpha_tab_installs SET {field}=? WHERE account_id='account-a'"
        ))
        .bind(value.as_str().unwrap())
        .execute(&mut source)
        .await
        .unwrap();
    }
    if change
        .as_ref()
        .is_some_and(|(field, value)| *field == "adoption" && value == "shell_auto.v1")
    {
        source.execute("UPDATE control_events SET payload=json_set(payload,'$.adoption','shell_auto.v1') WHERE id='install'").await.unwrap();
    }
    source.close().await.unwrap();
    let report = run(f.options(&["secret", "note"], false)).await.unwrap();
    assert!(report.refusals.is_empty());
    let db = f.db().await;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    (f, db, report)
}
async fn operator_app_preflight(db: &Db, members: &[&str]) -> crate::Result<Value> {
    let proof = operator_app_proof(db).await;
    let mut conn = db.pool().acquire().await?;
    k::app_installs::inspect_frozen_activation_on(
        &mut conn,
        &proof,
        &members.iter().map(|s| s.to_string()).collect(),
    )
    .await
}

#[tokio::test]
async fn operator_apps_dry_run_parity_launch_and_idempotency() {
    let (_f, db, report) = operator_app_fixture(None).await;
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let preview = operator_app_preflight(&db, &["account-a", "account-b"])
        .await
        .unwrap();
    assert_eq!(preview["packages"][0]["eligible"], 2);
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    let caller = crate::mcp::Caller::authenticated("account-a")
        .with_hosting_context("account-a", "hq-fixture");
    // SAFETY: synthetic verified same-origin browser session.
    let caller = unsafe { caller.with_verified_hosting_session("fixture-session") };
    let mut conn = db.pool().acquire().await.unwrap();
    assert!(k::app_installs::launch_source_on(
        &mut conn,
        &report.principals["account-a"],
        &caller,
        "agent.docs",
        "install"
    )
    .await
    .err()
    .unwrap()
    .to_string()
    .contains("not activated"));
    drop(conn);
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(&db, &host, operator_app_proof(&db).await)
        .await
        .unwrap();
    let captured: String =
        sqlx::query_scalar("SELECT payload FROM kernel_app_state WHERE record_id='secret'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let captured: k::app_state::RetainedAppState = serde_json::from_str(&captured).unwrap();
    for row in captured.alpha_tab_installs {
        let principal = &report.principals[row["account_id"].as_str().unwrap()];
        let installed: String =
            sqlx::query_scalar("SELECT row_json FROM kernel_app_installs WHERE principal=?")
                .bind(principal)
                .fetch_one(db.pool())
                .await
                .unwrap();
        // Full row equality covers account/scope, pin, consent, acknowledgements,
        // declared read descriptors and provenance; no reconstructed defaults.
        assert_eq!(serde_json::from_str::<Value>(&installed).unwrap(), row);
    }
    let mut conn = db.pool().acquire().await.unwrap();
    let launched = k::app_installs::launch_source_on(
        &mut conn,
        &report.principals["account-a"],
        &caller,
        "agent.docs",
        "install",
    )
    .await
    .unwrap();
    assert_eq!(launched.body, OPERATOR_APP_BODY);
    drop(conn);
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let summary = operator_app_preflight(&db, &["account-a", "account-b"])
        .await
        .unwrap();
    assert_eq!(summary["already_active"], true);
    k::app_installs::activate_as(&db, &host, operator_app_proof(&db).await)
        .await
        .unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn operator_apps_refuse_unmapped_adopting_member() {
    let f = Fixture::new().await;
    let (db, _) = native_install_fixture(&f).await; // includes unmapped account-c
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    assert!(operator_app_preflight(&db, &["account-a", "account-b"])
        .await
        .unwrap_err()
        .to_string()
        .contains("unmapped in hosted identity"));
}
#[tokio::test]
async fn operator_apps_refuse_offboarded_adopting_member() {
    let (_f, db, _) = operator_app_fixture(None).await;
    app_roster(&db, "account-b", &["account-b"]).await;
    assert!(operator_app_preflight(&db, &["account-b"])
        .await
        .unwrap_err()
        .to_string()
        .contains("offboarded or not admitted"));
}
#[tokio::test]
async fn operator_apps_refuse_real_offboarding_revocation_after_readmission() {
    let (_f, db, report) = operator_app_fixture(None).await;
    app_roster(&db, "account-b", &["account-b"]).await;
    // SAFETY: synthetic catalog authorization, with b retained as recipient.
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
    let mut conn = db.pool().acquire().await.unwrap();
    assert!(
        k::hosted_identity::account_admitted_before(
            &mut conn,
            &report.principals["account-a"],
            i64::MAX
        )
        .await
        .unwrap(),
        "readmission isolates the persistent revocation branch"
    );
    drop(conn);
    let revoked: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kernel_app_consent_revocations WHERE principal=?")
            .bind(&report.principals["account-a"])
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(revoked, 1);
    assert!(operator_app_preflight(&db, &["account-a", "account-b"])
        .await
        .unwrap_err()
        .to_string()
        .contains("offboarded or not admitted"));
}
#[tokio::test]
async fn operator_apps_refuse_current_catalog_exclusion() {
    let (_f, db, _) = operator_app_fixture(None).await;
    assert!(operator_app_preflight(&db, &["account-b"])
        .await
        .unwrap_err()
        .to_string()
        .contains("unmapped in current hosted catalog"));
}
#[tokio::test]
async fn operator_apps_refuse_wrong_pin() {
    let (_f, db, _) = operator_app_fixture(Some(("version", json!("0.9.0")))).await;
    assert!(operator_app_preflight(&db, &["account-a", "account-b"])
        .await
        .unwrap_err()
        .to_string()
        .contains("install control witness mismatch"));
}
#[tokio::test]
async fn operator_apps_refuse_wrong_digest() {
    let (_f, db, _) = operator_app_fixture(Some(("digest", json!("bad-digest")))).await;
    assert!(operator_app_preflight(&db, &["account-a", "account-b"])
        .await
        .unwrap_err()
        .to_string()
        .contains("source or declaration digest mismatch"));
}
#[tokio::test]
async fn operator_apps_refuse_wrong_declaration_digest() {
    let (_f, db, _) =
        operator_app_fixture(Some(("declaration_digest", json!("bad-declaration")))).await;
    assert!(operator_app_preflight(&db, &["account-a", "account-b"])
        .await
        .unwrap_err()
        .to_string()
        .contains("source or declaration digest mismatch"));
}
async fn operator_apps_excludes(change: (&str, Value)) {
    let (_f, db, report) = operator_app_fixture(Some(change)).await;
    let summary = operator_app_preflight(&db, &["account-a", "account-b"])
        .await
        .unwrap();
    assert_eq!(summary["packages"][0]["eligible"], 1);
    assert_eq!(summary["packages"][0]["excluded"], 1);
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(&db, &host, operator_app_proof(&db).await)
        .await
        .unwrap();
    let executable: bool =
        sqlx::query_scalar("SELECT executable FROM kernel_app_installs WHERE principal=?")
            .bind(&report.principals["account-a"])
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(!executable);
}
#[tokio::test]
async fn operator_apps_refuses_inactive_consent() {
    operator_apps_excludes(("status", json!("disabled"))).await;
}
#[tokio::test]
async fn operator_apps_refuses_removed_consent() {
    operator_apps_excludes(("status", json!("removed"))).await;
}
#[tokio::test]
async fn operator_apps_refuses_never_adopted_consent() {
    operator_apps_excludes(("adoption", json!("caller_asserted"))).await;
}

async fn operator_app_proof(db: &Db) -> k::app_installs::VerifiedFrozenApps {
    let head: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1").fetch_one(db.pool()).await.unwrap();
    let seq: i64 =
        sqlx::query_scalar("SELECT event_seq FROM kernel_app_state WHERE record_id='secret'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    // SAFETY: this fixture owns the frozen synthetic source and unpublished target.
    unsafe {
        k::app_installs::VerifiedFrozenApps::from_verified_contract_import_unchecked(
            serde_json::from_str(&head).unwrap(),
            "ab".repeat(32),
            BTreeMap::from([("secret".into(), seq)]),
        )
    }
}

#[tokio::test]
async fn operator_apps_preserves_v1_shell_auto_without_reinterpreting_old_activation() {
    let (_f, db, report) = operator_app_fixture(Some(("adoption", json!("shell_auto.v1")))).await;
    let legacy = app_activation_proof(&db).await;
    let mut conn = db.pool().acquire().await.unwrap();
    let legacy_summary = k::app_installs::inspect_frozen_activation_on(
        &mut conn,
        &legacy,
        &["account-a".to_string(), "account-b".to_string()]
            .into_iter()
            .collect(),
    )
    .await
    .unwrap();
    assert_eq!(legacy_summary["packages"][0]["eligible"], 1);
    drop(conn);
    let summary = operator_app_preflight(&db, &["account-a", "account-b"])
        .await
        .unwrap();
    assert_eq!(summary["packages"][0]["eligible"], 2);
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(&db, &host, operator_app_proof(&db).await)
        .await
        .unwrap();
    let row: (bool,String) = sqlx::query_as("SELECT executable,json_extract(row_json,'$.adoption') FROM kernel_app_installs WHERE principal=?")
        .bind(&report.principals["account-a"]).fetch_one(db.pool()).await.unwrap();
    assert_eq!(row, (true, "shell_auto.v1".into()));
    let caller = crate::mcp::Caller::authenticated("account-a")
        .with_hosting_context("account-a", "hq-fixture");
    // SAFETY: fixture's verified synthetic browser session.
    let caller = unsafe { caller.with_verified_hosting_session("fixture-session") };
    let mut conn = db.pool().acquire().await.unwrap();
    let launched = k::app_installs::launch_source_on(
        &mut conn,
        &report.principals["account-a"],
        &caller,
        "agent.docs",
        "install",
    )
    .await
    .unwrap();
    assert_eq!(launched.generation, "install");
    drop(conn);

    assert!(
        k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
            .await
            .is_err()
    );
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn operator_apps_contract_admits_unknown_package_and_version_launch_and_revocation() {
    for package in [
        "agent.docs",
        "agent.slack-workspace-v2",
        "synthetic.new-app",
    ] {
        let f = Fixture::new().await;
        native_install_source_with_pin(&f, OPERATOR_APP_BODY, package, "999.42.0").await;
        let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
            .await
            .unwrap();
        source
            .execute("DELETE FROM alpha_tab_installs WHERE account_id='account-c'")
            .await
            .unwrap();
        source.close().await.unwrap();
        let report = run(f.options(&["secret", "note"], false)).await.unwrap();
        assert!(report.refusals.is_empty());
        let db = f.db().await;
        app_roster(&db, "account-a", &["account-a", "account-b"]).await;
        let summary = operator_app_preflight(&db, &["account-a", "account-b"])
            .await
            .unwrap();
        assert_eq!(summary["packages"][0]["eligible"], 2);
        let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
            .await
            .unwrap()
            .unwrap()
            .0;
        k::app_installs::activate_as(&db, &host, operator_app_proof(&db).await)
            .await
            .unwrap();
        let caller = crate::mcp::Caller::authenticated("account-a")
            .with_hosting_context("account-a", "hq-fixture");
        // SAFETY: synthetic browser session.
        let caller = unsafe { caller.with_verified_hosting_session("fixture-session") };
        let a = &report.principals["account-a"];
        let mut conn = db.pool().acquire().await.unwrap();
        let launched = k::app_installs::launch_source_on(&mut conn, a, &caller, package, "install")
            .await
            .unwrap();
        assert_eq!(launched.version, "999.42.0");
        drop(conn);
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
        let app = crate::mcp::Caller::authenticated("account-a").with_host_asserted_app(
            crate::mcp::app_attribution::AppAttribution::new(package, "999.42.0", "install")
                .unwrap(),
        );
        registry
            .call_engine(
                crate::mcp::EngineHandle::KernelV2(db.clone()),
                app.clone(),
                "get_record",
                json!({"ids":["note"]}),
            )
            .await
            .unwrap();
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        k::replay_all_projections(&db).await.unwrap();
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
        k::app_installs::remove_as(&db, a, package, "install")
            .await
            .unwrap();
        assert!(
            registry
                .call_engine(
                    crate::mcp::EngineHandle::KernelV2(db.clone()),
                    app,
                    "get_record",
                    json!({"ids":["note"]})
                )
                .await
                .is_err(),
            "each request must recheck removal"
        );
        let mut conn = db.pool().acquire().await.unwrap();
        assert!(
            k::app_installs::launch_source_on(&mut conn, a, &caller, package, "install")
                .await
                .is_err()
        );
        drop(conn);
        db.close().await;
    }
}

#[tokio::test]
async fn operator_apps_contract_exclusions_do_not_abort_activation() {
    for declaration in [
        json!({"contract":"native.app.v2","needs":[{"need":"records.search.v1"}],"effects":[]}),
        json!({"contract":"native.app.v2","needs":[],"effects":["records.body-set.v1"]}),
        json!({"contract":"native.app.v99","needs":[],"effects":[]}),
        json!({"needs":[{"key":"notes","label":"Notes","need":"sql.snapshot.v1","sql":"SELECT id FROM records ORDER BY id"}],"effects":[]}),
    ] {
        let (_f, db, report) = operator_app_fixture(Some((
            "consented_declaration",
            json!(declaration.to_string()),
        )))
        .await;
        let summary = operator_app_preflight(&db, &["account-a", "account-b"])
            .await
            .unwrap();
        assert_eq!(summary["packages"][0]["eligible"], 1);
        assert_eq!(
            summary["packages"][0]["exclusion_reasons"]["app_not_yet_available_on_v2"],
            1
        );
        let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
            .await
            .unwrap()
            .unwrap()
            .0;
        k::app_installs::activate_as(&db, &host, operator_app_proof(&db).await)
            .await
            .unwrap();
        let caller = crate::mcp::Caller::authenticated("account-a")
            .with_hosting_context("account-a", "hq-fixture");
        // SAFETY: synthetic browser session.
        let caller = unsafe { caller.with_verified_hosting_session("fixture-session") };
        let mut conn = db.pool().acquire().await.unwrap();
        let error = k::app_installs::launch_source_on(
            &mut conn,
            &report.principals["account-a"],
            &caller,
            "agent.docs",
            "install",
        )
        .await
        .err()
        .unwrap();
        assert!(error.to_string().contains("app_not_yet_available_on_v2"));
        drop(conn);
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        k::replay_all_projections(&db).await.unwrap();
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
        db.close().await;
    }
}

#[tokio::test]
async fn operator_apps_witness_types_exclude_individually_but_mismatches_remain_fatal() {
    for kind in [
        "alpha_tab.restored",
        "alpha_tab.installed",
        "alpha_tab.future_adoption",
    ] {
        for tampered in [false, true] {
            let f = Fixture::new().await;
            native_install_source(&f, OPERATOR_APP_BODY).await;
            let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
                .await
                .unwrap();
            source
                .execute("DELETE FROM alpha_tab_installs WHERE account_id='account-c'")
                .await
                .unwrap();
            sqlx::query("UPDATE control_events SET type=? WHERE id='install'")
                .bind(kind)
                .execute(&mut source)
                .await
                .unwrap();
            if matches!(kind, "alpha_tab.installed" | "alpha_tab.restored") {
                source.execute("ALTER TABLE control_events ADD COLUMN idempotency_key TEXT; ALTER TABLE control_events ADD COLUMN schema_version INTEGER; ALTER TABLE control_events ADD COLUMN aggregate_kind TEXT; ALTER TABLE control_events ADD COLUMN aggregate_id TEXT; ALTER TABLE control_events ADD COLUMN reason TEXT;").await.unwrap();
                sqlx::query("UPDATE control_events SET actor='canonical_import',idempotency_key='legacy-state',schema_version=1,aggregate_kind='alpha_tab',aggregate_id=?,reason='Stored legacy adoption' WHERE id='install'")
                    .bind(crate::control::alpha_tab_aggregate_id("account-a","agent.docs")).execute(&mut source).await.unwrap();
            }
            if tampered {
                sqlx::query("UPDATE control_events SET payload=json_set(payload,'$.version','999.99.0') WHERE id='install'").execute(&mut source).await.unwrap();
            }
            source.close().await.unwrap();
            run(f.options(&["secret", "note"], false)).await.unwrap();
            let db = f.db().await;
            app_roster(&db, "account-a", &["account-a", "account-b"]).await;
            let summary = operator_app_preflight(&db, &["account-a", "account-b"]).await;
            if tampered {
                assert!(summary
                    .unwrap_err()
                    .to_string()
                    .contains("witness mismatch"));
            } else {
                let summary = summary.unwrap();
                let unknown = kind == "alpha_tab.future_adoption";
                assert_eq!(
                    summary["packages"][0]["eligible"],
                    if unknown { 1 } else { 2 }
                );
                if unknown {
                    assert_eq!(
                        summary["packages"][0]["exclusion_reasons"]
                            ["app_adoption_witness_not_yet_available_on_v2"],
                        1
                    );
                }
                let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
                    .await
                    .unwrap()
                    .unwrap()
                    .0;
                k::app_installs::activate_as(&db, &host, operator_app_proof(&db).await)
                    .await
                    .unwrap();
                if unknown {
                    let caller = crate::mcp::Caller::authenticated("account-a")
                        .with_hosting_context("account-a", "fixture");
                    // SAFETY: synthetic same-origin test session.
                    let caller = unsafe { caller.with_verified_hosting_session("fixture-session") };
                    let account = k::resolve_principal_by_binding(&db, "account-a")
                        .await
                        .unwrap()
                        .unwrap()
                        .0;
                    let mut conn = db.pool().acquire().await.unwrap();
                    let error = k::app_installs::launch_source_on(
                        &mut conn,
                        &account,
                        &caller,
                        "agent.docs",
                        "install",
                    )
                    .await
                    .err()
                    .unwrap();
                    assert!(error
                        .to_string()
                        .contains("app_adoption_witness_not_yet_available_on_v2"));
                    drop(conn);
                }
                let before = k::dump_all_kernel_tables(&db).await.unwrap();
                k::replay_all_projections(&db).await.unwrap();
                assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
            }
            db.close().await;
        }
    }
}

#[tokio::test]
async fn operator_apps_format_three_activates_and_replays_verified_shell_auto() {
    let (_f, db, report) = operator_app_fixture(Some(("adoption", json!("shell_auto.v1")))).await;
    let head:String=sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1").fetch_one(db.pool()).await.unwrap();
    let seq: i64 =
        sqlx::query_scalar("SELECT event_seq FROM kernel_app_state WHERE record_id='secret'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    // SAFETY: synthetic frozen source and exclusively owned target.
    let proof = || unsafe {
        k::app_installs::VerifiedFrozenApps::from_verified_v1_parity_import_unchecked(
            serde_json::from_str(&head).unwrap(),
            "ab".repeat(32),
            BTreeMap::from([("secret".into(), seq)]),
        )
    };
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(&db, &host, proof())
        .await
        .unwrap();
    k::app_installs::activate_as(&db, &host, proof())
        .await
        .unwrap();
    let executable: bool = sqlx::query_scalar(
        "SELECT executable FROM kernel_app_installs WHERE principal=? AND package='agent.docs'",
    )
    .bind(&report.principals["account-a"])
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(executable);
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    assert!(
        k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
            .await
            .is_err(),
        "format 2 cannot reinterpret format 3"
    );
    db.close().await;
}
#[path = "app_state/declarative_apps.rs"]
mod declarative_apps;

#[cfg(feature = "v2-kernel-probe")]
mod app_messaging {
    use super::*;
    use crate::mcp::{app_attribution::AppAttribution, Caller, EngineHandle};

    async fn fixture() -> (Fixture, Db, super::super::super::Report) {
        fixture_version("0.5.18").await
    }
    async fn fixture_version(version: &str) -> (Fixture, Db, super::super::super::Report) {
        fixture_activation(version, true).await
    }
    async fn fixture_activation(
        version: &str,
        activate: bool,
    ) -> (Fixture, Db, super::super::super::Report) {
        let f = Fixture::new().await;
        native_install_source_with_pin(
            &f,
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Synthetic Slack</title></head><body><main>Synthetic messaging fixture</main></body></html>"#,
            "agent.slack-workspace-v2",
            version,
        )
        .await;
        let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
            .await
            .unwrap();
        source.execute(r#"
          INSERT INTO bindings VALUES('person-a','native-principal','principal-a',1),('person-b','native-principal','principal-b',1),('person-c','native-principal','principal-c',1),('person-c','account','account-c',1);
          INSERT INTO records(id,type,kind,name,home_id,owner_id,created_at,updated_at,archived,policy_anchor_id) VALUES
          ('person-a','Entity','person','A','native:root','person-a','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'native:root'),
          ('person-b','Entity','person','B','native:root','person-b','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'native:root'),('person-c','Entity','person','C','native:root','person-c','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'native:root');
        "#).await.unwrap();
        source.close().await.unwrap();
        std::fs::write(&f.members, "account-a\naccount-b\naccount-c\n").unwrap();
        let report = run(f.options(
            &[
                "secret", "note", "person-a", "person-b", "person-c", "folder",
            ],
            false,
        ))
        .await
        .unwrap();
        assert!(
            report.refusals.is_empty(),
            "{}",
            serde_json::to_string(&report.refusals).unwrap()
        );
        let db = f.db().await;
        app_roster(&db, "account-a", &["account-a", "account-b", "account-c"]).await;
        let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
            .await
            .unwrap()
            .unwrap()
            .0;
        if activate {
            k::app_installs::activate_as(&db, &host, operator_app_proof(&db).await)
                .await
                .unwrap();
        }
        // Both members may run the same source; source View is independent of data View.
        k::rehome_record_as(
            &db,
            &report.principals["account-a"],
            "secret",
            KERNEL_ROOT_ID,
        )
        .await
        .unwrap();
        (f, db, report)
    }
    fn app(account: &str) -> Caller {
        app_version(account, "0.5.18")
    }
    fn app_version(account: &str, version: &str) -> Caller {
        Caller::authenticated(account).with_host_asserted_app(
            AppAttribution::new(
                "agent.slack-workspace-v2",
                version,
                match account {
                    "account-a" => "install",
                    "account-b" => "install-b",
                    _ => "install-c",
                },
            )
            .unwrap(),
        )
    }
    async fn call(db: &Db, caller: Caller, args: Value) -> crate::Result<Value> {
        tool(db, caller, "manage_messages", args).await
    }
    async fn tool(db: &Db, caller: Caller, name: &str, args: Value) -> crate::Result<Value> {
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
        registry
            .call_engine(EngineHandle::KernelV2(db.clone()), caller, name, args)
            .await
    }
    fn send(key: &str) -> Value {
        json!({"action":"send","body":"Synthetic Slack channel message","origin":{"type":"collection","collection_id":"folder"},"addressed_to":[],"expectation":"none","idempotency_key":key,"reason":"Message sent from the Slack app"})
    }
    fn inbox_value(mut value: Value) -> Value {
        // Snapshot handles are opaque random tokens; compare every other field.
        assert!(value["snapshot"].is_string());
        value.as_object_mut().unwrap().remove("snapshot");
        value
    }
    #[tokio::test]
    async fn slack_app_inbox_matches_member_view_and_excludes_private_state() {
        let (_f, db, _report) = fixture().await;
        let mut own = send("inbox-own-direct");
        own["origin"] = json!({"type":"direct","participant_ids":["person-a","person-b"]});
        own["addressed_to"] = json!(["person-a"]);
        own["expectation"] = json!("reply");
        let own_request = own.clone();
        let own = call(&db, app("account-b"), own).await.unwrap();
        // Cross the actual default page boundary; omitted limit must return 50.
        for n in 0..50 {
            let mut request = own_request.clone();
            request["idempotency_key"] = json!(format!("inbox-page-{n}"));
            call(&db, app("account-b"), request).await.unwrap();
        }
        let mut other = send("inbox-other-direct");
        other["origin"] = json!({"type":"direct","participant_ids":["person-b","person-c"]});
        other["addressed_to"] = json!(["person-c"]);
        let other = call(&db, app("account-b"), other).await.unwrap();
        // Establish privacy before the folder's policy-inheriting child home
        // is bound. Moving only a public Collection record afterwards does
        // not change that already-created child home's audience.
        let folder = tool(&db, Caller::authenticated("account-a"), "create_record",
            json!({"type":"Collection","kind":"folder","name":"Private inbox fixture","home_id":"folder","access_policy":"account_only"}))
            .await.unwrap();
        let mut private = send("inbox-private-channel");
        private["origin"] = json!({"type":"collection","collection_id":folder["id"]});
        let private = call(&db, app("account-a"), private).await.unwrap();
        // Prove the actual folder AND message access boundary independently
        // of inbox app/member equality: both callers could otherwise leak.
        for account in ["account-a", "account-b", "account-c"] {
            let get = tool(
                &db,
                Caller::authenticated(account),
                "get_record",
                json!({"ids":[folder["id"],private["id"]]}),
            )
            .await
            .unwrap();
            let rows = get["records"].as_array().unwrap();
            assert_eq!(rows.len(), 2);
            let status = if account == "account-a" {
                "found"
            } else {
                "not_found"
            };
            assert!(
                rows.iter().all(|row| row["status"] == status),
                "{account}: {get}"
            );
        }
        // B's private preference must not become A's inbox state.
        call(&db, app("account-b"), json!({"action":"set_preference","message_id":own["id"],"preference":"archive","expected_version":0,"idempotency_key":"inbox-b-archive","reason":"Private B preference"})).await.unwrap();
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        for account in ["account-a", "account-b", "account-c"] {
            for request in [
                json!({"action":"list_inbox"}),
                json!({"action":"list_inbox","view":"browse","limit":200}),
                json!({"action":"list_inbox","view":"browse","scope":"direct","limit":1,"preview_chars":8}),
            ] {
                let member = call(&db, Caller::authenticated(account), request.clone())
                    .await
                    .unwrap();
                let installed = call(&db, app(account), request.clone()).await.unwrap();
                assert_eq!(
                    inbox_value(installed.clone()),
                    inbox_value(member),
                    "{account}: {request}"
                );
                let page = installed["items"].as_array().unwrap();
                if account == "account-a" {
                    assert!(!page.iter().any(|row| row["message_id"] == other["id"]));
                    if request["view"] == "browse" && request["scope"].is_null() {
                        let row = page
                            .iter()
                            .find(|row| row["message_id"] == own["id"])
                            .unwrap();
                        assert_eq!(row["attention"]["archived"], false);
                    }
                } else {
                    assert!(!page.iter().any(|row| row["message_id"] == private["id"]));
                    if account == "account-c" {
                        assert!(!page.iter().any(|row| row["message_id"] == own["id"]));
                    } else if request["view"] == "browse" && request["scope"].is_null() {
                        let row = page
                            .iter()
                            .find(|row| row["message_id"] == own["id"])
                            .unwrap();
                        assert_eq!(row["attention"]["archived"], true);
                    }
                }
                if request["limit"] == 1 {
                    assert!(page.len() <= 1);
                }
            }
        }
        let default = call(&db, app("account-a"), json!({"action":"list_inbox"}))
            .await
            .unwrap();
        assert_eq!(default["view"], "needs_me");
        assert_eq!(default["items"].as_array().unwrap().len(), 50);
        assert_eq!(default["next_after"], 50);
        let continuation = json!({"action":"list_inbox","snapshot":default["snapshot"],"after":50});
        let tail = call(&db, app("account-a"), continuation.clone())
            .await
            .unwrap();
        assert_eq!(tail["items"].as_array().unwrap().len(), 1);
        assert_eq!(tail["items"][0]["message_id"], own["id"]);
        assert_eq!(
            inbox_value(tail),
            inbox_value(
                call(&db, Caller::authenticated("account-a"), continuation)
                    .await
                    .unwrap()
            )
        );
        // The closed transport rejects forged claims and viewer selectors.
        let forged = json!({"action":"list_inbox","view":"browse","recipient_id":"person-c","account_id":"account-c","app":{"package":"agent.slack-workspace-v2","version":"0.5.18","install_event_id":"install-c"}});
        let refused = call(&db, Caller::authenticated("account-a"), forged.clone())
            .await
            .unwrap_err()
            .to_string();
        assert!(refused.contains("unknown field"), "{refused}");
        assert_eq!(
            call(&db, app("account-a"), forged)
                .await
                .unwrap_err()
                .to_string(),
            refused
        );
        for request in [
            json!({"action":"list_inbox","limit":0}),
            json!({"action":"list_inbox","limit":201}),
            json!({"action":"list_inbox","scope":"all"}),
            json!({"action":"list_inbox","preview_chars":1001}),
            json!({"action":"list_inbox","snapshot":default["snapshot"]}),
        ] {
            assert_eq!(
                call(&db, app("account-b"), request.clone())
                    .await
                    .unwrap_err()
                    .to_string(),
                call(&db, Caller::authenticated("account-b"), request)
                    .await
                    .unwrap_err()
                    .to_string()
            );
        }
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
        db.close().await;
    }
    #[tokio::test]
    async fn slack_app_inbox_requires_activation_and_host_claim_not_json() {
        let (_f, db, _report) = fixture_activation("0.5.18", false).await;
        let request = json!({"action":"list_inbox"});
        assert!(call(&db, app("account-a"), request.clone()).await.is_err());
        let mut forged = request;
        forged["app"] = json!({"package":"agent.slack-workspace-v2","version":"0.5.18","install_event_id":"install"});
        assert!(call(&db, app("account-a"), forged.clone()).await.is_err());
        let refused = call(&db, Caller::authenticated("account-a"), forged)
            .await
            .unwrap_err()
            .to_string();
        assert!(refused.contains("unknown field"), "{refused}");
        // A clean member read still works without app activation; JSON never
        // upgrades it to an admitted app call.
        assert!(call(
            &db,
            Caller::authenticated("account-a"),
            json!({"action":"list_inbox"})
        )
        .await
        .is_ok());
        db.close().await;
    }
    #[tokio::test]
    async fn slack_041_observed_send_is_attributed_idempotent_and_replayable() {
        let (_f, db, _report) = fixture_version("0.4.1").await;
        let caller = app_version("account-a", "0.4.1");
        let request = send("slack-041-send");
        let receipt = call(&db, caller.clone(), request.clone()).await.unwrap();
        assert_eq!(receipt["app_attribution"]["version"], "0.4.1");
        assert_eq!(call(&db, caller, request).await.unwrap(), receipt);
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        k::replay_all_projections(&db).await.unwrap();
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
        db.close().await;
    }
    #[tokio::test]
    async fn slack_0518_observed_paths_are_atomic_app_bound_and_replayable() {
        let (_f, db, report) = fixture().await;
        // Synthetic 0.5.18 identity and the observed state/preference/destination,
        // relevance and opened payloads; no retained production source.
        let args = send("slack-041-send");
        let sent = call(&db, app("account-a"), args.clone()).await.unwrap();
        let id = sent["id"].as_str().unwrap();
        assert_eq!(
            sent["app_attribution"]["package"],
            "agent.slack-workspace-v2"
        );
        assert_eq!(
            call(&db, app("account-a"), args.clone()).await.unwrap(),
            sent
        );
        assert!(
            call(&db, Caller::authenticated("account-a"), args.clone())
                .await
                .is_err(),
            "a member cannot replay an app receipt"
        );
        let mut changed = args.clone();
        changed["body"] = json!("Another intent");
        assert!(call(&db, app("account-a"), changed).await.is_err());
        let direct = send("direct-receipt");
        call(&db, Caller::authenticated("account-a"), direct.clone())
            .await
            .unwrap();
        assert!(
            call(&db, app("account-a"), direct).await.is_err(),
            "an app cannot replay a member receipt"
        );
        let state = call(
            &db,
            app("account-a"),
            json!({"action":"list_message_state","message_ids":[id]}),
        )
        .await
        .unwrap();
        assert_eq!(state["messages"][0]["message_id"], id);
        for (i, pref) in ["snooze", "clear_snooze", "archive", "restore", "mark_read"]
            .into_iter()
            .enumerate()
        {
            let mut p = json!({"action":"set_preference","message_id":id,"preference":pref,"expected_version":i,"idempotency_key":format!("slack-0518-{pref}"),"reason":"Synthetic Slack preference"});
            if pref == "snooze" {
                p["snoozed_until"] = json!("2099-01-01T00:00:00Z");
            }
            let out = call(&db, app("account-a"), p.clone()).await.unwrap();
            assert!(out["app_attribution"].is_object());
            assert_eq!(call(&db, app("account-a"), p).await.unwrap(), out);
        }
        let destinations = call(&db, app("account-a"), json!({"action":"list_destinations"}))
            .await
            .unwrap();
        assert!(destinations.to_string().contains("folder"));
        let join = json!({"action":"set_destination","collection_id":"folder","destination":"add","expected_version":0,"idempotency_key":"slack-join","reason":"Join in Slack"});
        let joined = call(&db, app("account-b"), join.clone()).await.unwrap();
        assert_eq!(joined["changed"], true);
        assert_eq!(call(&db, app("account-b"), join).await.unwrap(), joined);
        for action in ["mark_no_longer_relevant", "unmark_no_longer_relevant"] {
            let request = json!({"action":action,"message_id":id,"idempotency_key":action,"reason":"Synthetic Slack relevance","note":"Keep the history"});
            // `note` is only part of mark's contract.
            let mut request = request;
            if action.starts_with("unmark") {
                request.as_object_mut().unwrap().remove("note");
            }
            let out = call(&db, app("account-a"), request.clone()).await.unwrap();
            assert!(out["app_attribution"].is_object());
            assert_eq!(call(&db, app("account-a"), request).await.unwrap(), out);
        }
        let ids = vec![id.to_owned()];
        let issuer = crate::awareness::HumanInteractionTokenIssuer::random("synthetic-slack-open");
        let token = issuer.issue("account-b", "opened", &ids, 60).unwrap();
        let caller = app("account-b")
            .with_human_interaction_token(&issuer, &token, "opened", &ids)
            .unwrap();
        let opened = json!({"action":"mutate_human_awareness","message_ids":ids,"stage":"opened","expected_versions":{id:0},"idempotency_key":"slack-opened","reason":"Opened mention in Slack"});
        assert!(call(&db, app("account-b"), opened.clone()).await.is_err());
        let out = call(&db, caller.clone(), opened.clone()).await.unwrap();
        assert_eq!(out["results"][0]["stage"], "opened");
        assert_eq!(call(&db, caller, opened).await.unwrap(), out);
        let token = issuer.issue("account-b", "opened", &ids, 60).unwrap();
        let caller = app("account-b")
            .with_human_interaction_token(&issuer, &token, "opened", &ids)
            .unwrap();
        let noop = json!({"action":"mutate_human_awareness","message_ids":ids,"stage":"opened","expected_versions":{id:1},"idempotency_key":"slack-opened-noop","reason":"Already opened"});
        let noop_out = call(&db, caller.clone(), noop.clone()).await.unwrap();
        assert_eq!(noop_out["changed"], false);
        assert_eq!(
            call(&db, caller, noop).await.unwrap(),
            noop_out,
            "no-op awareness retries keep their original app attribution"
        );
        let own = call(
            &db,
            app("account-a"),
            json!({"action":"list_message_state","message_ids":[id]}),
        )
        .await
        .unwrap();
        assert_ne!(
            own["messages"][0]["human"]["stage"], "opened",
            "app reports never mutate another member's awareness"
        );
        let bad_before = k::dump_all_kernel_tables(&db).await.unwrap();
        for action in [
            "add_reaction",
            "remove_reaction",
            "list_context",
            "edit",
            "delete",
            "set_routing",
            "set_agent_disposition",
            "get_attention",
            "share_history",
            "unknown",
            "classify",
            "unclassify",
            "move",
            "satisfy_acknowledgement_expectation_with_reaction",
            "list_conversation",
            "list_unclassified",
            "list_my_conversations",
            "list_notification_candidates",
            "get_notification_preference",
            "set_notification_preference",
        ] {
            let error = call(
                &db,
                app("account-a"),
                json!({"action":action,"message_id":id}),
            )
            .await
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("app_operation_unsupported_on_v2"),
                "{action}: {error}"
            );
        }
        assert_eq!(bad_before, k::dump_all_kernel_tables(&db).await.unwrap());
        sqlx::query("CREATE TRIGGER fail_app_completion BEFORE INSERT ON kernel_app_actions BEGIN SELECT RAISE(ABORT,'synthetic app completion failure'); END").execute(db.write_pool()).await.unwrap();
        let before_failure = k::dump_all_kernel_tables(&db).await.unwrap();
        for request in [
            send("late-attribution-failure"),
            json!({"action":"mark_no_longer_relevant","message_id":id,"idempotency_key":"late-mark-failure","reason":"Rollback a relevance effect too"}),
        ] {
            assert!(call(&db, app("account-a"), request).await.is_err());
            assert_eq!(
                before_failure,
                k::dump_all_kernel_tables(&db).await.unwrap(),
                "late attribution failure rolls back effects and receipts"
            );
        }
        sqlx::query("DROP TRIGGER fail_app_completion")
            .execute(db.write_pool())
            .await
            .unwrap();
        let mismatches:i64=sqlx::query_scalar("SELECT count(*) FROM kernel_app_actions a JOIN content_events s ON s.id=a.admitted_event_id JOIN content_events c ON c.id=a.event_id WHERE s.act<>c.act OR EXISTS(SELECT 1 FROM json_each(a.outputs_json) o JOIN content_events e ON e.id=json_extract(o.value,'$.event_id') WHERE e.act<>s.act)").fetch_one(db.pool()).await.unwrap();
        assert_eq!(mismatches, 0);
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        k::replay_all_projections(&db).await.unwrap();
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
        assert!(k::read_record_as(&db, &report.principals["account-a"], id)
            .await
            .unwrap()
            .is_some());
        db.close().await;
    }
    #[tokio::test]
    async fn slack_app_admission_rechecks_identity_source_and_revocation_on_retries() {
        let (_f, db, report) = fixture().await;
        let args = send("consent-send");
        let sent = call(&db, app("account-a"), args.clone()).await.unwrap();
        assert!(sent["id"].is_string());
        let read = json!({"action":"list_inbox"});
        for (version, generation) in [
            ("0.4.1", "install"),
            ("0.5.18", "another-generation"),
            ("0.5.18", "install-b"),
        ] {
            let caller = Caller::authenticated("account-a").with_host_asserted_app(
                AppAttribution::new("agent.slack-workspace-v2", version, generation).unwrap(),
            );
            assert!(call(&db, caller, read.clone()).await.is_err());
        }
        let a = &report.principals["account-a"];
        let other_send = send("source-view-retry");
        call(&db, app("account-b"), other_send.clone())
            .await
            .unwrap();
        let hidden = k::create_home(&db, KERNEL_ROOT_ID, Some(&[(a, "manage")]), a)
            .await
            .unwrap();
        k::rehome_record_as(&db, a, "secret", &hidden)
            .await
            .unwrap();
        assert!(call(&db, app("account-b"), read.clone()).await.is_err());
        assert!(call(&db, app("account-b"), other_send).await.is_err());
        k::rehome_record_as(&db, a, "secret", KERNEL_ROOT_ID)
            .await
            .unwrap();
        assert!(call(&db, app("account-b"), read.clone()).await.is_ok());
        let mut forbidden = send("hidden-destination");
        forbidden["origin"] = json!({"type":"collection","collection_id":"private"});
        let before_visibility = k::dump_all_kernel_tables(&db).await.unwrap();
        let app_error = call(&db, app("account-b"), forbidden.clone())
            .await
            .unwrap_err()
            .to_string();
        let member_error = call(&db, Caller::authenticated("account-b"), forbidden)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(app_error, member_error);
        assert_eq!(
            before_visibility,
            k::dump_all_kernel_tables(&db).await.unwrap()
        );
        // Preserve a preflight claim across removal. The actual snapshot must
        // re-admit, even if dispatch already accepted this member/session.
        let caller = app("account-a");
        let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
            &caller,
            "manage_messages",
            &args,
            None,
        );
        k::app_installs::remove_as(&db, a, "agent.slack-workspace-v2", "install")
            .await
            .unwrap();
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        dispatch
            .scope(async {
                let mut tx = db.write_pool().begin().await.unwrap();
                assert!(k::app_installs::admit_dispatched_on(&mut tx, a)
                    .await
                    .is_err());
                tx.rollback().await.unwrap();
            })
            .await;
        assert!(call(&db, caller.clone(), read).await.is_err());
        assert!(call(&db, caller, args).await.is_err());
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
        db.close().await;
    }
    #[tokio::test]
    async fn slack_app_offboarding_epoch_survives_member_readmission() {
        let (_f, db, report) = fixture().await;
        let args = send("epoch-receipt");
        let sent = call(&db, app("account-a"), args.clone()).await.unwrap();
        app_roster(&db, "account-b", &["account-b"]).await;
        // SAFETY: complete synthetic catalogue; B is the retained recipient.
        let offboard = unsafe {
            k::hosted_identity::offboarding::VerifiedOffboarding::from_catalog_unchecked(
                uuid::Uuid::new_v4().to_string(),
                "account-b".into(),
                "account-a".into(),
                "account-b".into(),
                "Fixture revocation".into(),
            )
        };
        k::hosted_identity::offboarding::apply(&db, offboard)
            .await
            .unwrap();
        assert!(call(&db, app("account-a"), json!({"action":"list_inbox"}))
            .await
            .is_err());
        app_roster(&db, "account-a", &["account-a", "account-b"]).await;
        let epoch: i64 = sqlx::query_scalar(
            "SELECT event_seq FROM kernel_app_consent_revocations WHERE principal=?",
        )
        .bind(&report.principals["account-a"])
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert!(epoch > 0);
        assert!(call(&db, app("account-a"), json!({"action":"list_inbox"}))
            .await
            .is_err());
        assert!(
            call(&db, app("account-a"), args).await.is_err(),
            "readmission never revives an old app receipt"
        );
        assert!(call(
            &db,
            app("account-a"),
            json!({"action":"list_message_state","message_ids":[sent["id"]]})
        )
        .await
        .is_err());
        db.close().await;
    }
    #[tokio::test]
    async fn slack_app_direct_privacy_and_recipient_visibility_equal_member_calls() {
        let (_f, db, report) = fixture().await;
        let mut args = send("app-direct-private");
        args["origin"] = json!({"type":"direct","participant_ids":["person-b","person-c"]});
        args["addressed_to"] = json!(["person-c"]);
        args["expectation"] = json!("reply");
        let sent = call(&db, app("account-b"), args.clone()).await.unwrap();
        let id = sent["id"].as_str().unwrap();
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        for action in [
            "list_message_state",
            "mark_no_longer_relevant",
            "unmark_no_longer_relevant",
            "set_preference",
        ] {
            let request = if action == "list_message_state" {
                json!({"action":action,"message_ids":[id]})
            } else {
                json!({"action":action,"message_id":id,"preference":"mark_read","expected_version":0,"idempotency_key":action,"reason":"Must preserve Direct privacy"})
            };
            let app_error = call(&db, app("account-a"), request.clone())
                .await
                .unwrap_err()
                .to_string();
            let member_error = call(&db, Caller::authenticated("account-a"), request)
                .await
                .unwrap_err()
                .to_string();
            assert_eq!(app_error, member_error);
        }
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
        let mark=call(&db,app("account-c"),json!({"action":"mark_no_longer_relevant","message_id":id,"note":"Synthetic Slack mark","idempotency_key":"recipient-c-mark","reason":"No longer relevant in Slack"})).await.unwrap();
        let marks=tool(&db,app("account-b"),"query_sql",json!({"sql":"SELECT l.target_id AS message_id, substr(r.body, 1, 360) AS note, (SELECT e.actor FROM content_events e WHERE e.record_id = r.id ORDER BY e.local_seq LIMIT 1) AS author_account FROM links l JOIN records r ON r.id = l.source_id WHERE l.relationship = 'resolves' AND l.note = 'no_longer_relevant' AND r.type = 'Annotation' AND r.kind = 'no_longer_relevant' AND r.deleted_at IS NULL AND r.archived = 0 AND l.target_id IN (SELECT m.id FROM records m WHERE m.type = 'Message' AND m.deleted_at IS NULL AND (m.home_id IS NULL OR m.home_id = 'native:unfiled')) ORDER BY r.created_at DESC, r.id DESC LIMIT 200"})).await.unwrap();
        assert_eq!(
            marks["rows"],
            json!([{"message_id":id,"note":"Synthetic Slack mark","author_account":report.principals["account-c"]}])
        );
        assert!(mark["app_attribution"].is_object());
        let a = &report.principals["account-a"];
        let private = k::create_home(&db, KERNEL_ROOT_ID, Some(&[(a, "manage")]), a)
            .await
            .unwrap();
        k::rehome_record_as(&db, a, "person-c", &private)
            .await
            .unwrap();
        args["idempotency_key"] = json!("recipient-no-longer-visible");
        let app_error = call(&db, app("account-b"), args.clone())
            .await
            .unwrap_err()
            .to_string();
        let member_error = call(&db, Caller::authenticated("account-b"), args)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(app_error, member_error);
        db.close().await;
    }
}

#[tokio::test]
async fn native_app_sql_separates_only_admitted_staging_from_the_caller_vm_bound() {
    use crate::mcp::kernel_v2::sql::with_elapsed;
    use crate::mcp::{app_attribution::AppAttribution, Caller, EngineHandle};
    use std::time::Duration;

    let f = Fixture::new().await;
    let body = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>SQL reader</title></head><body><main>Sample</main></body></html>"#;
    let (db, report) = native_install_fixture_with_body(&f, body).await;
    let actor = &report.principals["account-a"];
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let request = json!({"sql":"SELECT id FROM records ORDER BY id"});
    let mut registry = crate::mcp::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let call = |caller, request| {
        registry.call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller,
            "query_sql",
            request,
        )
    };
    let ordinary = || Caller::authenticated("account-a");
    let app = || {
        ordinary()
            .with_host_asserted_app(AppAttribution::new("agent.docs", "0.8.2", "install").unwrap())
    };

    // A host assertion without executable activation is not admission.
    assert!(with_elapsed(
        Duration::from_secs(3),
        Duration::ZERO,
        call(app(), request.clone())
    )
    .await
    .is_err());
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let expected = call(ordinary(), request.clone()).await.unwrap();
    let actual = with_elapsed(
        Duration::from_secs(3),
        Duration::ZERO,
        call(app(), request.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        actual, expected,
        "app allowance must preserve all visible results"
    );

    let denied = with_elapsed(
        Duration::from_secs(3),
        Duration::ZERO,
        call(ordinary(), request.clone()),
    )
    .await
    .unwrap_err();
    assert!(
        denied.to_string().contains("query_sql [timeout]"),
        "{denied}"
    );
    // Caller JSON cannot select an allowance or establish app admission.
    let mut forged = request.clone();
    forged["app"] = json!({"package":"agent.docs","version":"0.8.2","install_event_id":"install"});
    forged["staging_budget_ms"] = json!(8000);
    assert!(with_elapsed(
        Duration::from_secs(3),
        Duration::ZERO,
        call(ordinary(), forged)
    )
    .await
    .is_err());
    let stale = ordinary().with_host_asserted_app(
        AppAttribution::new("agent.docs", "0.8.2", "forged-generation").unwrap(),
    );
    assert!(with_elapsed(
        Duration::from_secs(3),
        Duration::ZERO,
        call(stale, request.clone())
    )
    .await
    .is_err());

    let denied = with_elapsed(
        Duration::from_secs(9),
        Duration::ZERO,
        call(app(), request.clone()),
    )
    .await
    .unwrap_err();
    assert!(
        denied.to_string().contains("query_sql [timeout]"),
        "{denied}"
    );
    // Enough visible rows to invoke SQLite's progress handler deterministically.
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<20) INSERT INTO kernel_records(id,home_id,owner_id,created_seq,created_at) SELECT printf('vm-bound:%05d',x),r.home_id,r.owner_id,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id='note'")
        .execute(db.write_pool()).await.unwrap();
    let denied = with_elapsed(Duration::ZERO, Duration::from_secs(3),
        call(app(), json!({"sql":"SELECT count(*) AS n FROM records a CROSS JOIN records b CROSS JOIN records c"})))
        .await.unwrap_err();
    assert!(
        denied.to_string().contains("query_sql [timeout]"),
        "{denied}"
    );

    k::app_installs::remove_as(&db, actor, "agent.docs", "install")
        .await
        .unwrap();
    assert!(
        with_elapsed(Duration::from_secs(3), Duration::ZERO, call(app(), request))
            .await
            .is_err()
    );
    db.close().await;
}

#[cfg(feature = "package-cel-dev")]
#[path = "app_state/package_delivery.rs"]
mod package_delivery;
