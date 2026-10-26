//! Native HTML uses the ordinary v1 sanitizer and isolated delivery, backed by
//! sealed frozen source authority rather than a v1 storage handle.
use super::*;
use crate::mcp::tools::alpha_tabs::AppBundleDelivery;
use std::sync::Arc;

const HTML: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Frozen</title></head><body><main><h1>Frozen artifact</h1></main></body></html>"#;

fn delivery() -> AppBundleDelivery {
    AppBundleDelivery { enabled:true,
        runtime:crate::artifact_html::RuntimeConfig::new("https://parent.test","https://artifact.test").unwrap(),
        keyring:Some(Arc::new(native_artifact_runtime::deployment_keyring::DeploymentKeyring::from_json_bundle(
            r#"{"active_key_id":"test","keys":[{"id":"test","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}"#).unwrap())) }
}

fn caller(account: &str) -> crate::mcp::Caller {
    // SAFETY: these tests own the complete authenticated fixture ingress.
    unsafe {
        crate::mcp::Caller::authenticated(account)
            .with_hosting_context(account, "fixture-db")
            .with_verified_hosting_session("11111111-1111-4111-8111-111111111111")
    }
}

async fn frozen(body: &str, runtime: &str, target: Option<&str>) -> (Fixture, Db, String) {
    frozen_source(body, runtime, target, false).await
}

async fn frozen_source(
    body: &str,
    runtime: &str,
    target: Option<&str>,
    attested: bool,
) -> (Fixture, Db, String) {
    frozen_source_shape(body, runtime, target, attested, false).await
}

async fn frozen_source_shape(
    body: &str,
    runtime: &str,
    target: Option<&str>,
    attested: bool,
    historical: bool,
) -> (Fixture, Db, String) {
    frozen_source_package_shape(body, runtime, target, attested, historical, false, false).await
}

async fn frozen_source_package_shape(
    body: &str,
    runtime: &str,
    target: Option<&str>,
    attested: bool,
    historical: bool,
    package: bool,
    folder_membership: bool,
) -> (Fixture, Db, String) {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
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
    sqlx::query(
        "INSERT INTO facet_values VALUES('secret','runtime',?,NULL,NULL,'2026-01-01T00:00:00Z')",
    )
    .bind(runtime)
    .execute(&mut source)
    .await
    .unwrap();
    source
        .execute(
            "INSERT INTO facet_observations VALUES('secret','runtime','2026-01-01T00:00:00Z',1)",
        )
        .await
        .unwrap();
    if package {
        source.execute("INSERT INTO facet_values VALUES('secret','app_package','true',NULL,NULL,'2026-01-01T00:00:00Z')").await.unwrap();
        source.execute("INSERT INTO facet_observations VALUES('secret','app_package','2026-01-01T00:00:00Z',1)").await.unwrap();
    }
    if let Some(target) = target {
        sqlx::query("INSERT INTO links(id,source_id,target_id,relationship,created_at) VALUES('board-renders','secret',?,'renders','2026-01-01T00:00:00Z')")
            .bind(target).execute(&mut source).await.unwrap();
    }
    if attested {
        let html = crate::artifact_html::validate_cached_with_limit(
            body,
            if package {
                crate::artifact_html::PACKAGE_BODY_LIMIT
            } else {
                crate::artifact_html::BODY_LIMIT
            },
        )
        .unwrap();
        let mut attestation=crate::mcp::tools::artifacts::artifact_source_attestation_payload("secret","html-attestation","created:secret",body,
            json!({"runtime":runtime,"artifact_ports":html.artifact_ports,"imports":[],"module_inputs":{},"capability_requests":html.capability_requests,"interactions":html.interactions,"diagnostics":html.diagnostics})).unwrap();
        if historical {
            attestation
                .artifact_source
                .as_object_mut()
                .unwrap()
                .remove("interactions");
            attestation
                .artifact_source
                .as_object_mut()
                .unwrap()
                .remove("write_diagnostics");
            attestation.attestation_sha256 =
                crate::mcp::tools::artifacts::mdx_sha256_for_projection(
                    &attestation.artifact_source,
                );
        }
        source.execute("ALTER TABLE artifact_source_attestations ADD COLUMN source_sha256 TEXT; ALTER TABLE artifact_source_attestations ADD COLUMN attestation_sha256 TEXT; ALTER TABLE artifact_source_attestations ADD COLUMN event_seq INTEGER; ALTER TABLE artifact_source_attestations ADD COLUMN created_at TEXT").await.unwrap();
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('html-attestation','secret','artifact.source_attested',?,'account-a','2026-02-02T00:00:00Z')")
            .bind(serde_json::to_string(&attestation).unwrap()).execute(&mut source).await.unwrap();
        let seq: i64 =
            sqlx::query_scalar("SELECT seq FROM content_events WHERE id='html-attestation'")
                .fetch_one(&mut source)
                .await
                .unwrap();
        sqlx::query("INSERT INTO artifact_source_attestations VALUES('secret','html-attestation','created:secret',?,?,?,?,?)")
            .bind(serde_json::to_string(&attestation.artifact_source).unwrap())
            .bind(native_artifact_runtime::mdx::sha256_hex(body.as_bytes()))
            .bind(&attestation.attestation_sha256).bind(seq).bind("2026-02-02T00:00:00Z")
            .execute(&mut source).await.unwrap();
    }
    if folder_membership {
        // Reuse Fixture's private child policy; run(options) below creates its
        // v2 boundary through import_home_policy_as and the policy projector.
        // The artifact source uses the existing root policy so both members
        // can render it without introducing a second source policy fixture.
        source.execute("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id) SELECT 'part-only',type,kind,'Part-only',body,'native:root',owner_id,lifecycle,summary,created_at,updated_at,0,'native:root' FROM records WHERE id='note'; INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('created:part-only','part-only','record.created','{}','original-creator','2026-01-01T00:00:00Z'); INSERT INTO links VALUES('part-only-folder','part-only','folder','part_of',NULL,'2026-01-01T00:00:00Z')").await.unwrap();
        source.execute("UPDATE records SET home_id='folder',type='Document',kind='note' WHERE id='private'; UPDATE records SET home_id='folder',policy_anchor_id='native:root' WHERE id='secret'; UPDATE records SET archived=1 WHERE id='archived'; UPDATE records SET deleted_at='2026-02-03T00:00:00Z' WHERE id='task'").await.unwrap();
    }
    source.close().await.unwrap();
    let mut options = f.options(
        if folder_membership {
            &["secret", "private", "note", "archived", "task", "part-only"]
        } else {
            &["secret", "private", "note"]
        },
        false,
    );
    options.history = true;
    let report = run(options).await.unwrap();
    assert!(report.refusals.is_empty());
    assert!(report.app_state.capture_complete);
    let db = f.db().await;
    super::app_state::app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let head:String=sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1").fetch_one(db.pool()).await.unwrap();
    let digest = native_artifact_runtime::mdx::sha256_hex(body.as_bytes());
    // SAFETY: full synthetic frozen import above, exclusive fixture database.
    let proof = if attested {
        let seq: i64 =
            sqlx::query_scalar("SELECT event_seq FROM kernel_app_state WHERE record_id='secret'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        // SAFETY: exact synthetic attestation and completed import above.
        unsafe {
            k::artifact_closures::VerifiedArtifactClosure::from_verified_import_unchecked(
                serde_json::from_str(&head).unwrap(),
                "ab".repeat(32),
                "secret".into(),
                seq,
            )
        }
    } else {
        unsafe {
            k::artifact_closures::VerifiedArtifactClosure::from_verified_legacy_import_unchecked(
                serde_json::from_str(&head).unwrap(),
                "ab".repeat(32),
                "secret".into(),
                "created:secret".into(),
                digest,
                runtime.into(),
                target.into_iter().map(str::to_owned).collect(),
            )
        }
    };
    k::artifact_closures::activate_as(&db, &host, proof)
        .await
        .unwrap();
    let actor = k::resolve_principal_by_binding(&db, "account-a")
        .await
        .unwrap()
        .unwrap()
        .0;
    (f, db, actor)
}

async fn render(db: &Db, actor: &str, account: &str) -> Value {
    crate::mcp::kernel_v2::artifacts::html_board::try_render(
        db,
        &caller(account),
        actor,
        &json!({"id":"secret"}),
        Some(&delivery()),
    )
    .await
    .unwrap()
    .unwrap()
}

#[tokio::test]
async fn imported_native_html_frozen_source_visibility_liveness_and_replay() {
    let (_f, db, actor) = frozen(HTML, crate::artifact_html::RUNTIME_ID, None).await;
    let rendered = render(&db, &actor, "account-a").await;
    assert_eq!(rendered["status"], "rendered", "{rendered}");
    assert_eq!(rendered["plan"]["kind"], "isolated_html");
    assert!(rendered["runtime"].get("verification").is_some());
    assert_eq!(rendered["launch"]["expires_in_ms"], 300_000);
    assert_eq!(
        rendered["plan"]["body_digest"],
        native_artifact_runtime::mdx::sha256_hex(HTML.as_bytes())
    );
    let url = rendered["launch"]["url"].as_str().unwrap();
    let (digest, cap) = url
        .split(native_artifact_html::bundle_url::ROUTE_PATH)
        .nth(1)
        .unwrap()
        .split_once('/')
        .unwrap();
    let fields = native_artifact_html::bundle_url::verify(
        delivery().keyring.as_ref().unwrap(),
        "https://artifact.test",
        digest,
        cap,
        chrono::Utc::now().timestamp() as u64,
    )
    .unwrap();
    assert!(fields.artifact_render);
    assert!(fields.preview_receipt.is_none());
    assert_eq!(fields.install_event, "secret");
    let mut tx = db.pool().begin().await.unwrap();
    let source = crate::mcp::kernel_v2::artifacts::html_board::bundle_source_on(
        &mut tx, &actor, "secret", digest,
    )
    .await
    .unwrap();
    assert_eq!(source.0, HTML);
    tx.rollback().await.unwrap();
    let bytes =
        crate::artifact_html::compose_bundle_delivery(&source.0, "https://parent.test", source.1)
            .unwrap();
    assert!(bytes.contains("native-html-bootstrap"));
    let csp = crate::artifact_html::bundle_delivery_headers("https://parent.test").unwrap();
    assert_eq!(
        csp["Content-Security-Policy"],
        crate::artifact_html::content_security_policy("https://parent.test").unwrap()
    );
    let other = k::resolve_principal_by_binding(&db, "account-b")
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(render(&db, &other, "account-b").await["status"], "error");
    let mut tx = db.pool().begin().await.unwrap();
    assert!(
        crate::mcp::kernel_v2::artifacts::html_board::bundle_source_on(
            &mut tx, &other, "secret", digest
        )
        .await
        .is_err()
    );
    tx.rollback().await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(render(&db, &actor, "account-a").await["status"], "rendered");
    let mut registry = crate::mcp::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_hosted_kernel_v2_tools(&mut registry).unwrap();
    registry
        .call_engine(
            crate::mcp::registry::EngineHandle::KernelV2(db.clone()),
            crate::mcp::Caller::authenticated("account-a"),
            "archive_record",
            json!({"id":"secret","archived":true,"reason":"Archive frozen HTML"}),
        )
        .await
        .unwrap();
    // v1 direct rendering permits archival; View and the current source
    // still determine availability. Archival is not a source edit.
    assert_eq!(render(&db, &actor, "account-a").await["status"], "rendered");
    let mut tx = db.pool().begin().await.unwrap();
    assert!(
        crate::mcp::kernel_v2::artifacts::html_board::bundle_source_on(
            &mut tx, &actor, "secret", digest
        )
        .await
        .is_ok()
    );
    tx.rollback().await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn html_ordinary_render_keeps_v1_source_ceiling_for_marked_packages() {
    let body = HTML.replace(
        "</main>",
        &format!(
            "<!--{}--></main>",
            "a".repeat(crate::artifact_html::BODY_LIMIT)
        ),
    );
    let v1_failure = crate::artifact_html::validate_cached(&body).unwrap_err();
    assert_eq!(v1_failure.code, "html_source_too_large");
    assert!(crate::artifact_html::validate_cached_with_limit(
        &body,
        crate::artifact_html::PACKAGE_BODY_LIMIT
    )
    .is_ok());
    let (_f, db, actor) = frozen_source_package_shape(
        &body,
        crate::artifact_html::RUNTIME_ID,
        None,
        false,
        false,
        true,
        false,
    )
    .await;
    let rendered = render(&db, &actor, "account-a").await;
    assert_eq!(
        rendered["diagnostic"]["code"], v1_failure.code,
        "{rendered}"
    );
    let mut tx = db.pool().begin().await.unwrap();
    assert!(
        crate::mcp::kernel_v2::artifacts::html_board::bundle_source_on(
            &mut tx,
            &actor,
            "secret",
            &native_artifact_runtime::mdx::sha256_hex(body.as_bytes()),
        )
        .await
        .is_err()
    );
    tx.rollback().await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn imported_native_board_uses_the_v1_adapter_and_frozen_renders_binding() {
    let body = r#"{"v":"1","title":"Board","group_by":"kind","lanes":[{"title":"Artifacts","value":"artifact"}]}"#;
    let (_f, db, actor) = frozen(body, "native.board.v1", Some("private")).await;
    let rendered = render(&db, &actor, "account-a").await;
    assert_eq!(rendered["status"], "rendered", "{rendered}");
    assert_eq!(rendered["plan"]["kind"], "board");
    assert!(rendered["runtime"].get("verification").is_some());
    assert_eq!(rendered["plan"]["title"], "Board");
    assert_eq!(rendered["input"]["mode"], "bound");
    assert!(rendered["plan"]["lanes"][0]["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == "secret"));
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(
        render(&db, &actor, "account-a").await["plan"],
        rendered["plan"]
    );
    // Persisted v1 queries may filter the whole workspace without a home/ID
    // seed. They still materialize through the caller's record visibility.
    sqlx::query("UPDATE kernel_record_fields SET value_json='\"query\"' WHERE record_id='private' AND name='v1_kind'")
        .execute(db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_facets(record_id,key,value,value_num,vocab_ref,as_of,event_seq) VALUES('private','query',?,NULL,NULL,'2026-01-01T00:00:00Z',1)")
        .bind(json!({"v":"0.2","query":{"steps":[{"step":"filter","types":["Document"]}]}}).to_string())
        .execute(db.write_pool()).await.unwrap();
    let workspace_query = render(&db, &actor, "account-a").await;
    assert_eq!(workspace_query["status"], "rendered", "{workspace_query}");
    assert!(workspace_query["plan"]["lanes"][0]["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == "secret"));
    // A binding cannot be silently repointed underneath a frozen executable closure.
    sqlx::query("UPDATE kernel_generic_links SET target_id='note' WHERE source_id='secret' AND relationship='renders'")
        .execute(db.write_pool()).await.unwrap();
    assert_eq!(render(&db, &actor, "account-a").await["status"], "error");
    db.close().await;
}

#[tokio::test]
async fn invalid_frozen_board_preserves_the_v1_runtime_diagnostic() {
    // Standalone validation succeeds at activation, but the frozen renders
    // binding makes inline rows invalid at render time, just as in v1.
    let body = r#"{"v":"1","group_by":"kind","lanes":[{"title":"Artifacts","value":"artifact"}],"records":[]}"#;
    let (_f, db, actor) = frozen(body, "native.board.v1", Some("private")).await;
    let rendered = render(&db, &actor, "account-a").await;
    assert_eq!(rendered["status"], "error");
    assert_eq!(
        rendered["diagnostic"]["format"],
        "native.artifact-diagnostic.v1"
    );
    assert_eq!(rendered["diagnostic"]["code"], "invalid_artifact_body");
    assert_eq!(
        rendered["diagnostic"]["details"]["runtime"],
        "native.board.v1"
    );
    assert_eq!(rendered["diagnostic"]["details"]["artifact_id"], "secret");
    assert_eq!(rendered["diagnostic"]["details"]["mode"], "bound");
    let mut expected =
        crate::mcp::tools::artifacts::render_board_compat(body, "bound", None, vec![]).unwrap_err();
    // v1's outer render path adds these fields to the adapter failure.
    expected["diagnostic"]["details"]["artifact_id"] = json!("secret");
    expected["diagnostic"]["details"]["runtime"] = json!("native.board.v1");
    expected["diagnostic"]["details"]["mode"] = json!("bound");
    assert_eq!(rendered, expected);
    let malformed = crate::mcp::tools::artifacts::render_board_compat(
        "not board JSON",
        "standalone",
        None,
        vec![],
    )
    .unwrap_err();
    assert_eq!(
        malformed["diagnostic"]["format"],
        "native.artifact-diagnostic.v1"
    );
    assert_eq!(malformed["diagnostic"]["code"], "invalid_artifact_body");
    db.close().await;
}

#[tokio::test]
async fn frozen_html_app_admission_refuses_before_target_lookup() {
    let (_f, db, actor) = frozen(HTML, crate::artifact_html::RUNTIME_ID, None).await;
    let app = crate::mcp::app_attribution::AppAttribution::new(
        "agent.docs",
        "0.9.0",
        "22222222-2222-4222-8222-222222222222",
    )
    .unwrap();
    // The synthetic ingress owns this app assertion, but has no consent for
    // it. A missing target must not bypass that admission refusal.
    let caller = caller("account-a").with_host_asserted_app(app);
    let mut errors = Vec::new();
    for id in ["secret", "missing"] {
        let args = json!({"id":id});
        let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
            &caller,
            "render_artifact",
            &args,
            None,
        );
        let error = dispatch
            .scope(crate::mcp::kernel_v2::artifacts::html_board::try_render(
                &db,
                &caller,
                &actor,
                &args,
                Some(&delivery()),
            ))
            .await
            .unwrap_err();
        errors.push(error.to_string());
    }
    assert_eq!(errors[0], errors[1]);
    assert!(!errors[0].contains("artifact_source_unavailable"));
    db.close().await;
}

#[tokio::test]
async fn frozen_html_refuses_tombstone_and_replaced_pin_including_same_text_revision() {
    let (_f, db, actor) = frozen(HTML, crate::artifact_html::RUNTIME_ID, None).await;
    let digest = native_artifact_runtime::mdx::sha256_hex(HTML.as_bytes());
    // Corruption at either side of the projection is not executable authority.
    sqlx::query("UPDATE kernel_record_bodies SET body='replaced' WHERE record_id='secret'")
        .execute(db.write_pool())
        .await
        .unwrap();
    assert_eq!(render(&db, &actor, "account-a").await["status"], "error");
    k::replay_all_projections(&db).await.unwrap();
    sqlx::query("UPDATE kernel_record_bodies SET event_seq=(SELECT MAX(seq)+1 FROM content_events) WHERE record_id='secret'")
        .execute(db.write_pool()).await.unwrap();
    assert_eq!(render(&db, &actor, "account-a").await["status"], "error");
    k::replay_all_projections(&db).await.unwrap();
    sqlx::query("UPDATE kernel_artifact_closures SET source_body='replaced',source_sha256=? WHERE artifact_id='secret'")
        .bind(native_artifact_runtime::mdx::sha256_hex(b"replaced"))
        .execute(db.write_pool()).await.unwrap();
    assert_eq!(render(&db, &actor, "account-a").await["status"], "error");
    k::replay_all_projections(&db).await.unwrap();
    sqlx::query("INSERT INTO kernel_import_tombstones(record_id,deleted_at,event_seq) VALUES('secret','2026-01-01T00:00:00Z',1)")
        .execute(db.write_pool()).await.unwrap();
    assert_eq!(render(&db, &actor, "account-a").await["status"], "error");
    let mut tx = db.pool().begin().await.unwrap();
    assert!(
        crate::mcp::kernel_v2::artifacts::html_board::bundle_source_on(
            &mut tx, &actor, "secret", &digest
        )
        .await
        .is_err()
    );
    tx.rollback().await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn frozen_html_revalidates_inputs_without_workspace_wide_invalidation() {
    let (_f, db, actor) = frozen(HTML, crate::artifact_html::RUNTIME_ID, Some("private")).await;
    for (id, expected) in [("note", "rendered"), ("secret", "error")] {
        let captured = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let rendering = crate::mcp::kernel_v2::artifacts::RENDER_PAUSE.scope(
            (captured.clone(), resume.clone()),
            render(&db, &actor, "account-a"),
        );
        let write = async {
            captured.notified().await;
            let changed=ordinary_kernel_call(&db,"account-a","update_record",json!({
                "id":id,"name":"Updated during render","reason":"Verify dependency-scoped revalidation",
                "idempotency_key":format!("html-race-{id}")
            })).await;
            resume.notify_one();
            changed.unwrap();
        };
        let (rendered, ()) = tokio::join!(rendering, write);
        assert_eq!(rendered["status"], expected, "{rendered}");
    }
    db.close().await;
}

#[tokio::test]
async fn frozen_html_reuses_exact_v1_attestation_including_named_manifest() {
    let body=HTML.replace("</head>",r#"<script type="application/json" id="native-artifact-manifest">{"schema":"native.html.artifact.v1","inputs":{},"capability_requests":[]}</script></head>"#);
    let (_f, db, actor) = frozen_source(&body, crate::artifact_html::RUNTIME_ID, None, true).await;
    let rendered = render(&db, &actor, "account-a").await;
    assert_eq!(rendered["status"], "rendered", "{rendered}");
    assert!(rendered["plan"]["input_bundle"].is_object());
    assert_eq!(
        rendered["input_digest"],
        native_artifact_runtime::mdx::sha256_hex(&crate::canonical_json::canonical_json(
            &rendered["input"]
        )),
        "named HTML retains v1 JCS digest semantics"
    );
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(render(&db, &actor, "account-a").await["status"], "rendered");
    db.close().await;
}

#[tokio::test]
async fn html_app_api_reads_use_current_user_visibility_and_install_authority() {
    use crate::mcp::{app_attribution::AppAttribution, Caller, EngineHandle, ToolRegistry};
    let f = Fixture::new().await;
    let body=HTML.replace("</main>","<script>window.nativeArtifact.ready.then(function(){ if (window.nativeArtifact.call) window.nativeArtifact.call('query_sql',{sql:'SELECT id FROM records'}); });</script></main>");
    super::app_state::native_install_source(&f, &body).await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source.execute("UPDATE records SET home_id='native:root',policy_anchor_id='native:root' WHERE id='secret'; DELETE FROM links WHERE source_id='secret' AND relationship='part_of'").await.unwrap();
    source.close().await.unwrap();
    let report = run(f.options(&["secret", "private", "note"], false))
        .await
        .unwrap();
    assert!(report.refusals.is_empty());
    let db = f.db().await;
    super::app_state::app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(
        &db,
        &host,
        super::app_state::app_activation_proof(&db).await,
    )
    .await
    .unwrap();
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_hosted_kernel_v2_tools(&mut registry).unwrap();
    let app = Caller::authenticated("account-b")
        .with_host_asserted_app(AppAttribution::new("agent.docs", "0.8.2", "install-b").unwrap());
    let rows=registry.call_engine(EngineHandle::KernelV2(db.clone()),app.clone(),"query_sql",json!({"sql":"SELECT id FROM records WHERE id IN ('secret','private','note') ORDER BY id"})).await.unwrap();
    assert_eq!(
        rows["rows"],
        json!([{"id":"note"},{"id":"secret"}]),
        "{rows}"
    );
    let get = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            app.clone(),
            "get_record",
            json!({"ids":["private"]}),
        )
        .await
        .unwrap();
    assert_eq!(get["records"][0]["status"], "not_found");
    super::app_state::app_roster(&db, "account-a", &["account-a"]).await;
    assert!(registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            app,
            "query_sql",
            json!({"sql":"SELECT id FROM records"})
        )
        .await
        .is_err());
    db.close().await;
}

#[tokio::test]
async fn frozen_html_retains_pre_diagnostics_attestation_and_unbound_required_refusal() {
    let body = HTML.replace(
        "</main>",
        "<script>missingHistoricalGlobal();</script></main>",
    );
    let (_f, db, actor) =
        frozen_source_shape(&body, crate::artifact_html::RUNTIME_ID, None, true, true).await;
    let rendered = render(&db, &actor, "account-a").await;
    assert_eq!(rendered["status"], "rendered", "{rendered}");
    assert!(
        rendered.get("write_diagnostics").is_none(),
        "do not invent findings absent from the frozen attestation"
    );
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(render(&db, &actor, "account-a").await["status"], "rendered");
    db.close().await;
    let body=HTML.replace("</head>",r#"<script type="application/json" id="native-artifact-manifest">{"schema":"native.html.artifact.v1","inputs":{"items":{"envelope":"native.collection-envelope.v1","required":true,"expose_to_root":true}},"capability_requests":[{"capability":"input.read","scope":{"port":"items"}}]}</script></head>"#);
    let (_f, db, actor) = frozen_source(&body, crate::artifact_html::RUNTIME_ID, None, true).await;
    let rendered = render(&db, &actor, "account-a").await;
    assert_eq!(rendered["status"], "error", "{rendered}");
    assert_eq!(rendered["diagnostic"]["code"], "named_input_missing");
    db.close().await;
    let optional = body.replace("\"required\":true", "\"required\":false");
    let (_f, db, actor) =
        frozen_source(&optional, crate::artifact_html::RUNTIME_ID, None, true).await;
    let rendered = render(&db, &actor, "account-a").await;
    assert_eq!(rendered["status"], "error", "{rendered}");
    assert_eq!(rendered["diagnostic"]["code"], "module_capability_denied");
    db.close().await;
}

#[tokio::test]
async fn html_sql_facet_history_reconstructs_import_and_native_changes_under_visibility() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    for (id, record, event_type, value, as_of) in [
        (
            "obs-old",
            "secret",
            "facet.set",
            Some("old"),
            "2026-02-01T00:00:00Z",
        ),
        (
            "obs-replace",
            "secret",
            "facet.set",
            Some("private"),
            "2026-02-01T00:00:00Z",
        ),
        (
            "obs-unset",
            "secret",
            "facet.unset",
            None,
            "2026-02-02T00:00:00Z",
        ),
        (
            "obs-public",
            "note",
            "facet.set",
            Some("public"),
            "2026-02-01T00:00:00Z",
        ),
    ] {
        let mut payload = json!({"key":"metric","as_of":as_of,"observation_only":true});
        if event_type == "facet.set" {
            payload["value"] = json!(value);
        }
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES(?,?,?,?,'account-a','2026-02-03T00:00:00Z')")
            .bind(id).bind(record).bind(event_type)
            .bind(payload.to_string())
            .execute(&mut source).await.unwrap();
    }
    source.close().await.unwrap();
    let mut options = f.options(&["secret", "private", "note"], false);
    options.history = true;
    let report = run(options).await.unwrap();
    assert!(report.refusals.is_empty());
    let db = f.db().await;
    super::app_state::app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let sql = "SELECT id,record_id,key,value,op,as_of,event_seq FROM facet_observations WHERE key='metric' ORDER BY record_id,as_of";
    let read =
        |account: &'static str| ordinary_kernel_call(&db, account, "query_sql", json!({"sql":sql}));
    let a = read("account-a").await.unwrap();
    assert_eq!(a["rows"].as_array().unwrap().len(), 3, "{a}");
    assert_eq!(a["rows"][1]["id"], "fo:secret:metric:2026-02-01T00:00:00Z");
    assert_eq!(a["rows"][1]["value"], "private");
    assert_eq!(a["rows"][2]["op"], "unset");
    let b = read("account-b").await.unwrap();
    assert_eq!(b["rows"].as_array().unwrap().len(), 1, "{b}");
    assert_eq!(b["rows"][0]["record_id"], "note");
    assert_eq!(b["rows"][0]["value"], "public");
    let joined = ordinary_kernel_call(&db, "account-a", "query_sql", json!({"sql":"SELECT o.id,e.id AS event_id FROM facet_observations o JOIN content_events e ON e.local_seq=o.event_seq WHERE o.record_id='secret' AND o.op='set'"})).await.unwrap();
    assert_eq!(joined["rows"][0]["event_id"], "obs-replace");
    let actor = k::resolve_principal_by_binding(&db, "account-a")
        .await
        .unwrap()
        .unwrap()
        .0;
    for (value, as_of) in [
        (Some("native"), "2026-02-01T00:00:00Z"),
        (None, "2026-02-02T00:00:00Z"),
    ] {
        k::observe_facet_as(
            &db,
            &actor,
            "note",
            &k::FacetObservation {
                key: "metric".into(),
                value: value.map(str::to_owned),
                value_num: None,
                vocab_ref: None,
                as_of: as_of.into(),
            },
            None,
        )
        .await
        .unwrap();
    }
    let b = read("account-b").await.unwrap();
    assert_eq!(b["rows"].as_array().unwrap().len(), 2, "{b}");
    assert_eq!(b["rows"][0]["value"], "native");
    assert_eq!(b["rows"][1]["op"], "unset");
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(read("account-b").await.unwrap()["rows"], b["rows"]);
    db.close().await;
}

#[tokio::test]
async fn html_activity_input_is_pseudonymous_current_membership_and_clock_bound() {
    let (_f, db, actor) = frozen(HTML, crate::artifact_html::RUNTIME_ID, None).await;
    let key = k::mint_run_as(&db, &actor, None).await.unwrap();
    let context = k::open_run_as(&db, &actor, &key).await.unwrap();
    k::set_run_intent_as(&db, &context, "Unshared transient declaration")
        .await
        .unwrap();
    let sql = "SELECT current_principal() AS viewer,activity_id,run_key,principal_ref,principal_display_name,appears_active,declared_intent,declared_intent_state FROM agent_activity ORDER BY activity_id";
    let read = || ordinary_kernel_call(&db, "account-b", "query_sql", json!({"sql":sql}));
    let b = read().await.unwrap();
    assert_eq!(b["time_dependent"], true);
    assert!(b["now_ms_ms"].as_i64().is_some());
    let rows = b["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{b}");
    assert_eq!(rows[0]["run_key"], key);
    assert_eq!(rows[0]["appears_active"], 1);
    assert!(rows[0]["principal_ref"]
        .as_str()
        .unwrap()
        .starts_with("native:workspace-member:"));
    assert_ne!(rows[0]["principal_ref"], actor);
    assert!(rows[0]["principal_display_name"].is_null());
    assert!(rows[0]["declared_intent"].is_null());
    assert_eq!(rows[0]["declared_intent_state"], "unavailable");
    assert!(!serde_json::to_string(rows)
        .unwrap()
        .contains("Unshared transient declaration"));
    super::app_state::app_roster(&db, "account-b", &["account-b"]).await;
    assert_eq!(read().await.unwrap()["rows"], json!([]));
    super::app_state::app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    k::finish_run_as(&db, &context).await.unwrap();
    assert_eq!(read().await.unwrap()["rows"][0]["appears_active"], 0);
    super::app_state::app_roster(&db, "account-a", &["account-a"]).await;
    assert!(read().await.is_err());
    db.close().await;
}

#[tokio::test]
async fn html_saved_record_inputs_keep_facet_filters_and_explicit_archive_opt_in() {
    let (_f, db, actor) = frozen(HTML, crate::artifact_html::RUNTIME_ID, Some("private")).await;
    let home = k::read_record_as(&db, &actor, "secret")
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let created = ordinary_kernel_call(
        &db,
        "account-a",
        "create_record",
        json!({
            "type":"Document","kind":"note","name":"Archived input","home_id":home,
            "reason":"Verify saved record input parity","idempotency_key":"html-archived-input"
        }),
    )
    .await
    .unwrap();
    let id = created["id"].as_str().unwrap();
    k::observe_facet_as(
        &db,
        &actor,
        id,
        &k::FacetObservation {
            key: "metric".into(),
            value: Some("2".into()),
            value_num: Some(2.0),
            vocab_ref: None,
            as_of: "2026-02-01T00:00:00Z".into(),
        },
        None,
    )
    .await
    .unwrap();
    ordinary_kernel_call(
        &db,
        "account-a",
        "archive_record",
        json!({
            "id":id,"archived":true,"reason":"Verify explicit archived input selection"
        }),
    )
    .await
    .unwrap();
    // Adapter fixture: use the same verified binding for a computed Collection.
    // This tests read semantics, independently of Collection authoring/migration.
    sqlx::query("UPDATE kernel_record_fields SET value_json='\"query\"' WHERE record_id='private' AND name='v1_kind'")
        .execute(db.write_pool()).await.unwrap();
    for (ids, archived, membership, expected) in [
        (json!([id]), true, json!([2, 3]), 1),
        (json!([id]), false, json!([2, 3]), 0),
        (json!([]), true, json!([2, 3]), 1),
        (json!([]), false, json!([2, 3]), 0),
        (json!([]), true, json!([3, 4]), 0),
    ] {
        let query = json!({"v":"0.2","query":{"steps":[{"step":"filter","ids":ids,"types":["Document"],"kinds":["note"],"include_archived":archived,"facets":[{"key":"metric","in":membership},{"key":"metric","eq":"2"},{"key":"metric","ne":"3"}]}]}});
        sqlx::query("INSERT INTO kernel_facets(record_id,key,value,value_num,vocab_ref,as_of,event_seq) VALUES('private','query',?,NULL,NULL,'2026-02-01T00:00:00Z',1) ON CONFLICT(record_id,key) DO UPDATE SET value=excluded.value")
            .bind(query.to_string()).execute(db.write_pool()).await.unwrap();
        let result = render(&db, &actor, "account-a").await;
        assert_eq!(result["status"], "rendered", "{result}");
        assert_eq!(
            result["input"]["records"].as_array().unwrap().len(),
            expected,
            "{result}"
        );
    }
    db.close().await;
}

#[tokio::test]
async fn html_metadata_queries_skip_large_retained_bodies_without_raising_value_limits() {
    let f = Fixture::new().await;
    let large = "x".repeat(crate::query::sql::MAX_SQLITE_VALUE_BYTES as usize + 4096);
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE records SET body=?,updated_at='2026-02-02T00:00:00Z' WHERE id='note'")
        .bind(&large)
        .execute(&mut source)
        .await
        .unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('large-body','note','record.updated',?,'account-a','2026-02-02T00:00:00Z')")
        .bind(json!({"body":large}).to_string()).execute(&mut source).await.unwrap();
    source.close().await.unwrap();
    let mut options = f.options(&["note"], false);
    options.history = true;
    let report = run(options).await.unwrap();
    assert!(report.refusals.is_empty());
    let db = f.db().await;
    super::app_state::app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let metadata = ordinary_kernel_call(
        &db,
        "account-a",
        "query_sql",
        json!({
            "sql":"SELECT id,name,home_id,updated_at_ms FROM records WHERE id='note'"
        }),
    )
    .await
    .unwrap();
    assert_eq!(metadata["rows"][0]["id"], "note");
    assert_eq!(metadata["rows"][0]["home_id"], "folder");
    assert!(metadata["rows"][0]["updated_at_ms"].as_i64().is_some());
    assert!(
        ordinary_kernel_call(
            &db,
            "account-a",
            "query_sql",
            json!({
                "sql":"SELECT body FROM records WHERE id='note'"
            })
        )
        .await
        .is_err(),
        "the public value budget must remain in force"
    );
    db.close().await;
}

#[tokio::test]
async fn html_named_input_keeps_v1_capacity_above_the_mdx_byte_limit() {
    let body = HTML.replace("</head>", r#"<script type="application/json" id="native-artifact-manifest">{"schema":"native.html.artifact.v1","inputs":{"items":{"envelope":"native.collection-envelope.v1","required":true,"expose_to_root":true}},"capability_requests":[{"capability":"input.read","scope":{"port":"items"}}]}</script></head>"#);
    let (_f, db, actor) = frozen_source(&body, crate::artifact_html::RUNTIME_ID, None, true).await;
    // Materializer fixture, like the MDX adapter fixtures: source activation
    // and grant-witness admission are qualified independently above.
    let scope = json!({"artifact_port":"items"});
    let grants = json!([{"subject_kind":"artifact_source","subject_record_id":"secret",
        "subject_event_id":"created:secret","capability":"input.read",
        "scope":scope.to_string(),"scope_sha256":native_artifact_runtime::mdx::sha256_hex(
            &native_artifact_runtime::mdx_v2::canonical_json_bytes(&scope))}]);
    sqlx::query(
        "UPDATE kernel_artifact_closures SET bindings=?,grants=? WHERE artifact_id='secret'",
    )
    .bind(json!([{"port_name":"items","collection_id":"folder","event_seq":1}]).to_string())
    .bind(grants.to_string())
    .execute(db.write_pool())
    .await
    .unwrap();
    for (size, expected) in [
        (
            // Collection rows also appear in the aggregate records array.
            native_artifact_runtime::mdx_v2::MAX_INPUT_JSON_BYTES / 2 + 4096,
            "rendered",
        ),
        (crate::artifact_html::INPUT_JSON_LIMIT + 1, "error"),
    ] {
        k::observe_facet_as(
            &db,
            &actor,
            "note",
            &k::FacetObservation {
                key: "html_capacity_fixture".into(),
                value: Some("x".repeat(size)),
                value_num: None,
                vocab_ref: None,
                as_of: "2026-01-01T00:00:00Z".into(),
            },
            None,
        )
        .await
        .unwrap();
        let result = render(&db, &actor, "account-a").await;
        assert_eq!(result["status"], expected, "{}", result["diagnostic"]);
        if expected == "rendered" {
            let bytes = serde_json::to_vec(&result["input"]).unwrap().len();
            assert!(bytes > native_artifact_runtime::mdx_v2::MAX_INPUT_JSON_BYTES);
            assert!(bytes <= crate::artifact_html::INPUT_JSON_LIMIT);
        } else {
            assert_eq!(result["diagnostic"]["code"], "html_input_too_large");
        }
    }
    db.close().await;
}

#[tokio::test]
async fn html_saved_query_pages_keep_v1_default_and_facet_order() {
    let (_f, db, actor) = frozen(HTML, crate::artifact_html::RUNTIME_ID, Some("private")).await;
    let home = k::read_record_as(&db, &actor, "secret")
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let mut ids = Vec::new();
    for name in ["Zebra", "Alpha"] {
        let row = ordinary_kernel_call(
            &db,
            "account-a",
            "create_record",
            json!({
                "type":"Document","kind":"note","name":name,"home_id":home,
                "reason":"Qualify saved input membership ordering"
            }),
        )
        .await
        .unwrap();
        ids.push(row["id"].as_str().unwrap().to_owned());
    }
    ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":ids[0],"summary":"Newest update","reason":"Qualify the update order"}),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_records SET created_at=CASE WHEN id=? THEN '2020-01-01T00:00:00Z' ELSE '2021-01-01T00:00:00Z' END WHERE id IN (?,?)")
        .bind(&ids[0]).bind(&ids[0]).bind(&ids[1]).execute(db.write_pool()).await.unwrap();
    sqlx::query("UPDATE kernel_record_metadata SET last_activity_at=CASE WHEN record_id=? THEN '2021-01-01T00:00:00Z' ELSE '2020-01-01T00:00:00Z' END WHERE record_id IN (?,?)")
        .bind(&ids[1]).bind(&ids[0]).bind(&ids[1]).execute(db.write_pool()).await.unwrap();
    sqlx::query("UPDATE kernel_record_fields SET value_json='\"query\"' WHERE record_id='private' AND name='v1_kind'")
        .execute(db.write_pool()).await.unwrap();
    for (order, expected) in [
        (None, 0),
        (Some("updated_desc"), 0),
        (Some("created_desc"), 1),
        (Some("last_activity_desc"), 1),
        (Some("name_asc"), 1),
    ] {
        let mut query = json!({"steps":[{"step":"filter","ids":ids}],"limit":1});
        if let Some(order) = order {
            query["order"] = json!(order);
        }
        let definition = json!({"v":"0.2","query":query});
        sqlx::query("INSERT INTO kernel_facets(record_id,key,value,value_num,vocab_ref,as_of,event_seq) VALUES('private','query',?,NULL,NULL,'2026-01-01T00:00:00Z',1) ON CONFLICT(record_id,key) DO UPDATE SET value=excluded.value")
            .bind(definition.to_string()).execute(db.write_pool()).await.unwrap();
        let result = render(&db, &actor, "account-a").await;
        assert_eq!(result["status"], "rendered", "{result}");
        assert_eq!(result["input"]["records"][0]["id"], ids[expected]);
        assert_eq!(result["input"]["records"].as_array().unwrap().len(), 1);
    }
    k::observe_facet_as(
        &db,
        &actor,
        &ids[0],
        &k::FacetObservation {
            key: "rank".into(),
            value: Some("4".into()),
            value_num: Some(4.0),
            vocab_ref: None,
            as_of: "2026-01-01T00:00:00Z".into(),
        },
        None,
    )
    .await
    .unwrap();
    for (lane, expected) in [("number", 0), ("text", 0)] {
        let definition = json!({"v":"0.2","query":{"steps":[{"step":"filter","ids":ids}],"limit":1,"order":"name_asc","facet_order":{"key":"rank","lane":lane,"direction":"desc"}}});
        sqlx::query("UPDATE kernel_facets SET value=? WHERE record_id='private' AND key='query'")
            .bind(definition.to_string())
            .execute(db.write_pool())
            .await
            .unwrap();
        let result = render(&db, &actor, "account-a").await;
        assert_eq!(result["status"], "rendered", "{result}");
        assert_eq!(
            result["input"]["records"][0]["id"], ids[expected],
            "missing primary facet values remain last"
        );
    }
    let page = crate::query::pipeline::PipelineOptions::default().limit as usize;
    while ids.len() <= page {
        let row = ordinary_kernel_call(&db,"account-a","create_record",json!({
            "type":"Document","kind":"note","name":format!("Page row {}",ids.len()),"home_id":k::hq::v1_import_home_id("folder"),
            "reason":"Qualify default page versus explicit complete membership"
        })).await.unwrap();
        ids.push(row["id"].as_str().unwrap().to_owned());
    }
    let definition = json!({"v":"0.2","query":{"steps":[{"step":"filter","ids":ids}]}});
    sqlx::query("UPDATE kernel_facets SET value=? WHERE record_id='private' AND key='query'")
        .bind(definition.to_string())
        .execute(db.write_pool())
        .await
        .unwrap();
    let result = render(&db, &actor, "account-a").await;
    assert_eq!(result["status"], "rendered", "{result}");
    assert_eq!(result["input"]["records"].as_array().unwrap().len(), page);
    sqlx::query("INSERT INTO kernel_facets(record_id,key,value,value_num,vocab_ref,as_of,event_seq) VALUES('private','input_membership','all_matching',NULL,NULL,'2026-01-01T00:00:00Z',1)")
        .execute(db.write_pool()).await.unwrap();
    let result = render(&db, &actor, "account-a").await;
    assert_eq!(result["status"], "rendered", "{result}");
    assert_eq!(
        result["input"]["records"].as_array().unwrap().len(),
        page + 1
    );
    db.close().await;
}

#[tokio::test]
async fn html_saved_query_traverses_retained_provider_direction_with_current_visibility() {
    let (_f, db, actor) = frozen(HTML, crate::artifact_html::RUNTIME_ID, Some("folder")).await;
    let home = k::read_record_as(&db, &actor, "secret")
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let row=ordinary_kernel_call(&db,"account-a","create_record",json!({"type":"Document","kind":"note","name":"Private target","summary":"private traversal content","home_id":home,"reason":"Qualify provider traversal visibility"})).await.unwrap();
    let target = row["id"].as_str().unwrap();
    // Adapter fixture: the ordinary renderer still performs all current gates.
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id='secret'")
        .bind(crate::events::KERNEL_ROOT_ID)
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query("UPDATE kernel_record_fields SET value_json='\"query\"' WHERE record_id='folder' AND name='v1_kind'")
        .execute(db.write_pool()).await.unwrap();
    let (left, right) = if "note" < target {
        ("note", target)
    } else {
        (target, "note")
    };
    let state = crate::kernel::provider_catalogue::StoredState {
        pins: crate::v2_standard::relates_to_v3::pins(),
        state: json!({"left":left,"right":right,"assertions":[{"id":"imported-direction","sources":[{"source_id":"original-link","from":"note","to":target,"claimed_author":null,"claimed_timestamp":"2026-01-01T00:00:00Z","note":null}],"retracted":false,"asserted_by":actor,"asserted_at":"2026-01-01T00:00:00Z","asserted_seq":1,"retracted_by":null,"retracted_at":null,"retracted_seq":null}]}),
        attribution: Value::Null,
    };
    sqlx::query("INSERT INTO kernel_provider_state(id,provider_key,state_json,subjects_json,head) VALUES('traversal-fixture','relates_to.v1',?,?,1)")
        .bind(serde_json::to_string(&state).unwrap()).bind(json!([left,right]).to_string()).execute(db.write_pool()).await.unwrap();
    for subject in [left, right] {
        sqlx::query("INSERT INTO kernel_provider_subjects(subject_id,aggregate_id) VALUES(?,'traversal-fixture')").bind(subject).execute(db.write_pool()).await.unwrap();
    }
    for (account, direction, count) in [
        ("account-a", "out", 1),
        ("account-a", "in", 0),
        ("account-b", "out", 0),
    ] {
        let query = json!({"v":"0.2","query":{"steps":[{"step":"filter","ids":["note"]},{"step":"traverse","target":"links","direction":direction,"relationship":"relates_to"},{"step":"filter","types":["Document"]}]}});
        sqlx::query("INSERT INTO kernel_facets(record_id,key,value,value_num,vocab_ref,as_of,event_seq) VALUES('folder','query',?,NULL,NULL,'2026-01-01T00:00:00Z',1) ON CONFLICT(record_id,key) DO UPDATE SET value=excluded.value")
            .bind(query.to_string()).execute(db.write_pool()).await.unwrap();
        let principal = k::resolve_principal_by_binding(&db, account)
            .await
            .unwrap()
            .unwrap()
            .0;
        let result = render(&db, &principal, account).await;
        assert_eq!(result["status"], "rendered", "{result}");
        assert_eq!(result["input"]["records"].as_array().unwrap().len(), count);
        if count == 1 {
            assert_eq!(result["input"]["records"][0]["id"], target);
        }
        if account == "account-b" {
            assert!(!result.to_string().contains(target));
            assert!(!result.to_string().contains("private traversal content"));
        }
    }
    db.close().await;
}

#[tokio::test]
async fn html_folder_logical_membership_keeps_child_policy_archive_and_deletion_guards() {
    let (_f, db, _) = frozen_source_package_shape(
        HTML,
        crate::artifact_html::RUNTIME_ID,
        Some("folder"),
        false,
        false,
        false,
        true,
    )
    .await;
    let child_home: String =
        sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id='private'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(child_home, k::hq::v1_import_home_id("private"));
    assert!(sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='kernel.import_home_policy.v1')")
        .bind(&child_home).fetch_one(db.pool()).await.unwrap(),
        "the importer must establish the child's policy through kernel events");
    let deleted = ordinary_kernel_call(
        &db,
        "account-a",
        "create_record",
        json!({"type":"Document","kind":"note","name":"Deleted live child","home_id":"folder"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ordinary_kernel_call(
        &db,
        "account-a",
        "delete_record",
        json!({"id":deleted,"reason":"Synthetic live deletion guard"}),
    )
    .await
    .unwrap();
    for account in ["account-a", "account-b"] {
        let actor = k::resolve_principal_by_binding(&db, account)
            .await
            .unwrap()
            .unwrap()
            .0;
        assert!(k::read_record_as(&db, &actor, "folder")
            .await
            .unwrap()
            .is_some());
        let child = k::read_record_as(&db, &actor, "private").await.unwrap();
        assert_eq!(child.is_some(), account == "account-a");
        let result = render(&db, &actor, account).await;
        assert_eq!(result["status"], "rendered", "{result}");
        let ids: Vec<&str> = result["input"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap())
            .collect();
        // V1 collection_member_values_in filters records.home_id, not part_of
        // links or the separate policy anchor. Both rows are logically filed
        // in folder, but only A can View the record-local policy on private.
        assert!(ids.contains(&"note"));
        assert_eq!(ids.contains(&"private"), account == "account-a");
        assert!(!ids.contains(&"archived"));
        assert!(!ids.contains(&"task"));
        assert!(!ids.contains(&deleted.as_str()));
        assert!(!ids.contains(&"folder"));
        assert!(!ids.contains(&"part-only"));
    }
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    let actor = k::resolve_principal_by_binding(&db, "account-a")
        .await
        .unwrap()
        .unwrap()
        .0;
    let result = render(&db, &actor, "account-a").await;
    assert!(result["input"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == "private"));
    // The saved JSON Collection filter shares the same folder candidate
    // reader. Exercise it as an adapter fixture, without changing authoring.
    sqlx::query("UPDATE kernel_record_fields SET value_json='\"query\"' WHERE record_id='folder' AND name='v1_kind'")
        .execute(db.write_pool()).await.unwrap();
    let query = json!({"v":"0.2","query":{"steps":[{"step":"filter","home_id":"folder"}]}});
    sqlx::query("INSERT INTO kernel_facets(record_id,key,value,value_num,vocab_ref,as_of,event_seq) VALUES('folder','query',?,NULL,NULL,'2026-01-01T00:00:00Z',1)")
        .bind(query.to_string()).execute(db.write_pool()).await.unwrap();
    for account in ["account-a", "account-b"] {
        let actor = k::resolve_principal_by_binding(&db, account)
            .await
            .unwrap()
            .unwrap()
            .0;
        let result = render(&db, &actor, account).await;
        assert_eq!(result["status"], "rendered", "{result}");
        let ids: Vec<&str> = result["input"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.contains(&"private"), account == "account-a");
        assert!(!ids.contains(&"archived"));
        assert!(!ids.contains(&"task"));
        assert!(!ids.contains(&deleted.as_str()));
        assert!(!ids.contains(&"part-only"));
    }
    db.close().await;
}
