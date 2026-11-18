//! Personal source publication and consent continuity over the inherited frozen
//! import fixture. Hosted cookie/catalogue authority is synthetic; the actual
//! MCP writes, preview receipts, adoption and kernel replay are exercised.
use super::*;
use crate::mcp::{Caller, EngineHandle, ToolRegistry};

const OLD: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Personal</title></head><body><main>Old generation</main></body></html>"#;
const NEW: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Personal</title></head><body><main>New generation</main></body></html>"#;
const PACKAGE: &str = "personal.owner-slides";

fn registry() -> ToolRegistry {
    let mut r = ToolRegistry::new();
    r.set_catalog_assets(crate::mcp::tools::catalog_assets::fixture_assets(
        NEW,
        "agent.docs",
        "0.5.0",
    ));
    crate::mcp::register_builtin_tools(&mut r).unwrap();
    crate::mcp::tools::register_surface_tools(&mut r).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut r).unwrap();
    r
}
async fn render(db: &Db) -> Value {
    use crate::mcp::tools::alpha_tabs::AppBundleDelivery;
    let delivery = AppBundleDelivery { enabled:true,
        runtime:crate::artifact_html::RuntimeConfig::new("https://parent.test","https://artifact.test").unwrap(),
        keyring:Some(std::sync::Arc::new(native_artifact_runtime::deployment_keyring::DeploymentKeyring::from_json_bundle(
            r#"{"active_key_id":"test","keys":[{"id":"test","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}"#).unwrap())) };
    let mut tools = ToolRegistry::new();
    tools.set_app_bundle_delivery(Some(delivery));
    crate::mcp::register_builtin_tools(&mut tools).unwrap();
    crate::mcp::tools::register_surface_tools(&mut tools).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut tools).unwrap();
    // SAFETY: the test owns this authenticated browser ingress.
    let caller =
        unsafe { owner().with_verified_hosting_session("11111111-1111-4111-8111-111111111111") };
    tools
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller,
            "render_artifact",
            json!({"id":"secret"}),
        )
        .await
        .unwrap()
}
fn owner() -> Caller {
    Caller::authenticated("account-a")
        .with_hosting_context("account-a", "hq-fixture")
        .with_hosting_owner(true)
}
async fn call(db: &Db, caller: Caller, tool: &str, args: Value) -> crate::Result<Value> {
    registry()
        .call_engine(EngineHandle::KernelV2(db.clone()), caller, tool, args)
        .await
}
async fn fixture(f: &Fixture, package: &str) -> (Db, String, String) {
    fixture_with(f, package, &["secret", "note"]).await
}
async fn fixture_with(f: &Fixture, package: &str, records: &[&str]) -> (Db, String, String) {
    native_install_source_with_pin(f, OLD, package, "0.4.0").await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source.execute("INSERT INTO facet_values VALUES('secret','app_package','true',NULL,NULL,'2026-01-01T00:00:00Z'); INSERT INTO facet_observations VALUES('secret','app_package','2026-01-01T00:00:00Z',1);").await.unwrap();
    // The generic app fixture carries deliberately malformed custody-only
    // declarations. This personal app has no named inputs or v1 source grants.
    source
        .execute("DELETE FROM artifact_source_attestations; DELETE FROM artifact_inputs;")
        .await
        .unwrap();
    source.close().await.unwrap();
    let mut options = f.options(records, false);
    options.history = true;
    let report = run(options).await.unwrap();
    assert!(report.refusals.is_empty());
    let db = f.db().await;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let raw:String=sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1").fetch_one(db.pool()).await.unwrap();
    let seq: i64 =
        sqlx::query_scalar("SELECT event_seq FROM kernel_app_state WHERE record_id='secret'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    // SAFETY: this fixture's synthetic import is frozen and verified.
    let proof = unsafe {
        k::app_installs::VerifiedFrozenApps::from_verified_declarative_import_unchecked(
            serde_json::from_str(&raw).unwrap(),
            "ab".repeat(32),
            BTreeMap::from([("secret".into(), seq)]),
        )
    };
    k::app_installs::activate_as(&db, &host, proof)
        .await
        .unwrap();
    // SAFETY: the fixture owns this complete frozen legacy source and digest.
    let closure = unsafe {
        k::artifact_closures::VerifiedArtifactClosure::from_verified_legacy_import_unchecked(
            serde_json::from_str(&raw).unwrap(),
            "ab".repeat(32),
            "secret".into(),
            "source".into(),
            crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(OLD),
            "native.html.v1".into(),
            vec![],
        )
    };
    k::artifact_closures::activate_as(&db, &host, closure)
        .await
        .unwrap();
    (
        db,
        report.principals["account-a"].clone(),
        report.principals["account-b"].clone(),
    )
}
fn update(body: &str, digest: &str, key: &str) -> Value {
    json!({"id":"secret","body_set":body,"if_body_digest":digest,"idempotency_key":key,"reason":"Publish the owner's next app source revision"})
}
fn prepare(digest: &str) -> Value {
    json!({"action":"prepare_install","package":PACKAGE,"version":"0.5.0","artifact_id":"secret","expected_body_digest":digest,
        "declaration":{"contract":"native.app.v2","needs":[],"effects":[]},"reason":"Preview and adopt the new personal app"})
}
fn request(args: &Value) -> k::app_installs::InstallRequest {
    let mut args = args.clone();
    args.as_object_mut().unwrap().remove("action");
    serde_json::from_value(args).unwrap()
}

async fn fresh_catalog_source(db: &Db, private: bool, body: &str) -> Value {
    let mut args = json!({"type":"Document","kind":"artifact","name":"Fresh Docs",
        "body":body,"facets":{"runtime":"native.html.v1","app_package":"true"},
        "reason":"Stage an exact catalog source","confirm":true});
    if private {
        args["access_policy"] = json!("account_only");
    }
    call(db, owner(), "create_record", args).await.unwrap()
}
fn initial_catalog_publication(created: &Value) -> Value {
    json!({"action":"publish_catalog_update","artifact_id":created["id"],"package":"agent.docs","version":"0.5.0",
        "expected_body_digest":created["body_digest"],"expected_install_event_id":null,
        "idempotency_key":"first-docs-publication","reason":"Prepare the catalog app for human approval"})
}

#[tokio::test]
async fn catalog_initial_publication_prepares_private_source_without_adopting_and_replays() {
    let f = Fixture::new().await;
    let (db, a, _) = fixture(&f, PACKAGE).await;
    let created = fresh_catalog_source(&db, true, NEW).await;
    let artifact = created["id"].as_str().unwrap();
    let before_body: String = sqlx::query_scalar("SELECT e.id FROM kernel_record_bodies b JOIN content_events e ON e.seq=b.event_seq WHERE b.record_id=?")
        .bind(artifact).fetch_one(db.pool()).await.unwrap();
    let publication = initial_catalog_publication(&created);
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    for (field, value) in [
        ("expected_body_digest", json!("00".repeat(32))),
        ("idempotency_key", json!("")),
        ("version", json!("9.9.9")),
        ("expected_install_event_id", json!("invented")),
    ] {
        let mut bad = publication.clone();
        bad[field] = value;
        assert!(call(&db, owner(), "manage_alpha_tabs", bad).await.is_err());
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    }
    let mut omitted = publication.clone();
    omitted
        .as_object_mut()
        .unwrap()
        .remove("expected_install_event_id");
    assert!(call(&db, owner(), "manage_alpha_tabs", omitted)
        .await
        .is_err());
    for denied in [
        owner().with_hosting_owner(false),
        Caller::authenticated("account-b")
            .with_hosting_context("account-b", "hq-fixture")
            .with_hosting_owner(true),
        owner().with_host_asserted_app(
            crate::mcp::app_attribution::AppAttribution::new("agent.docs", "0.5.0", "install")
                .unwrap(),
        ),
    ] {
        assert!(call(&db, denied, "manage_alpha_tabs", publication.clone())
            .await
            .is_err());
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    }
    let published = call(&db, owner(), "manage_alpha_tabs", publication.clone())
        .await
        .unwrap();
    let after = k::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(
        published,
        call(&db, owner(), "manage_alpha_tabs", publication.clone())
            .await
            .unwrap()
    );
    assert_eq!(after, k::dump_all_kernel_tables(&db).await.unwrap());
    let raw:String=sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id=? AND type='kernel.app_catalog_source_published.v1'")
        .bind(artifact).fetch_one(db.pool()).await.unwrap();
    let witness: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(witness["format"], 2);
    assert!(witness["install_generation"].is_null());
    assert_eq!(witness["body_predecessor"], before_body);
    let mut prep = prepare(created["body_digest"].as_str().unwrap());
    prep["artifact_id"] = created["id"].clone();
    prep["package"] = json!("agent.docs");
    let prepared = call(&db, owner(), "manage_alpha_tabs", prep).await.unwrap();
    assert_eq!(prepared["ready"], true, "{prepared}");
    assert_eq!(prepared["source_revision"], published["source_revision"]);
    assert!(prepared["current_install_event_id"].is_null());
    assert_eq!(prepared["adoption"], "caller_asserted");
    let mut install = prepared["next_call"]["arguments"].clone();
    install["idempotency_key"] = json!("original-docs-install-key");
    let staged = call(&db, owner(), "manage_alpha_tabs", install.clone())
        .await
        .unwrap();
    assert_eq!(staged["install"]["adoption"], "caller_asserted");
    assert_eq!(
        staged["install"]["consented_source_revision"],
        published["source_revision"]
    );
    assert_eq!(
        call(&db, owner(), "manage_alpha_tabs", install)
            .await
            .unwrap()["install"],
        staged["install"]
    );
    let installed = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(installed, k::dump_all_kernel_tables(&db).await.unwrap());
    k::app_installs::remove_as(
        &db,
        &a,
        "agent.docs",
        staged["install"]["event_id"].as_str().unwrap(),
    )
    .await
    .unwrap();
    let removed = k::dump_all_kernel_tables(&db).await.unwrap();
    assert!(call(&db, owner(), "manage_alpha_tabs", publication)
        .await
        .is_err());
    assert_eq!(removed, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn catalog_initial_source_revision_change_refuses_the_prepared_pin() {
    let f = Fixture::new().await;
    let (db, _, _) = fixture(&f, PACKAGE).await;
    let created = fresh_catalog_source(&db, true, NEW).await;
    let published = call(
        &db,
        owner(),
        "manage_alpha_tabs",
        initial_catalog_publication(&created),
    )
    .await
    .unwrap();
    // An ordinary guarded source publication is a different body revision,
    // including when its bytes are identical. It cannot reuse the catalog pin.
    call(&db,owner(),"update_record",json!({"id":created["id"],"body_set":NEW,"if_body_digest":created["body_digest"],"reason":"Publish a distinct source revision","idempotency_key":"different-body-event"})).await.unwrap();
    let mut prep = prepare(created["body_digest"].as_str().unwrap());
    prep["artifact_id"] = created["id"].clone();
    prep["package"] = json!("agent.docs");
    prep["expected_source_revision"] = published["source_revision"].clone();
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    assert!(call(&db, owner(), "manage_alpha_tabs", prep).await.is_err());
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    assert!(call(
        &db,
        owner(),
        "manage_alpha_tabs",
        initial_catalog_publication(&created)
    )
    .await
    .is_err());
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn catalog_initial_publication_refuses_nonprivate_and_nonmatching_sources() {
    let f = Fixture::new().await;
    let (db, _, _) = fixture(&f, PACKAGE).await;
    for (private, body) in [(false, NEW), (true, OLD)] {
        let created = fresh_catalog_source(&db, private, body).await;
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        assert!(call(
            &db,
            owner(),
            "manage_alpha_tabs",
            initial_catalog_publication(&created)
        )
        .await
        .is_err());
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    }
    db.close().await;
}

#[tokio::test]
async fn owner_app_first_publication_requires_fresh_scoped_adoption_and_replays() {
    let f = Fixture::new().await;
    let (db, a, _) = fixture(&f, PACKAGE).await;
    let caller = || owner().with_hosting_owner(false);
    let created = call(
        &db,
        caller(),
        "create_record",
        json!({
            "type":"Document","kind":"artifact","name":"First personal app",
            "body":OLD,"facets":{"runtime":"native.html.v1","app_package":"true"},
            "reason":"Create a never-installed app","confirm":true
        }),
    )
    .await
    .unwrap();
    let artifact = created["id"].as_str().unwrap();
    let folder = call(
        &db,
        caller(),
        "create_record",
        json!({
            "type":"Collection","kind":"folder","name":"First app folder",
            "reason":"Choose a folder at first adoption","confirm":true
        }),
    )
    .await
    .unwrap()["id"]
        .clone();
    let package = "personal.first-app";
    let mut prep = prepare(&crate::mcp::tools::lifecycle::body_digest(Some(OLD)));
    prep["artifact_id"] = json!(artifact);
    prep["package"] = json!(package);
    assert_eq!(
        call(&db, caller(), "manage_alpha_tabs", prep.clone())
            .await
            .unwrap()["ready"],
        false
    );
    let digest = crate::mcp::tools::lifecycle::body_digest(Some(OLD));
    let mut publish = update(OLD, &digest, "first-publication");
    publish["id"] = json!(artifact);
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    for (denied, mut args) in [
        (
            Caller::authenticated("account-b").with_hosting_context("account-b", "hq-fixture"),
            publish.clone(),
        ),
        (caller().with_hosting_member(false), publish.clone()),
        (caller(), publish.clone()),
        (caller(), publish.clone()),
        (
            caller().with_host_asserted_app(
                crate::mcp::app_attribution::AppAttribution::new(PACKAGE, "0.4.0", "install")
                    .unwrap(),
            ),
            publish.clone(),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        if denied == 2 {
            args.1["if_body_digest"] = json!("00".repeat(32));
        }
        if denied == 3 {
            args.1["body_set"] = json!("<script>invalid</script>");
        }
        assert!(call(&db, args.0, "update_record", args.1).await.is_err());
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    }
    call(&db, caller(), "update_record", publish).await.unwrap();
    let format: i64 = sqlx::query_scalar("SELECT json_extract(payload,'$.format') FROM content_events WHERE record_id=? AND type='kernel.app_source_published.v1'")
        .bind(artifact).fetch_one(db.pool()).await.unwrap();
    assert_eq!(format, 2);
    let mut again = update(OLD, &digest, "first-publication-no-op");
    again["id"] = json!(artifact);
    assert_eq!(
        call(&db, caller(), "update_record", again).await.unwrap()["changed"],
        false
    );
    let publications: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='kernel.app_source_published.v1'")
        .bind(artifact).fetch_one(db.pool()).await.unwrap();
    assert_eq!(
        publications, 1,
        "a later same-bytes edit must not republish"
    );
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let prepared = call(&db, caller(), "manage_alpha_tabs", prep.clone())
        .await
        .unwrap();
    assert_eq!(prepared["ready"], true, "{prepared}");
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    let mut reserved = prep;
    reserved["package"] = json!("agent.docs");
    assert!(call(&db, caller(), "manage_alpha_tabs", reserved)
        .await
        .is_err());
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    let mut install = prepared["next_call"]["arguments"].clone();
    install["idempotency_key"] = json!("stage-first-app");
    let staged = call(&db, caller(), "manage_alpha_tabs", install.clone())
        .await
        .unwrap();
    assert_eq!(staged["install"]["adoption"], "caller_asserted");
    let generation = staged["install"]["event_id"].as_str().unwrap().to_owned();
    let mut pin = request(&install);
    pin.expected_install_event_id = Some(generation.clone());
    pin.idempotency_key = None;
    let mut tx = db.write_pool().begin().await.unwrap();
    assert!(
        k::app_installs::admit_install_on(&mut tx, &a, package, &generation)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let preview = k::app_installs::preview_as(
        &db,
        &a,
        &native_app_hosted_caller("account-a", &pin, false),
        pin.clone(),
    )
    .await
    .unwrap();
    assert_eq!(preview.body, OLD);
    let mut adopt = k::app_installs::AdoptRequest {
        pin: pin.clone(),
        receipt_id: preview.receipt.receipt_id,
        nonce: preview.receipt.nonce,
        preview_session: preview.receipt.preview_session,
        scope: Some(json!({"kind":"folders","folder_ids":[folder]})),
    };
    adopt.pin.idempotency_key = Some("adopt-first-app".into());
    let adopted = k::app_installs::adopt_as(
        &db,
        &a,
        &native_app_hosted_caller("account-a", &pin, true),
        adopt,
    )
    .await
    .unwrap();
    assert_eq!(adopted.install["adoption"], "shell_adopt.v1");
    assert_eq!(
        adopted.install["scope"],
        json!({"kind":"folders","folder_ids":[folder]})
    );
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    k::verify_v2_ready(&db).await.unwrap();
    // Removal remains a refusal boundary for further source publication.
    let generation = adopted.install["event_id"].as_str().unwrap();
    k::app_installs::remove_as(&db, &a, package, generation)
        .await
        .unwrap();
    let mut after_remove = update(
        NEW,
        &crate::mcp::tools::lifecycle::body_digest(Some(OLD)),
        "removed-first-source",
    );
    after_remove["id"] = json!(artifact);
    assert!(call(&db, caller(), "update_record", after_remove.clone())
        .await
        .is_err());
    // A later reinstall can replace the current row with a different source.
    // The old source's retained pin must still prevent first-publication reuse.
    let replacement = call(
        &db,
        caller(),
        "create_record",
        json!({
            "type":"Document","kind":"artifact","name":"Replacement personal app",
            "body":OLD,"facets":{"runtime":"native.html.v1","app_package":"true"},
            "reason":"Replace a removed install's source","confirm":true
        }),
    )
    .await
    .unwrap()["id"]
        .clone();
    let mut publish = update(OLD, &digest, "publish-replacement");
    publish["id"] = replacement.clone();
    call(&db, caller(), "update_record", publish).await.unwrap();
    let mut replacement_prepare = prepare(&digest);
    replacement_prepare["artifact_id"] = replacement.clone();
    replacement_prepare["package"] = json!(package);
    let prepared = call(&db, caller(), "manage_alpha_tabs", replacement_prepare)
        .await
        .unwrap();
    assert_eq!(prepared["ready"], true, "{prepared}");
    let mut install = prepared["next_call"]["arguments"].clone();
    install["idempotency_key"] = json!("stage-replacement");
    call(&db, caller(), "manage_alpha_tabs", install)
        .await
        .unwrap();
    let current: String = sqlx::query_scalar("SELECT json_extract(row_json,'$.artifact_id') FROM kernel_app_installs WHERE principal=? AND package=?")
        .bind(&a).bind(package).fetch_one(db.pool()).await.unwrap();
    assert_eq!(current, replacement.as_str().unwrap());
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    assert!(call(&db, caller(), "update_record", after_remove)
        .await
        .is_err());
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn owner_app_update_attests_prepares_adopts_without_interrupting_old_generation_and_replays()
{
    update_flow(false, true).await;
}
#[tokio::test]
async fn catalog_update_attests_prepares_adopts_without_interrupting_old_generation_and_replays() {
    update_flow(true, true).await;
}
#[tokio::test]
async fn member_app_update_attests_prepares_adopts_and_replays() {
    update_flow(false, false).await;
}

async fn update_flow(catalog: bool, workspace_owner: bool) {
    let caller = || owner().with_hosting_owner(workspace_owner);
    let package = if catalog { "agent.docs" } else { PACKAGE };
    let prepare = |digest: &str| {
        let mut args = prepare(digest);
        args["package"] = json!(package);
        args
    };
    let f = Fixture::new().await;
    let (db, a, b) = fixture(&f, package).await;
    k::app_installs::remove_as(&db, &b, package, "install-b")
        .await
        .unwrap();
    let rendered_before = render(&db).await;
    assert_eq!(rendered_before["status"], "rendered", "{rendered_before}");
    let closure_before: String = sqlx::query_scalar(
        "SELECT descriptor FROM kernel_artifact_closures WHERE artifact_id='secret'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let old_digest = crate::mcp::tools::lifecycle::body_digest(Some(OLD));
    if catalog {
        k::verify_v2_ready(&db).await.unwrap();
    }
    if catalog {
        let publication = json!({"action":"publish_catalog_update","artifact_id":"secret","package":package,"version":"0.5.0","expected_body_digest":old_digest,"expected_install_event_id":"install","reason":"Publish host catalog update"});
        for (field, value) in [
            ("expected_body_digest", json!("00".repeat(32))),
            ("expected_install_event_id", json!("stale")),
            ("package", json!("agent.missing")),
            ("version", json!("9.9.9")),
            ("artifact_id", json!("note")),
        ] {
            let before = k::dump_all_kernel_tables(&db).await.unwrap();
            let mut bad = publication.clone();
            bad[field] = value;
            assert!(call(&db, owner(), "manage_alpha_tabs", bad).await.is_err());
            assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
        }
        assert!(call(
            &db,
            owner().with_hosting_owner(false),
            "manage_alpha_tabs",
            publication.clone()
        )
        .await
        .is_err());
        let foreign = Caller::authenticated("account-b")
            .with_hosting_context("account-b", "hq-fixture")
            .with_hosting_owner(true);
        let app = owner().with_host_asserted_app(
            crate::mcp::app_attribution::AppAttribution::new(package, "0.4.0", "install").unwrap(),
        );
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        for denied in [foreign, app] {
            assert!(call(&db, denied, "manage_alpha_tabs", publication.clone())
                .await
                .is_err());
            assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
        }
        call(&db, owner(), "manage_alpha_tabs", publication.clone())
            .await
            .unwrap();
        let retry = call(&db, owner(), "manage_alpha_tabs", publication)
            .await
            .unwrap();
        assert_eq!(
            retry["body_digest"],
            crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(NEW)
        );
    } else {
        let saved = call(
            &db,
            caller(),
            "update_record",
            update(NEW, &old_digest, "publish-next"),
        )
        .await
        .unwrap();
        let retry = call(
            &db,
            caller(),
            "update_record",
            update(NEW, &old_digest, "publish-next"),
        )
        .await
        .unwrap();
        assert_eq!(saved, retry);
    }
    if catalog {
        k::verify_v2_ready(&db).await.unwrap();
    }
    let rendered_after = render(&db).await;
    assert_eq!(rendered_after["status"], "rendered", "{rendered_after}");
    assert_eq!(
        rendered_after["plan"]["body_digest"],
        crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(OLD)
    );
    assert_eq!(
        closure_before,
        sqlx::query_scalar::<_, String>(
            "SELECT descriptor FROM kernel_artifact_closures WHERE artifact_id='secret'"
        )
        .fetch_one(db.pool())
        .await
        .unwrap()
    );
    let mut delivery_tx = db.write_pool().begin().await.unwrap();
    let delivered = crate::mcp::kernel_v2::artifacts::html_board::bundle_source_on(
        &mut delivery_tx,
        &a,
        "secret",
        &crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(OLD),
    )
    .await
    .unwrap();
    assert_eq!(
        delivered.0, OLD,
        "hosted artifact delivery retains the activated bytes"
    );
    delivery_tx.rollback().await.unwrap();
    let event_type = if catalog {
        "kernel.app_catalog_source_published.v1"
    } else {
        "kernel.app_source_published.v1"
    };
    let (revision,descriptor,event_id):(String,String,String)=sqlx::query_as("SELECT json_extract(payload,'$.source_revision'),json_extract(payload,'$.attestation.artifact_source'),id FROM content_events WHERE type=? ORDER BY seq DESC LIMIT 1").bind(event_type).fetch_one(db.pool()).await.unwrap();
    let descriptor: Value = serde_json::from_str(&descriptor).unwrap();
    assert_eq!(descriptor["source_event_id"], revision);
    assert_eq!(descriptor["attestation_event_id"], event_id);
    assert_eq!(
        descriptor["source_sha256"],
        crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(NEW)
    );
    // Replay admission verifies the recorded host attestation payload; a
    // changed descriptor or source-event witness cannot enter the projection.
    let mut tx = db.write_pool().begin().await.unwrap();
    let mut attested = crate::conformance::rebuild::read_all_events(&mut tx)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.id == event_id)
        .unwrap();
    let mut payload: Value = serde_json::from_str(attested.payload.as_deref().unwrap()).unwrap();
    payload["attestation"]["artifact_source"]["source_sha256"] = json!("00".repeat(32));
    attested.payload = Some(payload.to_string());
    let corrupt = if catalog {
        k::app_installs::catalog::project(&mut tx, &attested).await
    } else {
        k::app_installs::sources::project(&mut tx, &attested).await
    };
    assert!(corrupt.is_err());
    tx.rollback().await.unwrap();
    if catalog {
        // Check the retained verifier itself, rather than stopping at the
        // projector's equality check against the canonical event row.
        let mut tx = db.write_pool().begin().await.unwrap();
        let original = crate::conformance::rebuild::read_all_events(&mut tx)
            .await
            .unwrap()
            .into_iter()
            .find(|e| e.id == event_id)
            .unwrap();
        let original_payload: Value =
            serde_json::from_str(original.payload.as_deref().unwrap()).unwrap();
        k::app_installs::catalog::verify(&original_payload, "secret", &event_id, &revision, NEW)
            .unwrap();
        for field in ["entry", "payload_text", "intent", "result", "declaration"] {
            let mut corrupt = original_payload.clone();
            match field {
                "entry" => corrupt["entry"]["body_digest"] = json!("00".repeat(32)),
                "payload_text" => {
                    let text = corrupt["payload_text"].as_str().unwrap().to_owned() + " ";
                    corrupt["payload_text"] = json!(text);
                }
                "intent" => corrupt["intent"]["reason"] = json!("changed reason"),
                "result" => corrupt["result"]["source_revision"] = json!("substituted"),
                "declaration" => {
                    use sha2::Digest;
                    let mut payload: Value =
                        serde_json::from_str(corrupt["payload_text"].as_str().unwrap()).unwrap();
                    payload["declaration"]["effects"] = json!(["invented"]);
                    let text = payload.to_string();
                    let hash = hex::encode(sha2::Sha256::digest(text.as_bytes()));
                    corrupt["payload_text"] = json!(text);
                    corrupt["entry"]["payload_sha256"] = json!(hash);
                    corrupt["entry"]["payload_path"] = json!(format!("packages/{hash}.json"));
                    corrupt["catalog"]["entries"][0] = corrupt["entry"].clone();
                    let mut bytes = serde_json::to_vec(&corrupt["catalog"]["entries"]).unwrap();
                    bytes.push(b'\n');
                    corrupt["catalog"]["digest"] = json!(hex::encode(sha2::Sha256::digest(&bytes)));
                }
                _ => unreachable!(),
            }
            assert!(
                k::app_installs::catalog::verify(&corrupt, "secret", &event_id, &revision, NEW)
                    .is_err(),
                "retained {field} corruption must refuse"
            );
        }
        tx.rollback().await.unwrap();
        // Change both the retained row and the EventRow together so admission
        // reaches the predecessor/install/same-act witness checks.
        for field in [
            "body_predecessor",
            "install_generation",
            "body_act",
            "body_actor",
        ] {
            let mut tx = db.write_pool().begin().await.unwrap();
            // Deliberate forensic corruption fixture. The trigger drop is
            // transactional and is restored by the rollback below.
            sqlx::query("DROP TRIGGER IF EXISTS content_events_no_update")
                .execute(&mut *tx)
                .await
                .unwrap();
            let mut event = original.clone();
            let mut payload = original_payload.clone();
            if field == "body_act" {
                sqlx::query("UPDATE content_events SET act=NULL WHERE id=?")
                    .bind(&revision)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            } else if field == "body_actor" {
                sqlx::query("UPDATE content_events SET actor=? WHERE id=?")
                    .bind(&b)
                    .bind(&revision)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            } else {
                payload[field] = json!("substituted");
                event.payload = Some(payload.to_string());
                sqlx::query("UPDATE content_events SET payload=? WHERE id=?")
                    .bind(&event.payload)
                    .bind(&event_id)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            }
            let error = k::app_installs::catalog::project(&mut tx, &event)
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("body/install/actor witness mismatch"),
                "{field} reached deep witness refusal: {error}"
            );
            tx.rollback().await.unwrap();
        }
    }
    let hidden = call(
        &db,
        Caller::authenticated("account-b")
            .with_hosting_context("account-b", "hq-fixture")
            .with_hosting_owner(true),
        "manage_alpha_tabs",
        prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(NEW)),
    )
    .await
    .unwrap();
    let mut missing = prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(NEW));
    missing["artifact_id"] = json!("missing-source");
    assert_eq!(
        hidden,
        call(
            &db,
            Caller::authenticated("account-b")
                .with_hosting_context("account-b", "hq-fixture")
                .with_hosting_owner(true),
            "manage_alpha_tabs",
            missing
        )
        .await
        .unwrap(),
        "hidden native evidence is indistinguishable from an absent source"
    );
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let prepared = call(
        &db,
        caller(),
        "manage_alpha_tabs",
        prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(NEW)),
    )
    .await
    .unwrap();
    assert_eq!(prepared["ready"], true, "{prepared}");
    if catalog {
        let err = call(
            &db,
            caller().with_hosting_owner(false),
            "manage_alpha_tabs",
            prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(NEW)),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("workspace-owner footing"), "{err}");
        let mut replacement = ToolRegistry::new();
        replacement.set_catalog_assets(crate::mcp::tools::catalog_assets::fixture_assets(
            "replacement catalog payload",
            "agent.docs",
            "0.6.0",
        ));
        crate::mcp::register_builtin_tools(&mut replacement).unwrap();
        crate::mcp::tools::register_surface_tools(&mut replacement).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut replacement).unwrap();
        let retained = replacement
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                caller(),
                "manage_alpha_tabs",
                prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(NEW)),
            )
            .await
            .unwrap();
        assert_eq!(
            retained["ready"], true,
            "recorded pin survives a host catalog change"
        );
        let mut tx = db.write_pool().begin().await.unwrap();
        assert!(
            k::app_installs::sources::require_update_owner_on(
                &mut tx,
                &a,
                "secret",
                Some(package),
                "source"
            )
            .await
            .is_err(),
            "an unrelated catalog publication cannot reclassify a frozen/custom revision"
        );
        let mut wrong = request(&prepared["next_call"]["arguments"]);
        wrong.declaration["effects"] = json!(["invented"]);
        assert!(k::app_installs::sources::native_pin_on(&mut tx, &wrong)
            .await
            .unwrap()
            .is_none());
        tx.rollback().await.unwrap();
    }

    assert_eq!(
        call(
            &db,
            caller(),
            "manage_alpha_tabs",
            prepare(&"00".repeat(32))
        )
        .await
        .unwrap()["ready"],
        false
    );

    assert_eq!(prepared["source_revision"], revision);
    assert_eq!(
        before,
        k::dump_all_kernel_tables(&db).await.unwrap(),
        "preparation is read-only"
    );
    let mut install = prepared["next_call"]["arguments"].clone();
    install["idempotency_key"] = json!("stage-next");
    if catalog {
        let err = call(
            &db,
            caller().with_hosting_owner(false),
            "manage_alpha_tabs",
            install.clone(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("workspace-owner footing"), "{err}");
    }
    let mut stale_install = install.clone();
    stale_install["expected_install_event_id"] = json!("stale-predecessor");
    assert!(call(&db, caller(), "manage_alpha_tabs", stale_install)
        .await
        .is_err());
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    let staged = call(&db, caller(), "manage_alpha_tabs", install.clone())
        .await
        .unwrap();
    assert_eq!(staged["install"]["pending_update"], true);
    assert_eq!(staged["install"]["adoption"], "caller_asserted");
    let direct = k::app_installs::install_for_user_as(&db, &a, request(&install))
        .await
        .unwrap();
    assert_eq!(direct.install["skip_reason"], "adoption_required");
    assert_eq!(
        direct.install["launch_binding"]["reason"],
        "adoption_required"
    );

    let pending = staged["install"]["event_id"].as_str().unwrap().to_owned();
    let retry = call(&db, caller(), "manage_alpha_tabs", install.clone())
        .await
        .unwrap();
    assert_eq!(retry["changed"], false);
    let active = k::app_installs::inspect_as(&db, &a, package).await.unwrap();
    assert_eq!(active["install"]["event_id"], "install");
    assert_eq!(active["pending_update"]["event_id"], pending);
    assert_eq!(active["pending_update"]["skip_reason"], "adoption_required");
    assert_eq!(
        active["pending_update"]["launch_binding"]["reason"],
        "adoption_required"
    );
    let launch_caller = native_app_hosted_caller("account-a", &request(&install), false)
        .with_hosting_owner(workspace_owner);
    let mut launch_tx = db.write_pool().begin().await.unwrap();
    assert_eq!(
        k::app_installs::launch_source_on(&mut launch_tx, &a, &launch_caller, package, "install")
            .await
            .unwrap()
            .body,
        OLD
    );
    launch_tx.rollback().await.unwrap();

    let mut tx = db.write_pool().begin().await.unwrap();
    assert_eq!(
        k::app_installs::admit_install_on(&mut tx, &a, package, "install")
            .await
            .unwrap()
            .body,
        OLD
    );
    assert!(
        k::app_installs::admit_install_on(&mut tx, &a, package, &pending)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let projected = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&db).await.unwrap());
    let mut pin = request(&install);
    pin.idempotency_key = None;
    pin.expected_install_event_id = Some(pending.clone());
    let preview_caller =
        native_app_hosted_caller("account-a", &pin, false).with_hosting_owner(workspace_owner);
    if catalog {
        let err = k::app_installs::preview_as(
            &db,
            &a,
            &preview_caller.clone().with_hosting_owner(false),
            pin.clone(),
        )
        .await
        .err()
        .expect("a member cannot preview a catalogue update");
        assert!(err.to_string().contains("workspace-owner footing"), "{err}");
    }
    let review = k::app_installs::preview_as(&db, &a, &preview_caller, pin.clone())
        .await
        .unwrap();
    assert_eq!(review.body, NEW);
    let mut tx = db.write_pool().begin().await.unwrap();
    assert_eq!(
        k::app_installs::bundle_source_on(
            &mut tx,
            &preview_caller,
            package,
            &pending,
            &pin.digest,
            Some(&review.receipt.receipt_id)
        )
        .await
        .unwrap()
        .0,
        NEW
    );
    assert!(k::app_installs::bundle_source_on(
        &mut tx,
        &preview_caller,
        PACKAGE,
        &pending,
        &pin.digest,
        None
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    let mut adopt = k::app_installs::AdoptRequest {
        scope: None,
        pin: pin.clone(),
        receipt_id: review.receipt.receipt_id,
        nonce: review.receipt.nonce,
        preview_session: review.receipt.preview_session,
    };
    adopt.pin.idempotency_key = Some("adopt-next".into());
    let adopting =
        native_app_hosted_caller("account-a", &pin, true).with_hosting_owner(workspace_owner);
    if catalog {
        let err = k::app_installs::adopt_as(
            &db,
            &a,
            &adopting.clone().with_hosting_owner(false),
            adopt.clone(),
        )
        .await
        .err()
        .expect("a member cannot adopt a catalogue update");
        assert!(err.to_string().contains("workspace-owner footing"), "{err}");
    }
    let mut bad = adopt.clone();
    bad.nonce = "not-the-preview-nonce".into();
    assert!(k::app_installs::adopt_as(&db, &a, &adopting, bad)
        .await
        .is_err());
    let adopted = k::app_installs::adopt_as(&db, &a, &adopting, adopt.clone())
        .await
        .unwrap();
    let previous: String = sqlx::query_scalar(
        "SELECT previous_generation FROM kernel_app_installs WHERE principal=? AND package=?",
    )
    .bind(&a)
    .bind(package)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        previous, "install",
        "adoption records the actually running predecessor"
    );
    assert_eq!(adopted.install["adoption"], "shell_adopt.v1");
    assert!(
        !k::app_installs::adopt_as(&db, &a, &adopting, adopt)
            .await
            .unwrap()
            .outcome
            .changed
    );
    let mut tx = db.write_pool().begin().await.unwrap();
    assert_eq!(
        k::app_installs::admit_install_on(&mut tx, &a, package, &adopted.outcome.generation)
            .await
            .unwrap()
            .body,
        NEW
    );
    assert!(
        k::app_installs::admit_install_on(&mut tx, &a, package, "install")
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    assert!(
        call(&db, caller(), "manage_alpha_tabs", install)
            .await
            .is_err(),
        "stale staging retry cannot undo adoption"
    );
    let projected = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&db).await.unwrap());
    if catalog {
        k::verify_v2_ready(&db).await.unwrap();
    }
    sqlx::query("DROP TABLE kernel_app_package_sources; DROP TABLE kernel_app_install_outcomes")
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut tx = db.write_pool().begin().await.unwrap();
    k::app_installs::ensure_schema(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&db).await.unwrap());
    // Sharing closes publication/consent for further updates, not execution of
    // the already adopted native generation under its existing View/consent.
    k::rehome_record_as(&db, &a, "secret", KERNEL_ROOT_ID)
        .await
        .unwrap();
    let b_state = k::app_installs::inspect_as(&db, &b, package).await.unwrap();
    let pins = k::app_installs::frozen_sources_as(&db, &b).await.unwrap();
    let old = pins
        .iter()
        .find(|pin| pin["source_revision"] == "source")
        .unwrap();
    k::app_installs::install_as(
        &db,
        &b,
        k::app_installs::InstallRequest {
            package: package.into(),
            version: "0.4.0".into(),
            digest: old["digest"].as_str().unwrap().into(),
            artifact_id: "secret".into(),
            source_revision: "source".into(),
            declaration: serde_json::from_str(old["consented_declaration"].as_str().unwrap())
                .unwrap(),
            reason: "Stage the unchanged frozen source independently".into(),
            request: None,
            idempotency_key: None,
            expected_install_event_id: Some(
                b_state["install"]["event_id"].as_str().unwrap().into(),
            ),
        },
    )
    .await
    .unwrap();
    let mut tx = db.write_pool().begin().await.unwrap();
    assert_eq!(
        k::app_installs::admit_install_on(&mut tx, &a, package, &adopted.outcome.generation)
            .await
            .unwrap()
            .body,
        NEW,
        "sharing must not revoke the adopted generation"
    );
    tx.rollback().await.unwrap();
    app_roster(&db, "account-b", &["account-b"]).await;
    let offboarded = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(
        offboarded,
        k::dump_all_kernel_tables(&db).await.unwrap(),
        "later owner offboarding cannot rewrite historical publication or adoption"
    );
    db.close().await;
}

#[tokio::test]
async fn owner_app_source_refuses_shared_artifacts_nonowners_stale_guards_and_invalid_sources_atomically(
) {
    let f = Fixture::new().await;
    let (db, a, b) = fixture(&f, PACKAGE).await;
    let digest = crate::mcp::tools::lifecycle::body_digest(Some(OLD));
    let err = call(
        &db,
        owner().with_hosting_owner(false),
        "update_record",
        update(NEW, &digest, "shared"),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("another principal has an active install"),
        "{err}"
    );
    k::app_installs::remove_as(&db, &b, PACKAGE, "install-b")
        .await
        .unwrap();
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    for (caller, args) in [
        (
            owner().with_hosting_owner(false).with_hosting_member(false),
            update(NEW, &digest, "guest"),
        ),
        (
            Caller::authenticated("account-b").with_hosting_context("account-b", "hq-fixture"),
            update(NEW, &digest, "not-source-owner"),
        ),
        (owner(), update(NEW, &"00".repeat(32), "stale")),
        (
            owner(),
            update("<script>invalid</script>", &digest, "invalid-html"),
        ),
    ] {
        assert!(call(&db, caller, "update_record", args).await.is_err());
        assert_eq!(
            before,
            k::dump_all_kernel_tables(&db).await.unwrap(),
            "refusal rolls back source, attestation and receipt"
        );
    }
    let mut missing_guard = update(NEW, &digest, "missing-guard");
    missing_guard
        .as_object_mut()
        .unwrap()
        .remove("if_body_digest");
    assert!(call(&db, owner(), "update_record", missing_guard)
        .await
        .unwrap_err()
        .to_string()
        .contains("if_body_digest"));
    call(&db,owner(),"update_record",json!({"id":"secret","facets":{"runtime":"native.mdx.v2"},"reason":"Exercise the non-HTML refusal"})).await.unwrap();
    assert!(call(
        &db,
        owner(),
        "update_record",
        update(NEW, &digest, "non-html")
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("native.html.v1"));
    assert_eq!(
        k::read_record_as(&db, &a, "secret")
            .await
            .unwrap()
            .unwrap()
            .body
            .as_deref(),
        Some(OLD)
    );
    db.close().await;
}

#[tokio::test]
async fn owner_app_source_refuses_catalogue_package_publication() {
    let f = Fixture::new().await;
    let (db, _, b) = fixture(&f, "agent.docs").await;
    k::app_installs::remove_as(&db, &b, "agent.docs", "install-b")
        .await
        .unwrap();
    let err = call(
        &db,
        owner(),
        "update_record",
        update(
            NEW,
            &crate::mcp::tools::lifecycle::body_digest(Some(OLD)),
            "catalogue",
        ),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("catalogue packages are not supported"),
        "{err}"
    );
    db.close().await;
}

#[tokio::test]
async fn owner_app_update_refuses_sharing_after_publication_and_staging() {
    shared_update_flow(false).await;
}
#[tokio::test]
async fn catalog_update_refuses_sharing_after_publication_and_staging() {
    shared_update_flow(true).await;
}
async fn shared_update_flow(catalog: bool) {
    let package = if catalog { "agent.docs" } else { PACKAGE };
    let prepare = |digest: &str| {
        let mut args = prepare(digest);
        args["package"] = json!(package);
        args
    };
    let f = Fixture::new().await;
    let (db, a, b) = fixture(&f, package).await;
    let removed = k::app_installs::remove_as(&db, &b, package, "install-b")
        .await
        .unwrap();
    if catalog {
        publish_catalog(&db).await;
    } else {
        call(
            &db,
            owner(),
            "update_record",
            update(
                NEW,
                &crate::mcp::tools::lifecycle::body_digest(Some(OLD)),
                "publish",
            ),
        )
        .await
        .unwrap();
    }
    let prepared = call(
        &db,
        owner(),
        "manage_alpha_tabs",
        prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(NEW)),
    )
    .await
    .unwrap();
    let install = prepared["next_call"]["arguments"].clone();
    let staged = call(&db, owner(), "manage_alpha_tabs", install.clone())
        .await
        .unwrap();
    let mut preview_pin = request(&install);
    preview_pin.expected_install_event_id =
        Some(staged["install"]["event_id"].as_str().unwrap().into());
    let review = k::app_installs::preview_as(
        &db,
        &a,
        &native_app_hosted_caller("account-a", &preview_pin, false).with_hosting_owner(true),
        preview_pin.clone(),
    )
    .await
    .unwrap();
    // A separately admitted member can still stage the old frozen source.
    // That turns the artifact into a shared package and closes this update lane.
    k::rehome_record_as(&db, &a, "secret", KERNEL_ROOT_ID)
        .await
        .unwrap();
    let mut old_prepare = prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(OLD));
    old_prepare["version"] = json!("0.4.0");
    let offered = call(
        &db,
        Caller::authenticated("account-b").with_hosting_context("account-b", "hq-fixture"),
        "manage_alpha_tabs",
        old_prepare,
    )
    .await
    .unwrap();
    assert_eq!(
        offered["ready"], true,
        "a different native publication cannot obstruct exact frozen-pin preparation: {offered}"
    );
    let pins = k::app_installs::frozen_sources_as(&db, &b).await.unwrap();
    let old = pins
        .iter()
        .find(|pin| pin["source_revision"] == "source")
        .unwrap();
    k::app_installs::install_as(
        &db,
        &b,
        k::app_installs::InstallRequest {
            package: package.into(),
            version: "0.4.0".into(),
            digest: old["digest"].as_str().unwrap().into(),
            artifact_id: "secret".into(),
            source_revision: "source".into(),
            declaration: serde_json::from_str(old["consented_declaration"].as_str().unwrap())
                .unwrap(),
            reason: "Independently stage the old frozen pin".into(),
            request: None,
            idempotency_key: None,
            expected_install_event_id: Some(removed),
        },
    )
    .await
    .unwrap();
    for args in [
        prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(NEW)),
        install,
    ] {
        let err = call(&db, owner(), "manage_alpha_tabs", args)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("another principal has an active install"),
            "{err}"
        );
    }
    let mut pin = request(&prepared["next_call"]["arguments"]);
    pin.expected_install_event_id = Some(staged["install"]["event_id"].as_str().unwrap().into());
    let err = k::app_installs::preview_as(
        &db,
        &a,
        &native_app_hosted_caller("account-a", &pin, false).with_hosting_owner(true),
        pin.clone(),
    )
    .await
    .err()
    .unwrap();
    assert!(
        err.to_string()
            .contains("another principal has an active install"),
        "{err}"
    );
    let err = k::app_installs::adopt_as(
        &db,
        &a,
        &native_app_hosted_caller("account-a", &preview_pin, true).with_hosting_owner(true),
        k::app_installs::AdoptRequest {
            scope: None,
            pin: preview_pin,
            receipt_id: review.receipt.receipt_id,
            nonce: review.receipt.nonce,
            preview_session: review.receipt.preview_session,
        },
    )
    .await
    .err()
    .unwrap();
    assert!(
        err.to_string()
            .contains("another principal has an active install"),
        "{err}"
    );
    let mut tx = db.write_pool().begin().await.unwrap();
    assert_eq!(
        k::app_installs::admit_install_on(&mut tx, &a, package, "install")
            .await
            .unwrap()
            .body,
        OLD
    );
    tx.rollback().await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn owner_app_new_revision_can_reinstall_after_removal_with_fresh_adoption() {
    let f = Fixture::new().await;
    let (db, a, b) = fixture(&f, PACKAGE).await;
    k::app_installs::remove_as(&db, &b, PACKAGE, "install-b")
        .await
        .unwrap();
    call(
        &db,
        owner(),
        "update_record",
        update(
            NEW,
            &crate::mcp::tools::lifecycle::body_digest(Some(OLD)),
            "publish",
        ),
    )
    .await
    .unwrap();
    let removed = k::app_installs::remove_as(&db, &a, PACKAGE, "install")
        .await
        .unwrap();
    let err = call(
        &db,
        owner(),
        "update_record",
        update(
            OLD,
            &crate::mcp::tools::lifecycle::body_digest(Some(NEW)),
            "removed-publish",
        ),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("existing custom package and artifact"),
        "{err}"
    );
    assert!(call(
        &db,
        owner(),
        "manage_alpha_tabs",
        prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(NEW))
    )
    .await
    .is_err());
    let mut frozen_prepare = prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(OLD));
    frozen_prepare["version"] = json!("0.4.0");
    let frozen = call(&db, owner(), "manage_alpha_tabs", frozen_prepare)
        .await
        .unwrap();
    let reinstalled = call(
        &db,
        owner(),
        "manage_alpha_tabs",
        frozen["next_call"]["arguments"].clone(),
    )
    .await
    .unwrap();
    let restored = reinstalled["install"]["event_id"].as_str().unwrap();
    let format: i64 = sqlx::query_scalar(
        "SELECT json_extract(payload,'$.format') FROM content_events WHERE id=?",
    )
    .bind(restored)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        format, 1,
        "pure frozen installs retain rollback-compatible format"
    );
    let prepared = call(
        &db,
        owner(),
        "manage_alpha_tabs",
        prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(NEW)),
    )
    .await
    .unwrap();
    assert_eq!(prepared["ready"], true, "{prepared}");
    assert_eq!(frozen["current_install_event_id"], removed);
    assert_eq!(prepared["current_install_event_id"], restored);
    let mut pin = request(&prepared["next_call"]["arguments"]);
    let staged = k::app_installs::install_as(&db, &a, pin.clone())
        .await
        .unwrap();
    assert_eq!(
        k::app_installs::inspect_as(&db, &a, PACKAGE).await.unwrap()["install"]["adoption"],
        "caller_asserted"
    );
    pin.expected_install_event_id = Some(staged.generation);
    let review = k::app_installs::preview_as(
        &db,
        &a,
        &native_app_hosted_caller("account-a", &pin, false).with_hosting_owner(true),
        pin.clone(),
    )
    .await
    .unwrap();
    let adopted = k::app_installs::adopt_as(
        &db,
        &a,
        &native_app_hosted_caller("account-a", &pin, true).with_hosting_owner(true),
        k::app_installs::AdoptRequest {
            scope: None,
            pin,
            receipt_id: review.receipt.receipt_id,
            nonce: review.receipt.nonce,
            preview_session: review.receipt.preview_session,
        },
    )
    .await
    .unwrap();
    let mut tx = db.write_pool().begin().await.unwrap();
    assert_eq!(
        k::app_installs::admit_install_on(&mut tx, &a, PACKAGE, &adopted.outcome.generation)
            .await
            .unwrap()
            .body,
        NEW
    );
    tx.rollback().await.unwrap();
    let projected = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

async fn staged_update(db: &Db, a: &str) -> k::app_installs::InstallRequest {
    call(
        db,
        owner(),
        "update_record",
        update(
            NEW,
            &crate::mcp::tools::lifecycle::body_digest(Some(OLD)),
            "publish-boundary",
        ),
    )
    .await
    .unwrap();
    let prepared = call(
        db,
        owner(),
        "manage_alpha_tabs",
        prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(NEW)),
    )
    .await
    .unwrap();
    let mut pin = request(&prepared["next_call"]["arguments"]);
    let staged = k::app_installs::install_as(db, a, pin.clone())
        .await
        .unwrap();
    pin.expected_install_event_id = Some(staged.generation);
    pin
}

#[tokio::test]
async fn owner_app_frozen_member_retry_and_already_installed_preserve_main_behavior() {
    let f = Fixture::new().await;
    let (db, a, b) = fixture(&f, PACKAGE).await;
    k::rehome_record_as(&db, &a, "secret", KERNEL_ROOT_ID)
        .await
        .unwrap();
    let member = Caller::authenticated("account-b").with_hosting_context("account-b", "hq-fixture");
    let mut args = prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(OLD));
    args["version"] = json!("0.4.0");
    let refusal = call(&db, member.clone(), "manage_alpha_tabs", args.clone())
        .await
        .unwrap();
    assert_eq!(
        refusal["findings"][0]["code"], "already_installed",
        "{refusal}"
    );
    assert_eq!(
        refusal["findings"][0]["message"],
        "This account already has this package installed."
    );
    k::app_installs::remove_as(&db, &b, PACKAGE, "install-b")
        .await
        .unwrap();
    let prepared = call(&db, member.clone(), "manage_alpha_tabs", args.clone())
        .await
        .unwrap();
    let mut install = prepared["next_call"]["arguments"].clone();
    install["idempotency_key"] = json!("member-keyed-install");
    let staged = call(&db, member.clone(), "manage_alpha_tabs", install.clone())
        .await
        .unwrap();
    assert_eq!(staged["changed"], true);
    let direct = k::app_installs::install_for_user_as(&db, &b, request(&install))
        .await
        .unwrap();
    assert_eq!(direct.install["skip_reason"], "digest_unverified");
    assert_eq!(
        direct.install["launch_binding"]["reason"],
        "digest_unverified"
    );
    let inspected = k::app_installs::inspect_as(&db, &b, PACKAGE).await.unwrap();
    assert_eq!(inspected["install"]["skip_reason"], "digest_unverified");
    let listed = k::app_installs::list_as(&db, &b, Some("full".into()), None)
        .await
        .unwrap();
    let row = listed["installs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["package"] == PACKAGE)
        .unwrap();
    assert_eq!(row["skip_reason"], "digest_unverified");

    let retry = call(&db, member.clone(), "manage_alpha_tabs", install)
        .await
        .unwrap();
    assert_eq!(retry["changed"], false);
    assert_eq!(retry["install"]["event_id"], staged["install"]["event_id"]);
    assert_eq!(
        call(&db, member, "manage_alpha_tabs", args).await.unwrap(),
        refusal
    );
    db.close().await;
}

#[tokio::test]
async fn owner_app_update_refuses_visible_third_party_and_host_asserted_callers() {
    use crate::mcp::app_attribution::AppAttribution;
    let f = Fixture::new().await;
    let (db, a, b) = fixture(&f, PACKAGE).await;
    k::app_installs::remove_as(&db, &b, PACKAGE, "install-b")
        .await
        .unwrap();
    k::rehome_record_as(&db, &a, "secret", KERNEL_ROOT_ID)
        .await
        .unwrap();
    assert!(k::read_record_as(&db, &b, "secret")
        .await
        .unwrap()
        .is_some());
    let third_party = Caller::authenticated("account-b")
        .with_hosting_context("account-b", "hq-fixture")
        .with_hosting_owner(true);
    let err = call(
        &db,
        third_party,
        "update_record",
        update(
            NEW,
            &crate::mcp::tools::lifecycle::body_digest(Some(OLD)),
            "visible-not-owned",
        ),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("only the source artifact owner"),
        "{err}"
    );
    let app =
        owner().with_host_asserted_app(AppAttribution::new(PACKAGE, "0.4.0", "install").unwrap());
    let err = call(
        &db,
        app.clone(),
        "update_record",
        update(
            NEW,
            &crate::mcp::tools::lifecycle::body_digest(Some(OLD)),
            "app-publish",
        ),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("eligible workspace member"),
        "{err}"
    );
    let pin = staged_update(&db, &a).await;
    for args in [
        prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(NEW)),
        {
            let mut args = serde_json::to_value(&pin).unwrap();
            args["action"] = json!("install");
            args
        },
    ] {
        let err = call(
            &db,
            owner().with_hosting_owner(false).with_hosting_member(false),
            "manage_alpha_tabs",
            args.clone(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("eligible workspace member"),
            "{err}"
        );
        let err = call(&db, app.clone(), "manage_alpha_tabs", args)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("app_operation_refused"), "{err}");
    }
    db.close().await;
}

#[tokio::test]
async fn owner_app_update_adoption_rechecks_footing_removal_offboarding_and_latest_pending() {
    for change in ["footing", "removal", "offboarding", "newer-pending"] {
        let f = Fixture::new().await;
        let (db, a, b) = fixture(&f, PACKAGE).await;
        k::app_installs::remove_as(&db, &b, PACKAGE, "install-b")
            .await
            .unwrap();
        let pin = staged_update(&db, &a).await;
        let preview = native_app_hosted_caller("account-a", &pin, false).with_hosting_owner(true);
        let err = k::app_installs::preview_as(
            &db,
            &a,
            &preview
                .clone()
                .with_hosting_owner(false)
                .with_hosting_member(false),
            pin.clone(),
        )
        .await
        .err()
        .unwrap();
        assert!(
            err.to_string().contains("eligible workspace member"),
            "{err}"
        );
        let review = k::app_installs::preview_as(&db, &a, &preview, pin.clone())
            .await
            .unwrap();
        let mut adopting =
            native_app_hosted_caller("account-a", &pin, true).with_hosting_owner(true);
        match change {
            "footing" => {
                adopting = adopting
                    .with_hosting_owner(false)
                    .with_hosting_member(false)
            }
            "removal" => {
                k::app_installs::remove_as(&db, &a, PACKAGE, "install")
                    .await
                    .unwrap();
            }
            "offboarding" => app_roster(&db, "account-b", &["account-b"]).await,
            "newer-pending" => {
                let newer = NEW.replace("New generation", "Newer generation");
                call(
                    &db,
                    owner(),
                    "update_record",
                    update(
                        &newer,
                        &crate::mcp::tools::lifecycle::body_digest(Some(NEW)),
                        "publish-newer",
                    ),
                )
                .await
                .unwrap();
                let prepared = call(
                    &db,
                    owner(),
                    "manage_alpha_tabs",
                    prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(
                        &newer,
                    )),
                )
                .await
                .unwrap();
                k::app_installs::install_as(&db, &a, request(&prepared["next_call"]["arguments"]))
                    .await
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        let err = k::app_installs::adopt_as(
            &db,
            &a,
            &adopting,
            k::app_installs::AdoptRequest {
                scope: None,
                pin,
                receipt_id: review.receipt.receipt_id,
                nonce: review.receipt.nonce,
                preview_session: review.receipt.preview_session,
            },
        )
        .await
        .err()
        .unwrap();
        if change == "footing" {
            assert!(
                err.to_string().contains("eligible workspace member"),
                "{err}"
            );
        }
        assert_eq!(
            before,
            k::dump_all_kernel_tables(&db).await.unwrap(),
            "refused {change} adoption is atomic"
        );
        db.close().await;
    }
}

#[tokio::test]
async fn owner_app_historical_publication_replays_without_current_kit_or_catalogue_policy() {
    // Simulate a former custom package later entering the compiled catalogue,
    // and a kit version which the present binary no longer supplies. The host
    // evidence is built directly, as a previous publisher would have recorded.
    let f = Fixture::new().await;
    let (db, a, b) = fixture(&f, "agent.docs").await;
    k::app_installs::remove_as(&db, &b, "agent.docs", "install-b")
        .await
        .unwrap();
    let body=NEW.replace("</head>",r#"<script type="application/json" id="native-app-kit">{"schema":"native.app-kit.v1","major":65535}</script></head>"#);
    let html = crate::artifact_html::validate_cached_with_limit(
        &body,
        crate::artifact_html::PACKAGE_BODY_LIMIT,
    )
    .unwrap();
    assert!(html.require_available_kit().is_err());
    let mut tx = db.write_pool().begin().await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    let revision = crate::store::append_in(
        &db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: "secret".into(),
            event_type: "kernel.body_set.v1".into(),
            actor: Some(a.clone()),
            payload: json!({"body":body}),
        },
        &mut acts,
    )
    .await
    .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let attestation=crate::mcp::tools::artifacts::artifact_source_attestation_payload("secret",&id,&revision.id,&body,json!({"runtime":"native.html.v1","artifact_ports":html.artifact_ports,"imports":[],"module_inputs":{},"capability_requests":html.capability_requests,"interactions":html.interactions,"diagnostics":html.diagnostics})).unwrap();
    crate::store::append_with_event_id_on(
        &db,
        &mut tx,
        id,
        crate::store::AppendSpec {
            record_id: "secret".into(),
            event_type: k::app_installs::sources::PUBLISHED.into(),
            actor: Some(a),
            payload: json!({"format":1,"source_revision":revision.id,"attestation":attestation}),
        },
        &mut acts,
    )
    .await
    .unwrap();
    let historical = k::app_installs::sources::native_pin_on(
        &mut tx,
        &k::app_installs::InstallRequest {
            package: "agent.docs".into(),
            version: "0.5.0".into(),
            digest: String::new(),
            artifact_id: "secret".into(),
            source_revision: revision.id,
            declaration: json!({"contract":"native.app.v2","needs":[],"effects":[]}),
            reason: "Read historical source evidence".into(),
            request: None,
            idempotency_key: None,
            expected_install_event_id: None,
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(historical.1, body);
    db.commit_kernel_content(tx).await.unwrap();
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn owner_app_publication_refuses_closure_continuity_with_named_bindings() {
    assert_capability_closure_refused_after_publication(
        "bindings",
        json!([{"port_name":"items","collection_id":"private","event_seq":1}]),
    )
    .await;
}

#[tokio::test]
async fn owner_app_publication_refuses_closure_continuity_with_capability_grants() {
    assert_capability_closure_refused_after_publication("grants", json!([{"subject_kind":"artifact_source","subject_record_id":"secret","subject_event_id":"source","capability":"input.read","scope_sha256":"00".repeat(32),"scope":"{\"artifact_port\":\"items\"}"}])).await;
}

async fn assert_capability_closure_refused_after_publication(column: &str, evidence: Value) {
    let f = Fixture::new().await;
    let (db, a, b) = fixture(&f, PACKAGE).await;
    k::app_installs::remove_as(&db, &b, PACKAGE, "install-b")
        .await
        .unwrap();
    call(
        &db,
        owner(),
        "update_record",
        update(
            NEW,
            &crate::mcp::tools::lifecycle::body_digest(Some(OLD)),
            "publish-with-closure",
        ),
    )
    .await
    .unwrap();
    assert_eq!(render(&db).await["status"], "rendered");
    let invocation = json!({"version":"native.artifact-invocation.v1","artifact_id":"secret","entry_id":"unknown_entry",
        "source_digest":crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(OLD),"values":{},"idempotency_key":"closure-continuity"});
    let invoked = call(
        &db,
        gesture_caller(owner(), &invocation),
        "invoke_artifact_interaction",
        invocation.clone(),
    )
    .await
    .unwrap();
    assert_eq!(invoked["error"]["code"], "unknown_entry", "{invoked}");
    // As in the existing named-input renderer fixtures, substitute an already
    // verified projection to isolate delivery and interaction admission. Real
    // activation/grant verification is covered by the import suites.
    let sql = match column {
        "bindings" => "UPDATE kernel_artifact_closures SET bindings=? WHERE artifact_id='secret'",
        "grants" => "UPDATE kernel_artifact_closures SET grants=? WHERE artifact_id='secret'",
        _ => unreachable!(),
    };
    sqlx::query(sql)
        .bind(evidence.to_string())
        .execute(db.write_pool())
        .await
        .unwrap();
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let rendered = render(&db).await;
    assert_eq!(
        rendered["diagnostic"]["code"], "artifact_source_unavailable",
        "{column}: {rendered}"
    );
    let mut tx = db.write_pool().begin().await.unwrap();
    let err = crate::mcp::kernel_v2::artifacts::html_board::bundle_source_on(
        &mut tx,
        &a,
        "secret",
        &crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(OLD),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("frozen artifact source changed"),
        "{column}: {err}"
    );
    tx.rollback().await.unwrap();
    let invoked = call(
        &db,
        gesture_caller(owner(), &invocation),
        "invoke_artifact_interaction",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(
        invoked["error"]["code"], "artifact_source_unavailable",
        "{column}: {invoked}"
    );
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

async fn publish_catalog(db: &Db) {
    call(db,owner(),"manage_alpha_tabs",json!({"action":"publish_catalog_update","artifact_id":"secret","package":"agent.docs","version":"0.5.0","expected_body_digest":crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(OLD),"expected_install_event_id":"install","reason":"Publish host selected catalog bytes"})).await.unwrap();
}

#[tokio::test]
async fn catalog_update_offboarding_closes_staged_adoption_and_replays() {
    let f = Fixture::new().await;
    let (db, a, b) = fixture(&f, "agent.docs").await;
    k::app_installs::remove_as(&db, &b, "agent.docs", "install-b")
        .await
        .unwrap();
    publish_catalog(&db).await;
    let mut args = prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(NEW));
    args["package"] = json!("agent.docs");
    let prepared = call(&db, owner(), "manage_alpha_tabs", args).await.unwrap();
    let mut pin = request(&prepared["next_call"]["arguments"]);
    let staged = k::app_installs::install_for_user_as(&db, &a, pin.clone())
        .await
        .unwrap();
    pin.expected_install_event_id = Some(staged.outcome.generation);
    let review = k::app_installs::preview_as(
        &db,
        &a,
        &native_app_hosted_caller("account-a", &pin, false).with_hosting_owner(true),
        pin.clone(),
    )
    .await
    .unwrap();
    app_roster(&db, "account-b", &["account-b"]).await;
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let err = k::app_installs::adopt_as(
        &db,
        &a,
        &native_app_hosted_caller("account-a", &pin, true).with_hosting_owner(true),
        k::app_installs::AdoptRequest {
            scope: None,
            pin,
            receipt_id: review.receipt.receipt_id,
            nonce: review.receipt.nonce,
            preview_session: review.receipt.preview_session,
        },
    )
    .await;
    assert!(err.is_err());
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

// Start a real v2 adoption root. The imported fixture deliberately has no
// provenance, so its verified legacy label alone must not qualify for carry.
async fn adopt_carry_root(db: &Db, a: &str) -> String {
    let pins = k::app_installs::frozen_sources_as(db, a).await.unwrap();
    let old = pins
        .iter()
        .find(|p| p["source_revision"] == "source")
        .unwrap();
    let pin = k::app_installs::InstallRequest {
        package: PACKAGE.into(),
        version: "0.4.0".into(),
        digest: old["digest"].as_str().unwrap().into(),
        artifact_id: "secret".into(),
        source_revision: "source".into(),
        declaration: serde_json::from_str(old["consented_declaration"].as_str().unwrap()).unwrap(),
        reason: "Establish a verified v2 adoption root".into(),
        request: None,
        idempotency_key: None,
        expected_install_event_id: Some("install".into()),
    };
    let preview = native_app_hosted_caller("account-a", &pin, false).with_hosting_owner(true);
    let review = k::app_installs::preview_as(db, a, &preview, pin.clone())
        .await
        .unwrap();
    k::app_installs::adopt_as(
        db,
        a,
        &native_app_hosted_caller("account-a", &pin, true).with_hosting_owner(true),
        k::app_installs::AdoptRequest {
            scope: None,
            pin,
            receipt_id: review.receipt.receipt_id,
            nonce: review.receipt.nonce,
            preview_session: review.receipt.preview_session,
        },
    )
    .await
    .unwrap()
    .outcome
    .generation
}

async fn publish_carry_update(
    db: &Db,
    body: &str,
    previous: &str,
    version: &str,
    declaration: Value,
) -> Value {
    call(
        db,
        owner(),
        "update_record",
        update(
            body,
            &crate::mcp::tools::lifecycle::body_digest(Some(previous)),
            version,
        ),
    )
    .await
    .unwrap();
    let mut args = prepare(&crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(
        body,
    ));
    args["version"] = json!(version);
    args["declaration"] = declaration;
    let prepared = call(db, owner(), "manage_alpha_tabs", args).await.unwrap();
    assert_eq!(prepared["ready"], true, "{prepared}");
    prepared["next_call"]["arguments"].clone()
}

#[tokio::test]
async fn owner_app_unchanged_permissions_carry_adoption_chain_and_recover() {
    let f = Fixture::new().await;
    let (db, a, b) = fixture(&f, PACKAGE).await;
    k::app_installs::remove_as(&db, &b, PACKAGE, "install-b")
        .await
        .unwrap();
    let root = adopt_carry_root(&db, &a).await;
    let scope = json!({"kind":"folders","folder_ids":["private"]});
    call(
        &db,
        owner(),
        "manage_alpha_tabs",
        json!({"action":"set_scope","package":PACKAGE,"scope":scope}),
    )
    .await
    .unwrap();
    let declaration = json!({"effects":[],"needs":[],"contract":"native.app.v2"});
    let install = publish_carry_update(&db, NEW, OLD, "0.5.0", declaration.clone()).await;
    let carried = call(&db, owner(), "manage_alpha_tabs", install.clone())
        .await
        .unwrap();
    let generation = carried["install"]["event_id"].as_str().unwrap().to_owned();
    assert_eq!(carried["install"]["adoption"], "shell_adopt.v1");
    assert_eq!(carried["install"]["adoption_basis"], "carried");
    assert_eq!(carried["install"]["scope"], scope);
    assert_eq!(
        carried["install"]["adoption_provenance"]["carried_from_event_id"],
        root
    );
    assert_eq!(
        carried["install"]["adoption_provenance"]["original_adoption_event_id"],
        root
    );
    assert_eq!(
        carried["install"]["adoption_provenance"]["reviewed_source_revision"],
        "source"
    );
    assert_ne!(carried["install"]["consented_source_revision"], "source");
    let inspected = k::app_installs::inspect_as(&db, &a, PACKAGE).await.unwrap();
    assert!(inspected["pending_update"].is_null());
    assert_eq!(inspected["install"]["event_id"], generation);
    let caller =
        native_app_hosted_caller("account-a", &request(&install), false).with_hosting_owner(true);
    let mut tx = db.write_pool().begin().await.unwrap();
    assert_eq!(
        k::app_installs::launch_source_on(&mut tx, &a, &caller, PACKAGE, &generation)
            .await
            .unwrap()
            .body,
        NEW
    );
    assert!(
        k::app_installs::admit_install_on(&mut tx, &a, PACKAGE, &root)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let retry = call(&db, owner(), "manage_alpha_tabs", install.clone())
        .await
        .unwrap();
    assert_eq!(retry["changed"], false);
    assert_eq!(retry["install"]["event_id"], generation);

    // A second update preserves the original review, while linking the
    // immediate predecessor. No receipt ever certifies the new bytes.
    let newer = NEW.replace("New generation", "Next generation");
    let next = publish_carry_update(&db, &newer, NEW, "0.5.1", declaration).await;
    let second = call(&db, owner(), "manage_alpha_tabs", next).await.unwrap();
    assert_eq!(second["install"]["scope"], scope);
    let provenance = &second["install"]["adoption_provenance"];
    assert_eq!(provenance["original_adoption_event_id"], root);
    assert_eq!(provenance["carried_from_event_id"], generation);
    assert_eq!(provenance["reviewed_source_revision"], "source");
    assert!(call(&db, owner(), "manage_alpha_tabs", install)
        .await
        .is_err());
    let projected = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&db).await.unwrap());
    sqlx::query("DROP TABLE kernel_app_installs; DROP TABLE kernel_app_consent_revocations; DROP TABLE kernel_app_package_sources; DROP TABLE kernel_app_install_outcomes")
        .execute(db.write_pool()).await.unwrap();
    let mut tx = db.write_pool().begin().await.unwrap();
    k::app_installs::ensure_schema(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn owner_app_changed_permissions_stay_pending_until_explicit_adoption() {
    let f = Fixture::new().await;
    let (db, a, b) = fixture(&f, PACKAGE).await;
    k::app_installs::remove_as(&db, &b, PACKAGE, "install-b")
        .await
        .unwrap();
    let root = adopt_carry_root(&db, &a).await;
    let declaration = json!({"needs":["records.search.v1"],"effects":[]});
    let install = publish_carry_update(&db, NEW, OLD, "0.5.0", declaration).await;
    let staged = call(&db, owner(), "manage_alpha_tabs", install.clone())
        .await
        .unwrap();
    assert_eq!(staged["install"]["pending_update"], true);
    assert_eq!(staged["install"]["adoption_basis"], "requires_adoption");
    let mut pin = request(&install);
    pin.expected_install_event_id = Some(staged["install"]["event_id"].as_str().unwrap().into());
    let caller = native_app_hosted_caller("account-a", &pin, false).with_hosting_owner(true);
    let mut tx = db.write_pool().begin().await.unwrap();
    assert_eq!(
        k::app_installs::launch_source_on(&mut tx, &a, &caller, PACKAGE, &root)
            .await
            .unwrap()
            .body,
        OLD
    );
    assert!(k::app_installs::admit_install_on(
        &mut tx,
        &a,
        PACKAGE,
        pin.expected_install_event_id.as_ref().unwrap()
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    let review = k::app_installs::preview_as(&db, &a, &caller, pin.clone())
        .await
        .unwrap();
    let adopted = k::app_installs::adopt_as(
        &db,
        &a,
        &native_app_hosted_caller("account-a", &pin, true).with_hosting_owner(true),
        k::app_installs::AdoptRequest {
            scope: None,
            pin,
            receipt_id: review.receipt.receipt_id,
            nonce: review.receipt.nonce,
            preview_session: review.receipt.preview_session,
        },
    )
    .await
    .unwrap();
    assert_eq!(adopted.install["adoption_basis"], "direct");
    let projected = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn owner_app_carry_refuses_ineligible_predecessor_and_historical_staging_is_stable() {
    for boundary in [
        "legacy",
        "revoked",
        "unverified",
        "provenance",
        "source",
        "historical",
    ] {
        let f = Fixture::new().await;
        let (db, a, b) = fixture(&f, PACKAGE).await;
        k::app_installs::remove_as(&db, &b, PACKAGE, "install-b")
            .await
            .unwrap();
        let root = if boundary == "legacy" {
            "install".into()
        } else {
            adopt_carry_root(&db, &a).await
        };
        let install = publish_carry_update(
            &db,
            NEW,
            OLD,
            "0.5.0",
            json!({"contract":"native.app.v2","needs":[],"effects":[]}),
        )
        .await;
        let mut tx = db.write_pool().begin().await.unwrap();
        // Projection corruption is deliberately transactional: none of these
        // unsupported mutations enter canonical history or survive rollback.
        match boundary {
            "revoked" => {
                sqlx::query("UPDATE kernel_app_installs SET row_json=json_set(row_json,'$.consent_revocation_seq',-1) WHERE principal=?").bind(&a).execute(&mut *tx).await.unwrap();
            }
            "unverified" => {
                sqlx::query("UPDATE kernel_app_installs SET executable=0,refusal='adoption_required' WHERE principal=?").bind(&a).execute(&mut *tx).await.unwrap();
            }
            "provenance" => {
                sqlx::query("UPDATE kernel_app_installs SET row_json=json_set(row_json,'$.adoption_provenance',NULL) WHERE principal=?").bind(&a).execute(&mut *tx).await.unwrap();
            }
            "source" => {
                sqlx::query("UPDATE kernel_app_installs SET row_json=json_set(row_json,'$.digest','invalid') WHERE principal=?").bind(&a).execute(&mut *tx).await.unwrap();
            }
            _ => (),
        }
        let mut pin = request(&install);
        let key = format!("boundary-{boundary}");
        pin.idempotency_key = None;
        let actor = a.clone();
        let source_seq: i64 = sqlx::query_scalar("SELECT seq FROM content_events WHERE type='kernel.app_source_published.v1' ORDER BY seq DESC LIMIT 1").fetch_one(&mut *tx).await.unwrap();
        let aggregate = format!(
            "kernel:app-installs:{}",
            uuid::Uuid::new_v5(
                &uuid::Uuid::NAMESPACE_OID,
                &serde_json::to_vec(&(&a, PACKAGE)).unwrap()
            )
        );
        crate::store::append_in(&db, &mut tx, crate::store::AppendSpec {
            record_id: aggregate,
            event_type: "kernel.app_install_recorded.v1".into(), actor: Some(actor),
            payload: json!({"format":if boundary == "historical" {2} else {3},"key":key,"request":pin,
                "source_event_seq":source_seq,"revocation_seq":0}),
        }, &mut crate::act::ActAllocation::new()).await.unwrap();
        let active: String = sqlx::query_scalar(
            "SELECT generation FROM kernel_app_installs WHERE principal=? AND package=?",
        )
        .bind(&a)
        .bind(PACKAGE)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(active, root, "{boundary} must not confer carry");
        if boundary == "historical" {
            tx.commit().await.unwrap();
            let projected = k::dump_all_kernel_tables(&db).await.unwrap();
            k::replay_all_projections(&db).await.unwrap();
            assert_eq!(projected, k::dump_all_kernel_tables(&db).await.unwrap());
            let inspected = k::app_installs::inspect_as(&db, &a, PACKAGE).await.unwrap();
            assert_eq!(inspected["install"]["event_id"], root);
            assert_eq!(
                inspected["pending_update"]["adoption_basis"],
                "requires_adoption"
            );
        } else {
            tx.rollback().await.unwrap();
        }
        db.close().await;
    }
}

#[path = "owner_updates/materialized_updates.rs"]
mod materialized_updates;
#[path = "owner_updates/shelf.rs"]
mod shelf;
#[path = "owner_updates/shelf_enable.rs"]
mod shelf_enable;
#[path = "owner_updates/shelf_fresh.rs"]
mod shelf_fresh;
#[path = "owner_updates/shelf_updates.rs"]
mod shelf_updates;
