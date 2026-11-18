use super::*;
use crate::mcp::{kernel_v2::NativeAppDataNeeds, Caller};
use crate::realtime::v2::{AppDataNeeds, AppDataRequest};

fn sql_need(key: &str, sql: &str) -> Value {
    json!({"need":"sql.snapshot.v1","key":key,"label":"Synthetic rows","sql":sql})
}
fn declaration() -> Value {
    let mut page = sql_need(
        "notion.page",
        "SELECT id,name,type,kind,body FROM records WHERE id=?1 ORDER BY id LIMIT 1",
    );
    page["params"] = json!([{"name":"record_id","type":"text","max_len":128,"required":true}]);
    json!({"needs":[sql_need("notion.recent","SELECT id,name FROM records WHERE id='note' ORDER BY id"),page,"records.search.v1"],
        "effects":[{"effect":"records.title-set.v1","target":{"need":"notion.recent"}},
            {"effect":"records.body-set.v1","target":{"need":"notion.page"},"max_body_bytes":32}]})
}
fn source_body() -> String {
    let manifest = json!({"schema":"native.html.artifact.v2","inputs":{"items":{"envelope":"native.collection-envelope.v1","required":true,"expose_to_root":true}},
        "capability_requests":[{"capability":"input.read","scope":{"port":"items"}}],
        "interactions":[{"id":"rename","label":"Rename","effect":"title.set","slots":{"record":{"domain":{"kind":"bound_input","port":"items"}}},"title":{}},
            {"id":"save","label":"Save","effect":"body.set","slots":{"record":{"domain":{"kind":"bound_input","port":"items"}}},"body":{"max_bytes":64}}]});
    OPERATOR_APP_BODY.replace("</head>",&format!("<script type=\"application/json\" id=\"native-artifact-manifest\">{manifest}</script></head>"))
}
async fn proof(db: &Db) -> k::app_installs::VerifiedFrozenApps {
    let raw:String=sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1").fetch_one(db.pool()).await.unwrap();
    let seq: i64 =
        sqlx::query_scalar("SELECT event_seq FROM kernel_app_state WHERE record_id='secret'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    // SAFETY: this test owns a frozen synthetic import and unpublished target.
    unsafe {
        k::app_installs::VerifiedFrozenApps::from_verified_declarative_import_unchecked(
            serde_json::from_str(&raw).unwrap(),
            "ab".repeat(32),
            BTreeMap::from([("secret".into(), seq)]),
        )
    }
}
pub(super) async fn fixture(declaration: &Value) -> (Fixture, Db, super::super::super::Report) {
    fixture_with(declaration, None, 5).await
}
async fn fixture_with(
    declaration: &Value,
    change: Option<(&str, &str)>,
    format: u32,
) -> (Fixture, Db, super::super::super::Report) {
    fixture_with_extra_installs(declaration, change, format, 0).await
}

async fn fixture_with_extra_installs(
    declaration: &Value,
    change: Option<(&str, &str)>,
    format: u32,
    extra_installs: usize,
) -> (Fixture, Db, super::super::super::Report) {
    let f = Fixture::new().await;
    let body = if extra_installs == 0 {
        source_body()
    } else {
        source_body().replace(
            "</body>",
            &format!("<!--{}--></body>", "synthetic".repeat(16_384)),
        )
    };
    // Future/unknown declaration shapes need not be understood by v1's current
    // digest helper. Seed retained witnesses, then preserve the unknown shape
    // for the format-5 exclusion test; it must refuse before treating a pin as
    // executable authority.
    let seed_declaration = if k::app_installs::declarations::source_supported(declaration) {
        declaration.clone()
    } else {
        self::declaration()
    };
    native_install_declared_source(
        &f,
        &body,
        "agent.notion-pages",
        "999.42.0",
        &seed_declaration,
    )
    .await;
    let html = crate::artifact_html::validate(&body).unwrap();
    let compiler = json!({"runtime":"native.html.v1","artifact_ports":html.artifact_ports,"imports":[],"module_inputs":{},"capability_requests":html.capability_requests,"interactions":html.interactions,"diagnostics":html.diagnostics});
    let attested = crate::mcp::tools::artifacts::artifact_source_attestation_payload(
        "secret",
        "attestation",
        "source",
        &body,
        compiler,
    )
    .unwrap();
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("DELETE FROM alpha_tab_installs WHERE account_id='account-c'; ALTER TABLE artifact_source_attestations ADD COLUMN source_sha256 TEXT; ALTER TABLE artifact_source_attestations ADD COLUMN attestation_sha256 TEXT; ALTER TABLE artifact_source_attestations ADD COLUMN event_seq INTEGER; ALTER TABLE artifact_source_attestations ADD COLUMN created_at TEXT;").await.unwrap();
    if seed_declaration != *declaration {
        sqlx::query("UPDATE alpha_tab_installs SET consented_declaration=?")
            .bind(declaration.to_string())
            .execute(&mut source)
            .await
            .unwrap();
        sqlx::query("UPDATE control_events SET payload=json_set(payload,'$.consented_declaration',json(?)) WHERE type='alpha_tab.adopted'")
            .bind(declaration.to_string()).execute(&mut source).await.unwrap();
    }
    // Source first, attestation next: the imported closure is checked using
    // the same event witnesses as operator activate-artifacts.
    source
        .execute("DELETE FROM content_events WHERE id='attestation'")
        .await
        .unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('attestation','secret','artifact.source_attested',?,'account-a','2026-02-02T00:00:00Z')").bind(serde_json::to_string(&attested).unwrap()).execute(&mut source).await.unwrap();
    let attestation_seq: i64 =
        sqlx::query_scalar("SELECT seq FROM content_events WHERE id='attestation'")
            .fetch_one(&mut source)
            .await
            .unwrap();
    let sha = native_artifact_runtime::mdx::sha256_hex(body.as_bytes());
    sqlx::query("UPDATE artifact_source_attestations SET descriptor=?,source_sha256=?,attestation_sha256=?,event_seq=?,created_at='2026-02-02T00:00:00Z'").bind(serde_json::to_string(&attested.artifact_source).unwrap()).bind(&sha).bind(&attested.attestation_sha256).bind(attestation_seq).execute(&mut source).await.unwrap();
    source.execute("ALTER TABLE artifact_inputs ADD COLUMN artifact_source_attestation_event_id TEXT; ALTER TABLE artifact_inputs ADD COLUMN artifact_source_event_id TEXT; ALTER TABLE artifact_inputs ADD COLUMN artifact_source_sha256 TEXT; ALTER TABLE artifact_inputs ADD COLUMN event_seq INTEGER;").await.unwrap();
    let binding = json!({"artifact_id":"secret","port_name":"items","collection_id":"private","artifact_source_attestation_event_id":"attestation","artifact_source_event_id":"source","artifact_source_sha256":sha});
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('input','secret','artifact.input_bound',?,'account-a','2026-02-02T00:00:00Z')").bind(binding.to_string()).execute(&mut source).await.unwrap();
    let binding_seq: i64 = sqlx::query_scalar("SELECT seq FROM content_events WHERE id='input'")
        .fetch_one(&mut source)
        .await
        .unwrap();
    sqlx::query("UPDATE artifact_inputs SET artifact_source_attestation_event_id='attestation',artifact_source_event_id='source',artifact_source_sha256=?,event_seq=?").bind(&sha).bind(binding_seq).execute(&mut source).await.unwrap();
    source.execute("ALTER TABLE artifact_module_grants ADD COLUMN artifact_source_attestation_event_id TEXT; ALTER TABLE artifact_module_grants ADD COLUMN artifact_source_event_id TEXT; ALTER TABLE artifact_module_grants ADD COLUMN artifact_source_sha256 TEXT; ALTER TABLE artifact_module_grants ADD COLUMN source_sha256 TEXT; ALTER TABLE artifact_module_grants ADD COLUMN event_seq INTEGER; ALTER TABLE artifact_module_grants ADD COLUMN scope TEXT;").await.unwrap();
    let scope = json!({"artifact_port":"items"});
    let scope_sha = native_artifact_runtime::mdx::sha256_hex(
        &native_artifact_runtime::mdx_v2::canonical_json_bytes(&scope),
    );
    let grant = json!({"artifact_id":"secret","subject_kind":"artifact_source","subject_record_id":"secret","subject_event_id":"source","source_sha256":sha,"capability":"input.read","scope_sha256":scope_sha,"scope":scope,"attestation":{"artifact_source_attestation_event_id":"attestation","artifact_source_event_id":"source","artifact_source_sha256":sha}});
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('grant','secret','artifact.module_grant_set',?,'account-a','2026-02-02T00:00:00Z')").bind(grant.to_string()).execute(&mut source).await.unwrap();
    let grant_seq: i64 = sqlx::query_scalar("SELECT seq FROM content_events WHERE id='grant'")
        .fetch_one(&mut source)
        .await
        .unwrap();
    sqlx::query("INSERT INTO artifact_module_grants VALUES('secret','artifact_source','secret','source','input.read',?,'attestation','source',?,?,?,?)").bind(scope_sha).bind(&sha).bind(&sha).bind(grant_seq).bind(scope.to_string()).execute(&mut source).await.unwrap();
    if let Some((field, value)) = change {
        let (field, scope) = match field.strip_prefix("all:") {
            Some(field) => (field, ""),
            None => (field, " WHERE account_id='account-a'"),
        };
        assert!(matches!(field, "status" | "adoption" | "digest"));
        sqlx::query(&format!("UPDATE alpha_tab_installs SET {field}=?{scope}"))
            .bind(value)
            .execute(&mut source)
            .await
            .unwrap();
    }
    // Independent package pins share synthetic source bytes. Roadmap belongs
    // only to A, so B exercises v1's shared-source reinstall behavior.
    for index in 0..extra_installs {
        let package = match index {
            0 => "agent.docs".to_owned(),
            1 => "agent.roadmap-base".to_owned(),
            _ => format!("agent.synthetic-{index}"),
        };
        let declared = if index == 0 {
            json!({"contract":"native.app.v2","needs":[],"effects":[]})
        } else {
            self::declaration()
        };
        let declaration_digest =
            crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&declared).unwrap();
        let digest = crate::mcp::tools::alpha_tabs::alpha_tab_digest(
            &crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(&body),
            &declaration_digest,
            "native.html.v1",
        );
        for account in ["account-a", "account-b"] {
            if index == 1 && account == "account-b" {
                continue;
            }
            let event_id = format!("extra-install-{index}-{account}");
            sqlx::query("INSERT INTO alpha_tab_installs(artifact_id,account_id,package,consented_source_revision,event_id,status,adoption,version,digest,declaration_digest,consented_declaration) VALUES('secret',?,?,'source',?,'installed','shell_adopt.v1','999.42.0',?,?,?)")
                .bind(account).bind(&package).bind(&event_id).bind(&digest).bind(&declaration_digest).bind(declared.to_string()).execute(&mut source).await.unwrap();
            let evidence = json!({"account_id":account,"package":package,"version":"999.42.0","digest":digest,"artifact_id":"secret","consented_source_revision":"source","declaration_digest":declaration_digest,"consented_declaration":declared,"adoption":"shell_adopt.v1"});
            sqlx::query("INSERT INTO control_events(id,subject_id,type,payload,actor,created_at) VALUES(?,?,'alpha_tab.adopted',?,?,'2026-01-01T00:00:00Z')")
                .bind(event_id).bind(account).bind(evidence.to_string()).bind(account).execute(&mut source).await.unwrap();
        }
    }
    // Both data operands are under the private folder; every fact is synthetic.
    source.execute("UPDATE records SET home_id='private',policy_anchor_id='private',body='Before' WHERE id='note'; UPDATE content_events SET payload='{\"body\":\"Before\"}' WHERE id='created:note';").await.unwrap();
    source.close().await.unwrap();
    let mut options = f.options(&["secret", "note"], false);
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
    let raw:String=sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1").fetch_one(db.pool()).await.unwrap();
    let seq: i64 =
        sqlx::query_scalar("SELECT event_seq FROM kernel_app_state WHERE record_id='secret'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    // SAFETY: fixture owns the verified source closure and frozen target.
    let closure = unsafe {
        k::artifact_closures::VerifiedArtifactClosure::from_verified_import_unchecked(
            serde_json::from_str(&raw).unwrap(),
            "ab".repeat(32),
            "secret".into(),
            seq,
        )
    };
    k::artifact_closures::activate_as(&db, &host, closure)
        .await
        .unwrap();
    k::app_installs::activate_as(
        &db,
        &host,
        if format == 4 {
            operator_app_proof(&db).await
        } else {
            assert_eq!(format, 5);
            proof(&db).await
        },
    )
    .await
    .unwrap();
    (f, db, report)
}
fn request() -> AppDataRequest {
    AppDataRequest {
        package: "agent.notion-pages".into(),
        expected_install_event_id: "install".into(),
        need: None,
        params: json!({}),
    }
}

#[tokio::test]
async fn declarative_sql_prism_installed_single_and_batch_reads_match() {
    let needs: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/kernel_v2_prism_reads.json"
    ))
    .unwrap();
    let (_f, db, report) = fixture(&json!({"needs":needs,"effects":[]})).await;
    let actor = &report.principals["account-a"];
    let home = k::read_record_as(&db, actor, "note")
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let task = ordinary_kernel_call(&db,"account-a","create_record",json!({
        "type":"WorkItem","kind":"task","name":"Prism fixture task","body":"Small selected body","home_id":home
    })).await.unwrap()["id"].as_str().unwrap().to_owned();
    ordinary_kernel_call(&db,"account-a","create_record",json!({
        "type":"WorkItem","kind":"task","name":"Unrelated large task",
        "body":"x".repeat(crate::query::sql::MAX_SQLITE_VALUE_BYTES as usize+4096),"home_id":home
    })).await.unwrap();
    for projected in [false, true] {
        if projected {
            k::sql_record_projection::catch_up(&db).await.unwrap();
            k::sql_event_projection::catch_up(&db).await.unwrap();
        }
        let caller = Caller::authenticated("account-a");
        let mut reads = Vec::new();
        let mut expected = Vec::new();
        for need in needs.as_array().unwrap() {
            let snapshot = need["key"] == "prism.records";
            let params = if snapshot {
                json!({})
            } else {
                json!({"id":task})
            };
            let request = AppDataRequest {
                need: if snapshot {
                    None
                } else {
                    Some(need["key"].as_str().unwrap().into())
                },
                params: params.clone(),
                ..request()
            };
            let result = NativeAppDataNeeds
                .evaluate(&db, &caller, &request)
                .await
                .unwrap_or_else(|e| panic!("{} projected={projected}: {e}", need["key"]))
                .result;
            if need["key"] == "prism.body" {
                assert_eq!(result["result"]["rows"][0]["body"], "Small selected body");
            }
            reads.push(if snapshot {
                json!({"need":"attention.query.v1"})
            } else {
                json!({"need":need["key"],"params":params})
            });
            expected.push(result);
        }
        let batch=ordinary_kernel_call(&db,"account-a","manage_alpha_tabs",json!({"action":"live_read","package":"agent.notion-pages","expected_install_event_id":"install","reads":reads})).await.unwrap();
        for (index, single) in expected.iter().enumerate() {
            let actual = &batch["results"][index]["ok"];
            assert!(
                actual.is_object(),
                "{}: {}",
                needs[index]["key"],
                batch["results"][index]
            );
            if index == 0 {
                assert_eq!(actual, single);
            } else {
                assert_eq!(
                    actual["result"]["rows"], single["result"]["rows"],
                    "{} projected={projected}",
                    needs[index]["key"]
                );
                assert_eq!(actual["result"]["columns"], single["result"]["columns"]);
            }
        }
    }
    db.close().await;
}

#[tokio::test]
async fn declarative_launch_is_sample_only_before_separate_live_read() {
    let (_f, db, _) = fixture(&declaration()).await;
    let (db, hub) = crate::realtime::RealtimeHub::attach(db, None)
        .await
        .unwrap();
    hub.set_app_data_needs(std::sync::Arc::new(NativeAppDataNeeds));
    let caller = Caller::authenticated("account-a").with_hosting_context("account-a", "fixture");
    // SAFETY: this fixture owns the synthetic same-origin cookie session.
    let caller =
        unsafe { caller.with_verified_hosting_session("11111111-1111-4111-8111-111111111111") };
    let mut registry = crate::mcp::ToolRegistry::new();
    registry.set_app_bundle_delivery(Some(crate::mcp::tools::alpha_tabs::AppBundleDelivery {
        enabled: true,
        runtime: crate::artifact_html::RuntimeConfig::new(
            "http://localhost", "https://artifact.declarative.test",
        ).unwrap(),
        keyring: Some(std::sync::Arc::new(
            native_artifact_runtime::deployment_keyring::DeploymentKeyring::from_json_bundle(
                r#"{"active_key_id":"synthetic","keys":[{"id":"synthetic","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}"#,
            ).unwrap(),
        )),
    }));
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let launch = registry
        .call_engine(
            crate::mcp::EngineHandle::KernelV2(db.clone()),
            caller.clone(),
            "manage_alpha_tabs",
            json!({"action":"launch","package":"agent.notion-pages",
            "expected_install_event_id":"install","delivery":"reusable.v1"}),
        )
        .await
        .unwrap();
    assert_eq!(launch["launch"]["kind"], "reusable.v1");
    assert_eq!(launch["input"]["mode"], "sample");
    assert_eq!(launch["input"]["sample_preview"], true);
    // The shell rejects sample launches marked live, including declarations
    // without a native.app.v2 contract marker (as used by installed Prism).
    assert_eq!(launch["live_reads"], false);
    assert_eq!(launch["effects_wired"], false);
    let read = registry
        .call_engine(
            crate::mcp::EngineHandle::KernelV2(db.clone()),
            caller,
            "manage_alpha_tabs",
            json!({"action":"live_read","package":"agent.notion-pages",
            "expected_install_event_id":"install"}),
        )
        .await
        .unwrap();
    assert_eq!(read["live_reads"], true);
    // The shipping launcher requires the same snapshot mapping as v1,
    // even when all consented reads are SQL needs rather than Attention.
    assert_eq!(
        read["declared_port"],
        crate::mcp::tools::alpha_tabs::alpha_tab_attention_port_mapping()
    );
    assert_eq!(
        read["input"]["sql"]["notion.recent"]["rows"][0]["id"],
        "note"
    );
    db.close().await;
}

#[tokio::test]
async fn declarative_sql_snapshot_params_search_visibility_and_revocation() {
    let (_f, db, report) = fixture(&declaration()).await;
    let caller = Caller::authenticated("account-a");
    let evaluator = NativeAppDataNeeds;
    let req = request();
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let snapshot = evaluator.evaluate(&db, &caller, &req).await.unwrap();
    assert_eq!(
        snapshot.result["input"]["sql"]["notion.recent"]["rows"][0]["id"],
        "note"
    );
    assert!(snapshot.result["input"]["sql"].get("notion.page").is_none());
    assert_eq!(
        snapshot.gate,
        evaluator.revalidate(&db, &caller, &req).await.unwrap()
    );
    let page = AppDataRequest {
        need: Some("notion.page".into()),
        params: json!({"record_id":"note"}),
        ..req.clone()
    };
    let read = evaluator.evaluate(&db, &caller, &page).await.unwrap();
    assert_eq!(read.result["result"]["rows"][0]["body"], "Before");
    assert!(read.result["result"].get("as_of_seq").is_none());
    for params in [
        json!({}),
        json!({"record_id":7}),
        json!({"record_id":"note","sql":"SELECT * FROM main.kernel_records"}),
        json!({"record_id":"x".repeat(129)}),
    ] {
        assert!(evaluator
            .evaluate(
                &db,
                &caller,
                &AppDataRequest {
                    params,
                    ..page.clone()
                }
            )
            .await
            .is_err());
    }
    let search = AppDataRequest {
        need: Some("records.search.v1".into()),
        params: json!({"query":"Before","limit":10}),
        ..req.clone()
    };
    let found = evaluator.evaluate(&db, &caller, &search).await.unwrap();
    assert!(found.result["result"]["hits"]
        .as_array()
        .unwrap()
        .iter()
        .any(|hit| hit["id"] == "note"));
    assert_eq!(
        before,
        k::dump_all_kernel_tables(&db).await.unwrap(),
        "reads are read only"
    );
    // This installed identity gets its declared surface, never Class 1's
    // broad app-host claim for arbitrary ordinary tools.
    let claim = crate::mcp::app_attribution::AppAttribution::new(
        "agent.notion-pages",
        "999.42.0",
        "install",
    )
    .unwrap();
    assert!(
        k::app_installs::admit_account_app_as(&db, "account-a", &claim)
            .await
            .is_err()
    );
    let a = &report.principals["account-a"];
    let b = &report.principals["account-b"];
    k::replace_home_policy(
        &db,
        a,
        &k::hq::v1_import_home_id("private"),
        &[(a, "manage"), (b, "view")],
    )
    .await
    .unwrap();
    let b_req = AppDataRequest {
        expected_install_event_id: "install-b".into(),
        ..page.clone()
    };
    assert_eq!(
        evaluator
            .evaluate(&db, &Caller::authenticated("account-b"), &b_req)
            .await
            .unwrap()
            .result["result"]["rows"][0]["id"],
        "note"
    );
    k::replace_home_policy(
        &db,
        a,
        &k::hq::v1_import_home_id("private"),
        &[(a, "manage")],
    )
    .await
    .unwrap();
    assert!(
        evaluator
            .evaluate(&db, &Caller::authenticated("account-b"), &b_req)
            .await
            .is_err(),
        "source visibility is rechecked"
    );
    let fresh = evaluator.revalidate(&db, &caller, &req).await.unwrap();
    assert_ne!(
        fresh, snapshot.gate,
        "policy epoch fences a revoke/regrant cycle"
    );
    k::app_installs::remove_as(&db, a, "agent.notion-pages", "install")
        .await
        .unwrap();
    assert!(evaluator.evaluate(&db, &caller, &page).await.is_err());
    assert!(evaluator.revalidate(&db, &caller, &req).await.is_err());
    let projected = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn declarative_sql_shell_batches_preserve_single_results_item_errors_and_authority() {
    let (_f, db, report) = fixture(&declaration()).await;
    let args = json!({"action":"live_read","package":"agent.notion-pages","expected_install_event_id":"install",
        "reads":[{"need":"notion.page","params":{"record_id":"note"}},
            {"need":"records.search.v1","params":{"query":"Before","limit":10}},
            {"need":"notion.page","params":{"record_id":3}},
            {"need":"unknown.need"},
            {"need":"attention.query.v1"}]});
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let batch = ordinary_kernel_call(&db, "account-a", "manage_alpha_tabs", args.clone())
        .await
        .unwrap();
    assert_eq!(batch["results"].as_array().unwrap().len(), 5);
    for index in [0, 1, 4] {
        let item = &args["reads"][index];
        let single = NativeAppDataNeeds
            .evaluate(
                &db,
                &Caller::authenticated("account-a"),
                &AppDataRequest {
                    need: (index != 4).then(|| item["need"].as_str().unwrap().to_owned()),
                    params: item.get("params").cloned().unwrap_or_else(|| json!({})),
                    ..request()
                },
            )
            .await
            .unwrap();
        assert_eq!(batch["results"][index]["ok"], single.result);
        assert_eq!(batch["pin"], single.result["pin"]);
        assert_eq!(batch["source"], single.result["source"]);
    }
    assert_eq!(batch["results"][2]["error"]["code"], "invalid_sql_param");
    assert_eq!(batch["results"][3]["error"]["code"], "undeclared_need");
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    for reads in [json!([]), json!(vec![json!({"need":"notion.page"}); 17])] {
        let mut invalid = args.clone();
        invalid["reads"] = reads;
        assert!(
            ordinary_kernel_call(&db, "account-a", "manage_alpha_tabs", invalid)
                .await
                .unwrap_err()
                .to_string()
                .contains("[invalid_params]")
        );
    }
    let mut mixed = args.clone();
    mixed["need"] = json!("notion.page");
    assert!(
        ordinary_kernel_call(&db, "account-a", "manage_alpha_tabs", mixed)
            .await
            .unwrap_err()
            .to_string()
            .contains("[invalid_params]")
    );
    k::app_installs::remove_as(
        &db,
        &report.principals["account-a"],
        "agent.notion-pages",
        "install",
    )
    .await
    .unwrap();
    assert!(
        ordinary_kernel_call(&db, "account-a", "manage_alpha_tabs", args)
            .await
            .is_err(),
        "revocation refuses the whole batch"
    );
    db.close().await;
}

async fn invocation(db: &Db, entry: &str, key: &str) -> Value {
    let source =
        sqlx::query_scalar::<_, String>("SELECT pin_json FROM kernel_app_package_sources LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let pin: Value = serde_json::from_str(&source).unwrap();
    let mut request = json!({"version":"native.artifact-invocation.v1","artifact_id":"secret","entry_id":entry,"source_digest":pin["bundle_sha256"],"slots":{"record":"note"},"values":{},"observed":{},"idempotency_key":key,
        "alpha_install_guard":{"package":"agent.notion-pages","expected_install_event_id":"install","artifact_id":"secret","source_revision":pin["source_revision"],"version":pin["version"],"digest":pin["digest"],"declaration_digest":pin["declaration_digest"]}});
    if entry == "save" {
        request["values"] = json!({"body":"After","expected_body_digest":crate::mcp::tools::lifecycle::body_digest(Some("Before"))});
    } else {
        let principal = k::resolve_principal_by_binding(db, "account-a")
            .await
            .unwrap()
            .unwrap()
            .0;
        let revision = k::read_record_as(db, &principal, "note")
            .await
            .unwrap()
            .unwrap()
            .revision;
        request["values"] = json!({"title":"Renamed"});
        request["observed"] = json!({"note":{"title":format!("rec:{revision}")}});
    }
    request
}
async fn invoke(db: &Db, actor: &str, request: Value) -> crate::Result<Value> {
    crate::mcp::kernel_v2::intents::invoke(
        db,
        &gesture_caller(Caller::authenticated("account-a"), &request),
        actor,
        request,
    )
    .await
}

#[tokio::test]
async fn declarative_sql_effects_bounds_cas_replay_attribution_and_revocation() {
    let (_f, db, report) = fixture(&declaration()).await;
    let a = &report.principals["account-a"];
    let caller = Caller::authenticated("account-a").with_hosting_context("account-a", "fixture");
    // SAFETY: synthetic same-origin cookie context for signed render delivery.
    let caller =
        unsafe { caller.with_verified_hosting_session("11111111-1111-4111-8111-111111111111") };
    let delivery=crate::mcp::tools::alpha_tabs::AppBundleDelivery {
        enabled:true,
        runtime:crate::artifact_html::RuntimeConfig::new("http://localhost","https://artifact.declarative.test").unwrap(),
        keyring:Some(std::sync::Arc::new(native_artifact_runtime::deployment_keyring::DeploymentKeyring::from_json_bundle(
            r#"{"active_key_id":"synthetic","keys":[{"id":"synthetic","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}"#).unwrap())),
    };
    let rendered = crate::mcp::kernel_v2::artifacts::html_board::try_render(
        &db,
        &caller,
        a,
        &json!({"id":"secret"}),
        Some(&delivery),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    assert_eq!(
        rendered["plan"]["interaction_availability"]["supported_entries"],
        json!(["rename", "save"])
    );
    assert!(rendered["plan"]["observed"]["note"]["title"]
        .as_str()
        .unwrap()
        .starts_with("rec:"));
    let mut bad = invocation(&db, "save", "too-large").await;
    bad["values"]["body"] = json!("é".repeat(17));
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(
        invoke(&db, a, bad).await.unwrap()["error"]["code"],
        "body_too_large"
    );
    let mut forged = invocation(&db, "save", "forged-pin").await;
    forged["alpha_install_guard"]["digest"] = json!(format!("sha256:{}", "ff".repeat(32)));
    assert_eq!(
        invoke(&db, a, forged).await.unwrap()["error"]["code"],
        "alpha_guard_pin_mismatch"
    );
    let mut outside = invocation(&db, "rename", "outside-need").await;
    outside["slots"]["record"] = json!("secret");
    assert_eq!(
        invoke(&db, a, outside).await.unwrap()["error"]["code"],
        "record_outside_need"
    );
    let mut stale = invocation(&db, "save", "stale-body").await;
    stale["values"]["expected_body_digest"] = json!("ff".repeat(32));
    assert_eq!(
        invoke(&db, a, stale).await.unwrap()["error"]["code"],
        "body_digest_conflict"
    );
    let mut unissued = invocation(&db, "rename", "unissued-title-token").await;
    unissued["observed"] = json!({"note":{"title":"rec:999999999"}});
    assert_eq!(
        invoke(&db, a, unissued).await.unwrap()["error"]["code"],
        "invalid_precondition"
    );
    assert_eq!(
        before,
        k::dump_all_kernel_tables(&db).await.unwrap(),
        "every refusal is atomic"
    );
    let save = invocation(&db, "save", "save").await;
    let saved = invoke(&db, a, save.clone()).await.unwrap();
    assert_eq!(saved["status"], "committed", "{saved:#}");
    assert_eq!(saved["changes"][0]["after"]["utf8_bytes"], 5);
    assert_eq!(saved["app_attribution"]["package"], "agent.notion-pages");
    assert_eq!(saved["app_attribution"]["install_event_id"], "install");
    assert_gesture_origin(&db, "save").await;
    let renamed_request = invocation(&db, "rename", "rename").await;
    let renamed = invoke(&db, a, renamed_request.clone()).await.unwrap();
    assert_eq!(renamed["status"], "committed", "{renamed:#}");
    assert_eq!(renamed["changes"][0]["after"], "Renamed");
    assert_eq!(renamed["app_attribution"]["package"], "agent.notion-pages");
    let explicit_same_title = invocation(&db, "rename", "same-title-new-command").await;
    let same = invoke(&db, a, explicit_same_title).await.unwrap();
    assert_eq!(same["status"], "committed", "{same:#}");
    assert_eq!(same["changes"][0]["before"], "Renamed");
    assert_eq!(same["changes"][0]["after"], "Renamed");
    assert_ne!(
        same["changes"][0]["version"], renamed["changes"][0]["version"],
        "v1 records each explicit title effect even if its value is unchanged"
    );
    let facts = k::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(
        invoke(&db, a, save.clone()).await.unwrap(),
        saved,
        "replay precedes mutable body CAS"
    );
    let mut refreshed = renamed_request;
    refreshed["observed"] = json!({});
    refreshed["gesture"] = json!("Fresh retry after an uncertain response");
    assert_eq!(invoke(&db, a, refreshed).await.unwrap(), renamed);
    assert_eq!(
        facts,
        k::dump_all_kernel_tables(&db).await.unwrap(),
        "replays append nothing"
    );
    let mut conflict = save.clone();
    conflict["values"]["body"] = json!("Different");
    assert_eq!(
        invoke(&db, a, conflict).await.unwrap()["error"]["code"],
        "idempotency_conflict"
    );
    // Attribution and effect share the authenticated actor and act.
    let actions:Vec<(String,i64)>=sqlx::query_as("SELECT actor,act FROM content_events WHERE act=(SELECT act FROM content_events WHERE id=?) ORDER BY seq")
        .bind(saved["app_attribution"]["event_id"].as_str().unwrap()).fetch_all(db.pool()).await.unwrap();
    assert!(actions.len() >= 3);
    assert!(actions
        .iter()
        .all(|(actor, act)| actor == a && *act == actions[0].1));
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(facts, k::dump_all_kernel_tables(&db).await.unwrap());
    k::app_installs::remove_as(&db, a, "agent.notion-pages", "install")
        .await
        .unwrap();
    assert!(
        invoke(&db, a, save).await.is_err(),
        "revoked consent refuses even a success receipt"
    );
    db.close().await;
}

#[tokio::test]
async fn declarative_sql_public_notion_then_roadmap_need_parity() {
    // Public proof descriptors only; all imported records/source bytes are
    // synthetic. Exact package versions are not an admission rule.
    for raw in [
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/v2-notion-pages-declaration.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/v2-roadmap-base-declaration.json"
        )),
    ] {
        let descriptor: Value = serde_json::from_str(raw).unwrap();
        let declared = &descriptor["declaration"];
        let parsed = k::app_installs::declarations::declarative(declared).unwrap();
        let (_f, db, _report) = fixture(declared).await;
        let caller = Caller::authenticated("account-a");
        NativeAppDataNeeds
            .evaluate(&db, &caller, &request())
            .await
            .unwrap();
        for need in parsed.sql {
            let params = need
                .params
                .iter()
                .map(|param| (param.name.clone(), json!("note")))
                .collect::<serde_json::Map<_, _>>();
            let req = AppDataRequest {
                need: Some(need.key.clone()),
                params: Value::Object(params),
                ..request()
            };
            let result = NativeAppDataNeeds
                .evaluate(&db, &caller, &req)
                .await
                .unwrap_or_else(|err| panic!("{}: {err}", need.key));
            assert_eq!(result.result["need"], need.key);
            assert!(result.result["result"].get("as_of_seq").is_none());
        }
        db.close().await;
    }
}

#[tokio::test]
async fn declarative_sql_blob_metadata_requires_live_visible_attachment_reference() {
    let (_f, db, report) = fixture(&declaration()).await;
    let attachment = ordinary_kernel_call(
        &db,
        "account-a",
        "attach_text",
        json!({"record_id":"note","text":"Synthetic attached text","filename":"fixture.txt"}),
    )
    .await
    .unwrap();
    let attachment_id = attachment["attachment_id"].as_str().unwrap();
    let a = &report.principals["account-a"];
    let b = &report.principals["account-b"];
    let bytes = b"Unreferenced synthetic bytes";
    let unused = crate::blob::new_blob_meta(bytes, Some("text/plain"), None);
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    k::blobs::put(&mut tx, bytes, &unused).await.unwrap();
    tx.commit().await.unwrap();
    let query = json!({"sql":"SELECT id,mime,size_bytes,original_filename FROM blobs ORDER BY id"});
    let owner = ordinary_kernel_call(&db, "account-a", "query_sql", query.clone())
        .await
        .unwrap();
    assert_eq!(
        owner["rows"].as_array().unwrap().len(),
        1,
        "unreferenced bytes are not a public blob relation row"
    );
    assert_eq!(owner["rows"][0]["original_filename"], "fixture.txt");
    let hidden = ordinary_kernel_call(&db, "account-b", "query_sql", query.clone())
        .await
        .unwrap();
    assert_eq!(hidden["rows"], json!([]));
    k::replace_home_policy(
        &db,
        a,
        &k::hq::v1_import_home_id("private"),
        &[(a, "manage"), (b, "view")],
    )
    .await
    .unwrap();
    let visible = ordinary_kernel_call(&db, "account-b", "query_sql", query.clone())
        .await
        .unwrap();
    assert_eq!(visible["rows"], owner["rows"]);
    k::replace_home_policy(
        &db,
        a,
        &k::hq::v1_import_home_id("private"),
        &[(a, "manage")],
    )
    .await
    .unwrap();
    assert_eq!(
        ordinary_kernel_call(&db, "account-b", "query_sql", query.clone())
            .await
            .unwrap()["rows"],
        json!([])
    );
    // A stale or forged facet cannot expose bytes through a retained reference.
    sqlx::query(
        "UPDATE kernel_facets SET value='different-handle' WHERE record_id=? AND key='blob_ref'",
    )
    .bind(attachment_id)
    .execute(db.write_pool())
    .await
    .unwrap();
    assert_eq!(
        ordinary_kernel_call(&db, "account-a", "query_sql", query)
            .await
            .unwrap()["rows"],
        json!([])
    );
    db.close().await;
}

#[tokio::test]
async fn declarative_sql_hosted_review_binds_full_declaration_and_new_generation() {
    hosted_review_with_format(5).await;
}

#[tokio::test]
async fn declarative_sql_format4_member_readopts_with_fresh_consent_and_no_upgrade() {
    hosted_review_with_format(4).await;
}

async fn hosted_review_with_format(format: u32) {
    let declared = declaration();
    let (_f, db, report) = fixture_with(&declared, None, format).await;
    let a = &report.principals["account-a"];
    let sources = k::app_installs::frozen_sources_as(&db, a).await.unwrap();
    assert_eq!(sources.len(), 1);
    let source = &sources[0];
    if format == 4 {
        let list = ordinary_kernel_call(
            &db,
            "account-a",
            "manage_alpha_tabs",
            json!({"action":"list"}),
        )
        .await
        .unwrap();
        if cfg!(feature = "package-cel-dev") {
            assert_eq!(
                list["development_package_operations"],
                "native.package-cel-dev.reads/1"
            );
        } else {
            assert!(
                list.get("development_package_operations").is_none(),
                "shipping v2 must not offer development bridge admission"
            );
        }
        assert_eq!(
            list["installs"][0]["launch_binding"]["reason"],
            "readopt_required_on_v2"
        );
        assert!(NativeAppDataNeeds
            .evaluate(&db, &Caller::authenticated("account-a"), &request())
            .await
            .is_err());
        let pinned: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_app_package_sources")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(
            pinned, 0,
            "reading retained sources must not upgrade activation or its projections"
        );
    }
    let pin = k::app_installs::InstallRequest {
        package: "agent.notion-pages".into(),
        version: "999.42.0".into(),
        digest: source["digest"].as_str().unwrap().into(),
        artifact_id: "secret".into(),
        source_revision: "source".into(),
        declaration: declared,
        reason: "Review synthetic declared permissions".into(),
        request: None,
        idempotency_key: Some("declarative-review".into()),
        expected_install_event_id: Some("install".into()),
    };
    let preview_caller = native_app_hosted_caller("account-a", &pin, false);
    let preview = k::app_installs::preview_as(&db, a, &preview_caller, pin.clone())
        .await
        .unwrap();
    let mut delivery = db.write_pool().begin().await.unwrap();
    assert_eq!(
        k::app_installs::bundle_source_on(
            &mut delivery,
            &preview_caller,
            &pin.package,
            "install",
            &pin.digest,
            Some(&preview.receipt.receipt_id)
        )
        .await
        .unwrap()
        .0,
        source_body()
    );
    if format == 4 {
        assert!(k::app_installs::launch_source_on(
            &mut delivery,
            a,
            &preview_caller,
            &pin.package,
            "install"
        )
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("app_not_yet_available_on_v2"));
    }
    delivery.rollback().await.unwrap();
    assert_eq!(preview.receipt.needs, vec!["records.search.v1"]);
    assert_eq!(
        preview.receipt.effects,
        vec!["records.body-set.v1", "records.title-set.v1"]
    );
    let mut changed = pin.clone();
    changed.declaration["needs"][0]["sql"] = json!("SELECT id FROM records ORDER BY id");
    assert!(
        k::app_installs::preview_as(&db, a, &preview_caller, changed)
            .await
            .is_err(),
        "SQL bytes participate in the consent digest"
    );
    let caller = native_app_hosted_caller("account-a", &pin, true);
    let adopt_request = k::app_installs::AdoptRequest {
        pin,
        receipt_id: preview.receipt.receipt_id,
        nonce: preview.receipt.nonce,
        preview_session: preview.receipt.preview_session,
        scope: None,
    };
    if format == 4 {
        let revision = k::read_record_as(&db, a, "secret")
            .await
            .unwrap()
            .unwrap()
            .revision;
        k::set_archived_as(&db, a, "secret", true, revision)
            .await
            .unwrap();
        assert!(
            k::app_installs::adopt_as(&db, a, &caller, adopt_request.clone())
                .await
                .is_err(),
            "source liveness is rechecked before consuming fresh consent"
        );
        let revision = k::read_record_as(&db, a, "secret")
            .await
            .unwrap()
            .unwrap()
            .revision;
        k::set_archived_as(&db, a, "secret", false, revision)
            .await
            .unwrap();
    }
    let adopted = k::app_installs::adopt_as(&db, a, &caller, adopt_request.clone())
        .await
        .unwrap();
    let retry = k::app_installs::adopt_as(&db, a, &caller, adopt_request)
        .await
        .unwrap();
    assert_eq!(retry.outcome.generation, adopted.outcome.generation);
    assert!(!retry.outcome.changed);
    assert_ne!(adopted.outcome.generation, "install");
    let mut delivery = db.write_pool().begin().await.unwrap();
    let launched = k::app_installs::launch_source_on(
        &mut delivery,
        a,
        &caller,
        "agent.notion-pages",
        &adopted.outcome.generation,
    )
    .await
    .unwrap();
    assert_eq!(launched.body, source_body());
    assert_eq!(
        k::app_installs::bundle_source_on(
            &mut delivery,
            &caller,
            "agent.notion-pages",
            &adopted.outcome.generation,
            launched.pin["digest"].as_str().unwrap(),
            None
        )
        .await
        .unwrap()
        .0,
        source_body()
    );
    delivery.rollback().await.unwrap();

    assert!(NativeAppDataNeeds
        .evaluate(&db, &Caller::authenticated("account-a"), &request())
        .await
        .is_err());
    NativeAppDataNeeds
        .evaluate(
            &db,
            &Caller::authenticated("account-a"),
            &AppDataRequest {
                expected_install_event_id: adopted.outcome.generation,
                ..request()
            },
        )
        .await
        .unwrap();
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn declarative_sql_snapshot_without_parameterless_needs_is_undeclared() {
    let mut declared = declaration();
    declared["needs"] = json!([declared["needs"][1].clone(), "records.search.v1"]);
    declared["effects"] = json!([]);
    let (_f, db, _report) = fixture(&declared).await;
    let caller = Caller::authenticated("account-a");
    assert!(NativeAppDataNeeds
        .evaluate(&db, &caller, &request())
        .await
        .unwrap_err()
        .to_string()
        .contains("[undeclared_need]"));
    let keyed = AppDataRequest {
        need: Some("notion.page".into()),
        params: json!({"record_id":"note"}),
        ..request()
    };
    assert_eq!(
        NativeAppDataNeeds
            .evaluate(&db, &caller, &keyed)
            .await
            .unwrap()
            .result["result"]["rows"][0]["id"],
        "note"
    );
    let batch=ordinary_kernel_call(&db,"account-a","manage_alpha_tabs",json!({"action":"live_read","package":"agent.notion-pages","expected_install_event_id":"install","reads":[{"need":"attention.query.v1"},{"need":"notion.page","params":{"record_id":"note"}}]})).await.unwrap();
    assert_eq!(batch["results"][0]["error"]["code"], "undeclared_need");
    assert_eq!(batch["results"][1]["ok"]["result"]["rows"][0]["id"], "note");
    db.close().await;
}

#[tokio::test]
async fn declarative_sql_format5_excludes_inactive_removed_and_unadopted_installs() {
    for (field, value, reason) in [
        ("status", "disabled", "inactive_on_v1"),
        ("status", "removed", "removed_on_v1"),
        ("adoption", "caller_asserted", "unadopted_on_v1"),
    ] {
        let (_f, db, report) = fixture_with(&declaration(), Some((field, value)), 5).await;
        let executable:bool=sqlx::query_scalar("SELECT executable FROM kernel_app_installs WHERE principal=? AND package='agent.notion-pages'").bind(&report.principals["account-a"]).fetch_one(db.pool()).await.unwrap();
        assert!(!executable);
        assert!(NativeAppDataNeeds
            .evaluate(&db, &Caller::authenticated("account-a"), &request())
            .await
            .is_err());
        let mut conn = db.pool().acquire().await.unwrap();
        let summary = k::app_installs::inspect_frozen_activation_on(
            &mut conn,
            &proof(&db).await,
            &["account-a".into(), "account-b".into()]
                .into_iter()
                .collect(),
        )
        .await
        .unwrap();
        assert_eq!(summary["packages"][0]["eligible"], 1);
        assert_eq!(summary["packages"][0]["exclusion_reasons"][reason], 1);
        drop(conn);
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        k::replay_all_projections(&db).await.unwrap();
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
        db.close().await;
    }
}

#[tokio::test]
async fn declarative_sql_format5_unknown_shapes_are_per_install_exclusions() {
    for declared in [
        json!({"contract":"unknown.contract","needs":[],"effects":[]}),
        json!({"needs":["unknown.need"],"effects":[]}),
        json!({"needs":[],"effects":[],"unexpected":true}),
    ] {
        let (_f, db, _report) = fixture(&declared).await;
        let excluded:i64=sqlx::query_scalar("SELECT count(*) FROM kernel_app_installs WHERE executable=0 AND refusal='app_not_yet_available_on_v2'").fetch_one(db.pool()).await.unwrap();
        assert_eq!(excluded, 2);
        let sources: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_app_package_sources")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(sources, 0);
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        k::replay_all_projections(&db).await.unwrap();
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
        db.close().await;
    }
}

#[tokio::test]
async fn declarative_sql_format4_cannot_be_reinterpreted_by_format5_replay() {
    let (_f, db, _report) = fixture_with(&declaration(), None, 4).await;
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let error = k::app_installs::activate_as(&db, &host, proof(&db).await)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("activation evidence changed"));
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    let sources: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_app_package_sources")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(
        sources, 0,
        "format 4 deliberately retains no executable Class 2 pin"
    );
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn declarative_sql_retained_source_admission_excludes_inactive_and_unadopted_v1() {
    for (field, value) in [
        ("all:status", "disabled"),
        ("all:status", "removed"),
        ("all:adoption", "caller_asserted"),
    ] {
        let (_f, db, report) = fixture_with(&declaration(), Some((field, value)), 4).await;
        let a = &report.principals["account-a"];
        assert!(k::app_installs::frozen_sources_as(&db, a)
            .await
            .unwrap()
            .is_empty());
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        assert!(NativeAppDataNeeds
            .evaluate(&db, &Caller::authenticated("account-a"), &request())
            .await
            .is_err());
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
        db.close().await;
    }
}

#[tokio::test]
async fn declarative_sql_retained_source_admission_refuses_tampered_capsule() {
    let digest = format!("sha256:{}", "0".repeat(64));
    let (_f, db, report) = fixture_with(&declaration(), Some(("digest", &digest)), 4).await;
    let a = &report.principals["account-a"];
    let sources = k::app_installs::frozen_sources_as(&db, a).await.unwrap();
    assert_eq!(
        sources.len(),
        1,
        "the other member's verified pin remains available"
    );
    assert_ne!(sources[0]["digest"], digest);
    let list = ordinary_kernel_call(
        &db,
        "account-a",
        "manage_alpha_tabs",
        json!({"action":"list"}),
    )
    .await
    .unwrap();
    assert_eq!(
        list["installs"][0]["launch_binding"]["reason"],
        "retained_source_unverified_on_v2"
    );
    assert!(list["installs"][0]["launch_binding"]
        .get("delivery")
        .is_none());
    let executable: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kernel_app_installs WHERE executable=1")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(executable, 0);
    db.close().await;
}

#[tokio::test]
async fn declarative_sql_bad_retained_install_isolated_from_lists_and_preparation() {
    let digest = format!("sha256:{}", "0".repeat(64));
    // 39 mapped installs, 20 packages and ~144 KiB source bytes: larger than
    // the supplied counts-only HQ inventory, with no private bundle data.
    let (_f, db, report) =
        fixture_with_extra_installs(&declaration(), Some(("digest", &digest)), 4, 19).await;
    let a = &report.principals["account-a"];
    let b = &report.principals["account-b"];
    k::replace_home_policy(
        &db,
        a,
        &k::hq::v1_import_home_id("private"),
        &[(a, "manage"), (b, "view")],
    )
    .await
    .unwrap();
    for account in ["account-a", "account-b"] {
        for view in ["full", "summary"] {
            let started = std::time::Instant::now();
            let list = ordinary_kernel_call(
                &db,
                account,
                "manage_alpha_tabs",
                json!({"action":"list","view":view}),
            )
            .await
            .unwrap();
            eprintln!(
                "synthetic_retained_list account={account} view={view} elapsed_us={}",
                started.elapsed().as_micros()
            );
            let installs = list["installs"].as_array().unwrap();
            assert_eq!(installs.len(), if account == "account-a" { 20 } else { 19 });
            assert!(installs
                .iter()
                .any(|entry| entry["package"] == "agent.docs" && entry["target_resolves"] == true));
            if view == "full" {
                assert_eq!(list["frozen_sources"].as_array().unwrap().len(), 20);
                let notion = installs
                    .iter()
                    .find(|entry| entry["package"] == "agent.notion-pages")
                    .unwrap();
                assert_eq!(
                    notion["launch_binding"]["reason"],
                    if account == "account-a" {
                        "retained_source_unverified_on_v2"
                    } else {
                        "readopt_required_on_v2"
                    }
                );
                assert!(installs
                    .iter()
                    .any(|entry| entry["package"] == "agent.synthetic-2"
                        && entry["launch_binding"]["reason"] == "readopt_required_on_v2"));
            }
        }
    }
    let prepare = ordinary_kernel_call(&db, "account-b", "manage_alpha_tabs", json!({"action":"prepare_install","package":"agent.roadmap-base","version":"999.42.0","artifact_id":"secret","declaration":declaration(),"expected_source_revision":"source","reason":"synthetic member reinstall","request":"Install the roadmap app"})).await.unwrap();
    assert_eq!(
        prepare["ready"], true,
        "another member can prepare a fresh install from the valid shared pin"
    );
    assert!(NativeAppDataNeeds
        .evaluate(&db, &Caller::authenticated("account-a"), &request())
        .await
        .is_err());
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn installed_app_management_reads_do_not_wait_for_write_pool() {
    let (_f, db, report) = fixture(&declaration()).await;
    let principal = &report.principals["account-a"];
    let mut expected_lists = Vec::new();
    for view in ["full", "summary"] {
        expected_lists.push(
            k::app_installs::list_as(&db, principal, Some(view.into()), None)
                .await
                .unwrap(),
        );
    }
    let mut expected_inspections = Vec::new();
    for package in ["agent.notion-pages", "agent.docs", "agent.not-installed"] {
        expected_inspections.push(
            k::app_installs::inspect_as(&db, principal, package)
                .await
                .unwrap(),
        );
    }
    assert_eq!(expected_inspections[0]["installed"], true);
    assert_eq!(expected_inspections[2]["installed"], false);

    // Isolate the inventory handler body: outer dispatcher admission may still
    // need the writer pool. These reads must not retain its scarce connections
    // for the complete source/pending/visibility inventory transaction.
    let mut held_writers = Vec::new();
    for _ in 0..db.write_pool().options().get_max_connections() {
        held_writers.push(db.write_pool().acquire().await.unwrap());
    }
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            db.write_pool().acquire(),
        )
        .await
        .is_err(),
        "control: every writer connection must be held"
    );

    let reads = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for (view, expected) in ["full", "summary"].into_iter().zip(expected_lists) {
            let actual = k::app_installs::list_as(&db, principal, Some(view.into()), None)
                .await
                .unwrap();
            assert_eq!(actual, expected, "{view} inventory changed");
        }
        for (package, expected) in ["agent.notion-pages", "agent.docs", "agent.not-installed"]
            .into_iter()
            .zip(expected_inspections)
        {
            let actual = k::app_installs::inspect_as(&db, principal, package)
                .await
                .unwrap();
            assert_eq!(actual, expected, "{package} inspection changed");
        }
    })
    .await;
    drop(held_writers);
    reads.expect("inventory read handlers waited for the exhausted writer pool");
    db.close().await;
}

#[tokio::test]
async fn installed_app_inventory_does_not_load_current_artifact_bodies() {
    let (_f, db, report) = fixture(&declaration()).await;
    let artifact = k::read_record_as(&db, &report.principals["account-a"], "secret")
        .await
        .unwrap()
        .unwrap();
    let title = artifact.fields["title"].clone();
    assert!(title.as_str().is_some_and(|name| !name.is_empty()));
    let mut expected = Vec::new();
    for view in ["full", "summary"] {
        let list = ordinary_kernel_call(
            &db,
            "account-a",
            "manage_alpha_tabs",
            json!({"action":"list", "view":view}),
        )
        .await
        .unwrap();
        let entry = list["installs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["package"] == "agent.notion-pages")
            .unwrap();
        assert_eq!(
            entry["name"], title,
            "{view} must expose the authored title"
        );
        expected.push(list);
    }
    // Fault-inject only the current-body storage. Inventory needs today's
    // visibility, kind, name and archive state, plus the separately retained
    // source pins; it must not fetch whole current HTML bundles for those.
    sqlx::query("ALTER TABLE kernel_record_bodies RENAME TO inventory_test_bodies")
        .execute(db.write_pool())
        .await
        .unwrap();
    for (view, expected) in ["full", "summary"].into_iter().zip(expected) {
        let actual = ordinary_kernel_call(
            &db,
            "account-a",
            "manage_alpha_tabs",
            json!({"action":"list", "view":view}),
        )
        .await
        .unwrap();
        assert_eq!(
            actual, expected,
            "{view} inventory changed without metadata changes"
        );
    }
    sqlx::query("ALTER TABLE inventory_test_bodies RENAME TO kernel_record_bodies")
        .execute(db.write_pool())
        .await
        .unwrap();
    // A missing artifact still yields an isolated unavailable target; it
    // must not turn a partial install row into a failed whole inventory.
    sqlx::query("UPDATE kernel_app_installs SET row_json=json_set(row_json,'$.artifact_id','missing-inventory-source') WHERE package='agent.notion-pages'")
        .execute(db.write_pool()).await.unwrap();
    for view in ["full", "summary"] {
        let list = ordinary_kernel_call(
            &db,
            "account-a",
            "manage_alpha_tabs",
            json!({"action":"list", "view":view}),
        )
        .await
        .unwrap();
        let entry = list["installs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["package"] == "agent.notion-pages")
            .unwrap();
        assert_eq!(entry["target_resolves"], false);
        assert_eq!(entry["target_skip_reason"], "unauthorized");
        assert!(
            entry["name"].is_null(),
            "unavailable target must not disclose its name"
        );
    }
    db.close().await;
}

#[tokio::test]
async fn local_registry_keeps_installed_apps_usable_without_a_hosted_signer() {
    let (_fixture, db, _) = fixture(&declaration()).await;
    for local_copy in [false, true] {
        let caller = if local_copy {
            Caller::authenticated("account-a")
        } else {
            Caller::authenticated("account-a").with_hosting_context("account-a", "fixture")
        };
        let mut registry = crate::mcp::ToolRegistry::new();
        registry.set_standby_read_only(local_copy);
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
        for args in [
            json!({"action":"list"}),
            json!({"action":"inspect","package":"agent.notion-pages"}),
        ] {
            let inspect = args["action"] == "inspect";
            let result = registry
                .call_engine(
                    crate::mcp::EngineHandle::KernelV2(db.clone()),
                    caller.clone(),
                    "manage_alpha_tabs",
                    args,
                )
                .await
                .unwrap();
            let entry = if inspect {
                &result["install"]
            } else {
                result["installs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["package"] == "agent.notion-pages")
                    .unwrap()
            };
            assert_eq!(entry["status"], "installed");
            assert_eq!(entry["target_resolves"], true);
            assert_eq!(
                entry["launch_binding"]["reason"],
                if local_copy {
                    "launch_request_required"
                } else {
                    "delivery_unavailable"
                }
            );
        }
        if local_copy {
            let bundle = registry.call_engine(crate::mcp::EngineHandle::KernelV2(db.clone()), caller.clone(),
                "read_app_bundle", json!({"package":"agent.notion-pages","expected_install_event_id":"install", "parent_origin":"native-ui://app","offset":0,"length":128})).await.unwrap();
            assert_eq!(bundle["length"], 128);
        }
    }
}
