//! Real registry/executor tests for shared publication management.
use super::*;
use crate::kernel::{self, publications};
use crate::mcp::kernel_v2::writes::publication::testing;
use crate::mcp::registry::EngineKind;
use sha2::Digest;

struct World {
    _dir: tempfile::TempDir,
    db: crate::Db,
    admin: String,
    manager: String,
    record: String,
    registry: Arc<ToolRegistry>,
    caller: Caller,
    server: ExecutorPrototypeStdioServer,
    store: plan_store::PlanStore,
}
impl World {
    async fn new() -> Self {
        Self::new_with_sql(false).await
    }
    async fn new_with_sql(with_sql: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (db, admin) = kernel::create_v2_database(
            dir.path().join("publication.db").to_str().unwrap(),
            "account",
            "Admin",
            "acct:admin",
        )
        .await
        .unwrap();
        let manager = kernel::create_principal(&db, "account", "Manager", "acct:manager", &admin)
            .await
            .unwrap();
        kernel::replace_home_policy(
            &db,
            &admin,
            crate::events::KERNEL_ROOT_ID,
            &[(&admin, "manage"), (&manager, "manage")],
        )
        .await
        .unwrap();
        let package = crate::v2_standard::document4_package();
        let installed = kernel::install_package_as(&db, &admin, &package)
            .await
            .unwrap();
        kernel::adopt_package_at(
            &db,
            &admin,
            crate::events::KERNEL_ROOT_ID,
            &package,
            Some(&installed),
            &[],
        )
        .await
        .unwrap();
        let record = kernel::create_json_as(
            &db,
            &admin,
            "native.standard.document",
            "note",
            r#"{"title":"private-title-sentinel","body":"Saved **body** ![alt](private.png)"}"#,
            crate::events::KERNEL_ROOT_ID,
        )
        .await
        .unwrap();
        let mut registry = if with_sql {
            Arc::try_unwrap(super::tests::hosted_registry())
                .ok()
                .unwrap()
        } else {
            let mut registry = ToolRegistry::new();
            crate::mcp::register_builtin_tools(&mut registry).unwrap();
            crate::mcp::register_surface_tools(&mut registry).unwrap();
            registry
        };
        crate::mcp::tools::register_publication_management_tool(&mut registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
        let registry = Arc::new(registry);
        let caller =
            Caller::authenticated("acct:manager").with_hosting_context("manager", "workspace");
        assert!(!caller.is_host_owner());
        let store = plan_store::PlanStore::open_for_database(db.path())
            .await
            .unwrap();
        let server = ExecutorPrototypeStdioServer::new_with_plan_store(
            registry.clone(),
            EngineHandle::KernelV2(db.clone()),
            caller.clone(),
            None,
            ExecutorConstruction {
                plan_store: Some(store.clone()),
                hosted_authority: None,
                pinned_catalogue: None,
                experimental: if with_sql {
                    ExperimentalExecutors::from_env_value(Some("sql_write".into())).unwrap()
                } else {
                    ExperimentalExecutors::empty()
                },
                lean: true,
                telemetry: TelemetryConstruction::Disabled,
                transport: telemetry::TelemetryTransport::Http,
                deployment_mutation_barrier: None,
            },
        )
        .await
        .unwrap();
        Self {
            _dir: dir,
            db,
            admin,
            manager,
            record,
            registry,
            caller,
            server,
            store,
        }
    }
    async fn args(&self, action: &str, key: &str) -> Value {
        let (revision, state) =
            publications::inspect_revision_as(&self.db, &self.manager, &self.record)
                .await
                .unwrap();
        let mut args = json!({"id":self.record,"expected_revision":revision,"expected_publication_version":state.as_ref().map(|s|s.version),"operation_key":key,"reason":"Explicit sharing decision"});
        if action == "unpublish" {
            args["public_id"] = json!(state.unwrap().public_id);
        }
        args
    }
    async fn prepare(&self, action: &str, args: Value) -> Value {
        self.server
            .handle_guarded_plan_fixture_message(prepare(action, args))
            .await
            .unwrap()
    }
    async fn count(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(self.db.pool())
            .await
            .unwrap()
    }
    async fn demote(&self) {
        kernel::replace_home_policy(
            &self.db,
            &self.admin,
            crate::events::KERNEL_ROOT_ID,
            &[(&self.admin, "manage"), (&self.manager, "edit")],
        )
        .await
        .unwrap();
    }
}
async fn revision(db: &crate::Db, actor: &str, id: &str) -> i64 {
    kernel::read_record_as(db, actor, id)
        .await
        .unwrap()
        .unwrap()
        .revision
}
fn prepare(action: &str, args: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"records_write","operation":format!("manage_publication.{action}"),"arguments":args}}})
}
fn execute(action: &str, plan: &Value) -> Value {
    json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"records_write","operation":format!("manage_publication.{action}"),"plan_id":plan["plan_id"],"target":plan["target"],"effect_summary":plan["effect_summary"]}}})
}
fn payload(reply: &Value) -> &Value {
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    &reply["result"]["structuredContent"]
}

#[tokio::test]
async fn publication_plan_refuses_replacement_births_with_matching_content() {
    testing(true, async {
        let dir = tempfile::tempdir().unwrap();
        let record = uuid::Uuid::new_v4().to_string();
        async fn database(path: &std::path::Path, record: &str) -> (crate::Db, String) {
            let (db, admin) = kernel::create_v2_database(path.to_str().unwrap(), "account", "Manager", "fixture:manager").await.unwrap();
            let importer = kernel::resolve_principal_by_binding(&db, kernel::hq::HOST_IMPORT_BINDING).await.unwrap().unwrap().0;
            kernel::hq::import_record_as(&db, &importer, record, crate::events::KERNEL_ROOT_ID,
                Some(&admin), &kernel::hq::ImportRecordState { body: Some("same saved body".into()), ..Default::default() }).await.unwrap();
            (db, admin)
        }
        let (first, first_admin) = database(&dir.path().join("first.db"), &record).await;
        let (replacement, replacement_admin) = database(&dir.path().join("replacement.db"), &record).await;
        let original = publications::prepare_as(&first, &first_admin, &record).await.unwrap();
        let next = publications::prepare_as(&replacement, &replacement_admin, &record).await.unwrap();
        assert_eq!((original.record_revision, &original.title, &original.body), (next.record_revision, &next.title, &next.body));
        assert_ne!(original.binding.database_birth, next.binding.database_birth);
        assert_ne!(original.binding.record_birth, next.binding.record_birth);
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        crate::mcp::tools::register_publication_management_tool(&mut registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
        let registry = Arc::new(registry);
        let caller = Caller::authenticated("fixture:manager").with_hosting_context("manager", "same-catalog-database");
        let store = plan_store::PlanStore::open_for_database(first.path()).await.unwrap();
        async fn server(registry: Arc<ToolRegistry>, db: crate::Db, caller: Caller, store: plan_store::PlanStore) -> ExecutorPrototypeStdioServer {
            ExecutorPrototypeStdioServer::new_with_plan_store(registry, EngineHandle::KernelV2(db), caller, None,
                ExecutorConstruction { plan_store: Some(store), hosted_authority: None, pinned_catalogue: None,
                    experimental: ExperimentalExecutors::empty(), lean: true, telemetry: TelemetryConstruction::Disabled,
                    transport: telemetry::TelemetryTransport::Http, deployment_mutation_barrier: None }).await.unwrap()
        }
        let first_server = server(registry.clone(), first, caller.clone(), store.clone()).await;
        let replacement_server = server(registry, replacement.clone(), caller, store).await;
        let args = json!({"id":record,"expected_revision":original.record_revision,"expected_publication_version":null,"operation_key":"same-plan","reason":"fixture"});
        let prepared = first_server.handle_guarded_plan_fixture_message(prepare("publish", args.clone())).await.unwrap();
        let plan = payload(&prepared);
        let replacement_prepared = replacement_server.handle_guarded_plan_fixture_message(prepare("publish", args)).await.unwrap();
        let replacement_plan = payload(&replacement_prepared);
        for field in ["executor", "operation", "target", "effect_summary", "effect", "state_revision", "target_state_digest", "arguments_digest", "revalidation_arguments_digest", "source_arguments_digest", "effect_digest", "contract_digest", "catalogue_digest"] {
            assert_eq!(plan[field], replacement_plan[field], "different {field}");
        }
        assert_eq!(plan["operation_evidence"]["kind"], replacement_plan["operation_evidence"]["kind"]);
        assert_eq!(plan["operation_evidence"]["authority"], replacement_plan["operation_evidence"]["authority"]);
        assert_ne!(plan["operation_evidence"]["binding"]["database_birth"], replacement_plan["operation_evidence"]["binding"]["database_birth"]);
        assert_ne!(plan["operation_evidence"]["binding"]["record_birth"], replacement_plan["operation_evidence"]["binding"]["record_birth"]);
        let refused = replacement_server.handle_guarded_plan_fixture_message(execute("publish", plan)).await.unwrap();
        assert_eq!(refused["result"]["isError"], true, "{refused}");
        assert_eq!(refused["result"]["structuredContent"]["plan_error"]["code"], "plan_stale", "{refused}");
        assert!(publications::inspect_as(&replacement, &replacement_admin, &record).await.unwrap().is_none());
    }).await;
}

#[tokio::test]
async fn publication_plan_live_consent_current_manage_and_idempotency() {
    testing(true, async {
        let w = World::new().await;
        let args = w.args("publish", "publish").await;
        let before = w.count().await;
        let preview = w.server.handle_guarded_plan_fixture_message(json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"records_read","operation":"manage_publication.preview","arguments":{"id":w.record}}}})).await.unwrap();
        let preview = &payload(&preview)["preview"];
        assert_eq!(preview["title"], "private-title-sentinel");
        assert_eq!(preview["body"], "Saved **body** ![alt](private.png)");
        let prepared = w.prepare("publish", args.clone()).await;
        let plan = payload(&prepared);
        let mut different_reason = args.clone();
        different_reason["reason"] = json!("A different reviewed reason");
        let other = w.prepare("publish", different_reason).await;
        let other_plan = payload(&other);
        assert_eq!(w.count().await, before);
        assert_eq!(plan["effect"]["record_revision"], preview["record_revision"]);
        assert_eq!(plan["effect"]["representation"]["body_sha256"], preview["body_sha256"]);
        assert_eq!(plan["effect"]["representation"]["title_sha256"], hex::encode(sha2::Sha256::digest(b"private-title-sentinel")));
        assert_eq!(plan["effect"]["consent"]["future_saved_edits_public"], true);
        assert_eq!(plan["effect"]["consent"]["images"], "alt_text_only");
        let stored = w.store.load(plan["plan_id"].as_str().unwrap(), chrono::Utc::now().timestamp_millis()).await.unwrap().unwrap();
        let stored_json = stored.payload.to_string();
        assert!(!stored_json.contains("private-title-sentinel"));
        assert!(!stored_json.contains("Saved **body**"));
        assert!(stored_json.contains("Explicit sharing decision"));
        assert!(stored_json.len() < 16 * 1024, "small payload stores no private document");
        let mut tampered = execute("publish", plan);
        tampered["params"]["arguments"]["arguments"] = json!({"reason":"replacement"});
        assert_eq!(w.server.handle_guarded_plan_fixture_message(tampered).await.unwrap()["result"]["isError"],true);
        let request = execute("publish", plan);
        let result = w.server.handle_guarded_plan_fixture_message(request.clone()).await.unwrap();
        payload(&result);
        assert_eq!(w.count().await, before + 1);
        let other_result = w.server.handle_guarded_plan_fixture_message(execute("publish", other_plan)).await.unwrap();
        assert_eq!(other_result["result"]["isError"], true, "{other_result}");
        assert_eq!(w.count().await, before + 1);
        let again = w.server.handle_guarded_plan_fixture_message(request.clone()).await.unwrap();
        payload(&again);
        assert_eq!(w.count().await, before + 1);
        let state = publications::inspect_as(&w.db, &w.manager, &w.record)
            .await
            .unwrap()
            .unwrap();
        kernel::set_body_as(
            &w.db,
            &w.admin,
            &w.record,
            "Later saved body",
            revision(&w.db, &w.admin, &w.record).await,
        )
        .await
        .unwrap();
        let publications::PublicRead::Available(doc) =
            publications::read_public(&w.db, &state.public_id)
                .await
                .unwrap()
        else {
            panic!("missing document")
        };
        assert_eq!(doc.body, "Later saved body");
        let receipt = payload(&result);
        let event_id = receipt["kernel_receipt"]["event_id"].as_str().unwrap();
        let event: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE id=?").bind(event_id).fetch_one(w.db.pool()).await.unwrap();
        assert!(!event.contains("Explicit sharing decision"));
        assert_eq!(receipt["routing"]["status"], "not_configured");
        assert!(receipt["routing"]["public_url"].is_null());
        w.demote().await;
        let before = w.count().await;
        let denied = w.server.handle_guarded_plan_fixture_message(request).await.unwrap();
        assert_eq!(denied["result"]["isError"], true);
        assert_eq!(w.count().await, before);
    })
    .await;
}

#[tokio::test]
async fn publication_plan_demotion_and_record_drift_refuse_without_effects() {
    for change in ["demote", "body", "title"] {
        testing(true, async {
            let w = World::new().await;
            let prepared = w.prepare("publish", w.args("publish", "stale").await).await;
            let plan = payload(&prepared);
            if change == "demote" {
                w.demote().await;
            } else if change == "title" {
                kernel::revise_json_as_expected(
                    &w.db,
                    &w.admin,
                    &w.record,
                    r#"{"title":"changed after consent"}"#,
                    Some(revision(&w.db, &w.admin, &w.record).await),
                )
                .await
                .unwrap();
            } else {
                kernel::set_body_as(
                    &w.db,
                    &w.admin,
                    &w.record,
                    "Changed after consent",
                    revision(&w.db, &w.admin, &w.record).await,
                )
                .await
                .unwrap();
            }
            let before = w.count().await;
            let refused = w
                .server
                .handle_guarded_plan_fixture_message(execute("publish", plan))
                .await
                .unwrap();
            assert_eq!(refused["result"]["isError"], true, "{refused}");
            assert_eq!(w.count().await, before);
            assert!(publications::inspect_as(&w.db, &w.admin, &w.record)
                .await
                .unwrap()
                .is_none());
        })
        .await;
    }
}

#[tokio::test]
async fn publication_plan_cas_race_after_revalidation_is_fenced_by_kernel_writer() {
    let mut w = World::new().await;
    let gate = w.server.set_view_dispatch_gate();
    let args = w.args("publish", "racing").await;
    let prepared = testing(true, w.prepare("publish", args.clone())).await;
    let request = execute("publish", payload(&prepared));
    let db = w.db.clone();
    let admin = w.admin.clone();
    let record = w.record.clone();
    let run = tokio::spawn(testing(true, async move {
        w.server
            .handle_guarded_plan_fixture_message(request)
            .await
            .unwrap()
    }));
    tokio::time::timeout(std::time::Duration::from_secs(30), gate.entered.acquire())
        .await
        .expect("executor did not reach the dispatch fence")
        .unwrap()
        .forget();
    let (revision, state) = publications::inspect_revision_as(&db, &admin, &record)
        .await
        .unwrap();
    let winner = publications::change_as(
        &db,
        &admin,
        publications::PublicationRequest {
            record_id: record.clone(),
            action: publications::PublicationAction::Publish,
            expected_revision: revision,
            expected_publication_version: state.map(|s| s.version),
            operation_key: "winner".into(),
        },
    )
    .await
    .unwrap();
    gate.release.add_permits(1);
    let refused = run.await.unwrap();
    assert_eq!(refused["result"]["isError"], true, "{refused}");
    assert_eq!(
        publications::inspect_as(&db, &admin, &record)
            .await
            .unwrap(),
        Some(winner.state)
    );
}

#[tokio::test]
async fn publication_unpublish_oversize_remains_available_through_executor() {
    testing(true,async {
        let w=World::new().await;
        let prepared=w.prepare("publish",w.args("publish","publish").await).await;
        payload(&w.server.handle_guarded_plan_fixture_message(execute("publish",payload(&prepared))).await.unwrap());
        kernel::set_body_as(&w.db,&w.admin,&w.record,&"x".repeat(4*1024*1024+1),revision(&w.db,&w.admin,&w.record).await).await.unwrap();
        assert!(publications::prepare_as(&w.db,&w.manager,&w.record).await.is_err());
        let inspected=w.server.handle_guarded_plan_fixture_message(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"records_read","operation":"manage_publication.inspect","arguments":{"id":w.record}}}})).await.unwrap();
        let state=payload(&inspected)["publication"].clone();
        assert_eq!(state["active"],true);
        let before=w.count().await;
        let prepared=w.prepare("unpublish",w.args("unpublish","withdraw").await).await;
        assert_eq!(w.count().await,before);
        payload(&w.server.handle_guarded_plan_fixture_message(execute("unpublish",payload(&prepared))).await.unwrap());
        assert_eq!(publications::read_public(&w.db,state["public_id"].as_str().unwrap()).await.unwrap(),publications::PublicRead::Unavailable);
    }).await;
}

#[tokio::test]
async fn publication_disabled_closed_contract_and_raw_source_have_no_effects() {
    let w = World::new().await;
    let args = w.args("publish", "disabled").await;
    let before = w.count().await;
    let disabled = w.prepare("publish", args.clone()).await;
    assert!(
        disabled.to_string().contains("publication_disabled"),
        "{disabled}"
    );
    testing(true,async {
        for key in ["principal","origin","body","unexpected"] {
            let mut invalid=args.clone();invalid[key]=json!("untrusted");
            assert_eq!(w.prepare("publish",invalid).await["result"]["isError"],true);
        }
        let mut source=args;source["action"]=json!("publish");
        let refused = w.registry.call_engine(EngineHandle::KernelV2(w.db.clone()),w.caller.clone(),"manage_publication",source).await.unwrap_err().to_string();
        assert!(refused.contains("publication_executor_required"), "{refused}");
        assert_eq!(w.count().await, before);
        w.demote().await;
        let before=w.count().await;
        let inspect = w.server.handle_guarded_plan_fixture_message(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"records_read","operation":"manage_publication.inspect","arguments":{"id":w.record}}}})).await.unwrap();
        assert_eq!(inspect["result"]["isError"],true);
        let denied=w.prepare("publish",json!({"id":w.record,"expected_revision":0,"expected_publication_version":null,"operation_key":"denied","reason":"test"})).await;
        assert_eq!(denied["result"]["isError"],true);
        assert_eq!(w.count().await,before);
    }).await;
    assert_eq!(w.count().await, before + 1); // deliberate policy demotion only
}

#[tokio::test]
async fn publication_app_attributed_reads_and_writes_refuse_without_effects() {
    testing(true, async {
        let w = World::new().await;
        let app = w.caller.clone().with_host_asserted_app(
            crate::mcp::app_attribution::AppAttribution::new("test.app", "1.0.0", "installation")
                .unwrap(),
        );
        let mut source = w.args("publish", "app").await;
        source["action"] = json!("publish");
        let before = w.count().await;
        let preview = crate::mcp::kernel_v2::writes::publication::preview(&w.db, &app, &source)
            .await
            .unwrap_err();
        assert!(preview.to_string().contains("app-attributed"));
        let inspect = w
            .registry
            .call_engine(
                EngineHandle::KernelV2(w.db.clone()),
                app.clone(),
                "manage_publication",
                json!({"action":"inspect", "id":w.record}),
            )
            .await;
        assert!(inspect.is_err());
        let content = w
            .registry
            .call_engine(
                EngineHandle::KernelV2(w.db.clone()),
                app.clone(),
                "manage_publication",
                json!({"action":"preview", "id":w.record}),
            )
            .await;
        assert!(content.is_err());
        let planned = app.with_write_plan_execution(crate::mcp::registry::WritePlanExecution {
            plan_id: "fixture".into(),
            effect_digest: "fixture".into(),
            executor: "records_write".into(),
            operation: "manage_publication.publish".into(),
        });
        let write = w
            .registry
            .call_engine(
                EngineHandle::KernelV2(w.db.clone()),
                planned,
                "manage_publication",
                source,
            )
            .await;
        assert!(write.is_err());
        assert_eq!(w.count().await, before);
        assert!(publications::inspect_as(&w.db, &w.manager, &w.record)
            .await
            .unwrap()
            .is_none());
    })
    .await;
}

#[tokio::test]
async fn publication_copy_inspection_reports_recorded_state_and_refuses_mutation() {
    testing(true, async {
        let w = World::new().await;
        let (revision, state) = publications::inspect_revision_as(&w.db, &w.manager, &w.record)
            .await
            .unwrap();
        publications::change_as(
            &w.db,
            &w.manager,
            publications::PublicationRequest {
                record_id: w.record.clone(),
                action: publications::PublicationAction::Publish,
                expected_revision: revision,
                expected_publication_version: state.map(|s| s.version),
                operation_key: "copy-source".into(),
            },
        )
        .await
        .unwrap();
        let copy = crate::db::open_kernel_v2_standby_read_only(w.db.path().to_str().unwrap())
            .await
            .unwrap();
        let result = w
            .registry
            .call_engine(
                EngineHandle::KernelV2(copy.clone()),
                w.caller.clone(),
                "manage_publication",
                json!({"action":"inspect","id":w.record}),
            )
            .await
            .unwrap();
        assert_eq!(result["authority"], "recorded_copy_not_current_authority");
        assert_eq!(result["publication"]["active"], true);
        let mut args = w.args("unpublish", "copy-refusal").await;
        args["action"] = json!("unpublish");
        assert!(
            crate::mcp::kernel_v2::writes::publication::preview(&copy, &w.caller, &args)
                .await
                .unwrap_err()
                .to_string()
                .contains("publication_profile_unsupported")
        );
        assert!(
            publications::inspect_as(&w.db, &w.manager, &w.record)
                .await
                .unwrap()
                .unwrap()
                .active
        );
    })
    .await;
}

#[tokio::test]
async fn publication_explicit_registration_preserves_default_and_supports_lean_sql_composition() {
    let mut default = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut default).unwrap();
    crate::mcp::register_surface_tools(&mut default).unwrap();
    assert!(default.get("manage_publication").is_none());
    default.validate_profile_budgets().unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut default).unwrap();
    let catalogue = build_ordinary_catalogue_projection(
        &default,
        EngineKind::KernelV2,
        false,
        &ExperimentalExecutors::empty(),
        true,
    )
    .unwrap();
    assert!(!catalogue
        .contracts
        .keys()
        .any(|(_, op)| op.starts_with("manage_publication.")));
    assert!(!serde_json::to_string(&catalogue.descriptors)
        .unwrap()
        .contains("manage_publication"));

    let mut alone = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut alone).unwrap();
    crate::mcp::register_surface_tools(&mut alone).unwrap();
    crate::mcp::tools::register_publication_management_tool(&mut alone).unwrap();
    alone.validate_profile_budgets().unwrap();

    testing(true, async {
        let w = World::new_with_sql(true).await;
        // Startup validates both legacy profiles before choosing Lean. The
        // combined catalogue must pass that unchanged admission as well.
        w.registry.validate_profile_budgets().unwrap();
        crate::mcp::validate_lens_profile_budgets(&w.registry).unwrap();
        assert!(w.server.descriptor_bytes < 32 * 1024);
        assert_eq!(w.server.contracts.keys().filter(|(_, operation)| operation.starts_with("manage_publication.")).count(), 4);
        let full = build_ordinary_catalogue_projection(&w.registry, EngineKind::KernelV2, false,
            &ExperimentalExecutors::from_env_value(Some("sql_write".into())).unwrap(), false).unwrap();
        let descriptor = full.descriptors.iter().find(|d| d["name"] == "records_write").unwrap();
        assert!(descriptor["inputSchema"].get("oneOf").is_none());
        let operations = descriptor["inputSchema"]["properties"]["operation"]["enum"].as_array().unwrap();
        for name in ["manage_publication.publish", "manage_publication.unpublish"] {
            assert!(operations.iter().any(|value| value == name), "{name} missing from direct envelope");
        }
        for (executor, operation) in [("records_read","manage_publication.inspect"), ("records_read","manage_publication.preview"), ("records_write","manage_publication.publish"), ("records_write","manage_publication.unpublish")] {
            assert!(w.server.contracts.contains_key(&(executor.into(),operation.into())), "missing {operation}");
        }
        let preview = w.server.handle_guarded_plan_fixture_message(json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"records_read","operation":"manage_publication.preview","arguments":{"id":w.record}}}})).await.unwrap();
        assert_eq!(payload(&preview)["preview"]["title"],"private-title-sentinel");
        let prepared = w.prepare("publish",w.args("publish","lean-combined").await).await;
        let done = w.server.handle_guarded_plan_fixture_message(execute("publish",payload(&prepared))).await.unwrap();
        payload(&done);
    }).await;
}

#[tokio::test]
async fn cookie_publication_source_channel_is_narrow_and_capability_bound() {
    let mut w = World::new().await;
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    crate::mcp::tools::register_publication_management_tool(&mut registry).unwrap();
    // Observe the actual source caller independently of tool-result formatting.
    // The real HTTP proof separately commits through the canonical handler and
    // compares the persisted event/receipt actor with this admitted account.
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    for name in ["get_record", "manage_publication"] {
        let source_observed = observed.clone();
        registry
            .register_engine_handler(name, EngineKind::KernelV2, move |_engine, caller, _args| {
                let observed = source_observed.clone();
                async move {
                    observed
                        .lock()
                        .unwrap()
                        .push((name, caller.channel().as_str()));
                    Ok(json!({}))
                }
            })
            .unwrap();
    }
    w.server.registry = Arc::new(registry);
    w.server.hosted_publication_management = true;
    let caller = w
        .caller
        .clone()
        .with_channel(crate::provenance::Channel::Web);
    // SAFETY: test-only capability for this synthetic route; never serialized.
    let caller = unsafe {
        caller
            .with_verified_hosting_session("session")
            .with_verified_hosted_cookie_session("session".into(), "fixture.db".into())
    };
    for (name, args, expected) in [
        (
            "manage_publication",
            json!({"action":"inspect","id":w.record}),
            "web",
        ),
        ("get_record", json!({"id":w.record}), "mcp"),
    ] {
        let outcome=w.server.delegate_with_caller(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}}),caller.clone()).await;
        let body = match outcome {
            RpcOutcome::Response { body, .. } => body,
            _ => panic!("expected source reply"),
        };
        assert_eq!(body["result"]["isError"], false, "{body}");
        assert_eq!(observed.lock().unwrap().last(), Some(&(name, expected)));
    }
    // Changing the admitted hosting identity clears both cookie capabilities.
    let switched = caller.with_hosting_context("other-user", "other-database");
    assert!(switched.hosted_cookie_session().is_none());
    assert!(switched.hosting_session_id().is_none());
}

#[test]
fn ready_link_renders_only_trusted_origin_plus_canonical_id() {
    use super::write_operations::render_ready_link;
    let id = "a".repeat(32);
    assert_eq!(
        render_ready_link("https://public.example.test", &id),
        Some(format!("https://public.example.test/p/{id}?app=agent.docs"))
    );
    assert_eq!(
        render_ready_link("http://127.0.0.1:4317", &id),
        Some(format!("http://127.0.0.1:4317/p/{id}?app=agent.docs"))
    );
    // Closed-form refusals: userinfo, non-root path, query, fragment,
    // non-loopback http, non-canonical IDs, and empty inputs never render.
    for origin in [
        "https://user@public.example.test",
        "https://user:pass@public.example.test",
        "https://public.example.test/base",
        "https://public.example.test?x=1",
        "https://public.example.test#frag",
        "http://public.example.test",
        "http://192.168.0.4:4317",
        "not a url",
        "",
    ] {
        assert_eq!(render_ready_link(origin, &id), None, "{origin}");
    }
    for bad_id in [
        "A".repeat(32),
        "a".repeat(31),
        "a".repeat(33),
        "g".repeat(32),
        String::new(),
    ] {
        assert_eq!(
            render_ready_link("https://public.example.test", &bad_id),
            None,
            "{bad_id}"
        );
    }
}

/// Publication must coexist with the deployed SQL, Reach and optional
/// outbox surfaces. Lean does not waive legacy profile admission.
#[cfg(feature = "v2-kernel-probe")]
#[test]
fn publication_combined_hosted_catalogues_fit_without_removing_tools() {
    use crate::mcp::registry::EngineKind;
    use crate::mcp::{
        descriptor_projection_bytes, lens_descriptor_projection, ExposureProfile, McpSurfaceMode,
    };
    for outbox in [false, true] {
        let mut registry = Arc::try_unwrap(super::tests::hosted_registry())
            .ok()
            .unwrap();
        let baseline_names: Vec<_> = registry.specs().map(|s| s.name.clone()).collect();
        crate::mcp::tools::register_publication_management_tool(&mut registry).unwrap();
        if outbox {
            crate::mcp::tools::register_outbox_status_tool(&mut registry).unwrap();
        }
        crate::mcp::kernel_v2::register_hosted_kernel_v2_tools(&mut registry).unwrap();
        for name in baseline_names {
            assert!(registry.get(&name).is_some(), "lost deployed tool {name}");
        }
        registry.validate_profile_budgets().unwrap();
        crate::mcp::validate_lens_profile_budgets(&registry).unwrap();
        for profile in ExposureProfile::ALL {
            println!(
                "publication combined outbox={outbox} {profile}: ordinary={} lens={} cap={}",
                descriptor_projection_bytes(&registry.descriptor_projection(profile)),
                descriptor_projection_bytes(
                    &lens_descriptor_projection(&registry, profile).unwrap()
                ),
                profile.max_descriptor_bytes()
            );
        }
        // Include staging's SQL-only and production's SQL+freshness
        // allowlists, for both ordinary surfaces and both engines.
        for allowlist in ["sql_write", "experimental_freshness,sql_write"] {
            let experimental =
                ExperimentalExecutors::from_env_value(Some(allowlist.into())).unwrap();
            for surface in [McpSurfaceMode::Executor, McpSurfaceMode::Lean] {
                for engine in [EngineKind::Sqlite, EngineKind::KernelV2] {
                    let pinned = ExecutorPrototypeStdioServer::pin_hosted_catalogue_for_engine(
                        &registry,
                        &experimental,
                        surface,
                        engine,
                    )
                    .unwrap();
                    assert_eq!(
                        pinned.contracts.contains_key(&(
                            "records_write".into(),
                            "manage_publication.publish".into()
                        )),
                        engine == EngineKind::KernelV2
                    );
                    assert!(pinned.descriptor_bytes() <= 96 * 1024);
                    println!("publication outbox={outbox} {allowlist} {surface} {engine:?}: {} executor bytes", pinned.descriptor_bytes());
                }
            }
            let lens = ExecutorPrototypeLensServer::pin_catalogue_with_experimental(
                &registry,
                &experimental,
            )
            .unwrap();
            assert!(lens.descriptor_bytes() <= 96 * 1024);
        }
    }
}

#[tokio::test]
async fn v2_direct_publication_executes_and_replays_in_one_call() {
    testing(true, async {
        let w = World::new().await;
        let request = prepare("publish", w.args("publish", "one-call-publish").await);
        let before = w.count().await;
        let done = w.server.handle_message(request.clone()).await.unwrap();
        let receipt = payload(&done);
        assert!(receipt.is_object(), "{done}");
        assert!(w.count().await > before, "direct call must commit");
        let state = publications::inspect_revision_as(&w.db, &w.manager, &w.record)
            .await
            .unwrap()
            .1
            .unwrap();
        assert!(state.active);
        let after = w.count().await;
        let replay = w.server.handle_message(request).await.unwrap();
        assert_eq!(payload(&replay), receipt);
        assert_eq!(w.count().await, after);
        let withdrawn = w
            .server
            .handle_message(prepare(
                "unpublish",
                w.args("unpublish", "one-call-unpublish").await,
            ))
            .await
            .unwrap();
        payload(&withdrawn);
        assert!(
            !publications::inspect_revision_as(&w.db, &w.manager, &w.record)
                .await
                .unwrap()
                .1
                .unwrap()
                .active
        );
    })
    .await;
}

#[test]
fn v2_direct_catalogue_discloses_effective_execution_and_rejects_public_plan_fields() {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    crate::mcp::tools::register_publication_management_tool(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let catalogue = build_ordinary_catalogue(
        &registry,
        EngineKind::KernelV2,
        false,
        &ExperimentalExecutors::empty(),
    )
    .unwrap();
    let snapshot = project_catalog_operations_snapshot(
        &catalogue.contracts,
        &catalogue.operations_by_executor,
    );
    for row in snapshot.iter() {
        assert!(!row.plan_required, "{}/{}", row.executor, row.operation);
        assert!(row.direct_execution_enabled);
        let contract = &catalogue.contracts[&(row.executor.clone(), row.operation.clone())];
        assert_eq!(contract.payload()["prototype"]["plan_required"], false);
        if let Some(expected) = kernel_v2_tool_description(&contract.source_tool) {
            assert_eq!(contract.payload()["source"]["tool_description"], expected);
            assert!(expected.contains("direct call"));
        }
    }
    for descriptor in &catalogue.descriptors {
        let name = descriptor["name"].as_str().unwrap();
        if matches!(name, "bootstrap" | "describe_operation") {
            continue;
        }
        let operation = catalogue.operations_by_executor[name].first().unwrap();
        let validator = jsonschema::validator_for(&descriptor["inputSchema"]).unwrap();
        assert!(
            validator.is_valid(&json!({"operation":operation,"arguments":{}})),
            "{descriptor}"
        );
        assert!(
            !validator.is_valid(
                &json!({"operation":operation,"plan_id":"forged","target":"x","effect_summary":"x"})
            ),
            "{descriptor}"
        );
    }
    assert!(catalogue
        .contracts
        .contains_key(&("identity_admin".into(), "manage_bindings.add".into())));
    // The full audited source includes newer v1 actions which the truthful
    // v2 schema omits. Their absence must withhold only those operations,
    // rather than making every v2 catalogue fail selector projection.
    for pair in [
        ("identity_read", "manage_bindings.observations"),
        ("records_write", "manage_citations.reanchor"),
    ] {
        assert!(!catalogue
            .contracts
            .contains_key(&(pair.0.into(), pair.1.into())));
    }
    // Registration alone never invents missing v2 source handlers.
    for ((executor, operation), contract) in &catalogue.contracts {
        assert!(
            registry.has_engine_operation(
                &contract.source_tool,
                EngineKind::KernelV2,
                contract
                    .selector
                    .as_ref()
                    .map(|s| (s.field.as_str(), s.value.as_str()))
            ),
            "{executor}.{operation}"
        );
    }
}

#[test]
fn v2_direct_contract_prefers_explicit_engine_schema_over_legacy_selector_schema() {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let original = registry
        .get("manage_bindings")
        .unwrap()
        .input_schema
        .clone();
    registry
        .register_operation_schema(
            "manage_bindings",
            "add",
            json!({
                "type":"object", "properties":{
                    "action":{"type":"string","const":"add"},
                    "legacy_only":{"type":"string"}
                }, "required":["action","legacy_only"]
            }),
        )
        .unwrap();
    registry
        .extend_kernel_v2_arguments(
            "manage_bindings",
            json!({
                "v2_concurrency_token":{"type":"integer"}
            }),
        )
        .unwrap();
    registry
        .isolate_kernel_v2_schema("manage_bindings", original)
        .unwrap();
    let catalogue = build_ordinary_catalogue(
        &registry,
        EngineKind::KernelV2,
        false,
        &ExperimentalExecutors::empty(),
    )
    .unwrap();
    let contract = &catalogue.contracts[&("identity_admin".into(), "manage_bindings.add".into())];
    assert_eq!(
        contract.input_schema["properties"]["v2_concurrency_token"]["type"],
        "integer"
    );
    assert!(contract.input_schema["properties"]
        .get("legacy_only")
        .is_none());
}

#[tokio::test]
async fn v2_direct_lean_tools_list_accepts_only_direct_call_envelopes() {
    let w = World::new().await;
    let listed = w
        .server
        .handle_message(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        .await
        .unwrap();
    let descriptor = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "call_executor")
        .unwrap();
    let schema = &descriptor["inputSchema"];
    let validator = jsonschema::validator_for(schema).unwrap();
    assert!(validator.is_valid(
        &json!({"executor":"records_write","operation":"manage_publication.publish","arguments":{}})
    ));
    assert!(!validator.is_valid(&json!({"executor":"records_write","operation":"manage_publication.publish","plan_id":"cached","target":"cached","effect_summary":"cached"})));
    for field in ["plan_id", "target", "effect_summary"] {
        assert!(schema["properties"].get(field).is_none());
    }
    assert!(!descriptor["description"]
        .as_str()
        .unwrap()
        .contains("prepare"));
}

#[tokio::test]
async fn v2_direct_expired_and_indeterminate_outcomes_keep_direct_guidance_and_preserve_rows() {
    testing(true, async {
        let mut w = World::new().await;
        w.server.write_runtime = Some(write_operations::WriteRuntime::with_ttl_ms(
            Arc::new(w.store.clone()),
            0,
        ));
        let request = prepare("publish", w.args("publish", "expired-direct").await);
        let before = w.count().await;
        for _ in 0..2 {
            let refused = w.server.handle_message(request.clone()).await.unwrap();
            assert_eq!(refused["result"]["isError"], true, "{refused}");
            let error = &refused["result"]["structuredContent"]["plan_error"];
            assert_eq!(error["code"], "plan_expired", "{refused}");
            assert_eq!(error["continuation"]["request_key_field"], "operation_key");
            assert!(!refused.to_string().contains("prepare the current effect"));
            assert_eq!(w.count().await, before);
        }
        let old: String =
            sqlx::query_scalar("SELECT plan_id FROM write_plans WHERE state='expired'")
                .fetch_one(w.store.local_pool())
                .await
                .unwrap();
        w.server.write_runtime = Some(write_operations::WriteRuntime::new(w.store.clone()));
        let fresh = prepare("publish", w.args("publish", "fresh-direct").await);
        let done = w.server.handle_message(fresh.clone()).await.unwrap();
        let result = payload(&done);
        for field in ["plan_id", "target", "effect_summary"] {
            assert!(result.get(field).is_none(), "{done}");
        }
        assert!(matches!(
            w.store
                .load(&old, chrono::Utc::now().timestamp_millis())
                .await
                .unwrap()
                .unwrap()
                .state,
            plan_store::StoredState::Expired
        ));
        let completed: String =
            sqlx::query_scalar("SELECT plan_id FROM write_plans WHERE state='completed'")
                .fetch_one(w.store.local_pool())
                .await
                .unwrap();
        sqlx::query("UPDATE write_plans SET state='indeterminate' WHERE plan_id=?")
            .bind(&completed)
            .execute(w.store.local_pool())
            .await
            .unwrap();
        let before = w.count().await;
        let uncertain = w.server.handle_message(fresh).await.unwrap();
        assert_eq!(
            uncertain["result"]["structuredContent"]["plan_error"]["code"],
            "plan_execution_indeterminate",
            "{uncertain}"
        );
        assert_eq!(
            uncertain["result"]["structuredContent"]["plan_error"]["continuation"]["action"],
            "inspect_state_before_retry"
        );
        assert!(!uncertain.to_string().contains("new_plan"));
        assert!(!uncertain.to_string().contains("replacement plan"));
        assert_eq!(w.count().await, before);
        assert!(matches!(
            w.store
                .load(&completed, chrono::Utc::now().timestamp_millis())
                .await
                .unwrap()
                .unwrap()
                .state,
            plan_store::StoredState::Indeterminate { .. }
        ));
    })
    .await;
}

#[tokio::test]
async fn v2_direct_prepared_request_across_catalogue_change_has_direct_recovery() {
    testing(true,async {
        let mut w=World::new().await;
        let args=w.args("publish","old-catalogue").await;
        let operation="manage_publication.publish";
        let binding=json!({"actor":w.caller.actor(),"principal":w.caller.hosting_principal().unwrap(),
            "workspace":w.caller.hosting_database().unwrap(),"database":format!("kernel-v2:{}",w.caller.hosting_database().unwrap())});
        let plan_id=format!("wpl1:direct:{}",hex::encode(sha2::Sha256::digest(serde_jcs::to_vec(&json!(["v2-direct",binding,"records_write",operation,args])).unwrap())));
        let contract=w.server.contracts[&("records_write".into(),operation.into())].clone();
        let prepared=w.server.prepare_write_plan(json!(1),true,contract,json!({"operation":operation,"arguments":args}),None,Some(plan_id.clone())).await;
        payload(&prepared);
        let before=w.count().await;
        w.server.manifest_digest="new-catalogue".into();
        let refused=w.server.handle_message(prepare("publish",args)).await.unwrap();
        assert_eq!(refused["result"]["structuredContent"]["plan_error"]["code"],"plan_contract_mismatch","{refused}");
        assert_eq!(refused["result"]["structuredContent"]["plan_error"]["continuation"]["request_key_field"],"operation_key");
        assert_eq!(w.count().await,before);
        assert!(matches!(w.store.load(&plan_id,chrono::Utc::now().timestamp_millis()).await.unwrap().unwrap().state,plan_store::StoredState::Prepared));
        payload(&w.server.handle_message(prepare("publish",w.args("publish","new-catalogue").await)).await.unwrap());
    }).await;
}
