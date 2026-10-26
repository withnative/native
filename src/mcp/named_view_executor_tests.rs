//! Real executor routing for the closed producer gate.
pub(crate) mod tests {
    use super::super::*;
    struct ViewAuthority {
        catalog: crate::Db,
        entered: std::sync::Mutex<Option<Arc<tokio::sync::Semaphore>>>,
        release: std::sync::Mutex<Option<Arc<tokio::sync::Semaphore>>>,
        acquisitions: std::sync::atomic::AtomicUsize,
    }
    impl ViewAuthority {
        async fn new(dir: &std::path::Path, roles: &[(&str, &str)]) -> Arc<Self> {
            let catalog =
                crate::db::create_database(dir.join("catalog-fixture.db").to_str().unwrap())
                    .await
                    .unwrap();
            sqlx::query("CREATE TABLE fixture_roles(user_id TEXT PRIMARY KEY, role TEXT NOT NULL)")
                .execute(catalog.write_pool())
                .await
                .unwrap();
            for (user, role) in roles {
                sqlx::query("INSERT INTO fixture_roles VALUES(?,?)")
                    .bind(user)
                    .bind(role)
                    .execute(catalog.write_pool())
                    .await
                    .unwrap();
            }
            Arc::new(Self {
                catalog,
                entered: std::sync::Mutex::new(None),
                release: std::sync::Mutex::new(None),
                acquisitions: std::sync::atomic::AtomicUsize::new(0),
            })
        }
    }
    impl HostedPlanCatalogue for ViewAuthority {
        fn executor_plan_pool(&self) -> &sqlx::SqlitePool {
            self.catalog.pool()
        }
    }
    impl HostedExecutorAuthority for ViewAuthority {
        fn acquire_sql_commit_authority<'a>(
            &'a self,
            caller: &'a Caller,
        ) -> futures::future::BoxFuture<'a, Result<sqlx::Transaction<'static, sqlx::Sqlite>>>
        {
            Box::pin(async move {
                // Observe the guard entry itself, independently of where the
                // caller places its carried proof or post-acquisition trace.
                crate::mcp::kernel_v2::writes::named_views::note_commit_phase("guard");
                let mut tx = crate::db::begin_write(self.catalog.write_pool()).await?;
                let role: String =
                    sqlx::query_scalar("SELECT role FROM fixture_roles WHERE user_id=?")
                        .bind(caller.hosting_principal().unwrap())
                        .fetch_one(&mut *tx)
                        .await?;
                if (role == "owner") != caller.is_host_owner() {
                    return Err(Error::Conflict(
                        "SQL commit membership changed since ingress".into(),
                    ));
                }
                self.acquisitions
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let entered = self.entered.lock().unwrap().take();
                let release = self.release.lock().unwrap().take();
                if let Some(entered) = entered {
                    entered.add_permits(1);
                }
                if let Some(release) = release {
                    release.acquire().await.unwrap().forget();
                }
                Ok(tx)
            })
        }
        fn validate_membership_write(&self, _: Value) -> Result<()> {
            Err(Error::engine("membership fixture does not expose writes"))
        }
        fn prepare_membership_write<'a>(
            &'a self,
            _: &'a crate::Db,
            _: &'a Caller,
            _: Value,
        ) -> futures::future::BoxFuture<'a, Result<HostedMembershipPreparation>> {
            Box::pin(async {
                Err(Error::engine(
                    "membership fixture does not expose preparation",
                ))
            })
        }
    }

    pub(crate) async fn named_view_operations_gate_off_through_source_app_and_call_executor() {
        let dir = tempfile::tempdir().unwrap();
        let (db, _) = crate::kernel::create_v2_database(
            dir.path().join("views.db").to_str().unwrap(),
            "account",
            "Admin",
            "acct:admin",
        )
        .await
        .unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
        let registry = Arc::new(registry);
        let caller =
            Caller::authenticated("acct:admin").with_hosting_context("account", "workspace");
        let store = plan_store::PlanStore::open_for_database(db.path())
            .await
            .unwrap();
        let server = ExecutorPrototypeStdioServer::new_with_plan_store(
            registry.clone(),
            EngineHandle::KernelV2(db.clone()),
            caller.clone(),
            None,
            ExecutorConstruction {
                plan_store: Some(store),
                hosted_authority: None,
                pinned_catalogue: None,
                experimental: ExperimentalExecutors::empty(),
                lean: true,
                telemetry: TelemetryConstruction::Disabled,
                transport: telemetry::TelemetryTransport::Http,
                deployment_mutation_barrier: None,
            },
        )
        .await
        .unwrap();
        // Normal preparation may install optional indexes while producers stay
        // off. The source operation must not install a missing one when off.
        sqlx::query("DROP INDEX idx_kernel_named_view_lifecycle")
            .execute(db.write_pool())
            .await
            .unwrap();
        let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        for (executor, operation) in [
            ("records_read", "get_view_revision"),
            ("records_read", "list_view_revisions"),
            ("records_write", "record_view_revision"),
            ("records_write", "activate_view"),
            ("records_write", "unpublish_view"),
            ("records_write", "prepare_named_views"),
        ] {
            let operation_args = match operation {
                "get_view_revision" => {
                    json!({"view_id":"native.named-view:bearer","revision_id":"11111111-1111-4111-8111-111111111111"})
                }
                "list_view_revisions" => json!({"view_id":"native.named-view:bearer"}),
                "record_view_revision" => {
                    json!({"id":"bearer","definition":{},"idempotency_key":"closed"})
                }
                "activate_view" => {
                    json!({"id":"bearer","pin":{},"name":"view_closed","expected_binding_event_id":null,"idempotency_key":"closed"})
                }
                "unpublish_view" => {
                    json!({"id":"bearer","expected_binding_event_id":null,"idempotency_key":"closed"})
                }
                _ => json!({}),
            };
            let mut args = operation_args.clone();
            args["action"] = json!(operation);
            let error = registry
                .call_engine(
                    EngineHandle::KernelV2(db.clone()),
                    caller.clone(),
                    "manage_named_views",
                    args.clone(),
                )
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("disabled"), "{operation}: {error}");
            let app = caller.clone().with_host_asserted_app(
                crate::mcp::app_attribution::AppAttribution::new(
                    "test.app",
                    "1.0.0",
                    "installation",
                )
                .unwrap(),
            );
            assert!(registry
                .call_engine(
                    EngineHandle::KernelV2(db.clone()),
                    app,
                    "manage_named_views",
                    args
                )
                .await
                .is_err());
            let body=server.handle_message(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":executor,"operation":operation,"arguments":operation_args}}})).await.unwrap();
            assert!(
                serde_json::to_string(&body).unwrap().contains("disabled"),
                "{operation}: {body}"
            );
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            before
        );
        assert!(!crate::named_views::storage::verify_index_on(
            &mut db.pool().acquire().await.unwrap()
        )
        .await
        .unwrap());
    }

    pub(crate) async fn named_view_executor_plan_prepares_without_writing_and_commits_exactly_once()
    {
        for race in [None, Some("drift"), Some("cas")] {
            publication_plan_fixture(race).await;
        }
    }
    async fn publication_plan_fixture(race: Option<&'static str>) {
        let dir = tempfile::tempdir().unwrap();
        let (db, admin) = crate::kernel::create_v2_database(
            dir.path().join("plan.db").to_str().unwrap(),
            "account",
            "Admin",
            "acct:admin",
        )
        .await
        .unwrap();
        let home = crate::kernel::create_home(
            &db,
            crate::events::KERNEL_ROOT_ID,
            Some(&[(&admin, "manage")]),
            &admin,
        )
        .await
        .unwrap();
        let id = crate::kernel::create_record_as(&db, &admin, &home)
            .await
            .unwrap();
        let source_id = crate::kernel::create_record_as(&db, &admin, &home)
            .await
            .unwrap();
        let event_id: String = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
        )
        .bind(&source_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let mut tx = db.pool().begin().await.unwrap();
        let event = crate::named_views::read_event(&mut tx, &event_id, i64::MAX)
            .await
            .unwrap();
        let mut definition = crate::named_views::testing_definition();
        definition["source_pins"] = json!([{"record_id":source_id,"revision_id":event_id,"sha256":crate::named_views::closure::source_digest(&event).unwrap()}]);
        tx.rollback().await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
        let registry = Arc::new(registry);
        let caller = Caller::authenticated("acct:admin")
            .with_hosting_context("account", "workspace")
            .with_hosting_owner(true);
        let store = plan_store::PlanStore::open_for_database(db.path())
            .await
            .unwrap();
        let authority = ViewAuthority::new(dir.path(), &[("account", "owner")]).await;
        let mut server = ExecutorPrototypeStdioServer::new_with_plan_store(
            registry.clone(),
            EngineHandle::KernelV2(db.clone()),
            caller.clone(),
            None,
            ExecutorConstruction {
                plan_store: Some(store.clone()),
                hosted_authority: Some(authority.clone()),
                pinned_catalogue: None,
                experimental: ExperimentalExecutors::empty(),
                lean: true,
                telemetry: TelemetryConstruction::Disabled,
                transport: telemetry::TelemetryTransport::Http,
                deployment_mutation_barrier: None,
            },
        )
        .await
        .unwrap();
        let dispatch_gate = race.map(|_| server.set_view_dispatch_gate());
        let server = Arc::new(server);
        let work = async {
            let draft=registry.call_engine(EngineHandle::KernelV2(db.clone()),caller.clone(),"manage_named_views",json!({"action":"record_view_revision","id":id,"definition":definition,"idempotency_key":"draft-plan"})).await.unwrap();
            let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap();
            let prepared=server.handle_message(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"records_write","operation":"activate_view","arguments":{"id":id,"pin":draft["pin"],"name":"view_planned","expected_binding_event_id":null,"idempotency_key":"activate-plan"}}}})).await.unwrap();
            assert_eq!(prepared["result"]["isError"], false, "{prepared}");
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                    .fetch_one(db.pool())
                    .await
                    .unwrap(),
                before
            );
            // Ordinary data changes do not change the approved exact definition.
            crate::kernel::create_record_as(&db, &admin, &home)
                .await
                .unwrap();
            let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap();
            let plan = &prepared["result"]["structuredContent"];
            let source_args = json!({"action":"activate_view","idempotency_key":"activate-plan"});
            let preparations_before =
                crate::mcp::kernel_v2::writes::named_views::preparation_count(&db, &source_args);
            let request = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"records_write","operation":"activate_view","plan_id":plan["plan_id"],"target":plan["target"],"effect_summary":plan["effect_summary"]}}});
            if let Some(gate) = dispatch_gate {
                let running = {
                    let server = server.clone();
                    let request = request.clone();
                    tokio::spawn(crate::named_views::gate::testing(
                        true,
                        crate::mcp::kernel_v2::writes::named_views::trace_commit(async move {
                            server.handle_message(request).await.unwrap()
                        }),
                    ))
                };
                gate.entered.acquire().await.unwrap().forget();
                if race == Some("drift") {
                    let source = crate::kernel::read_record_as(&db, &admin, &source_id)
                        .await
                        .unwrap()
                        .unwrap();
                    crate::kernel::set_archived_as(&db, &admin, &source_id, true, source.revision)
                        .await
                        .unwrap();
                } else {
                    let publication = caller.clone().with_write_plan_execution(
                        crate::mcp::registry::WritePlanExecution {
                            plan_id: "racing-plan".into(),
                            effect_digest: "racing-effect".into(),
                            executor: "records_write".into(),
                            operation: "activate_view".into(),
                        },
                    );
                    registry.call_engine(EngineHandle::KernelV2(db.clone()), publication, "manage_named_views", json!({"action":"activate_view","id":id,"pin":draft["pin"],"name":"view_racer","expected_binding_event_id":null,"idempotency_key":"racing-activation"})).await.unwrap();
                }
                let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
                    .fetch_one(db.pool())
                    .await
                    .unwrap();
                gate.release.add_permits(1);
                let (failed, trace) = running.await.unwrap();
                assert_eq!(
                    trace,
                    ["prepare"],
                    "preflight must run once, before any catalog guard"
                );
                assert_eq!(
                    crate::mcp::kernel_v2::writes::named_views::preparation_count(
                        &db,
                        &source_args
                    ),
                    preparations_before + 1
                );
                assert_eq!(failed["result"]["isError"], true, "{failed}");
                let text = failed.to_string();
                assert!(!text.contains("indeterminate"), "{failed}");
                assert!(
                    text.contains(if race == Some("cas") {
                        "plan_stale"
                    } else {
                        "preparation_rejected"
                    }),
                    "{failed}"
                );
                assert_eq!(server.view_dispatch_attempts(), 0);
                assert_eq!(
                    authority
                        .acquisitions
                        .load(std::sync::atomic::Ordering::SeqCst),
                    0
                );
                assert!(matches!(
                    store
                        .load(
                            plan["plan_id"].as_str().unwrap(),
                            chrono::Utc::now().timestamp_millis()
                        )
                        .await
                        .unwrap()
                        .unwrap()
                        .state,
                    plan_store::StoredState::Prepared
                ));
                assert_eq!(
                    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                        .fetch_one(db.pool())
                        .await
                        .unwrap(),
                    before
                );
                return;
            }
            let (executed, trace) = crate::mcp::kernel_v2::writes::named_views::trace_commit(
                server.handle_message(request.clone()),
            )
            .await;
            let executed = executed.unwrap();
            assert_eq!(trace, ["prepare", "guard"], "fresh analysis must happen exactly once before the guard, even if dispatch loses its carried proof");
            assert_eq!(
                crate::mcp::kernel_v2::writes::named_views::preparation_count(&db, &source_args),
                preparations_before + 1,
                "count preparations independently of task-local proof and trace"
            );
            assert_eq!(executed["result"]["isError"], false, "{executed}");
            let after: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap();
            assert_eq!(after, before + 1);
            let source = crate::kernel::read_record_as(&db, &admin, &source_id)
                .await
                .unwrap()
                .unwrap();
            crate::kernel::set_archived_as(&db, &admin, &source_id, true, source.revision)
                .await
                .unwrap();
            let after: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap();
            let retry = server.handle_message(request).await.unwrap();
            assert_eq!(retry["result"]["isError"], false, "{retry}");
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                    .fetch_one(db.pool())
                    .await
                    .unwrap(),
                after
            );
        };
        crate::named_views::gate::testing(true, work).await;
    }
    pub(crate) async fn named_view_owner_role_and_demotion() {
        let dir = tempfile::tempdir().unwrap();
        let (db, admin) = crate::kernel::create_v2_database(
            dir.path().join("roles.db").to_str().unwrap(),
            "account",
            "Admin",
            "acct:admin",
        )
        .await
        .unwrap();
        let publisher =
            crate::kernel::create_principal(&db, "account", "Publisher", "acct:publisher", &admin)
                .await
                .unwrap();
        let second =
            crate::kernel::create_principal(&db, "account", "Second owner", "acct:second", &admin)
                .await
                .unwrap();
        let editor =
            crate::kernel::create_principal(&db, "account", "Editor", "acct:editor", &admin)
                .await
                .unwrap();
        let home = crate::kernel::create_home(
            &db,
            crate::events::KERNEL_ROOT_ID,
            Some(&[(&publisher, "edit"), (&second, "edit"), (&editor, "edit")]),
            &admin,
        )
        .await
        .unwrap();
        let id = crate::kernel::create_record_as(&db, &admin, &home)
            .await
            .unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
        let registry = Arc::new(registry);
        // Multiple workspace owners; the publisher has Edit and
        // no home Manage. The member editor can draft but cannot publish.
        let authority = ViewAuthority::new(
            dir.path(),
            &[
                ("publisher", "owner"),
                ("other-owner", "owner"),
                ("standing-owner", "owner"),
                ("editor", "member"),
            ],
        )
        .await;
        let owner = Caller::authenticated("acct:publisher")
            .with_hosting_context("publisher", "workspace")
            .with_hosting_owner(true);
        let member = Caller::authenticated("acct:editor")
            .with_hosting_context("editor", "workspace")
            .with_hosting_owner(false);
        let make_server = |caller: Caller| {
            let registry = registry.clone();
            let db = db.clone();
            let authority = authority.clone();
            async move {
                let store = plan_store::PlanStore::open_for_database(db.path())
                    .await
                    .unwrap();
                Arc::new(
                    ExecutorPrototypeStdioServer::new_with_plan_store(
                        registry,
                        EngineHandle::KernelV2(db),
                        caller,
                        None,
                        ExecutorConstruction {
                            plan_store: Some(store),
                            hosted_authority: Some(authority),
                            pinned_catalogue: None,
                            experimental: ExperimentalExecutors::empty(),
                            lean: true,
                            telemetry: TelemetryConstruction::Disabled,
                            transport: telemetry::TelemetryTransport::Http,
                            deployment_mutation_barrier: None,
                        },
                    )
                    .await
                    .unwrap(),
                )
            }
        };
        let second_caller = Caller::authenticated("acct:second")
            .with_hosting_context("other-owner", "workspace")
            .with_hosting_owner(true);
        let second_server = make_server(second_caller.clone()).await;
        let server = make_server(owner.clone()).await;
        let member_server = make_server(member.clone()).await;
        let work = async {
            let draft = registry.call_engine(EngineHandle::KernelV2(db.clone()),member,"manage_named_views",json!({"action":"record_view_revision","id":id,"definition":crate::named_views::testing_definition(),"idempotency_key":"member-draft"})).await.unwrap();
            let prepare_request = |operation: &str, args: Value| json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"records_write","operation":operation,"arguments":args}}});
            let activation = json!({"id":id,"pin":draft["pin"],"name":"view_role","expected_binding_event_id":null,"idempotency_key":"owner-publish"});
            let denied = member_server
                .handle_message(prepare_request("activate_view", activation.clone()))
                .await
                .unwrap();
            assert!(
                denied
                    .to_string()
                    .contains("view_publication_requires_workspace_owner"),
                "{denied}"
            );
            let prepared = server
                .handle_message(prepare_request("activate_view", activation))
                .await
                .unwrap();
            assert_eq!(prepared["result"]["isError"], false, "{prepared}");
            let execute_request = |operation: &str, prepared: &Value| {
                let plan = &prepared["result"]["structuredContent"];
                json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"records_write","operation":operation,"plan_id":plan["plan_id"],"target":plan["target"],"effect_summary":plan["effect_summary"]}}})
            };
            let request = execute_request("activate_view", &prepared);
            let entered = Arc::new(tokio::sync::Semaphore::new(0));
            let release = Arc::new(tokio::sync::Semaphore::new(0));
            *authority.entered.lock().unwrap() = Some(entered.clone());
            *authority.release.lock().unwrap() = Some(release.clone());
            let publishing = {
                let server = server.clone();
                let request = request.clone();
                tokio::spawn(crate::named_views::gate::testing(true, async move {
                    server.handle_message(request).await.unwrap()
                }))
            };
            entered.acquire().await.unwrap().forget();
            // Demotion must wait for the same catalog writer guard. Once it
            // obtains the writer, the publication must already be committed.
            let demoting = {
                let authority = authority.clone();
                let db = db.clone();
                tokio::spawn(async move {
                    let mut tx = crate::db::begin_write(authority.catalog.write_pool())
                        .await
                        .unwrap();
                    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events WHERE type='kernel.named_view_binding_changed.v1'").fetch_one(db.pool()).await.unwrap();
                    assert_eq!(count, 1, "demotion serialized before publication commit");
                    sqlx::query("UPDATE fixture_roles SET role='member' WHERE user_id='publisher'")
                        .execute(&mut *tx)
                        .await
                        .unwrap();
                    tx.commit().await.unwrap();
                })
            };
            release.add_permits(1);
            let published = publishing.await.unwrap();
            assert_eq!(published["result"]["isError"], false, "{published}");
            demoting.await.unwrap();
            let demoted = owner.clone().with_hosting_owner(false);
            let demoted_server = make_server(demoted.clone()).await;
            let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap();
            let acquisitions = authority
                .acquisitions
                .load(std::sync::atomic::Ordering::SeqCst);
            let replay = demoted_server
                .handle_message(request.clone())
                .await
                .unwrap();
            assert_eq!(replay["result"]["isError"], false, "{replay}");
            assert!(published["result"]["structuredContent"].is_object());
            assert_eq!(
                replay["result"]["structuredContent"], published["result"]["structuredContent"],
                "return the original receipt"
            );

            assert_eq!(
                authority
                    .acquisitions
                    .load(std::sync::atomic::Ordering::SeqCst),
                acquisitions,
                "receipt replay must not acquire owner authority"
            );
            for operation in ["activate_view", "unpublish_view"] {
                let args = if operation == "activate_view" {
                    json!({"id":id,"pin":draft["pin"],"name":"view_renamed","expected_binding_event_id":null,"idempotency_key":"demoted-rename"})
                } else {
                    json!({"id":id,"expected_binding_event_id":null,"idempotency_key":"demoted-unpublish"})
                };
                let denied = demoted_server
                    .handle_message(prepare_request(operation, args))
                    .await
                    .unwrap();
                assert!(
                    denied
                        .to_string()
                        .contains("view_publication_requires_workspace_owner"),
                    "{denied}"
                );
            }
            let visible = crate::mcp::kernel_v2::sql::query_sql(
                &db,
                &publisher,
                json!({"sql":"SELECT id FROM view_role ORDER BY id LIMIT 1"}),
            )
            .await
            .unwrap();
            assert!(
                !visible["rows"].as_array().unwrap().is_empty(),
                "demotion must not unpublish"
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                    .fetch_one(db.pool())
                    .await
                    .unwrap(),
                before
            );
            let binding: String = sqlx::query_scalar("SELECT id FROM content_events WHERE type='kernel.named_view_binding_changed.v1' ORDER BY seq DESC LIMIT 1").fetch_one(db.pool()).await.unwrap();
            let removal = second_server.handle_message(prepare_request("unpublish_view", json!({"id":id,"expected_binding_event_id":binding,"idempotency_key":"owner-unpublish"}))).await.unwrap();
            assert_eq!(removal["result"]["isError"], false, "{removal}");
            let remove_request = execute_request("unpublish_view", &removal);
            let removed = second_server
                .handle_message(remove_request.clone())
                .await
                .unwrap();
            assert_eq!(removed["result"]["isError"], false, "{removed}");
            sqlx::query("UPDATE fixture_roles SET role='member' WHERE user_id='other-owner'")
                .execute(authority.catalog.write_pool())
                .await
                .unwrap();
            let second_demoted = make_server(second_caller.with_hosting_owner(false)).await;
            let acquisitions = authority
                .acquisitions
                .load(std::sync::atomic::Ordering::SeqCst);
            let removed_replay = second_demoted
                .handle_message(remove_request.clone())
                .await
                .unwrap();
            assert_eq!(
                removed_replay["result"]["isError"], false,
                "{removed_replay}"
            );
            assert!(removed["result"]["structuredContent"].is_object());
            assert_eq!(
                removed_replay["result"]["structuredContent"],
                removed["result"]["structuredContent"]
            );
            assert_eq!(
                authority
                    .acquisitions
                    .load(std::sync::atomic::Ordering::SeqCst),
                acquisitions
            );
            crate::kernel::replace_home_policy(&db, &admin, &home, &[(&editor, "edit")])
                .await
                .unwrap();
            for (server, request) in [
                (&demoted_server, request),
                (&second_demoted, remove_request),
            ] {
                let refused = server.handle_message(request).await.unwrap();
                assert_eq!(
                    refused["result"]["isError"], true,
                    "revoked access must refuse receipt replay: {refused}"
                );
            }
            // A stale ingress owner snapshot is also refused by the unchanged
            // catalog guard, not accepted merely because its flag says owner.
            assert!(authority
                .acquire_sql_commit_authority(&owner)
                .await
                .is_err());
        };
        crate::named_views::gate::testing(true, work).await;
    }
}

#[tokio::test]
async fn named_view_v2_draft_refuses_source_app_and_indirect_executor_with_gate_open() {
    use super::*;
    let dir = tempfile::tempdir().unwrap();
    let (db, actor) = crate::kernel::create_v2_database(
        dir.path().join("reader.db").to_str().unwrap(),
        "account",
        "Owner",
        "acct:owner",
    )
    .await
    .unwrap();
    let bearer = crate::kernel::create_record_as(&db, &actor, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let registry = Arc::new(registry);
    let caller = Caller::authenticated("acct:owner").with_hosting_context("account", "workspace");
    let store = plan_store::PlanStore::open_for_database(db.path())
        .await
        .unwrap();
    let server = ExecutorPrototypeStdioServer::new_with_plan_store(
        registry.clone(),
        EngineHandle::KernelV2(db.clone()),
        caller.clone(),
        None,
        ExecutorConstruction {
            plan_store: Some(store),
            hosted_authority: None,
            pinned_catalogue: None,
            experimental: ExperimentalExecutors::empty(),
            lean: true,
            telemetry: TelemetryConstruction::Disabled,
            transport: telemetry::TelemetryTransport::Http,
            deployment_mutation_barrier: None,
        },
    )
    .await
    .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    crate::named_views::gate::testing(true,async {
        let args=json!({"id":bearer,"definition":crate::named_views::testing_v2_definition(),"idempotency_key":"reader-only"});
        let mut source_args=args.clone();source_args["action"]=json!("record_view_revision");
        let error=registry.call_engine(EngineHandle::KernelV2(db.clone()),caller.clone(),"manage_named_views",source_args.clone()).await.unwrap_err().to_string();
        assert!(error.contains("unknown field") && error.contains("generated"),"{error}");
        let app=caller.clone().with_host_asserted_app(crate::mcp::app_attribution::AppAttribution::new("test.app","1.0.0","installation").unwrap());
        assert!(registry.call_engine(EngineHandle::KernelV2(db.clone()),app,"manage_named_views",source_args).await.is_err());
        let body=server.handle_message(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"records_write","operation":"record_view_revision","arguments":args}}})).await.unwrap();
        let text=serde_json::to_string(&body).unwrap();
        assert!(text.contains("unknown field") && text.contains("generated"),"{text}");
    }).await;
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after);
}
