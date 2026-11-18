//! Producer boundary and real serialized-writer races (not node cleanup tests).
use super::*;
use crate::mcp::registry::{Caller, EngineHandle, ToolRegistry};
struct Allowed;
impl RouteGuard for Allowed {
    fn recheck(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}
pub(crate) struct World {
    _dir: tempfile::TempDir,
    pub(crate) db: Db,
    pub(crate) principal: String,
    pub(crate) admin: String,
    pub(crate) home: String,
    pub(crate) origin: String,
}
pub(crate) async fn world() -> World {
    world_with_preparation(true).await
}
async fn world_with_preparation(typed: bool) -> World {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = super::super::create_v2_database(
        dir.path().join("settle.db").to_str().unwrap(),
        "account",
        "Owner",
        "acct:admin",
    )
    .await
    .unwrap();
    let principal = super::super::create_principal(&db, "account", "Member", "acct:owner", &admin)
        .await
        .unwrap();
    let home = super::super::create_home(
        &db,
        crate::events::KERNEL_ROOT_ID,
        Some(&[(&admin, "manage"), (&principal, "edit")]),
        &admin,
    )
    .await
    .unwrap();
    for package in [
        crate::v2_standard::v1_compat::package(),
        crate::v2_standard::document4_package(),
        crate::v2_standard::relates_to::package(),
    ] {
        let pin = package.identity().unwrap();
        super::super::install_package_as(&db, &admin, &package)
            .await
            .unwrap();
        super::super::adopt_package_at(
            &db,
            &admin,
            crate::events::KERNEL_ROOT_ID,
            &package,
            Some(&pin),
            &package.declared_reads,
        )
        .await
        .unwrap();
    }
    if typed {
        prepare(&db, true).await.unwrap();
    }
    let origin = origin(&db).await.unwrap();
    World {
        _dir: dir,
        db,
        principal,
        admin,
        home,
        origin,
    }
}
pub(crate) fn route(w: &World) -> AuthenticatedRoute<'_> {
    AuthenticatedRoute {
        guard: std::sync::Arc::new(Allowed),
        account: "acct:owner",
        principal: &w.principal,
        database: "test-db",
        origin: &w.origin,
        node_client: "client_node_test",
    }
}
pub(crate) fn create(w: &World, key: &str) -> Request {
    let (id, nonce) = crate::record_id::mint(
        &crate::record_id::qualified_principal(&w.principal),
        "first-party",
        [41; 32],
    );
    let args = json!({"id":id,"id_nonce":nonce,"idempotency_key":key,"type":"Document","kind":"note","name":"Pending edit","home_id":w.home,"reason":"Original settlement qualification"});
    let fp = receipts::intent_fingerprint(
        "create_record",
        args.clone(),
        json!({"app":null,"mint_context":"first-party"}),
    )
    .unwrap();
    let digest = crate::mcp::executor_prototype::original_settlement_contract(
        8,
        "create_record",
        None,
        "records_write",
        "create_record",
        None,
    )
    .unwrap()
    .unwrap();
    let mut o = Original {
        account_id: "acct:owner".into(),
        principal_id: w.principal.clone(),
        database_id: "test-db".into(),
        origin_database_id: w.origin.clone(),
        operation: "create_record".into(),
        operation_key: key.into(),
        journal_variant: 8,
        retained_contract_digest: digest,
        catalog_executor: "records_write".into(),
        catalog_operation: "create_record".into(),
        retained_provider_fingerprint: fp,
        arguments: args,
        assertion: "first_party".into(),
        app: None,
        mint_context: Some("first-party".into()),
        delegation_ref: None,
        asserting_client_id: None,
        asserting_device_id: None,
        expected_binding_sha256: String::new(),
    };
    o.expected_binding_sha256 = recompute_binding(&o).unwrap().0;
    Request {
        schema: "native.original-settlement.request.v1".into(),
        action: "settle_original".into(),
        purpose: "held_refusal_resolution".into(),
        abandon_if_unapplied: true,
        original: o,
    }
}
async fn write(w: &World, args: Value) -> Result<Value> {
    call_tool(w, "create_record", args).await
}
pub(crate) async fn call_tool(w: &World, tool: &str, args: Value) -> Result<Value> {
    let mut r = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut r)?;
    crate::mcp::register_surface_tools(&mut r)?;
    crate::mcp::kernel_v2::register_hosted_kernel_v2_tools(&mut r)?;
    crate::mcp::kernel_v2::writes::with_minted_ids_for_settlement_test(r.call_engine(
        EngineHandle::KernelV2(w.db.clone()),
        Caller::authenticated("acct:owner"),
        tool,
        args,
    ))
    .await
}
pub(crate) fn update(w: &World, id: &str, key: &str) -> Request {
    let mut r = create(w, key);
    r.original.operation = "update_record".into();
    r.original.catalog_operation = "update_record".into();
    r.original.journal_variant = 7;
    r.original.mint_context = None;
    r.original.arguments = json!({"id":id,"body_append":"Retained in-flight original edit","idempotency_key":key,"reason":"Serialized settlement qualification"});
    r.original.retained_contract_digest =
        crate::mcp::executor_prototype::original_settlement_contract(
            7,
            "update_record",
            None,
            "records_write",
            "update_record",
            None,
        )
        .unwrap()
        .unwrap();
    r.original.retained_provider_fingerprint =
        receipts::intent_fingerprint("update_record", r.original.arguments.clone(), Value::Null)
            .unwrap();
    r.original.expected_binding_sha256 = recompute_binding(&r.original).unwrap().0;
    r
}

#[tokio::test]
async fn installed_settlement_abandons_only_one_install_and_keeps_global_receipts() {
    let w = world().await;
    let id = super::super::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::DOCUMENT_FAMILY,
        "note",
        r#"{"title":"Two install settlement"}"#,
        &w.home,
    )
    .await
    .unwrap();
    let original = update(&w, &id, "both-installations").original;
    let a = "a".repeat(64);
    let b = "b".repeat(64);
    let route = route(&w);
    let status =
        |install, action| installed::settle(&w.db, &route, install, action, original.clone());
    assert_eq!(
        status(&a, installed::Action::Status).await.unwrap()["verdict"],
        "absent"
    );
    let abandoned = status(&a, installed::Action::Abandon).await.unwrap();
    assert_eq!(abandoned["verdict"], "unapplied_terminal");
    assert_eq!(abandoned["install_id"], a);
    assert_eq!(
        status(&b, installed::Action::Status).await.unwrap()["verdict"],
        "absent"
    );
    assert!(installed::validate_answer(&original, &a, &abandoned).is_ok());
    assert!(installed::validate_answer(&original, &b, &abandoned).is_err());
    let absent = update(&w, &id, "another-install-original").original;
    let mut tx = w.db.write_pool().begin().await.unwrap();
    {
        let mut snapshot = outcome_profile::verified_outcomes_on(&mut tx)
            .await
            .unwrap();
        assert!(installed::prove_terminal_inclusion(
            &mut snapshot,
            &w.principal,
            &a,
            &original.expected_binding_sha256,
            &abandoned,
        )
        .await
        .unwrap()
        .is_some());
        let mut wrong_native_event = abandoned.clone();
        wrong_native_event["native"]["canonical_event_id"] = json!("different-event");
        assert!(installed::prove_terminal_inclusion(
            &mut snapshot,
            &w.principal,
            &a,
            &original.expected_binding_sha256,
            &wrong_native_event,
        )
        .await
        .is_err());
        let mut without_fact = abandoned.clone();
        without_fact["original_binding_sha256"] = json!(absent.expected_binding_sha256);
        without_fact["namespace_sha256"] = json!(namespace(&absent));
        assert!(installed::prove_terminal_inclusion(
            &mut snapshot,
            &w.principal,
            &a,
            &absent.expected_binding_sha256,
            &without_fact,
        )
        .await
        .unwrap()
        .is_none());
    }
    tx.rollback().await.unwrap();
    // A direct writer uses the same global receipt namespace that a future
    // enrolled writer will use. Install A's fact never retires this key.
    let committed = call_tool(&w, &original.operation, original.arguments.clone())
        .await
        .unwrap();
    let retry = call_tool(&w, &original.operation, original.arguments.clone())
        .await
        .unwrap();
    assert_eq!(committed, retry);
    assert_eq!(
        status(&b, installed::Action::Status).await.unwrap()["verdict"],
        "accepted"
    );
    assert_eq!(
        status(&a, installed::Action::Abandon).await.unwrap(),
        abandoned
    );
    let mut conflicting = original.clone();
    conflicting.arguments["body_append"] = json!("another version");
    conflicting.retained_provider_fingerprint =
        receipts::intent_fingerprint("update_record", conflicting.arguments.clone(), Value::Null)
            .unwrap();
    conflicting.expected_binding_sha256 = recompute_binding(&conflicting).unwrap().0;
    let mismatch = installed::settle(
        &w.db,
        &route,
        &b,
        installed::Action::Abandon,
        conflicting.clone(),
    )
    .await
    .unwrap();
    assert_eq!(mismatch["verdict"], "mismatch");
    assert!(
        call_tool(&w, &conflicting.operation, conflicting.arguments.clone())
            .await
            .is_err()
    );
    let effects: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE record_id=? AND payload LIKE '%Retained in-flight original edit%'",
    ).bind(&id).fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(effects, 1);
}

#[tokio::test]
async fn installed_write_blocks_an_abandoned_install_and_deduplicates_the_other_installs() {
    let w = world().await;
    let id = super::super::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::DOCUMENT_FAMILY,
        "note",
        r#"{"title":"Scoped write qualification"}"#,
        &w.home,
    )
    .await
    .unwrap();
    let original = update(&w, &id, "installed-after-observe").original;
    use std::sync::atomic::{AtomicBool, Ordering};
    struct CurrentGrant(AtomicBool);
    impl RouteGuard for CurrentGrant {
        fn recheck(
            &self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
            Box::pin(async move {
                if self.0.load(Ordering::Acquire) {
                    Ok(())
                } else {
                    Err(Error::auth("fixture grant revoked"))
                }
            })
        }
    }
    let current_grant = std::sync::Arc::new(CurrentGrant(AtomicBool::new(true)));
    let mut route = route(&w);
    route.guard = current_grant.clone();
    let install_a = "a".repeat(64);
    let install_b = "b".repeat(64);
    let install_c = "c".repeat(64);

    let mut unkeyed = original.clone();
    unkeyed
        .arguments
        .as_object_mut()
        .unwrap()
        .remove("idempotency_key");
    assert!(
        installed::custody::observe(&w.db, &route, &install_a, 1, &unkeyed)
            .await
            .is_err()
    );
    let fenced = installed::settle(
        &w.db,
        &route,
        &install_a,
        installed::Action::Abandon,
        original.clone(),
    )
    .await
    .unwrap();
    assert_eq!(fenced["verdict"], "unapplied_terminal");
    installed::custody::observe(&w.db, &route, &install_a, 1, &original)
        .await
        .unwrap();
    assert!(matches!(
        installed::write(&w.db, &route, &install_a, 1, original.clone()).await,
        Err(Error::Conflict(_))
    ));
    let page = installed::custody::read_page(&w.db, &route, &install_a, 0)
        .await
        .unwrap();
    assert_eq!(page.high_water, 1);
    assert_eq!(
        page.observed[0].original_binding_sha256,
        original.expected_binding_sha256
    );
    let page = installed::custody::read_page(&w.db, &route, &install_b, 0)
        .await
        .unwrap();
    assert_eq!(page.high_water, 0);

    assert!(
        installed::write(&w.db, &route, &install_b, 1, original.clone())
            .await
            .is_err()
    );
    installed::custody::observe(&w.db, &route, &install_b, 1, &original)
        .await
        .unwrap();
    current_grant.0.store(false, Ordering::Release);
    assert!(matches!(
        installed::write(&w.db, &route, &install_b, 1, original.clone()).await,
        Err(Error::Auth(_)),
    ));
    current_grant.0.store(true, Ordering::Release);
    let applied = installed::write(&w.db, &route, &install_b, 1, original.clone())
        .await
        .unwrap();
    installed::custody::observe(&w.db, &route, &install_c, 1, &original)
        .await
        .unwrap();
    let duplicate = installed::write(&w.db, &route, &install_c, 1, original.clone())
        .await
        .unwrap();
    assert_eq!(applied, duplicate);
    let effects: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE record_id=? AND payload LIKE '%Retained in-flight original edit%'",
    ).bind(&id).fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(effects, 1);
}

#[tokio::test]
async fn settlement_fences_key_and_record_id_in_all_retry_shapes() {
    let w = world().await;
    let request = create(&w, "held-key");
    let answer = settle(&w.db, &route(&w), request.clone()).await.unwrap();
    assert_eq!(answer["verdict"], "unapplied_terminal", "{answer}");
    let repeated = settle(&w.db, &route(&w), request.clone()).await.unwrap();
    assert_eq!(repeated, answer);
    for key in [Some("held-key"), Some("other-key"), None] {
        let mut args = request.original.arguments.clone();
        args["name"] = json!("A different fingerprint cannot bypass retirement");
        if let Some(k) = key {
            args["idempotency_key"] = json!(k)
        } else {
            args.as_object_mut().unwrap().remove("idempotency_key");
        }
        let error = write(&w, args).await.unwrap_err();
        let Error::OriginalConflict(c) = error else {
            panic!("expected typed fence: {error:?}")
        };
        assert_eq!(c.fence_id, answer["fence"]["fence_id"].as_str().unwrap());
        assert_eq!(
            c.native_fence.canonical_event_id,
            answer["fence"]["native"]["canonical_event_id"]
        );
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_records WHERE id=?")
        .bind(request.original.arguments["id"].as_str().unwrap())
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}
#[tokio::test]
async fn settlement_accepted_is_reference_only_and_remains_after_record_revocation() {
    let w = world().await;
    // Another principal owns the record, so removing the member's home grant
    // really removes Edit (record owners retain a legitimate Manage floor).
    let id = super::super::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::DOCUMENT_FAMILY,
        "note",
        r#"{"title":"Admin-owned original"}"#,
        &w.home,
    )
    .await
    .unwrap();
    let request = update(&w, &id, "accepted-key");
    let receipt = call_tool(&w, "update_record", request.original.arguments.clone())
        .await
        .unwrap();
    let answer = settle(&w.db, &route(&w), request.clone()).await.unwrap();
    assert_eq!(answer["verdict"], "accepted", "{answer}");
    assert!(answer["receipt"].get("raw_json").is_none());
    assert!(answer.to_string().contains("receipt_sha256"));
    assert!(!answer.to_string().contains("Pending edit"));
    assert_eq!(receipt["id"], request.original.arguments["id"]);
    super::super::replace_home_policy(&w.db, &w.admin, &w.home, &[(&w.admin, "manage")])
        .await
        .unwrap();
    let cap = super::super::kernel_effective_capability(
        &w.db,
        &w.principal,
        receipt["id"].as_str().unwrap(),
    )
    .await
    .unwrap();
    assert!(
        !cap.allows(crate::authorization::Capability::Edit),
        "test must actually revoke Edit"
    );
    assert_eq!(settle(&w.db, &route(&w), request).await.unwrap(), answer);
    let unapplied = update(&w, &id, "unapplied-after-revocation");
    let abandoned = settle(&w.db, &route(&w), unapplied).await.unwrap();
    assert_eq!(abandoned["verdict"], "unapplied_terminal", "{abandoned}");
    assert_eq!(abandoned["fence"]["reason"], "owner_abandoned_unapplied");
}
#[tokio::test]
async fn settlement_unknown_contract_binding_and_identity_never_fence() {
    let w = world().await;
    let r = create(&w, "unsupported");
    for field in [
        "contract",
        "default_create",
        "principal",
        "fingerprint",
        "catalog",
        "unsupported_graph",
        "historical_client",
        "delegation",
        "host_assertion",
    ] {
        let mut r = r.clone();
        match field {
            "contract" => {
                r.original.retained_contract_digest = "a".repeat(64);
                r.original.expected_binding_sha256 = recompute_binding(&r.original).unwrap().0;
            }
            "default_create" => {
                r.original.retained_contract_digest =
                    "f78f2d13c41eb5e481b4bb63e1be105acd03a28c2b3ea3aa164b7f6c49ebe881".into();
                r.original.expected_binding_sha256 = recompute_binding(&r.original).unwrap().0;
            }
            "unsupported_graph" => r.original.operation = "create_many".into(),
            "historical_client" => {
                r.original.asserting_client_id = Some("fabricated-client".into())
            }
            "delegation" => r.original.delegation_ref = Some("unsupported-delegation".into()),
            "host_assertion" => r.original.assertion = "host".into(),
            "principal" => r.original.principal_id = "rebound".into(),
            "catalog" => {
                r.original.catalog_operation = "manage_links.add".into();
                r.original.expected_binding_sha256 = recompute_binding(&r.original).unwrap().0;
            }
            _ => r.original.retained_provider_fingerprint = "{}".into(),
        }
        let a = settle(&w.db, &route(&w), r).await.unwrap();
        assert_eq!(a["verdict"], "status_required", "{field}: {a}");
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events WHERE type=?")
        .bind(fences::EVENT)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}
#[tokio::test]
async fn settlement_writer_wins_or_aborts_with_no_race_window() {
    use crate::coedit::live::kernel_writes::{test_gate, TestStage};
    for fail in [false, true] {
        let w = std::sync::Arc::new(world().await);
        let base = create(&w, "base");
        let created = write(&w, base.original.arguments).await.unwrap();
        let id = created["id"].as_str().unwrap().to_owned();
        let original = update(&w, &id, "writer-race");
        let gate = test_gate(&w.db, TestStage::AfterMutation, fail);
        let (writer_world, args) = (w.clone(), original.original.arguments.clone());
        let writer =
            tokio::spawn(async move { call_tool(&writer_world, "update_record", args).await });
        gate.entered.notified().await; // Actual domain effects and receipt are still uncommitted.
        let checkout = test_gate(&w.db, TestStage::BeforeOwnedLane, false);
        let (settle_world, request) = (w.clone(), original.clone());
        let settler = tokio::spawn(async move {
            settle(&settle_world.db, &route(&settle_world), request)
                .await
                .unwrap()
        });
        checkout.entered.notified().await;
        checkout.release.notify_one();
        gate.release.notify_one();
        let written = writer.await.unwrap();
        let answer = settler.await.unwrap();
        if fail {
            assert!(written.is_err());
            assert_eq!(answer["verdict"], "unapplied_terminal", "{answer}");
        } else {
            assert!(written.is_ok(), "{written:?}");
            assert_eq!(answer["verdict"], "accepted", "{answer}");
        }
        let repeated = settle(&w.db, &route(&w), original).await.unwrap();
        assert_eq!(repeated, answer);
    }
}
#[tokio::test]
async fn settlement_fence_wins_before_original_update_reaches_writer() {
    let w = world().await;
    let base = create(&w, "base");
    let created = write(&w, base.original.arguments).await.unwrap();
    let original = update(&w, created["id"].as_str().unwrap(), "fence-race");
    let answer = settle(&w.db, &route(&w), original.clone()).await.unwrap();
    assert_eq!(answer["verdict"], "unapplied_terminal");
    let error = call_tool(&w, "update_record", original.original.arguments)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::OriginalConflict(_)), "{error:?}");
}

#[tokio::test]
async fn settlement_sql_guards_work_with_recursive_triggers_off() {
    let w = world().await;
    let r = create(&w, "guarded");
    settle(&w.db, &route(&w), r).await.unwrap();
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let recursive: i64 = sqlx::query_scalar("PRAGMA recursive_triggers")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(recursive, 0);
    for statement in ["DELETE FROM kernel_mcp_write_receipts","UPDATE kernel_mcp_write_receipts SET receipt_json='{}',terminal_json=NULL,retired_record_id=NULL,outcome_kind='accepted'","INSERT OR REPLACE INTO kernel_mcp_write_receipts(principal_id,operation,operation_key,request_json,receipt_json,outcome_kind) SELECT principal_id,operation,operation_key,request_json,'{}','accepted' FROM kernel_mcp_write_receipts"]{
        assert!(sqlx::query(statement).execute(&mut *tx).await.is_err(),"{statement}");
    }
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn settlement_lost_response_retains_guard_until_durable_fence() {
    struct Blocking {
        entered: std::sync::Arc<tokio::sync::Notify>,
        release: std::sync::Arc<tokio::sync::Notify>,
        finished: std::sync::Arc<tokio::sync::Notify>,
    }
    impl RouteGuard for Blocking {
        fn recheck(
            &self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
            Box::pin(async move {
                self.entered.notify_one();
                self.release.notified().await;
                Ok(())
            })
        }
    }
    impl Drop for Blocking {
        fn drop(&mut self) {
            self.finished.notify_one();
        }
    }
    let w = std::sync::Arc::new(world().await);
    let request = create(&w, "lost-response");
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let finished = std::sync::Arc::new(tokio::sync::Notify::new());
    let guard = std::sync::Arc::new(Blocking {
        entered: entered.clone(),
        release: release.clone(),
        finished: finished.clone(),
    });
    let task_world = w.clone();
    let original = request.clone();
    let response = tokio::spawn(async move {
        let mut route = route(&task_world);
        route.guard = guard;
        settle(&task_world.db, &route, original).await
    });
    entered.notified().await;
    response.abort();
    let _ = response.await;
    release.notify_one();
    finished.notified().await;
    let recovered = settle(&w.db, &route(&w), request).await.unwrap();
    assert_eq!(recovered["verdict"], "unapplied_terminal", "{recovered}");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events WHERE type=?")
        .bind(fences::EVENT)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn original_settlement_rebuild_preserves_terminal_and_typed_lookup() {
    let w = world().await;
    let r = create(&w, "rebuild-fence");
    let a = settle(&w.db, &route(&w), r.clone()).await.unwrap();
    let before = super::super::projection_dump::dump(&w.db).await.unwrap();
    super::super::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        super::super::projection_dump::dump(&w.db).await.unwrap(),
        before
    );
    assert_eq!(settle(&w.db, &route(&w), r.clone()).await.unwrap(), a);
    let mut conn = w.db.pool().acquire().await.unwrap();
    assert!(matches!(
        lookup_outcome_on(&mut conn, &w.principal, "create_record", "rebuild-fence")
            .await
            .unwrap(),
        KeyedOutcome::Terminal { .. }
    ));
}

#[tokio::test]
async fn original_settlement_import_retired_id_is_per_record_and_rolls_back() {
    let w = world().await;
    let r = create(&w, "import-fence");
    let a = settle(&w.db, &route(&w), r.clone()).await.unwrap();
    let host = super::super::resolve_principal_by_binding(&w.db, super::super::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let state = super::super::hq::ImportRecordState {
        message: None,
        persona: None,
        message_principal: None,
        metadata: None,
        definition: None,
        body: Some("Imported recovery text".into()),
        facets: vec![],
        archived: false,
    };
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let err = super::super::hq::import_record_as(
        &w.db,
        &host,
        r.original.arguments["id"].as_str().unwrap(),
        &w.home,
        None,
        &state,
    )
    .await
    .unwrap_err();
    let Error::OriginalConflict(c) = err else {
        panic!("expected typed import conflict: {err:?}")
    };
    assert_eq!(c.fence_id, a["fence"]["fence_id"]);
    assert_eq!(
        c.native_fence.canonical_event_id,
        a["fence"]["native"]["canonical_event_id"]
    );
    assert_eq!(
        before,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap()
    );
    let delta = super::super::hq::resume_record_with_blob_as(
        &w.db,
        &host,
        r.original.arguments["id"].as_str().unwrap(),
        &w.home,
        None,
        &state,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(delta, Error::OriginalConflict(_)), "{delta:?}");
    let unrelated = uuid::Uuid::new_v4().to_string();
    super::super::hq::import_record_as(&w.db, &host, &unrelated, &w.home, None, &state)
        .await
        .unwrap();
}

#[tokio::test]
async fn original_settlement_canonical_create_before_fence_replays_but_new_create_conflicts() {
    let w = world().await;
    let r = create(&w, "ordered-fence");
    write(&w, r.original.arguments.clone()).await.unwrap();
    let id = r.original.arguments["id"].as_str().unwrap();
    // Normal settlement must not fence the occupied ID under another key.
    assert_eq!(
        settle(&w.db, &route(&w), create(&w, "different-key"))
            .await
            .unwrap()["verdict"],
        "status_required"
    );
    // Sealed restore fixture: historical create predates a later retirement.
    // It deliberately bypasses producer absence admission, never append gates.
    let fact = FenceFact {
        format: 1,
        operation: r.original.operation.clone(),
        operation_key: "ordered-restore".into(),
        request_json: r.original.retained_provider_fingerprint.clone(),
        terminal: Terminal {
            schema: "native.original-fence.v1".into(),
            fence_id: Uuid::new_v4().to_string(),
            reason: "owner_abandoned_unapplied".into(),
            scope: "entire_idempotency_namespace".into(),
            retired_record_id: Some(id.into()),
            namespace_sha256: String::new(),
            original_binding_sha256: String::new(),
            account_id: r.original.account_id.clone(),
            principal_id: w.principal.clone(),
            database_id: r.original.database_id.clone(),
            origin_database_id: w.origin.clone(),
            journal_variant: 8,
            retained_contract_digest: r.original.retained_contract_digest.clone(),
            catalog_executor: r.original.catalog_executor.clone(),
            catalog_operation: r.original.catalog_operation.clone(),
            mint_context: Some("first-party".into()),
            delegation_ref: None,
            assertion: "first_party".into(),
            app: None,
            asserting_client_id: None,
            asserting_device_id: None,
            settled_by_client_id: "client_node_test".into(),
        },
    };
    let mut historical = r.original.clone();
    historical.operation_key = "ordered-restore".into();
    historical.arguments["idempotency_key"] = json!("ordered-restore");
    let mut fact = fact;
    fact.terminal.original_binding_sha256 = recompute_binding(&historical).unwrap().0;
    fact.terminal.namespace_sha256 = namespace(&historical);
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let fence = crate::store::append_kernel_mcp_receipt_on(
        &w.db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: receipts::STREAM.into(),
            event_type: fences::EVENT.into(),
            payload: serde_json::to_value(fact).unwrap(),
            actor: Some(w.principal.clone()),
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    // Full chronological rebuild must preserve the legitimate earlier create.
    let before = super::super::projection_dump::dump(&w.db).await.unwrap();
    super::super::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        super::super::projection_dump::dump(&w.db).await.unwrap(),
        before
    );
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let later = EventRow {
        local_seq: fence.local_seq + 1,
        id: Uuid::new_v4().to_string(),
        record_id: id.into(),
        event_type: "kernel.record_created.v1".into(),
        payload: Some("{}".into()),
        actor: Some(w.principal.clone()),
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: fence.created_at,
        causal_envelope: crate::events::CausalEnvelopeV1::legacy_unknown(),
        act: None,
    };
    let err = super::super::project_kernel_record_created(&mut tx, &later)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::OriginalConflict(_)), "{err:?}");
    let mut forged = later;
    forged.local_seq = fence.local_seq - 1;
    assert!(matches!(
        fences::refuse_retired_on(&mut tx, id, Some(&forged))
            .await
            .unwrap_err(),
        Error::OriginalConflict(_)
    ));
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn original_settlement_legacy_receipt_migrates_without_reauthoring_bytes() {
    let w = world().await;
    let original = create(&w, "migration-success");
    write(&w, original.original.arguments.clone())
        .await
        .unwrap();
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let bytes:(String,String)=sqlx::query_as("SELECT request_json,receipt_json FROM kernel_mcp_write_receipts WHERE operation_key='migration-success'").fetch_one(&mut *tx).await.unwrap();
    sqlx::query("DROP TABLE kernel_mcp_write_receipts")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("DROP INDEX idx_kernel_mcp_write_fence_events")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE kernel_mcp_write_receipts (principal_id TEXT NOT NULL, operation TEXT NOT NULL, operation_key TEXT NOT NULL, request_json TEXT NOT NULL, receipt_json TEXT NOT NULL, PRIMARY KEY(principal_id,operation,operation_key))").execute(&mut *tx).await.unwrap();
    sqlx::query(
        "INSERT INTO kernel_mcp_write_receipts VALUES(?,'create_record','migration-success',?,?)",
    )
    .bind(&w.principal)
    .bind(&bytes.0)
    .bind(&bytes.1)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let old = crate::standby::kernel_v2::coordinates(&mut w.db.pool().acquire().await.unwrap())
        .await
        .unwrap();
    assert_eq!(old.reader_format, 1);
    let a = settle(&w.db, &route(&w), original.clone()).await.unwrap();
    assert_eq!(
        a["verdict"], "status_required",
        "legacy producer must never mutate on doubt"
    );
    assert_eq!(a["reason"], "settlement_preparation_required");
    assert_eq!(a["terminal"], false);
    prepare(&w.db, true).await.unwrap();
    let migrated:(String,String)=sqlx::query_as("SELECT request_json,receipt_json FROM kernel_mcp_write_receipts WHERE operation_key='migration-success'").fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(bytes, migrated);
    let a = settle(&w.db, &route(&w), original.clone()).await.unwrap();
    assert_eq!(a["verdict"], "accepted", "{a}");
    let new = crate::standby::kernel_v2::coordinates(&mut w.db.pool().acquire().await.unwrap())
        .await
        .unwrap();
    assert_eq!(new.reader_format, 2);
    let old_shape = crate::standby::shapes::v2(1, &old.schema_sha256)
        .unwrap()
        .shape();
    let new_shape = crate::standby::shapes::v2(2, &new.schema_sha256)
        .unwrap()
        .shape();
    assert!(!crate::standby::shapes::follows(
        crate::standby::shapes::lookup(&old_shape).unwrap(),
        crate::standby::shapes::lookup(&new_shape).unwrap()
    ));
    let adv = json!({"version":1,"shapes":[old_shape]}).to_string();
    assert!(crate::standby::shapes::negotiate(&new_shape, Some(&adv)).is_err());
}

#[tokio::test]
async fn original_settlement_receipt_identity_mismatch_never_fences_or_reauthors() {
    let w = world().await;
    let original = create(&w, "occupied-key");
    write(&w, original.original.arguments.clone())
        .await
        .unwrap();
    let answer = settle(&w.db, &route(&w), original.clone()).await.unwrap();
    assert_eq!(answer["verdict"], "accepted");
    let mut other = original.clone();
    other.original.arguments["name"] = json!("Different intent");
    other.original.retained_provider_fingerprint = receipts::intent_fingerprint(
        "create_record",
        other.original.arguments.clone(),
        json!({"app":null,"mint_context":"first-party"}),
    )
    .unwrap();
    other.original.expected_binding_sha256 = recompute_binding(&other.original).unwrap().0;
    let mismatch = settle(&w.db, &route(&w), other).await.unwrap();
    assert_eq!(mismatch["verdict"], "mismatch", "{mismatch}");
    assert_eq!(settle(&w.db, &route(&w), original).await.unwrap(), answer);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM content_events WHERE type='kernel.mcp_write_fenced.v1'"
        )
        .fetch_one(w.db.pool())
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn original_settlement_concurrent_calls_share_one_fence_and_changed_request_core() {
    struct Block {
        entered: std::sync::Arc<tokio::sync::Notify>,
        release: std::sync::Arc<tokio::sync::Notify>,
    }
    impl RouteGuard for Block {
        fn recheck(
            &self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
            Box::pin(async move {
                self.entered.notify_one();
                self.release.notified().await;
                Ok(())
            })
        }
    }
    use crate::coedit::live::kernel_writes::{test_gate, TestStage};
    let w = std::sync::Arc::new(world().await);
    let original = create(&w, "concurrent-settlement");
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let guard = std::sync::Arc::new(Block {
        entered: entered.clone(),
        release: release.clone(),
    });
    let first_world = w.clone();
    let first_original = original.clone();
    let first = tokio::spawn(async move {
        let mut r = route(&first_world);
        r.guard = guard;
        settle(&first_world.db, &r, first_original).await.unwrap()
    });
    entered.notified().await;
    let queued = test_gate(&w.db, TestStage::BeforeOwnedLane, false);
    let second_world = w.clone();
    let second_original = original.clone();
    let second = tokio::spawn(async move {
        settle(&second_world.db, &route(&second_world), second_original)
            .await
            .unwrap()
    });
    queued.entered.notified().await;
    queued.release.notify_one();
    release.notify_one();
    let a = first.await.unwrap();
    assert_eq!(second.await.unwrap(), a);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM content_events WHERE type='kernel.mcp_write_fenced.v1'"
        )
        .fetch_one(w.db.pool())
        .await
        .unwrap(),
        1
    );
    let mut changed = original;
    changed.original.arguments["name"] = json!("Changed retained intent");
    changed.original.retained_provider_fingerprint = receipts::intent_fingerprint(
        "create_record",
        changed.original.arguments.clone(),
        json!({"app":null,"mint_context":"first-party"}),
    )
    .unwrap();
    changed.original.expected_binding_sha256 = recompute_binding(&changed.original).unwrap().0;
    let b = settle(&w.db, &route(&w), changed).await.unwrap();
    assert_eq!(b["verdict"], "unapplied_terminal");
    assert_eq!(b["fence"], a["fence"]);
    assert_eq!(b["namespace_sha256"], a["namespace_sha256"]);
    assert_ne!(b["original_binding_sha256"], a["original_binding_sha256"]);
}

#[tokio::test]
async fn original_settlement_variant_nine_binds_native_archive_and_link_actions() {
    let w = world().await;
    let base = create(&w, "native-base");
    let receipt = write(&w, base.original.arguments.clone()).await.unwrap();
    let id = receipt["id"].as_str().unwrap();
    let target = super::super::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::DOCUMENT_FAMILY,
        "note",
        r#"{"title":"Link target"}"#,
        &w.home,
    )
    .await
    .unwrap();
    for (source, executor, operation, action, key) in [
        (
            "archive_record",
            "records_lifecycle",
            "archive_record",
            None,
            "native-archive",
        ),
        (
            "manage_links",
            "records_write",
            "manage_links.add",
            Some("add"),
            "native-add",
        ),
        (
            "manage_links",
            "records_write",
            "manage_links.remove",
            Some("remove"),
            "native-remove",
        ),
    ] {
        let mut r = base.clone();
        let o = &mut r.original;
        o.journal_variant = 9;
        o.operation = source.into();
        o.catalog_executor = executor.into();
        o.catalog_operation = operation.into();
        o.operation_key = key.into();
        o.mint_context = None;
        o.arguments = if let Some(action) = action {
            json!({"action":action,"source_id":id,"target_id":target,"relationship":"relates_to","idempotency_key":key})
        } else {
            json!({"id":id,"archived":true,"reason":"Native variant-9 qualification","idempotency_key":key})
        };
        o.retained_contract_digest = crate::mcp::executor_prototype::original_settlement_contract(
            9, source, action, executor, operation, None,
        )
        .unwrap()
        .unwrap();
        o.retained_provider_fingerprint =
            receipts::intent_fingerprint(source, o.arguments.clone(), Value::Null).unwrap();
        o.expected_binding_sha256 = recompute_binding(o).unwrap().0;
        let a = settle(&w.db, &route(&w), r.clone()).await.unwrap();
        assert_eq!(a["verdict"], "unapplied_terminal", "{operation}: {a}");
        assert!(matches!(
            call_tool(&w, source, r.original.arguments)
                .await
                .unwrap_err(),
            Error::OriginalConflict(_)
        ));
    }
}

#[tokio::test]
async fn original_settlement_off_default_creation_and_first_write_stay_legacy() {
    let (db, principal) =
        super::super::create_v2_database(":memory:", "account", "Legacy default", "acct:legacy")
            .await
            .unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pragma_table_info('kernel_mcp_write_receipts')")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(count, 5);
    // Also exercise the lazy creation boundary: no ledger exists until this
    // database's first keyed write. Serving must not promote it to reader 2.
    sqlx::query("DROP TABLE kernel_mcp_write_receipts")
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    receipts::record_on(
        &db,
        &mut tx,
        &mut crate::act::ActAllocation::new(),
        receipts::Outcome {
            principal: &principal,
            operation: "update_record",
            key: "first-key",
            request: "{}",
            receipt: r#"{"original":true}"#,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM pragma_table_info('kernel_mcp_write_receipts')"
        )
        .fetch_one(db.pool())
        .await
        .unwrap(),
        5
    );
    let generation =
        crate::standby::kernel_v2::coordinates(&mut db.pool().acquire().await.unwrap())
            .await
            .unwrap();
    assert_eq!(generation.reader_format, 1);
    // The previous release's positional INSERT remains valid with preparation off.
    sqlx::query(
        "INSERT INTO kernel_mcp_write_receipts VALUES(?,'update_record','old-release','{}','{}')",
    )
    .bind(&principal)
    .execute(db.write_pool())
    .await
    .unwrap();
    assert!(prepare(&db, false).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM pragma_table_info('kernel_mcp_write_receipts')"
        )
        .fetch_one(db.pool())
        .await
        .unwrap(),
        5
    );
    prepare(&db, true).await.unwrap();
    assert_eq!(
        crate::standby::kernel_v2::coordinates(&mut db.pool().acquire().await.unwrap())
            .await
            .unwrap()
            .reader_format,
        2
    );
    let bytes: String = sqlx::query_scalar(
        "SELECT receipt_json FROM kernel_mcp_write_receipts WHERE operation_key='first-key'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(bytes, r#"{"original":true}"#);
}

#[tokio::test]
async fn original_settlement_variant_nine_create_and_update_keep_original_variant_and_identity() {
    for operation in ["create_record", "update_record"] {
        let w = world().await;
        let mut r = if operation == "create_record" {
            create(&w, "nine-create")
        } else {
            let seed = create(&w, "seed-nine-update");
            let applied = write(&w, seed.original.arguments).await.unwrap();
            update(&w, applied["id"].as_str().unwrap(), "nine-update")
        };
        r.original.journal_variant = 9;
        r.original.expected_binding_sha256 = recompute_binding(&r.original).unwrap().0;
        let binding = r.original.expected_binding_sha256.clone();
        let answer = settle(&w.db, &route(&w), r.clone()).await.unwrap();
        assert_eq!(answer["verdict"], "unapplied_terminal", "{answer}");
        assert_eq!(answer["original_binding_sha256"], binding);
        assert_eq!(settle(&w.db, &route(&w), r.clone()).await.unwrap(), answer);
        let mut conn = w.db.pool().acquire().await.unwrap();
        let KeyedOutcome::Terminal { fact, .. } = lookup_outcome_on(
            &mut conn,
            &w.principal,
            operation,
            &r.original.operation_key,
        )
        .await
        .unwrap() else {
            panic!("expected original terminal")
        };
        assert_eq!(fact.terminal.journal_variant, 9);
        assert_eq!(
            fact.terminal.retained_contract_digest,
            r.original.retained_contract_digest
        );
        assert_eq!(fact.request_json, r.original.retained_provider_fingerprint);
        assert_eq!(fact.terminal.mint_context, r.original.mint_context);
        drop(conn);
        assert!(matches!(
            call_tool(&w, operation, r.original.arguments.clone())
                .await
                .unwrap_err(),
            Error::OriginalConflict(_)
        ));
        if operation == "create_record" {
            assert_eq!(
                r.original.retained_contract_digest,
                "79c37864d58d7fa2b3e55e2f13cb075658cae8ecd01b2f84b3e8d80b944dfff2"
            );
            let mut wrong = r.clone();
            wrong.original.mint_context = None;
            assert!(recompute_binding(&wrong.original).is_err());
            wrong = r.clone();
            wrong.original.retained_contract_digest =
                "f78f2d13c41eb5e481b4bb63e1be105acd03a28c2b3ea3aa164b7f6c49ebe881".into();
            wrong.original.expected_binding_sha256 = recompute_binding(&wrong.original).unwrap().0;
            assert_eq!(
                settle(&w.db, &route(&w), wrong).await.unwrap()["reason"],
                "profile_unsupported"
            );
        }
    }
}

// No producer flag is enabled and no settlement producer is called. Cover an
// unprepared legacy database and a previously prepared typed database whose
// producer is off. Optional accelerators must not become write authority.
#[tokio::test]
async fn original_settlement_first_lazy_receipt_index_flag_off_writes_and_probes() {
    async fn remove_indexes(db: &Db) {
        for name in [
            "idx_kernel_mcp_write_receipt_events",
            "idx_kernel_mcp_write_fence_events",
            "idx_kernel_mcp_retired_record_id",
        ] {
            sqlx::query(&format!("DROP INDEX IF EXISTS {name}"))
                .execute(db.write_pool())
                .await
                .unwrap();
        }
    }
    let mut failures = Vec::new();
    for typed in [false, true] {
        let w = world_with_preparation(typed).await;
        assert!(prepare(&w.db, false).await.is_err());
        let seed = super::super::create_record_as(&w.db, &w.admin, &w.home)
            .await
            .unwrap();
        remove_indexes(&w.db).await;
        let mut args = create(&w, "no-key").original.arguments;
        args.as_object_mut().unwrap().remove("idempotency_key");
        let created = write(&w, args).await;
        println!(
            "lazy indexes typed={typed} unkeyed create: {}",
            created.is_ok()
        );
        if let Err(error) = created {
            failures.push(format!("typed={typed} create: {error}"));
        }
        remove_indexes(&w.db).await;
        let updated = call_tool(&w, "update_record", json!({"id":seed,"body_append":"Lazy index proof","reason":"Optional index qualification","idempotency_key":"lazy-update"})).await;
        println!(
            "lazy indexes typed={typed} keyed update: {}",
            updated.is_ok()
        );
        if let Err(error) = updated {
            failures.push(format!("typed={typed} update: {error}"));
        }
        // A successful keyed write builds the accelerator normally. Remove it
        // again so coverage/settlement probes must work without lazy DDL.
        remove_indexes(&w.db).await;
        let mut tx = w.db.write_pool().begin().await.unwrap();
        for (label, result) in [
            (
                "key fence",
                fences::refuse_key_on(&mut tx, &w.principal, "update_record", "absent").await,
            ),
            (
                "retired ID",
                fences::refuse_retired_on(&mut tx, "not-retired", None).await,
            ),
            (
                "canonical coverage",
                receipts::require_covered_on(&mut tx).await,
            ),
            (
                "head identity coverage",
                receipts::require_head_identity_coverage_on(&mut tx).await,
            ),
        ] {
            if let Err(error) = result {
                failures.push(format!("typed={typed} {label}: {error}"));
            }
        }
        let accepted = sqlx::query_as::<_, (String, String, String)>(receipts::ACCEPTED_LOOKUP_SQL)
            .bind(&w.principal)
            .bind("update_record")
            .bind("lazy-update")
            .fetch_all(&mut *tx)
            .await;
        match accepted {
            Ok(rows) if rows.len() == 1 => (),
            other => failures.push(format!("typed={typed} accepted receipt: {other:?}")),
        }
        if typed {
            if !matches!(
                lookup_outcome_on(&mut tx, &w.principal, "update_record", "lazy-update").await,
                Ok(KeyedOutcome::Accepted { .. })
            ) {
                failures.push("typed accepted lookup failed".into());
            }
            if !matches!(
                lookup_outcome_on(&mut tx, &w.principal, "update_record", "absent").await,
                Ok(KeyedOutcome::Absent)
            ) {
                failures.push("typed absent lookup failed".into());
            }
        }
        let indexes:i64=sqlx::query_scalar("SELECT count(*) FROM main.sqlite_schema WHERE type='index' AND name IN ('idx_kernel_mcp_write_receipt_events','idx_kernel_mcp_write_fence_events','idx_kernel_mcp_retired_record_id')").fetch_one(&mut *tx).await.unwrap();
        assert_eq!(indexes, 0, "probes must not run lazy DDL");
        tx.rollback().await.unwrap();
        w.db.close().await;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
