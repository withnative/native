use super::*;
use crate::Error;
use std::collections::BTreeSet;

#[tokio::test]
async fn named_view_validation_caches_success_and_failure_by_exact_closure() {
    use crate::query::sql::view_validation;
    let (pin, def) = planned(
        &uuid::Uuid::new_v4().to_string(),
        "SELECT id FROM records",
        static_records(),
    );
    let roots = BTreeMap::from([("view_cached".into(), pin.clone())]);
    let good = closure::build(&roots, &BTreeMap::from([(pin, def)])).unwrap();
    for _ in 0..2 {
        view_validation::analyze(&good, Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
    }
    assert_eq!(view_validation::builds(&good.digest), 1);
    let (pin, def) = planned(
        &uuid::Uuid::new_v4().to_string(),
        "SELECT missing AS id FROM view_child",
        BTreeMap::from([(
            "view_child".into(),
            contract::Dependency::View(good.nodes[0].pin.clone()),
        )]),
    );
    let bad = closure::build(
        &BTreeMap::from([("view_cached".into(), pin.clone())]),
        &BTreeMap::from([
            (pin, def),
            (good.nodes[0].pin.clone(), good.nodes[0].definition.clone()),
        ]),
    )
    .unwrap();
    let first = view_validation::analyze(&bad, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        first,
        view_validation::analyze(&bad, Instant::now() + Duration::from_secs(2))
            .await
            .unwrap_err()
            .to_string()
    );
    assert_eq!(view_validation::builds(&bad.digest), 1);
}

#[tokio::test]
async fn named_view_pinned_read_keeps_one_snapshot_and_cancellation_cleans() {
    use crate::{events::KERNEL_ROOT_ID, kernel, mcp::kernel_v2};
    use std::sync::Arc;
    use tokio::sync::Barrier;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snapshot.db");
    let (db, actor) =
        kernel::create_v2_database(path.to_str().unwrap(), "account", "Admin", "acct:admin")
            .await
            .unwrap();
    let home = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&actor, "manage")]), &actor)
        .await
        .unwrap();
    let bearer = kernel::create_record_as(&db, &actor, &home).await.unwrap();
    let (pin, def) = planned(
        &bearer,
        &format!("SELECT id FROM records WHERE id='{bearer}' AND archived=0"),
        static_records(),
    );
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    insert_retained_definition(&mut tx, &pin, &def, None).await;
    tx.commit().await.unwrap();
    let (_, query) = planned(
        "query",
        "SELECT id FROM view_snapshot",
        BTreeMap::from([("view_snapshot".into(), contract::Dependency::View(pin))]),
    );
    let arrived = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    let read_db = db.clone();
    let read_actor = actor.clone();
    let read_query = query.query.clone();
    let task = tokio::spawn(kernel_v2::sql::with_named_read_pause(
        arrived.clone(),
        resume.clone(),
        async move { kernel_v2::query_pinned_saved_sql(&read_db, &read_actor, &read_query).await },
    ));
    tokio::time::timeout(Duration::from_secs(10), arrived.wait())
        .await
        .unwrap();
    let record = kernel::read_record_as(&db, &actor, &bearer)
        .await
        .unwrap()
        .unwrap();
    kernel::set_archived_as(&db, &actor, &bearer, true, record.revision)
        .await
        .unwrap();
    resume.wait().await;
    assert_eq!(task.await.unwrap().unwrap()["rows"], json!([{"id":bearer}]));
    assert!(kernel_v2::query_pinned_saved_sql(&db, &actor, &query.query)
        .await
        .is_err());
    let record = kernel::read_record_as(&db, &actor, &bearer)
        .await
        .unwrap()
        .unwrap();
    kernel::set_archived_as(&db, &actor, &bearer, false, record.revision)
        .await
        .unwrap();
    let arrived = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    let read_db = db.clone();
    let read_actor = actor.clone();
    let read_query = query.query.clone();
    let task = tokio::spawn(kernel_v2::sql::with_named_registered_pause(
        arrived.clone(),
        resume,
        async move { kernel_v2::query_pinned_saved_sql(&read_db, &read_actor, &read_query).await },
    ));
    tokio::time::timeout(Duration::from_secs(10), arrived.wait())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    // Hold every pool slot at once, so the assertion covers the canceled slot
    // if it was reused as well as every other surviving connection.
    let mut slots = Vec::new();
    for _ in 0..db.governed_pool().options().get_max_connections() {
        slots.push(db.governed_pool().acquire().await.unwrap());
    }
    for slot in &mut slots {
        let leaks: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_schema WHERE name LIKE '%native_view%' OR name LIKE 'view_%'")
            .fetch_one(&mut **slot).await.unwrap();
        assert_eq!(leaks, 0);
    }
    drop(slots);
    assert_eq!(
        kernel_v2::query_pinned_saved_sql(&db, &actor, &query.query)
            .await
            .unwrap()["rows"],
        json!([{"id":bearer}])
    );
}

#[tokio::test]
async fn named_view_hosted_exact_execution_keeps_b1_on_a1_and_cleans_temp() {
    use crate::{events::KERNEL_ROOT_ID, kernel};
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    let home = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&admin, "manage")]), &admin)
        .await
        .unwrap();
    let a = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let b = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let (a1, d1) = planned(
        &a,
        &format!("SELECT id FROM records WHERE id='{a}'"),
        static_records(),
    );
    let (a2, d2) = planned(&a, "SELECT id FROM records WHERE 0", static_records());
    let (b1, db1) = planned(
        &b,
        "SELECT id FROM view_a",
        BTreeMap::from([("view_a".into(), contract::Dependency::View(a1.clone()))]),
    );
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    for (p, d) in [(&a1, &d1), (&a2, &d2), (&b1, &db1)] {
        insert_retained_definition(&mut tx, p, d, None).await;
    }
    tx.commit().await.unwrap();
    let (_, q) = planned(
        "query",
        "SELECT b.id FROM view_b b LEFT JOIN view_a a ON a.id=b.id",
        BTreeMap::from([
            ("view_a".into(), contract::Dependency::View(a2)),
            ("view_b".into(), contract::Dependency::View(b1)),
        ]),
    );
    let result = crate::mcp::kernel_v2::query_pinned_saved_sql(&db, &admin, &q.query)
        .await
        .unwrap();
    assert_eq!(result["rows"], json!([{"id":a}]));
    assert!(result["view_provenance"]["closure_digest"]
        .as_str()
        .is_some());
    let mut dependencies = static_records();
    dependencies.insert(
        "view_unused".into(),
        contract::Dependency::View(q.query.roots()["view_b"].clone()),
    );
    let (_, mut pruned) = planned(
        "query",
        &format!(
            "WITH unused AS (SELECT id FROM view_unused) SELECT id FROM records WHERE id='{a}'"
        ),
        dependencies,
    );
    let observed = crate::mcp::kernel_v2::query_pinned_saved_sql(&db, &admin, &pruned.query)
        .await
        .unwrap();
    assert!(observed["view_provenance"]["roots"]
        .get("view_unused")
        .is_some());
    if let contract::Dependency::View(pin) = pruned.query.relations.get_mut("view_unused").unwrap()
    {
        pin.revision_id = uuid::Uuid::new_v4().to_string();
    }
    assert!(
        crate::mcp::kernel_v2::query_pinned_saved_sql(&db, &admin, &pruned.query)
            .await
            .unwrap_err()
            .to_string()
            .contains("view_revision_unavailable")
    );
    let mut conn = db.governed_pool().acquire().await.unwrap();
    let leaked:i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_schema WHERE name LIKE '%native_view%' OR name LIKE 'view_%'").fetch_one(&mut *conn).await.unwrap();
    assert_eq!(leaked, 0);
}

#[tokio::test]
async fn named_view_details_are_one_read_bounded_and_visibility_safe() {
    use crate::{events::KERNEL_ROOT_ID, kernel, mcp::kernel_v2};
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    let viewer = kernel::create_principal(&db, "account", "Viewer", "acct:viewer", &admin)
        .await
        .unwrap();
    let home = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&viewer, "view")]), &admin)
        .await
        .unwrap();
    let private = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[]), &admin)
        .await
        .unwrap();
    let public = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let hidden = kernel::create_record_as(&db, &admin, &private)
        .await
        .unwrap();
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let mut pins = Vec::new();
    for _ in 0..9 {
        let (pin, def) = planned(&public, "SELECT id FROM records", static_records());
        insert_retained_definition(&mut tx, &pin, &def, None).await;
        pins.push(pin);
    }
    let (hidden_pin, hidden_def) = planned(&hidden, "SELECT id FROM records", static_records());
    insert_retained_definition(&mut tx, &hidden_pin, &hidden_def, None).await;
    let (dep_pin, dep_def) = planned(
        &public,
        "SELECT id FROM view_hidden",
        BTreeMap::from([(
            "view_hidden".into(),
            contract::Dependency::View(hidden_pin.clone()),
        )]),
    );
    insert_retained_definition(&mut tx, &dep_pin, &dep_def, None).await;
    for (name, pin) in [
        ("view_public", pins[0].clone()),
        ("view_hidden", hidden_pin.clone()),
    ] {
        let payload = serde_json::to_string(&Transition {
            v: 1,
            view_id: pin.view_id.clone(),
            expected: None,
            action: Action::Activate {
                name: name.into(),
                pin: pin.clone(),
            },
        })
        .unwrap();
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,1,'legacy_unknown')").bind(uuid::Uuid::new_v4().to_string()).bind(pin.view_id.strip_prefix("native.named-view:").unwrap()).bind(TRANSITION).bind(payload).bind("2026-10-25").execute(&mut *tx).await.unwrap();
    }
    tx.commit().await.unwrap();
    let result=kernel_v2::sql::query_sql(&db,&viewer,json!({"sql":"SELECT relation_name,revision_id,columns_json FROM catalog_view_definitions ORDER BY relation_name"})).await.unwrap();
    assert_eq!(result["row_count"], 1);
    assert_eq!(result["rows"][0]["revision_id"], pins[0].revision_id);
    assert!(result["rows"][0]["columns_json"]
        .as_str()
        .unwrap()
        .contains("Stable record identity"));
    assert!(!serde_json::to_string(&result)
        .unwrap()
        .contains("SELECT id"));
    let mut refusals = Vec::new();
    for name in ["view_hidden", "view_nonexistent"] {
        refusals.push(
            kernel_v2::sql::query_sql(&db, &viewer, json!({"sql":format!("SELECT * FROM {name}")}))
                .await
                .unwrap_err()
                .to_string(),
        );
    }
    assert_eq!(refusals[0], refusals[1]);
    assert!(refusals[0].contains(MISSING));
    let mut tx = db.pool().begin().await.unwrap();
    let deadline = || Instant::now() + Duration::from_secs(2);
    let page = details::list_on(&mut tx, &admin, &pins[0].view_id, 8, None, deadline())
        .await
        .unwrap();
    assert_eq!(page["revisions"].as_array().unwrap().len(), 8);
    let next = page["cursor"].as_str().unwrap();
    let rest = details::list_on(&mut tx, &admin, &pins[0].view_id, 8, Some(next), deadline())
        .await
        .unwrap();
    assert_eq!(rest["revisions"].as_array().unwrap().len(), 2);
    assert!(rest["cursor"].is_null());
    assert!(page["binding"]["event_id"].as_str().is_some());
    assert_eq!(
        page["binding"]["pin"],
        serde_json::to_value(&pins[0]).unwrap()
    );
    let visible_page = details::list_on(&mut tx, &viewer, &pins[0].view_id, 16, None, deadline())
        .await
        .unwrap();
    let unavailable_header = visible_page["revisions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["revision_id"] == dep_pin.revision_id)
        .unwrap();
    assert_eq!(unavailable_header["available"], false);
    assert_eq!(unavailable_header["diagnostic"], "view_missing");
    assert!(unavailable_header.get("dependencies").is_none());
    assert!(!serde_json::to_string(&visible_page)
        .unwrap()
        .contains(&hidden));
    assert!(details::list_on(
        &mut tx,
        &viewer,
        &pins[0].view_id,
        8,
        Some(next),
        deadline()
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("cursor_invalid"));
    let unavailable = details::get_on(
        &mut tx,
        &viewer,
        &hidden_pin.view_id,
        &hidden_pin.revision_id,
        deadline(),
    )
    .await
    .unwrap_err()
    .to_string();
    let dependent = details::get_on(
        &mut tx,
        &viewer,
        &dep_pin.view_id,
        &dep_pin.revision_id,
        deadline(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(unavailable.contains("view_missing"));
    assert!(dependent.contains("view_missing"));
    assert!(!dependent.contains(&hidden));
    assert!(
        details::list_on(&mut tx, &viewer, &pins[0].view_id, 17, None, deadline())
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn named_view_operations_record_cas_retry_unpublish_and_prepare_are_atomic() {
    use crate::{
        events::KERNEL_ROOT_ID,
        kernel,
        mcp::{
            kernel_v2,
            registry::{Caller, EngineHandle, ToolRegistry, WritePlanExecution},
        },
    };
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    let editor = kernel::create_principal(&db, "account", "Editor", "acct:editor", &admin)
        .await
        .unwrap();
    let reader = kernel::create_principal(&db, "account", "Reader", "acct:reader", &admin)
        .await
        .unwrap();
    kernel::create_principal(&db, "account", "Outsider", "acct:outsider", &admin)
        .await
        .unwrap();
    let home = kernel::create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(&editor, "edit"), (&reader, "view")]),
        &admin,
    )
    .await
    .unwrap();
    let id = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let admin_caller = Caller::authenticated("acct:admin")
        .with_hosting_context("admin", "workspace")
        .with_hosting_owner(true);
    let work = async {
        let source_id: String = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
        )
        .bind(&id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let mut source_conn = db.pool().acquire().await.unwrap();
        let source = read_event(&mut source_conn, &source_id, i64::MAX)
            .await
            .unwrap();
        drop(source_conn);
        let mut invalid = definition_fixture();
        invalid["source_pins"] = json!([{"record_id":id,"revision_id":source_id,"sha256":closure::source_digest(&source).unwrap()}]);
        let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let error=registry.call_engine(EngineHandle::KernelV2(db.clone()),Caller::authenticated("acct:editor"),"manage_named_views",json!({"action":"record_view_revision","id":id,"definition":invalid,"idempotency_key":"self-invalidating"})).await.unwrap_err().to_string();
        assert!(error.contains("view_source_invalidated"), "{error}");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            before
        );
        let args = json!({"action":"record_view_revision","id":id,"definition":definition_fixture(),"idempotency_key":"draft"});
        let before_deny: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert!(
            registry
                .call_engine(
                    EngineHandle::KernelV2(db.clone()),
                    Caller::authenticated("acct:reader"),
                    "manage_named_views",
                    args.clone()
                )
                .await
                .is_err(),
            "bearer View never substitutes for draft Edit"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            before_deny
        );
        let draft = registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                Caller::authenticated("acct:editor"),
                "manage_named_views",
                args.clone(),
            )
            .await
            .unwrap();
        for action in ["get_view_revision", "list_view_revisions"] {
            let mut read = json!({"action":action,"view_id":draft["pin"]["view_id"]});
            if action == "get_view_revision" {
                read["revision_id"] = draft["pin"]["revision_id"].clone();
            }
            assert!(
                registry
                    .call_engine(
                        EngineHandle::KernelV2(db.clone()),
                        Caller::authenticated("acct:outsider"),
                        "manage_named_views",
                        read.clone()
                    )
                    .await
                    .is_err(),
                "metadata requires current bearer View"
            );
            registry
                .call_engine(
                    EngineHandle::KernelV2(db.clone()),
                    Caller::authenticated("acct:editor"),
                    "manage_named_views",
                    read,
                )
                .await
                .unwrap();
        }
        let retry = registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                Caller::authenticated("acct:editor"),
                "manage_named_views",
                args,
            )
            .await
            .unwrap();
        assert_eq!(retry["event_id"], draft["event_id"]);
        assert_eq!(retry["replayed"], true);
        let activate = json!({"action":"activate_view","id":id,"pin":draft["pin"],"name":"view_operation","expected_binding_event_id":null,"idempotency_key":"activate"});
        assert!(registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                admin_caller.clone(),
                "manage_named_views",
                activate.clone()
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("write plan"));
        let plan_caller = |caller: Caller, op: &str| {
            caller.with_write_plan_execution(WritePlanExecution {
                plan_id: "test-plan".into(),
                effect_digest: "test-effect".into(),
                executor: "records_write".into(),
                operation: op.into(),
            })
        };
        assert!(registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                plan_caller(
                    Caller::authenticated("acct:editor")
                        .with_hosting_context("editor", "workspace")
                        .with_hosting_owner(false),
                    "activate_view"
                ),
                "manage_named_views",
                activate.clone()
            )
            .await
            .is_err());
        let published = registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                plan_caller(admin_caller.clone(), "activate_view"),
                "manage_named_views",
                activate.clone(),
            )
            .await
            .unwrap();
        let retry = registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                plan_caller(admin_caller.clone(), "activate_view"),
                "manage_named_views",
                activate.clone(),
            )
            .await
            .unwrap();
        assert_eq!(retry["event_id"], published["event_id"]);
        let mut stale = activate;
        stale["idempotency_key"] = json!("different-plan");
        assert!(registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                plan_caller(admin_caller.clone(), "activate_view"),
                "manage_named_views",
                stale
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("binding_conflict"));
        let unpublish = json!({"action":"unpublish_view","id":id,"expected_binding_event_id":published["event_id"],"idempotency_key":"unpublish"});
        let unpublished = registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                plan_caller(admin_caller.clone(), "unpublish_view"),
                "manage_named_views",
                unpublish,
            )
            .await
            .unwrap();
        let before_noop: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let noop = json!({"action":"unpublish_view","id":id,"expected_binding_event_id":unpublished["event_id"],"idempotency_key":"inactive-noop"});
        assert!(registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                plan_caller(admin_caller.clone(), "unpublish_view"),
                "manage_named_views",
                noop
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("view_binding_inactive"));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            before_noop
        );
        let left = json!({"action":"activate_view","id":id,"pin":draft["pin"],"name":"view_operation","expected_binding_event_id":unpublished["event_id"],"idempotency_key":"race-left"});
        let mut right = left.clone();
        right["idempotency_key"] = json!("race-right");
        let (left, right) = tokio::join!(
            registry.call_engine(
                EngineHandle::KernelV2(db.clone()),
                plan_caller(admin_caller.clone(), "activate_view"),
                "manage_named_views",
                left
            ),
            registry.call_engine(
                EngineHandle::KernelV2(db.clone()),
                plan_caller(admin_caller.clone(), "activate_view"),
                "manage_named_views",
                right
            )
        );
        assert_ne!(
            left.is_ok(),
            right.is_ok(),
            "one serialized CAS writer must win: {left:?} {right:?}"
        );
        let (_, query) = planned(
            &id,
            "SELECT id FROM view_operation",
            BTreeMap::from([(
                "view_operation".into(),
                contract::Dependency::View(serde_json::from_value(draft["pin"].clone()).unwrap()),
            )]),
        );
        assert!(kernel_v2::query_pinned_saved_sql(&db, &admin, &query.query)
            .await
            .is_ok());
        sqlx::query("DROP INDEX idx_kernel_named_view_lifecycle")
            .execute(db.write_pool())
            .await
            .unwrap();
        let mut tx = db.pool().begin().await.unwrap();
        assert!(!storage::verify_index_on(&mut tx).await.unwrap());
        tx.rollback().await.unwrap();
        let before =
            crate::standby::kernel_v2::coordinates(&mut db.pool().acquire().await.unwrap())
                .await
                .unwrap();
        assert!(
            registry
                .call_engine(
                    EngineHandle::KernelV2(db.clone()),
                    Caller::authenticated("acct:editor"),
                    "manage_named_views",
                    json!({"action":"prepare_named_views"})
                )
                .await
                .is_err(),
            "bearer Edit does not grant workspace preparation"
        );
        let mut denied_tx = db.pool().begin().await.unwrap();
        assert!(
            !storage::verify_index_on(&mut denied_tx).await.unwrap(),
            "denied preparation must not install an index"
        );
        denied_tx.rollback().await.unwrap();
        let first = registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                admin_caller.clone(),
                "manage_named_views",
                json!({"action":"prepare_named_views"}),
            )
            .await
            .unwrap();
        assert_eq!(first["already_prepared"], false);
        let second = registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                admin_caller,
                "manage_named_views",
                json!({"action":"prepare_named_views"}),
            )
            .await
            .unwrap();
        assert_eq!(second["already_prepared"], true);
        let after = crate::standby::kernel_v2::coordinates(&mut db.pool().acquire().await.unwrap())
            .await
            .unwrap();
        assert_eq!(format!("{before:?}"), format!("{after:?}"));
    };
    crate::named_views::gate::testing(true, work).await;
}

#[tokio::test]
async fn named_view_real_executor_gate_off() {
    crate::mcp::executor_prototype::named_views::tests::named_view_operations_gate_off_through_source_app_and_call_executor().await;
}
#[tokio::test]
async fn named_view_real_executor_plan_commits_once() {
    crate::mcp::executor_prototype::named_views::tests::named_view_executor_plan_prepares_without_writing_and_commits_exactly_once().await;
}

#[tokio::test]
async fn named_view_hosted_saved_query_port_retains_exact_provenance() {
    use crate::{events::KERNEL_ROOT_ID, kernel, mcp::kernel_v2::artifacts};
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    let home = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&admin, "manage")]), &admin)
        .await
        .unwrap();
    let bearer = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let query_record = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let (pin, definition) = planned(
        &bearer,
        &format!("SELECT id FROM records WHERE id='{bearer}'"),
        static_records(),
    );
    let (_, query) = planned(
        "query",
        "SELECT id FROM view_exact",
        BTreeMap::from([("view_exact".into(), contract::Dependency::View(pin.clone()))]),
    );
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    insert_retained_definition(&mut tx, &pin, &definition, None).await;
    sqlx::query("INSERT INTO kernel_facets(record_id,key,value,as_of,event_seq) VALUES(?,'query',?,'2026-10-25',0)").bind(&query_record).bind(serde_json::to_string(&query.query).unwrap()).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let result =
        artifacts::testing_governed_sql_input(&db, &admin, &query_record, &schema_digest())
            .await
            .unwrap();
    assert_eq!(result["relation"]["rows"], json!([{"id":bearer}]));
    let receipt = &result["source"]["execution_receipt"];
    assert_eq!(receipt["version"], "native.governed-sql-port-receipt.v2");
    assert_eq!(
        receipt["view_provenance"]["roots"]["view_exact"],
        serde_json::to_value(&pin).unwrap()
    );
    assert_eq!(receipt["query_sha256"].as_str().unwrap().len(), 64);
    assert!(receipt["relations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["name"] == "records"));
    assert_eq!(
        result["source"]["content_revision"]["token"]
            .as_str()
            .unwrap()
            .len(),
        "native.snapshot.v1.".len() + 64
    );
    sqlx::query("UPDATE kernel_facets SET value=? WHERE record_id=? AND key='query'")
        .bind(serde_json::to_string(&definition.query.static_shape()).unwrap())
        .bind(&query_record)
        .execute(db.write_pool())
        .await
        .unwrap();
    let static_result =
        artifacts::testing_governed_sql_input(&db, &admin, &query_record, &schema_digest())
            .await
            .unwrap();
    assert_eq!(
        static_result["source"]["execution_receipt"]["version"],
        "native.governed-sql-port-receipt.v1"
    );
    assert!(static_result["source"]["execution_receipt"]
        .get("view_provenance")
        .is_none());
}

#[tokio::test]
async fn named_view_unprepared_catalogs_never_scan_event_history() {
    use crate::{kernel, mcp::kernel_v2};
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    let home = kernel::create_home(
        &db,
        crate::events::KERNEL_ROOT_ID,
        Some(&[(&admin, "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let id = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let (pin, def) = planned(&id, "SELECT id FROM records", static_records());
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    insert_retained_definition(&mut tx, &pin, &def, None).await;
    let binding = Transition {
        v: 1,
        view_id: pin.view_id.clone(),
        expected: None,
        action: Action::Activate {
            name: "view_catalog_continuity".into(),
            pin,
        },
    };
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,1,'legacy_unknown')")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&id).bind(TRANSITION)
        .bind(serde_json::to_string(&binding).unwrap()).bind("2026-10-25").execute(&mut *tx).await.unwrap();
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<65537) INSERT INTO content_events(id,record_id,type,payload,created_at,causal_envelope_version,causal_status) SELECT 'unrelated-'||x,'unrelated','fixture','{}','2026-10-25',1,'legacy_unknown' FROM n")
        .execute(&mut *tx).await.unwrap();
    sqlx::query("DROP INDEX idx_kernel_named_view_lifecycle")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    for relation in [
        "catalog_relations",
        "catalog_columns",
        "catalog_view_definitions",
    ] {
        let (reply, scanned) = storage::measured_fallback(kernel_v2::sql::query_sql(
            &db,
            &admin,
            json!({"sql":format!("SELECT * FROM {relation}")}),
        ))
        .await;
        let reply = reply.unwrap();
        assert_eq!(scanned, 0, "{relation}");
        assert_eq!(reply["notices"][0]["code"], "view_catalog_incomplete");
        assert!(reply["notices"][0]["message"]
            .as_str()
            .unwrap()
            .contains("prepare_named_views"));
        assert!(reply["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| !row["relation_name"].as_str().unwrap().starts_with("view_")));
        if relation != "catalog_view_definitions" {
            assert!(reply["row_count"].as_u64().unwrap() > 0);
        }
    }
    let (reply, scanned) = storage::measured_fallback(kernel_v2::sql::query_sql(
        &db,
        &admin,
        json!({"sql":"SELECT * FROM view_catalog_continuity"}),
    ))
    .await;
    assert!(scanned > 0);
    assert!(reply
        .unwrap_err()
        .to_string()
        .contains("view_registry_scan_budget_exceeded"));
    storage::ensure_index_on(&mut db.write_pool().acquire().await.unwrap())
        .await
        .unwrap();
    let (reply, scanned) = storage::measured_fallback(kernel_v2::sql::query_sql(&db, &admin,
        json!({"sql":"SELECT relation_name FROM catalog_relations WHERE relation_name='view_catalog_continuity'"}))).await;
    assert_eq!(scanned, 0);
    assert_eq!(reply.unwrap()["row_count"], 1);
}

#[tokio::test]
async fn named_view_publication_owners_and_demotion_are_serialized() {
    crate::mcp::kernel_v2::writes::named_views::with_evicted_validation(
        crate::mcp::executor_prototype::named_views::tests::named_view_owner_role_and_demotion(),
    )
    .await;
}

#[tokio::test]
async fn named_view_static_catalogs_survive_legacy_and_invalid_history() {
    use crate::{kernel, mcp::kernel_v2};
    for (kind, payload) in [(LEGACY, "{}"), (REVISION, "not json")] {
        let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
            .await
            .unwrap();
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,1,'legacy_unknown')")
            .bind(uuid::Uuid::new_v4().to_string()).bind("legacy-bearer").bind(kind).bind(payload).bind("2026-10-25").execute(db.write_pool()).await.unwrap();
        for relation in [
            "catalog_relations",
            "catalog_columns",
            "catalog_view_definitions",
        ] {
            let reply = kernel_v2::sql::query_sql(
                &db,
                &admin,
                json!({"sql":format!("SELECT * FROM {relation}")}),
            )
            .await
            .unwrap();
            if relation != "catalog_view_definitions" {
                assert!(reply["row_count"].as_u64().unwrap() > 0);
            }
            assert_eq!(reply["notices"][0]["code"], "view_catalog_incomplete");
            assert!(reply["rows"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| !r["relation_name"].as_str().unwrap().starts_with("view_")));
        }
        assert!(kernel_v2::sql::query_sql(
            &db,
            &admin,
            json!({"sql":"SELECT * FROM view_explicit"})
        )
        .await
        .is_err());
    }
}

#[tokio::test]
async fn named_view_drifted_definitions_remain_readable_and_unpublishable() {
    use crate::{
        kernel,
        mcp::{
            kernel_v2,
            registry::{Caller, EngineHandle, ToolRegistry},
        },
    };
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    let home = kernel::create_home(
        &db,
        crate::events::KERNEL_ROOT_ID,
        Some(&[(&admin, "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let id = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let source_id = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let event_id: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(&source_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let event = read_event(&mut tx, &event_id, i64::MAX).await.unwrap();
    let (_, mut def) = planned(&id, "SELECT id FROM records", static_records());
    def.source_pins.push(contract::SourcePin {
        record_id: source_id.clone(),
        revision_id: event_id,
        sha256: closure::source_digest(&event).unwrap(),
    });
    tx.rollback().await.unwrap();
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let caller = Caller::authenticated("acct:admin")
        .with_hosting_context("admin", "workspace")
        .with_hosting_owner(true);
    let plan_caller = |operation: &str| {
        caller
            .clone()
            .with_write_plan_execution(crate::mcp::registry::WritePlanExecution {
                plan_id: "test-view-plan".into(),
                effect_digest: "test-effect".into(),
                executor: "records_write".into(),
                operation: operation.into(),
            })
    };
    let draft_args = json!({"action":"record_view_revision","id":id,"definition":def,"idempotency_key":"drift-draft"});
    let draft = gate::testing(
        true,
        registry.call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller.clone(),
            "manage_named_views",
            draft_args.clone(),
        ),
    )
    .await
    .unwrap();
    let pin: Pin = serde_json::from_value(draft["pin"].clone()).unwrap();
    let activation_args = json!({"action":"activate_view","id":id,"pin":pin,"name":"view_drifted","expected_binding_event_id":null,"idempotency_key":"drift-publish"});
    let activation = gate::testing(
        true,
        registry.call_engine(
            EngineHandle::KernelV2(db.clone()),
            plan_caller("activate_view"),
            "manage_named_views",
            activation_args.clone(),
        ),
    )
    .await
    .unwrap();
    let binding_id = activation["event_id"].as_str().unwrap().to_owned();
    let source = kernel::read_record_as(&db, &admin, &source_id)
        .await
        .unwrap()
        .unwrap();
    kernel::set_archived_as(&db, &admin, &source_id, true, source.revision)
        .await
        .unwrap();
    let mut tx = db.pool().begin().await.unwrap();
    let result = details::get_on(
        &mut tx,
        &admin,
        &pin.view_id,
        &pin.revision_id,
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(
        result["definition"]["query"]["sql"],
        "SELECT id FROM records"
    );
    assert_eq!(result["diagnostic"], "view_source_invalidated");
    tx.rollback().await.unwrap();
    assert!(
        kernel_v2::sql::query_sql(&db, &admin, json!({"sql":"SELECT id FROM view_drifted"}))
            .await
            .is_err()
    );
    // An archived bearer remains readable metadata and can release its slot.
    let bearer = kernel::read_record_as(&db, &admin, &id)
        .await
        .unwrap()
        .unwrap();
    kernel::set_archived_as(&db, &admin, &id, true, bearer.revision)
        .await
        .unwrap();
    let mut tx = db.pool().begin().await.unwrap();
    let listed = details::list_on(
        &mut tx,
        &admin,
        &pin.view_id,
        8,
        None,
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(
        listed["revisions"][0]["diagnostic"],
        "view_source_invalidated"
    );
    assert_eq!(listed["revisions"][0]["available"], false);
    assert_eq!(listed["revisions"][0]["revision_id"], pin.revision_id);
    tx.rollback().await.unwrap();
    gate::testing(true, async {
        for (args, original) in [(&draft_args, &draft), (&activation_args, &activation)] {
            let retry = registry
                .call_engine(
                    EngineHandle::KernelV2(db.clone()),
                    plan_caller(args["action"].as_str().unwrap()),
                    "manage_named_views",
                    args.clone(),
                )
                .await
                .unwrap();
            assert_eq!(retry["event_id"], original["event_id"]);
            assert_eq!(retry["replayed"], true);
        }
        kernel_v2::writes::named_views::authorize_retry(&db, &admin, &activation_args, true)
            .await
            .unwrap();
    })
    .await;
    let args = json!({"action":"unpublish_view","id":id,"expected_binding_event_id":binding_id,"idempotency_key":"broken-unpublish"});
    gate::testing(true, async {
        let receipt = registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                plan_caller("unpublish_view"),
                "manage_named_views",
                args.clone(),
            )
            .await
            .unwrap();
        assert!(receipt.get("pin").is_none());
        let retry = registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                plan_caller("unpublish_view"),
                "manage_named_views",
                args.clone(),
            )
            .await
            .unwrap();
        assert_eq!(retry["event_id"], receipt["event_id"]);
        assert_eq!(retry["replayed"], true);
        kernel_v2::writes::named_views::authorize_retry(&db, &admin, &args, true)
            .await
            .unwrap();
    })
    .await;
}

#[tokio::test]
async fn named_view_validation_never_caches_worker_setup_or_timeout_failures() {
    use crate::query::sql::{named_views::SchemaFailure, view_validation};
    for fault in ["setup", "panic", "timeout"] {
        let (pin, def) = planned(
            &uuid::Uuid::new_v4().to_string(),
            "SELECT id FROM records",
            static_records(),
        );
        let plan = closure::build(
            &BTreeMap::from([("view_transient".into(), pin.clone())]),
            &BTreeMap::from([(pin, def)]),
        )
        .unwrap();
        let deadline = Instant::now()
            + if fault == "timeout" {
                Duration::from_millis(10)
            } else {
                Duration::from_secs(2)
            };
        let first = view_validation::analyze_with(&plan, deadline, move || {
            if fault == "panic" {
                panic!("injected validator worker failure");
            }
            if fault == "timeout" {
                std::thread::sleep(Duration::from_millis(30));
                return Ok(BTreeSet::new());
            }
            Err(SchemaFailure::Infrastructure(Error::engine(
                "injected setup failure",
            )))
        })
        .await;
        assert!(first.is_err(), "{fault}");
        view_validation::analyze(&plan, Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(view_validation::builds(&plan.digest), 2, "{fault}");
    }
}

#[tokio::test]
async fn named_view_saved_outer_statement_keeps_portable_function_gates() {
    use crate::{kernel, mcp::kernel_v2};
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    let home = kernel::create_home(
        &db,
        crate::events::KERNEL_ROOT_ID,
        Some(&[(&admin, "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let id = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let (pin, def) = planned(&id, "SELECT id FROM records", static_records());
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    insert_retained_definition(&mut tx, &pin, &def, None).await;
    tx.commit().await.unwrap();
    // hex is admitted in ad-hoc SQLite and passes the portable text classifier;
    // saved SQL's engine allowlist must nevertheless refuse it.
    let (_, qdef) = planned(
        "query",
        "SELECT hex(id) AS id FROM view_portable",
        BTreeMap::from([(
            "view_portable".into(),
            contract::Dependency::View(pin.clone()),
        )]),
    );
    qdef.query.validate_current().unwrap();
    assert!(kernel_v2::query_pinned_saved_sql(&db, &admin, &qdef.query)
        .await
        .is_err());
    let mut detail_query = qdef.query.clone();
    detail_query.sql =
        "SELECT relation_name AS id FROM catalog_view_definitions ORDER BY id".into();
    assert!(detail_query
        .validate_current()
        .unwrap_err()
        .to_string()
        .contains("catalog_view_definitions"));
    assert!(
        kernel_v2::query_pinned_saved_sql(&db, &admin, &detail_query)
            .await
            .unwrap_err()
            .to_string()
            .contains("catalog_view_definitions")
    );
    let plan = closure::build(
        &BTreeMap::from([("view_portable".into(), pin.clone())]),
        &BTreeMap::from([(pin, def)]),
    )
    .unwrap();
    let validators = crate::query::sql::NamedViewValidators::from_closure(&plan).unwrap();
    validators
        .inspect("SELECT hex(id) AS id FROM view_portable")
        .unwrap();
    assert!(validators.inspect_saved(&qdef.query.sql).is_err());
}

#[tokio::test]
async fn named_view_details_refuse_v1_and_read_only_profiles() {
    use crate::{kernel, mcp::kernel_v2};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("profiles.db");
    let (db, admin) =
        kernel::create_v2_database(path.to_str().unwrap(), "account", "Admin", "acct:admin")
            .await
            .unwrap();
    let readonly = crate::db::open_kernel_v2_standby_read_only(path.to_str().unwrap())
        .await
        .unwrap();
    let error = kernel_v2::sql::query_sql(
        &readonly,
        &admin,
        json!({"sql":"SELECT * FROM catalog_view_definitions"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("view_profile_unsupported"), "{error}");
    // The v1 executor must not serve its validator's empty detail shape.
    let error = crate::query::sql::query_sql(
        &db,
        crate::mcp::Caller::authenticated("acct:admin"),
        "SELECT * FROM catalog_view_definitions",
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("view_profile_unsupported"), "{error}");
}

#[tokio::test]
async fn named_view_retained_isolation_and_body_only_columns_precede_execution() {
    use crate::{kernel, mcp::kernel_v2, query::sql::view_validation};
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    let home = kernel::create_home(
        &db,
        crate::events::KERNEL_ROOT_ID,
        Some(&[(&admin, "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let good = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let bad = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let (good, good_def) = planned(
        &good,
        &format!("SELECT id FROM records WHERE id='{good}' AND archived=0"),
        static_records(),
    );
    let (bad, bad_def) = planned(&bad, "SELECT missing AS id FROM records", static_records());
    let roots = BTreeMap::from([
        ("view_a_good".into(), good.clone()),
        ("view_z_bad".into(), bad.clone()),
    ]);
    let definitions = BTreeMap::from([(good.clone(), good_def), (bad.clone(), bad_def)]);
    let combined = closure::build(&roots, &definitions).unwrap();
    let good_plan = closure::build(
        &BTreeMap::from([("view_a_good".into(), good.clone())]),
        &definitions,
    )
    .unwrap();
    let bad_plan = closure::build(
        &BTreeMap::from([("view_z_bad".into(), bad.clone())]),
        &definitions,
    )
    .unwrap();
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    for (pin, def) in &definitions {
        insert_retained_definition(&mut tx, pin, def, None).await;
    }
    for (name, pin) in &roots {
        let event = Transition {
            v: 1,
            view_id: pin.view_id.clone(),
            expected: None,
            action: Action::Activate {
                name: name.clone(),
                pin: pin.clone(),
            },
        };
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,1,'legacy_unknown')")
            .bind(uuid::Uuid::new_v4().to_string()).bind(pin.view_id.strip_prefix("native.named-view:").unwrap()).bind(TRANSITION).bind(serde_json::to_string(&event).unwrap()).bind("2026-10-25").execute(&mut *tx).await.unwrap();
    }
    tx.commit().await.unwrap();
    let (failed, stats) = kernel_v2::sql::measured(kernel_v2::sql::query_sql(
        &db,
        &admin,
        json!({"sql":"SELECT g.id FROM view_a_good g JOIN view_z_bad b ON b.id=g.id"}),
    ))
    .await;
    assert!(failed.is_err());
    assert_eq!(
        stats.staged_records, 0,
        "invalid combined schema never executes or stages rows"
    );
    assert_eq!(view_validation::builds(&combined.digest), 1);
    assert_eq!(
        view_validation::builds(&good_plan.digest),
        1,
        "isolation follows the failed combined attempt"
    );
    assert_eq!(view_validation::builds(&bad_plan.digest), 1);
    let catalog = kernel_v2::sql::query_sql(&db,&admin,json!({"sql":"SELECT relation_name FROM catalog_relations WHERE relation_name LIKE 'view_%'"})).await.unwrap();
    assert_eq!(catalog["rows"], json!([{"relation_name":"view_a_good"}]));
    let count = kernel_v2::sql::query_sql(
        &db,
        &admin,
        json!({"sql":"SELECT count(*) AS n FROM view_a_good"}),
    )
    .await
    .unwrap();
    assert_eq!(
        count["rows"],
        json!([{"n":1}]),
        "the outer query names no column, but the body needs archived and id staged"
    );
    assert_eq!(view_validation::builds(&good_plan.digest), 1);
    assert_eq!(view_validation::builds(&bad_plan.digest), 1);
}
