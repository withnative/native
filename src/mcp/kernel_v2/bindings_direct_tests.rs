use super::*;

struct Fixture {
    _dir: tempfile::TempDir,
    db: Db,
    registry: ToolRegistry,
    admin: String,
    first: String,
    second: String,
    document: String,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("bindings.db").to_str().unwrap(),
        "account",
        "Owner",
        "bindings:owner",
    )
    .await
    .unwrap();
    let viewer = kernel::create_principal(&db, "account", "Viewer", "bindings:viewer", &admin)
        .await
        .unwrap();
    let home = kernel::create_home(
        &db,
        crate::events::KERNEL_ROOT_ID,
        Some(&[(&viewer, "view")]),
        &admin,
    )
    .await
    .unwrap();
    let definition = json!({"family":"fixture.bindings.direct","version":1,"interpreter":"native.defn/2","primary_type":"Entity","kinds":[{"token":"person","description":"Binding proof","maturity":"current","identity":{"field":"title"},"fields":[{"name":"title","type":"text","required":true}],"links":[]}]});
    let pin = kernel::install_definition_as(
        &db,
        &admin,
        "fixture.bindings.direct",
        1,
        &serde_json::to_vec(&definition).unwrap(),
    )
    .await
    .unwrap();
    kernel::adopt_definition_as(&db, &admin, &pin.family, Some(&pin))
        .await
        .unwrap();
    let first = kernel::create_as(
        &db,
        &admin,
        &pin.family,
        "person",
        json!({"title":"One"}).as_object().unwrap(),
        &home,
    )
    .await
    .unwrap();
    let second = kernel::create_as(
        &db,
        &admin,
        &pin.family,
        "person",
        json!({"title":"Two"}).as_object().unwrap(),
        &home,
    )
    .await
    .unwrap();
    let document = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::identity::register_identity_tools(&mut registry).unwrap();
    super::register(&mut registry).unwrap();
    Fixture {
        _dir: dir,
        db,
        registry,
        admin,
        first,
        second,
        document,
    }
}

async fn call(f: &Fixture, actor: &str, args: Value) -> Result<Value> {
    f.registry
        .call_engine(
            EngineHandle::KernelV2(f.db.clone()),
            Caller::authenticated(actor),
            "manage_bindings",
            args,
        )
        .await
}
fn claim(id: &str) -> Value {
    // Use the public wire grammar: fixture labels are principal components
    // within the reserved native network, rather than invented networks.
    json!({"system":"native-principal","identifier":format!("native/{id}")})
}
async fn add(f: &Fixture, record: &str, id: &str, canonical: bool) {
    call(f,"bindings:owner",json!({"action":"add","record_id":record,"binding":claim(id),"canonical":canonical,"reason":"binding proof"})).await.unwrap();
}

#[tokio::test]
async fn canonicalize_remove_reconcile_are_atomic_replayable_and_keep_principals_separate() {
    let f = fixture().await;
    let subject_before = kernel::read_record_as(&f.db, &f.admin, &f.first)
        .await
        .unwrap()
        .unwrap();
    let schema = f
        .registry
        .get("manage_bindings")
        .unwrap()
        .input_schema_for_engine(EngineKind::KernelV2);
    assert!(schema["properties"]["action"]["enum"]
        .as_array()
        .unwrap()
        .contains(&json!("reconcile")));
    assert!(!schema["properties"]["action"]["enum"]
        .as_array()
        .unwrap()
        .contains(&json!("observations")));
    assert!(schema["properties"]
        .get("if_binding_state_revision")
        .is_some());
    let principal_before: Vec<(String, String)> = sqlx::query_as(
        "SELECT principal_id,auth_binding FROM kernel_principals ORDER BY principal_id",
    )
    .fetch_all(f.db.pool())
    .await
    .unwrap();
    add(&f, &f.first, "one", true).await;
    add(&f, &f.first, "two", false).await;
    add(&f, &f.first, "three", false).await;
    let args = json!({"action":"canonicalize","record_id":f.first,"binding":claim("two"),"reason":"choose canonical"});
    let result = call(&f, "bindings:owner", args.clone()).await.unwrap();
    assert_eq!(result["status"], "canonicalized");
    assert!(result["event_id"].is_string());
    assert!(result.get("act").is_none());
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    assert_eq!(
        call(&f, "bindings:owner", args).await.unwrap()["changed"],
        false
    );
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    let remove = json!({"action":"remove","record_id":f.first,"binding":claim("three"),"reason":"remove alias"});
    let authority_before_remove = kernel::notifications::vector(f.db.pool())
        .await
        .unwrap()
        .authorization;
    assert_eq!(
        call(&f, "bindings:owner", remove.clone()).await.unwrap()["status"],
        "removed"
    );
    assert!(
        kernel::notifications::vector(f.db.pool())
            .await
            .unwrap()
            .authorization
            > authority_before_remove
    );
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    assert_eq!(
        call(&f, "bindings:owner", remove).await.unwrap()["changed"],
        false
    );
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    let mut reconcile = json!({"action":"reconcile","target_record_id":f.second,"expected_source_record_id":f.first,"bindings":[claim("two")],"reason":"transfer only binding"});
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    let preview = call(&f, "bindings:owner", reconcile.clone()).await.unwrap();
    assert_eq!(preview["changed"], false);
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    reconcile["apply"] = json!(true);
    reconcile["if_binding_state_revision"] = preview["binding_state_revision"].clone();
    let applied = call(&f, "bindings:owner", reconcile.clone()).await.unwrap();
    assert_eq!(applied["status"], "reconciled");
    assert!(call(&f, "bindings:owner", reconcile)
        .await
        .unwrap_err()
        .to_string()
        .contains("stale expected owner"));
    let listing = call(
        &f,
        "bindings:owner",
        json!({"action":"list","record_id":f.second}),
    )
    .await
    .unwrap();
    assert_eq!(listing["bindings"][0]["identifier"], "native/two");
    assert_eq!(listing["bindings"][0]["is_canonical"], true);
    let principal_after: Vec<(String, String)> = sqlx::query_as(
        "SELECT principal_id,auth_binding FROM kernel_principals ORDER BY principal_id",
    )
    .fetch_all(f.db.pool())
    .await
    .unwrap();
    assert_eq!(principal_before, principal_after);
    let subject_after = kernel::read_record_as(&f.db, &f.admin, &f.first)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(subject_before.revision, subject_after.revision);
    assert_eq!(subject_before.body, subject_after.body);
    assert_eq!(subject_before.metadata, subject_after.metadata);
    let hidden_audit = super::super::sql::query_sql(&f.db,&f.admin,json!({"sql":"SELECT count(*) AS n FROM content_events WHERE type IN ('kernel.identity_binding_removed.v1','kernel.identity_bindings_reconciled.v1')"})).await.unwrap();
    assert_eq!(hidden_audit["rows"][0]["n"], 0);
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    kernel::replay_all_projections(&f.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    f.db.close().await;
}

#[tokio::test]
async fn direct_binding_guards_refuse_missing_reserved_durable_colliding_and_stale_effects() {
    let f = fixture().await;
    add(&f, &f.first, "durable", true).await;
    let viewer = kernel::resolve_caller_principal_by_binding(&f.db, "bindings:viewer")
        .await
        .unwrap()
        .unwrap()
        .0;
    // Admission rejects attempts to bypass the MCP planner and append an
    // unauthorized native effect directly.
    assert!(crate::store::append(&f.db,crate::store::AppendSpec {
        record_id:crate::events::KERNEL_ROOT_ID.into(), event_type:identity_bindings::REMOVED_EVENT.into(),
        payload:json!({"record_id":f.first,"binding":claim("durable"),"reason":"forged native effect"}), actor:Some(viewer.clone()),
    }).await.is_err());
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    for args in [
        json!({"action":"canonicalize","record_id":f.first,"binding":claim("missing"),"reason":"must exist"}),
        json!({"action":"remove","record_id":f.first,"binding":claim("durable"),"reason":"keep required identity"}),
        json!({"action":"canonicalize","record_id":f.first,"binding":{"system":"account","identifier":"reserved"},"reason":"reserved"}),
        json!({"action":"reconcile","target_record_id":f.document,"expected_source_record_id":f.first,"bindings":[claim("durable")],"apply":true,"reason":"wrong shape"}),
        json!({"action":"reconcile","target_record_id":f.second,"expected_source_record_id":f.first,"bindings":[],"apply":true,"reason":"empty"}),
        json!({"action":"reconcile","target_record_id":f.first,"expected_source_record_id":f.first,"bindings":[claim("durable")],"apply":true,"reason":"same"}),
        json!({"action":"reconcile","target_record_id":f.second,"expected_source_record_id":f.first,"bindings":[claim("durable"),claim("durable")],"apply":true,"reason":"duplicate"}),
    ] {
        assert!(call(&f, "bindings:owner", args).await.is_err());
        assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    }
    for args in [
        json!({"action":"remove","record_id":f.first,"binding":claim("durable"),"reason":"unauthorized"}),
        json!({"action":"canonicalize","record_id":f.first,"binding":claim("durable"),"reason":"unauthorized"}),
        json!({"action":"reconcile","target_record_id":f.second,"expected_source_record_id":f.first,"bindings":[claim("durable")],"apply":true,"reason":"unauthorized"}),
    ] {
        assert!(call(&f, "bindings:viewer", args).await.is_err());
    }
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    let target_home = kernel::create_home(
        &f.db,
        crate::events::KERNEL_ROOT_ID,
        Some(&[(&viewer, "manage")]),
        &f.admin,
    )
    .await
    .unwrap();
    kernel::rehome_record_as(&f.db, &f.admin, &f.second, &target_home)
        .await
        .unwrap();
    assert!(call(&f,"bindings:viewer",json!({"action":"reconcile","target_record_id":f.second,"expected_source_record_id":f.first,"bindings":[claim("durable")],"apply":true,"reason":"target manage does not grant source manage"})).await.is_err());
    let delegated = call(&f,"bindings:viewer",json!({"action":"add","record_id":f.second,"binding":claim("delegated"),"reason":"manage one record"})).await.unwrap();
    assert!(delegated.get("act").is_none());
    assert!(delegated["event_id"].is_string());
    assert!(delegated["binding_state_revision"]
        .as_str()
        .unwrap()
        .starts_with("ibsv2:"));
    add(&f, &f.first, "alias", false).await;
    let mut tx = f.db.pool().begin().await.unwrap();
    let revision = identity_bindings::revision_on(&mut tx, &f.first)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_direct_binding_delete BEFORE DELETE ON kernel_identity_bindings BEGIN SELECT RAISE(ABORT,'synthetic removal failure'); END").execute(f.db.write_pool()).await.unwrap();
    assert!(call(&f,"bindings:owner",json!({"action":"remove","record_id":f.first,"binding":claim("alias"),"reason":"roll back removal"})).await.is_err());
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    sqlx::query("DROP TRIGGER fail_direct_binding_delete")
        .execute(f.db.write_pool())
        .await
        .unwrap();
    let removed = call(&f,"bindings:owner",json!({"action":"remove","record_id":f.first,"binding":claim("alias"),"reason":"one alias","if_binding_state_revision":revision})).await.unwrap();
    assert_ne!(removed["binding_state_revision"], revision);
    assert!(call(&f,"bindings:owner",json!({"action":"canonicalize","record_id":f.first,"binding":claim("durable"),"reason":"stale no-op","if_binding_state_revision":revision})).await.unwrap_err().to_string().contains("revision conflict"));
    add(&f, &f.second, "other", true).await;
    assert!(call(&f,"bindings:owner",json!({"action":"reconcile","target_record_id":f.second,"expected_source_record_id":f.first,"bindings":[claim("durable")],"apply":true,"reason":"canonical collision"})).await.unwrap_err().to_string().contains("canonical binding collision"));
    let native = json!({"system":"native-record","identifier":crate::identity::encode_native_record("ndb_00000000000000000000000000000000","record").unwrap()});
    call(
        &f,
        "bindings:owner",
        json!({"action":"add","record_id":f.document,"binding":native,"reason":"durable record"}),
    )
    .await
    .unwrap();
    assert!(call(
        &f,
        "bindings:owner",
        json!({"action":"remove","record_id":f.document,"binding":native,"reason":"must retain"})
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("required durable"));
    f.db.close().await;
}
