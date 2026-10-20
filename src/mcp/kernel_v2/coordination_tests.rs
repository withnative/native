use super::*;
use crate::events::KERNEL_ROOT_ID;

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    register_kernel_v2_tools(&mut registry).unwrap();
    registry
}
async fn call(db: &Db, credential: &str, tool: &str, args: Value) -> Result<Value> {
    registry()
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated(credential),
            tool,
            args,
        )
        .await
}
async fn adopt(db: &Db, admin: &str, manifest: &crate::package_manifest::PackageManifest) {
    let id = kernel::install_package_as(db, admin, manifest)
        .await
        .unwrap();
    kernel::adopt_package_at(
        db,
        admin,
        KERNEL_ROOT_ID,
        manifest,
        Some(&id),
        &manifest.declared_reads,
    )
    .await
    .unwrap();
}
async fn seed(
    db: &Db,
    importer: &str,
    pin: &crate::meta::definition_artifact::RevisionIdentity,
    id: &str,
    owner: &str,
    title: &str,
    body: &str,
) {
    kernel::import_record_as(
        db,
        importer,
        id,
        KERNEL_ROOT_ID,
        Some(owner),
        &kernel::ImportRecordState {
            definition: Some(kernel::ImportDefinition {
                pin: pin.clone(),
                primary_type: "V1".into(),
                kind: "record".into(),
                fields: json!({"v1_type":"Document","v1_kind":"agent-instructions","title":title})
                    .as_object()
                    .unwrap()
                    .clone(),
            }),
            body: Some(body.into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
}

async fn bind(
    db: &Db,
    importer: &str,
    id: &str,
    scope: &str,
    scope_id: &str,
    record: &str,
    position: i64,
) {
    let account_principal = if scope == "account" {
        Some(
            kernel::resolve_principal_by_binding(db, scope_id)
                .await
                .unwrap()
                .unwrap()
                .0,
        )
    } else {
        None
    };
    let binding = kernel::ImportInstructionBinding {
        id: id.into(),
        scope_kind: scope.into(),
        scope_id: scope_id.strip_prefix("acct:").unwrap_or(scope_id).into(),
        account_principal,
        source_record_id: record.into(),
        position,
        enabled: true,
        created_at: "2026-10-01T00:00:00Z".into(),
        actor: Some("original-v1-account".into()),
    };
    assert_eq!(
        kernel::import_instruction_binding_as(db, importer, &binding)
            .await
            .unwrap(),
        kernel::InstructionBindingImportResult::Created
    );
    assert_eq!(
        kernel::import_instruction_binding_as(db, importer, &binding)
            .await
            .unwrap(),
        kernel::InstructionBindingImportResult::Unchanged
    );
}

#[tokio::test]
async fn kernel_v2_coordination_registry_roundtrip_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("coordination.db");
    let path = path.to_str().unwrap();
    let (mut db, admin) = kernel::create_v2_database(path, "account", "Admin", "acct:admin")
        .await
        .unwrap();
    let other = kernel::create_principal(&db, "account", "Other", "acct:other", &admin)
        .await
        .unwrap();
    kernel::replace_home_policy(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &[(&admin, "manage"), (&other, "edit")],
    )
    .await
    .unwrap();
    let manifest = crate::v2_standard::v1_compat::package();
    adopt(&db, &admin, &manifest).await;
    adopt(&db, &admin, &crate::v2_standard::claims_v1::package()).await;
    let definition = &manifest.definitions[0];
    let pin = crate::meta::definition_artifact::RevisionIdentity {
        family: definition.family.clone(),
        version: definition.version,
        digest: definition.digest.clone(),
    };
    let importer = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    seed(
        &db,
        &importer,
        &pin,
        crate::schema::WORKSPACE_INSTRUCTIONS_ID,
        &admin,
        "Workspace agent instructions",
        "Workspace instructions from body lane",
    )
    .await;
    let personal = uuid::Uuid::new_v4().to_string();
    seed(
        &db,
        &importer,
        &pin,
        &personal,
        &admin,
        "Arbitrary orchestrator delivery guide",
        "Admin personal instructions",
    )
    .await;
    let foreign = uuid::Uuid::new_v4().to_string();
    seed(
        &db,
        &importer,
        &pin,
        &foreign,
        &other,
        "My agent instructions",
        "Other personal instructions",
    )
    .await;
    bind(
        &db,
        &importer,
        "v1-workspace-binding",
        "database",
        "native:database",
        crate::schema::WORKSPACE_INSTRUCTIONS_ID,
        0,
    )
    .await;
    bind(
        &db,
        &importer,
        "v1-admin-binding",
        "account",
        "acct:admin",
        &personal,
        1,
    )
    .await;
    bind(
        &db,
        &importer,
        "v1-other-binding",
        "account",
        "acct:other",
        &foreign,
        1,
    )
    .await;
    let refused = crate::store::append(&db, crate::store::AppendSpec {
        record_id: "native:ordinary-cannot-import".into(),
        event_type: "kernel.record_created.v1".into(),
        payload: json!({"home_id":KERNEL_ROOT_ID,"owner_id":null,"primary_type":null,"kind":null,"accession":null,"pin":null,"interpreter":null,"fields":null}),
        actor: Some(admin.clone()),
    }).await;
    assert!(
        refused.is_err(),
        "ordinary principals cannot bypass UUID identity admission"
    );
    let target = kernel::create_record_as(&db, &admin, KERNEL_ROOT_ID)
        .await
        .unwrap();
    let boot = call(&db, "acct:admin", "bootstrap", json!({}))
        .await
        .unwrap();
    assert_eq!(boot["principal"]["principal_id"], admin);
    assert_eq!(boot["workspace"]["primary_workspace"]["id"], KERNEL_ROOT_ID);
    assert_eq!(boot["instructions"]["entries"].as_array().unwrap().len(), 2);
    assert_eq!(
        boot["instructions"]["entries"][0]["content"],
        "Workspace instructions from body lane"
    );
    assert_eq!(
        boot["instructions"]["entries"][1]["content"],
        "Admin personal instructions"
    );
    assert_eq!(boot["pending_obligations"]["status"], "read_only");
    let rendered = crate::mcp::render::render("bootstrap", &boot).unwrap();
    assert!(rendered.contains("Workspace instructions from body lane"));
    assert!(rendered.contains("Admin personal instructions"));
    assert!(rendered.contains("Onboarding programmes and member state are imported read-only"));
    assert!(rendered.contains("Bootstrap opens a durable run"));
    assert!(!rendered.contains("bootstrap does not allocate a durable run"));
    assert!(!rendered.contains("native:unfiled"));
    let key = boot["run"]["run_key"].as_str().unwrap().to_owned();
    assert_eq!(boot["session"]["run_key"], key);
    let other_boot = call(&db, "acct:other", "bootstrap", json!({}))
        .await
        .unwrap();
    assert_eq!(
        other_boot["instructions"]["entries"][1]["content"],
        "Other personal instructions"
    );
    let other_key = other_boot["run"]["run_key"].as_str().unwrap().to_owned();
    let declaration = call(
        &db,
        "acct:admin",
        "set_intent",
        json!({"run_key":key,"intent":"Implement cutover"}),
    )
    .await
    .unwrap();
    assert_eq!(declaration["accepted_intent"], "Implement cutover");
    assert_eq!(declaration["briefing_version"], 2);
    assert_eq!(
        declaration["briefing"]["availability"]["status"],
        "unavailable"
    );
    let retry_args = json!({"run_key":key,"record_id":target,"operation_key":"claim-one"});
    let claimed = call(&db, "acct:admin", "start_work", retry_args.clone())
        .await
        .unwrap();
    assert_eq!(claimed["claimed"], true);
    assert_eq!(claimed["held_by_run_key"], key);
    assert_eq!(claimed["changed"], true);
    let work_text = crate::mcp::render::render("start_work", &claimed).unwrap();
    assert!(work_text.contains("Working context and overlap briefing are not implemented"));
    assert!(!work_text.contains("Dependencies — ready"));
    assert!(!work_text.contains("Open comment threads (0)"));
    assert!(work_text.contains(claimed["receipt"]["receipt_id"].as_str().unwrap()));
    let receipt = claimed["receipt"].clone();
    let retried = call(&db, "acct:admin", "start_work", retry_args.clone())
        .await
        .unwrap();
    assert_eq!(retried["receipt"], receipt);
    assert_eq!(retried["claimed"], true);
    assert_eq!(retried["changed"], false);
    let foreign_claim = call(
        &db,
        "acct:other",
        "start_work",
        json!({"run_key":other_key,"record_id":target}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(foreign_claim.contains("already_claimed"), "{foreign_claim}");
    let preview = call(
        &db,
        "acct:other",
        "start_work",
        json!({"run_key":other_key,"record_id":target,"action":"preview"}),
    )
    .await
    .unwrap();
    assert!(call(
        &db,
        "acct:other",
        "start_work",
        json!({"run_key":other_key,"record_id":target,"action":"release"})
    )
    .await
    .is_err());
    assert_eq!(preview["work_state"]["details"]["visibility"], "withheld");
    assert!(preview["held_by_run_key"].is_null());
    assert!(call(&db, "acct:other", "close_run", json!({"run_key":key}))
        .await
        .is_err());
    assert!(call(
        &db,
        "acct:other",
        "get_record",
        json!({"ids":[target],"run_key":key})
    )
    .await
    .is_err());
    // Close both pools and reopen the file: no process-local run/claim state.
    db.close().await;
    db = crate::db::open_database(path).await.unwrap();
    let continued = call(&db, "acct:admin", "bootstrap", json!({"run_key":key}))
        .await
        .unwrap();
    assert_eq!(continued["run"]["run_key"], key);
    let read = call(
        &db,
        "acct:admin",
        "get_record",
        json!({"ids":[target],"run_key":key}),
    )
    .await
    .unwrap();
    assert_eq!(read["run_context"]["intent"], "Implement cutover");
    let retried = call(&db, "acct:admin", "start_work", retry_args.clone())
        .await
        .unwrap();
    assert_eq!(retried["receipt"], receipt);
    assert_eq!(retried["claimed"], true);
    assert_eq!(retried["changed"], false);
    let release_args = json!({"run_key":key,"record_id":target,"action":"release","operation_key":"release-one", "expected_holder_run_key":key,"expected_generation":claimed["generation"],"expected_head":claimed["head"]});
    let released = call(&db, "acct:admin", "start_work", release_args.clone())
        .await
        .unwrap();
    assert_eq!(released["claimed"], false);
    assert_eq!(
        call(&db, "acct:admin", "start_work", release_args.clone())
            .await
            .unwrap()["receipt"],
        released["receipt"]
    );
    let again = call(
        &db,
        "acct:admin",
        "start_work",
        json!({"run_key":key,"record_id":target,"operation_key":"claim-two"}),
    )
    .await
    .unwrap();
    assert!(again["generation"].as_u64().unwrap() > claimed["generation"].as_u64().unwrap());
    let mut stale = release_args.clone();
    stale["operation_key"] = json!("stale-release");
    assert!(call(&db, "acct:admin", "start_work", stale)
        .await
        .unwrap_err()
        .to_string()
        .contains("stale_claim"));
    // Old receipts survive occupancy changes and are not new releases.
    assert_eq!(
        call(&db, "acct:admin", "start_work", release_args)
            .await
            .unwrap()["receipt"],
        released["receipt"]
    );
    let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
    kernel::replay_all_projections(&db).await.unwrap();
    assert_eq!(kernel::dump_all_kernel_tables(&db).await.unwrap(), before);
    assert_eq!(
        call(&db, "acct:admin", "close_run", json!({"run_key":key}))
            .await
            .unwrap()["changed"],
        true
    );
    assert_eq!(
        call(&db, "acct:admin", "close_run", json!({"run_key":key}))
            .await
            .unwrap()["changed"],
        false
    );
    assert!(call(
        &db,
        "acct:admin",
        "set_intent",
        json!({"run_key":key,"intent":"Too late"})
    )
    .await
    .is_err());
    assert!(call(
        &db,
        "acct:admin",
        "start_work",
        json!({"run_key":key,"record_id":target,"operation_key":"new-closed-claim"})
    )
    .await
    .is_err());
    let closed_boot = call(&db, "acct:admin", "bootstrap", json!({"run_key":key}))
        .await
        .unwrap();
    assert_eq!(closed_boot["run"]["closed"], true);
    assert_eq!(closed_boot["session"]["reuse_required"], false);
    let closed_text = crate::mcp::render::render("bootstrap", &closed_boot).unwrap();
    assert!(closed_text.contains("This run is closed"));
    assert!(closed_text.contains("run_closed"));
    assert!(!closed_text.contains("continues the same open run"));
    assert_eq!(
        call(&db, "acct:admin", "start_work", retry_args)
            .await
            .unwrap()["receipt"],
        receipt
    );
}

#[tokio::test]
async fn kernel_v2_coordination_non_admin_opens_own_run_and_requires_auth_binding() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("runs.db").to_str().unwrap(),
        "account",
        "Admin",
        "acct:admin",
    )
    .await
    .unwrap();
    let agent = kernel::create_principal(&db, "agent", "Agent", "agent:worker", &admin)
        .await
        .unwrap();
    let boot = call(&db, "agent:worker", "bootstrap", json!({}))
        .await
        .unwrap();
    assert_eq!(boot["principal"]["principal_id"], agent);
    let key = boot["run"]["run_key"].as_str().unwrap();
    assert!(call(&db, "acct:admin", "bootstrap", json!({"run_key":key}))
        .await
        .is_err());
    assert!(call(&db, "missing", "bootstrap", json!({})).await.is_err());
    let intent = call(
        &db,
        "agent:worker",
        "set_intent",
        json!({"run_key":key,"intent":"Agent work","model":"test"}),
    )
    .await
    .unwrap();
    assert_eq!(intent["declared_model"]["status"], "unsupported");
    let minted = call(
        &db,
        "agent:worker",
        "set_intent",
        json!({"run_key":"new","intent":"New run"}),
    )
    .await
    .unwrap();
    assert!(minted["run_context"]["run_key"].is_string());
}

#[tokio::test]
async fn kernel_v2_instruction_bindings_order_visibility_provenance_and_faults() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bindings.db");
    let (mut db, admin) =
        kernel::create_v2_database(path.to_str().unwrap(), "account", "Admin", "acct:admin")
            .await
            .unwrap();
    let other = kernel::create_principal(&db, "account", "Other", "acct:other", &admin)
        .await
        .unwrap();
    kernel::replace_home_policy(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &[(&admin, "manage"), (&other, "view")],
    )
    .await
    .unwrap();
    let manifest = crate::v2_standard::v1_compat::package();
    adopt(&db, &admin, &manifest).await;
    let definition = &manifest.definitions[0];
    let pin = crate::meta::definition_artifact::RevisionIdentity {
        family: definition.family.clone(),
        version: definition.version,
        digest: definition.digest.clone(),
    };
    let importer = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    for (id, title, body) in [
        ("source:later", "Subagent routing guide", "Later guide"),
        ("source:first", "Delivery guide", "First guide"),
        ("source:unbound", "My agent instructions", "Must not appear"),
        ("source:workspace", "Any workspace title", "Workspace guide"),
    ] {
        let owner = if id == "source:unbound" {
            &other
        } else {
            &admin
        };
        seed(&db, &importer, &pin, id, owner, title, body).await;
    }
    // Deliberately import out of order and use arbitrary source IDs/titles.
    bind(
        &db,
        &importer,
        "binding:later",
        "account",
        "acct:other",
        "source:later",
        20,
    )
    .await;
    bind(
        &db,
        &importer,
        "binding:first",
        "account",
        "acct:other",
        "source:first",
        10,
    )
    .await;
    bind(
        &db,
        &importer,
        "binding:workspace",
        "database",
        "native:database",
        "source:workspace",
        99,
    )
    .await;
    let boot = call(&db, "acct:other", "bootstrap", json!({}))
        .await
        .unwrap();
    assert_eq!(boot["instructions"]["status"], "ready");
    let entries = boot["instructions"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["content"], "Workspace guide");
    assert_eq!(entries[1]["content"], "First guide");
    assert_eq!(entries[2]["content"], "Later guide");
    assert!(!boot.to_string().contains("Must not appear"));
    let guest = registry()
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("acct:other").with_hosting_member(false),
            "bootstrap",
            json!({}),
        )
        .await
        .unwrap();
    assert_eq!(
        guest["instructions"]["entries"].as_array().unwrap().len(),
        2
    );
    assert_eq!(
        guest["instructions"]["entries"][0]["content"],
        "First guide"
    );
    // A visible binding never confers visibility on its source.
    let private = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&admin, "manage")]), &admin)
        .await
        .unwrap();
    let hidden = kernel::create_record_as(&db, &admin, &private)
        .await
        .unwrap();
    assert!(kernel::read_record_as(&db, &other, &hidden)
        .await
        .unwrap()
        .is_none());
    // Hidden/missing workspace bindings are indistinguishable from no binding.
    bind(
        &db,
        &importer,
        "binding:workspace-hidden",
        "database",
        "native:database",
        &hidden,
        0,
    )
    .await;
    bind(
        &db,
        &importer,
        "binding:workspace-missing",
        "database",
        "native:database",
        "workspace:missing-private-source",
        0,
    )
    .await;
    seed(
        &db,
        &importer,
        &pin,
        "source:empty",
        &other,
        "Empty instruction source",
        "",
    )
    .await;
    bind(
        &db,
        &importer,
        "binding:empty-account",
        "account",
        "acct:other",
        "source:empty",
        15,
    )
    .await;
    let no_body = kernel::create_record_as(&db, &admin, KERNEL_ROOT_ID)
        .await
        .unwrap();
    bind(
        &db,
        &importer,
        "binding:empty-workspace",
        "database",
        "native:database",
        &no_body,
        50,
    )
    .await;
    let skipped = call(&db, "acct:other", "bootstrap", json!({}))
        .await
        .unwrap();
    assert_eq!(skipped["instructions"], boot["instructions"]);
    assert_eq!(
        skipped["instructions"]["resolved_bytes"],
        "Workspace guide".len() + "First guide".len() + "Later guide".len()
    );
    let rendered = crate::mcp::render::render("bootstrap", &skipped).unwrap();
    for secret in [
        &hidden,
        "binding:workspace-hidden",
        "binding:workspace-missing",
        "workspace:missing-private-source",
    ] {
        assert!(!skipped.to_string().contains(secret));
        assert!(!rendered.contains(secret));
    }
    bind(
        &db,
        &importer,
        "binding:dangling",
        "account",
        "acct:other",
        "missing:instruction",
        30,
    )
    .await;
    bind(
        &db,
        &importer,
        "binding:hidden",
        "account",
        "acct:other",
        &hidden,
        40,
    )
    .await;
    let partial = call(&db, "acct:other", "bootstrap", json!({}))
        .await
        .unwrap();
    assert_eq!(partial["instructions"]["status"], "partial");
    assert_eq!(
        partial["instructions"]["diagnostics"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let text = crate::mcp::render::render("bootstrap", &partial).unwrap();
    assert!(text.contains("missing:instruction"));
    assert!(text.contains(&hidden));
    assert!(text.contains("Standing instructions are partial"));
    let binding = kernel::ImportInstructionBinding {
        id: "binding:forgery".into(),
        account_principal: Some(other.clone()),
        scope_kind: "account".into(),
        scope_id: "acct:other".into(),
        source_record_id: "source:first".into(),
        position: 0,
        enabled: true,
        created_at: "2026-10-01T00:00:00Z".into(),
        actor: Some("legacy-author".into()),
    };
    assert!(kernel::import_instruction_binding_as(&db, &admin, &binding)
        .await
        .is_err());
    for event_type in [
        "kernel.instruction_binding_imported.v1",
        "kernel.instruction_binding_updated.v1",
    ] {
        assert!(crate::store::append(
            &db,
            crate::store::AppendSpec {
                record_id: binding.id.clone(),
                event_type: event_type.into(),
                payload: serde_json::to_value(&binding).unwrap(),
                actor: Some(importer.clone()),
            }
        )
        .await
        .is_err());
    }
    let mut changed = binding.clone();
    changed.id = "binding:first".into();
    assert!(
        kernel::import_instruction_binding_as(&db, &importer, &changed)
            .await
            .is_err()
    );
    let legacy: (String,Option<String>,String) = sqlx::query_as("SELECT b.created_at,b.legacy_actor,e.actor FROM kernel_instruction_bindings b JOIN content_events e ON e.seq=b.event_seq WHERE b.id='binding:first'").fetch_one(db.write_pool()).await.unwrap();
    assert_eq!(
        legacy,
        (
            "2026-10-01T00:00:00Z".into(),
            Some("v1:original-v1-account".into()),
            importer.clone()
        )
    );
    let original = kernel::ImportInstructionBinding {
        id: "binding:first".into(),
        scope_kind: "account".into(),
        scope_id: "other".into(),
        account_principal: Some(other.clone()),
        source_record_id: "source:first".into(),
        position: 10,
        enabled: true,
        created_at: "2026-10-01T00:00:00Z".into(),
        actor: Some("original-v1-account".into()),
    };
    let mut revised = original.clone();
    revised.enabled = false;
    assert_eq!(
        kernel::import_instruction_binding_as(&db, &importer, &revised)
            .await
            .unwrap(),
        kernel::InstructionBindingImportResult::Updated
    );
    assert_eq!(
        kernel::import_instruction_binding_as(&db, &importer, &revised)
            .await
            .unwrap(),
        kernel::InstructionBindingImportResult::Unchanged
    );
    let disabled = call(&db, "acct:other", "bootstrap", json!({}))
        .await
        .unwrap();
    assert_eq!(
        disabled["instructions"]["entries"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        disabled["instructions"]["entries"][1]["content"],
        "Later guide"
    );
    revised.enabled = true;
    revised.position = 5;
    revised.source_record_id = "source:unbound".into();
    assert_eq!(
        kernel::import_instruction_binding_as(&db, &importer, &revised)
            .await
            .unwrap(),
        kernel::InstructionBindingImportResult::Updated
    );
    let retargeted = call(&db, "acct:other", "bootstrap", json!({}))
        .await
        .unwrap();
    assert_eq!(
        retargeted["instructions"]["entries"][1]["content"],
        "Must not appear"
    );
    assert_eq!(
        retargeted["instructions"]["entries"][2]["content"],
        "Later guide"
    );
    // Returning to the initial snapshot is still an update to the latest state.
    assert_eq!(
        kernel::import_instruction_binding_as(&db, &importer, &original)
            .await
            .unwrap(),
        kernel::InstructionBindingImportResult::Updated
    );
    let imported_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE record_id='binding:first' AND type IN ('kernel.instruction_binding_imported.v1','kernel.instruction_binding_updated.v1')").fetch_one(db.write_pool()).await.unwrap();
    assert_eq!(imported_events, 4);
    let provenance: (String, Option<String>) = sqlx::query_as(
        "SELECT created_at,legacy_actor FROM kernel_instruction_bindings WHERE id='binding:first'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(
        provenance,
        (
            original.created_at.clone(),
            Some("v1:original-v1-account".into())
        )
    );
    let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
    kernel::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
    db = crate::db::open_database(path.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        kernel::import_instruction_binding_as(&db, &importer, &original)
            .await
            .unwrap(),
        kernel::InstructionBindingImportResult::Unchanged
    );
    let reopened = call(&db, "acct:other", "bootstrap", json!({}))
        .await
        .unwrap();
    assert_eq!(reopened["instructions"], partial["instructions"]);

    // Intent storage faults must abort the request, rather than echoing no intent.
    let key = boot["run"]["run_key"].as_str().unwrap();
    call(
        &db,
        "acct:other",
        "set_intent",
        json!({"run_key":key,"intent":"Preserved intent"}),
    )
    .await
    .unwrap();
    // Deliberate corruption in this disposable fixture only; ordinary writes
    // retain the append-only guard.
    sqlx::query("DROP TRIGGER content_events_no_update")
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query(
        "UPDATE content_events SET payload='invalid-json' WHERE type='kernel.run_intent_set.v1'",
    )
    .execute(db.write_pool())
    .await
    .unwrap();
    let error = call(&db, "acct:other", "bootstrap", json!({"run_key":key}))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("expected"), "{error}");
    sqlx::query("ALTER TABLE content_events RENAME TO unavailable_content_events")
        .execute(db.write_pool())
        .await
        .unwrap();
    let storage_error = call(&db, "acct:other", "bootstrap", json!({"run_key":key}))
        .await
        .unwrap_err();
    assert!(
        storage_error.to_string().contains("no such table"),
        "{storage_error}"
    );
}
