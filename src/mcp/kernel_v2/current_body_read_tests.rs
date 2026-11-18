//! Inactive composed current-body proofs; no execution claimed before qualification.
use super::current_body_read::{self as current, Stage};
use super::tests::registry;
use super::*;
use crate::coedit::{
    live::{self, kernel_reads, kernel_writes, OpenRequest, Opened, SessionPeer},
    PeerKind,
};
use crate::events::KERNEL_ROOT_ID;
use yrs::updates::decoder::Decode;
use yrs::{Doc, GetString, OffsetKind, Options, ReadTxn, Text, Transact, Update};
#[derive(Clone)]
struct World {
    db: crate::db::Db,
    admin: String,
    caller: Caller,
}
// Genuine source fixtures use the same V1 admission/import workflow as the
// qualified kernel policy tests; no target fact or projection rows are forged.
struct ImportedV1 {
    dir: tempfile::TempDir,
    source: Db,
    world: World,
    account: String,
    record: String,
}
async fn import_v1_snapshot(dir: &std::path::Path, resume: bool) -> crate::v1_import::Report {
    let report = crate::v1_import::run(crate::v1_import::Options {
        source: dir.join("source.db"),
        target: dir.join("target.db"),
        seeds: vec![],
        all: true,
        history: true,
        resume,
        members_file: Some(dir.join("members.txt")),
    })
    .await
    .unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    assert!(
        report.review.is_empty(),
        "{}",
        serde_json::to_string(&report.review).unwrap()
    );
    report
}
async fn imported_v1() -> ImportedV1 {
    use crate::identity::hosted::{
        reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
        HostedMembershipSource,
    };
    let dir = tempfile::tempdir().unwrap();
    let source = crate::create_database(dir.path().join("source.db").to_str().unwrap())
        .await
        .unwrap();
    let account = reconcile_hosted_identity(
        &source,
        "read-fence-owner@example.test",
        "read-fence-owner",
        &HostedMembershipArrival::new(
            HostedMembershipRole::Owner,
            HostedMembershipSource::Direct,
            "2026-10-28T00:00:00Z".into(),
        )
        .unwrap(),
        None,
    )
    .await
    .unwrap();
    registry().call(source.clone(), Caller::local(), "manage_record_policy", json!({"action":"grant","record_id":"native:root","subject":{"kind":"account","account_id":account},"capability":"manage","reason":"Establish source importer owner"})).await.unwrap();
    let record = registry().call(source.clone(), Caller::authenticated(account.clone()), "create_record", json!({"type":"Document","kind":"note","name":"Read fence source","body":"genuine V1 source body","home_id":"native:root","reason":"Prepare read fence import"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    std::fs::write(dir.path().join("members.txt"), format!("{account}\n")).unwrap();
    let report = import_v1_snapshot(dir.path(), false).await;
    let db = kernel::open_v2_database(dir.path().join("target.db").to_str().unwrap())
        .await
        .unwrap();
    let world = World {
        db,
        admin: report.principals[&account].clone(),
        caller: Caller::authenticated(account.clone()),
    };
    ImportedV1 {
        dir,
        source,
        world,
        account,
        record,
    }
}

async fn world() -> World {
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    kernel::prepare_v2_database(&db).await.unwrap();
    let package = crate::v2_standard::v1_compat::package();
    let identity = package.identity().unwrap();
    kernel::install_package_as(&db, &admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&identity),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let manifest: Value = serde_json::from_str(crate::meta::kind::CORE_KIND_MANIFEST_JSON).unwrap();
    let mut rows = Vec::new();
    for typ in ["Document", "WorkItem"] {
        rows.push((
            "vocabularies",
            json!({"id":format!("voc:kind:{typ}"),"name":format!("kind:{typ}")}),
        ));
        for entry in manifest["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["type"] == typ)
        {
            rows.push(("vocabulary_values", json!({"id":entry["value_id"], "vocabulary_id":format!("voc:kind:{typ}"), "value":entry["token"], "status":"active", "gloss":null,"ordinal":0,"terminality":"open","metadata":entry["metadata"].to_string(),"alias_of":null})));
        }
    }
    let rows = rows
        .into_iter()
        .map(|(section, row)| kernel::v1_state::ImportedState {
            section: section.into(),
            source_id: row["id"].as_str().unwrap().into(),
            origin: "kernel-coedit-proof".into(),
            value_json: Some(row.to_string()),
            account_principal: None,
            record_id: None,
            observed_at: "2026-10-28T00:00:00Z".into(),
            snapshot: json!({}),
        })
        .collect::<Vec<_>>();
    kernel::v1_state::import_state_batch_as(&db, &host, &rows)
        .await
        .unwrap();
    let v1_tables: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('records','vocabularies','vocabulary_values')").fetch_one(db.pool()).await.unwrap();
    assert_eq!(v1_tables, 0);
    World {
        db,
        admin,
        caller: Caller::authenticated("acct:admin"),
    }
}
async fn record(w: &World, typ: &str, kind: &str, body: Option<&str>) -> String {
    let id = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":typ,"v1_kind":kind,"title":"Foundation"}).to_string(),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    if let Some(body) = body {
        let revision = kernel::read_record_as(&w.db, &w.admin, &id)
            .await
            .unwrap()
            .unwrap()
            .revision;
        kernel::set_body_as(&w.db, &w.admin, &id, body, revision)
            .await
            .unwrap();
    }
    id
}

async fn room(w: &World, id: &str) -> (SessionPeer, Opened) {
    let (peer, opened) = kernel_writes::open_for_test(
        &w.db,
        &w.caller,
        OpenRequest {
            record_id: id.into(),
            mode: PeerKind::Edit,
            resume_peer: None,
        },
    )
    .await
    .unwrap();
    peer.set_idle_after_for_test(std::time::Duration::from_secs(3600));
    peer.set_version_interval_for_test(std::time::Duration::ZERO);
    (peer, opened)
}

async fn peer_update(peer: &SessionPeer, opened: &Opened, text: &str) -> Vec<u8> {
    let mut options =
        Options::with_client_id(yrs::ClientID::new(u64::from(opened.doc_client_ids[0])));
    options.offset_kind = OffsetKind::Bytes;
    let doc = Doc::with_options(options);
    let sync = peer.sync(&[]).await.unwrap();
    doc.transact_mut()
        .apply_update(Update::decode_v1(&sync).unwrap())
        .unwrap();
    let before = doc.transact().state_vector();
    let body = doc.get_or_insert_text("body");
    let end = body.get_string(&doc.transact()).len() as u32;
    body.insert(&mut doc.transact_mut(), end, text);
    let update = doc.transact().encode_diff_v1(&before);
    update
}

async fn append_peer(peer: &SessionPeer, opened: &Opened, text: &str) {
    let update = peer_update(peer, opened, text).await;
    peer.apply("writer-proof", &update).await.unwrap();
}

async fn update(w: &World, args: Value) -> crate::Result<Value> {
    call(w, "update_record", args).await
}
async fn call(w: &World, name: &str, args: Value) -> crate::Result<Value> {
    let mut tools = crate::mcp::registry::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut tools).unwrap();
    crate::mcp::tools::register_surface_tools(&mut tools).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut tools).unwrap();
    tools
        .call_engine(
            crate::mcp::registry::EngineHandle::KernelV2(w.db.clone()),
            w.caller.clone(),
            name,
            args,
        )
        .await
}

// Run context is a request argument at ordinary registry ingress; a Caller
// field alone is replaced by canonical resolution. Retain the actual echo even
// when the selected handler's T2 principal check refuses.
async fn keyed_one(w: &World, id: &str, key: &str) -> Result<Value> {
    assert_eq!(w.caller.run_key(), Some(key));
    let tools = registry();
    let outcome = current::with_current_body_probe(tools.call_engine_detailed(
        EngineHandle::KernelV2(w.db.clone()),
        w.caller.clone(),
        "get_record",
        json!({"ids":[id],"run_key":key}),
    ))
    .await?;
    assert_eq!(outcome.original_arguments["run_key"].as_str(), Some(key));
    assert_eq!(outcome.run_context["run_key"].as_str(), Some(key));
    let result = outcome.into_result()?;
    Ok(result["records"][0].clone())
}

async fn stored_body(w: &World, id: &str) -> String {
    kernel::read_record_as(&w.db, &w.admin, id)
        .await
        .unwrap()
        .unwrap()
        .body
        .unwrap_or_default()
}

async fn read(w: &World, ids: &[String]) -> Result<Value> {
    current::with_current_body_probe(call(w, "get_record", json!({"ids":ids}))).await
}
async fn one(w: &World, id: &str) -> Result<Value> {
    read(w, &[id.to_owned()])
        .await
        .map(|v| v["records"][0].clone())
}
fn fork(w: &World) -> World {
    w.clone()
}
async fn events(w: &World) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap()
}
async fn peer_apply_bytes(peer: &SessionPeer, opened: &Opened, text: &str) -> Vec<u8> {
    peer_update(peer, opened, text).await
}
async fn entered(gate: &std::sync::Arc<current::Gate>) {
    tokio::time::timeout(std::time::Duration::from_secs(20), gate.entered.notified())
        .await
        .expect("test checkpoint not reached");
}

#[tokio::test]
async fn ordinary_view_account_and_nonaccount_get_record_observe_acknowledged_live_body() {
    let w = world().await;
    let viewer = kernel::create_principal(&w.db, "account", "Viewer", "read:viewer", &w.admin)
        .await
        .unwrap();
    let agent = kernel::create_principal(&w.db, "agent", "Observer", "read:agent", &w.admin)
        .await
        .unwrap();
    let home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "edit"), (&viewer, "view"), (&agent, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    let id = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":"Document","v1_kind":"note","title":"View"}).to_string(),
        &home,
    )
    .await
    .unwrap();
    let rev = kernel::read_record_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_body_as(&w.db, &w.admin, &id, "seed", rev)
        .await
        .unwrap();
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " live").await;
    let count = events(&w).await;
    for binding in ["read:viewer", "read:agent"] {
        let reader = World {
            caller: Caller::authenticated(binding),
            ..fork(&w)
        };
        let row = one(&reader, &id).await.unwrap();
        assert_eq!(row["body"], "seed");
        assert_eq!(row["live_body"]["body"], "seed live");
        assert_eq!(row["live_body"]["dirty"], true);
        assert_eq!(row["body_read_contract"], "native.current-body.v1");
        assert!(update(&reader, json!({"id":id,"body_append":" denied"}))
            .await
            .is_err());
        assert!(kernel_writes::open_for_test(
            &w.db,
            &reader.caller,
            OpenRequest {
                record_id: id.clone(),
                mode: PeerKind::Edit,
                resume_peer: None
            }
        )
        .await
        .is_err());
    }
    assert_eq!(events(&w).await, count);
    peer.leave().await;
    let home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "edit"), (&agent, "edit")]),
        &w.admin,
    )
    .await
    .unwrap();
    let plain = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":"Document","v1_kind":"note","title":"Ordinary agent"}).to_string(),
        &home,
    )
    .await
    .unwrap();
    let agent_writer = World {
        caller: Caller::authenticated("read:agent"),
        ..fork(&w)
    };
    update(
        &agent_writer,
        json!({"id":plain,"body_append":"ordinary non-account"}),
    )
    .await
    .unwrap();
    update(
        &agent_writer,
        json!({"id":plain,"name":"non-account metadata"}),
    )
    .await
    .unwrap();
    assert_eq!(
        one(&agent_writer, &plain).await.unwrap()["body"],
        "ordinary non-account"
    );
    assert!(kernel_writes::base_for_test(&w.db, &plain).is_none());
    assert!(kernel_writes::open_for_test(
        &w.db,
        &agent_writer.caller,
        OpenRequest {
            record_id: plain,
            mode: PeerKind::Edit,
            resume_peer: None
        }
    )
    .await
    .is_err()); // Only CRDT author admission remains account-only.
}

#[tokio::test]
async fn current_probe_off_preserves_existing_durable_get_record_and_durable_consumers() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " live").await;
    let before = events(&w).await;
    let ordinary = call(&w, "get_record", json!({"ids":[id]})).await.unwrap();
    assert_eq!(ordinary["records"][0]["body"], "seed");
    assert!(ordinary["records"][0].get("live_body").is_none());
    assert_eq!(stored_body(&w, &id).await, "seed");
    let history = call(&w, "get_history", json!({"record_id":id,"detail":"full"}))
        .await
        .unwrap();
    assert!(!history.to_string().contains("seed live"));
    assert_eq!(events(&w).await, before);
    peer.leave().await;
}

#[tokio::test]
async fn no_room_get_record_preserves_null_empty_large_and_non_live_scope_readability() {
    let w = world().await;
    let absent = record(&w, "Document", "note", None).await;
    let empty = record(&w, "Document", "note", Some("")).await;
    let before = events(&w).await;
    let result = read(&w, &[absent.clone(), empty.clone()]).await.unwrap();
    let rows = result["records"].as_array().unwrap();
    assert_eq!(rows[0]["body_basis"]["body_present"], false);
    assert_eq!(rows[1]["body_basis"]["body_present"], true);
    assert_eq!(rows[0]["body_digest"], rows[1]["body_digest"]);
    assert_ne!(
        rows[0]["body_basis"]["revision"],
        rows[1]["body_basis"]["revision"]
    );
    for row in rows {
        assert_eq!(row["live_body"], Value::Null);
    }
    assert_eq!(events(&w).await, before);
    let large = "x".repeat(1024 * 1024 + 1);
    let large_id = record(&w, "Document", "note", Some(&large)).await;
    let row = one(&w, &large_id).await.unwrap();
    assert_eq!(row["body"], large);
    assert_eq!(row["live_body"], Value::Null);
    assert!(kernel_writes::open_for_test(
        &w.db,
        &w.caller,
        OpenRequest {
            record_id: large_id,
            mode: PeerKind::Edit,
            resume_peer: None
        }
    )
    .await
    .is_err());
    // An attachment derives View from a real bearer; create_json alone leaves
    // it intentionally hidden. Use actual attach_text admission before body set.
    let bearer = record(&w, "Document", "note", Some("attachment bearer")).await;
    let special = call(
        &w,
        "attach_text",
        json!({"record_id":bearer,"text":"non-live durable body","filename":"read-fence.txt"}),
    )
    .await
    .unwrap()["attachment_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let revision = kernel::read_record_as(&w.db, &w.admin, &special)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_body_as(&w.db, &w.admin, &special, "non-live durable body", revision)
        .await
        .unwrap();
    let row = one(&w, &special).await.unwrap();
    assert_eq!(row["body"], "non-live durable body");
    assert_eq!(row["live_body"], Value::Null);
    let actual = kernel::read_record_as(&w.db, &w.admin, &special)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(actual.fields["v1_type"], "Document");
    assert_eq!(actual.fields["v1_kind"], "attachment");
    let (birth_type, birth_typ, birth_kind): (String,String,String) = sqlx::query_as("SELECT e.type,json_extract(e.payload,'$.fields.v1_type'),json_extract(e.payload,'$.fields.v1_kind') FROM main.kernel_records r JOIN main.content_events e ON e.seq=r.created_seq AND e.record_id=r.id WHERE r.id=?").bind(&special).fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(
        (birth_type.as_str(), birth_typ.as_str(), birth_kind.as_str()),
        ("kernel.record_created.v1", "Document", "attachment")
    );
    let mut snapshot = w.db.write_pool().begin().await.unwrap();
    let interpreter = kernel::v1_state::interpreter_on(&mut snapshot, &w.admin)
        .await
        .unwrap();
    assert_eq!(
        interpreter.canonical_imported_kind("Document", "attachment"),
        "attachment"
    );
    crate::coedit::kernel_v2::require_live_scope_on(&mut snapshot, &w.admin, &actual)
        .await
        .unwrap();
    snapshot.rollback().await.unwrap();
    // Existing predicate deliberately keeps ordinary Document attachment scope.
    let (attachment_peer, _) = kernel_writes::open_for_test(
        &w.db,
        &w.caller,
        OpenRequest {
            record_id: special,
            mode: PeerKind::Edit,
            resume_peer: None,
        },
    )
    .await
    .unwrap();
    attachment_peer.leave().await;

    // Genuine explicitly excluded kind, created through ordinary native tools.
    let instruction = call(&w, "create_record", json!({"type":"Document","kind":"instruction","name":"Read-only unsupported scope","body":"non-live instruction body","reason":"Prove NoRoom preserves ordinary View"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let actual = kernel::read_record_as(&w.db, &w.admin, &instruction)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(actual.fields["v1_type"], "Document");
    assert_eq!(actual.fields["v1_kind"], "instruction");
    let (birth_type, birth_typ, birth_kind): (String,String,String) = sqlx::query_as("SELECT e.type,json_extract(e.payload,'$.fields.v1_type'),json_extract(e.payload,'$.fields.v1_kind') FROM main.kernel_records r JOIN main.content_events e ON e.seq=r.created_seq AND e.record_id=r.id WHERE r.id=?").bind(&instruction).fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(
        (birth_type.as_str(), birth_typ.as_str(), birth_kind.as_str()),
        ("kernel.record_created.v1", "Document", "instruction")
    );
    let mut snapshot = w.db.write_pool().begin().await.unwrap();
    let interpreter = kernel::v1_state::interpreter_on(&mut snapshot, &w.admin)
        .await
        .unwrap();
    assert_eq!(
        interpreter.canonical_imported_kind("Document", "instruction"),
        "instruction"
    );
    let refused = crate::coedit::kernel_v2::require_live_scope_on(&mut snapshot, &w.admin, &actual)
        .await
        .unwrap_err();
    assert!(refused
        .to_string()
        .contains("room scope is no longer live Markdown"));
    snapshot.rollback().await.unwrap();
    let row = one(&w, &instruction).await.unwrap();
    assert_eq!(row["body"], "non-live instruction body");
    assert_eq!(row["live_body"], Value::Null);
    assert!(kernel_writes::open_for_test(
        &w.db,
        &w.caller,
        OpenRequest {
            record_id: instruction,
            mode: PeerKind::Edit,
            resume_peer: None
        }
    )
    .await
    .is_err());
    let runtime = record(&w, "Document", "note", Some("runtime durable body")).await;
    kernel::observe_facet_as(
        &w.db,
        &w.admin,
        &runtime,
        &kernel::FacetObservation {
            key: "runtime".into(),
            value: Some("html".into()),
            value_num: None,
            vocab_ref: None,
            as_of: "2026-10-28T00:00:00Z".into(),
        },
        None,
    )
    .await
    .unwrap();
    let row = one(&w, &runtime).await.unwrap();
    assert_eq!(row["body"], "runtime durable body");
    assert_eq!(row["live_body"], Value::Null);
    assert!(kernel_writes::open_for_test(
        &w.db,
        &w.caller,
        OpenRequest {
            record_id: runtime,
            mode: PeerKind::Edit,
            resume_peer: None
        }
    )
    .await
    .is_err());
}

#[tokio::test]
async fn accepted_epoch_changes_in_each_gap_retry_once_on_original_deadline() {
    for stage in [Stage::AfterT1, Stage::SqlClosed] {
        let w = world().await;
        let id = record(&w, "Document", "note", Some("seed")).await;
        let (peer, opened) = room(&w, &id).await;
        let bytes = peer_apply_bytes(&peer, &opened, " accepted").await;
        let gate = current::gate(&w.db, stage);
        let reader = {
            let w = fork(&w);
            let id = id.clone();
            tokio::spawn(async move { one(&w, &id).await })
        };
        entered(&gate).await;
        peer.apply("accepted-between-phases", &bytes).await.unwrap();
        gate.release.notify_one();
        let row = reader.await.unwrap().unwrap();
        assert_eq!(row["live_body"]["body"], "seed accepted");
        peer.leave().await;
    }
    // Repeated actual acknowledged churn refuses the whole attempt1 result.
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    let first = current::gate(&w.db, Stage::SqlClosed);
    let retry = current::gate(&w.db, Stage::Retry);
    let reader = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move { one(&w, &id).await })
    };
    entered(&first).await;
    append_peer(&peer, &opened, " first").await;
    first.release.notify_one();
    entered(&retry).await;
    let second = current::gate(&w.db, Stage::SqlClosed);
    retry.release.notify_one();
    entered(&second).await;
    append_peer(&peer, &opened, " second").await;
    second.release.notify_one();
    assert!(reader.await.unwrap().is_err());
    peer.leave().await;

    // Virtual clock is the deadline stimulus, never a scheduling oracle.
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    let first = current::gate(&w.db, Stage::AfterT1);
    let retry = current::gate(&w.db, Stage::Retry);
    let reader = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move { one(&w, &id).await })
    };
    entered(&first).await;
    tokio::time::pause();
    // Keep the runtime ready so it cannot auto-advance while SQLite workers
    // execute real SQL. Only explicit advance() moves this proof's clock.
    let clock_hold = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    tokio::time::advance(std::time::Duration::from_secs(8)).await;
    append_peer(&peer, &opened, " deadline").await;
    first.release.notify_one();
    entered(&retry).await;
    let second = current::gate(&w.db, Stage::AfterT1);
    retry.release.notify_one();
    entered(&second).await;
    tokio::time::advance(std::time::Duration::from_secs(3)).await;
    assert!(reader.await.unwrap().is_err()); // original10s, not fresh attempt1
    clock_hold.abort();
    let _ = clock_hold.await;
    tokio::time::resume();
    peer.leave().await;
}

#[tokio::test]
async fn same_epoch_cut_and_same_bytes_new_event_invalidate_current_body_fence() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " dirty").await;
    let gate = current::gate(&w.db, Stage::SqlClosed);
    let reader = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move { one(&w, &id).await })
    };
    entered(&gate).await;
    let cut = peer
        .version("cut between T2 and T3")
        .await
        .unwrap()
        .unwrap();
    gate.release.notify_one();
    let row = reader.await.unwrap().unwrap();
    assert_eq!(row["body_basis"]["body_event"]["id"], cut.event_id);
    assert_eq!(row["live_body"]["dirty"], false);
    assert_eq!(row["body"], "seed dirty");
    let before = one(&w, &id).await.unwrap();
    update(&w, json!({"id":id,"name":"metadata only"}))
        .await
        .unwrap();
    let metadata = one(&w, &id).await.unwrap();
    assert_ne!(metadata["record_version"], before["record_version"]);
    assert_eq!(
        metadata["body_basis"]["revision"],
        before["body_basis"]["revision"]
    );
    assert_eq!(
        metadata["live_body"]["revision"],
        before["live_body"]["revision"]
    );
    // Ordinary identical body_set is deliberately a no-op. Preserve that
    // compatibility, then create genuine accepted dirty items with equal text.
    update(
        &w,
        json!({"id":id,"body_set":"seed dirty","if_body_digest":metadata["body_digest"]}),
    )
    .await
    .unwrap();
    assert_eq!(
        one(&w, &id).await.unwrap()["body_basis"]["body_event"],
        metadata["body_basis"]["body_event"]
    );
    let insert = peer_update(&peer, &opened, "x").await;
    peer.apply("equal-text-insert", &insert).await.unwrap();
    let mut options =
        Options::with_client_id(yrs::ClientID::new(u64::from(opened.doc_client_ids[0])));
    options.offset_kind = OffsetKind::Bytes;
    let doc = Doc::with_options(options);
    doc.transact_mut()
        .apply_update(Update::decode_v1(&peer.sync(&[]).await.unwrap()).unwrap())
        .unwrap();
    let before_delete = doc.transact().state_vector();
    let body = doc.get_or_insert_text("body");
    let last = body.get_string(&doc.transact()).len() as u32 - 1;
    body.remove_range(&mut doc.transact_mut(), last, 1);
    let delete = doc.transact().encode_diff_v1(&before_delete);
    peer.apply("equal-text-delete", &delete).await.unwrap();
    let epochs_before = kernel_reads::observed_epochs_for_test(&w.db, &id).unwrap();
    assert!(epochs_before.1 < epochs_before.0); // genuine accepted dirty items
    let gate = current::gate(&w.db, Stage::SqlClosed);
    let reader = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move { one(&w, &id).await })
    };
    entered(&gate).await;
    let same_text_cut = peer
        .version("same bytes, genuine new body event after T2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        same_text_cut.body_sha256,
        metadata["body_digest"].as_str().unwrap()
    );
    let epochs_after = kernel_reads::observed_epochs_for_test(&w.db, &id).unwrap();
    assert_eq!(epochs_after.0, epochs_before.0); // no accepted edit across T1/T2/T3
    assert_eq!(epochs_after.1, epochs_after.0); // actual cut advanced versioned epoch
    assert_ne!(epochs_after.1, epochs_before.1);
    // This is the full committed-coordinate fence, NOT an isolated body-event-
    // only predicate: legal drain/install advances versioned_epoch as well.

    gate.release.notify_one();
    let same = reader.await.unwrap().unwrap();
    assert_eq!(
        same["body_basis"]["body_event"]["id"],
        same_text_cut.event_id
    );
    assert_eq!(same["body"], metadata["body"]);
    assert_ne!(
        same["body_basis"]["body_event"],
        metadata["body_basis"]["body_event"]
    );
    assert_ne!(
        same["body_basis"]["revision"],
        metadata["body_basis"]["revision"]
    );
    peer.leave().await;
}

#[tokio::test]
async fn no_room_publication_guard_blocks_seed_through_sql_and_close() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let first = current::gate(&w.db, Stage::AfterT1);
    let closed = current::gate(&w.db, Stage::SqlClosed);
    let reader = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move { one(&w, &id).await })
    };
    entered(&first).await;
    assert!(!live::release_idle_database(&w.db)); // actual owner pin, no room
    let queued = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::SeedGateQueued, false);
    let opener = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move { room(&w, &id).await })
    };
    queued.entered.notified().await;
    queued.release.notify_one();
    first.release.notify_one();
    entered(&closed).await;
    assert!(kernel_writes::base_for_test(&w.db, &id).is_none());
    assert!(!opener.is_finished());
    closed.release.notify_one();
    let row = reader.await.unwrap().unwrap();
    assert_eq!(row["live_body"], Value::Null);
    let (peer, _) = opener.await.unwrap();
    peer.leave().await;
}

#[tokio::test]
async fn exact_seed_handle_clones_pass_reopened_foreign_handle_join_and_read_refuse() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " live").await;
    assert!(one(&fork(&w), &id).await.is_ok());
    let db = kernel::open_v2_database(w.db.path().to_str().unwrap())
        .await
        .unwrap();
    assert!(!db.same_handle(&w.db));
    assert_ne!(db.handle_id(), w.db.handle_id());
    let foreign = World { db, ..fork(&w) };
    assert!(one(&foreign, &id).await.is_err());
    assert!(kernel_writes::open_for_test(
        &foreign.db,
        &foreign.caller,
        OpenRequest {
            record_id: id.clone(),
            mode: PeerKind::Edit,
            resume_peer: None
        }
    )
    .await
    .is_err());
    assert!(update(&foreign, json!({"id":id,"body_append":" foreign"}))
        .await
        .is_err());
    assert!(one(&w, &id).await.is_ok());
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed live")
    );
    peer.leave().await;
}

async fn scoped_view_record(w: &World) -> (World, String, String, String) {
    let principal =
        kernel::create_principal(&w.db, "account", "Scoped reader", "read:scoped", &w.admin)
            .await
            .unwrap();
    let home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "edit"), (&principal, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    let id = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":"Document","v1_kind":"note","title":"Scoped"}).to_string(),
        &home,
    )
    .await
    .unwrap();
    let rev = kernel::read_record_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_body_as(&w.db, &w.admin, &id, "seed", rev)
        .await
        .unwrap();
    (
        World {
            caller: Caller::authenticated("read:scoped"),
            ..fork(w)
        },
        id,
        home,
        principal,
    )
}

#[tokio::test]
async fn view_membership_and_historical_run_changes_use_t2_unbound_caller_refuses() {
    // Actual native View revocation, before versus after first SQL snapshot.
    // No projection edits manufacture authority or revocation evidence.
    for stage in [Stage::AfterT1, Stage::SnapshotReady] {
        let w = world().await;
        let (reader, id, home, _) = scoped_view_record(&w).await;
        let (peer, opened) = room(&w, &id).await;
        append_peer(&peer, &opened, " secret").await;
        let gate = current::gate(&w.db, stage);
        let reading = {
            let id = id.clone();
            tokio::spawn(async move { one(&reader, &id).await })
        };
        entered(&gate).await;
        kernel::replace_home_policy(&w.db, &w.admin, &home, &[(&w.admin, "edit")])
            .await
            .unwrap();
        gate.release.notify_one();
        let result = reading.await.unwrap();
        if stage == Stage::AfterT1 {
            match result {
                Ok(row) => {
                    assert_eq!(row["status"], "not_found");
                    assert!(row.get("live_body").is_none());
                }
                Err(error) => assert!(!error.to_string().contains("seed secret")),
            }
        } else {
            // T2, rather than T3 current authority, is the documented point.
            let row = result.unwrap();
            assert_eq!(row["live_body"]["body"], "seed secret");
        }
        peer.leave().await;
    }
    for stage in [Stage::AfterT1, Stage::SnapshotReady] {
        let w = world().await;
        let (reader, id, _, _) = scoped_view_record(&w).await;
        async fn roster(w: &World, members: &[&str]) {
            kernel::hosted_identity::reconcile_hosted_caller(&w.db, |_| async {
                // SAFETY: this fixture owns the complete host catalogue. The
                // real reconciliation API appends the actual roster event.
                Ok(unsafe {
                    kernel::hosted_identity::VerifiedHostedMembership::from_accounts_unchecked(
                        "acct:admin".into(),
                        members.iter().map(|s| (*s).into()).collect(),
                    )
                })
            })
            .await
            .unwrap();
        }
        roster(&w, &["acct:admin", "read:scoped"]).await;
        let (peer, opened) = room(&w, &id).await;
        append_peer(&peer, &opened, " membership secret").await;
        let gate = current::gate(&w.db, stage);
        let reading = {
            let id = id.clone();
            tokio::spawn(async move { one(&reader, &id).await })
        };
        entered(&gate).await;
        roster(&w, &["acct:admin"]).await;
        gate.release.notify_one();
        let result = reading.await.unwrap();
        if stage == Stage::AfterT1 {
            assert!(result.is_err());
        } else {
            assert_eq!(
                result.unwrap()["live_body"]["body"],
                "seed membership secret"
            );
        }
        let unbound = World {
            caller: Caller::authenticated("read:no-such-binding"),
            ..fork(&w)
        };
        assert!(one(&unbound, &id).await.is_err());
        peer.leave().await;
    }
    for stage in [Stage::AfterT1, Stage::SnapshotReady] {
        let imported = imported_v1().await;
        // Actual V1 bootstrap issues the correlation key AFTER initial export.
        // It has no native runtime ledger in the target; never collide/overwrite
        // a key minted by target kernel bootstrap or invent an arbitrary word.
        let run = registry()
            .call(
                imported.source.clone(),
                Caller::authenticated(imported.account.clone())
                    .with_channel(crate::provenance::Channel::Mcp),
                "bootstrap",
                json!({"run_key":"new"}),
            )
            .await
            .unwrap();
        let key = run["run"]["run_key"].as_str().unwrap().to_owned();
        assert_eq!(run["session"]["run_key"].as_str(), Some(key.as_str()));
        // Authoritative source persistence, not merely a minted response string.
        let (activity, source_account, start_id, start_seq, control_type, control_key): (String,String,String,i64,String,String) = sqlx::query_as("SELECT r.activity_id,r.account_id,r.start_event_id,r.start_event_seq,e.type,e.run_key FROM main.agent_runs r JOIN main.control_events e ON e.id=r.start_event_id AND e.seq=r.start_event_seq AND e.aggregate_id=r.activity_id WHERE r.run_key=?").bind(&key).fetch_one(imported.source.pool()).await.unwrap();
        assert_eq!(source_account, imported.account);
        assert_eq!(control_type, "agent_run.started.v2");
        assert_eq!(control_key, key);
        assert!(start_seq > 0 && !start_id.is_empty());
        let native_target_runs: i64 = sqlx::query_scalar("SELECT count(*) FROM main.kernel_runs r JOIN main.kernel_principals p ON p.principal_id=r.run_principal WHERE p.auth_binding=?").bind(format!("mcp-run:{key}")).fetch_one(imported.world.db.pool()).await.unwrap();
        assert_eq!(native_target_runs, 0);
        let reader = World {
            caller: imported
                .world
                .caller
                .clone()
                .with_run_context(Some(key.clone()), None),
            ..fork(&imported.world)
        };
        assert!(keyed_one(&reader, &imported.record, &key).await.is_ok());
        let gate = current::gate(&imported.world.db, stage);
        let reading = {
            let id = imported.record.clone();
            let key = key.clone();
            tokio::spawn(async move { keyed_one(&reader, &id, &key).await })
        };
        entered(&gate).await;
        // Official resume copies the REAL source run history. No live room:
        // the unported importer must never be rescued around live ownership.
        import_v1_snapshot(imported.dir.path(), true).await;
        // Exact target historical row and its actual sealed import event.
        // The official importer serializes its ordered primary-key values as
        // a JSON array, even for the single activity_id key in runs.
        let source_id = serde_json::to_string(&vec![activity.clone()]).unwrap();
        let (target_source_id, target_activity, target_key, target_start, target_account, event_type): (String,String,String,String,String,String) = sqlx::query_as("SELECT s.source_id,json_extract(s.payload,'$.activity_id'),json_extract(s.payload,'$.run_key'),json_extract(s.payload,'$.start_event_id'),s.account_principal,e.type FROM main.kernel_v1_state s JOIN main.content_events e ON e.seq=s.event_seq AND e.type='kernel.v1_state_imported.v1' AND json_extract(e.payload,'$.section')=s.section AND json_extract(e.payload,'$.source_id')=s.source_id AND json_extract(e.payload,'$.origin')=s.origin AND json_extract(e.payload,'$.record_id') IS s.record_id AND json_extract(e.payload,'$.value_json')=s.payload AND json_extract(e.payload,'$.account_principal') IS s.account_principal WHERE s.section='runs' AND s.source_id=?").bind(&source_id).fetch_one(imported.world.db.pool()).await.unwrap();
        assert_eq!(target_source_id, source_id);
        assert_eq!(target_activity, activity);
        assert_eq!(target_key, key);
        assert_eq!(target_start, start_id);
        assert_eq!(target_account, imported.world.admin);
        assert_eq!(event_type, "kernel.v1_state_imported.v1");
        gate.release.notify_one();
        let result = reading.await.unwrap();
        if stage == Stage::AfterT1 {
            let refused = result.unwrap_err();
            assert!(
                refused
                    .to_string()
                    .contains("historical imported run cannot authorize runtime writes"),
                "wrong refusal: {refused}"
            );
        } else {
            let row = result.unwrap();
            assert_eq!(row["body"], "genuine V1 source body");
            assert_eq!(row["live_body"], Value::Null);
        }
        let later = World {
            caller: imported
                .world
                .caller
                .clone()
                .with_run_context(Some(key.clone()), None),
            ..fork(&imported.world)
        };
        let refused = keyed_one(&later, &imported.record, &key).await.unwrap_err();
        assert!(
            refused
                .to_string()
                .contains("historical imported run cannot authorize runtime writes"),
            "wrong refusal: {refused}"
        );
    }
}

#[tokio::test]
async fn unsupported_explicit_or_ambient_app_snapshot_never_falls_back_to_write_pool() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " private").await;
    let claim = crate::mcp::app_attribution::AppAttribution::new(
        "example.read-proof",
        "1.0.0",
        "missing-install",
    )
    .unwrap();
    let explicit = World {
        caller: w.caller.clone().with_host_asserted_app(claim),
        ..fork(&w)
    };
    let before = events(&w).await;
    assert!(one(&explicit, &id).await.is_err());
    // This is an uninstalled claim, not fabricated installed-app authority.
    // The ambient dispatch must also be rejected on the actual read snapshot.
    let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
        &explicit.caller,
        "get_record",
        &json!({"ids":[id]}),
        None,
    );
    // Ordinary ToolRegistry replaces provenance with its actual Caller. Test
    // the ambient-only boundary directly as supplemental negative evidence;
    // it never supplies installed-app authority or a successful body result.
    assert!(dispatch
        .scope(sql::with_current_materialization(
            &w.db,
            &w.caller,
            &[("records", "id")],
            std::slice::from_ref(&id),
            |_| async { Ok(()) }
        ))
        .await
        .is_err());
    assert_eq!(events(&w).await, before);
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed private")
    );
    peer.leave().await;
}

#[tokio::test]
async fn prepared_or_failed_update_is_invisible_to_ordinary_current_get_record() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = room(&w, &id).await;
    let closed = current::gate(&w.db, Stage::SqlClosed);
    let reader = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move { one(&w, &id).await })
    };
    entered(&closed).await;
    let mutation = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterMutation, true);
    let writer = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move { update(&w, json!({"id":id,"body_append":" uncommitted"})).await })
    };
    mutation.entered.notified().await;
    // An actual prepared successor and SQL body exist, but no accepted install.
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed")
    );
    let queued = kernel_reads::gate(&w.db, kernel_reads::ReadStage::ValidateOps);
    closed.release.notify_one();
    queued.entered.notified().await; // actual mutex acquisition polled Pending
    assert!(!reader.is_finished());
    mutation.release.notify_one();
    assert!(writer.await.unwrap().is_err()); // explicit acknowledged rollback
    queued.release.notify_one();
    let row = reader.await.unwrap().unwrap();
    assert_eq!(row["body"], "seed");
    assert_eq!(row["live_body"]["body"], "seed");
    assert_eq!(stored_body(&w, &id).await, "seed");
    peer.leave().await;
}

#[tokio::test]
async fn postcommit_preinstall_get_record_waits_then_matches_or_refuses_uncertainty() {
    for uncertain in [false, true] {
        let w = world().await;
        let id = record(&w, "Document", "note", Some("seed")).await;
        let (peer, _) = room(&w, &id).await;
        let closed = current::gate(&w.db, Stage::SqlClosed);
        let reader = {
            let w = fork(&w);
            let id = id.clone();
            tokio::spawn(async move { one(&w, &id).await })
        };
        entered(&closed).await;
        let committed =
            kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterDurability, uncertain);
        let writer = {
            let w = fork(&w);
            let id = id.clone();
            tokio::spawn(
                async move { update(&w, json!({"id":id,"body_append":" committed"})).await },
            )
        };
        committed.entered.notified().await;
        assert_eq!(stored_body(&w, &id).await, "seed committed");
        assert_eq!(
            kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
            Some("seed")
        );
        let queued = kernel_reads::gate(&w.db, kernel_reads::ReadStage::ValidateOps);
        closed.release.notify_one();
        queued.entered.notified().await;
        assert!(!reader.is_finished());
        committed.release.notify_one();
        let result = writer.await.unwrap();
        queued.release.notify_one();
        if uncertain {
            assert!(result.is_err());
            assert!(reader.await.unwrap().is_err());
            assert!(kernel_writes::quarantine_for_test(&w.db).is_some());
            // Only this known-depth-zero injected postcommit resource is
            // disposed. Terminal quarantine stays armed; no product recovery.
            kernel_writes::dispose_settled_quarantine_for_test(&w.db).await;
            drop(peer);
        } else {
            result.unwrap();
            let row = reader.await.unwrap().unwrap();
            assert_eq!(row["body"], "seed committed");
            assert_eq!(row["live_body"]["body"], "seed committed");
            assert_eq!(row["live_body"]["dirty"], false);
            peer.leave().await;
        }
    }
}

#[tokio::test]
async fn composed_get_record_sql_close_ack_precedes_any_t3_ops_wait() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = room(&w, &id).await;
    let rolled = current::gate(&w.db, Stage::SqlRolledBack);
    let closed = current::gate(&w.db, Stage::SqlClosed);
    let reader = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move { one(&w, &id).await })
    };
    entered(&rolled).await; // actual explicit ROLLBACK has acknowledged
    let held = kernel_writes::KernelBodyWrite::acquire(
        &w.db,
        &w.caller,
        Some(&id),
        kernel_writes::KernelWriteMode::RouteBody,
    )
    .await
    .unwrap();
    let queued = kernel_reads::gate(&w.db, kernel_reads::ReadStage::ValidateOps);
    rolled.release.notify_one();
    entered(&closed).await; // reachable ONLY after actual lease.close().await
    assert!(!reader.is_finished());
    closed.release.notify_one();
    queued.entered.notified().await; // real ops Future Pending, no SQL retained
    assert!(!reader.is_finished());
    drop(held);
    queued.release.notify_one();
    assert!(reader.await.unwrap().is_ok());
    // An ambient original read session is refused before T1, not inherited.
    let nested = sql::with_read_session(&w.db, &w.admin, &[("records", "id")], one(&w, &id)).await;
    assert!(nested.is_err());
    peer.leave().await;
}

#[tokio::test]
async fn cancel_during_sql_or_t3_discards_session_and_releases_publication() {
    for stage in [Stage::SqlMaterialized, Stage::SqlRolledBack] {
        let w = world().await;
        let id = record(&w, "Document", "note", Some("seed")).await;
        let gate = current::gate(&w.db, stage);
        let reader = {
            let w = fork(&w);
            let id = id.clone();
            tokio::spawn(async move { one(&w, &id).await })
        };
        entered(&gate).await;
        let queued =
            kernel_writes::test_gate(&w.db, kernel_writes::TestStage::SeedGateQueued, false);
        let opener = {
            let w = fork(&w);
            let id = id.clone();
            tokio::spawn(async move { room(&w, &id).await })
        };
        queued.entered.notified().await; // exclusive publication actually Pending
        reader.abort();
        assert!(reader.await.unwrap_err().is_cancelled());
        queued.release.notify_one();
        let (peer, _) = opener.await.unwrap(); // progresses without releasing SQL gate
        assert!(one(&w, &id).await.is_ok()); // fresh governed staging identity
        peer.leave().await;
    }
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let fail = current::gate_with_failure(&w.db, Stage::SqlRolledBack, true);
    let reader = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move { one(&w, &id).await })
    };
    entered(&fail).await;
    fail.release.notify_one();
    assert!(reader.await.unwrap().is_err()); // no ClosedCurrentGet/T3/result
    assert!(one(&w, &id).await.is_ok());
    assert!(sql::with_failed_current_close_ack(one(&w, &id))
        .await
        .is_err());
    assert!(one(&w, &id).await.is_ok());
    // T3 cancellation releases the continuous publication guard as well.
    let (peer, _) = room(&w, &id).await;
    let closed = current::gate(&w.db, Stage::SqlClosed);
    let reader = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move { one(&w, &id).await })
    };
    entered(&closed).await;
    let held = kernel_writes::KernelBodyWrite::acquire(
        &w.db,
        &w.caller,
        Some(&id),
        kernel_writes::KernelWriteMode::RouteBody,
    )
    .await
    .unwrap();
    let queued = kernel_reads::gate(&w.db, kernel_reads::ReadStage::ValidateOps);
    closed.release.notify_one();
    queued.entered.notified().await;
    reader.abort();
    assert!(reader.await.unwrap_err().is_cancelled());
    drop(held);
    assert!(one(&w, &id).await.is_ok());
    peer.leave().await;
}

#[tokio::test]
async fn sealed_quarantined_closed_and_blocked_rooms_never_become_healthy_no_room() {
    let w = world().await;
    let _registration = live::register_kernel_lifecycle(&w.db);
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " retained").await;
    let closed = current::gate(&w.db, Stage::SqlClosed);
    let reader = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move { one(&w, &id).await })
    };
    entered(&closed).await;
    let held = kernel_writes::KernelBodyWrite::acquire(
        &w.db,
        &w.caller,
        Some(&id),
        kernel_writes::KernelWriteMode::RouteBody,
    )
    .await
    .unwrap();
    let queued = kernel_reads::gate(&w.db, kernel_reads::ReadStage::ValidateOps);
    closed.release.notify_one();
    queued.entered.notified().await;
    let witness = live::seal_kernel_retirement(&w.db);
    queued.release.notify_one();
    assert!(reader.await.unwrap().is_err()); // retained ops still held
    assert!(one(&w, &id).await.is_err());
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed retained")
    );
    drop(held);
    assert!(matches!(
        witness.drive_once().await,
        live::KernelRetirementState::Quiescent
    ));
    assert!(one(&w, &id).await.is_err()); // terminal, not healthy NoRoom
    drop(peer);
}

#[tokio::test]
async fn room_state_is_t3_diagnostic_and_dirty_matches_versioned_epoch() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = room(&w, &id).await;
    let before = one(&w, &id).await.unwrap();
    assert_eq!(before["live_body"]["dirty"], false);
    let gate = current::gate(&w.db, Stage::SqlClosed);
    let reader = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move { one(&w, &id).await })
    };
    entered(&gate).await;
    peer.leave().await; // clean leave only: same epoch and committed body basis
    gate.release.notify_one();
    let grace = reader.await.unwrap().unwrap();
    assert_eq!(grace["live_body"]["room_state"], "grace");
    assert_eq!(
        grace["live_body"]["revision"],
        before["live_body"]["revision"]
    );
    let (peer, _) = room(&w, &id).await;
    let active = one(&w, &id).await.unwrap();
    assert_eq!(active["live_body"]["room_state"], "active");
    assert_eq!(
        active["live_body"]["revision"],
        grace["live_body"]["revision"]
    );
    peer.leave().await;
}

#[tokio::test]
async fn multirecord_get_record_uses_one_publication_guard_and_no_partial_retry() {
    let w = world().await;
    let a = record(&w, "Document", "note", Some("a")).await;
    let b = record(&w, "Document", "note", Some("b")).await;
    let no_room = record(&w, "Document", "note", Some("c")).await;
    let (ap, ao) = room(&w, &a).await;
    let (bp, bo) = room(&w, &b).await;
    let captured = kernel_reads::gate(&w.db, kernel_reads::ReadStage::RecordCaptured);
    let initial = current::gate(&w.db, Stage::AfterT1);
    let retry = current::gate(&w.db, Stage::Retry);
    let reader = {
        let w = fork(&w);
        let ids = vec![a.clone(), b.clone(), no_room.clone()];
        tokio::spawn(async move { read(&w, &ids).await })
    };
    captured.entered.notified().await; // first record captured, rest not yet
    let queued = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::SeedGateQueued, false);
    let opener = {
        let w = fork(&w);
        let id = no_room.clone();
        tokio::spawn(async move { room(&w, &id).await })
    };
    queued.entered.notified().await; // actual exclusive wait DURING capture
    queued.release.notify_one(); // keep the exclusive request queued on lock
    captured.release.notify_one();
    entered(&initial).await; // later captures did not reacquire a shared guard
    append_peer(&ap, &ao, " first").await;
    initial.release.notify_one();
    entered(&retry).await; // entire attempt discarded, no prefix emitted
    assert!(!reader.is_finished());
    let (cp, _) = opener.await.unwrap(); // retry drops attempt0 publication guard
    append_peer(&bp, &bo, " second").await;
    retry.release.notify_one();
    let value = reader.await.unwrap().unwrap();
    assert_eq!(value["records"][0]["live_body"]["body"], "a first");
    assert_eq!(value["records"][1]["live_body"]["body"], "b second");
    assert_eq!(value["records"][2]["live_body"]["body"], "c");
    assert!(read(&w, &vec![a; 101]).await.is_err());
    ap.leave().await;
    bp.leave().await;
    cp.leave().await;
}

#[tokio::test]
async fn current_response_cap_counts_metadata_escaping_and_duplicated_body_bytes() {
    let limit = crate::query::sql_contract::MAX_RESULT_ENCODED_BYTES;
    let metadata = json!({"body":"", "name":"\"\\\n", "facets":[{"key":"x","value":"\u{1}"}],"live_body":{"body":"","committed":{"body_present":true}}});
    let encoded = serde_json::to_vec(&metadata).unwrap().len();
    assert_eq!(
        current::encoded_size_within(&metadata, encoded).unwrap(),
        encoded
    );
    assert!(current::encoded_size_within(&metadata, encoded - 1).is_err());
    // Exactly-at-cap and one-byte-over exercise the capped writer itself.
    let exact = json!("x".repeat(limit - 2));
    assert_eq!(current::encoded_size_within(&exact, limit).unwrap(), limit);
    assert!(current::encoded_size_within(&exact, limit - 1).is_err());
    for body in ["x".repeat(768 * 1024), "\u{1}".repeat(128 * 1024)] {
        let w = world().await;
        let mut ids = Vec::new();
        let mut peers = Vec::new();
        for _ in 0..3 {
            let id = record(&w, "Document", "note", Some(&body)).await;
            let (peer, _) = room(&w, &id).await;
            ids.push(id);
            peers.push(peer);
        }
        let before = events(&w).await;
        let ordinary = call(&w, "get_record", json!({"ids":ids})).await.unwrap();
        assert!(current::encoded_size_within(&ordinary, limit).is_ok());
        // Durable-only fits; adding three complete live copies must refuse.
        assert!(read(&w, &ids).await.is_err());
        assert_eq!(events(&w).await, before);
        for peer in peers {
            peer.leave().await;
        }
    }
    // All native fields remain inside /5's 4096-byte text and input limits.
    // Same body payload fits with ordinary titles; escaping valid titles is
    // enough to cross the WHOLE response cap after name/fields duplication.
    let body = "x".repeat((limit - 24 * 1024) / 6);
    for escaped_metadata in [false, true] {
        let w = world().await;
        let title = if escaped_metadata {
            "\"".repeat(4000)
        } else {
            "metadata".to_owned()
        };
        let mut ids = Vec::new();
        let mut peers = Vec::new();
        for _ in 0..3 {
            let id = kernel::create_json_as(
                &w.db,
                &w.admin,
                crate::v2_standard::v1_compat::FAMILY,
                "record",
                &json!({"v1_type":"Document","v1_kind":"note","title":title}).to_string(),
                KERNEL_ROOT_ID,
            )
            .await
            .unwrap();
            let revision = kernel::read_record_as(&w.db, &w.admin, &id)
                .await
                .unwrap()
                .unwrap()
                .revision;
            kernel::set_body_as(&w.db, &w.admin, &id, &body, revision)
                .await
                .unwrap();
            let (peer, _) = room(&w, &id).await;
            ids.push(id);
            peers.push(peer);
        }
        let ordinary = call(&w, "get_record", json!({"ids":ids})).await.unwrap();
        assert!(current::encoded_size_within(&ordinary, limit).is_ok());
        let result = read(&w, &ids).await;
        if escaped_metadata {
            assert!(result.is_err()); // valid escaped metadata pushes total over cap
        } else {
            assert!(result.is_ok()); // identical six body copies fit below cap
        }
        for peer in peers {
            peer.leave().await;
        }
    }
}

#[tokio::test]
async fn preowner_fleet_capacity_and_runtime_failures_block_until_actual_new_cut() {
    for case in ["fleet", "capacity", "runtime"] {
        let w = world().await;
        let id = record(&w, "Document", "note", Some("seed")).await;
        let (peer, opened) = room(&w, &id).await;
        append_peer(&peer, &opened, " dirty").await;
        let before = events(&w).await;
        let leases = take_write_leases(&w).await; // any write-pool checkout would stall
        let peer = match case {
            "fleet" => {
                let hook = live::test_kernel_fleet_admission(&w.db, std::sync::Arc::new(|_| None));
                assert!(tokio::time::timeout(
                    std::time::Duration::from_secs(20),
                    peer.version("actual Fleet refusal")
                )
                .await
                .expect("Fleet must refuse without a write-pool checkout")
                .is_err());
                drop(hook);
                peer
            }
            "capacity" => {
                let held = kernel_writes::hold_job_slots_for_test(&w.db, 8);
                assert!(tokio::time::timeout(
                    std::time::Duration::from_secs(20),
                    peer.version("actual admission capacity refusal")
                )
                .await
                .expect("capacity must refuse without SQL")
                .is_err());
                drop(held);
                peer
            }
            _ => {
                // Runtime refusal happens before any SQL or async room lock.
                let (peer, result) = std::thread::spawn(move || {
                    futures::executor::block_on(async {
                        let result = peer.version("actual missing runtime refusal").await;
                        (peer, result)
                    })
                })
                .join()
                .unwrap();
                assert!(result.is_err());
                peer
            }
        };
        drop(leases);
        assert_eq!(events(&w).await, before);
        assert_eq!(
            kernel_reads::finalization_blocked_for_test(&w.db, &id),
            Some(true)
        );
        assert!(one(&w, &id).await.is_err()); // admission restoration is no clear
        append_peer(&peer, &opened, " still unsaved").await;
        assert!(one(&w, &id).await.is_err()); // accepted epoch drift is no escape
        let event = peer
            .version("known new body event resolves latch")
            .await
            .unwrap()
            .unwrap();
        let row = one(&w, &id).await.unwrap();
        assert_eq!(row["body_basis"]["body_event"]["id"], event.event_id);
        assert_eq!(row["live_body"]["dirty"], false);
        assert_eq!(
            kernel_reads::finalization_blocked_for_test(&w.db, &id),
            Some(false)
        );
        peer.leave().await;
    }
}

#[tokio::test]
async fn blocked_latch_survives_replay_metadata_rejoin_view_and_authority_restoration() {
    let w = world().await;
    let (reader, id, home, viewer) = scoped_view_record(&w).await;
    let author =
        kernel::create_principal(&w.db, "account", "Author", "read:latch-author", &w.admin)
            .await
            .unwrap();
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &home,
        &[(&w.admin, "edit"), (&viewer, "view"), (&author, "edit")],
    )
    .await
    .unwrap();
    let writer = World {
        caller: Caller::authenticated("read:latch-author"),
        ..fork(&w)
    };
    let keyed = json!({"id":id,"body_append":" keyed","idempotency_key":"latch-replay-proof"});
    update(&writer, keyed.clone()).await.unwrap();
    let (peer, opened) = room(&writer, &id).await;
    append_peer(&peer, &opened, " dirty").await;
    let closed = current::gate(&w.db, Stage::SqlClosed);
    let reading = {
        let reader = fork(&reader);
        let id = id.clone();
        tokio::spawn(async move { one(&reader, &id).await })
    };
    entered(&closed).await;
    let armed = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LifecycleAfterArm, false);
    let outer = kernel_writes::test_gate(
        &w.db,
        kernel_writes::TestStage::LifecycleBeforeOuterFailurePublication,
        false,
    );
    let cut = {
        let writer = fork(&writer);
        let id = id.clone();
        tokio::spawn(async move {
            kernel_reads::cut_for_test(&writer.db, &id, "real current actor Edit refusal").await
        })
    };
    armed.entered.notified().await;
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &home,
        &[(&w.admin, "edit"), (&viewer, "view"), (&author, "view")],
    )
    .await
    .unwrap();
    let queued = kernel_reads::gate(&w.db, kernel_reads::ReadStage::ValidateOps);
    closed.release.notify_one();
    queued.entered.notified().await;
    armed.release.notify_one();
    outer.entered.notified().await;
    assert_eq!(
        kernel_reads::finalization_blocked_for_test(&w.db, &id),
        Some(true)
    );
    queued.release.notify_one();
    assert!(reading.await.unwrap().is_err()); // observer fallback still held
    outer.release.notify_one();
    assert!(cut.await.unwrap().is_err());
    assert!(one(&reader, &id).await.is_err());
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &home,
        &[(&w.admin, "edit"), (&viewer, "view"), (&author, "edit")],
    )
    .await
    .unwrap();
    peer.recheck_access(&writer.caller).await.unwrap();
    append_peer(&peer, &opened, " edited").await;
    update(&writer, json!({"id":id,"name":"metadata after failure"}))
        .await
        .unwrap();
    update(&writer, keyed).await.unwrap(); // matching receipt BEFORE flush
    let (joined, _) = room(&writer, &id).await;
    assert!(one(&reader, &id).await.is_err());
    assert_eq!(stored_body(&w, &id).await, "seed keyed");
    assert_eq!(
        kernel_reads::finalization_blocked_for_test(&w.db, &id),
        Some(true)
    );
    assert!(update(
        &writer,
        json!({"id":id,"body_set":"unaccepted candidate","if_body_digest":"0".repeat(64)})
    )
    .await
    .is_err());
    // flush-first really committed pending text before this unrelated guard
    // failure; its disarmed owned mark must not re-block the new durable base.
    assert_eq!(
        kernel_reads::finalization_blocked_for_test(&w.db, &id),
        Some(false)
    );
    assert_eq!(
        one(&reader, &id).await.unwrap()["body"],
        "seed keyed dirty edited"
    );
    joined.leave().await;
    peer.leave().await;
}

#[tokio::test]
async fn late_failure_cannot_poison_new_body_event_or_replacement_room() {
    for replace in [false, true] {
        let w = world().await;
        let id = record(&w, "Document", "note", Some("seed")).await;
        let (peer, opened) = room(&w, &id).await;
        append_peer(&peer, &opened, " dirty").await;
        let held = kernel_writes::hold_job_slots_for_test(&w.db, 8);
        let failed = kernel_writes::test_gate(
            &w.db,
            kernel_writes::TestStage::LifecycleBeforeOuterFailurePublication,
            false,
        );
        let old = {
            let w = fork(&w);
            let id = id.clone();
            tokio::spawn(async move {
                kernel_reads::cut_for_test(&w.db, &id, "old capacity failure").await
            })
        };
        failed.entered.notified().await; // stamp captured, no result escaped
        drop(held);
        peer.version("intervening actual body cut")
            .await
            .unwrap()
            .unwrap();
        let before = one(&w, &id).await.unwrap();
        let (peer, opened) = if replace {
            peer.leave().await;
            kernel_reads::expire_clean_for_test(&w.db, &id).await;
            room(&w, &id).await
        } else {
            (peer, opened)
        };
        append_peer(&peer, &opened, " new edit").await;
        failed.release.notify_one();
        assert!(old.await.unwrap().is_err());
        let row = one(&w, &id).await.unwrap();
        assert_eq!(row["live_body"]["body"], "seed dirty new edit");
        assert_eq!(
            kernel_reads::finalization_blocked_for_test(&w.db, &id),
            Some(false)
        );
        if replace {
            assert_ne!(
                row["live_body"]["revision"],
                before["live_body"]["revision"]
            );
        }
        peer.leave().await;
    }
}

#[tokio::test]
async fn queued_finalizer_refreshes_failure_basis_after_intervening_success() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " first").await;
    let queued = kernel_writes::test_gate(
        &w.db,
        kernel_writes::TestStage::LifecycleBeforeAcquire,
        false,
    );
    let old = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move { kernel_reads::cut_for_test(&w.db, &id, "queued attempt").await })
    };
    queued.entered.notified().await; // original fallback basis A captured
    peer.version("new known cut B before queued acquisition")
        .await
        .unwrap()
        .unwrap();
    append_peer(&peer, &opened, " dirty on B").await;
    // Actual failure after the queued owner refreshes under ops. Outer fallback
    // A is deliberately stale; only the refreshed owned field can mark B.
    let fail = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LifecycleAfterArm, true);
    queued.release.notify_one();
    fail.entered.notified().await;
    fail.release.notify_one();
    assert!(old.await.unwrap().is_err());
    assert_eq!(
        kernel_reads::finalization_blocked_for_test(&w.db, &id),
        Some(true)
    );
    assert!(one(&w, &id).await.is_err());
    peer.version("resolve B with actual event C")
        .await
        .unwrap()
        .unwrap();
    assert!(one(&w, &id).await.is_ok());
    peer.leave().await;
}

#[tokio::test]
async fn marker_publication_in_each_gap_and_same_text_event_aba_never_falls_back() {
    for stage in [Stage::AfterT1, Stage::SqlClosed] {
        let w = world().await;
        let id = record(&w, "Document", "note", Some("seed")).await;
        let (peer, opened) = room(&w, &id).await;
        append_peer(&peer, &opened, " dirty").await;
        let gate = current::gate(&w.db, stage);
        let reader = {
            let w = fork(&w);
            let id = id.clone();
            tokio::spawn(async move { one(&w, &id).await })
        };
        entered(&gate).await;
        let hook = live::test_kernel_fleet_admission(&w.db, std::sync::Arc::new(|_| None));
        assert!(peer
            .version("actual failed finalizer in phase gap")
            .await
            .is_err());
        drop(hook);
        gate.release.notify_one();
        assert!(reader.await.unwrap().is_err());
        peer.version("clear only with new durable event")
            .await
            .unwrap()
            .unwrap();
        peer.leave().await;
    }
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    // Accepted insert+delete restores identical bytes with a genuinely dirty
    // epoch; a later real cut must still append a different body event.
    let bytes = peer_update(&peer, &opened, "x").await;
    peer.apply("insert", &bytes).await.unwrap();
    let mut options =
        Options::with_client_id(yrs::ClientID::new(u64::from(opened.doc_client_ids[0])));
    options.offset_kind = OffsetKind::Bytes;
    let doc = Doc::with_options(options);
    doc.transact_mut()
        .apply_update(Update::decode_v1(&peer.sync(&[]).await.unwrap()).unwrap())
        .unwrap();
    let before = doc.transact().state_vector();
    let body = doc.get_or_insert_text("body");
    body.remove_range(&mut doc.transact_mut(), 4, 1);
    let bytes = doc.transact().encode_diff_v1(&before);
    peer.apply("delete", &bytes).await.unwrap();
    let gate = current::gate(&w.db, Stage::SqlClosed);
    let reader = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move { one(&w, &id).await })
    };
    entered(&gate).await;
    let old = kernel_writes::base_for_test(&w.db, &id).unwrap();
    let hook = live::test_kernel_fleet_admission(&w.db, std::sync::Arc::new(|_| None));
    assert!(peer.version("false to true latch").await.is_err());
    drop(hook);
    let new = peer
        .version("true to false on same text NEW event")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(new.body_sha256, old.body_sha256);
    assert_ne!(
        Some(new.event_id.as_str()),
        old.proof.body_event_id.as_deref()
    );
    gate.release.notify_one();
    let row = reader.await.unwrap().unwrap();
    assert_eq!(row["body_basis"]["body_event"]["id"], new.event_id);
    assert_eq!(row["body"], "seed");
    peer.leave().await;
}

#[tokio::test]
async fn dropped_finalizer_waiter_never_marks_success_and_owned_failure_still_blocks() {
    for fail in [false, true] {
        let w = world().await;
        let id = record(&w, "Document", "note", Some("seed")).await;
        let (peer, opened) = room(&w, &id).await;
        append_peer(&peer, &opened, " dirty").await;
        let gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::BeforeCommit, fail);
        let closed = current::gate(&w.db, Stage::SqlClosed);
        let reader = {
            let w = fork(&w);
            let id = id.clone();
            tokio::spawn(async move { one(&w, &id).await })
        };
        entered(&closed).await;
        let waiter = {
            let w = fork(&w);
            let id = id.clone();
            tokio::spawn(async move {
                kernel_reads::cut_for_test(&w.db, &id, "owned completion after waiter drop").await
            })
        };
        gate.entered.notified().await;
        let queued = kernel_reads::gate(&w.db, kernel_reads::ReadStage::ValidateOps);
        closed.release.notify_one();
        queued.entered.notified().await;
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert_eq!(
            kernel_reads::finalization_blocked_for_test(&w.db, &id),
            Some(false)
        );
        gate.release.notify_one();
        queued.release.notify_one();
        let result = reader.await.unwrap();
        if fail {
            assert!(result.is_err());
            assert_eq!(
                kernel_reads::finalization_blocked_for_test(&w.db, &id),
                Some(true)
            );
            peer.version("retry actual cut after owned failure")
                .await
                .unwrap()
                .unwrap();
        } else {
            assert_eq!(result.unwrap()["body"], "seed dirty");
            assert_eq!(
                kernel_reads::finalization_blocked_for_test(&w.db, &id),
                Some(false)
            );
        }
        peer.leave().await;
    }
}

#[tokio::test]
async fn v1_gate_wait_refuses_injected_foreign_native_custody_without_rebinding() {
    // Negative failure injection ONLY. This is not a valid native publication,
    // migration, authority, same-file cutover or physical-generation fixture.
    let directory = tempfile::tempdir().unwrap();
    let db = crate::create_database(directory.path().join("v1.sqlite").to_str().unwrap())
        .await
        .unwrap();
    let mut tools = crate::mcp::registry::ToolRegistry::new();
    crate::mcp::register_surface_tools(&mut tools).unwrap();
    let created=tools.call(db.clone(),Caller::local(),"create_record",json!({"type":"Document","kind":"note","name":"V1 control","body":"v1 seed","reason":"real V1 fixture"})).await.unwrap();
    let id = created["id"].as_str().unwrap().to_owned();
    let native = world().await;
    let native_id = record(&native, "Document", "note", Some("native seed")).await;
    let (peer, _) = room(&native, &native_id).await;
    let held = kernel_reads::hold_publication_for_test(&db).await;
    let queued = kernel_writes::test_gate(&db, kernel_writes::TestStage::V1GateQueued, false);
    let writer = {
        let db = db.clone();
        let id = id.clone();
        tokio::spawn(async move {
            live::begin_body_write(&db, &id, &Caller::local())
                .await
                .map(|_| ())
        })
    };
    queued.entered.notified().await; // actual authorized V1 gate Future Pending
    let injection =
        kernel_reads::inject_foreign_native_room_for_test(&db, &id, &native.db, &native_id);
    queued.release.notify_one();
    drop(held);
    assert!(writer.await.unwrap().is_err());
    assert!(injection.native_identity_unchanged());
    drop(injection); // exact-Arc scoped cleanup also runs on assertion failure
    let ordinary = live::begin_body_write(&db, &id, &Caller::local())
        .await
        .unwrap();
    assert!(!ordinary.is_routed());
    drop(ordinary);
    tools
        .call(
            db.clone(),
            Caller::local(),
            "update_record",
            json!({"id":id,"body_append":" ordinary","reason":"V1 positive control"}),
        )
        .await
        .unwrap();
    assert!(one(&native, &native_id).await.is_ok());
    peer.leave().await;
}

async fn take_write_leases(w: &World) -> Vec<sqlx::pool::PoolConnection<sqlx::Sqlite>> {
    let mut leases = Vec::new();
    for _ in 0..w.db.write_pool().options().get_max_connections() {
        leases.push(w.db.write_pool().acquire().await.unwrap());
    }
    leases
}

async fn deferred_commit_fault(w: &World, id: &str, install: bool) {
    let mut leases = take_write_leases(w).await;
    for connection in &mut leases {
        if install {
            // Failure injection only: private TEMP constraint, never an app,
            // principal, action, native event or successful permission fixture.
            // The writer contract (73ad275 M4) refuses connections carrying a
            // TEMP trigger on a marked input table, so the latch hangs off the
            // causal-head row that the main schema writes for every event
            // appended in the same write transaction.
            sqlx::query("CREATE TEMP TABLE read_latch_parent(id INTEGER PRIMARY KEY); CREATE TEMP TABLE read_latch_child(parent INTEGER REFERENCES read_latch_parent(id) DEFERRABLE INITIALLY DEFERRED)").execute(&mut **connection).await.unwrap();
            let id = id.replace('\'', "''");
            sqlx::query(&format!("CREATE TEMP TRIGGER read_latch_fail AFTER INSERT ON main.content_event_heads WHEN (SELECT record_id FROM main.content_events WHERE id=NEW.event_id)='{id}' BEGIN INSERT INTO read_latch_child VALUES(7); END")).execute(&mut **connection).await.unwrap();
        } else {
            sqlx::query("DROP TRIGGER IF EXISTS temp.read_latch_fail; DROP TABLE IF EXISTS temp.read_latch_child; DROP TABLE IF EXISTS temp.read_latch_parent").execute(&mut **connection).await.unwrap();
        }
    }
}

#[tokio::test]
async fn consuming_begin_rollback_and_commit_rollback_mark_before_ops_release() {
    for case in ["begin", "rollback", "commit_rollback"] {
        let w = world().await;
        let id = record(&w, "Document", "note", Some("seed")).await;
        let (peer, opened) = room(&w, &id).await;
        append_peer(&peer, &opened, " dirty").await;
        let closed = current::gate(&w.db, Stage::SqlClosed);
        let reader = {
            let w = fork(&w);
            let id = id.clone();
            tokio::spawn(async move { one(&w, &id).await })
        };
        entered(&closed).await;
        let mut blocker = None;
        if case == "begin" {
            let foreign = kernel::open_v2_database(w.db.path().to_str().unwrap())
                .await
                .unwrap();
            let mut leases = take_write_leases(&w).await;
            for lease in &mut leases {
                sqlx::query("PRAGMA busy_timeout=0")
                    .execute(&mut **lease)
                    .await
                    .unwrap();
            }
            drop(leases);
            let mut connection = foreign.write_pool().acquire().await.unwrap();
            sqlx::query("BEGIN IMMEDIATE")
                .execute(&mut *connection)
                .await
                .unwrap();
            blocker = Some((foreign, connection)); // actual external writer fence
        } else if case == "commit_rollback" {
            deferred_commit_fault(&w, &id, true).await;
        }
        let stage = if case == "begin" {
            kernel_writes::TestStage::LifecycleAfterArm
        } else {
            kernel_writes::TestStage::BeforeCommit
        };
        let inside = kernel_writes::test_gate(&w.db, stage, case == "rollback");
        let outer = kernel_writes::test_gate(
            &w.db,
            kernel_writes::TestStage::LifecycleBeforeOuterFailurePublication,
            false,
        );
        let cut = {
            let w = fork(&w);
            let id = id.clone();
            tokio::spawn(async move {
                kernel_reads::cut_for_test(&w.db, &id, "real consuming settlement failure").await
            })
        };
        inside.entered.notified().await; // actual owner still holds room ops
        let queued = kernel_reads::gate(&w.db, kernel_reads::ReadStage::ValidateOps);
        closed.release.notify_one();
        queued.entered.notified().await;
        inside.release.notify_one();
        outer.entered.notified().await; // owner was consumed/dropped; fallback NOT yet published
        assert_eq!(
            kernel_reads::finalization_blocked_for_test(&w.db, &id),
            Some(true)
        );
        queued.release.notify_one();
        assert!(reader.await.unwrap().is_err()); // owned field marked before ops release
        outer.release.notify_one();
        assert!(cut.await.unwrap().is_err());
        if let Some((_, mut connection)) = blocker {
            sqlx::query("ROLLBACK")
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        if case == "commit_rollback" {
            deferred_commit_fault(&w, &id, false).await;
        }
        assert_eq!(stored_body(&w, &id).await, "seed");
        peer.version("new event after known begin/rollback failure")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(one(&w, &id).await.unwrap()["body"], "seed dirty");
        peer.leave().await;
    }
}

#[tokio::test]
async fn actual_routed_primitive_install_clears_only_after_new_durable_body_event() {
    use kernel_writes::{KernelBodyWrite, KernelTransaction, KernelWriteMode};
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " dirty").await;
    let hook = live::test_kernel_fleet_admission(&w.db, std::sync::Arc::new(|_| None));
    assert!(peer.version("actual failed cut").await.is_err());
    drop(hook);
    assert!(one(&w, &id).await.is_err());
    let committed =
        kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterDurability, false);
    let install = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move {
            kernel_writes::owned_result(w.db.clone(), async move {
                let ownership = KernelBodyWrite::acquire(
                    &w.db,
                    &w.caller,
                    Some(&id),
                    KernelWriteMode::RouteBody,
                )
                .await?;
                let mut transaction =
                    KernelTransaction::begin(&w.db, ownership, KernelBodyWrite::quarantine).await?;
                let (tx, owner) = transaction.parts();
                let mut acts = crate::act::ActAllocation::new();
                // Real NonApp scope on this SAME original W0 loan/memo.
                let actor = super::principal_on(tx, &w.caller).await?;
                let args = json!({"id":id,"body_set":"seed dirty routed"});
                let digest = crate::provenance::digest_json(&args);
                let binding = crate::kernel::app_installs::bind_update_action_on(
                    tx, None, &w.caller, &actor, &args, &digest, &acts,
                )
                .await?;
                assert!(
                    owner
                        .append_dispatched_body_in(
                            tx,
                            &id,
                            "seed dirty routed",
                            None,
                            "real routed candidate install",
                            &mut acts,
                            Some(binding)
                        )
                        .await?
                );
                owner.validate_in(tx).await?;
                let mut owner = transaction.commit().await?;
                owner.install_committed()?;
                Ok(())
            })
            .await
        })
    };
    committed.entered.notified().await; // actual durability precedes installation
    assert_eq!(
        kernel_reads::finalization_blocked_for_test(&w.db, &id),
        Some(true)
    );
    committed.release.notify_one();
    install.await.unwrap().unwrap();
    assert_eq!(
        kernel_reads::finalization_blocked_for_test(&w.db, &id),
        Some(false)
    );
    let row = one(&w, &id).await.unwrap();
    assert_eq!(row["body"], "seed dirty routed");
    assert_eq!(row["live_body"]["dirty"], false);
    peer.leave().await;
}

#[tokio::test]
async fn imported_birth_refuses_only_probe_while_author_and_durable_get_stay_compatible() {
    let w = world().await;
    let template = record(&w, "Document", "note", None).await;
    let view = kernel::read_record_as(&w.db, &w.admin, &template)
        .await
        .unwrap()
        .unwrap();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let id = uuid::Uuid::new_v4().to_string();
    let state = kernel::ImportRecordState {
        definition: Some(kernel::ImportDefinition {
            pin: view.pin.unwrap(),
            primary_type: "V1".into(),
            kind: "record".into(),
            fields: view.fields,
        }),
        body: Some("imported body".into()),
        ..Default::default()
    };
    kernel::import_record_as(&w.db, &host, &id, KERNEL_ROOT_ID, Some(&w.admin), &state)
        .await
        .unwrap();
    let loaded = crate::coedit::kernel_v2::load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
        .await
        .unwrap();
    assert_eq!(loaded.body, "imported body");
    assert_eq!(
        call(&w, "get_record", json!({"ids":[id]})).await.unwrap()["records"][0]["body"],
        "imported body"
    );
    // UUID import deliberately emits an actual native record-created birth.
    // The body may be imported without invalidating that genuine birth proof.
    let (native_birth, imported_body): (String, String) = sqlx::query_as("SELECT birth.type,body.type FROM main.kernel_records r JOIN main.content_events birth ON birth.seq=r.created_seq AND birth.record_id=r.id JOIN main.kernel_record_bodies b ON b.record_id=r.id JOIN main.content_events body ON body.seq=b.event_seq AND body.record_id=r.id WHERE r.id=?").bind(&id).fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(native_birth, "kernel.record_created.v1");
    assert_eq!(imported_body, "kernel.import_state.v1");
    assert_eq!(one(&w, &id).await.unwrap()["body"], "imported body");

    // Genuine non-UUID BIRTH from V1's sealed instruction provisioning,
    // carried through the official importer, rather than rewritten created_seq.
    let imported = imported_v1().await;
    let unsupported = crate::schema::WORKSPACE_INSTRUCTIONS_ID;
    let birth: String = sqlx::query_scalar("SELECT e.type FROM main.kernel_records r JOIN main.content_events e ON e.seq=r.created_seq AND e.record_id=r.id WHERE r.id=?").bind(unsupported).fetch_one(imported.world.db.pool()).await.unwrap();
    assert_eq!(birth, "kernel.import_record_created.v1");
    let durable = call(&imported.world, "get_record", json!({"ids":[unsupported]}))
        .await
        .unwrap();
    assert_eq!(durable["records"][0]["status"], "found");
    let refused = one(&imported.world, unsupported).await.unwrap_err();
    assert!(
        refused
            .to_string()
            .contains("current body read: unsupported or missing record birth evidence"),
        "wrong refusal: {refused}"
    );

    assert!(
        crate::coedit::kernel_v2::load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn cancel_actual_pending_sql_close_never_acknowledges_or_recycles_old_handle() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let probe = sql::CurrentCloseProbe::new(); // scoped release on panic/cancellation
    let reader = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(probe.scope(async move { one(&w, &id).await }))
    };
    tokio::time::timeout(std::time::Duration::from_secs(20), probe.pending())
        .await
        .expect(
            "actual close future must poll Pending after real rollback and SQLite VM handshake",
        );
    assert_ne!(probe.handle(), 0);
    assert!(!probe.acknowledged());
    let queued = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::SeedGateQueued, false);
    let opener = {
        let w = fork(&w);
        let id = id.clone();
        tokio::spawn(async move { room(&w, &id).await })
    };
    queued.entered.notified().await; // publication still held through close
    reader.abort();
    assert!(reader.await.unwrap_err().is_cancelled());
    assert!(!probe.acknowledged()); // no physical close ACK or ClosedCurrentGet
    queued.release.notify_one();
    let (peer, _) = opener.await.unwrap(); // progresses while old worker remains held
    let mut other = w.db.governed_pool().acquire().await.unwrap();
    {
        let mut handle = other.lock_handle().await.unwrap();
        // The old handle is STILL alive in the blocked VM; pointer inequality
        // here tests lease exclusion, never durable physical-generation identity.
        assert_ne!(handle.as_raw_handle().as_ptr() as usize, probe.handle());
    }
    other.close_on_drop();
    drop(other);
    probe.release_worker();
    assert!(one(&w, &id).await.is_ok());
    peer.leave().await;
}
