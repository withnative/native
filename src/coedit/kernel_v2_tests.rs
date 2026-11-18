//! Foundation proofs on the actual prepared kernel, never a v1 records shim.
use super::{backend::SessionBackend, kernel_v2, *};
use crate::{events::KERNEL_ROOT_ID, kernel, mcp::Caller};
use serde_json::{json, Value};
use yrs::updates::decoder::Decode;
use yrs::{Doc, GetString, OffsetKind, Options, ReadTxn, Text, Transact, Update};

#[derive(Clone)]
struct World {
    db: crate::db::Db,
    admin: String,
    caller: Caller,
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
fn open(registry: &mut SessionRegistry, id: &str, body: &str) -> OpenOk {
    registry
        .open(OpenParams {
            database_id: "kernel-foundation".into(),
            record_id: id.into(),
            committed_body: body.into(),
            kind: PeerKind::Edit,
            record_supported: true,
        })
        .unwrap()
}
fn client(opened: &OpenOk) -> Doc {
    let mut options = Options::with_client_id(yrs::ClientID::new(u64::from(opened.client_ids[0])));
    options.offset_kind = OffsetKind::Bytes;
    let doc = Doc::with_options(options);
    doc.transact_mut()
        .apply_update(Update::decode_v1(&opened.sync_step2).unwrap())
        .unwrap();
    doc
}
fn insert(
    registry: &mut SessionRegistry,
    peer: &OpenOk,
    doc: &Doc,
    at: u32,
    text: &str,
    fact: &AcknowledgedContributor,
) -> Ack {
    let before = doc.transact().state_vector();
    doc.get_or_insert_text("body")
        .insert(&mut doc.transact_mut(), at, text);
    let update = doc.transact().encode_diff_v1(&before);
    registry
        .apply_update_attributed(&peer.session_id, &peer.peer_id, &update, fact)
        .unwrap()
}
async fn fact(w: &World) -> AcknowledgedContributor {
    let mut tx = w.db.pool().begin().await.unwrap();
    let fact = kernel_v2::contributor_on(&mut tx, &w.caller).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(fact.principal, w.admin);
    assert_ne!(fact.principal, w.caller.credential());
    fact
}
async fn cut(
    w: &World,
    id: &str,
    basis: Option<i64>,
    snapshot: &VersionSnapshot,
) -> live::BaseVersion {
    let mut tx = crate::db::begin_write(w.db.write_pool()).await.unwrap();
    let proof = kernel_v2::cut_in(
        &w.db,
        &mut tx,
        &w.caller,
        id,
        basis,
        snapshot,
        &mut crate::act::ActAllocation::new(),
    )
    .await
    .unwrap();
    w.db.commit_kernel_content(tx).await.unwrap();
    proof
}

#[tokio::test]
async fn prepared_kernel_document_task_epic_two_peers_native_cut_history_and_replay() {
    let w = world().await;
    for (typ, kind) in [
        ("Document", "note"),
        ("WorkItem", "task"),
        ("WorkItem", "epic"),
    ] {
        for initial in [None, Some(""), Some("seed😀")] {
            let id = record(&w, typ, kind, initial).await;
            let loaded = SessionBackend::KernelV2
                .load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
                .await
                .unwrap();
            assert_eq!(loaded.body, initial.unwrap_or_default());
            assert_eq!(
                loaded.base.proof.body_event_seq.is_some(),
                initial.is_some()
            );
            let mut registry = SessionRegistry::new();
            let a = open(&mut registry, &id, &loaded.body);
            let b = open(&mut registry, &id, "ignored");
            let da = client(&a);
            let db = client(&b);
            let author = fact(&w).await;
            let ack = insert(&mut registry, &a, &da, 0, "A", &author);
            db.transact_mut()
                .apply_update(Update::decode_v1(&ack.broadcast).unwrap())
                .unwrap();
            let ack = insert(&mut registry, &b, &db, 1, "B", &author);
            da.transact_mut()
                .apply_update(Update::decode_v1(&ack.broadcast).unwrap())
                .unwrap();
            let snapshot = registry.version_snapshot(&a.session_id).unwrap();
            assert_eq!(
                da.get_or_insert_text("body").get_string(&da.transact()),
                snapshot.body()
            );
            assert_eq!(
                db.get_or_insert_text("body").get_string(&db.transact()),
                snapshot.body()
            );
            let proof = cut(&w, &id, loaded.base.proof.body_event_seq, &snapshot).await;
            assert!(proof.proof.snapshot.is_some());
            assert!(proof.proof.body_event_seq > loaded.base.proof.body_event_seq);
            let reopened = SessionBackend::KernelV2
                .load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
                .await
                .unwrap();
            assert_eq!(reopened.body, snapshot.body());
            assert_eq!(reopened.base.proof.body_event_id, proof.proof.body_event_id);
            assert_eq!(reopened.base.body_sha256, proof.body_sha256);
            let history = kernel::body_history_as(&w.db, &w.admin, &id).await.unwrap();
            let latest = history.last().unwrap();
            assert_eq!(latest.body, snapshot.body());
            assert_eq!(latest.event.id, proof.proof.body_event_id.clone().unwrap());
            assert_eq!(latest.event.event_type, "kernel.body_set.v1");
            let metadata = latest.coedit.as_ref().unwrap();
            assert_eq!(metadata["session"], a.session_id.0);
            assert_eq!(metadata["contributors"][0]["principal"], w.admin);
            assert!(metadata.contains_key("span_map"));
            let native_events: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM content_events WHERE record_id=? AND type='record.updated'",
            )
            .bind(&id)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
            assert_eq!(native_events, 0);
            let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
            kernel::replay_all_projections(&w.db).await.unwrap();
            assert_eq!(kernel::dump_all_kernel_tables(&w.db).await.unwrap(), before);
            let after = kernel::body_history_as(&w.db, &w.admin, &id).await.unwrap();
            assert_eq!(after, history);
            let reopened_registry = open(&mut SessionRegistry::new(), &id, snapshot.body());
            let reopened_doc = client(&reopened_registry);
            assert_eq!(
                reopened_doc
                    .get_or_insert_text("body")
                    .get_string(&reopened_doc.transact()),
                snapshot.body()
            );
        }
    }
    w.db.close().await;
}

#[tokio::test]
async fn metadata_revision_advances_without_body_basis_change_but_same_body_new_event_is_stale() {
    let w = world().await;
    let id = record(&w, "WorkItem", "task", Some("same")).await;
    let initial = kernel_v2::load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
        .await
        .unwrap();
    let metadata_revision = kernel::read_record_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::revise_json_as_expected(
        &w.db,
        &w.admin,
        &id,
        &json!({"title":"Metadata changed"}).to_string(),
        Some(metadata_revision),
    )
    .await
    .unwrap();
    let metadata = kernel_v2::load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
        .await
        .unwrap();
    assert_ne!(metadata.base.version, initial.base.version);
    assert_eq!(metadata.base.proof, initial.base.proof);
    let mut registry = SessionRegistry::new();
    let opened = open(&mut registry, &id, &initial.body);
    let snapshot = registry.version_snapshot(&opened.session_id).unwrap();
    let proof = cut(&w, &id, initial.base.proof.body_event_seq, &snapshot).await;
    assert_ne!(
        proof.proof.body_event_seq,
        initial.base.proof.body_event_seq
    );
    assert_eq!(proof.body_sha256, initial.base.body_sha256);
    let mut tx = crate::db::begin_write(w.db.write_pool()).await.unwrap();
    let stale = kernel_v2::cut_in(
        &w.db,
        &mut tx,
        &w.caller,
        &id,
        initial.base.proof.body_event_seq,
        &snapshot,
        &mut crate::act::ActAllocation::new(),
    )
    .await;
    assert!(matches!(stale, Err(crate::Error::Conflict(_))));
    tx.rollback().await.unwrap();
    assert_eq!(
        kernel::read_record_as(&w.db, &w.admin, &id)
            .await
            .unwrap()
            .unwrap()
            .fields["title"],
        "Metadata changed"
    );
    w.db.close().await;
}

#[tokio::test]
async fn absent_to_explicit_empty_cut_has_real_evidence_and_rollback_does_not_install_it() {
    let w = world().await;
    let id = record(&w, "WorkItem", "epic", None).await;
    let mut registry = SessionRegistry::new();
    let opened = open(&mut registry, &id, "");
    let snapshot = registry.version_snapshot(&opened.session_id).unwrap();
    let mut tx = crate::db::begin_write(w.db.write_pool()).await.unwrap();
    let provisional = kernel_v2::cut_in(
        &w.db,
        &mut tx,
        &w.caller,
        &id,
        None,
        &snapshot,
        &mut crate::act::ActAllocation::new(),
    )
    .await
    .unwrap();
    assert!(provisional.proof.body_event_id.is_some());
    tx.rollback().await.unwrap();
    let absent = kernel_v2::load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
        .await
        .unwrap();
    assert!(absent.base.proof.body_event_id.is_none());
    assert_eq!(
        kernel::read_record_as(&w.db, &w.admin, &id)
            .await
            .unwrap()
            .unwrap()
            .body,
        None
    );
    let committed = cut(&w, &id, None, &snapshot).await;
    assert!(committed.proof.body_event_id.is_some());
    assert_eq!(
        kernel::read_record_as(&w.db, &w.admin, &id)
            .await
            .unwrap()
            .unwrap()
            .body,
        Some(String::new())
    );
    w.db.close().await;
}

#[tokio::test]
async fn native_cut_refuses_unbound_contributor_and_forged_app_and_missing_caller() {
    let w = world().await;
    let id = record(&w, "Document", "note", None).await;
    let mut registry = SessionRegistry::new();
    let peer = open(&mut registry, &id, "");
    let doc = client(&peer);
    let mut wrong = fact(&w).await;
    wrong.principal = w.caller.credential().into(); // v1 credential is not a kernel principal.
    insert(&mut registry, &peer, &doc, 0, "bad", &wrong);
    let snapshot = registry.version_snapshot(&peer.session_id).unwrap();
    let mut tx = crate::db::begin_write(w.db.write_pool()).await.unwrap();
    assert!(kernel_v2::cut_in(
        &w.db,
        &mut tx,
        &w.caller,
        &id,
        None,
        &snapshot,
        &mut crate::act::ActAllocation::new()
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    let forged_app =
        crate::mcp::app_attribution::AppAttribution::new("unknown", "1", "missing-install")
            .unwrap();
    let caller = Caller::authenticated("acct:admin").with_host_asserted_app(forged_app);
    assert!(
        kernel_v2::load_committed(&w.db, &caller, &id, PeerKind::Edit)
            .await
            .is_err()
    );
    assert!(kernel_v2::load_committed(
        &w.db,
        &Caller::authenticated("unknown"),
        &id,
        PeerKind::Edit
    )
    .await
    .is_err());
    assert!(kernel::body_history_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .is_empty());
    w.db.close().await;
}

#[test]
fn native_metadata_keeps_old_payloads_origin_and_strict_members() {
    use crate::coedit::version_metadata::{kernel_metadata, validate_kernel_metadata};
    use kernel::hq::KernelBodyPayload;
    let old = json!({"body":"","origin":{"kind":"independent","session":"unrelated"}});
    let decoded: KernelBodyPayload = serde_json::from_value(old.clone()).unwrap();
    assert!(decoded.coedit.is_none());
    assert_eq!(serde_json::to_value(decoded).unwrap(), old);
    assert!(serde_json::from_value::<KernelBodyPayload>(json!({"body":"","coedit":null})).is_err());
    assert!(
        serde_json::from_value::<KernelBodyPayload>(json!({"body":"","unknown":true})).is_err()
    );
    let mut registry = SessionRegistry::new();
    let opened = open(&mut registry, "schema-only", "");
    let snapshot = registry.version_snapshot(&opened.session_id).unwrap();
    let metadata = kernel_metadata(&snapshot).unwrap();
    validate_kernel_metadata("", &metadata).unwrap();
    for key in ["session", "contributors", "span_map"] {
        let mut missing = metadata.clone();
        missing.remove(key);
        assert!(validate_kernel_metadata("", &missing).is_err());
    }
    let mut unknown = metadata.clone();
    unknown.insert("unknown".into(), json!(true));
    assert!(validate_kernel_metadata("", &unknown).is_err());
    let mut nested = metadata.clone();
    nested["span_map"]
        .as_object_mut()
        .unwrap()
        .insert("unknown".into(), json!(true));
    assert!(validate_kernel_metadata("", &nested).is_err());
    let mut bad_tiling = metadata;
    bad_tiling["span_map"]["spans"] = json!([[0, 1, 0]]);
    assert!(validate_kernel_metadata("", &bad_tiling).is_err());
}

#[tokio::test]
async fn kernel_view_permission_does_not_admit_edit_or_disclose_native_contributors() {
    let w = world().await;
    let viewer = kernel::create_principal(&w.db, "account", "Viewer", "acct:viewer", &w.admin)
        .await
        .unwrap();
    let home = kernel::create_home(&w.db, KERNEL_ROOT_ID, Some(&[(&viewer, "view")]), &w.admin)
        .await
        .unwrap();
    let id = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":"WorkItem","v1_kind":"task","title":"View proof"}).to_string(),
        &home,
    )
    .await
    .unwrap();
    let mut registry = SessionRegistry::new();
    let opened = open(&mut registry, &id, "");
    let snapshot = registry.version_snapshot(&opened.session_id).unwrap();
    cut(&w, &id, None, &snapshot).await;
    let caller = Caller::authenticated("acct:viewer");
    SessionBackend::KernelV2
        .load_committed(&w.db, &caller, &id, PeerKind::View)
        .await
        .unwrap();
    let refused = SessionBackend::KernelV2
        .load_committed(&w.db, &caller, &id, PeerKind::Edit)
        .await
        .err()
        .unwrap();
    assert_eq!(refused.code, RefusalCode::Forbidden);
    let history = kernel::body_history_as(&w.db, &viewer, &id).await.unwrap();
    assert_eq!(history.last().unwrap().body, "");
    assert!(history.last().unwrap().coedit.is_none());
    assert!(history.last().unwrap().event.native_body_version.is_none());
    w.db.close().await;
}

#[tokio::test]
async fn imported_body_event_evidence_and_native_full_history_survive_metadata_revision() {
    let w = world().await;
    let template = record(&w, "WorkItem", "task", None).await;
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
        body: Some("imported😀".into()),
        ..Default::default()
    };
    kernel::import_record_as(&w.db, &host, &id, KERNEL_ROOT_ID, Some(&w.admin), &state)
        .await
        .unwrap();
    let loaded = kernel_v2::load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
        .await
        .unwrap();
    let (event_id, seq): (String, i64) = sqlx::query_as(
        "SELECT id,seq FROM content_events WHERE record_id=? AND type='kernel.import_state.v1'",
    )
    .bind(&id)
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!(
        loaded.base.proof.body_event_id.as_deref(),
        Some(event_id.as_str())
    );
    assert_eq!(loaded.base.proof.body_event_seq, Some(seq));
    let mut registry = SessionRegistry::new();
    let opened = open(&mut registry, &id, &loaded.body);
    let snapshot = registry.version_snapshot(&opened.session_id).unwrap();
    let proof = cut(&w, &id, Some(seq), &snapshot).await;
    let metadata_revision = kernel::read_record_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::revise_json_as_expected(
        &w.db,
        &w.admin,
        &id,
        &json!({"title":"new title"}).to_string(),
        Some(metadata_revision),
    )
    .await
    .unwrap();
    let latest = kernel_v2::load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
        .await
        .unwrap();
    assert_eq!(latest.base.proof.body_event_id, proof.proof.body_event_id);
    let mut tools = crate::mcp::registry::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut tools).unwrap();
    crate::mcp::tools::register_surface_tools(&mut tools).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut tools).unwrap();
    let history = tools
        .call_engine(
            crate::mcp::registry::EngineHandle::KernelV2(w.db.clone()),
            w.caller.clone(),
            "get_history",
            json!({"record_id":id,"detail":"full"}),
        )
        .await
        .unwrap();
    let event = history["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["id"] == proof.proof.body_event_id.clone().unwrap())
        .unwrap();
    assert_eq!(event["native_event_type"], "kernel.body_set.v1");
    assert_eq!(event["payload"]["body"], "imported😀");
    assert_eq!(event["payload"]["session"], opened.session_id.0);
    assert!(event["payload"]["span_map"].is_object());
    let context = tools
        .call_engine(
            crate::mcp::registry::EngineHandle::KernelV2(w.db.clone()),
            w.caller.clone(),
            "get_event_context",
            json!({"event_id":proof.proof.body_event_id}),
        )
        .await
        .unwrap();
    // The public context event must retain version metadata too. Its payload
    // is shaped by the same shared history helper as ordinary native history.
    assert_eq!(context["event"]["payload"]["session"], opened.session_id.0);
    assert!(context["event"]["payload"]["span_map"].is_object());
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

#[tokio::test]
async fn native_document_pin_and_special_body_boundaries_use_kernel_catalogue() {
    let w = world().await;
    let package = crate::v2_standard::document4_package();
    let identity = kernel::install_package_as(&w.db, &w.admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&identity),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let id = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::DOCUMENT_FAMILY,
        "note",
        &json!({"title":"Native document"}).to_string(),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let loaded = SessionBackend::KernelV2
        .load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
        .await
        .unwrap();
    assert!(loaded.admitted_as_document);
    assert!(loaded.base.proof.body_event_seq.is_none());
    let mut registry = SessionRegistry::new();
    let opened = open(&mut registry, &id, "");
    let snapshot = registry.version_snapshot(&opened.session_id).unwrap();
    cut(&w, &id, None, &snapshot).await;
    kernel::observe_facet_as(
        &w.db,
        &w.admin,
        &id,
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
    let refused = SessionBackend::KernelV2
        .load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
        .await
        .err()
        .unwrap();
    assert_eq!(refused.code, RefusalCode::RecordUnsupported);
    for (typ, kind) in [
        ("Document", "artifact"),
        ("Document", "instruction"),
        ("WorkItem", "unknown"),
    ] {
        let id = record(&w, typ, kind, None).await;
        let refused = SessionBackend::KernelV2
            .load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
            .await
            .err()
            .unwrap();
        assert_eq!(refused.code, RefusalCode::RecordUnsupported);
    }
    w.db.close().await;
}

// N1: actual prepared kernel authority; no body-free fabricated record views,
// install rows, host context or native event/projection facts are constructed.
struct N1GateRelease(std::sync::Arc<live::kernel_writes::TestGate>);
impl Drop for N1GateRelease {
    fn drop(&mut self) {
        self.0.release.notify_one();
    }
}

async fn n1_gate_entered(gate: &live::kernel_writes::TestGate) {
    // Failure bound only. Actual checkpoint entry, never elapsed time, is the
    // ordering evidence; release guards settle owned work on assertion panic.
    tokio::time::timeout(std::time::Duration::from_secs(30), gate.entered.notified())
        .await
        .expect("actual N1 checkpoint was not reached");
}

async fn n1_call(w: &World, caller: Caller, name: &str, args: Value) -> crate::Result<Value> {
    let mut tools = crate::mcp::registry::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut tools).unwrap();
    crate::mcp::tools::register_surface_tools(&mut tools).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut tools).unwrap();
    tools
        .call_engine(
            crate::mcp::registry::EngineHandle::KernelV2(w.db.clone()),
            caller,
            name,
            args,
        )
        .await
}
async fn n1_open(w: &World, id: &str) -> Result<(live::SessionPeer, live::Opened), Refused> {
    live::open_kernel_inactive(
        &w.db,
        &w.caller,
        live::OpenRequest {
            record_id: id.into(),
            mode: PeerKind::Edit,
            resume_peer: None,
        },
    )
    .await
}

#[tokio::test]
async fn metadata_recheck_uses_real_scope_without_body_hydration_or_hash() {
    use kernel_v2::BodyWorkStage as Stage;
    let w = world().await;
    let id = record(&w, "Document", "note", Some("genuine committed text")).await;
    let observation = kernel_v2::observe_body(&id, true);
    for _ in 0..8 {
        kernel_v2::revalidate(&w.db, &w.caller, &id, PeerKind::Edit)
            .await
            .unwrap();
    }
    assert!(observation.stages().is_empty());
    // Negative control: the real full loader reaches the observed hydration
    // boundary and is denied; a disconnected no-op observer cannot pass.
    let error = kernel_v2::load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
        .await
        .err()
        .unwrap();
    assert!(error
        .to_string()
        .contains("test observation refused actual target-body hydration"));
    assert_eq!(
        observation.stages(),
        vec![Stage::Encoding, Stage::Size, Stage::Hydrate]
    );
    w.db.close().await;
}

#[tokio::test]
async fn metadata_recheck_preserves_document_and_governed_workitem_eligibility() {
    let w = world().await;
    for (typ, kind, expected) in [
        ("Document", "note", true),
        ("Document", "attachment", true),
        ("WorkItem", "task", true),
        ("WorkItem", "epic", true),
        ("Document", "artifact", false),
        ("Document", "instruction", false),
        ("WorkItem", "unknown", false),
    ] {
        let id = if typ == "Document" && kind == "attachment" {
            // Attachments derive View/Edit from a real bearer. Generic creation
            // without part_of leaves them hidden, even from their stored owner.
            let bearer = record(&w, "Document", "note", Some("actual bearer")).await;
            let id = n1_call(
                &w,
                w.caller.clone(),
                "attach_text",
                json!({"record_id":bearer,"text":"actual body","filename":"n1-eligibility.txt"}),
            )
            .await
            .unwrap()["attachment_id"]
                .as_str()
                .unwrap()
                .to_owned();
            let actual = kernel::read_record_as(&w.db, &w.admin, &id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(actual.fields["v1_type"], "Document");
            assert_eq!(actual.fields["v1_kind"], "attachment");
            kernel::set_body_as(&w.db, &w.admin, &id, "actual body", actual.revision)
                .await
                .unwrap();
            id
        } else {
            record(&w, typ, kind, Some("actual body")).await
        };
        let full = SessionBackend::KernelV2
            .load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
            .await;
        let observation = kernel_v2::observe_body(&id, true);
        let metadata = SessionBackend::KernelV2
            .revalidate(&w.db, &w.caller, &id, PeerKind::Edit)
            .await;
        assert_eq!(metadata.is_ok(), expected, "{typ}/{kind}");
        assert_eq!(full.is_ok(), metadata.is_ok());
        if !expected {
            assert_eq!(metadata.unwrap_err().code, RefusalCode::RecordUnsupported);
            assert_eq!(full.err().unwrap().code, RefusalCode::RecordUnsupported);
        }
        assert!(observation.stages().is_empty());
    }
    // A real non-compatibility pin must keep native family/type/kind semantics.
    let package = crate::v2_standard::document4_package();
    let identity = kernel::install_package_as(&w.db, &w.admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&identity),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let id = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::DOCUMENT_FAMILY,
        "note",
        &json!({"title":"Real native pin"}).to_string(),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let actual = kernel::read_record_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        actual.family.as_deref(),
        Some(crate::v2_standard::DOCUMENT_FAMILY)
    );
    let observation = kernel_v2::observe_body(&id, true);
    kernel_v2::revalidate(&w.db, &w.caller, &id, PeerKind::Edit)
        .await
        .unwrap();
    assert!(observation.stages().is_empty());
    w.db.close().await;
}

#[tokio::test]
async fn metadata_recheck_preserves_missing_hidden_deleted_and_runtime_refusals() {
    let w = world().await;
    let viewer = kernel::create_principal(&w.db, "account", "Viewer", "n1:viewer", &w.admin)
        .await
        .unwrap();
    let home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    let hidden = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":"Document","v1_kind":"note","title":"Hidden"}).to_string(),
        &home,
    )
    .await
    .unwrap();
    let caller = Caller::authenticated("n1:viewer");
    assert_eq!(
        kernel::resolve_principal_by_binding(&w.db, caller.credential())
            .await
            .unwrap()
            .unwrap()
            .0,
        viewer
    );
    for id in [&hidden, "missing-n1-target"] {
        let observation = kernel_v2::observe_body(id, true);
        let refused = SessionBackend::KernelV2
            .revalidate(&w.db, &caller, id, PeerKind::View)
            .await
            .unwrap_err();
        assert_eq!(refused.code, RefusalCode::Forbidden);
        assert!(observation.stages().is_empty());
    }
    let deleted = record(&w, "Document", "note", None).await;
    n1_call(
        &w,
        w.caller.clone(),
        "delete_record",
        json!({"id":deleted,"reason":"N1 real deletion"}),
    )
    .await
    .unwrap();
    let refusal = SessionBackend::KernelV2
        .revalidate(&w.db, &w.caller, &deleted, PeerKind::View)
        .await
        .unwrap_err();
    assert_eq!(refusal.code, RefusalCode::Forbidden);
    let runtime = record(&w, "Document", "note", None).await;
    kernel::observe_facet_as(
        &w.db,
        &w.admin,
        &runtime,
        &kernel::FacetObservation {
            key: "runtime".into(),
            value: None,
            value_num: None,
            vocab_ref: None,
            as_of: "2026-10-28T00:00:00Z".into(),
        },
        None,
    )
    .await
    .unwrap();
    let present: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_facets WHERE record_id=? AND key='runtime')",
    )
    .bind(&runtime)
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert!(present); // A present NULL-valued facet still reserves the body.
    let refusal = SessionBackend::KernelV2
        .revalidate(&w.db, &w.caller, &runtime, PeerKind::Edit)
        .await
        .unwrap_err();
    assert_eq!(refusal.code, RefusalCode::RecordUnsupported);
    w.db.close().await;
}

#[tokio::test]
async fn metadata_recheck_rejects_unbound_account_and_real_policy_revocation() {
    let w = world().await;
    let viewer = kernel::create_principal(&w.db, "account", "Viewer", "n1:policy-viewer", &w.admin)
        .await
        .unwrap();
    let home = kernel::create_home(&w.db, KERNEL_ROOT_ID, Some(&[(&viewer, "view")]), &w.admin)
        .await
        .unwrap();
    let id = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":"WorkItem","v1_kind":"task","title":"Scoped"}).to_string(),
        &home,
    )
    .await
    .unwrap();
    let caller = Caller::authenticated("n1:policy-viewer");
    let observation = kernel_v2::observe_body(&id, true);
    SessionBackend::KernelV2
        .revalidate(&w.db, &caller, &id, PeerKind::View)
        .await
        .unwrap();
    assert_eq!(
        SessionBackend::KernelV2
            .revalidate(&w.db, &caller, &id, PeerKind::Edit)
            .await
            .unwrap_err()
            .code,
        RefusalCode::Forbidden
    );
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[(&w.admin, "manage")])
        .await
        .unwrap();
    assert_eq!(
        SessionBackend::KernelV2
            .revalidate(&w.db, &caller, &id, PeerKind::View)
            .await
            .unwrap_err()
            .code,
        RefusalCode::Forbidden
    );
    assert_eq!(
        SessionBackend::KernelV2
            .revalidate(
                &w.db,
                &Caller::authenticated("n1:unbound"),
                &id,
                PeerKind::View
            )
            .await
            .unwrap_err()
            .code,
        RefusalCode::Forbidden
    );
    assert!(observation.stages().is_empty());
    w.db.close().await;
}

#[tokio::test]
async fn metadata_recheck_retains_actual_app_install_gate() {
    let w = world().await;
    let id = record(&w, "Document", "note", None).await;
    let unadmitted_claim =
        crate::mcp::app_attribution::AppAttribution::new("n1.absent.app", "1", "missing-install")
            .unwrap();
    let claimed = w.caller.clone().with_host_asserted_app(unadmitted_claim);
    let observation = kernel_v2::observe_body(&id, true);
    assert!(kernel_v2::revalidate(&w.db, &claimed, &id, PeerKind::Edit)
        .await
        .is_err());
    assert!(observation.stages().is_empty());
    kernel_v2::revalidate(&w.db, &w.caller, &id, PeerKind::Edit)
        .await
        .unwrap();
    w.db.close().await;
}

#[tokio::test]
async fn seed_preflight_refuses_oversized_ascii_before_utf8_hydration() {
    use kernel_v2::BodyWorkStage as Stage;
    let w = world().await;
    let body = "x".repeat(super::registry::MAX_BODY_BYTES + 1);
    let id = record(&w, "Document", "note", Some(&body)).await;
    let encoding: String = sqlx::query_scalar("PRAGMA encoding")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(encoding, "UTF-8");
    let observation = kernel_v2::observe_body(&id, true);
    let refused = n1_open(&w, &id).await.unwrap_err();
    assert_eq!(refused.code, RefusalCode::TooLarge);
    assert_eq!(observation.stages(), vec![Stage::Encoding, Stage::Size]);
    assert!(live::kernel_writes::base_for_test(&w.db, &id).is_none());
    assert_eq!(
        live::kernel_writes::retained_transactions_for_test(&w.db),
        0
    );
    // A fresh real write transaction proves first-seed rollback settled.
    let mut next = crate::db::begin_write(w.db.write_pool()).await.unwrap();
    crate::Db::rollback_owned_kernel_content(&mut next)
        .await
        .unwrap();
    drop(next);
    w.db.close().await;
}

#[tokio::test]
async fn seed_preflight_counts_utf8_and_embedded_nul_bytes_at_exact_boundary() {
    use kernel_v2::BodyWorkStage as Stage;
    let w = world().await;
    let limit = super::registry::MAX_BODY_BYTES;
    for body in [
        "x".repeat(limit),
        format!("{}{}", "界".repeat(limit / 3), "x".repeat(limit % 3)),
    ] {
        assert_eq!(body.len(), limit);
        let id = record(&w, "Document", "note", Some(&body)).await;
        let observation = kernel_v2::observe_body(&id, false);
        let loaded = kernel_v2::load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
            .await
            .unwrap();
        assert_eq!(loaded.body, body);
        assert_eq!(
            observation.stages(),
            vec![Stage::Encoding, Stage::Size, Stage::Hydrate, Stage::Hash]
        );
        drop(observation);
        let oversized = body + "\0";
        let id = record(&w, "Document", "note", Some(&oversized)).await;
        let observation = kernel_v2::observe_body(&id, true);
        let (sql_bytes, sql_chars): (i64, i64) = sqlx::query_as(
            "SELECT octet_length(body),length(body) FROM kernel_record_bodies WHERE record_id=?",
        )
        .bind(&id)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
        assert_eq!(sql_bytes as usize, limit + 1);
        assert!(sql_chars < sql_bytes); // chars/NUL are not a byte budget.
        let refused = SessionBackend::KernelV2
            .load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
            .await
            .err()
            .unwrap();
        assert_eq!(refused.code, RefusalCode::TooLarge);
        assert_eq!(observation.stages(), vec![Stage::Encoding, Stage::Size]);
    }
    w.db.close().await;
}

#[tokio::test]
async fn seed_preflight_keeps_absent_and_present_empty_loader_compatibility() {
    let w = world().await;
    let absent = record(&w, "Document", "note", None).await;
    let empty = record(&w, "Document", "note", Some("")).await;
    let a = kernel_v2::load_committed(&w.db, &w.caller, &absent, PeerKind::Edit)
        .await
        .unwrap();
    let e = kernel_v2::load_committed(&w.db, &w.caller, &empty, PeerKind::Edit)
        .await
        .unwrap();
    assert_eq!(a.body, "");
    assert_eq!(e.body, "");
    assert!(a.base.proof.body_event_id.is_none());
    assert!(e.base.proof.body_event_id.is_some());
    assert_eq!(a.base.body_sha256, e.base.body_sha256);
    w.db.close().await;
}

#[tokio::test]
async fn seed_preflight_never_queries_size_before_view_admission() {
    let w = world().await;
    kernel::create_principal(&w.db, "account", "No grants", "n1:no-view", &w.admin)
        .await
        .unwrap();
    let home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    let id = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":"Document","v1_kind":"note","title":"Private"}).to_string(),
        &home,
    )
    .await
    .unwrap();
    let revision = kernel::read_record_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_body_as(
        &w.db,
        &w.admin,
        &id,
        &"x".repeat(super::registry::MAX_BODY_BYTES + 1),
        revision,
    )
    .await
    .unwrap();
    let observation = kernel_v2::observe_body(&id, true);
    let refused = SessionBackend::KernelV2
        .load_committed(
            &w.db,
            &Caller::authenticated("n1:no-view"),
            &id,
            PeerKind::View,
        )
        .await
        .err()
        .unwrap();
    assert_eq!(refused.code, RefusalCode::Forbidden);
    assert!(observation.stages().is_empty()); // Not even encoding/size was read.
    w.db.close().await;
}

#[tokio::test]
async fn seed_utf8_octet_preflight_uses_sqlite_length_metadata() {
    use sqlx::Row;
    let w = world().await;
    let id = record(&w, "Document", "note", Some("one\0界")).await;
    let mut tx = w.db.pool().begin().await.unwrap();
    kernel_v2::revalidate_on(&mut tx, &w.caller, &id, PeerKind::View)
        .await
        .unwrap();
    let bytes: i64 = sqlx::query_scalar(
        "SELECT octet_length(body) FROM main.kernel_record_bodies WHERE record_id=?",
    )
    .bind(&id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(bytes, "one\0界".len() as i64);
    let plan = sqlx::query(
        "EXPLAIN SELECT octet_length(body) FROM main.kernel_record_bodies WHERE record_id=?",
    )
    .bind(&id)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    assert!(plan
        .iter()
        .any(|r| r.get::<String, _>("opcode") == "Column" && r.get::<i64, _>("p5") & 64 != 0));
    tx.rollback().await.unwrap();
    w.db.close().await;
}

#[tokio::test]
async fn seed_fence_checks_size_after_actual_intervening_body_commit() {
    use kernel_v2::BodyWorkStage as Stage;
    let w = world().await;
    let id = record(&w, "Document", "note", Some("small")).await;
    // This existing actual native append/transaction precedes the first-seed
    // fence. It is not a fabricated projection or a timing-based oracle.
    let mut tx = crate::db::begin_write(w.db.write_pool()).await.unwrap();
    let appended = crate::store::append_in(
        &w.db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: id.clone(),
            event_type: "kernel.body_set.v1".into(),
            actor: Some(w.admin.clone()),
            payload: json!({"body":"x".repeat(super::registry::MAX_BODY_BYTES+1)}),
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await
    .unwrap();
    let gate = live::kernel_writes::test_gate(
        &w.db,
        live::kernel_writes::TestStage::SeedBeforeFence,
        false,
    );
    let _release_gate = N1GateRelease(gate.clone());
    let observation = kernel_v2::observe_body(&id, true);
    let worker = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { n1_open(&w, &id).await })
    };
    n1_gate_entered(&gate).await; // owns lane/gate, before actual BEGIN IMMEDIATE
    w.db.commit_kernel_content(tx).await.unwrap();
    gate.release.notify_one();
    assert_eq!(
        worker.await.unwrap().unwrap_err().code,
        RefusalCode::TooLarge
    );
    assert_eq!(observation.stages(), vec![Stage::Encoding, Stage::Size]);
    assert!(live::kernel_writes::base_for_test(&w.db, &id).is_none());
    let actual: i64 =
        sqlx::query_scalar("SELECT event_seq FROM kernel_record_bodies WHERE record_id=?")
            .bind(&id)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(actual, appended.local_seq);
    w.db.close().await;
}

#[tokio::test]
async fn explicit_owned_kernel_opener_seeds_and_joins_actual_room() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("native seed")).await;
    let (first, opened) = n1_open(&w, &id).await.unwrap();
    assert!(opened.base.proof.body_event_id.is_some());
    assert!(opened.base.proof.snapshot.is_some());
    let observation = kernel_v2::observe_body(&id, true);
    let (second, joined) = n1_open(&w, &id).await.unwrap();
    assert_eq!(opened.session, joined.session);
    assert_ne!(opened.peer, joined.peer);
    first.recheck_access(&w.caller).await.unwrap();
    second.recheck_access(&w.caller).await.unwrap();
    assert!(observation.stages().is_empty()); // real join+heartbeat bypass body
    let mut options =
        Options::with_client_id(yrs::ClientID::new(u64::from(joined.doc_client_ids[0])));
    options.offset_kind = OffsetKind::Bytes;
    let doc = Doc::with_options(options);
    doc.transact_mut()
        .apply_update(Update::decode_v1(&joined.sync).unwrap())
        .unwrap();
    assert_eq!(
        doc.get_or_insert_text("body").get_string(&doc.transact()),
        "native seed"
    );
    first.leave().await;
    second.leave().await;
}

#[tokio::test]
async fn explicit_owned_kernel_opener_cancel_preserves_owner_settlement() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed after cancelled waiter")).await;
    let gate = live::kernel_writes::test_gate(
        &w.db,
        live::kernel_writes::TestStage::SeedBeforeFence,
        false,
    );
    let _release_gate = N1GateRelease(gate.clone());
    let inside = live::kernel_writes::test_gate(
        &w.db,
        live::kernel_writes::TestStage::SeedAfterFence,
        false,
    );
    let _release_inside = N1GateRelease(inside.clone());
    let request = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { n1_open(&w, &id).await })
    };
    n1_gate_entered(&gate).await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    gate.release.notify_one();
    // No second opener exists yet. This checkpoint follows the actual first
    // BEGIN IMMEDIATE, so the dropped response cannot have cancelled its job.
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        inside.entered.notified(),
    )
    .await
    .expect("original seed owner did not survive observer cancellation");
    assert!(live::kernel_writes::base_for_test(&w.db, &id).is_none());
    inside.release.notify_one();
    // This next actual opener queues behind the retained first owner's lane;
    // success proves settlement/publication without cancellation of its work.
    let (peer, opened) = n1_open(&w, &id).await.unwrap();
    assert!(opened.base.proof.snapshot.is_some());
    assert_eq!(
        live::kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed after cancelled waiter")
    );
    assert_eq!(
        live::kernel_writes::retained_transactions_for_test(&w.db),
        0
    );
    peer.leave().await;
}

#[tokio::test]
async fn metadata_recheck_does_not_change_nonaccount_ordinary_update_admission() {
    let w = world().await;
    let principal = kernel::create_principal(&w.db, "agent", "Real agent", "n1:agent", &w.admin)
        .await
        .unwrap();
    let home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&principal, "edit")]),
        &w.admin,
    )
    .await
    .unwrap();
    let id = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":"Document","v1_kind":"note","title":"Ordinary agent"}).to_string(),
        &home,
    )
    .await
    .unwrap();
    let caller = Caller::authenticated("n1:agent");
    n1_call(
        &w,
        caller.clone(),
        "update_record",
        json!({"id":id,"body_set":"ordinary agent text"}),
    )
    .await
    .unwrap();
    assert_eq!(
        kernel::read_record_as(&w.db, &principal, &id)
            .await
            .unwrap()
            .unwrap()
            .body
            .as_deref(),
        Some("ordinary agent text")
    );
    assert_eq!(
        SessionBackend::KernelV2
            .revalidate(&w.db, &caller, &id, PeerKind::Edit)
            .await
            .unwrap_err()
            .code,
        RefusalCode::Forbidden
    );
    let refusal = live::open_kernel_inactive(
        &w.db,
        &caller,
        live::OpenRequest {
            record_id: id.clone(),
            mode: PeerKind::Edit,
            resume_peer: None,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(refusal.code, RefusalCode::Forbidden);
    assert!(live::kernel_writes::base_for_test(&w.db, &id).is_none());
    w.db.close().await;
}

#[tokio::test]
async fn known_size_rollback_and_actual_settlement_error_keep_distinct_refusals() {
    use live::kernel_writes::KernelTransaction;
    use sqlx::{sqlite::SqliteTransactionManager, TransactionManager};
    let w = world().await;
    let id = record(
        &w,
        "Document",
        "note",
        Some(&"x".repeat(super::registry::MAX_BODY_BYTES + 1)),
    )
    .await;
    let mut owned = KernelTransaction::begin(&w.db, (), |_, _| {})
        .await
        .unwrap();
    let oversized = kernel_v2::load_committed_on(owned.parts().0, &w.caller, &id, PeerKind::Edit)
        .await
        .err()
        .unwrap();
    assert_eq!(
        oversized.to_string(),
        "kernel live body exceeds session budget"
    );
    // Deliberate savepoint failure stimulus on the actual transaction. The
    // depth refusal is not a known rollback ACK and cannot report TooLarge.
    SqliteTransactionManager::begin(owned.parts().0, None)
        .await
        .unwrap();
    let failed = crate::Db::rollback_owned_kernel_connection(owned.parts().0)
        .await
        .unwrap_err();
    assert_eq!(
        super::backend::kernel_refusal(failed).code,
        RefusalCode::Unavailable
    );
    assert_eq!(
        SqliteTransactionManager::get_transaction_depth(owned.parts().0),
        2
    );
    // Resolve only this test-created savepoint; no product unquarantine path.
    SqliteTransactionManager::rollback(owned.parts().0)
        .await
        .unwrap();
    let settled = owned.rollback(oversized).await;
    assert_eq!(
        super::backend::kernel_refusal(settled).code,
        RefusalCode::TooLarge
    );
    assert_eq!(
        live::kernel_writes::retained_transactions_for_test(&w.db),
        0
    );
    let mut next = crate::db::begin_write(w.db.write_pool()).await.unwrap();
    crate::Db::rollback_owned_kernel_content(&mut next)
        .await
        .unwrap();
    drop(next);
    w.db.close().await;
}

#[tokio::test]
async fn metadata_backend_keeps_actual_public_v1_open_and_loader_behavior() {
    let db = crate::create_database(":memory:").await.unwrap();
    let id = crate::store::create_record(
        &db,
        json!({"type":"Document","kind":"note","name":"V1 control","body":"legacy seed"}),
    )
    .await
    .unwrap();
    let caller = Caller::local();
    SessionBackend::V1
        .revalidate(&db, &caller, &id, PeerKind::Edit)
        .await
        .unwrap();
    let original = SessionBackend::V1
        .load_committed(&db, &caller, &id, PeerKind::Edit)
        .await
        .unwrap();
    assert_eq!(original.body, "legacy seed");
    let (peer, opened) = live::open(
        &db,
        &caller,
        live::OpenRequest {
            record_id: id.clone(),
            mode: PeerKind::Edit,
            resume_peer: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(live::live_text(&db, &id).as_deref(), Some("legacy seed"));
    assert_eq!(opened.base.body_sha256, original.base.body_sha256);
    peer.leave().await;
}

// M1 composed fixed private explicit ingress; no public route/scheduler.
async fn m1_edit(peer: &live::SessionPeer, opened: &live::Opened, value: &str, append: bool) {
    let mut options =
        Options::with_client_id(yrs::ClientID::new(u64::from(opened.doc_client_ids[0])));
    options.offset_kind = OffsetKind::Bytes;
    let doc = Doc::with_options(options);
    doc.transact_mut()
        .apply_update(Update::decode_v1(&peer.sync(&[]).await.unwrap()).unwrap())
        .unwrap();
    let before = doc.transact().state_vector();
    let body = doc.get_or_insert_text("body");
    let old = body.get_string(&doc.transact()).len() as u32;
    if !append && old > 0 {
        body.remove_range(&mut doc.transact_mut(), 0, old);
    }
    let at = if append { old } else { 0 };
    if value.is_empty() {
        // Real accepted CRDT activity, even for absent->present-empty text.
        body.insert(&mut doc.transact_mut(), at, "x");
        body.remove_range(&mut doc.transact_mut(), at, 1);
    } else {
        body.insert(&mut doc.transact_mut(), at, value);
    }
    let delta = doc.transact().encode_diff_v1(&before);
    peer.apply("m1-composed", &delta).await.unwrap();
}
#[tokio::test]
async fn explicit_document_task_epic_direct_dirty_body_and_nonapp_accounting() {
    let w = world().await;
    for (typ, kind) in [
        ("Document", "note"),
        ("WorkItem", "task"),
        ("WorkItem", "epic"),
    ] {
        let id = record(&w, typ, kind, Some("seed")).await;
        let (peer, opened) = n1_open(&w, &id).await.unwrap();
        m1_edit(&peer, &opened, " direct", true).await;
        let before = kernel::body_history_as(&w.db, &w.admin, &id)
            .await
            .unwrap()
            .len();
        let version = live::kernel_writes::explicit_version_for_test(&peer, &w.caller)
            .await
            .unwrap()
            .unwrap();
        let stored = kernel::read_record_as(&w.db, &w.admin, &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.body.as_deref(), Some("seed direct"));
        assert_eq!(
            kernel::body_history_as(&w.db, &w.admin, &id)
                .await
                .unwrap()
                .len(),
            before + 1
        );
        let act: i64 = sqlx::query_scalar("SELECT act FROM content_events WHERE id=?")
            .bind(&version.event_id)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        let actions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM content_events WHERE act=? AND type LIKE 'kernel.app_action_%'",
        )
        .bind(act)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
        assert_eq!(actions, 0);
        assert_eq!(
            version.proof.body_event_id.as_deref(),
            Some(version.event_id.as_str())
        );
        drop(peer);
    }
}
#[tokio::test]
async fn explicit_snapshot_presence_empty_and_redundant_controls() {
    let w = world().await;
    let id = record(&w, "Document", "note", None).await;
    let (peer, opened) = n1_open(&w, &id).await.unwrap();
    assert!(
        live::kernel_writes::explicit_version_for_test(&peer, &w.caller)
            .await
            .unwrap()
            .is_none()
    );
    assert!(kernel::read_record_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .unwrap()
        .body
        .is_none());
    m1_edit(&peer, &opened, "", false).await;
    let version = live::kernel_writes::explicit_version_for_test(&peer, &w.caller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        kernel::read_record_as(&w.db, &w.admin, &id)
            .await
            .unwrap()
            .unwrap()
            .body
            .as_deref(),
        Some("")
    );
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert!(
        live::kernel_writes::explicit_version_for_test(&peer, &w.caller)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap(),
        events
    );
    assert!(version.proof.body_event_seq.is_some());
    drop(peer);
}
#[tokio::test]
async fn explicit_view_peer_refuses_without_effect_or_requester_substitution() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = live::kernel_writes::open_for_test(
        &w.db,
        &w.caller,
        live::OpenRequest {
            record_id: id.clone(),
            mode: PeerKind::View,
            resume_peer: None,
        },
    )
    .await
    .unwrap();
    let before = kernel::body_history_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .len();
    assert!(
        live::kernel_writes::explicit_version_for_test(&peer, &w.caller)
            .await
            .is_err()
    );
    assert_eq!(
        kernel::body_history_as(&w.db, &w.admin, &id)
            .await
            .unwrap()
            .len(),
        before
    );
    drop(peer);
}
async fn m1_shared_app_target() -> (
    std::sync::Arc<crate::v1_import::NativePeerTwoAdoptedAppsFixture>,
    String,
) {
    let f = crate::v1_import::native_peer_two_adopted_apps_fixture_for_test().await;
    let home = kernel::create_home(
        &f.owner.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.owner.principal, "edit"), (&f.second_principal, "edit")]),
        &f.owner.administrator,
    )
    .await
    .unwrap();
    let id = kernel::create_json_as(
        &f.owner.db,
        &f.owner.administrator,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":"Document","v1_kind":"note","title":"Explicit initiator"}).to_string(),
        &home,
    )
    .await
    .unwrap();
    (f, id)
}
async fn m1_open_app(
    db: &crate::db::Db,
    caller: &Caller,
    id: &str,
) -> (live::SessionPeer, live::Opened) {
    live::kernel_writes::open_for_test(
        db,
        caller,
        live::OpenRequest {
            record_id: id.into(),
            mode: PeerKind::Edit,
            resume_peer: None,
        },
    )
    .await
    .unwrap()
}
#[tokio::test]
async fn explicit_nonapp_preserves_app_authors_without_action() {
    let (f, id) = m1_shared_app_target().await;
    let registration = live::kernel_writes::register_writer_fixture_owner_for_test(
        &f.owner.db,
        std::sync::Arc::clone(&f.owner),
    );
    let (app, opened) = m1_open_app(&f.owner.db, &f.owner.adopted_caller, &id).await;
    m1_edit(&app, &opened, "app authored", false).await;
    let actual_nonapp = Caller::authenticated("account-a");
    assert!(actual_nonapp.host_asserted_app().is_none());
    let (requester, _) = m1_open_app(&f.owner.db, &actual_nonapp, &id).await;
    let version = live::kernel_writes::explicit_version_for_test(&requester, &actual_nonapp)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(version.contributors.len(), 1);
    assert_eq!(
        version.contributors[0]
            .app
            .as_ref()
            .unwrap()
            .install_event_id,
        f.owner.adopted_generation
    );
    let (actor, act): (String, i64) =
        sqlx::query_as("SELECT actor,act FROM content_events WHERE id=?")
            .bind(&version.event_id)
            .fetch_one(f.owner.db.pool())
            .await
            .unwrap();
    assert_eq!(actor, f.owner.administrator);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE act=? AND type LIKE 'kernel.app_action_%'",
    )
    .bind(act)
    .fetch_one(f.owner.db.pool())
    .await
    .unwrap();
    assert_eq!(count, 0);
    drop(app);
    drop(requester);
    drop(registration);
    f.owner.db.close().await;
    drop(f);
}
#[tokio::test]
async fn explicit_historical_span_rules_do_not_reauthorize_old_app_generation() {
    let (f, id) = m1_shared_app_target().await;
    let registration = live::kernel_writes::register_writer_fixture_owner_for_test(
        &f.owner.db,
        std::sync::Arc::clone(&f.owner),
    );
    let (app, opened) = m1_open_app(&f.owner.db, &f.owner.adopted_caller, &id).await;
    m1_edit(&app, &opened, "old author", false).await;
    live::kernel_writes::explicit_version_for_test(&app, &f.owner.adopted_caller)
        .await
        .unwrap()
        .unwrap();
    kernel::app_installs::remove_as(
        &f.owner.db,
        &f.owner.principal,
        &f.owner.pin.package,
        &f.owner.adopted_generation,
    )
    .await
    .unwrap();
    let (next, opened) = m1_open_app(&f.owner.db, &f.second_adopted_caller, &id).await;
    m1_edit(&next, &opened, " new author", true).await;
    let version = live::kernel_writes::explicit_version_for_test(&next, &f.second_adopted_caller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(version.contributors.len(), 1);
    assert_eq!(version.contributors[0].principal, f.second_principal);
    let (body, payload): (String, String) = sqlx::query_as(
        "SELECT json_extract(payload,'$.body'),payload FROM content_events WHERE id=?",
    )
    .bind(&version.event_id)
    .fetch_one(f.owner.db.pool())
    .await
    .unwrap();
    assert_eq!(body, "old author new author");
    assert!(payload.contains(&f.owner.adopted_generation));
    drop(app);
    drop(next);
    drop(registration);
    f.owner.db.close().await;
    drop(f);
}
