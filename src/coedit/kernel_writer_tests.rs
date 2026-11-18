//! Writer completion proofs. Every ordering edge is a channel or a held lock.
use super::live::kernel_writes::{owned_result, KernelTransaction};
use crate::db::Db;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

struct Ownership(Arc<Mutex<bool>>);
impl Drop for Ownership {
    fn drop(&mut self) {
        *self.0.lock().unwrap() = true;
    }
}
fn quarantine(_: &mut Ownership, _: &str) {}

#[tokio::test]
async fn dropping_response_during_transaction_keeps_owner_through_durability() {
    let db = crate::db::kernel_settlement_tests::database().await;
    let released = Arc::new(Mutex::new(false));
    let ownership = Ownership(Arc::clone(&released));
    let (entered, inside) = oneshot::channel();
    let (proceed, resume) = oneshot::channel();
    let (finished, durable) = oneshot::channel();
    let worker_db = db.clone();
    let diagnostics = crate::write_diagnostics::Context::new(
        "update_record",
        Some("h1_cancelled_request".into()),
        Some("h1_retry_group".into()),
    );
    let expected = diagnostics.fields();
    let owned_db = db.clone();
    let response = tokio::spawn(async move {
        diagnostics
            .scope(owned_result(owned_db, async move {
                assert_eq!(
                    crate::write_diagnostics::current().unwrap().fields(),
                    expected
                );
                let mut transaction =
                    KernelTransaction::begin(&worker_db, ownership, quarantine).await?;
                let (tx, _) = transaction.parts();
                sqlx::query("CREATE TABLE response_drop_evidence(value INTEGER)")
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("INSERT INTO response_drop_evidence VALUES(42)")
                    .execute(&mut *tx)
                    .await?;
                entered.send(()).unwrap();
                resume.await.unwrap();
                let ownership = transaction.commit().await?;
                assert_eq!(
                    crate::write_diagnostics::current().unwrap().fields(),
                    expected
                );
                // This stands in for synchronous registry install/drain under ops.
                assert!(!*ownership.0.lock().unwrap());
                drop(ownership);
                finished.send(()).unwrap();
                Ok(())
            }))
            .await
    });
    inside.await.unwrap();
    response.abort();
    assert!(response.await.unwrap_err().is_cancelled());
    assert!(!*released.lock().unwrap());
    proceed.send(()).unwrap();
    durable.await.unwrap();
    assert!(*released.lock().unwrap());
    let value: i64 = sqlx::query_scalar("SELECT value FROM response_drop_evidence")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(value, 42);
}

#[tokio::test]
async fn dropped_transaction_owns_guards_until_rollback_is_acknowledged() {
    let db = crate::db::kernel_settlement_tests::database().await;
    let released = Arc::new(Mutex::new(false));
    let mut transaction =
        KernelTransaction::begin(&db, Ownership(Arc::clone(&released)), quarantine)
            .await
            .unwrap();
    sqlx::query("CREATE TABLE dropped_transaction_evidence(value INTEGER)")
        .execute(&mut *transaction.parts().0)
        .await
        .unwrap();
    drop(transaction);
    // BEGIN on the sole connection can complete only after rollback cleanup
    // disposes the original transaction. It cannot pass a queued rollback.
    let mut next = crate::db::begin_write(db.write_pool()).await.unwrap();
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='dropped_transaction_evidence')",
    )
    .fetch_one(&mut *next)
    .await
    .unwrap();
    assert!(!exists);
    Db::rollback_owned_kernel_content(&mut next).await.unwrap();
    drop(next);
}

use super::live::{OpenRequest, Opened, SessionPeer};
use super::{live::kernel_writes, PeerKind};
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

async fn room(w: &World, id: &str) -> (SessionPeer, Opened) {
    kernel_writes::open_for_test(
        &w.db,
        &w.caller,
        OpenRequest {
            record_id: id.into(),
            mode: PeerKind::Edit,
            resume_peer: None,
        },
    )
    .await
    .unwrap()
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

async fn stored_body(w: &World, id: &str) -> String {
    kernel::read_record_as(&w.db, &w.admin, id)
        .await
        .unwrap()
        .unwrap()
        .body
        .unwrap_or_default()
}

#[tokio::test]
async fn ordinary_non_account_updates_and_replay_preserve_live_contributor_boundary() {
    use sha2::{Digest, Sha256};
    let digest = |body: &str| hex::encode(Sha256::digest(body.as_bytes()));
    let admin = world().await;
    for kind in ["agent", "run"] {
        let binding = format!("writer-proof:{kind}");
        let principal =
            kernel::create_principal(&admin.db, kind, "Ordinary writer", &binding, &admin.admin)
                .await
                .unwrap();
        let home = kernel::create_home(
            &admin.db,
            KERNEL_ROOT_ID,
            Some(&[(&principal, "edit")]),
            &admin.admin,
        )
        .await
        .unwrap();
        let id = kernel::create_json_as(
            &admin.db,
            &admin.admin,
            crate::v2_standard::v1_compat::FAMILY,
            "record",
            &json!({"v1_type":"Document","v1_kind":"note","title":"Ordinary"}).to_string(),
            &home,
        )
        .await
        .unwrap();
        let writer = World {
            caller: Caller::authenticated(&binding),
            ..admin.clone()
        };
        // Raw append custody has no account-only contributor requirement
        // either; preserve the explicit actor of this trusted Rust append API.
        crate::store::append(
            &admin.db,
            crate::store::AppendSpec {
                record_id: id.clone(),
                event_type: "kernel.body_set.v1".into(),
                actor: Some(principal),
                payload: json!({"body":"Raw ordinary body"}),
            },
        )
        .await
        .unwrap();
        assert_eq!(stored_body(&admin, &id).await, "Raw ordinary body");
        update(&writer, json!({"id":id,"summary":"Agent metadata"}))
            .await
            .unwrap();
        update(&writer, json!({"id":id,"body_set":"Unkeyed ordinary body","if_body_digest":digest("Raw ordinary body")}))
            .await
            .unwrap();
        let args = json!({"id":id,"body_set":"Ordinary body","if_body_digest":digest("Unkeyed ordinary body"),"idempotency_key":"ordinary-key"});
        let receipt = update(&writer, args.clone()).await.unwrap();
        let events = body_events(&admin, &id).await;
        assert_eq!(update(&writer, args).await.unwrap(), receipt);
        assert_eq!(body_events(&admin, &id).await, events);
        assert_eq!(stored_body(&admin, &id).await, "Ordinary body");
        let summary = kernel::read_record_as(&admin.db, &admin.admin, &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(summary.fields["summary"], "Agent metadata");

        // Ordinary Edit authority does not mint an account-only live author.
        assert!(kernel_writes::open_for_test(
            &writer.db,
            &writer.caller,
            OpenRequest {
                record_id: id.clone(),
                mode: PeerKind::Edit,
                resume_peer: None
            },
        )
        .await
        .is_err());
        let (peer, opened) = room(&admin, &id).await;
        append_peer(&peer, &opened, " + peer").await;
        assert!(update(
            &writer,
            json!({"id":id,"body_set":"Unauthorized live author","if_body_digest":digest("Ordinary body + peer")})
        )
        .await
        .is_err());
        assert_eq!(stored_body(&admin, &id).await, "Ordinary body");
        // Metadata remains an ordinary operation even while a room exists.
        update(&writer, json!({"id":id,"summary":"Still ordinary"}))
            .await
            .unwrap();
        update(&admin, json!({"id":id,"body_append":" account successor"}))
            .await
            .unwrap();
        assert_eq!(
            stored_body(&admin, &id).await,
            "Ordinary body + peer account successor"
        );

        let host = World {
            caller: Caller::authenticated(kernel::HOST_IMPORT_BINDING),
            ..admin.clone()
        };
        assert!(update(&host, json!({"id":id,"summary":"Forbidden host"}))
            .await
            .is_err());
        peer.leave().await;
    }
}

async fn body_events(w: &World, id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE record_id=? AND type='kernel.body_set.v1'",
    )
    .bind(id)
    .fetch_one(w.db.pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn ordinary_update_flushes_peer_then_installs_exact_native_successor() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " peer").await;
    let before = body_events(&w, &id).await;
    update(
        &w,
        json!({"id":id,"body_append":" agent","name":"Metadata retained","facets":{"writer_note":"kept"}}),
    )
    .await
    .unwrap();
    assert_eq!(stored_body(&w, &id).await, "seed peer agent");
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed peer agent")
    );
    assert_eq!(body_events(&w, &id).await, before + 2);
    let payload: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id=? AND type='kernel.body_set.v1' ORDER BY seq DESC LIMIT 1")
        .bind(&id).fetch_one(w.db.pool()).await.unwrap();
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload["coedit"]["session"], opened.session.0);
    assert_eq!(payload["coedit"]["contributors"][0]["principal"], w.admin);
    let loaded = super::backend::SessionBackend::KernelV2
        .load_committed(&w.db, &w.caller, &id, PeerKind::Edit)
        .await
        .unwrap();
    let base = kernel_writes::base_for_test(&w.db, &id).unwrap();
    assert_eq!(base.version, loaded.base.version);
    assert_eq!(base.proof.body_event_seq, loaded.base.proof.body_event_seq);
    assert_eq!(base.proof.body_event_id, loaded.base.proof.body_event_id);
    assert!(base.proof.snapshot.is_some());
    assert_eq!(
        kernel::read_record_as(&w.db, &w.admin, &id)
            .await
            .unwrap()
            .unwrap()
            .fields["title"],
        "Metadata retained"
    );
    let v1_tables: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('records','facet_values','permissions','activity_roster')")
        .fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(v1_tables, 0);
    peer.leave().await;
}

#[tokio::test]
async fn keyed_replay_and_new_key_refusal_do_not_flush_new_peer_text() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let request = json!({"id":id,"body_append":" old","idempotency_key":"original"});
    let receipt = update(&w, request.clone()).await.unwrap();
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " dirty").await;
    let events = body_events(&w, &id).await;
    let replay = update(&w, request.clone()).await.unwrap();
    assert_eq!(receipt, replay);
    assert!(update(
        &w,
        json!({"id":id,"body_append":" new","idempotency_key":"fresh"})
    )
    .await
    .is_err());
    assert!(update(
        &w,
        json!({"id":id,"body_append":" changed","idempotency_key":"original"})
    )
    .await
    .is_err());
    assert_eq!(body_events(&w, &id).await, events);
    assert_eq!(stored_body(&w, &id).await, "seed old");
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed old dirty")
    );
    peer.leave().await;
}

#[tokio::test]
async fn unported_writers_and_forged_metadata_refuse_without_losing_dirty_text() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " dirty").await;
    let events = body_events(&w, &id).await;
    let view = kernel::read_record_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        kernel::set_body_as(&w.db, &w.admin, &id, "clobber", view.revision)
            .await
            .is_err()
    );
    assert!(crate::store::append(
        &w.db,
        crate::store::AppendSpec {
            record_id: id.clone(),
            event_type: "kernel.body_set.v1".into(),
            actor: Some(w.admin.clone()),
            payload: json!({"body":"forged","coedit":{"session":opened.session.0}}),
        }
    )
    .await
    .is_err());
    assert!(update(&w, json!({"id":id,"facets":{"runtime":"html"}}))
        .await
        .is_err());
    assert_eq!(body_events(&w, &id).await, events);
    assert_eq!(stored_body(&w, &id).await, "seed");
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed dirty")
    );
    update(&w, json!({"id":id,"name":"Title","summary":"Summary"}))
        .await
        .unwrap();
    assert_eq!(body_events(&w, &id).await, events);
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed dirty")
    );
    peer.leave().await;
}

#[tokio::test]
async fn first_seed_fences_an_earlier_transaction_and_includes_its_exact_body_event() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let mut tx = crate::db::begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    let appended = crate::store::append_in(
        &w.db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: id.clone(),
            event_type: "kernel.body_set.v1".into(),
            actor: Some(w.admin.clone()),
            payload: json!({"body":"earlier writer"}),
        },
        &mut acts,
    )
    .await
    .unwrap();
    let gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::SeedBeforeFence, false);
    let opener = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { room(&w, &id).await })
    };
    gate.entered.notified().await;
    // Seed owns its open gate but has not acquired SQLite's writer fence.
    w.db.commit_kernel_content(tx).await.unwrap();
    gate.release.notify_one();
    let (peer, opened) = opener.await.unwrap();
    assert_eq!(
        opened.base.proof.body_event_id.as_deref(),
        Some(appended.id.as_str())
    );
    assert_eq!(opened.base.proof.body_event_seq, Some(appended.local_seq));
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("earlier writer")
    );
    peer.leave().await;
}

#[tokio::test]
async fn public_raw_append_holds_open_gate_through_durability_before_first_seed() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let write_gate =
        kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterMutation, false);
    let writer = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move {
            crate::store::append(
                &w.db,
                crate::store::AppendSpec {
                    record_id: id,
                    event_type: "kernel.body_set.v1".into(),
                    actor: Some(w.admin),
                    payload: json!({"body":"public raw writer"}),
                },
            )
            .await
            .unwrap()
        })
    };
    write_gate.entered.notified().await;
    let seed_gate =
        kernel_writes::test_gate(&w.db, kernel_writes::TestStage::SeedBeforeLane, false);
    let opener = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { room(&w, &id).await })
    };
    seed_gate.entered.notified().await;
    seed_gate.release.notify_one();
    write_gate.release.notify_one();
    let event = writer.await.unwrap();
    let (peer, opened) = opener.await.unwrap();
    assert_eq!(
        opened.base.proof.body_event_id.as_deref(),
        Some(event.id.as_str())
    );
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("public raw writer")
    );
    peer.leave().await;
}

#[tokio::test]
async fn native_body_append_tail_failure_rolls_back_fields_and_candidate_together() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = room(&w, &id).await;
    let events = body_events(&w, &id).await;
    let base = kernel_writes::base_for_test(&w.db, &id).unwrap();
    let gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterMutation, true);
    let request = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move {
            update(
                &w,
                json!({"id":id,"body_append":" discarded","name":"Discarded title"}),
            )
            .await
        })
    };
    gate.entered.notified().await;
    gate.release.notify_one();
    assert!(request.await.unwrap().is_err());
    assert_eq!(stored_body(&w, &id).await, "seed");
    assert_eq!(body_events(&w, &id).await, events);
    assert_eq!(kernel_writes::base_for_test(&w.db, &id), Some(base));
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed")
    );
    assert_eq!(
        kernel::read_record_as(&w.db, &w.admin, &id)
            .await
            .unwrap()
            .unwrap()
            .fields["title"],
        "Foundation"
    );
    peer.leave().await;
}

#[tokio::test]
async fn invalid_update_sources_do_not_flush_a_dirty_live_peer() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " dirty").await;
    let events = body_events(&w, &id).await;
    let base = kernel_writes::base_for_test(&w.db, &id).unwrap();
    for sources in [
        json!([id, id]),
        json!([{"record_id":id,"reason":"read","role":""}]),
    ] {
        assert!(update(
            &w,
            json!({"id":id,"body_append":" rejected","sources":sources})
        )
        .await
        .is_err());
        assert_eq!(body_events(&w, &id).await, events);
        assert_eq!(stored_body(&w, &id).await, "seed");
        assert_eq!(kernel_writes::base_for_test(&w.db, &id), Some(base.clone()));
        assert_eq!(
            kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
            Some("seed dirty")
        );
    }
    peer.leave().await;
}

#[tokio::test]
async fn metadata_commit_after_own_flush_is_not_hidden_from_timestamp_guard() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    let before = {
        let mut conn = w.db.pool().acquire().await.unwrap();
        kernel::record_metadata::updated_at_on(&mut conn, &id)
            .await
            .unwrap()
    };
    append_peer(&peer, &opened, " peer").await;
    let gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterFlush, false);
    let request = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move {
            update(
                &w,
                json!({"id":id,"body_append":" refused","if_unmodified_since":before}),
            )
            .await
        })
    };
    gate.entered.notified().await;
    let current_revision = kernel::read_record_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::revise_json_as_expected(
        &w.db,
        &w.admin,
        &id,
        &json!({"title":"Concurrent metadata"}).to_string(),
        Some(current_revision),
    )
    .await
    .unwrap();
    gate.release.notify_one();
    assert!(request.await.unwrap().is_err());
    assert_eq!(stored_body(&w, &id).await, "seed peer");
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed peer")
    );
    assert_eq!(
        kernel::read_record_as(&w.db, &w.admin, &id)
            .await
            .unwrap()
            .unwrap()
            .fields["title"],
        "Concurrent metadata"
    );
    peer.leave().await;
}

#[tokio::test]
async fn dropped_response_after_sql_durability_still_installs_and_publishes_once() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = room(&w, &id).await;
    let mut events = peer.subscribe();
    let before = body_events(&w, &id).await;
    let gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterDurability, false);
    let request = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { update(&w, json!({"id":id,"body_append":" agent"})).await })
    };
    gate.entered.notified().await;
    assert_eq!(stored_body(&w, &id).await, "seed agent");
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed")
    );
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    gate.release.notify_one();
    let version = loop {
        if let super::live::SessionEvent::Versioned(version) = events.recv().await.unwrap() {
            break version;
        }
    };
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed agent")
    );
    assert_eq!(body_events(&w, &id).await, before + 1);
    let base = kernel_writes::base_for_test(&w.db, &id).unwrap();
    assert_eq!(base.proof, version.proof);
    assert_eq!(
        base.proof.body_event_id.as_deref(),
        Some(version.event_id.as_str())
    );
    peer.leave().await;
}

#[tokio::test]
async fn permit_rejects_other_record_database_connection_and_payload() {
    use kernel_writes::{KernelBodyWrite, KernelTransaction, KernelWriteMode};
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = room(&w, &id).await;
    let ownership =
        KernelBodyWrite::acquire(&w.db, &w.caller, Some(&id), KernelWriteMode::RouteBody)
            .await
            .unwrap();
    let mut transaction = KernelTransaction::begin(&w.db, ownership, KernelBodyWrite::quarantine)
        .await
        .unwrap();
    let payload = json!({"body":"candidate"});
    let (tx, owner) = transaction.parts();
    let permit = owner.permit_for_test(tx, &payload).await.unwrap();
    assert!(permit
        .consume(&w.db, tx, "other-record", "kernel.body_set.v1", &payload)
        .is_err());
    let permit = owner.permit_for_test(tx, &payload).await.unwrap();
    assert!(permit
        .consume(
            &w.db,
            tx,
            &id,
            "kernel.body_set.v1",
            &json!({"body":"substituted"})
        )
        .is_err());
    let mut other_connection = w.db.pool().begin().await.unwrap();
    let permit = owner.permit_for_test(tx, &payload).await.unwrap();
    assert!(permit
        .consume(
            &w.db,
            &mut other_connection,
            &id,
            "kernel.body_set.v1",
            &payload
        )
        .is_err());
    other_connection.rollback().await.unwrap();
    let other = crate::db::kernel_settlement_tests::database().await;
    let permit = owner.permit_for_test(tx, &payload).await.unwrap();
    assert!(permit
        .consume(&other, tx, &id, "kernel.body_set.v1", &payload)
        .is_err());
    let mut foreign_tx = other.pool().begin().await.unwrap();
    assert!(owner
        .permit_for_test(&mut foreign_tx, &payload)
        .await
        .is_err());
    foreign_tx.rollback().await.unwrap();
    transaction
        .rollback(crate::Error::engine("test cancellation"))
        .await;
    peer.leave().await;
}

#[tokio::test]
async fn two_updates_and_peer_apply_serialize_without_an_acknowledgement_gap() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    let gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterMutation, false);
    let first = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { update(&w, json!({"id":id,"body_append":" A"})).await })
    };
    gate.entered.notified().await;
    let second_gate =
        kernel_writes::test_gate(&w.db, kernel_writes::TestStage::BeforeOwnedLane, false);
    let second = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { update(&w, json!({"id":id,"body_append":" B"})).await })
    };
    second_gate.entered.notified().await;
    second_gate.release.notify_one();
    let mut apply = Box::pin(append_peer(&peer, &opened, " P"));
    // Polling the real apply future proves it cannot acknowledge while the
    // first candidate is appended but uncommitted. No timeout/sleep oracle.
    assert!(futures::poll!(&mut apply).is_pending());
    assert_eq!(stored_body(&w, &id).await, "seed");
    gate.release.notify_one();
    let (_, a, b) = tokio::join!(apply, first, second);
    a.unwrap().unwrap();
    b.unwrap().unwrap();
    peer.version("settle final peer version").await.unwrap();
    let stored = stored_body(&w, &id).await;
    assert!(
        stored.contains(" A") && stored.contains(" B") && stored.contains(" P"),
        "{stored}"
    );
    assert_eq!(kernel_writes::live_text_for_test(&w.db, &id), Some(stored));
    peer.leave().await;
}

#[tokio::test]
async fn keyed_receipt_and_body_rollback_together_without_a_live_room() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterMutation, true);
    let request = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move {
            update(
                &w,
                json!({"id":id,"body_append":" discarded","idempotency_key":"rolled-back"}),
            )
            .await
        })
    };
    gate.entered.notified().await;
    gate.release.notify_one();
    assert!(request.await.unwrap().is_err());
    assert_eq!(stored_body(&w, &id).await, "seed");
    let receipt_table: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='kernel_mcp_write_receipts')",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    let receipts: i64 = if receipt_table {
        sqlx::query_scalar(
            "SELECT count(*) FROM kernel_mcp_write_receipts WHERE operation_key='rolled-back'",
        )
        .fetch_one(w.db.pool())
        .await
        .unwrap()
    } else {
        0
    };
    assert_eq!(receipts, 0);
    update(
        &w,
        json!({"id":id,"body_append":" once","idempotency_key":"rolled-back"}),
    )
    .await
    .unwrap();
    assert_eq!(stored_body(&w, &id).await, "seed once");
}

#[tokio::test]
async fn post_durability_uncertainty_quarantines_one_owner_and_refuses_queued_work() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = room(&w, &id).await;
    let gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterDurability, true);
    let first = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { update(&w, json!({"id":id,"body_append":" committed"})).await })
    };
    gate.entered.notified().await;
    let queued_gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LaneQueued, false);
    let queued = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { update(&w, json!({"id":id,"body_append":" refused"})).await })
    };
    queued_gate.entered.notified().await;
    gate.release.notify_one();
    let error = first.await.unwrap().unwrap_err().to_string();
    assert!(
        error.contains("uncertain") && error.contains("do not retry"),
        "{error}"
    );
    queued_gate.release.notify_one();
    let queued_error = queued.await.unwrap().unwrap_err().to_string();
    assert!(queued_error.contains("quarantin"), "{queued_error}");
    assert!(kernel_writes::quarantine_for_test(&w.db).is_some());
    assert_eq!(kernel_writes::retained_transactions_for_test(&w.db), 1);
    assert_eq!(stored_body(&w, &id).await, "seed committed");
    assert!(kernel_writes::open_for_test(
        &w.db,
        &w.caller,
        OpenRequest {
            record_id: id.clone(),
            mode: PeerKind::Edit,
            resume_peer: None,
        }
    )
    .await
    .is_err());
    assert!(update(&w, json!({"id":id,"name":"refused metadata"}))
        .await
        .is_err());
    assert_eq!(kernel_writes::retained_transactions_for_test(&w.db), 1);
    assert!(!super::live::release_idle_database(&w.db));
    kernel_writes::dispose_settled_quarantine_for_test(&w.db).await;
    assert_eq!(kernel_writes::retained_transactions_for_test(&w.db), 0);
    assert!(update(&w, json!({"id":id,"body_append":" still refused"}))
        .await
        .is_err());
    drop(peer);
}

#[tokio::test]
async fn first_open_already_waiting_on_lane_refuses_quarantine_without_seeding() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let unopened = record(&w, "Document", "note", Some("unopened")).await;
    let (peer, _) = room(&w, &id).await;
    let gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterDurability, true);
    let first = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { update(&w, json!({"id":id,"body_append":" committed"})).await })
    };
    gate.entered.notified().await;
    let queued_gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LaneQueued, false);
    let opener = {
        let w = w.clone();
        let id = unopened.clone();
        tokio::spawn(async move {
            kernel_writes::open_for_test(
                &w.db,
                &w.caller,
                OpenRequest {
                    record_id: id,
                    mode: PeerKind::Edit,
                    resume_peer: None,
                },
            )
            .await
        })
    };
    queued_gate.entered.notified().await; // real lane lock future polled Pending
    gate.release.notify_one();
    assert!(first.await.unwrap().is_err());
    queued_gate.release.notify_one();
    let error = opener.await.unwrap().unwrap_err().to_string();
    assert!(error.contains("quarantin"), "{error}");
    assert!(kernel_writes::base_for_test(&w.db, &unopened).is_none());
    assert_eq!(stored_body(&w, &unopened).await, "unopened");
    assert_eq!(kernel_writes::retained_transactions_for_test(&w.db), 1);
    kernel_writes::dispose_settled_quarantine_for_test(&w.db).await;
    drop(peer);
}

#[tokio::test]
async fn peer_apply_already_queued_on_ops_refuses_quarantine_without_acknowledgement() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    let update_bytes = peer_update(&peer, &opened, " unacknowledged peer").await;
    let gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterDurability, true);
    let first = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { update(&w, json!({"id":id,"body_append":" committed"})).await })
    };
    gate.entered.notified().await;
    let peer_gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::OpsQueued, false);
    let pending_peer = tokio::spawn(async move {
        let result = peer.apply("must-not-ack", &update_bytes).await;
        (peer, result)
    });
    peer_gate.entered.notified().await; // actual ops acquisition polled Pending
    gate.release.notify_one();
    assert!(first.await.unwrap().is_err());
    peer_gate.release.notify_one();
    let (peer, result) = pending_peer.await.unwrap();
    let error = result.unwrap_err().to_string();
    assert!(error.contains("quarantin"), "{error}");
    assert_eq!(stored_body(&w, &id).await, "seed committed");
    assert!(peer.sync(&[]).await.is_err()); // synchronous state path, no ops wait
    assert!(peer.recheck_access(&w.caller).await.is_err()); // no retained-ops wait
    assert_eq!(kernel_writes::retained_transactions_for_test(&w.db), 1);
    kernel_writes::dispose_settled_quarantine_for_test(&w.db).await;
    drop(peer);
}

#[tokio::test]
async fn owned_update_preserves_run_parent_and_intent_on_body_and_facet_events() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = room(&w, &id).await;
    let run = call(&w, "bootstrap", json!({"run_key":"new"}))
        .await
        .unwrap();
    let parent = call(&w, "bootstrap", json!({"run_key":"new"}))
        .await
        .unwrap();
    let run_key = run["session"]["run_key"].as_str().unwrap();
    let parent_key = parent["session"]["run_key"].as_str().unwrap();
    let intent = "Preserve the actual operation context across owned persistence";
    call(
        &w,
        "set_intent",
        json!({"run_key":run_key,"parent_key":parent_key,"intent":intent}),
    )
    .await
    .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    update(
        &w,
        json!({"id":id,"body_append":" annotated","facets":{"writer_context":"kept"},
        "run_key":run_key,"parent_key":parent_key}),
    )
    .await
    .unwrap();
    type AnnotatedEvent = (String, Option<String>, Option<String>, Option<String>);
    let events: Vec<AnnotatedEvent> = sqlx::query_as(
        "SELECT type,run_key,parent_key,intent FROM content_events WHERE record_id=? AND seq>? AND type IN ('kernel.body_set.v1','kernel.facet_observed.v1') ORDER BY seq")
        .bind(&id).bind(before).fetch_all(w.db.pool()).await.unwrap();
    assert_eq!(events.len(), 2);
    for (_, run, parent, recorded_intent) in events {
        assert_eq!(run.as_deref(), Some(run_key));
        assert_eq!(parent.as_deref(), Some(parent_key));
        assert_eq!(recorded_intent.as_deref(), Some(intent));
    }
    assert_eq!(stored_body(&w, &id).await, "seed annotated");
    peer.leave().await;
}

#[tokio::test]
async fn per_database_admission_bound_refuses_without_writes_and_preserves_other_database_capacity()
{
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let held = kernel_writes::hold_job_slots_for_test(&w.db, 8);
    let before = body_events(&w, &id).await;
    let error = update(&w, json!({"id":id,"body_append":" refused"}))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("database") && error.contains("capacity"),
        "{error}"
    );
    assert_eq!(body_events(&w, &id).await, before);
    assert_eq!(stored_body(&w, &id).await, "seed");
    let other = world().await;
    let other_id = record(&other, "Document", "note", Some("other")).await;
    update(&other, json!({"id":other_id,"body_append":" admitted"}))
        .await
        .unwrap();
    assert_eq!(stored_body(&other, &other_id).await, "other admitted");
    drop(held);
    update(&w, json!({"id":id,"body_append":" admitted"}))
        .await
        .unwrap();
    assert_eq!(stored_body(&w, &id).await, "seed admitted");
}

// W0/W1 source candidates. These use actual pooled leases/worker work; no
// authority, ACK, transaction depth or native projection fact is fabricated.
struct DispositionOwnership {
    write: kernel_writes::KernelBodyWrite,
    // Field order matters: real lane/gate ownership drops before this sentinel.
    _released: Ownership,
}
fn disposition_quarantine(owner: &mut DispositionOwnership, operation: &str) {
    owner.write.quarantine(operation);
}
async fn disposition_owner(
    db: &Db,
    released: Arc<Mutex<bool>>,
) -> crate::Result<DispositionOwnership> {
    let caller = Caller::authenticated("acct:admin");
    let write = kernel_writes::KernelBodyWrite::acquire(
        db,
        &caller,
        None,
        kernel_writes::KernelWriteMode::Metadata,
    )
    .await?;
    Ok(DispositionOwnership {
        write,
        _released: Ownership(released),
    })
}
async fn disposition_transaction(
    db: &Db,
    released: Arc<Mutex<bool>>,
) -> KernelTransaction<DispositionOwnership> {
    let work_db = db.clone();
    owned_result(db.clone(), async move {
        let owner = disposition_owner(&work_db, released).await?;
        KernelTransaction::begin(&work_db, owner, disposition_quarantine).await
    })
    .await
    .unwrap()
}
struct DispositionGateRelease(Arc<kernel_writes::TestGate>);
impl Drop for DispositionGateRelease {
    fn drop(&mut self) {
        self.0.release.notify_one();
    }
}
async fn disposition_entered(gate: &kernel_writes::TestGate) {
    tokio::time::timeout(std::time::Duration::from_secs(30), gate.entered.notified())
        .await
        .unwrap();
}
async fn disposition_retained(db: &Db) -> kernel_writes::RetainedObservation {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let mut held = kernel_writes::retained_observations_for_test(db);
            if !held.is_empty() {
                assert_eq!(held.len(), 1);
                return held.remove(0);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("actual native graph did not reach retention")
}
fn disposition_assert_unknown(db: &Db, released: &Mutex<bool>, lease: bool) {
    assert!(!*released.lock().unwrap());
    assert!(kernel_writes::quarantine_for_test(db).is_some());
    assert_eq!(kernel_writes::retained_transactions_for_test(db), 1);
    assert_eq!(kernel_writes::accepted_jobs_for_test(db), 1);
    let witness = super::live::seal_kernel_retirement(db);
    assert!(matches!(
        witness.observe(),
        super::live::KernelRetirementState::Uncertain { .. }
    ));
    let held = kernel_writes::retained_observations_for_test(db);
    assert_eq!(held[0].has_original_lease, lease);
    assert!(held[0].owns_original_job_slot);
}

#[tokio::test]
async fn disposition_no_runtime_retains_original_connection_and_native_slot() {
    let db = crate::db::kernel_settlement_tests::database().await;
    let _registration = super::live::register_kernel_lifecycle(&db);
    let released = Arc::new(Mutex::new(false));
    let observed = kernel_writes::observe_tasks_for_test(&db);
    let transaction = disposition_transaction(&db, released.clone()).await;
    let attached = observed.attached_lease();
    std::thread::spawn(move || drop(transaction))
        .join()
        .unwrap();
    let held = disposition_retained(&db).await;
    assert_eq!(
        (held.operation, held.connection_address),
        (attached.0, Some(attached.1))
    );
    disposition_assert_unknown(&db, &released, true);
    kernel_writes::dispose_settled_quarantine_for_test(&db).await;
    assert!(*released.lock().unwrap());
    assert_eq!(kernel_writes::accepted_jobs_for_test(&db), 0);
    assert!(kernel_writes::ensure_available(&db).is_err());
}

#[tokio::test]
async fn disposition_stopped_and_alive_unpolled_runtime_retain_cleanup_graph() {
    for stopped in [true, false] {
        let db = crate::db::kernel_settlement_tests::database().await;
        let _registration = super::live::register_kernel_lifecycle(&db);
        let released = Arc::new(Mutex::new(false));
        let transaction = disposition_transaction(&db, released.clone()).await;
        let (parked, entered) = oneshot::channel();
        let (finish, resume) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let handle = runtime.handle().clone();
            let mut runtime = Some(runtime);
            if stopped {
                drop(runtime.take());
            }
            {
                let _entered = handle.enter();
                drop(transaction);
            }
            parked.send(()).unwrap();
            if !stopped {
                resume.recv().unwrap();
                drop(runtime.take());
            }
        });
        entered.await.unwrap();
        assert!(!*released.lock().unwrap());
        assert_eq!(kernel_writes::accepted_jobs_for_test(&db), 1);
        if !stopped {
            assert!(kernel_writes::quarantine_for_test(&db).is_none());
            assert_eq!(kernel_writes::retained_transactions_for_test(&db), 0);
            finish.send(()).unwrap();
        }
        thread.join().unwrap();
        disposition_retained(&db).await;
        disposition_assert_unknown(&db, &released, true);
        kernel_writes::dispose_settled_quarantine_for_test(&db).await;
        assert!(*released.lock().unwrap());
    }
}

#[tokio::test]
async fn disposition_cleanup_abort_before_rollback_keeps_same_native_graph() {
    let db = crate::db::kernel_settlement_tests::database().await;
    let observed = kernel_writes::observe_tasks_for_test(&db);
    let released = Arc::new(Mutex::new(false));
    let transaction = disposition_transaction(&db, released.clone()).await;
    let attached = observed.attached_lease();
    let gate = kernel_writes::test_gate(&db, kernel_writes::TestStage::CleanupStarted, false);
    let _release = DispositionGateRelease(gate.clone());
    drop(transaction);
    disposition_entered(&gate).await;
    assert_eq!(kernel_writes::accepted_jobs_for_test(&db), 1);
    assert!(!*released.lock().unwrap());
    observed.abort_at(&gate).await;
    let held = disposition_retained(&db).await;
    assert_eq!(
        (held.operation, held.connection_address),
        (attached.0, Some(attached.1))
    );
    disposition_assert_unknown(&db, &released, true);
    kernel_writes::dispose_settled_quarantine_for_test(&db).await;
}

// Safe SQLx worker failure-injection only: no app/native event authority.
struct WorkerVmRelease {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<(Mutex<bool>, std::sync::Condvar)>,
}
impl WorkerVmRelease {
    fn release(&self) {
        *self.release.0.lock().unwrap() = true;
        self.release.1.notify_all();
    }
}
impl Drop for WorkerVmRelease {
    fn drop(&mut self) {
        self.release();
    }
}
async fn disposition_block_vm(
    transaction: &mut KernelTransaction<DispositionOwnership>,
) -> WorkerVmRelease {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let result = WorkerVmRelease {
        entered: entered.clone(),
        release: release.clone(),
    };
    let mut first = true;
    transaction
        .parts()
        .0
        .lock_handle()
        .await
        .unwrap()
        .set_progress_handler(1, move || {
            if first {
                first = false;
                entered.notify_one();
                let mut released = release.0.lock().unwrap();
                while !*released {
                    released = release.1.wait(released).unwrap();
                }
            }
            true
        });
    let mut query = Box::pin(sqlx::query_scalar::<_, i64>(
        "WITH RECURSIVE work(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM work WHERE x<1000) SELECT sum(x) FROM work"
    ).fetch_one(&mut *transaction.parts().0));
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::select! {
            _ = result.entered.notified() => {},
            value = &mut query => panic!("real worker VM did not block: {value:?}"),
        }
    })
    .await
    .unwrap();
    drop(query); // Actual SQL observer loss; original lease stays in graph.
    result
}

#[tokio::test]
async fn disposition_pending_worker_rollback_loss_keeps_connection_until_explicit_test_settlement()
{
    let db = crate::db::kernel_settlement_tests::database().await;
    let observed = kernel_writes::observe_tasks_for_test(&db);
    let released = Arc::new(Mutex::new(false));
    let mut transaction = disposition_transaction(&db, released.clone()).await;
    let attached = observed.attached_lease();
    let worker = disposition_block_vm(&mut transaction).await;
    let gate =
        kernel_writes::test_gate(&db, kernel_writes::TestStage::CleanupRollbackPending, false);
    let _release = DispositionGateRelease(gate.clone());
    drop(transaction);
    disposition_entered(&gate).await; // Actual borrowed rollback polled Pending.
    assert!(!*released.lock().unwrap());
    observed.abort_at(&gate).await;
    let held = disposition_retained(&db).await;
    assert_eq!(held.connection_address, Some(attached.1));
    disposition_assert_unknown(&db, &released, true);
    worker.release();
    // Later real depth-zero/worker progress never unquarantines automatically.
    kernel_writes::dispose_settled_quarantine_for_test(&db).await;
    assert!(*released.lock().unwrap());
    assert!(kernel_writes::ensure_available(&db).is_err());
}

#[tokio::test]
async fn disposition_normal_rollback_releases_connection_then_guards_then_final_slot() {
    let db = crate::db::kernel_settlement_tests::database().await;
    let _registration = super::live::register_kernel_lifecycle(&db);
    let released = Arc::new(Mutex::new(false));
    let mut prepared = db.write_pool().acquire().await.unwrap();
    sqlx::query("CREATE TEMP TABLE disposition_connection_marker(value INTEGER)")
        .execute(&mut *prepared)
        .await
        .unwrap();
    sqlx::query("INSERT INTO disposition_connection_marker VALUES(73)")
        .execute(&mut *prepared)
        .await
        .unwrap();
    drop(prepared);
    let mut transaction = disposition_transaction(&db, released.clone()).await;
    sqlx::query("INSERT INTO disposition_connection_marker VALUES(99)")
        .execute(&mut *transaction.parts().0)
        .await
        .unwrap();
    let gate =
        kernel_writes::test_gate(&db, kernel_writes::TestStage::CleanupBeforeDisposal, false);
    let disposed = kernel_writes::test_gate(&db, kernel_writes::TestStage::CleanupDisposed, false);
    let _disposed_release = DispositionGateRelease(disposed.clone());
    let _release = DispositionGateRelease(gate.clone());
    drop(transaction);
    disposition_entered(&gate).await; // Actual rollback ACK already completed.
    assert!(!*released.lock().unwrap());
    assert_eq!(kernel_writes::accepted_jobs_for_test(&db), 1);
    gate.release.notify_one();
    disposition_entered(&disposed).await; // Original graph's final slot has dropped.
    let mut reused = db.write_pool().acquire().await.unwrap();
    let marker: i64 = sqlx::query_scalar("SELECT value FROM disposition_connection_marker")
        .fetch_one(&mut *reused)
        .await
        .unwrap();
    assert_eq!(marker, 73); // Same physical SQLite session, not a new lease surrogate.
    assert!(*released.lock().unwrap());
    assert_eq!(kernel_writes::accepted_jobs_for_test(&db), 0);
    assert!(kernel_writes::quarantine_for_test(&db).is_none());
}

#[tokio::test]
async fn disposition_checkout_owner_loss_retains_no_lease_fence_and_wakes_prior_waiter() {
    let db = crate::db::kernel_settlement_tests::database().await;
    let held = db.write_pool().acquire().await.unwrap(); // Saturates real single-connection pool.
    let observed = kernel_writes::observe_tasks_for_test(&db);
    let gate = kernel_writes::test_gate(&db, kernel_writes::TestStage::CheckoutPending, false);
    let _release = DispositionGateRelease(gate.clone());
    let released = Arc::new(Mutex::new(false));
    let request = {
        let db = db.clone();
        let released = released.clone();
        tokio::spawn(async move {
            owned_result(db.clone(), async move {
                let owner = disposition_owner(&db, released).await?;
                KernelTransaction::begin(&db, owner, disposition_quarantine).await
            })
            .await
        })
    };
    disposition_entered(&gate).await; // Actual ordinary acquire polled Pending.
    let queued_gate = kernel_writes::test_gate(&db, kernel_writes::TestStage::LaneQueued, false);
    let _queued_release = DispositionGateRelease(queued_gate.clone());
    let queued = {
        let db = db.clone();
        tokio::spawn(async move {
            owned_result(db.clone(), async move {
                disposition_owner(&db, Arc::new(Mutex::new(false)))
                    .await
                    .map(|_| ())
            })
            .await
        })
    };
    disposition_entered(&queued_gate).await;
    observed.abort_at(&gate).await;
    assert!(request.await.unwrap().is_err());
    let retained = disposition_retained(&db).await;
    assert!(!retained.has_original_lease);
    assert_eq!(retained.phase, "CheckoutNativeUnknown");
    queued_gate.release.notify_one();
    assert!(queued.await.unwrap().is_err());
    disposition_assert_unknown(&db, &released, false);
    // No rollback/recovery helper applies to this no-lease terminal fence.
    drop(held);
}

#[tokio::test]
async fn disposition_actual_begin_ack_lost_then_cleanup_lost_retains_original_lease() {
    use sqlx::Connection;
    let w = world().await;
    let observed = kernel_writes::observe_tasks_for_test(&w.db);
    let worker = kernel_writes::pause_begin_worker_for_test(&w.db);
    let mut probe =
        sqlx::SqliteConnection::connect_with(w.db.write_pool().connect_options().as_ref())
            .await
            .unwrap();
    sqlx::query("PRAGMA busy_timeout=0")
        .execute(&mut probe)
        .await
        .unwrap();
    let gate =
        kernel_writes::test_gate(&w.db, kernel_writes::TestStage::BorrowedBeginPending, false);
    let _release = DispositionGateRelease(gate.clone());
    let cleanup = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::CleanupStarted, false);
    let _cleanup_release = DispositionGateRelease(cleanup.clone());
    let released = Arc::new(Mutex::new(false));
    let request = {
        let db = w.db.clone();
        let released = released.clone();
        tokio::spawn(async move {
            owned_result(db.clone(), async move {
                let owner = disposition_owner(&db, released).await?;
                KernelTransaction::begin(&db, owner, disposition_quarantine).await
            })
            .await
        })
    };
    worker.entered().await;
    disposition_entered(&gate).await;
    worker.release();
    // Genuine independent lock refusal proves the ORIGINAL BEGIN executed
    // while its selected future remains Pending, before result handling.
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            match sqlx::query("BEGIN IMMEDIATE")
                .execute(&mut probe)
                .await
                .map_err(crate::Error::from)
            {
                Err(error) if error.is_busy() => break,
                Err(error) => panic!("unexpected real BEGIN probe error: {error}"),
                Ok(_) => {
                    sqlx::query("ROLLBACK").execute(&mut probe).await.unwrap();
                    tokio::task::yield_now().await;
                }
            }
        }
    })
    .await
    .unwrap();
    observed.abort_at(&gate).await;
    assert!(request.await.unwrap().is_err());
    disposition_entered(&cleanup).await;
    observed.abort_at(&cleanup).await;
    let held = disposition_retained(&w.db).await;
    assert_eq!(held.connection_address, Some(observed.attached_lease().1));
    disposition_assert_unknown(&w.db, &released, true);
    kernel_writes::dispose_settled_quarantine_for_test(&w.db).await;
}

#[tokio::test]
async fn disposition_post_begin_policy_vm_loss_keeps_actual_connection_and_slot() {
    let db = crate::db::kernel_settlement_tests::database().await;
    let observed = kernel_writes::observe_tasks_for_test(&db);
    let worker = kernel_writes::pause_policy_worker_for_test(&db);
    let cleanup = kernel_writes::test_gate(&db, kernel_writes::TestStage::CleanupStarted, false);
    let _release = DispositionGateRelease(cleanup.clone());
    let released = Arc::new(Mutex::new(false));
    let request = {
        let db = db.clone();
        let released = released.clone();
        tokio::spawn(async move {
            owned_result(db.clone(), async move {
                let owner = disposition_owner(&db, released).await?;
                KernelTransaction::begin(&db, owner, disposition_quarantine).await
            })
            .await
        })
    };
    worker.entered().await; // Real policy-table VM, after acknowledged BEGIN/bookkeeping.
                            // Abort the actual operation task captured at original-lease attachment,
                            // not its result receiver or an unrelated coalesced task.
    observed.abort_operation(&observed.attached_lease().0).await;
    assert!(request.await.unwrap().is_err());
    disposition_entered(&cleanup).await;
    observed.abort_at(&cleanup).await;
    let held = disposition_retained(&db).await;
    assert_eq!(held.connection_address, Some(observed.attached_lease().1));
    disposition_assert_unknown(&db, &released, true);
    worker.release();
    kernel_writes::dispose_settled_quarantine_for_test(&db).await;
}

#[tokio::test]
async fn disposition_known_policy_refusal_returns_original_only_after_rollback() {
    use crate::storage_profile::{PortabilityEnforcement, PortabilityPolicyUpdate, StorageTarget};
    // Real ordinary schema/policy API; this tests the native BEGIN primitive,
    // not kernel-v2 portability-policy installation or actor/app admission.
    let db = crate::create_database(":memory:").await.unwrap();
    let capacity = db.write_pool().options().get_max_connections();
    assert!(capacity > 1);
    let mut held = Vec::new();
    for _ in 0..capacity - 1 {
        held.push(db.write_pool().acquire().await.unwrap());
    }
    let mut original = db.write_pool().acquire().await.unwrap();
    assert_eq!(db.write_pool().size(), capacity);
    sqlx::query("CREATE TEMP TABLE disposition_policy_marker(value INTEGER)")
        .execute(&mut *original)
        .await
        .unwrap();
    sqlx::query("INSERT INTO disposition_policy_marker VALUES(83)")
        .execute(&mut *original)
        .await
        .unwrap();
    let original_handle = original
        .lock_handle()
        .await
        .unwrap()
        .as_raw_handle()
        .as_ptr() as usize;
    // All other physical leases remain held through setup, ordinary refusal,
    // native refusal and final observation. Replacement loses this TEMP marker.
    drop(original);
    crate::storage_profile::update_portability_policy(
        &db,
        PortabilityPolicyUpdate {
            if_policy_revision: 0,
            enforcement: PortabilityEnforcement::Strict,
            target_profiles: vec![StorageTarget {
                id: "postgres-server".into(),
                revision: 5,
                mode: "network".into(),
            }],
            allow_conversions: vec![],
        },
    )
    .await
    .unwrap();
    let ordinary = crate::db::begin_write(db.write_pool())
        .await
        .err()
        .unwrap()
        .to_string();
    let released = Arc::new(Mutex::new(false));
    let work_db = db.clone();
    let done = released.clone();
    let error = owned_result(db.clone(), async move {
        // No fabricated app/actor: this is the native BEGIN/policy primitive.
        let owner = disposition_owner(&work_db, done).await?;
        KernelTransaction::begin(&work_db, owner, disposition_quarantine).await
    })
    .await
    .err()
    .unwrap();
    assert_eq!(error.to_string(), ordinary);
    assert!(ordinary.contains("strict_portability_blocked"));
    assert!(*released.lock().unwrap());
    assert_eq!(kernel_writes::accepted_jobs_for_test(&db), 0);
    assert!(kernel_writes::quarantine_for_test(&db).is_none());
    let mut connection = db.write_pool().acquire().await.unwrap();
    let marker: i64 = sqlx::query_scalar("SELECT value FROM temp.disposition_policy_marker")
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    assert_eq!(marker, 83);
    {
        let mut handle = connection.lock_handle().await.unwrap();
        assert_eq!(handle.as_raw_handle().as_ptr() as usize, original_handle);
        // SAFETY: the original pooled handle is live and exclusively locked.
        assert_ne!(
            unsafe { libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) },
            0
        );
    }
}

#[tokio::test]
async fn disposition_actual_rollback_failure_and_notification_unwind_retain_graphs() {
    // Actual SQLx/SQLite desynchronization is failure injection, NOT a native
    // business event, synthetic depth setter or fabricated worker ACK.
    let db = crate::db::kernel_settlement_tests::database().await;
    let observed = kernel_writes::observe_tasks_for_test(&db);
    let released = Arc::new(Mutex::new(false));
    let mut transaction = disposition_transaction(&db, released.clone()).await;
    sqlx::query("ROLLBACK")
        .execute(&mut *transaction.parts().0)
        .await
        .unwrap();
    let error = transaction
        .rollback(crate::Error::engine("original refusal"))
        .await;
    assert!(error.to_string().contains("uncertain"));
    let held = disposition_retained(&db).await;
    assert_eq!(held.connection_address, Some(observed.attached_lease().1));
    disposition_assert_unknown(&db, &released, true);
    // Deliberately leave this corrupted fixture quarantined. No product repair
    // or no-lease rollback is invented for test cleanup.

    fn panic_notification(_: &mut DispositionOwnership, _: &str) {
        panic!("notification unwind stimulus");
    }
    let other = crate::db::kernel_settlement_tests::database().await;
    let released = Arc::new(Mutex::new(false));
    let work_db = other.clone();
    let done = released.clone();
    let transaction = owned_result(other.clone(), async move {
        let owner = disposition_owner(&work_db, done).await?;
        KernelTransaction::begin(&work_db, owner, panic_notification).await
    })
    .await
    .unwrap();
    assert!(std::thread::spawn(move || drop(transaction))
        .join()
        .is_err());
    disposition_retained(&other).await;
    disposition_assert_unknown(&other, &released, true);
    kernel_writes::dispose_settled_quarantine_for_test(&other).await;
}

#[tokio::test]
async fn disposition_native_checkout_new_reuse_and_normal_error_keep_ordinary_pool_semantics() {
    let w = world().await;
    let initial_size = w.db.write_pool().size();
    let capacity = w.db.write_pool().options().get_max_connections();
    assert!(
        initial_size < capacity,
        "fixture must leave genuine connection capacity"
    );
    let mut held = Vec::new();
    // Collect existing physical leases without creating replacements while
    // earlier SQLx return tasks finish. Availability, not elapsed time, is proof.
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while held.len() < initial_size as usize {
            if let Some(connection) = w.db.write_pool().try_acquire() {
                held.push(connection);
            } else {
                tokio::task::yield_now().await;
            }
        }
    })
    .await
    .expect("initial physical leases must actually return before cold-create proof");
    assert_eq!(w.db.write_pool().size(), initial_size);
    // Leave exactly one physical seat. After its first cold creation, a later
    // acquire must await its asynchronous return or expose replacement via the
    // missing TEMP marker; spare capacity cannot hide the distinction.
    assert!(capacity > 1);
    for _ in initial_size..capacity - 1 {
        held.push(w.db.write_pool().acquire().await.unwrap());
    }
    assert_eq!(w.db.write_pool().size(), capacity - 1);
    assert_eq!(w.db.write_pool().num_idle(), 0);
    let mut first_handle = None;
    for pass in 0..2 {
        let work_db = w.db.clone();
        let (handle, count) = owned_result(w.db.clone(), async move {
            let (result, count) = crate::db::with_write_pool_acquisition_counter(async {
                let owner = disposition_owner(&work_db, Arc::new(Mutex::new(false))).await?;
                let mut transaction =
                    KernelTransaction::begin(&work_db, owner, disposition_quarantine).await?;
                let conn = transaction.parts().0;
                let handle = conn.lock_handle().await?.as_raw_handle().as_ptr() as usize;
                if pass == 0 {
                    // TEMP identity marker only, not a native authority fact.
                    sqlx::query("CREATE TEMP TABLE disposition_reuse_marker(value INTEGER)")
                        .execute(&mut *conn)
                        .await?;
                    sqlx::query("INSERT INTO disposition_reuse_marker VALUES(73)")
                        .execute(&mut *conn)
                        .await?;
                    drop(transaction.commit().await?);
                } else {
                    let value: i64 =
                        sqlx::query_scalar("SELECT value FROM disposition_reuse_marker")
                            .fetch_one(&mut *conn)
                            .await?;
                    assert_eq!(value, 73);
                    transaction
                        .rollback(crate::Error::engine("known reuse control rollback"))
                        .await;
                }
                Ok::<_, crate::Error>(handle)
            })
            .await;
            Ok((result?, count))
        })
        .await
        .unwrap();
        assert_eq!(count, 1); // Actual existing hook, no manual instrumentation.
        assert_eq!(w.db.write_pool().size(), capacity);
        if let Some(first) = first_handle {
            assert_eq!(handle, first);
        } else {
            first_handle = Some(handle);
        }
    }
    // All original leases stayed checked out; the new/reused session retained
    // its actual TEMP marker. Pointer equality alone is not lineage authority.
    drop(held);
    assert!(kernel_writes::quarantine_for_test(&w.db).is_none());
    w.db.write_pool().close().await;
    let released = Arc::new(Mutex::new(false));
    let work_db = w.db.clone();
    let done = released.clone();
    let error = owned_result(w.db.clone(), async move {
        let owner = disposition_owner(&work_db, done).await?;
        KernelTransaction::begin(&work_db, owner, disposition_quarantine).await
    })
    .await
    .err()
    .unwrap();
    assert!(matches!(error, crate::Error::Sqlx(sqlx::Error::PoolClosed)));
    assert!(*released.lock().unwrap());
    assert_eq!(kernel_writes::accepted_jobs_for_test(&w.db), 0);
    assert!(kernel_writes::quarantine_for_test(&w.db).is_none());
    // Normal acquire Err means no NEW constructor BEGIN, not physical drain.
}

#[tokio::test]
async fn disposition_lost_commit_ack_retains_durable_effect_and_original_prepared_owner() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = room(&w, &id).await;
    let mut events = peer.subscribe();
    let before = body_events(&w, &id).await;
    let observed = kernel_writes::observe_tasks_for_test(&w.db);
    let worker = kernel_writes::pause_commit_worker_for_test(&w.db);
    let gate = kernel_writes::test_gate(
        &w.db,
        kernel_writes::TestStage::BorrowedCommitPending,
        false,
    );
    let _release = DispositionGateRelease(gate.clone());
    let request = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { update(&w, json!({"id":id,"body_append":" committed"})).await })
    };
    worker.entered().await;
    disposition_entered(&gate).await;
    worker.release();
    // The actual durable native body is independent evidence COMMIT completed
    // while its selected driver continuation is still paused before handling.
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while stored_body(&w, &id).await != "seed committed" {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    observed.abort_at(&gate).await; // Actual native owner, not response observer.
    assert!(request.await.unwrap().is_err());
    let held = disposition_retained(&w.db).await;
    assert_eq!(held.phase, "CommitMayHaveRun");
    assert_eq!(held.connection_address, Some(observed.attached_lease().1));
    assert_eq!(stored_body(&w, &id).await, "seed committed");
    assert_eq!(body_events(&w, &id).await, before + 1);
    assert!(kernel_writes::live_text_for_test(&w.db, &id).is_none());
    kernel_writes::assert_quarantined_peer_body_for_test(&peer, "seed");
    while let Ok(event) = events.try_recv() {
        assert!(!matches!(event, super::live::SessionEvent::Versioned(_)));
    }
    assert!(peer.sync(&[]).await.is_err());
    // Do not call depth-zero rollback a product undo/recovery of this commit.
    kernel_writes::dispose_settled_quarantine_for_test(&w.db).await;
    assert_eq!(stored_body(&w, &id).await, "seed committed");
    drop(peer);
}

#[tokio::test]
async fn disposition_owner_loss_after_durability_cannot_become_rollback_only() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = room(&w, &id).await;
    let observed = kernel_writes::observe_tasks_for_test(&w.db);
    let gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterDurability, false);
    let _release = DispositionGateRelease(gate.clone());
    let request = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { update(&w, json!({"id":id,"body_append":" durable"})).await })
    };
    disposition_entered(&gate).await;
    let attached = observed.attached_lease();
    assert_eq!(stored_body(&w, &id).await, "seed durable");
    observed.abort_at(&gate).await;
    assert!(request.await.unwrap().is_err());
    let held = disposition_retained(&w.db).await;
    assert_eq!(held.phase, "CommitMayHaveRun");
    assert_eq!(
        (held.operation, held.connection_address),
        (attached.0, Some(attached.1))
    );
    assert!(kernel_writes::live_text_for_test(&w.db, &id).is_none());
    kernel_writes::assert_quarantined_peer_body_for_test(&peer, "seed");
    assert!(kernel_writes::ensure_available(&w.db).is_err());
    kernel_writes::dispose_settled_quarantine_for_test(&w.db).await;
    assert_eq!(stored_body(&w, &id).await, "seed durable");
    drop(peer);
}

#[tokio::test]
async fn disposition_later_checkout_failure_preserves_earlier_real_flush_event() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    let mut events = peer.subscribe();
    append_peer(&peer, &opened, " peer").await;
    let before = body_events(&w, &id).await;
    let gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterFlush, false);
    let _release = DispositionGateRelease(gate.clone());
    let request = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { update(&w, json!({"id":id,"body_append":" never"})).await })
    };
    disposition_entered(&gate).await;
    assert_eq!(stored_body(&w, &id).await, "seed peer");
    assert_eq!(body_events(&w, &id).await, before + 1);
    let version = loop {
        if let super::live::SessionEvent::Versioned(version) = events.recv().await.unwrap() {
            break version;
        }
    };
    assert_eq!(
        version.proof.body_event_seq,
        kernel_writes::base_for_test(&w.db, &id)
            .unwrap()
            .proof
            .body_event_seq
    );
    w.db.write_pool().close().await;
    gate.release.notify_one();
    assert!(request.await.unwrap().is_err());
    let actual: String =
        sqlx::query_scalar("SELECT body FROM main.kernel_record_bodies WHERE record_id=?")
            .bind(&id)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(actual, "seed peer");
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed peer")
    );
    // This constructor's normal acquire Err did not undo the prior saved cut.
    assert!(kernel_writes::quarantine_for_test(&w.db).is_none());
    drop(peer);
}

#[tokio::test]
async fn disposition_real_busy_begin_retries_on_same_lease_and_preserves_actual_hook_count() {
    let w = world().await;
    let blocker =
        w.db.write_pool()
            .begin_with("BEGIN IMMEDIATE")
            .await
            .unwrap();
    let observed = kernel_writes::observe_tasks_for_test(&w.db);
    let gate =
        kernel_writes::test_gate(&w.db, kernel_writes::TestStage::BorrowedBeginRefused, false);
    let _release = DispositionGateRelease(gate.clone());
    let request = {
        let db = w.db.clone();
        tokio::spawn(async move {
            owned_result(db.clone(), async move {
                let (result, acquisitions) =
                    crate::db::with_write_pool_acquisition_counter(async {
                        let owner = disposition_owner(&db, Arc::new(Mutex::new(false))).await?;
                        KernelTransaction::begin(&db, owner, disposition_quarantine).await
                    })
                    .await;
                Ok((result?, acquisitions))
            })
            .await
        })
    };
    // No sleep oracle: this checkpoint follows the ORIGINAL manager's real
    // SQLITE_BUSY acknowledgement with the independent writer still held.
    disposition_entered(&gate).await;
    assert_eq!(observed.begin_failures(), 1);
    let first = observed.attached_lease();
    blocker.rollback().await.unwrap();
    gate.release.notify_one();
    let (transaction, acquisitions) = request.await.unwrap().unwrap();
    assert_eq!(acquisitions, 1); // N actual BEGIN attempts, one checkout.
    assert_eq!(observed.attached_lease(), first);
    transaction
        .rollback(crate::Error::engine("real retry control complete"))
        .await;
    assert!(kernel_writes::quarantine_for_test(&w.db).is_none());
}

#[tokio::test]
async fn disposition_cleanup_panic_retains_original_graph_without_recursive_spawn() {
    let db = crate::db::kernel_settlement_tests::database().await;
    let observed = kernel_writes::observe_tasks_for_test(&db);
    let released = Arc::new(Mutex::new(false));
    let transaction = disposition_transaction(&db, released.clone()).await;
    let original = observed.attached_lease();
    let gate = kernel_writes::test_gate(&db, kernel_writes::TestStage::CleanupPanic, true);
    let _release = DispositionGateRelease(gate.clone());
    drop(transaction);
    disposition_entered(&gate).await;
    gate.release.notify_one();
    let held = disposition_retained(&db).await;
    assert_eq!(
        (held.operation, held.connection_address),
        (original.0, Some(original.1))
    );
    disposition_assert_unknown(&db, &released, true);
    assert_eq!(kernel_writes::retained_transactions_for_test(&db), 1);
    kernel_writes::dispose_settled_quarantine_for_test(&db).await;
}

#[tokio::test]
async fn disposition_known_commit_failure_settles_original_lease_before_native_release() {
    let db = crate::db::kernel_settlement_tests::database().await;
    let released = Arc::new(Mutex::new(false));
    let mut transaction = disposition_transaction(&db, released.clone()).await;
    let (conn, _) = transaction.parts();
    // TEMP deferred-FK failure injection only. No valid native record/event,
    // app authority or installation proof is manufactured by these rows.
    sqlx::query("CREATE TEMP TABLE disposition_parent(id INTEGER PRIMARY KEY)")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query("CREATE TEMP TABLE disposition_child(parent INTEGER REFERENCES disposition_parent(id) DEFERRABLE INITIALLY DEFERRED)").execute(&mut *conn).await.unwrap();
    sqlx::query("INSERT INTO disposition_child VALUES(7)")
        .execute(&mut *conn)
        .await
        .unwrap();
    let error = transaction.commit().await.err().unwrap();
    assert!(!error.to_string().contains("uncertain"));
    assert!(*released.lock().unwrap());
    assert_eq!(kernel_writes::accepted_jobs_for_test(&db), 0);
    assert!(kernel_writes::quarantine_for_test(&db).is_none());
    let mut reused = db.write_pool().acquire().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_schema WHERE name IN ('disposition_parent','disposition_child')").fetch_one(&mut *reused).await.unwrap();
    assert_eq!(count, 0);
}

// W2 source candidates. These are not runtime receipts. The closed production
// read role uses the unchanged loader; no fake source authority/ACK is supplied.
async fn earlier_loader_room(w: &World, id: &str) -> (SessionPeer, Opened) {
    let (peer, opened) = room(w, id).await;
    // Keep autosave out of these explicit ownership barriers. This configures
    // the genuine session timer; no elapsed interval is used as an oracle.
    peer.set_idle_after_for_test(std::time::Duration::from_secs(86_400));
    (peer, opened)
}
fn earlier_loader_start(
    w: &World,
    id: &str,
) -> tokio::task::JoinHandle<crate::Result<kernel_writes::KernelBodyWrite>> {
    let w = w.clone();
    let id = id.to_owned();
    tokio::spawn(async move {
        owned_result(w.db.clone(), async move {
            kernel_writes::KernelBodyWrite::acquire(
                &w.db,
                &w.caller,
                Some(&id),
                kernel_writes::KernelWriteMode::RouteBody,
            )
            .await
        })
        .await
    })
}
fn earlier_loader_unknown(
    db: &Db,
    expected_lease: Option<usize>,
) -> kernel_writes::EarlierLoaderObservation {
    let mut observations = kernel_writes::earlier_loader_retained_for_test(db);
    assert_eq!(observations.len(), 1);
    let observation = observations.remove(0);
    assert_eq!(observation.connection_address, expected_lease);
    assert!(observation.exact_slot_owner);
    assert!(observation.exact_room_owner);
    assert!(observation.exact_seed_handle);
    assert!(observation.original_session_matches);
    assert_eq!(observation.original_body, "seed");
    assert!(!observation.operation.is_empty());
    assert!(kernel_writes::quarantine_for_test(db).is_some());
    assert!(kernel_writes::accepted_jobs_for_test(db) >= 1);
    assert!(kernel_writes::ensure_available(db).is_err());
    observation
}

#[tokio::test]
async fn earlier_loader_read_pool_settles_before_separate_writer_checkout() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = earlier_loader_room(&w, &id).await;
    let disposed =
        kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LoaderBeforeDisposal, false);
    let _release = DispositionGateRelease(disposed.clone());
    let write = kernel_writes::test_gate(
        &w.db,
        kernel_writes::TestStage::CheckoutBeforeAcquire,
        false,
    );
    let _write_release = DispositionGateRelease(write.clone());
    let request = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { update(&w, json!({"id":id,"body_append":" successor"})).await })
    };
    disposition_entered(&disposed).await; // Real read rollback ACK + native clean.
    assert!(!request.is_finished());
    disposed.release.notify_one();
    disposition_entered(&write).await; // Reachable only after read lease disposal.
    assert_eq!(stored_body(&w, &id).await, "seed");
    assert!(kernel_writes::earlier_loader_retained_for_test(&w.db).is_empty());
    write.release.notify_one();
    request.await.unwrap().unwrap();
    assert_eq!(stored_body(&w, &id).await, "seed successor");
    peer.leave().await;
}

#[tokio::test]
async fn earlier_loader_known_view_and_edit_refusals_precede_dirty_flush() {
    for role in [None, Some("view")] {
        let w = world().await;
        let other =
            kernel::create_principal(&w.db, "account", "Loader viewer", "acct:loader", &w.admin)
                .await
                .unwrap();
        let entries = role.map(|r| vec![(other.as_str(), r)]).unwrap_or_default();
        let home = kernel::create_home(&w.db, KERNEL_ROOT_ID, Some(&entries), &w.admin)
            .await
            .unwrap();
        let id = kernel::create_json_as(
            &w.db,
            &w.admin,
            crate::v2_standard::v1_compat::FAMILY,
            "record",
            &json!({"v1_type":"Document","v1_kind":"note","title":"Read authority"}).to_string(),
            &home,
        )
        .await
        .unwrap();
        let revision = kernel::read_record_as(&w.db, &w.admin, &id)
            .await
            .unwrap()
            .unwrap()
            .revision;
        kernel::set_body_as(&w.db, &w.admin, &id, "seed", revision)
            .await
            .unwrap();
        let (peer, opened) = earlier_loader_room(&w, &id).await;
        append_peer(&peer, &opened, " retained").await;
        let before = body_events(&w, &id).await;
        let outsider = World {
            caller: Caller::authenticated("acct:loader"),
            ..w.clone()
        };
        let disposed =
            kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LoaderBeforeDisposal, false);
        let _release = DispositionGateRelease(disposed.clone());
        let request = {
            let id = id.clone();
            tokio::spawn(async move {
                update(&outsider, json!({"id":id,"body_append":" forbidden"})).await
            })
        };
        disposition_entered(&disposed).await; // Refusal is held behind actual rollback/clean check.
        assert!(!request.is_finished());
        disposed.release.notify_one();
        let error = request.await.unwrap().err().unwrap();
        assert!(error.to_string().contains("caller cannot access"));
        assert_eq!(body_events(&w, &id).await, before);
        assert_eq!(
            kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
            Some("seed retained")
        );
        assert!(kernel_writes::quarantine_for_test(&w.db).is_none());
        peer.leave().await;
    }
}

#[tokio::test]
async fn earlier_loader_keeps_full_load_and_utf8_preflight_before_flush() {
    use super::kernel_v2::{self, BodyWorkStage};
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = earlier_loader_room(&w, &id).await;
    let work = kernel_v2::observe_body(&id, false);
    let held = earlier_loader_start(&w, &id).await.unwrap().unwrap();
    assert_eq!(
        work.stages(),
        vec![
            BodyWorkStage::Encoding,
            BodyWorkStage::Size,
            BodyWorkStage::Hydrate,
            BodyWorkStage::Hash
        ]
    );
    assert_eq!(stored_body(&w, &id).await, "seed");
    drop(held);
    drop(work);
    peer.leave().await;
    // Oversized durable replacement while a valid live room exists is NOT
    // forged here. N1's genuine size tests remain controls; W2 fixture debt.
}

#[tokio::test]
async fn earlier_loader_full_load_error_settles_before_refusal() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = earlier_loader_room(&w, &id).await;
    let work = super::kernel_v2::observe_body(&id, true); // Explicit hydration failure injection.
    let disposed =
        kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LoaderBeforeDisposal, false);
    let _release = DispositionGateRelease(disposed.clone());
    let request = earlier_loader_start(&w, &id);
    disposition_entered(&disposed).await;
    assert!(!request.is_finished());
    disposed.release.notify_one();
    let error = request.await.unwrap().err().unwrap();
    assert!(error
        .to_string()
        .contains("kernel session foundation unavailable"));
    assert!(kernel_writes::earlier_loader_retained_for_test(&w.db).is_empty());
    assert!(kernel_writes::quarantine_for_test(&w.db).is_none());
    assert_eq!(kernel_writes::accepted_jobs_for_test(&w.db), 0);
    drop(work);
    peer.leave().await;
}

#[tokio::test]
async fn earlier_loader_ordinary_nonaccount_no_room_and_live_boundary_unchanged() {
    let w = world().await;
    let principal =
        kernel::create_principal(&w.db, "agent", "Loader agent", "agent:loader", &w.admin)
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
        &json!({"v1_type":"Document","v1_kind":"note","title":"Agent"}).to_string(),
        &home,
    )
    .await
    .unwrap();
    let agent = World {
        caller: Caller::authenticated("agent:loader"),
        ..w.clone()
    };
    update(&agent, json!({"id":id,"body_set":"seed"}))
        .await
        .unwrap();
    let (peer, _) = earlier_loader_room(&w, &id).await;
    let before = body_events(&w, &id).await;
    assert!(update(&agent, json!({"id":id,"body_append":" refused"}))
        .await
        .is_err());
    assert_eq!(body_events(&w, &id).await, before);
    assert!(kernel_writes::quarantine_for_test(&w.db).is_none());
    peer.leave().await;
}

#[tokio::test]
async fn earlier_loader_normal_read_pool_acquire_error_is_pool_owned() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (_peer, _) = earlier_loader_room(&w, &id).await;
    w.db.pool().close().await; // Actual pool-closed error, not a synthetic result.
    assert!(earlier_loader_start(&w, &id).await.unwrap().is_err());
    assert!(kernel_writes::earlier_loader_retained_for_test(&w.db).is_empty());
    assert!(kernel_writes::quarantine_for_test(&w.db).is_none());
    assert_eq!(kernel_writes::accepted_jobs_for_test(&w.db), 0);
}

#[tokio::test]
async fn earlier_loader_checkout_owner_loss_retains_no_lease_native_fence() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (_peer, _) = earlier_loader_room(&w, &id).await;
    let observed = kernel_writes::observe_tasks_for_test(&w.db);
    let mut held = Vec::new();
    for _ in 0..w.db.pool().options().get_max_connections() {
        held.push(w.db.pool().acquire().await.unwrap());
    }
    let pending =
        kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LoaderAcquirePending, false);
    let _release = DispositionGateRelease(pending.clone());
    let request = earlier_loader_start(&w, &id);
    disposition_entered(&pending).await; // Actual checkout future was polled Pending.
    observed.abort_at(&pending).await;
    assert!(request.await.unwrap().is_err());
    let proof = earlier_loader_unknown(&w.db, None);
    assert_eq!(proof.phase, "PoolOwnedCheckout");
    drop(held);
    kernel_writes::dispose_earlier_loader_for_test(&w.db).await;
    assert_eq!(kernel_writes::accepted_jobs_for_test(&w.db), 0);
    assert!(kernel_writes::ensure_available(&w.db).is_err()); // No unquarantine.
}

async fn earlier_loader_abort_worker(stage: kernel_writes::TestStage, expected_phase: &str) {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (_peer, _) = earlier_loader_room(&w, &id).await;
    let observed = kernel_writes::observe_tasks_for_test(&w.db);
    let worker = kernel_writes::pause_earlier_loader_worker_for_test(&w.db, stage);
    let pending = kernel_writes::test_gate(&w.db, stage, false);
    let _release = DispositionGateRelease(pending.clone());
    let request = earlier_loader_start(&w, &id);
    worker.entered().await;
    disposition_entered(&pending).await;
    let actual = observed.attached_lease();
    observed.abort_at(&pending).await;
    assert!(request.await.unwrap().is_err());
    let proof = earlier_loader_unknown(&w.db, Some(actual.1));
    assert_eq!(proof.operation, actual.0);
    assert_eq!(proof.phase, expected_phase);
    worker.release();
    kernel_writes::dispose_earlier_loader_for_test(&w.db).await;
    assert_eq!(stored_body(&w, &id).await, "seed");
}
#[tokio::test]
async fn earlier_loader_pending_deferred_begin_retains_original_lease() {
    earlier_loader_abort_worker(
        kernel_writes::TestStage::LoaderBeginPending,
        "BeginMayHaveRun",
    )
    .await;
}
#[tokio::test]
async fn earlier_loader_pending_full_load_retains_original_snapshot() {
    earlier_loader_abort_worker(kernel_writes::TestStage::LoaderLoadPending, "Loading").await;
}

#[tokio::test]
async fn earlier_loader_pending_rollback_retains_original_and_refuses_waiters() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (_peer, _) = earlier_loader_room(&w, &id).await;
    let observed = kernel_writes::observe_tasks_for_test(&w.db);
    let worker = kernel_writes::pause_earlier_loader_worker_for_test(
        &w.db,
        kernel_writes::TestStage::LoaderRollbackPending,
    );
    let pending = kernel_writes::test_gate(
        &w.db,
        kernel_writes::TestStage::LoaderRollbackPending,
        false,
    );
    let _release = DispositionGateRelease(pending.clone());
    let request = earlier_loader_start(&w, &id);
    worker.entered().await;
    disposition_entered(&pending).await;
    let queued = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LaneQueued, false);
    let _queued_release = DispositionGateRelease(queued.clone());
    let second = earlier_loader_start(&w, &id);
    disposition_entered(&queued).await; // Actual second lane lock was Pending.
    queued.release.notify_one();
    let lease = observed.attached_lease();
    observed.abort_at(&pending).await;
    assert!(request.await.unwrap().is_err());
    let proof = earlier_loader_unknown(&w.db, Some(lease.1));
    assert_eq!(proof.phase, "RollingBack");
    // First worker AND original guards remain retained; second must refuse
    // without releasing them. Timeout is a failure bound, not the ordering edge.
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(30), second)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    worker.release();
    kernel_writes::dispose_earlier_loader_for_test(&w.db).await;
}

#[tokio::test]
async fn earlier_loader_begin_and_rollback_failures_are_not_clean_refusals() {
    for fault in [
        kernel_writes::EarlierLoaderFault::NestedBeforeBegin,
        kernel_writes::EarlierLoaderFault::RollbackDesync,
    ] {
        let w = world().await;
        let id = record(&w, "Document", "note", Some("seed")).await;
        let (_peer, _) = earlier_loader_room(&w, &id).await;
        let observed = kernel_writes::observe_tasks_for_test(&w.db);
        kernel_writes::earlier_loader_fault_for_test(&w.db, fault);
        assert!(earlier_loader_start(&w, &id).await.unwrap().is_err());
        let proof = earlier_loader_unknown(&w.db, Some(observed.attached_lease().1));
        assert!(matches!(
            proof.phase.as_str(),
            "BeginMayHaveRun" | "RollingBack"
        ));
        kernel_writes::dispose_earlier_loader_for_test(&w.db).await;
    }
}

#[tokio::test]
async fn earlier_loader_native_clean_check_failure_keeps_original_graph() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (_peer, _) = earlier_loader_room(&w, &id).await;
    let observed = kernel_writes::observe_tasks_for_test(&w.db);
    kernel_writes::earlier_loader_fault_for_test(
        &w.db,
        kernel_writes::EarlierLoaderFault::DirtyAfterRollback,
    );
    assert!(earlier_loader_start(&w, &id).await.unwrap().is_err());
    assert_eq!(
        earlier_loader_unknown(&w.db, Some(observed.attached_lease().1)).phase,
        "CheckingClean"
    );
    kernel_writes::dispose_earlier_loader_for_test(&w.db).await;
}

#[tokio::test]
async fn earlier_loader_result_observer_drop_does_not_cancel_read_or_write() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = earlier_loader_room(&w, &id).await;
    let pending = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LoaderBegun, false);
    let _release = DispositionGateRelease(pending.clone());
    let write = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterDurability, false);
    let _write_release = DispositionGateRelease(write.clone());
    let response = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { update(&w, json!({"id":id,"body_append":" durable"})).await })
    };
    disposition_entered(&pending).await;
    response.abort();
    assert!(response.await.unwrap_err().is_cancelled());
    pending.release.notify_one();
    disposition_entered(&write).await;
    assert_eq!(stored_body(&w, &id).await, "seed durable");
    assert!(kernel_writes::quarantine_for_test(&w.db).is_none());
    write.release.notify_one();
    // Join the writer lane deterministically; don't infer install from body SQL.
    let held = earlier_loader_start(&w, &id).await.unwrap().unwrap();
    drop(held);
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed durable")
    );
    peer.leave().await;
}

#[tokio::test]
async fn earlier_loader_original_owner_retained_before_watch_and_changed() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (_peer, _) = earlier_loader_room(&w, &id).await;
    let observed = kernel_writes::observe_tasks_for_test(&w.db);
    let gate =
        kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LoaderLeaseAttached, false);
    let _release = DispositionGateRelease(gate.clone());
    let request = earlier_loader_start(&w, &id);
    disposition_entered(&gate).await;
    let lease = observed.attached_lease();
    observed.abort_at(&gate).await;
    assert!(request.await.unwrap().is_err());
    let proof = earlier_loader_unknown(&w.db, Some(lease.1));
    assert_eq!(proof.operation, lease.0);
    assert!(!proof.session.0.is_empty());
    let seal = super::live::seal_kernel_retirement(&w.db);
    assert!(matches!(
        seal.observe(),
        super::live::KernelRetirementState::Uncertain { .. }
    ));
    kernel_writes::dispose_earlier_loader_for_test(&w.db).await;
    // No map replacement or generation is asserted by this original-graph proof.
}

#[tokio::test]
async fn earlier_loader_prepoll_no_runtime_and_notification_unwind_are_bounded() {
    for mode in [
        kernel_writes::EarlierLoaderDropMode::Absent,
        kernel_writes::EarlierLoaderDropMode::Stopped,
        kernel_writes::EarlierLoaderDropMode::AliveUnpolled,
    ] {
        let w = world().await;
        let id = record(&w, "Document", "note", Some("seed")).await;
        let (_peer, _) = earlier_loader_room(&w, &id).await;
        kernel_writes::earlier_loader_drop_mode_for_test(&w.db, mode);
        assert!(earlier_loader_start(&w, &id).await.unwrap().is_err());
        assert_eq!(
            earlier_loader_unknown(&w.db, None).phase,
            "PoolOwnedCheckout"
        );
        kernel_writes::dispose_earlier_loader_for_test(&w.db).await;
        assert_eq!(kernel_writes::accepted_jobs_for_test(&w.db), 0);
    }
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (_peer, _) = earlier_loader_room(&w, &id).await;
    let observed = kernel_writes::observe_tasks_for_test(&w.db);
    let gate =
        kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LoaderLeaseAttached, false);
    let _release = DispositionGateRelease(gate.clone());
    let _panic = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LoaderNotifyPanic, true);
    let request = earlier_loader_start(&w, &id);
    disposition_entered(&gate).await;
    observed.abort_at(&gate).await;
    assert!(request.await.unwrap().is_err());
    earlier_loader_unknown(&w.db, Some(observed.attached_lease().1));
    kernel_writes::dispose_earlier_loader_for_test(&w.db).await;
}

#[tokio::test]
async fn earlier_loader_same_slot_capacity_and_final_drop_order() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = earlier_loader_room(&w, &id).await;
    let observed = kernel_writes::observe_tasks_for_test(&w.db);
    let held = earlier_loader_start(&w, &id).await.unwrap().unwrap();
    assert!(observed.earlier_loader_same_task_slot());
    assert_eq!(kernel_writes::accepted_jobs_for_test(&w.db), 1);
    drop(held);
    assert_eq!(kernel_writes::accepted_jobs_for_test(&w.db), 0);
    // This direct private call has NO task-local slot: one explicit fallback.
    let held = kernel_writes::KernelBodyWrite::acquire(
        &w.db,
        &w.caller,
        Some(&id),
        kernel_writes::KernelWriteMode::RouteBody,
    )
    .await
    .unwrap();
    assert!(!observed.earlier_loader_same_task_slot());
    assert_eq!(kernel_writes::accepted_jobs_for_test(&w.db), 1);
    drop(held);
    assert_eq!(kernel_writes::accepted_jobs_for_test(&w.db), 0);
    let slots = kernel_writes::hold_job_slots_for_test(&w.db, 8);
    assert!(kernel_writes::KernelBodyWrite::acquire(
        &w.db,
        &w.caller,
        Some(&id),
        kernel_writes::KernelWriteMode::RouteBody
    )
    .await
    .is_err());
    assert_eq!(kernel_writes::accepted_jobs_for_test(&w.db), 8);
    assert!(kernel_writes::earlier_loader_retained_for_test(&w.db).is_empty());
    assert!(kernel_writes::quarantine_for_test(&w.db).is_none());
    drop(slots);
    // Guards from capacity refusal must be released; this actual acquisition
    // and read/rollback succeeds, without relying on a timeout or slot reset.
    let held = earlier_loader_start(&w, &id).await.unwrap().unwrap();
    drop(held);
    assert_eq!(kernel_writes::accepted_jobs_for_test(&w.db), 0);
    peer.leave().await;
}

// M1 routing positives use the real ToolRegistry/native Update dispatcher.
async fn m1_app_writer() -> (
    Arc<crate::v1_import::NativePeerTwoAdoptedAppsFixture>,
    World,
    String,
) {
    let fixture = crate::v1_import::native_peer_two_adopted_apps_fixture_for_test().await;
    let f = &fixture.owner;
    let w = World {
        db: f.db.clone(),
        admin: f.administrator.clone(),
        caller: f.adopted_caller.clone(),
    };
    let home = kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.principal, "edit"), (&fixture.second_principal, "edit")]),
        &f.administrator,
    )
    .await
    .unwrap();
    let id = kernel::create_json_as(
        &f.db,
        &f.administrator,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":"Document","v1_kind":"note","title":"Routed actual app"}).to_string(),
        &home,
    )
    .await
    .unwrap();
    let revision = kernel::read_record_as(&f.db, &f.administrator, &id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_body_as(&f.db, &f.administrator, &id, "seed", revision)
        .await
        .unwrap();
    (fixture, w, id)
}
#[tokio::test]
async fn routed_app_binding_uses_original_pending_digest_target_and_act_once() {
    let (fixture, w, id) = m1_app_writer().await;
    let registration =
        kernel_writes::register_writer_fixture_owner_for_test(&w.db, Arc::clone(&fixture.owner));
    let (peer, _) = room(&w, &id).await;
    update(
        &w,
        json!({"id":id,"body_append":" routed","name":"metadata first"}),
    )
    .await
    .unwrap();
    assert_eq!(stored_body(&w, &id).await, "seed routed");
    let (body_id,act,actor):(String,i64,String)=sqlx::query_as(
        "SELECT id,act,actor FROM content_events WHERE record_id=? AND type='kernel.body_set.v1' ORDER BY seq DESC LIMIT 1")
        .bind(&id).fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(actor, fixture.owner.principal);
    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT type,id,payload FROM content_events WHERE act=? ORDER BY seq")
            .bind(act)
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert_eq!(
        rows.iter()
            .filter(|(t, _, _)| t == "kernel.app_action_started.v1")
            .count(),
        1
    );
    assert_eq!(
        rows.iter()
            .filter(|(t, _, _)| t == "kernel.app_action_recorded.v1")
            .count(),
        1
    );
    let body = rows
        .iter()
        .position(|(_, event, _)| event == &body_id)
        .unwrap();
    let start = rows
        .iter()
        .position(|(t, _, _)| t == "kernel.app_action_started.v1")
        .unwrap();
    let tail = rows
        .iter()
        .position(|(t, _, _)| t == "kernel.app_action_recorded.v1")
        .unwrap();
    assert!(start < body && body < tail);
    let declared: Value = serde_json::from_str(&rows[start].2).unwrap();
    assert_eq!(declared["operation"], "update_record");
    assert_eq!(declared["generation"], fixture.owner.adopted_generation);
    let recorded: Value = serde_json::from_str(&rows[tail].2).unwrap();
    assert!(recorded["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["event_id"] == body_id));
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed routed")
    );
    // A body-only declared basis must be identical at permit minting and
    // append, while staying out of the public body/coedit history envelope.
    let result = update(
        &w,
        json!({"id":id,"body_append":" with basis","sources":[id]}),
    )
    .await
    .unwrap();
    assert_eq!(result["basis"]["status"], "declared");
    let raw: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id=? AND type='kernel.body_set.v1' ORDER BY seq DESC LIMIT 1")
        .bind(&id).fetch_one(w.db.pool()).await.unwrap();
    let payload: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(payload["basis"]["sources"][0]["record_id"], id);
    assert_eq!(stored_body(&w, &id).await, "seed routed with basis");
    let history = kernel::body_history_as(&w.db, &w.admin, &id).await.unwrap();
    let exposed = history
        .iter()
        .filter_map(|entry| entry.event.native_body_version.as_ref())
        .collect::<Vec<_>>();
    assert!(!exposed.is_empty());
    assert!(exposed.iter().all(|payload| payload.get("basis").is_none()));
    drop(peer);
    drop(registration);
    w.db.close().await;
    drop(fixture);
}
#[tokio::test]
async fn routed_nonapp_requires_all_three_absences_and_original_unallocated_memo() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = room(&w, &id).await;
    update(
        &w,
        json!({"id":id,"name":"allocates before body","body_append":" nonapp"}),
    )
    .await
    .unwrap();
    assert_eq!(stored_body(&w, &id).await, "seed nonapp");
    let act:i64=sqlx::query_scalar("SELECT act FROM content_events WHERE record_id=? AND type='kernel.body_set.v1' ORDER BY seq DESC LIMIT 1")
        .bind(&id).fetch_one(w.db.pool()).await.unwrap();
    let kinds: Vec<String> =
        sqlx::query_scalar("SELECT type FROM content_events WHERE act=? ORDER BY seq")
            .bind(act)
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert!(kinds.len() >= 2);
    assert!(kinds.iter().any(|k| k == "kernel.body_set.v1"));
    assert!(!kinds.iter().any(|k| k.starts_with("kernel.app_action_")));
    drop(peer);
}
#[tokio::test]
async fn routed_wrong_actual_start_transaction_actor_target_or_act_refuses() {
    let (fixture, w, id) = m1_app_writer().await;
    let registration =
        kernel_writes::register_writer_fixture_owner_for_test(&w.db, Arc::clone(&fixture.owner));
    let (peer, _) = room(&w, &id).await;
    let caller = w.caller.clone();
    let actor = fixture.owner.principal.clone();
    let other_actor = fixture.second_principal.clone();
    let args = json!({"id":id,"body_append":"not committed"});
    let dispatch =
        crate::provenance::ProvenanceDispatch::from_caller(&caller, "update_record", &args, None);
    let db = w.db.clone();
    let owner_keepalive = Arc::clone(&fixture.owner);
    let target = id.clone();
    dispatch
        .scope(owned_result(db.clone(), async move {
            let owner = kernel_writes::KernelBodyWrite::acquire_fixture_owned_update_for_test(
                &db,
                &caller,
                Some(&id),
                kernel_writes::KernelWriteMode::RouteBody,
                Some(owner_keepalive.clone()),
            )
            .await?;
            let mut transaction =
                KernelTransaction::begin(&db, owner, kernel_writes::KernelBodyWrite::quarantine)
                    .await?;
            let mut acts = crate::act::ActAllocation::new();
            let digest = crate::provenance::digest_json(&args);
            let pending = {
                let (tx, _) = transaction.parts();
                kernel::app_installs::start_app_action_in(
                    &db,
                    tx,
                    &actor,
                    "update_record",
                    digest.clone(),
                    None,
                    &mut acts,
                )
                .await?
                .unwrap()
            };
            {
                let (tx, _) = transaction.parts();
                assert!(kernel::app_installs::bind_update_action_on(
                    tx,
                    Some(&pending),
                    &caller,
                    &other_actor,
                    &args,
                    &digest,
                    &acts
                )
                .await
                .is_err());
                assert!(kernel::app_installs::bind_update_action_on(
                    tx,
                    Some(&pending),
                    &caller,
                    &actor,
                    &args,
                    &"0".repeat(64),
                    &acts
                )
                .await
                .is_err());
                let binding = kernel::app_installs::bind_update_action_on(
                    tx,
                    Some(&pending),
                    &caller,
                    &actor,
                    &args,
                    &digest,
                    &acts,
                )
                .await?;
                assert!(binding
                    .require_update_scope(&caller, &actor, "another target", &acts)
                    .is_err());
                assert!(binding
                    .require_update_scope(&caller, &actor, &id, &crate::act::ActAllocation::new())
                    .is_err());
                assert!(kernel::app_installs::bind_update_action_on(
                    tx, None, &caller, &actor, &args, &digest, &acts
                )
                .await
                .is_err());
                drop(binding);
            }
            // An ACTUAL rolled-back start cannot be reused in a later real TX.
            let _ = transaction
                .rollback(crate::Error::engine("intentional fixture rollback"))
                .await;
            let owner = kernel_writes::KernelBodyWrite::acquire_fixture_owned_update_for_test(
                &db,
                &caller,
                Some(&id),
                kernel_writes::KernelWriteMode::RouteBody,
                Some(owner_keepalive),
            )
            .await?;
            let mut transaction =
                KernelTransaction::begin(&db, owner, kernel_writes::KernelBodyWrite::quarantine)
                    .await?;
            assert!(kernel::app_installs::bind_update_action_on(
                transaction.parts().0,
                Some(&pending),
                &caller,
                &actor,
                &args,
                &digest,
                &acts
            )
            .await
            .is_err());
            let _ = transaction
                .rollback(crate::Error::engine("intentional fixture rollback"))
                .await;
            Ok(())
        }))
        .await
        .unwrap();
    assert_eq!(stored_body(&w, &target).await, "seed");
    drop(peer);
    w.db.close().await;
    drop(registration);
    drop(fixture);
}
#[tokio::test]
async fn routed_missing_binding_cannot_fall_back_to_ordinary_body_event() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = room(&w, &id).await;
    let (db, caller, target) = (w.db.clone(), w.caller.clone(), id.clone());
    owned_result(db.clone(), async move {
        let owner = kernel_writes::KernelBodyWrite::acquire(
            &db,
            &caller,
            Some(&target),
            kernel_writes::KernelWriteMode::RouteBody,
        )
        .await?;
        let mut transaction =
            KernelTransaction::begin(&db, owner, kernel_writes::KernelBodyWrite::quarantine)
                .await?;
        let mut acts = crate::act::ActAllocation::new();
        let error = {
            let (tx, owner) = transaction.parts();
            owner
                .append_dispatched_body_in(
                    tx,
                    &target,
                    "denied",
                    None,
                    "missing binding",
                    &mut acts,
                    None,
                )
                .await
                .unwrap_err()
        };
        let _ = transaction.rollback(error).await;
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(stored_body(&w, &id).await, "seed");
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed")
    );
    drop(peer);
}
#[tokio::test]
async fn known_preflush_survives_outer_failure_without_new_association() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " accepted").await;
    let mut events = peer.subscribe();
    let before = kernel::body_history_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .len();
    assert!(update(
        &w,
        json!({"id":id,"body_append":" refused","if_body_digest":"0".repeat(64)})
    )
    .await
    .is_err());
    assert_eq!(stored_body(&w, &id).await, "seed accepted");
    assert_eq!(
        kernel::body_history_as(&w.db, &w.admin, &id)
            .await
            .unwrap()
            .len(),
        before + 1
    );
    assert!(matches!(
        events.try_recv().unwrap(),
        super::live::SessionEvent::Versioned(_)
    ));
    drop(peer);
}

#[tokio::test]
async fn routed_actual_earlier_read_owner_loss_retains_fixture_directory() {
    let (fixture, w, id) = m1_app_writer().await;
    let weak = Arc::downgrade(&fixture.owner);
    let registration =
        kernel_writes::register_writer_fixture_owner_for_test(&w.db, Arc::clone(&fixture.owner));
    let (peer, _) = room(&w, &id).await;
    let observed = kernel_writes::observe_tasks_for_test(&w.db);
    let worker = kernel_writes::pause_earlier_loader_worker_for_test(
        &w.db,
        kernel_writes::TestStage::LoaderBeginPending,
    );
    let pending =
        kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LoaderBeginPending, false);
    let _release = DispositionGateRelease(pending.clone());
    let request = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(
            async move { update(&w, json!({"id":id,"body_append":" must not arrive"})).await },
        )
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), worker.entered())
        .await
        .unwrap();
    disposition_entered(&pending).await;
    let actual = observed.attached_lease();
    drop(registration);
    drop(fixture);
    observed.abort_at(&pending).await;
    assert!(request.await.unwrap().is_err());
    assert!(weak.upgrade().is_some());
    let proof = earlier_loader_unknown(&w.db, Some(actual.1));
    assert_eq!(proof.operation, actual.0);
    assert_eq!(proof.phase, "BeginMayHaveRun");
    let teardown = weak.upgrade().unwrap();
    worker.release();
    kernel_writes::dispose_earlier_loader_for_test(&w.db).await;
    assert_eq!(kernel_writes::accepted_jobs_for_test(&w.db), 0);
    assert_eq!(stored_body(&w, &id).await, "seed");
    drop(peer);
    w.db.close().await;
    drop(teardown);
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn public_publication_reads_only_committed_body_while_coedit_has_dirty_text() {
    use kernel::publications::{self, PublicRead, PublicationAction, PublicationRequest};
    let w = world().await;
    let id = record(&w, "Document", "note", Some("committed seed")).await;
    let revision = kernel::read_record_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    let publication = publications::change_as(
        &w.db,
        &w.admin,
        PublicationRequest {
            record_id: id.clone(),
            action: PublicationAction::Publish,
            expected_revision: revision,
            expected_publication_version: None,
            operation_key: "coedit-publication".into(),
        },
    )
    .await
    .unwrap();
    let before = publications::read_public(&w.db, &publication.state.public_id)
        .await
        .unwrap();
    let (peer, opened) = room(&w, &id).await;
    peer.set_idle_after_for_test(std::time::Duration::from_secs(3600));
    peer.set_version_interval_for_test(std::time::Duration::ZERO);
    append_peer(&peer, &opened, " unsaved peer draft").await;
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("committed seed unsaved peer draft")
    );
    assert_eq!(stored_body(&w, &id).await, "committed seed");
    // Public reads never enter current-body/coedit observation and never flush
    // the peer's accepted but unversioned text as a read side effect.
    assert_eq!(
        publications::read_public(&w.db, &publication.state.public_id)
            .await
            .unwrap(),
        before
    );
    assert_eq!(stored_body(&w, &id).await, "committed seed");
    peer.version("Commit the peer draft")
        .await
        .unwrap()
        .unwrap();
    let after = publications::read_public(&w.db, &publication.state.public_id)
        .await
        .unwrap();
    match (&before, &after) {
        (PublicRead::Available(before), PublicRead::Available(after)) => {
            assert_eq!(before.body, "committed seed");
            assert_eq!(after.body, "committed seed unsaved peer draft");
            assert_ne!(before.version, after.version);
        }
        other => panic!("{other:?}"),
    }
    peer.leave().await;
}

#[tokio::test]
async fn batch_bodies_refuse_live_and_grace_without_flushing_or_partial_writes() {
    let w = world().await;
    let inactive = record(&w, "WorkItem", "task", Some("inactive")).await;
    let live = record(&w, "Document", "note", Some("seed")).await;
    let original = json!({"reason":"prior batch","idempotency_key":"batch-before-room","items":[{"op":"update","id":live,"body_append":" saved"}]});
    let receipt = call(&w, "batch_write", original.clone()).await.unwrap();
    let (peer, opened) = room(&w, &live).await;
    append_peer(&peer, &opened, " dirty").await;
    let events = body_events(&w, &live).await;
    // An existing receipt stays replayable even after a coedit room takes over.
    assert_eq!(call(&w, "batch_write", original).await.unwrap(), receipt);
    let args = json!({"reason":"atomic body cohort","sources":[inactive],"items":[
        {"op":"update","id":inactive,"body_append":" lost"},
        {"op":"update","id":live,"body_append":" clobber"}
    ]});
    let error = call(&w, "batch_write", args.clone()).await.unwrap_err();
    assert!(error.to_string().contains("items[1]"), "{error}");
    assert_eq!(stored_body(&w, &inactive).await, "inactive");
    assert_eq!(stored_body(&w, &live).await, "seed saved");
    assert_eq!(body_events(&w, &live).await, events);
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &live).as_deref(),
        Some("seed saved dirty")
    );
    peer.leave().await;
    let events = body_events(&w, &live).await;
    assert!(call(&w, "batch_write", args).await.is_err());
    assert_eq!(body_events(&w, &live).await, events);
    assert_eq!(stored_body(&w, &inactive).await, "inactive");
}

#[tokio::test]
async fn batch_body_owner_survives_response_loss_and_fences_first_room_seed() {
    let w = world().await;
    let a = record(&w, "Document", "note", Some("seed")).await;
    let b = record(&w, "WorkItem", "task", Some("other")).await;
    let args = json!({"reason":"body cohort","idempotency_key":"lost-batch-response","items":[
        {"op":"update","id":a,"body_append":" saved"},
        {"op":"update","id":b,"body_append":" saved"}
    ]});
    let write_gate =
        kernel_writes::test_gate(&w.db, kernel_writes::TestStage::BeginAcknowledged, false);
    let response = {
        let w = w.clone();
        let args = args.clone();
        tokio::spawn(async move { call(&w, "batch_write", args).await })
    };
    write_gate.entered.notified().await;
    response.abort();
    assert!(response.await.unwrap_err().is_cancelled());
    let seed_gate =
        kernel_writes::test_gate(&w.db, kernel_writes::TestStage::SeedBeforeLane, false);
    let opener = {
        let w = w.clone();
        let a = a.clone();
        tokio::spawn(async move { room(&w, &a).await })
    };
    seed_gate.entered.notified().await;
    seed_gate.release.notify_one();
    write_gate.release.notify_one();
    let (peer, _) = opener.await.unwrap();
    assert_eq!(stored_body(&w, &a).await, "seed saved");
    assert_eq!(stored_body(&w, &b).await, "other saved");
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &a).as_deref(),
        Some("seed saved")
    );
    let before = body_events(&w, &a).await + body_events(&w, &b).await;
    let receipt = call(&w, "batch_write", args).await.unwrap();
    assert_eq!(receipt["changed"], 2);
    assert_eq!(
        body_events(&w, &a).await + body_events(&w, &b).await,
        before
    );
    peer.leave().await;
}
