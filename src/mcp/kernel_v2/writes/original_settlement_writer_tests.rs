//! Defensive adapter tests for namespaces deliberately not admitted by the
//! phase-1 producer. Append a sentinel future-operation fact using a canonical
//! fence as its fixture template; this is NOT an assertion of settlement admission or
//! historical coverage. Full valid-fact coverage/rebuild tests live in kernel.
use super::*;
use crate::kernel::{
    original_settlement as settlement,
    original_settlement::tests::{call_tool, route, update, world, World},
};

async fn sentinel(
    w: &World,
    id: &str,
    operation: &str,
    key: &str,
) -> (sqlx::Transaction<'static, sqlx::Sqlite>, String) {
    let request = update(w, id, "sentinel-source");
    let answer = settlement::settle(&w.db, &route(w), request).await.unwrap();
    assert_eq!(answer["verdict"], "unapplied_terminal", "{answer}");
    let event = answer["fence"]["native"]["canonical_event_id"]
        .as_str()
        .unwrap();
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let raw: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE id=?")
        .bind(event)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let mut fact: Value = serde_json::from_str(&raw).unwrap();
    fact["operation"] = json!(operation);
    fact["operation_key"] = json!(key);
    let sentinel_event = uuid::Uuid::new_v4().to_string();
    // Keep append-only protections installed. Unsupported-operation sentinel
    // construction intentionally bypasses admission, never canonical UPDATE.
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,run_key,parent_key,intent,causal_envelope_version,causal_status,created_at,act) SELECT ?,record_id,type,?,actor,run_key,parent_key,intent,causal_envelope_version,causal_status,created_at,act FROM content_events WHERE id=?")
        .bind(&sentinel_event).bind(fact.to_string()).bind(event).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO content_event_causal_frontier(event_id,parent_event_id) SELECT ?,parent_event_id FROM content_event_causal_frontier WHERE event_id=?")
        .bind(&sentinel_event).bind(event).execute(&mut *tx).await.unwrap();
    (tx, answer["fence"]["fence_id"].as_str().unwrap().to_owned())
}
async fn base(w: &World) -> String {
    // Batch's current adapter accepts v4/v7 targets, while the retained
    // first-party create helper mints v8. Use a real kernel-owned v4 record.
    crate::kernel::create_json_as(
        &w.db,
        &w.principal,
        crate::v2_standard::DOCUMENT_FAMILY,
        "note",
        r#"{"title":"Adapter original"}"#,
        &w.home,
    )
    .await
    .unwrap()
}
fn assert_terminal(error: Error, fence: &str) {
    let Error::OriginalConflict(c) = error else {
        panic!("typed terminal required: {error:?}")
    };
    assert_eq!(c.fence_id, fence);
    assert!(!c.native_fence.canonical_event_id.is_empty());
    assert_eq!(c.namespace_sha256.len(), 64);
    assert_eq!(c.fenced_original_binding_sha256.len(), 64);
}
#[tokio::test]
async fn original_settlement_merge_batch_and_suggestions_wait_then_refuse_exact_and_changed_retries(
) {
    for (tool, operation) in [
        ("merge_body", "merge_body"),
        ("batch_write", "batch_write"),
        ("resolve_suggestions", "resolve_suggestions"),
    ] {
        let w = std::sync::Arc::new(world().await);
        let id = base(&w).await;
        let args = match tool {
            "merge_body" => {
                json!({"record_id":id,"base_version":"unverified-base","base_text":"before","my_text":"after","reason":"Keep the edit on a fenced retry","idempotency_key":"adapter-key"})
            }
            "batch_write" => {
                json!({"items":[{"op":"archive","id":id}],"reason":"Keep the edit on a fenced retry","idempotency_key":"adapter-key"})
            }
            _ => {
                json!({"suggestion_ids":[id],"action":"reject","reason":"Keep the edit on a fenced retry","idempotency_key":"adapter-key"})
            }
        };
        let (tx, fence) = sentinel(&w, &id, operation, "adapter-key").await;
        let wc = w.clone();
        let first_args = args.clone();
        let first = tokio::spawn(async move { call_tool(&wc, tool, first_args).await });
        // The real adapter cannot decide while the fence writer owns IMMEDIATE.
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(!first.is_finished(), "{tool} escaped the serialized writer");
        tx.commit().await.unwrap();
        assert_terminal(first.await.unwrap().unwrap_err(), &fence);
        let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        for changed in [false, true] {
            let mut retry = args.clone();
            if changed {
                retry["reason"] = json!("Changed fingerprint is still fenced");
            }
            assert_terminal(call_tool(&w, tool, retry).await.unwrap_err(), &fence);
        }
        assert_eq!(
            before,
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                .fetch_one(w.db.pool())
                .await
                .unwrap()
        );
    }
}
// #3540 keeps the batch namespace but adds body authoring and shared sources
// behind a different transaction owner. Fence both that owner and every shape.
#[tokio::test]
async fn original_settlement_guarded_body_batches_refuse_before_sources_guards_or_effects() {
    for mode in [
        "body_set",
        "body_append",
        "body_replace",
        "body_clear",
        "body_noop",
        "guard_only",
        "mixed",
        "shared_sources",
    ] {
        let w = std::sync::Arc::new(world().await);
        let id = base(&w).await;
        let other = base(&w).await;
        for record in [&id, &other] {
            call_tool(
                &w,
                "update_record",
                json!({"id":record,"body_append":"before","reason":"body batch fence fixture"}),
            )
            .await
            .unwrap();
        }
        let digest = crate::mcp::tools::lifecycle::body_digest(Some("before"));
        let mut item = json!({"op":"update","id":id,"if_body_digest":digest});
        match mode {
            "body_append" | "shared_sources" => item["body_append"] = json!(" after"),
            "body_replace" => {
                item["body_replace"] = json!([{"old":"before","new":"after","expected_count":1}])
            }
            "body_clear" => item["body_set"] = Value::Null,
            "body_noop" => item["body_set"] = json!("before"),
            "guard_only" => (),
            _ => item["body_set"] = json!("after"),
        }
        let mut args = json!({"items":[item],"reason":"Do not revive settled body batches","idempotency_key":"guarded-batch-key"});
        if mode == "mixed" {
            args["items"]
                .as_array_mut()
                .unwrap()
                .push(json!({"op":"update","id":other,"name":"Must not be renamed"}));
        }
        if mode == "shared_sources" {
            args["sources"] = json!([id]);
            args["items"].as_array_mut().unwrap().push(json!({"op":"update","id":other,"body_set":"from the original basis","if_body_digest":digest}));
        }
        let (tx, fence) = sentinel(&w, &id, "batch_write", "guarded-batch-key").await;
        let wc = w.clone();
        let first_args = args.clone();
        let first = tokio::spawn(async move { call_tool(&wc, "batch_write", first_args).await });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(!first.is_finished(), "{mode} escaped the IMMEDIATE writer");
        tx.commit().await.unwrap();
        assert_terminal(first.await.unwrap().unwrap_err(), &fence);
        let before = crate::kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        let events: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        for changed in [false, true] {
            let mut retry = args.clone();
            if changed {
                retry["reason"] = json!("Changed intent remains fenced");
                // A late record_on backstop would return a stale-guard error.
                // The early namespace refusal must win before evaluating it.
                retry["items"][0]["if_body_digest"] = json!("stale-body-guard");
                if mode == "shared_sources" {
                    retry["sources"] = json!([uuid::Uuid::new_v4().to_string()]);
                }
            }
            assert_terminal(
                call_tool(&w, "batch_write", retry).await.unwrap_err(),
                &fence,
            );
        }
        assert_eq!(
            crate::kernel::dump_all_kernel_tables(&w.db).await.unwrap(),
            before,
            "{mode} changed projections or bodies"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                .fetch_one(w.db.pool())
                .await
                .unwrap(),
            events,
            "{mode} appended effects or attribution"
        );
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM kernel_mcp_write_receipts WHERE operation='batch_write' AND operation_key='guarded-batch-key'").fetch_one(w.db.pool()).await.unwrap(),0,"no synthetic success receipt");
    }
}

#[tokio::test]
async fn original_settlement_url_post_fetch_waits_then_refuses_exact_and_changed_retries() {
    let w = world().await;
    let id = base(&w).await;
    let args =
        json!({"record_id":id,"url":"https://example.test/original","idempotency_key":"url-key"});
    let (tx, fence) = sentinel(&w, &id, "attach_from_url", "url-key").await;
    let db = w.db.clone();
    let actor = w.principal.clone();
    let first_args = args.clone();
    let first = tokio::spawn(async move {
        url_attachment::commit(&db, &actor, &first_args, "retained-fingerprint", fetched()).await
    });
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    assert!(!first.is_finished());
    tx.commit().await.unwrap();
    assert_terminal(first.await.unwrap().unwrap_err(), &fence);
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    for changed in [false, true] {
        let mut retry = args.clone();
        if changed {
            retry["url"] = json!("https://example.test/changed");
        }
        assert_terminal(
            url_attachment::commit(&w.db, &w.principal, &retry, "fingerprint", fetched())
                .await
                .unwrap_err(),
            &fence,
        );
    }
    assert_eq!(
        before,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap()
    );
}
fn fetched() -> url_attachment::FetchedUrl {
    url_attachment::FetchedUrl {
        bytes: b"download completed before settlement".to_vec(),
        mime: "text/plain".into(),
        filename: Some("original.txt".into()),
        name: "Original".into(),
        final_url: "https://example.test/original".into(),
        redirects: 0,
    }
}
#[tokio::test]
async fn original_settlement_image_waits_then_refuses_exact_and_changed_retries() {
    use crate::record_images::{ImageInsertMetadata, RecordImageError};
    let w = std::sync::Arc::new(world().await);
    let id = base(&w).await;
    let key = uuid::Uuid::new_v4().to_string();
    let metadata:ImageInsertMetadata=serde_json::from_value(json!({"version":"native.record-image-insert.v1","idempotency_key":key,"if_body_digest":"0".repeat(64),"splice":{"start":0,"end":0},"placement":{"alt":"Original image","size":"medium","alignment":"center"}})).unwrap();
    let mut image = std::io::Cursor::new(Vec::new());
    image::DynamicImage::new_rgb8(1, 1)
        .write_to(&mut image, image::ImageFormat::Png)
        .unwrap();
    let bytes = image.into_inner();
    let (tx, fence) = sentinel(&w, &id, "insert_record_image", &key).await;
    let wc = w.clone();
    let first_metadata = metadata.clone();
    let first_bytes = bytes.clone();
    let first_id = id.clone();
    let first = tokio::spawn(async move {
        super::super::record_images::insert(
            &wc.db,
            &Caller::authenticated("acct:owner"),
            &first_id,
            first_metadata,
            String::new(),
            first_bytes,
            "image/png",
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    assert!(!first.is_finished());
    tx.commit().await.unwrap();
    let RecordImageError::Internal(error) = first.await.unwrap().unwrap_err() else {
        panic!("image must preserve structured terminal")
    };
    assert_terminal(error, &fence);
    for changed in [false, true] {
        let mut retry = metadata.clone();
        if changed {
            retry.placement.alt = "Changed fingerprint".into();
        }
        let RecordImageError::Internal(error) = super::super::record_images::insert(
            &w.db,
            &Caller::authenticated("acct:owner"),
            &id,
            retry,
            String::new(),
            bytes.clone(),
            "image/png",
        )
        .await
        .unwrap_err() else {
            panic!("image must preserve structured terminal")
        };
        assert_terminal(error, &fence);
    }
}

#[tokio::test]
async fn original_settlement_named_view_preflight_refuses_exact_and_changed_retries() {
    let w = world().await;
    let id = base(&w).await;
    let (tx, fence) = sentinel(&w, &id, "manage_named_views.unpublish_view", "view-key").await;
    tx.commit().await.unwrap();
    for changed in [false, true] {
        let args = json!({"action":"unpublish_view","id":id,"expected_binding_event_id":null,"idempotency_key":"view-key","reason":if changed {"Changed fingerprint"} else {"Original fingerprint"}});
        let result = crate::named_views::gate::testing(
            true,
            named_views::prepare_commit(
                &w.db,
                &w.principal,
                &Caller::authenticated("acct:owner"),
                &args,
            ),
        )
        .await;
        assert_terminal(result.err().expect("typed refusal"), &fence);
    }
}

#[tokio::test]
async fn original_settlement_create_many_item_waits_then_refuses_exact_and_changed_retries() {
    let w = world().await;
    let id = base(&w).await;
    let key = "many-key";
    let item_key = create_many::item_command_identity_for_settlement_test(key, 0);
    let (tx, fence) = sentinel(&w, &id, "create_many", &item_key).await;
    let db = w.db.clone();
    let actor = w.principal.clone();
    let home = w.home.clone();
    let first = tokio::spawn(async move {
        create_many::item_for_settlement_test(
            &db,
            &actor,
            json!({"type":"Document","kind":"note","name":"Original","home_id":home}),
            key,
            "fingerprint",
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    assert!(!first.is_finished());
    tx.commit().await.unwrap();
    assert_terminal(first.await.unwrap().unwrap_err(), &fence);
    for fingerprint in ["fingerprint", "changed-fingerprint"] {
        assert_terminal(
            create_many::item_for_settlement_test(
                &w.db,
                &w.principal,
                json!({"type":"Document","name":"Changed"}),
                key,
                fingerprint,
            )
            .await
            .unwrap_err(),
            &fence,
        );
    }
}

#[tokio::test]
async fn original_settlement_url_conflict_fallback_waits_then_refuses_exact_and_changed_retries() {
    let w = world().await;
    let id = base(&w).await;
    let (tx, fence) = sentinel(&w, &id, "attach_from_url", "fallback-key").await;
    let db = w.db.clone();
    let actor = w.principal.clone();
    let first = tokio::spawn(async move {
        url_attachment::replay_after_conflict(
            &db,
            &actor,
            "fallback-key",
            "original",
            Error::conflict("receipt race"),
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    assert!(!first.is_finished());
    tx.commit().await.unwrap();
    assert_terminal(first.await.unwrap().unwrap_err(), &fence);
    for fingerprint in ["original", "changed"] {
        assert_terminal(
            url_attachment::replay_after_conflict(
                &w.db,
                &w.principal,
                "fallback-key",
                fingerprint,
                Error::conflict("receipt race"),
            )
            .await
            .unwrap_err(),
            &fence,
        );
    }
}
#[tokio::test]
async fn original_settlement_named_view_commit_waits_then_refuses_exact_and_changed_retries() {
    let w = world().await;
    let id = base(&w).await;
    let args = json!({"action":"unpublish_view","id":id,"expected_binding_event_id":null,"idempotency_key":"commit-key","reason":"Original view edit"});
    let (tx, fence) = sentinel(&w, &id, "manage_named_views.unpublish_view", "commit-key").await;
    let db = w.db.clone();
    let actor = w.principal.clone();
    let first_args = args.clone();
    let first = tokio::spawn(async move {
        let prepared =
            named_views::fence_commit_for_settlement_test(&db, &actor, &first_args).unwrap();
        let caller = Caller::authenticated("acct:owner");
        crate::named_views::gate::testing(
            true,
            named_views::with_prevalidated(
                prepared,
                named_views::execute(&db, &actor, &caller, first_args),
            ),
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    assert!(!first.is_finished());
    tx.commit().await.unwrap();
    assert_terminal(first.await.unwrap().unwrap_err(), &fence);
    for changed in [false, true] {
        let mut retry = args.clone();
        if changed {
            retry["reason"] = json!("Changed view edit");
        }
        let prepared =
            named_views::fence_commit_for_settlement_test(&w.db, &w.principal, &retry).unwrap();
        let caller = Caller::authenticated("acct:owner");
        assert_terminal(
            crate::named_views::gate::testing(
                true,
                named_views::with_prevalidated(
                    prepared,
                    named_views::execute(&w.db, &w.principal, &caller, retry),
                ),
            )
            .await
            .unwrap_err(),
            &fence,
        );
    }
}
