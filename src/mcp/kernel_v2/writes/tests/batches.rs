use super::*;

async fn note(w: &World, name: &str) -> String {
    admin(w, "create_record", json!({"type":"Document","kind":"note","name":name,"home_id":w.home,"reason":"batch fixture"})).await["id"].as_str().unwrap().into()
}

#[tokio::test]
async fn batch_fields_facets_links_archive_and_stable_retry() {
    let w = world().await;
    let a = note(&w, "Original").await;
    let b = note(&w, "Link source").await;
    let c = note(&w, "Target").await;
    let d = note(&w, "Archive").await;
    let args = json!({"reason":"organize related records","idempotency_key":"mixed-batch","items":[
        {"op":"update","id":a,"name":"Renamed","summary":"Summary","maturity":"working","facets":{"priority":"high","score":3},"if_maturity":null,"if_facets":{"priority":null},"if_home_id":w.home},
        {"op":"add_link","source_id":b,"target_id":c,"relationship":"relates_to","note":"shared context"},
        {"op":"archive","id":d}
    ]});
    let receipt = admin(&w, "batch_write", args.clone()).await;
    assert_eq!(receipt["changed"], 3);
    assert_eq!(receipt["results"][1]["target_id"], c);
    let current = record(&w, &a).await;
    assert_eq!(current.fields["title"], "Renamed");
    assert_eq!(current.fields["summary"], "Summary");
    assert!(record(&w, &d).await.archived);
    let priority: String =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='priority'")
            .bind(&a)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(priority, "high");
    let links = admin(&w, "manage_links", json!({"action":"list","record_id":b})).await;
    assert!(!links["links"].as_array().unwrap().is_empty());
    let cleared = admin(
        &w,
        "batch_write",
        json!({"reason":"clear optional values","items":[
            {"op":"update","id":a,"summary":null,"maturity":null,"facets":{"priority":null},
             "if_facets":{"priority":"high","score":3},"if_maturity":"working"}
        ]}),
    )
    .await;
    assert_eq!(cleared["changed"], 1);
    assert!(record(&w, &a)
        .await
        .fields
        .get("summary")
        .is_none_or(Value::is_null));
    admin(
        &w,
        "update_record",
        json!({"id":a,"name":"Later change","reason":"invalidate old guards"}),
    )
    .await;
    let before = count(&w).await;
    assert_eq!(admin(&w, "batch_write", args.clone()).await, receipt);
    assert_eq!(count(&w).await, before);
    let mut changed = args;
    changed["items"][0]["name"] = json!("Different intent");
    assert!(call(&w, "acct:admin", "batch_write", changed)
        .await
        .is_err());
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(kernel::dump_all_kernel_tables(&w.db).await.unwrap(), before);
    w.db.close().await;
}

#[tokio::test]
async fn batch_late_guard_rolls_back_move_fields_facets_and_relationship_then_key_can_retry() {
    let w = world().await;
    let a = note(&w, "Moving").await;
    let b = note(&w, "Source").await;
    let c = note(&w, "Target").await;
    let d = note(&w, "Guard").await;
    let mut args = json!({"reason":"atomic mixed work","idempotency_key":"late-refusal","items":[
        {"op":"update","id":a,"home_id":w.private,"name":"Moved","facets":{"priority":"high"}},
        {"op":"add_link","source_id":b,"target_id":c,"relationship":"relates_to"},
        {"op":"update","id":d,"summary":"New summary","if_maturity":"stale"}
    ]});
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let error = call(&w, "acct:admin", "batch_write", args.clone())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Conflict(_)), "{error}");
    assert!(error.to_string().contains("items[2]"), "{error}");
    assert_eq!(kernel::dump_all_kernel_tables(&w.db).await.unwrap(), before);
    args["items"][2]["if_maturity"] = Value::Null;
    let receipt = admin(&w, "batch_write", args.clone()).await;
    assert_eq!(receipt["changed"], 3);
    assert_eq!(record(&w, &a).await.home_id, w.private);
    let before = count(&w).await;
    assert_eq!(admin(&w, "batch_write", args).await, receipt);
    assert_eq!(count(&w).await, before);
    w.db.close().await;
}

#[tokio::test]
async fn batch_generic_link_noops_and_guard_only_updates_do_not_append() {
    let w = world().await;
    let a = note(&w, "Same").await;
    let b = note(&w, "Source").await;
    let c = note(&w, "Target").await;
    let args = json!({"reason":"generic link","items":[
        {"op":"update","id":a,"name":"Same","if_facets":{"absent":null}},
        {"op":"add_link","source_id":b,"target_id":c,"relationship":"derived_from","note":"basis"}
    ]});
    let first = admin(&w, "batch_write", args.clone()).await;
    assert_eq!(first["changed"], 1);
    assert!(first["results"][1]["link"]["id"].is_string());
    let before = count(&w).await;
    assert_eq!(admin(&w, "batch_write", args).await["changed"], 0);
    assert_eq!(count(&w).await, before);
    let guarded = json!({"reason":"assert unchanged","items":[{"op":"update","id":a,"if_maturity":null,"if_body_digest":crate::mcp::tools::lifecycle::body_digest(None)}]});
    assert_eq!(admin(&w, "batch_write", guarded).await["changed"], 0);
    assert_eq!(count(&w).await, before);
    w.db.close().await;
}

#[tokio::test]
async fn batch_link_target_visibility_is_required_for_write_and_receipt_replay() {
    let w = world().await;
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.home,
        &[(&w.admin, "manage"), (&w.viewer, "edit")],
    )
    .await
    .unwrap();
    let a = note(&w, "Source").await;
    let b = note(&w, "Target").await;
    let args = json!({"reason":"link visible records","idempotency_key":"viewer-link","items":[{"op":"add_link","source_id":a,"target_id":b,"relationship":"relates_to"}]});
    let receipt = call(&w, "acct:viewer", "batch_write", args.clone())
        .await
        .unwrap();
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.home,
        &[(&w.admin, "manage"), (&w.viewer, "view")],
    )
    .await
    .unwrap();
    assert_eq!(
        call(&w, "acct:viewer", "batch_write", args.clone())
            .await
            .unwrap(),
        receipt
    );
    admin(
        &w,
        "update_record",
        json!({"id":b,"home_id":w.private,"reason":"private target"}),
    )
    .await;
    let before = count(&w).await;
    assert!(call(&w, "acct:viewer", "batch_write", args.clone())
        .await
        .is_err());
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.home,
        &[(&w.admin, "manage"), (&w.viewer, "edit")],
    )
    .await
    .unwrap();
    let mut fresh = args;
    fresh["idempotency_key"] = json!("new-hidden-link");
    let before_fresh = count(&w).await;
    assert!(call(&w, "acct:viewer", "batch_write", fresh).await.is_err());
    assert_eq!(count(&w).await, before_fresh);
    assert!(before_fresh >= before);
    w.db.close().await;
}

#[tokio::test]
async fn batch_bodies_keep_guards_compact_receipts_and_atomic_retry() {
    let w = world().await;
    let a = note(&w, "Append").await;
    let b = note(&w, "Replace").await;
    let c = note(&w, "Set").await;
    for id in [&a, &b, &c] {
        admin(
            &w,
            "update_record",
            json!({"id":id,"body_append":"old reference","reason":"fixture"}),
        )
        .await;
    }
    let digest = crate::mcp::tools::lifecycle::body_digest(Some("old reference"));
    let mut args = json!({"reason":"fix known bodies","sources":[a],"idempotency_key":"body-batch","items":[
        {"op":"update","id":a,"body_append":" plus","if_body_digest":digest},
        {"op":"update","id":b,"body_replace":[{"old":"old","new":"new","expected_count":1}],"if_body_digest":digest},
        {"op":"update","id":c,"body_set":"replacement"}
    ]});
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert!(call(&w, "acct:admin", "batch_write", args.clone())
        .await
        .unwrap_err()
        .to_string()
        .contains("items[2]"));
    assert_eq!(kernel::dump_all_kernel_tables(&w.db).await.unwrap(), before);
    args["items"][2]["if_body_digest"] = json!(digest);
    let head = count(&w).await;
    let receipt = admin(&w, "batch_write", args.clone()).await;
    let text = crate::mcp::render::render("batch_write", &receipt).unwrap();
    assert_eq!(receipt["changed"], 3);
    for (index, (id, body)) in [
        (&a, "old reference plus"),
        (&b, "new reference"),
        (&c, "replacement"),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(record(&w, id).await.body.as_deref(), Some(body));
        assert_eq!(
            receipt["results"][index]["body_digest"],
            crate::mcp::tools::lifecycle::body_digest(Some(body))
        );
        assert!(receipt["results"][index]["version"]
            .as_str()
            .unwrap()
            .starts_with("rec:"));
        let result = &receipt["results"][index];
        assert!(
            text.lines().any(|line| [
                id.as_str(),
                result["version"].as_str().unwrap(),
                result["body_digest"].as_str().unwrap()
            ]
            .iter()
            .all(|token| line.split_whitespace().any(|part| part == *token))),
            "batch item must carry its own guard tokens:\n{text}"
        );
        assert!(receipt["results"][index].get("body").is_none());
        assert_eq!(receipt["results"][index]["basis"]["status"], "declared");
        let basis: String = sqlx::query_scalar("SELECT json_extract(payload,'$.basis.sources[0].revision_event_id') FROM content_events WHERE record_id=? AND seq>? AND type='kernel.body_set.v1' ORDER BY seq LIMIT 1").bind(id).bind(head).fetch_one(w.db.pool()).await.unwrap();
        let expected: String = sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? AND seq<=? AND type='kernel.body_set.v1' ORDER BY seq DESC LIMIT 1").bind(&a).bind(head).fetch_one(w.db.pool()).await.unwrap();
        assert_eq!(basis, expected);
    }
    let head = count(&w).await;
    assert_eq!(admin(&w, "batch_write", args.clone()).await, receipt);
    assert_eq!(count(&w).await, head);
    let mut changed = args;
    changed["items"][0]["body_append"] = json!("different");
    assert!(call(&w, "acct:admin", "batch_write", changed)
        .await
        .is_err());
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(kernel::dump_all_kernel_tables(&w.db).await.unwrap(), before);
    w.db.close().await;
}

#[tokio::test]
async fn batch_body_noops_null_clear_and_invalid_combinations() {
    let w = world().await;
    let a = note(&w, "Body").await;
    let b = note(&w, "Other").await;
    admin(
        &w,
        "update_record",
        json!({"id":a,"body_append":"known","reason":"fixture"}),
    )
    .await;
    let digest = crate::mcp::tools::lifecycle::body_digest(Some("known"));
    for item in [
        json!({"op":"update","id":a,"body_set":"first","body_append":"second"}),
        json!({"op":"update","id":a,"body_replace":[{"old":"missing","new":"new"}]}),
        json!({"op":"update","id":a,"body_set":null,"if_body_digest":"stale"}),
        json!({"op":"update","id":a,"body":"deprecated"}),
    ] {
        let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        assert!(call(&w,"acct:admin","batch_write",json!({"reason":"invalid","items":[{"op":"update","id":b,"name":"Must roll back"},item]})).await.is_err());
        assert_eq!(kernel::dump_all_kernel_tables(&w.db).await.unwrap(), before);
    }
    let head = count(&w).await;
    let noop = admin(&w,"batch_write",json!({"reason":"same body","sources":[],"items":[{"op":"update","id":a,"body_set":"known","if_body_digest":digest}]})).await;
    assert_eq!(noop["changed"], 0);
    assert_eq!(noop["results"][0]["body_digest"], digest);
    assert_eq!(noop["results"][0]["basis"]["status"], "not_recorded");
    assert_eq!(count(&w).await, head);
    let cleared = admin(&w,"batch_write",json!({"reason":"clear body","items":[{"op":"update","id":a,"body_set":null,"if_body_digest":digest}]})).await;
    assert_eq!(cleared["changed"], 1);
    assert_eq!(record(&w, &a).await.body.as_deref(), Some(""));
    w.db.close().await;
}
