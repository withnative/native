use super::*;

async fn basis_events(w: &World, id: &str, after: i64) -> Vec<(String, String, Value)> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id,type,payload FROM content_events WHERE record_id=? AND seq>? AND json_type(payload,'$.basis') IS NOT NULL ORDER BY seq",
    ).bind(id).bind(after).fetch_all(w.db.pool()).await.unwrap();
    rows.into_iter()
        .map(|(id, kind, raw)| (id, kind, serde_json::from_str(&raw).unwrap()))
        .collect()
}

#[tokio::test]
async fn update_sources_follow_first_authoring_event_and_replay_projections() {
    let w = world().await;
    let source = admin(&w, "create_record", json!({"type":"Document","kind":"note","home_id":w.home,"name":"Basis","body":"source body","reason":"fixture"})).await;
    // Fresh WorkItem/task records use the structured revision family.
    for (patch, expected) in [
        (json!({"name":"Renamed"}), "kernel.record_revised.v2"),
        (json!({"maturity":"working"}), "kernel.metadata_set.v1"),
        (json!({"body_append":" changed"}), "kernel.body_set.v1"),
        (
            json!({"facets":{"a":"one","b":"two"}}),
            "kernel.facet_observed.v1",
        ),
        (
            json!({"name":"Renamed","body_append":" changed","facets":{"a":"one"}}),
            "kernel.record_revised.v2",
        ),
    ] {
        let target = admin(&w, "create_record", json!({"type":"WorkItem","kind":"task","home_id":w.home,"name":"Original","body":"body","reason":"fixture"})).await;
        let id = target["id"].as_str().unwrap();
        let before = count(&w).await;
        let mut args = json!({"id":id,"sources":[{"record_id":source["id"],"reason":"consulted the basis","role":"context"}],"reason":"source-aware edit"});
        args.as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        let result = admin(&w, "update_record", args).await;
        assert_eq!(result["basis"]["status"], "declared");
        let events = basis_events(&w, id, before).await;
        assert_eq!(events.len(), 1, "{patch}");
        assert_eq!(events[0].1, expected);
        assert_eq!(
            events[0].2["basis"]["sources"][0]["record_id"],
            source["id"]
        );
        assert_eq!(
            events[0].2["basis"]["sources"][0]["revision_supplied_by"],
            "engine"
        );
        assert!(!record(&w, id).await.fields.contains_key("basis"));
        let context = admin(&w, "get_event_context", json!({"event_id":events[0].0})).await;
        assert_eq!(context["basis"]["status"], "declared");
        assert_eq!(context["basis"]["sources"][0]["record_id"], source["id"]);
    }
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(kernel::dump_all_kernel_tables(&w.db).await.unwrap(), before);
    w.db.close().await;
}

#[tokio::test]
async fn update_sources_empty_omitted_and_no_authoring_event_are_honest() {
    let w = world().await;
    let target = admin(&w, "create_record", json!({"type":"Document","kind":"note","home_id":w.home,"name":"Original","reason":"fixture"})).await;
    let id = target["id"].as_str().unwrap();
    let before = count(&w).await;
    let empty = admin(
        &w,
        "update_record",
        json!({"id":id,"body_append":"one","sources":[],"reason":"none consulted"}),
    )
    .await;
    assert_eq!(empty["basis"]["status"], "declared_none");
    let events = basis_events(&w, id, before).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].2["basis"]["sources"], json!([]));
    let before = count(&w).await;
    let omitted = admin(
        &w,
        "update_record",
        json!({"id":id,"body_append":"two","reason":"undeclared"}),
    )
    .await;
    assert!(omitted.get("basis").is_none());
    assert!(basis_events(&w, id, before).await.is_empty());
    let before = count(&w).await;
    let noop = admin(
        &w,
        "update_record",
        json!({"id":id,"name":"Original","sources":[id],"reason":"unchanged"}),
    )
    .await;
    assert_eq!(noop["effect"], "unchanged");
    assert_eq!(noop["basis"]["status"], "not_recorded");
    assert_eq!(noop["basis"]["source_count"], 0);
    assert_eq!(count(&w).await, before);
    let other = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","home_id":w.home,"reason":"fixture"}),
    )
    .await;
    let before = count(&w).await;
    let linked = admin(&w, "update_record", json!({"id":id,"links":[{"relationship":"derived_from","target_id":other["id"]}],"sources":[id],"reason":"link only"})).await;
    assert_eq!(linked["basis"]["status"], "not_recorded");
    assert!(basis_events(&w, id, before).await.is_empty());
    w.db.close().await;
}

#[tokio::test]
async fn update_sources_invalid_shape_revision_and_guard_refuse_atomically() {
    let w = world().await;
    let target = admin(&w, "create_record", json!({"type":"Document","kind":"note","home_id":w.home,"name":"Original","body":"original body","reason":"fixture"})).await;
    let source = admin(&w, "create_record", json!({"type":"Document","kind":"note","home_id":w.home,"name":"Source","reason":"fixture"})).await;
    let id = target["id"].as_str().unwrap();
    let source_id = source["id"].as_str().unwrap();
    for sources in [
        Value::Null,
        json!(false),
        json!({}),
        json!([""]),
        json!([source_id, source_id]),
        json!([{"record_id":source_id,"reason":""}]),
        json!([{"record_id":source_id,"reason":"read","role":""}]),
        json!([{"record_id":source_id,"reason":"read","revision_event_id":""}]),
        json!([{"record_id":source_id,"reason":"read","revision_event_id":target["write_receipt"]["event"]["event_id"]}]),
        json!(["missing-source"]),
        json!(vec![
            source_id;
            crate::authoring::MAX_SAVE_ACCOUNT_SOURCES + 1
        ]),
    ] {
        let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        assert!(call(&w, "acct:admin", "update_record", json!({"id":id,"name":"must not change","body_append":"lost","sources":sources,"reason":"invalid sources"})).await.is_err(), "{sources}");
        assert_eq!(
            kernel::dump_all_kernel_tables(&w.db).await.unwrap(),
            before,
            "{sources}"
        );
    }
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert!(call(&w, "acct:admin", "update_record", json!({"id":id,"body_set":"lost","if_body_digest":"bad","sources":[source_id],"reason":"stale guard"})).await.is_err());
    assert_eq!(kernel::dump_all_kernel_tables(&w.db).await.unwrap(), before);
    w.db.close().await;
}

#[tokio::test]
async fn update_sources_replay_keeps_original_basis_and_fresh_write_rechecks_view() {
    let w = world().await;
    for home in [&w.home, &w.private] {
        kernel::replace_home_policy(
            &w.db,
            &w.admin,
            home,
            &[(&w.admin, "manage"), (&w.viewer, "edit")],
        )
        .await
        .unwrap();
    }
    let target = admin(&w, "create_record", json!({"type":"Document","kind":"note","home_id":w.home,"body":"before","reason":"fixture"})).await;
    let source = admin(&w, "create_record", json!({"type":"Document","kind":"note","home_id":w.private,"body":"private evidence","reason":"fixture"})).await;
    let id = target["id"].as_str().unwrap();
    let before = count(&w).await;
    let args = json!({"id":id,"body_append":" after","sources":[{"record_id":source["id"],"reason":"private-source-reason"}],"idempotency_key":"source-update","reason":"fixture"});
    let first = call(&w, "acct:viewer", "update_record", args.clone())
        .await
        .unwrap();
    let events = basis_events(&w, id, before).await;
    assert_eq!(events.len(), 1);
    kernel::replace_home_policy(&w.db, &w.admin, &w.private, &[(&w.admin, "manage")])
        .await
        .unwrap();
    let before = count(&w).await;
    assert_eq!(
        call(&w, "acct:viewer", "update_record", args.clone())
            .await
            .unwrap(),
        first
    );
    assert_eq!(count(&w).await, before);
    let mut fresh = args;
    fresh["idempotency_key"] = json!("fresh-source-update");
    let snapshot = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert!(call(&w, "acct:viewer", "update_record", fresh)
        .await
        .is_err());
    assert_eq!(
        kernel::dump_all_kernel_tables(&w.db).await.unwrap(),
        snapshot
    );
    let context = call(
        &w,
        "acct:viewer",
        "get_event_context",
        json!({"event_id":events[0].0}),
    )
    .await
    .unwrap();
    assert_eq!(context["basis"]["completeness"], "partial");
    assert_eq!(context["basis"]["sources"], json!([]));
    assert!(!context.to_string().contains("private-source-reason"));
    w.db.close().await;
}

#[tokio::test]
async fn update_sources_structured_revision_keeps_explicit_historical_basis() {
    let w = world().await;
    let source = admin(&w, "create_record", json!({"type":"Document","kind":"note","home_id":w.home,"body":"source before","reason":"fixture"})).await;
    let source_id = source["id"].as_str().unwrap();
    let revision: String = sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? AND type IN ('kernel.record_created.v1','kernel.record_created.v2','kernel.body_set.v1') ORDER BY seq DESC LIMIT 1")
        .bind(source_id).fetch_one(w.db.pool()).await.unwrap();
    admin(
        &w,
        "update_record",
        json!({"id":source_id,"body_append":" newer","reason":"advance source"}),
    )
    .await;
    let target = admin(&w, "create_record", json!({"type":"Document","kind":"note","home_id":w.home,"name":"Before","reason":"fixture"})).await;
    let id = target["id"].as_str().unwrap();
    let before = count(&w).await;
    admin(&w, "update_record", json!({"id":id,"name":"After","sources":[{"record_id":source_id,"reason":"consulted the earlier text","revision_event_id":revision}],"reason":"structured edit"})).await;
    let events = basis_events(&w, id, before).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].1, "kernel.record_revised.v2");
    assert_eq!(
        events[0].2["basis"]["sources"][0]["revision_event_id"],
        revision
    );
    assert_eq!(
        events[0].2["basis"]["sources"][0]["revision_supplied_by"],
        "caller"
    );
    let context = admin(&w, "get_event_context", json!({"event_id":events[0].0})).await;
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        admin(&w, "get_event_context", json!({"event_id":events[0].0})).await,
        context
    );
    assert_eq!(record(&w, id).await.fields["title"], "After");
    w.db.close().await;
}

#[tokio::test]
async fn update_sources_skips_unchanged_first_facet_and_reports_all_unchanged() {
    let w = world().await;
    let target = admin(&w, "create_record", json!({"type":"WorkItem","kind":"task","home_id":w.home,"facets":{"a":"same"},"reason":"fixture"})).await;
    let id = target["id"].as_str().unwrap();
    let args =
        json!({"id":id,"facets":{"a":"same","b":"new"},"sources":[id],"reason":"facet edit"});
    let before = count(&w).await;
    let result = admin(&w, "update_record", args.clone()).await;
    assert_eq!(result["basis"]["status"], "declared");
    let events = basis_events(&w, id, before).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].2["key"], "b");
    let before = count(&w).await;
    let unchanged = admin(&w, "update_record", args).await;
    assert_eq!(unchanged["effect"], "unchanged");
    assert_eq!(unchanged["basis"]["status"], "not_recorded");
    assert_eq!(count(&w).await, before);
    w.db.close().await;
}

#[tokio::test]
async fn batch_sources_share_prewrite_revisions_and_report_unretained_items() {
    let w = world().await;
    let source = admin(&w, "create_record", json!({"type":"Document","kind":"note","home_id":w.home,"name":"Evidence","body":"before","reason":"fixture"})).await;
    let target = admin(&w, "create_record", json!({"type":"Document","kind":"note","home_id":w.home,"name":"Target","reason":"fixture"})).await;
    let noop = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","home_id":w.home,"name":"Same","reason":"fixture"}),
    )
    .await;
    let guarded = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","home_id":w.home,"reason":"fixture"}),
    )
    .await;
    let archived = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","home_id":w.home,"reason":"fixture"}),
    )
    .await;
    let linked = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","home_id":w.home,"reason":"fixture"}),
    )
    .await;
    let before = count(&w).await;
    let args = json!({"reason":"shared evidence","sources":[source["id"]],"idempotency_key":"shared-basis","items":[
        {"op":"update","id":source["id"],"name":"Revised evidence"},
        {"op":"update","id":target["id"],"facets":{"priority":"high"}},
        {"op":"update","id":noop["id"],"name":"Same"},
        {"op":"update","id":guarded["id"],"if_maturity":null},
        {"op":"archive","id":archived["id"]},
        {"op":"add_link","source_id":linked["id"],"target_id":target["id"],"relationship":"relates_to"}
    ]});
    let receipt = admin(&w, "batch_write", args.clone()).await;
    for index in 0..2 {
        assert_eq!(receipt["results"][index]["basis"]["status"], "declared");
        let id = if index == 0 {
            &source["id"]
        } else {
            &target["id"]
        };
        let events = basis_events(&w, id.as_str().unwrap(), before).await;
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].2["basis"]["sources"][0]["revision_event_id"],
            source["write_receipt"]["event"]["event_id"]
        );
    }
    for index in 2..6 {
        assert_eq!(receipt["results"][index]["basis"]["status"], "not_recorded");
    }
    let head = count(&w).await;
    assert_eq!(admin(&w, "batch_write", args).await, receipt);
    assert_eq!(count(&w).await, head);
    let empty = admin(&w, "batch_write", json!({"reason":"none consulted","sources":[],"items":[{"op":"update","id":target["id"],"name":"Empty declaration"}]})).await;
    assert_eq!(empty["results"][0]["basis"]["status"], "declared_none");
    let omitted = admin(&w, "batch_write", json!({"reason":"undeclared","items":[{"op":"update","id":target["id"],"name":"Omitted declaration"}]})).await;
    assert!(omitted["results"][0].get("basis").is_none());
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(kernel::dump_all_kernel_tables(&w.db).await.unwrap(), before);
    w.db.close().await;
}

#[tokio::test]
async fn batch_sources_validate_before_writes_and_late_refusal_rolls_back_basis() {
    let w = world().await;
    let source = admin(&w, "create_record", json!({"type":"Document","kind":"note","home_id":w.home,"body":"source","reason":"fixture"})).await;
    let target = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","home_id":w.home,"reason":"fixture"}),
    )
    .await;
    for sources in [
        Value::Null,
        json!(["missing"]),
        json!([source["id"], source["id"]]),
        json!([{"record_id":source["id"],"reason":"stale","revision_event_id":target["write_receipt"]["event"]["event_id"]}]),
    ] {
        let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        assert!(call(&w, "acct:admin", "batch_write", json!({"reason":"invalid basis","sources":sources,"items":[{"op":"update","id":target["id"],"name":"Must roll back"}]})).await.is_err());
        assert_eq!(kernel::dump_all_kernel_tables(&w.db).await.unwrap(), before);
    }
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert!(call(&w, "acct:admin", "batch_write", json!({"reason":"late guard","sources":[source["id"]],"idempotency_key":"rolled-back-basis","items":[
        {"op":"update","id":target["id"],"name":"Must roll back"},
        {"op":"update","id":source["id"],"name":"Refuse","if_body_digest":"stale"}
    ]})).await.is_err());
    assert_eq!(kernel::dump_all_kernel_tables(&w.db).await.unwrap(), before);
    w.db.close().await;
}

#[tokio::test]
async fn batch_sources_recheck_view_for_fresh_writes_but_retry_keeps_historical_receipt() {
    let w = world().await;
    for home in [&w.home, &w.private] {
        kernel::replace_home_policy(
            &w.db,
            &w.admin,
            home,
            &[(&w.admin, "manage"), (&w.viewer, "edit")],
        )
        .await
        .unwrap();
    }
    let source = admin(&w,"create_record",json!({"type":"Document","kind":"note","home_id":w.private,"body":"evidence","reason":"fixture"})).await;
    let target = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","home_id":w.home,"reason":"fixture"}),
    )
    .await;
    let args = json!({"reason":"shared evidence","sources":[source["id"]],"idempotency_key":"source-view","items":[{"op":"update","id":target["id"],"name":"After"}]});
    let first = call(&w, "acct:viewer", "batch_write", args.clone())
        .await
        .unwrap();
    kernel::replace_home_policy(&w.db, &w.admin, &w.private, &[(&w.admin, "manage")])
        .await
        .unwrap();
    let before = count(&w).await;
    assert_eq!(
        call(&w, "acct:viewer", "batch_write", args.clone())
            .await
            .unwrap(),
        first
    );
    assert_eq!(count(&w).await, before);
    // Receipt contains only the basis status/count, not source identities or reasons.
    assert!(!first.to_string().contains(source["id"].as_str().unwrap()));
    let mut fresh = args;
    fresh["idempotency_key"] = json!("fresh-source-view");
    assert!(call(&w, "acct:viewer", "batch_write", fresh).await.is_err());
    assert_eq!(count(&w).await, before);
    w.db.close().await;
}
