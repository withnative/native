// Record ids must be canonical v4/v7 UUIDs, so every comment fixture id here is
// a pinned `c0aa0000-0000-4000-8000-<counter>` literal. Counters follow the
// ascending order of the slugs they replaced, so thread orderings keyed on the
// id are unchanged.

use native_ce::citations::{capture_target_in, AnnotationTargetInput, SelectorInput, SourceSlot};
use native_ce::conformance::rebuild_and_diff;
use native_ce::events::EventRow;
use native_ce::generated::kinds::CoreKind;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::meta::kind::KindMetadataV1;
use native_ce::meta::{
    alias_value, promote_value, propose_value_with_kind_metadata_as, VocabularyValueTerminality,
};
use native_ce::projector::replay_with_blob_seeds;
use native_ce::query::events::log_prefix;
use native_ce::query::read::{get_record_with, EnrichOptions};
use native_ce::store::{append, AppendSpec};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

async fn db() -> Db {
    let db = create_database(":memory:").await.unwrap();
    native_ce::meta::seed_vocabularies(&db).await.unwrap();
    db
}

async fn replay_db() -> Db {
    let db = native_ce::open_database(":memory:").await.unwrap();
    native_ce::apply_schema(&db).await.unwrap();
    db
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    registry
        .call(
            db.clone(),
            Caller::local(),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap()
}

/// Read the current write token the way a caller must: through `get_record`.
/// Whole-body replacement is guarded, so the rewrites below carry the digest
/// they actually read rather than asserting an unguarded overwrite.
async fn current_body_digest(registry: &ToolRegistry, db: &Db, id: &str) -> String {
    call(registry, db, "get_record", json!({ "ids": [id] })).await["records"][0]["body_digest"]
        .as_str()
        .expect("get_record exposes body_digest")
        .to_owned()
}

async fn call_err(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> String {
    registry
        .call(
            db.clone(),
            Caller::local(),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap_err()
        .to_string()
}

async fn create(registry: &ToolRegistry, db: &Db, mut args: Value) -> String {
    let object = args.as_object_mut().unwrap();
    object.entry("kind").or_insert_with(|| json!("note"));
    call(registry, db, "create_record", args).await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn comment(
    registry: &ToolRegistry,
    db: &Db,
    id: &str,
    bearer: &str,
    body: &str,
    lifecycle: Option<&str>,
) -> String {
    let mut args = json!({
        "id": id,
        "type": "Annotation",
        "kind": "comment",
        "name": "",
        "body": body,
        "links": [{ "target_id": bearer, "relationship": "part_of" }],
    });
    if let Some(lifecycle) = lifecycle {
        args["lifecycle"] = json!(lifecycle);
    }
    create(registry, db, args).await
}

async fn anchored_comment(
    registry: &ToolRegistry,
    db: &Db,
    id: &str,
    bearer: &str,
    body: &str,
    source: &str,
    exact: &str,
) -> String {
    let start = source.find(exact).unwrap();
    let end = start + exact.len();
    let prefix = source[..start]
        .chars()
        .rev()
        .take(32)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    let suffix = source[end..].chars().take(32).collect::<String>();
    create(
        registry,
        db,
        json!({
            "id": id,
            "type": "Annotation",
            "kind": "comment",
            "body": body,
            "lifecycle": "open",
            "links": [{ "target_id": bearer, "relationship": "part_of" }],
            "target": {
                "target_record_id": bearer,
                "source_slot": "body",
                "purpose": "comment_context",
                "selectors": [
                    { "type": "text_quote", "exact": exact, "prefix": prefix, "suffix": suffix },
                    { "type": "data_position", "start": start, "end": end }
                ]
            }
        }),
    )
    .await
}

#[tokio::test]
async fn anchored_comment_roots_share_exact_context_with_agents_and_replies() {
    let db = db().await;
    let registry = registry();
    let source = "Lead **bold passage** tail";
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Bearer", "body": source }),
    )
    .await;
    let root = anchored_comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000004",
        &target,
        "Could this be clearer?",
        source,
        "bold passage",
    )
    .await;
    let reply = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000003",
        &root,
        "Yes",
        None,
    )
    .await;
    let reply_seq: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();

    let bearer = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [&target], "include_comments": true }),
    )
    .await;
    let anchor = &bearer["records"][0]["comments"][0]["target"];
    assert_eq!(anchor["target_record_id"], target);
    assert_eq!(anchor["source_slot"], "body");
    assert_eq!(anchor["validation"]["status"], "current");
    assert_eq!(anchor["anchored"]["excerpt"]["text"], "bold passage");
    assert!(anchor["source_state"]["event_seq"].is_number());
    assert!(anchor["source_state"]["sha256"].is_string());
    let rendered = native_ce::mcp::render::render("get_record", &bearer).unwrap();
    assert!(rendered.contains("[open]"), "{rendered}");
    assert!(
        rendered.contains("Anchored passage [current]: bold passage"),
        "{rendered}"
    );

    let replies = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [&root], "include_comments": true }),
    )
    .await;
    assert_eq!(
        replies["records"][0]["comments"][0]["target"]["annotation_id"],
        root
    );
    assert_eq!(
        replies["records"][0]["comments"][0]["target"]["anchored"]["excerpt"]["text"],
        "bold passage"
    );

    for args in [
        json!({ "ids": [&reply] }),
        json!({ "ids": [&reply], "as_of": { "content_seq": reply_seq } }),
    ] {
        let direct_reply = call(&registry, &db, "get_record", args).await;
        assert_eq!(direct_reply["records"][0]["target"]["annotation_id"], root);
        assert_eq!(
            direct_reply["records"][0]["target"]["anchored"]["excerpt"]["text"],
            "bold passage"
        );
        let rendered = native_ce::mcp::render::render("get_record", &direct_reply).unwrap();
        assert!(
            rendered.contains("Anchored passage [current]: bold passage"),
            "{rendered}"
        );
    }
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn anchored_comments_relocate_or_fail_closed_after_source_edits() {
    let db = db().await;
    let registry = registry();
    let source = "Before selected words after";
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Bearer", "body": source }),
    )
    .await;
    anchored_comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000002",
        &target,
        "Review this",
        source,
        "selected words",
    )
    .await;

    for (body, expected) in [
        ("Inserted. Before selected words after", "relocated"),
        ("Before selected words after. Appended.", "relocated"),
        ("Before changed words after", "stale"),
        (
            "Before selected words after / Before selected words after",
            "conflict",
        ),
    ] {
        call(
            &registry,
            &db,
            "update_record",
            json!({
                "id": target, "body": body,
                "if_body_digest": current_body_digest(&registry, &db, &target).await
            }),
        )
        .await;
        let read = call(
            &registry,
            &db,
            "get_record",
            json!({ "ids": [&target], "include_comments": true }),
        )
        .await;
        assert_eq!(
            read["records"][0]["comments"][0]["target"]["validation"]["status"], expected,
            "body={body}"
        );
        assert_eq!(
            read["records"][0]["comments"][0]["target"]["anchored"]["excerpt"]["text"],
            "selected words"
        );
    }
}

#[tokio::test]
async fn comment_targets_enforce_root_bearer_and_body_invariants() {
    let db = db().await;
    let registry = registry();
    let source = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Source", "body": "one passage" }),
    )
    .await;
    let other = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Other", "body": "one passage" }),
    )
    .await;
    let wrong_bearer = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "No", "lifecycle": "open",
            "links": [{ "target_id": source, "relationship": "part_of" }],
            "target": { "target_record_id": other, "source_slot": "body", "selectors": [{ "type": "text_quote", "exact": "one passage" }] }
        }),
    )
    .await;
    assert!(wrong_bearer.contains("must target its part_of bearer's body"));

    let alias_id = propose_value_with_kind_metadata_as(
        &db,
        "kind:Annotation",
        "thread-comment",
        None,
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy("Annotation", "thread-comment")),
        None,
    )
    .await
    .unwrap();
    promote_value(&db, &alias_id).await.unwrap();
    alias_value(&db, &alias_id, CoreKind::AnnotationComment.value_id())
        .await
        .unwrap();
    let root = create(
        &registry,
        &db,
        json!({
            "type": "Annotation", "kind": "thread-comment", "body": "Root", "lifecycle": "open",
            "links": [{ "target_id": source, "relationship": "part_of" }]
        }),
    )
    .await;
    let stored_kind: String = sqlx::query_scalar("SELECT kind FROM records WHERE id = ?")
        .bind(&root)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(stored_kind, "comment");
    let created_payload: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id = ? AND type = 'record.created'",
    )
    .bind(&root)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&created_payload).unwrap()["kind"],
        "comment"
    );
    let targeted_reply = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "No",
            "links": [{ "target_id": root, "relationship": "part_of" }],
            "target": { "target_record_id": root, "source_slot": "body", "selectors": [{ "type": "text_quote", "exact": "Root" }] }
        }),
    )
    .await;
    assert!(targeted_reply.contains("replies must be targetless"));

    let payload = {
        let pool = crate::common::fixture_write_pool(&db).await;
        let mut tx = pool.begin().await.unwrap();
        let payload = capture_target_in(
            &mut tx,
            AnnotationTargetInput {
                target_record_id: root.clone(),
                source_slot: SourceSlot::Body,
                purpose: Some("comment_context".into()),
                selectors: vec![
                    SelectorInput::TextQuote {
                        exact: "Root".into(),
                        prefix: None,
                        suffix: None,
                        position_hint: None,
                    },
                    SelectorInput::DataPosition {
                        start: 0,
                        end: 4,
                        selected_sha256: None,
                    },
                ],
            },
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        payload
    };
    // Raw target events and replay must enforce the same targetless-reply
    // invariant as create_record. Build the reply through the supported path,
    // then attempt the target event at both boundaries.
    let direct_reply = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000023",
        &root,
        "Reply",
        None,
    )
    .await;
    let base_seq: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let prefix = log_prefix(&db, base_seq).await.unwrap();
    let event_payload = serde_json::to_value(&payload).unwrap();
    let direct_error = append(
        &db,
        AppendSpec {
            record_id: direct_reply.clone(),
            event_type: "annotation.target.set".into(),
            payload: event_payload.clone(),
            actor: None,
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(direct_error.contains("comment replies must be targetless"));
    let mut replay_events = prefix;
    replay_events.push(EventRow {
        local_seq: base_seq + 1,
        id: "invalid-reply-target".into(),
        record_id: direct_reply.clone(),
        event_type: "annotation.target.set".into(),
        payload: Some(event_payload.to_string()),
        actor: None,
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: "2026-08-10T12:00:00.000Z".into(),
        causal_envelope: native_ce::events::CausalEnvelopeV1::default(),
    });
    let scratch = replay_db().await;
    let mut conn = crate::common::fixture_write_pool(&scratch)
        .await
        .acquire()
        .await
        .unwrap();
    let replay_error = replay_with_blob_seeds(&db, &mut conn, &replay_events, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(replay_error.contains("comment replies must be targetless"));
    drop(conn);
    scratch.close().await;

    // Removal remains a repair path for legacy projections that predate the
    // targetless-reply invariant. Preserve an event-backed target but corrupt
    // its bearer into reply position (a new set event is correctly impossible),
    // then remove it through the supported tool.
    let legacy_reply = anchored_comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000014",
        &source,
        "Legacy reply",
        "one passage",
        "one passage",
    )
    .await;
    sqlx::query(
        "UPDATE links SET target_id = ?
          WHERE source_id = ? AND relationship = 'part_of'",
    )
    .bind(&root)
    .bind(&legacy_reply)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let seeded: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM annotation_targets WHERE annotation_id = ?")
            .bind(&legacy_reply)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(seeded, 1);
    let repaired = call(
        &registry,
        &db,
        "manage_citations",
        json!({
            "action": "remove", "citation_id": legacy_reply,
            "reason": "Repair a legacy reply target"
        }),
    )
    .await;
    assert_eq!(repaired["action"], "removed");
    let repeated_repair = call_err(
        &registry,
        &db,
        "manage_citations",
        json!({
            "action": "remove", "citation_id": legacy_reply,
            "reason": "Prove the repair requires an existing target"
        }),
    )
    .await;
    assert!(
        repeated_repair.contains("has no target"),
        "{repeated_repair}"
    );

    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": source, "body": "same / same",
            "if_body_digest": current_body_digest(&registry, &db, &source).await
        }),
    )
    .await;
    let positioned = create(
        &registry,
        &db,
        json!({
            "type": "Annotation", "kind": "comment", "body": "The second one", "lifecycle": "open",
            "links": [{ "target_id": source, "relationship": "part_of" }],
            "target": { "target_record_id": source, "source_slot": "body", "selectors": [
                { "type": "text_quote", "exact": "same" },
                { "type": "data_position", "start": 7, "end": 11 }
            ] }
        }),
    )
    .await;
    let positioned_read = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [source], "include_comments": true }),
    )
    .await;
    let positioned_summary = positioned_read["records"][0]["comments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|comment| comment["id"] == positioned)
        .unwrap();
    assert_eq!(
        positioned_summary["target"]["validation"]["status"],
        "current"
    );
}

#[tokio::test]
async fn comment_windows_resolve_targets_only_inside_the_requested_page() {
    let db = db().await;
    let registry = registry();
    let source_body = "Context around selected words for a bounded page";
    let bearer = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Bearer", "body": source_body }),
    )
    .await;
    for index in 0..12 {
        comment(
            &registry,
            &db,
            // Pinned UUID ids whose counter is the loop index, so the twelve plain
            // roots keep their creation and id order.
            &format!("c0aa0001-0000-4000-8000-{index:012}"),
            &bearer,
            &format!("Plain {index:02}"),
            Some("open"),
        )
        .await;
    }
    let malformed = anchored_comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000015",
        &bearer,
        "Newest anchored root",
        source_body,
        "selected words",
    )
    .await;
    sqlx::query("UPDATE annotation_targets SET selectors = ? WHERE annotation_id = ?")
        .bind(r#"[{"type":"text_quote"}]"#)
        .bind(&malformed)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    let zero = call(
        &registry,
        &db,
        "get_record",
        json!({
            "ids": [&bearer], "include_comments": true,
            "comments_limit": 0, "comments_offset": 0
        }),
    )
    .await;
    assert_eq!(zero["records"][0]["comment_count"], 13);
    assert_eq!(zero["records"][0]["comments"], json!([]));

    let page = call(
        &registry,
        &db,
        "get_record",
        json!({
            "ids": [&bearer], "include_comments": true,
            "comments_limit": 1, "comments_offset": 1
        }),
    )
    .await;
    assert_eq!(page["records"][0]["comments"].as_array().unwrap().len(), 1);
    assert!(page["records"][0]["comments"][0]["target"].is_null());

    for opts in [
        EnrichOptions {
            include_comments: true,
            comments_limit: 0,
            ..EnrichOptions::default()
        },
        EnrichOptions {
            include_comments: true,
            comments_limit: 1,
            comments_offset: 1,
            ..EnrichOptions::default()
        },
    ] {
        let read = get_record_with(&db, &bearer, opts).await.unwrap().unwrap();
        assert_eq!(read.comment_count, 13);
        assert_eq!(
            read.comments.as_ref().map(Vec::len),
            Some(opts.comments_limit as usize)
        );
    }
}

#[tokio::test]
async fn removing_a_citation_target_cannot_promote_it_into_a_comment() {
    let db = db().await;
    let registry = registry();
    let source = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Source", "body": "evidence" }),
    )
    .await;
    let bearer = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Bearer" }),
    )
    .await;
    let citation = create(
        &registry,
        &db,
        json!({
            "type": "Annotation", "kind": "citation", "body": "Evidence",
            "links": [{ "target_id": bearer, "relationship": "part_of" }],
            "target": {
                "target_record_id": source, "source_slot": "body",
                "selectors": [{ "type": "text_quote", "exact": "evidence" }]
            }
        }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_citations",
        json!({ "action": "remove", "citation_id": citation }),
    )
    .await;

    let alias_id = propose_value_with_kind_metadata_as(
        &db,
        "kind:Annotation",
        "review-thread",
        None,
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy("Annotation", "review-thread")),
        None,
    )
    .await
    .unwrap();
    promote_value(&db, &alias_id).await.unwrap();
    alias_value(&db, &alias_id, CoreKind::AnnotationComment.value_id())
        .await
        .unwrap();
    for kind in ["comment", "review-thread"] {
        let tool_error = call_err(
            &registry,
            &db,
            "update_record",
            json!({
                "id": citation, "kind": kind, "body": "Question", "lifecycle": "open",
                "if_body_digest": current_body_digest(&registry, &db, &citation).await
            }),
        )
        .await;
        assert!(
            tool_error.contains("comment identity cannot be added"),
            "{kind}: {tool_error}"
        );
    }

    let base_seq: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let mut prefix = log_prefix(&db, base_seq).await.unwrap();
    let update_payload = json!({
        "kind": "comment", "body": "Question", "lifecycle": "open"
    });
    let direct_error = append(
        &db,
        AppendSpec {
            record_id: citation.clone(),
            event_type: "record.updated".into(),
            payload: update_payload.clone(),
            actor: None,
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        direct_error.contains("comment identity must be created atomically"),
        "{direct_error}"
    );
    prefix.push(EventRow {
        local_seq: base_seq + 1,
        id: "invalid-citation-comment-promotion".into(),
        record_id: citation,
        event_type: "record.updated".into(),
        payload: Some(update_payload.to_string()),
        actor: None,
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: "2026-08-10T12:00:01.000Z".into(),
        causal_envelope: native_ce::events::CausalEnvelopeV1::default(),
    });
    let scratch = replay_db().await;
    let scratch_pool = crate::common::fixture_write_pool(&scratch).await;
    let mut conn = scratch_pool.acquire().await.unwrap();
    let replay_error = replay_with_blob_seeds(&db, &mut conn, &prefix, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        replay_error.contains("comment identity must be created atomically"),
        "{replay_error}"
    );
    drop(conn);
    scratch.close().await;
}

#[tokio::test]
async fn comments_are_rich_independent_windows_with_thread_specific_ordering() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Bearer" }),
    )
    .await;
    let first = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000009",
        &target,
        "First root",
        Some("open"),
    )
    .await;
    let second = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000010",
        &target,
        "Second root",
        None,
    )
    .await;
    let reply_a = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000020",
        &first,
        "First reply",
        None,
    )
    .await;
    let reply_b = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000021",
        &first,
        "Second reply",
        None,
    )
    .await;

    let default_read = call(&registry, &db, "get_record", json!({ "ids": [&target] })).await;
    let record = &default_read["records"][0];
    assert_eq!(record["comment_count"], 2);
    assert_eq!(record["child_count"], 0);
    assert!(record.get("comments").is_none());

    let roots = call(
        &registry,
        &db,
        "get_record",
        json!({
            "ids": [&target], "include_comments": true,
            "comments_limit": 1, "comments_offset": 0
        }),
    )
    .await;
    assert_eq!(roots["records"][0]["comments"][0]["id"], second);
    assert_eq!(roots["records"][0]["comments"][0]["body"], "Second root");
    assert!(roots["records"][0]["comments"][0]["created_at"].is_string());

    let replies = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [&first], "include_comments": true }),
    )
    .await;
    assert_eq!(replies["records"][0]["comment_count"], 2);
    assert_eq!(replies["records"][0]["comments"][0]["id"], reply_a);
    assert_eq!(replies["records"][0]["comments"][1]["id"], reply_b);

    let hidden = call(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "name_contains": "" }] }),
    )
    .await;
    assert!(!hidden.to_string().contains(&first));
    assert!(!hidden.to_string().contains(&second));
    let explicit = call(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "kinds": ["comment"] }] }),
    )
    .await;
    assert_eq!(explicit["total"], 4);
}

#[tokio::test]
async fn comment_shape_and_flat_reply_contract_reject_malformed_authoring() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Bearer" }),
    )
    .await;
    for bad in [
        json!({ "type": "Annotation", "kind": "comment", "body": " " }),
        json!({ "type": "Annotation", "kind": "comment", "body": "x", "links": [] }),
        json!({ "type": "Annotation", "kind": "comment", "body": "x", "lifecycle": "resolved", "summary": "done", "links": [{"target_id": target, "relationship": "part_of"}] }),
        json!({ "type": "Annotation", "kind": "comment", "body": "x", "lifecycle": "open", "summary": "premature", "links": [{"target_id": target, "relationship": "part_of"}] }),
    ] {
        assert!(!call_err(&registry, &db, "create_record", bad)
            .await
            .is_empty());
    }

    let root = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000022",
        &target,
        "Root",
        Some("open"),
    )
    .await;
    let reply = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000019",
        &root,
        "Reply",
        None,
    )
    .await;
    let nested = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "Nested",
            "links": [{"target_id": reply, "relationship": "part_of"}]
        }),
    )
    .await;
    assert!(nested.contains("reply-to-reply"), "{nested}");
    let mutate_bearer = call_err(
        &registry,
        &db,
        "manage_links",
        json!({
            "action": "remove", "source_id": root, "target_id": target,
            "relationship": "part_of"
        }),
    )
    .await;
    assert!(
        mutate_bearer.contains("bearer is immutable"),
        "{mutate_bearer}"
    );
}

#[tokio::test]
async fn resolution_is_atomic_root_only_and_preserved_by_history_and_rebuild() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Bearer" }),
    )
    .await;
    let root = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000022",
        &target,
        "Question",
        Some("open"),
    )
    .await;
    let reply = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000019",
        &root,
        "Answer",
        None,
    )
    .await;

    let missing_summary = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": root, "lifecycle": "resolved" }),
    )
    .await;
    assert!(
        missing_summary.contains("nonblank resolution summary"),
        "{missing_summary}"
    );
    let root_read = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [root.clone()] }),
    )
    .await;
    let root_updated_at = root_read["records"][0]["updated_at"]
        .as_str()
        .unwrap()
        .to_owned();
    let resolved = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": root, "lifecycle": "resolved", "summary": "Handled in the answer",
            "if_unmodified_since": root_updated_at
        }),
    )
    .await;
    let previous_seq = resolved["previous_seq"].as_i64().unwrap();
    assert_eq!(
        resolved["lifecycle_interpretation"]["value"]["canonical"],
        "resolved"
    );
    assert_eq!(resolved["summary"], "Handled in the answer");

    let repeated = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": root, "lifecycle": "resolved", "summary": "Again" }),
    )
    .await;
    assert!(repeated.contains("open -> resolved"), "{repeated}");
    let reply_read = call(&registry, &db, "get_record", json!({ "ids": [reply] })).await;
    assert_eq!(
        reply_read["records"][0]["lifecycle_interpretation"]["status"],
        "absent"
    );
    let before = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [root], "as_of": { "content_seq": previous_seq } }),
    )
    .await;
    assert_eq!(
        before["records"][0]["lifecycle_interpretation"]["value"]["canonical"],
        "open"
    );
    assert!(before["records"][0]["summary"].is_null());
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn malformed_imported_comments_fail_closed_for_direct_and_bearer_reads() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Bearer" }),
    )
    .await;
    let other = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Other" }),
    )
    .await;
    let canonical = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000008",
        &target,
        "Canonical",
        Some("open"),
    )
    .await;
    let alias_id = propose_value_with_kind_metadata_as(
        &db,
        "kind:Annotation",
        "discussion",
        None,
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy("Annotation", "discussion")),
        None,
    )
    .await
    .unwrap();
    promote_value(&db, &alias_id).await.unwrap();
    alias_value(&db, &alias_id, CoreKind::AnnotationComment.value_id())
        .await
        .unwrap();
    let alias = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000001",
        &target,
        "Alias spelling",
        Some("open"),
    )
    .await;
    sqlx::query("UPDATE records SET kind = 'discussion' WHERE id = ?")
        .bind(&alias)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    let root = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000016",
        &target,
        "Question",
        Some("open"),
    )
    .await;
    sqlx::query(
        "INSERT INTO links(id, source_id, target_id, relationship, created_at)
         VALUES('corrupt-second-bearer', ?, ?, 'part_of', '2026-08-10T00:00:00Z')",
    )
    .bind(&root)
    .bind(&other)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let blank = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000007",
        &target,
        "Before",
        Some("open"),
    )
    .await;
    sqlx::query("UPDATE records SET body = '  ' WHERE id = ?")
        .bind(&blank)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let bad_lifecycle = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000006",
        &target,
        "Before",
        Some("open"),
    )
    .await;
    sqlx::query("UPDATE records SET lifecycle = 'closed' WHERE id = ?")
        .bind(&bad_lifecycle)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    let bearer = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [target], "include_comments": true }),
    )
    .await;
    assert_eq!(bearer["records"][0]["comment_count"], 2);
    for malformed in [&root, &blank, &bad_lifecycle] {
        let direct = call(&registry, &db, "get_record", json!({ "ids": [malformed] })).await;
        assert_eq!(direct["records"][0]["status"], "not_found");
    }

    let hidden = call(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "types": ["Annotation"] }] }),
    )
    .await;
    let hidden_rendered = hidden.to_string();
    assert!(!hidden_rendered.contains(&canonical));
    assert!(!hidden_rendered.contains(&alias));

    for spelling in ["comment", "discussion"] {
        let explicit = call(
            &registry,
            &db,
            "query_record",
            json!({ "steps": [{ "step": "filter", "kinds": [spelling] }] }),
        )
        .await;
        let ids: Vec<_> = explicit["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&canonical.as_str()));
        assert!(ids.contains(&alias.as_str()));
        assert!(!ids.contains(&root.as_str()));
        assert!(!ids.contains(&blank.as_str()));
        assert!(!ids.contains(&bad_lifecycle.as_str()));
    }
}

#[tokio::test]
async fn start_work_preview_and_claim_surface_only_bounded_open_threads() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Work", "lifecycle": "open", "body": "Passage for the open question" }),
    )
    .await;
    for index in 0..11 {
        comment(
            &registry,
            &db,
            // Pinned UUID ids whose counter is the loop index, so the eleven older
            // open roots keep their creation and id order.
            &format!("c0aa0002-0000-4000-8000-{index:012}"),
            &target,
            &format!("Older open {index:02}"),
            Some("open"),
        )
        .await;
    }
    let open = anchored_comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000017",
        &target,
        "Open",
        "Passage for the open question",
        "open question",
    )
    .await;
    let informational = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000012",
        &target,
        "FYI",
        None,
    )
    .await;
    for index in 0..22 {
        comment(
            &registry,
            &db,
            // Pinned UUID ids whose counter is the loop index, so the twenty-two
            // replies keep their creation and id order.
            &format!("c0aa0003-0000-4000-8000-{index:012}"),
            &open,
            &format!("Reply {index:02}"),
            None,
        )
        .await;
    }

    for action in ["preview", "claim"] {
        let out = call(
            &registry,
            &db,
            "start_work",
            json!({ "record_id": target, "action": action }),
        )
        .await;
        let comments = &out["context"]["comments"];
        assert_eq!(comments["open_thread_count"], 12);
        assert_eq!(comments["open_threads"].as_array().unwrap().len(), 10);
        assert_eq!(comments["open_threads"][0]["root"]["id"], open);
        assert_eq!(comments["open_threads"][0]["reply_count"], 22);
        assert_eq!(
            comments["open_threads"][0]["replies"]
                .as_array()
                .unwrap()
                .len(),
            20
        );
        assert!(!comments.to_string().contains(&informational));
        let rendered = native_ce::mcp::render::render("start_work", &out).unwrap();
        assert!(rendered.contains("Open comment threads (12)"), "{rendered}");
        assert!(
            rendered.contains("Anchored passage [current]: open question"),
            "{rendered}"
        );
    }
}

#[tokio::test]
async fn comment_roots_without_lifecycle_are_born_informational_and_never_count_as_open() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Work", "lifecycle": "open" }),
    )
    .await;
    let fyi = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000011",
        &target,
        "FYI",
        None,
    )
    .await;
    let question = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000018",
        &target,
        "Question",
        Some("open"),
    )
    .await;
    let answer = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000005",
        &question,
        "Answer",
        None,
    )
    .await;

    // Omitting the field no longer stores absence: the FYI state has a name.
    let fyi_read = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [fyi.clone()] }),
    )
    .await;
    assert_eq!(
        fyi_read["records"][0]["lifecycle_interpretation"]["value"]["canonical"],
        "informational"
    );
    let question_read = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [question.clone()] }),
    )
    .await;
    assert_eq!(
        question_read["records"][0]["lifecycle_interpretation"]["value"]["canonical"],
        "open"
    );
    // Thread state lives on the root, so a reply still stores null.
    let answer_read = call(&registry, &db, "get_record", json!({ "ids": [answer] })).await;
    assert_eq!(
        answer_read["records"][0]["lifecycle_interpretation"]["status"],
        "absent"
    );

    // An informational root is ordinary, readable thread content ...
    let bearer = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [target.clone()], "include_comments": true }),
    )
    .await;
    assert_eq!(bearer["records"][0]["comment_count"], 2);
    assert!(bearer.to_string().contains(&fyi));

    // ... and is still deliberately excluded from open-thread counts.
    let work = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": target, "action": "preview" }),
    )
    .await;
    let comments = &work["context"]["comments"];
    assert_eq!(comments["open_thread_count"], 1);
    assert_eq!(comments["open_threads"][0]["root"]["id"], question);
    assert!(!comments.to_string().contains(&fyi));
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn informational_roots_reject_resolution_with_a_refusal_that_names_the_state() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Bearer" }),
    )
    .await;
    let fyi = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000011",
        &target,
        "FYI",
        None,
    )
    .await;
    let refusal = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": fyi, "lifecycle": "resolved", "summary": "Nothing to resolve" }),
    )
    .await;
    assert!(refusal.contains("open -> resolved"), "{refusal}");
    assert!(refusal.contains("informational"), "{refusal}");

    // Rows written before the state had a name still store null. They stay
    // readable, stay writable, and refuse resolution for the same reason.
    let legacy = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000013",
        &target,
        "Legacy FYI",
        None,
    )
    .await;
    sqlx::query("UPDATE records SET lifecycle = NULL WHERE id = ?")
        .bind(&legacy)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let legacy_read = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [legacy.clone()] }),
    )
    .await;
    assert_eq!(legacy_read["records"][0]["id"], legacy);
    assert_eq!(
        legacy_read["records"][0]["lifecycle_interpretation"]["status"],
        "absent"
    );
    let edited = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": legacy,
            "body": "Legacy FYI, edited",
            "if_body_digest": legacy_read["records"][0]["body_digest"],
        }),
    )
    .await;
    assert_eq!(edited["body"], "Legacy FYI, edited");
    let legacy_refusal = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": legacy, "lifecycle": "resolved", "summary": "Nothing to resolve" }),
    )
    .await;
    assert!(legacy_refusal.contains("informational"), "{legacy_refusal}");

    // Naming the state does not change which transitions are legal.
    let question = comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000018",
        &target,
        "Question",
        Some("open"),
    )
    .await;
    let resolved = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": question, "lifecycle": "resolved", "summary": "Answered inline" }),
    )
    .await;
    assert_eq!(
        resolved["lifecycle_interpretation"]["value"]["canonical"],
        "resolved"
    );
    assert_eq!(resolved["summary"], "Answered inline");
}
