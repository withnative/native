//! Product journey across ordinary comments, revision-bound saves and reuse.

use native_ce::freshness::current_record_body_revision;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

#[tokio::test]
async fn authoring_operations_enforce_authority_and_redact_hidden_basis() {
    use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let premise = document(&registry, &db, "Private premise", "Private source text.").await;
    let account = document(&registry, &db, "Shared account", "Initial draft.").await;
    for id in [&premise, &account] {
        replace_explicit_policy(
            &db,
            "test:authoring",
            id,
            vec![AllowEntry::account("writer", Capability::Manage)],
        )
        .await
        .unwrap();
    }
    let revision = current_record_body_revision(&db, &account).await.unwrap();
    let request = json!({"record_id":account,"expected_revision_event_id":revision.revision_event_id,
        "body":"A bounded account.","sources":[source(&db,&premise,"Premise").await],
        "idempotency_key":"authorized-save","reason":"Declare the inspected basis."});
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    for (tool, args) in [
        ("save_account", request.clone()),
        ("get_reuse_context", json!({"record_id":account})),
    ] {
        let error = registry
            .call(db.clone(), Caller::authenticated("outsider"), tool, args)
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.contains("Private source text"), "{error}");
        assert!(!error.contains(&premise), "{error}");
    }
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after, "denied operations cannot append content");
    registry
        .call(
            db.clone(),
            Caller::authenticated("writer"),
            "save_account",
            request.clone(),
        )
        .await
        .unwrap();
    let full = registry
        .call(
            db.clone(),
            Caller::authenticated("writer"),
            "get_reuse_context",
            json!({"record_id":account}),
        )
        .await
        .unwrap();
    assert!(serde_json::to_string(&full).unwrap().contains(&premise));
    replace_explicit_policy(
        &db,
        "test:authoring",
        &account,
        vec![
            AllowEntry::account("writer", Capability::Manage),
            AllowEntry::account("reader", Capability::View),
        ],
    )
    .await
    .unwrap();
    let redacted = registry
        .call(
            db.clone(),
            Caller::authenticated("reader"),
            "get_reuse_context",
            json!({"record_id":account}),
        )
        .await
        .unwrap();
    let encoded = serde_json::to_string(&redacted).unwrap();
    assert!(!encoded.contains(&premise), "{redacted}");
    assert!(!encoded.contains("Private source text"), "{redacted}");
    assert!(encoded.contains("withheld"), "{redacted}");
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    registry
        .call(
            db.clone(),
            Caller::authenticated("reader"),
            "save_account",
            request,
        )
        .await
        .unwrap_err();
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after, "view permission cannot replay a mutation");
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    registry
        .call(db.clone(), Caller::local(), tool, args)
        .await
        .unwrap()
}

async fn document(registry: &ToolRegistry, db: &Db, name: &str, body: &str) -> String {
    call(
        registry,
        db,
        "create_record",
        json!({
            "type":"Document", "kind":"note", "name":name, "body":body,
            "reason":"Create the bounded authoring journey fixture."
        }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn source(db: &Db, id: &str, role: &str) -> Value {
    let revision = current_record_body_revision(db, id).await.unwrap();
    json!({"record_id":id, "revision_event_id":revision.revision_event_id,
        "role":role, "reason":"Declared material used for this draft."})
}

async fn save(
    registry: &ToolRegistry,
    db: &Db,
    id: &str,
    body: &str,
    sources: Vec<Value>,
    key: &str,
) -> Value {
    let revision = current_record_body_revision(db, id).await.unwrap();
    call(
        registry,
        db,
        "save_account",
        json!({
            "record_id":id, "expected_revision_event_id":revision.revision_event_id,
            "body":body, "sources":sources, "idempotency_key":key,
            "reason":"Preserve the exact declared basis of the authored account."
        }),
    )
    .await
}

#[tokio::test]
async fn challenged_brief_correction_reuse_and_resolution_preserve_revision_history() {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let s1 = document(&registry, &db, "Engineering source", "Friday is conditional. Engineering has not committed. QA feasibility is not established by this material.").await;
    let brief = document(&registry, &db, "Campaign brief", "Draft account.").await;
    let b1 = "Engineering has committed to Friday.";
    save(
        &registry,
        &db,
        &brief,
        b1,
        vec![source(&db, &s1, "Engineering statement").await],
        "brief-1",
    )
    .await;
    let commitment = call(&registry, &db, "create_record", json!({
        "type":"Annotation", "kind":"comment", "body":"The source does not record an Engineering commitment. Correct this wording.",
        "lifecycle":"open", "links":[{"target_id":brief,"relationship":"part_of"}],
        "target":{"target_record_id":brief,"source_slot":"body","selectors":[
            {"type":"text_quote","exact":b1},
            {"type":"data_position","start":0,"end":b1.len()}
        ]}, "reason":"Challenge the exact overstated passage."
    })).await["id"].as_str().unwrap().to_owned();
    let qa = call(&registry, &db, "create_record", json!({
        "type":"Annotation", "kind":"comment", "body":"QA feasibility is still an open question in the reviewed material.",
        "lifecycle":"open", "links":[{"target_id":brief,"relationship":"part_of"}],
        "reason":"Track QA independently from commitment wording."
    })).await["id"].as_str().unwrap().to_owned();
    let b2 = "Friday remains conditional; Engineering has not committed. QA feasibility is not established by the reviewed material.";
    save(
        &registry,
        &db,
        &brief,
        b2,
        vec![source(&db, &s1, "Engineering statement").await],
        "brief-2",
    )
    .await;
    call(&registry, &db, "update_record", json!({"id":commitment,"lifecycle":"resolved",
        "summary":"The commitment wording was corrected. The separate QA question remains open.",
        "reason":"Record the limited correction without resolving QA."
    })).await;
    let packet = call(
        &registry,
        &db,
        "get_reuse_context",
        json!({"record_id":brief}),
    )
    .await;
    assert_eq!(packet["record_id"], brief);
    assert_eq!(packet["basis"]["status"], "current");
    assert_eq!(packet["concerns"]["entries"].as_array().unwrap().len(), 1);
    assert_eq!(packet["concerns"]["entries"][0]["comment_id"], qa);
    assert_eq!(packet["treatment"]["entries"].as_array().unwrap().len(), 1);
    assert_eq!(packet["treatment"]["entries"][0]["comment_id"], commitment);
    assert_eq!(
        packet["drafting_instruction"]["version"],
        "native.authoring-scope-preservation.v2"
    );
    let encoded = serde_json::to_string(&packet).unwrap();
    assert!(encoded.contains(b2), "{packet}");
    assert!(
        encoded.contains("The commitment wording was corrected"),
        "{packet}"
    );
    assert!(
        encoded.contains("QA feasibility is still an open question"),
        "{packet}"
    );
    assert!(encoded.contains("not established"), "{packet}");
    let sales = document(&registry, &db, "Sales draft", "Draft account.").await;
    let d1_body = "Friday is conditional. Engineering has not committed. QA feasibility and release approval are not established by the supplied material.";
    save(
        &registry,
        &db,
        &sales,
        d1_body,
        vec![
            source(&db, &brief, "Corrected campaign brief").await,
            source(&db, &qa, "Open QA concern").await,
        ],
        "sales-1",
    )
    .await;
    let d1_revision = current_record_body_revision(&db, &sales).await.unwrap();

    let qa_evidence = document(&registry, &db, "QA outcome", "QA has verified feasibility for the proposed Friday scope. This statement does not establish release approval.").await;
    call(&registry, &db, "update_record", json!({"id":qa,"lifecycle":"resolved",
        "summary":"QA feasibility has been verified for the proposed scope; release approval is a separate question.",
        "reason":"Record the QA outcome without inferring release approval."
    })).await;
    let later_packet = call(
        &registry,
        &db,
        "get_reuse_context",
        json!({"record_id":brief}),
    )
    .await;
    assert!(later_packet["concerns"]["entries"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        later_packet["treatment"]["entries"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(serde_json::to_string(&later_packet)
        .unwrap()
        .contains("QA feasibility has been verified"));
    // Opt-in evidence export uses actual product packets, not hand-assembled
    // imitations. Normal CI never depends on a model or an external service.
    if let Ok(directory) = std::env::var("NATIVE_AUTHORING_EVAL_DIR") {
        let directory = std::path::Path::new(&directory);
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(
            directory.join("approval-unknown.json"),
            serde_json::to_vec_pretty(&later_packet).unwrap(),
        )
        .unwrap();
        call(&registry, &db, "create_record", json!({
            "type":"Annotation", "kind":"comment", "body":"The release owner records: Launch approval is pending; I have not made the decision.",
            "lifecycle":"open", "links":[{"target_id":brief,"relationship":"part_of"}],
            "reason":"Supply positive pending-decision evidence for the paired model evaluation."
        })).await;
        let pending_packet = call(
            &registry,
            &db,
            "get_reuse_context",
            json!({"record_id":brief}),
        )
        .await;
        std::fs::write(
            directory.join("approval-pending.json"),
            serde_json::to_vec_pretty(&pending_packet).unwrap(),
        )
        .unwrap();
    }
    let d2 = document(&registry, &db, "Later Sales draft", "Draft account.").await;
    save(&registry, &db, &d2, "Friday remains conditional. QA feasibility has been verified for the proposed scope. Release approval is not established by the supplied material.", vec![source(&db, &brief, "Campaign scope").await, source(&db, &qa_evidence, "Recorded QA outcome").await], "sales-2").await;
    assert_eq!(
        current_record_body_revision(&db, &sales).await.unwrap(),
        d1_revision,
        "later concern resolution and derivative save must not rewrite D1"
    );
    let original = call(&registry, &db, "get_record", json!({"ids":[sales]})).await;
    assert_eq!(original["records"][0]["body"], d1_body);
    let d2_revision = current_record_body_revision(&db, &d2).await.unwrap();
    call(
        &registry,
        &db,
        "update_record",
        json!({
        "id":d2, "body_set":"Ordinary edit after the declared save.",
        "if_body_digest":d2_revision.sha256,
            "reason":"Exercise the boundary between a body edit and renewed source coverage."
        }),
    )
    .await;
    let edited = call(&registry, &db, "get_reuse_context", json!({"record_id":d2})).await;
    assert_eq!(edited["basis"]["status"], "historical");
    assert_eq!(
        edited["basis"]["output_revision_event_id"],
        d2_revision.revision_event_id
    );
    assert_ne!(
        edited["record"]["revision"]["revision_event_id"],
        edited["basis"]["output_revision_event_id"]
    );
}
