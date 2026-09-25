//! `get_reuse_context` — bounded reuse context for one Document.

use native_ce::freshness::current_record_body_revision;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

const DOC: &str = "a0a00000-0000-4000-8000-000000000001";
const ROOT_OPEN: &str = "a0a00000-0000-4000-8000-000000000002";
const REPLY_ONE: &str = "a0a00000-0000-4000-8000-000000000003";
const ROOT_RESOLVED: &str = "a0a00000-0000-4000-8000-000000000004";
const ROOT_FYI: &str = "a0a00000-0000-4000-8000-000000000005";
const ROOT_ANCHORED: &str = "a0a00000-0000-4000-8000-000000000006";
const ROOT_SECOND: &str = "a0a00000-0000-4000-8000-000000000007";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn fixture() -> (Db, ToolRegistry) {
    let db = create_database(":memory:").await.unwrap();
    native_ce::meta::seed_vocabularies(&db).await.unwrap();
    (db, registry())
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

async fn create(registry: &ToolRegistry, db: &Db, args: Value) -> String {
    call(registry, db, "create_record", args).await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn document(registry: &ToolRegistry, db: &Db, id: &str, body: &str) -> String {
    create(
        registry,
        db,
        json!({ "id": id, "type": "Document", "kind": "note",
                "name": "reuse fixture", "body": body }),
    )
    .await
}

async fn comment(
    registry: &ToolRegistry,
    db: &Db,
    id: &str,
    bearer: &str,
    body: &str,
    lifecycle: Option<&str>,
) {
    let mut args = json!({
        "id": id, "type": "Annotation", "kind": "comment", "name": "",
        "body": body, "links": [{ "target_id": bearer, "relationship": "part_of" }],
        "reason": "Raise the bounded reuse fixture concern.",
    });
    if let Some(lifecycle) = lifecycle {
        args["lifecycle"] = json!(lifecycle);
    }
    create(registry, db, args).await;
}

async fn resolve(registry: &ToolRegistry, db: &Db, id: &str, summary: &str) {
    call(
        registry,
        db,
        "update_record",
        json!({ "id": id, "lifecycle": "resolved", "summary": summary }),
    )
    .await;
}

#[tokio::test]
async fn rejects_out_of_range_limit() {
    let (db, registry) = fixture().await;
    let err = registry
        .call(
            db.clone(),
            Caller::local(),
            "get_reuse_context",
            crate::common::with_test_reason(
                "get_reuse_context",
                json!({ "record_id": DOC, "limit": 51 }),
            ),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("limit"), "{err}");
    db.close().await;
}

#[tokio::test]
async fn missing_document_is_not_found() {
    let (db, registry) = fixture().await;
    let err = registry
        .call(
            db.clone(),
            Caller::local(),
            "get_reuse_context",
            crate::common::with_test_reason("get_reuse_context", json!({ "record_id": DOC })),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("does not exist"), "{err}");
    db.close().await;
}

#[tokio::test]
async fn open_concerns_replies_and_treatment_split() {
    let (db, registry) = fixture().await;
    document(&registry, &db, DOC, "Q3 closed.").await;
    comment(
        &registry,
        &db,
        ROOT_OPEN,
        DOC,
        "Is the rebate pending?",
        Some("open"),
    )
    .await;
    create(
        &registry,
        &db,
        json!({
            "id": REPLY_ONE, "type": "Annotation", "kind": "comment", "name": "",
            "body": "Checking with finance.",
            "links": [{ "target_id": ROOT_OPEN, "relationship": "part_of" }],
            "reason": "Reply to the bounded reuse fixture concern.",
        }),
    )
    .await;
    comment(
        &registry,
        &db,
        ROOT_RESOLVED,
        DOC,
        "Typo on line two.",
        Some("open"),
    )
    .await;
    resolve(&registry, &db, ROOT_RESOLVED, "Fixed inline.").await;
    // Informational roots (legacy null spelling here) are FYI: neither window.
    comment(&registry, &db, ROOT_FYI, DOC, "FYI only.", None).await;

    let out = call(
        &registry,
        &db,
        "get_reuse_context",
        json!({ "record_id": DOC }),
    )
    .await;
    assert_eq!(out["record_id"], json!(DOC));
    assert!(out["record"]["revision"]["revision_event_id"].is_string());
    assert!(out["record"]["revision"]["sha256"].is_string());
    // No receipt yet: no declared basis, uncertainty none — stated, not complete.
    assert_eq!(out["basis"]["status"], json!("none"));
    assert_eq!(out["basis"]["completeness"], json!("no_declared_basis"));
    assert!(out["basis"]["sources"].as_array().unwrap().is_empty());
    assert_eq!(out["uncertainty"]["status"], json!("none"));
    // Open root with body revision ref + one reply; resolved root in treatment;
    // FYI root in neither.
    let concerns = out["concerns"]["entries"].as_array().unwrap();
    assert_eq!(concerns.len(), 1, "{out}");
    assert_eq!(concerns[0]["comment_id"], json!(ROOT_OPEN));
    assert!(concerns[0]["body_revision_event_id"].is_string());
    assert!(concerns[0]["metadata_revision_event_id"].is_string());
    assert_eq!(concerns[0]["replies"].as_array().unwrap().len(), 1);
    assert_eq!(out["concerns"]["completeness"], json!("complete"));
    let treatment = out["treatment"]["entries"].as_array().unwrap();
    assert_eq!(treatment.len(), 1, "{out}");
    assert_eq!(treatment[0]["comment_id"], json!(ROOT_RESOLVED));
    assert_eq!(treatment[0]["resolution_summary"], json!("Fixed inline."));
    // Resolution-only change lands after the body event: metadata differs.
    assert_ne!(
        treatment[0]["metadata_revision_event_id"], treatment[0]["body_revision_event_id"],
        "{out}"
    );
    let encoded = serde_json::to_string(&out).unwrap();
    assert!(!encoded.contains(ROOT_FYI), "{out}");
    // Versioned instruction carries the unknown-vs-pending distinction.
    assert_eq!(
        out["drafting_instruction"]["version"],
        json!("native.authoring-scope-preservation.v2")
    );
    assert!(out["drafting_instruction"]["instruction"]
        .as_str()
        .unwrap()
        .contains("does not establish"));
    db.close().await;
}

#[tokio::test]
async fn anchored_root_carries_passage_target() {
    let (db, registry) = fixture().await;
    let body = "Friday remains conditional.";
    document(&registry, &db, DOC, body).await;
    let exact = "conditional";
    let start = body.find(exact).unwrap();
    create(
        &registry,
        &db,
        json!({
            "id": ROOT_ANCHORED, "type": "Annotation", "kind": "comment", "name": "",
            "body": "Which Friday does this mean?", "lifecycle": "open",
            "links": [{ "target_id": DOC, "relationship": "part_of" }],
            "target": {"target_record_id": DOC, "source_slot": "body", "selectors": [
                {"type": "text_quote", "exact": exact},
                {"type": "data_position", "start": start, "end": start + exact.len()},
            ]},
            "reason": "Anchor the bounded reuse fixture concern to its passage.",
        }),
    )
    .await;
    let out = call(
        &registry,
        &db,
        "get_reuse_context",
        json!({ "record_id": DOC }),
    )
    .await;
    let concerns = out["concerns"]["entries"].as_array().unwrap();
    assert_eq!(concerns.len(), 1, "{out}");
    assert!(concerns[0]["target"].is_object(), "{out}");
    assert_eq!(
        concerns[0]["target"]["target_record_id"],
        json!(DOC),
        "{out}"
    );
    db.close().await;
}

#[tokio::test]
async fn concern_window_truncates_with_callable_expansion() {
    let (db, registry) = fixture().await;
    document(&registry, &db, DOC, "Scope note.").await;
    comment(
        &registry,
        &db,
        ROOT_OPEN,
        DOC,
        "First question.",
        Some("open"),
    )
    .await;
    comment(
        &registry,
        &db,
        ROOT_SECOND,
        DOC,
        "Second question.",
        Some("open"),
    )
    .await;
    let out = call(
        &registry,
        &db,
        "get_reuse_context",
        json!({ "record_id": DOC, "limit": 1 }),
    )
    .await;
    assert_eq!(
        out["concerns"]["entries"].as_array().unwrap().len(),
        1,
        "{out}"
    );
    assert_eq!(out["concerns"]["completeness"], json!("truncated"), "{out}");
    assert_eq!(
        out["concerns"]["expand_via"]["tool"],
        json!("get_reuse_context"),
        "{out}"
    );
    assert_eq!(
        out["concerns"]["expand_via"]["args"]["roots_offset"],
        json!(1),
        "{out}"
    );
    // Treatment window is independent: empty here, and honestly complete.
    assert_eq!(out["treatment"]["completeness"], json!("complete"), "{out}");
    db.close().await;
}

#[tokio::test]
async fn ordinary_edit_after_save_marks_basis_historical() {
    let (db, registry) = fixture().await;
    let source = document(
        &registry,
        &db,
        "a0a00000-0000-4000-8000-000000000101",
        "Source text.",
    )
    .await;
    let account = document(
        &registry,
        &db,
        "a0a00000-0000-4000-8000-000000000102",
        "Initial draft.",
    )
    .await;
    let revision = current_record_body_revision(&db, &source).await.unwrap();
    let account_revision = current_record_body_revision(&db, &account).await.unwrap();
    call(
        &registry,
        &db,
        "save_account",
        json!({
            "record_id": account,
            "expected_revision_event_id": account_revision.revision_event_id,
            "body": "Saved draft.",
            "sources": [{
                "record_id": source,
                "revision_event_id": revision.revision_event_id,
                "role": "Premise",
                "reason": "Declared material used for this draft.",
            }],
            "idempotency_key": "reuse-historical",
            "reason": "Declare the inspected basis.",
        }),
    )
    .await;
    let current = call(
        &registry,
        &db,
        "get_reuse_context",
        json!({ "record_id": account }),
    )
    .await;
    assert_eq!(current["basis"]["status"], json!("current"), "{current}");
    assert_eq!(
        current["uncertainty"]["status"],
        json!("current"),
        "{current}"
    );
    assert_eq!(
        current["basis"]["sources"][0]["role"],
        json!("Premise"),
        "{current}"
    );
    // Ordinary edit after the receipt: the declared basis is now historical.
    let read = call(&registry, &db, "get_record", json!({ "ids": [account] })).await;
    let stamp = read["records"][0]["updated_at"]
        .as_str()
        .unwrap()
        .to_owned();
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": account, "body_append": " Touched.",
            "if_unmodified_since": stamp,
        }),
    )
    .await;
    let later = call(
        &registry,
        &db,
        "get_reuse_context",
        json!({ "record_id": account }),
    )
    .await;
    assert_eq!(later["basis"]["status"], json!("historical"), "{later}");
    assert_eq!(
        later["uncertainty"]["status"],
        json!("historical"),
        "{later}"
    );
    db.close().await;
}

#[tokio::test]
async fn governed_kind_and_lifecycle_aliases_remain_visible() {
    use native_ce::generated::kinds::CoreKind;
    use native_ce::meta::kind::KindMetadataV1;
    use native_ce::meta::{
        alias_value, promote_value, propose_value, propose_value_with_kind_metadata_as,
        VocabularyValueTerminality,
    };
    let (db, registry) = fixture().await;
    document(&registry, &db, DOC, "Account.").await;
    comment(
        &registry,
        &db,
        ROOT_OPEN,
        DOC,
        "Aliased open concern.",
        Some("open"),
    )
    .await;
    let kind_alias = propose_value_with_kind_metadata_as(
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
    promote_value(&db, &kind_alias).await.unwrap();
    alias_value(&db, &kind_alias, CoreKind::AnnotationComment.value_id())
        .await
        .unwrap();
    let lifecycle_alias = propose_value(&db, "comment-lifecycle", "unsettled", None)
        .await
        .unwrap();
    promote_value(&db, &lifecycle_alias).await.unwrap();
    let canonical: String = sqlx::query_scalar(
        "SELECT vv.id FROM vocabulary_values vv JOIN vocabularies v ON v.id=vv.vocabulary_id WHERE v.name='comment-lifecycle' AND vv.value='open'",
    ).fetch_one(db.pool()).await.unwrap();
    alias_value(&db, &lifecycle_alias, &canonical)
        .await
        .unwrap();
    // Imported historical spellings must be read through governed identity,
    // even when ordinary current writes canonicalize their inputs.
    sqlx::query("UPDATE records SET kind='discussion', lifecycle='unsettled' WHERE id=?")
        .bind(ROOT_OPEN)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let packet = call(
        &registry,
        &db,
        "get_reuse_context",
        json!({"record_id":DOC}),
    )
    .await;
    assert_eq!(
        packet["concerns"]["entries"].as_array().unwrap().len(),
        1,
        "{packet}"
    );
    assert_eq!(packet["concerns"]["entries"][0]["comment_id"], ROOT_OPEN);
    assert!(packet["treatment"]["entries"]
        .as_array()
        .unwrap()
        .is_empty());
    db.close().await;
}

#[tokio::test]
async fn inherited_uncertainty_can_be_expanded_without_losing_entries() {
    use native_ce::freshness::current_record_body_revision;
    let (db, registry) = fixture().await;
    let first = "a0a00000-0000-4000-8000-000000000010";
    let second = "a0a00000-0000-4000-8000-000000000011";
    document(&registry, &db, DOC, "Account.").await;
    document(&registry, &db, first, "First premise.").await;
    document(&registry, &db, second, "Second premise.").await;
    for round in 0..2 {
        let mut sources = Vec::new();
        for id in [first, second] {
            let revision = current_record_body_revision(&db, id).await.unwrap();
            sources.push(
                json!({"record_id":id,"revision_event_id":revision.revision_event_id,
                "role":"Premise","reason":"Used in the authored account."}),
            );
        }
        let output = current_record_body_revision(&db, DOC).await.unwrap();
        call(&registry, &db, "save_account", json!({
            "record_id":DOC,"expected_revision_event_id":output.revision_event_id,
            "body":format!("Authored account {round}."),"sources":sources,
            "idempotency_key":format!("uncertainty-page-{round}"),"reason":"Declare exact premises."
        })).await;
        if round == 0 {
            for id in [first, second] {
                call(
                    &registry,
                    &db,
                    "update_record",
                    json!({
                        "id":id,"body_append":" Revised evidence.","reason":"Change the premise."
                    }),
                )
                .await;
            }
        }
    }
    let first_page = call(
        &registry,
        &db,
        "get_reuse_context",
        json!({"record_id":DOC,"limit":1}),
    )
    .await;
    assert_eq!(first_page["uncertainty"]["truncated"], true);
    let next = &first_page["uncertainty"]["expand_via"];
    let second_page = call(
        &registry,
        &db,
        next["tool"].as_str().unwrap(),
        next["args"].clone(),
    )
    .await;
    assert_eq!(
        first_page["basis"]["receipt_id"],
        second_page["basis"]["receipt_id"]
    );
    assert_eq!(second_page["uncertainty"]["truncated"], false);
    assert_eq!(
        second_page["uncertainty"]["inherited"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_ne!(
        first_page["uncertainty"]["inherited"][0]["dependency_id"],
        second_page["uncertainty"]["inherited"][0]["dependency_id"]
    );
    db.close().await;
}
