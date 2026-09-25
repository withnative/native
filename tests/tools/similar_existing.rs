//! Integration coverage for the advisory `similar_existing` notice on
//! `create_record` and its behaviour under `create_many`.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, render, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

async fn setup() -> (Db, ToolRegistry) {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    (db, registry)
}

async fn create(registry: &ToolRegistry, db: &Db, arguments: Value) -> Value {
    registry
        .call(db.clone(), Caller::local(), "create_record", arguments)
        .await
        .unwrap()
}

async fn bind_account(db: &Db, person: &str, account: &str) {
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical)
         VALUES (?, 'account', ?, 1)",
    )
    .bind(person)
    .bind(account)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

#[tokio::test]
async fn a_near_duplicate_names_the_existing_record() {
    let (db, registry) = setup().await;
    let first = create(
        &registry,
        &db,
        json!({
            "type": "Document",
            "kind": "note",
            "name": "Quarterly logistics manifest",
            "reason": "record the original",
        }),
    )
    .await;
    let second = create(
        &registry,
        &db,
        json!({
            "type": "Document",
            "kind": "note",
            "name": "Quarterly logistics review",
            "reason": "record a near duplicate",
        }),
    )
    .await;
    let items = second["similar_existing"]["items"]
        .as_array()
        .expect("a near duplicate carries the notice");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], first["id"]);
    assert_eq!(
        items[0]["why"]["shared_name_terms"],
        json!(["quarterly", "logistics"])
    );
    db.close().await;
}

#[tokio::test]
async fn a_novel_record_carries_no_notice_at_all() {
    let (db, registry) = setup().await;
    create(
        &registry,
        &db,
        json!({
            "type": "Document",
            "kind": "note",
            "name": "Quarterly logistics manifest",
            "reason": "record the original",
        }),
    )
    .await;
    let novel = create(
        &registry,
        &db,
        json!({
            "type": "Document",
            "kind": "note",
            "name": "Trombone lighthouse garden",
            "reason": "record something unrelated",
        }),
    )
    .await;
    assert!(
        novel.get("similar_existing").is_none(),
        "a novel record must omit the field entirely: {novel}"
    );
    db.close().await;
}

#[tokio::test]
async fn batch_items_never_reference_each_other_but_still_name_outside_matches() {
    let (db, registry) = setup().await;
    let external = create(
        &registry,
        &db,
        json!({
            "type": "Document",
            "kind": "note",
            "name": "Quarterly logistics manifest",
            "reason": "record the pre-existing match",
        }),
    )
    .await;
    let receipt = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_many",
            json!({
                "reason": "create two siblings with the same name",
                "response_mode": "verbose",
                "records": [
                    {"ref": "a", "type": "Document", "kind": "note", "name": "Quarterly logistics manifest"},
                    {"ref": "b", "type": "Document", "kind": "note", "name": "Quarterly logistics manifest"}
                ]
            }),
        )
        .await
        .unwrap();
    let batch_ids = receipt["ids"]
        .as_array()
        .expect("create_many ids")
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for result in receipt["results"].as_array().expect("verbose results") {
        let record = &result["record"];
        let items = record["similar_existing"]["items"]
            .as_array()
            .expect("each item still sees the pre-existing match");
        assert_eq!(items.len(), 1);
        let matched = items[0]["id"].as_str().unwrap();
        assert_eq!(matched, external["id"]);
        assert!(!batch_ids.iter().any(|id| id == matched));
    }
    db.close().await;
}

/// The security property the notice must preserve: a record that matches on
/// name but that the creating caller cannot view must not leak through the
/// advisory. This is the only test that exercises the `visible_ids_in` leg,
/// because every other test calls as `Caller::local()` and bypasses
/// authorization entirely.
#[tokio::test]
async fn an_unviewable_match_never_appears_in_the_notice() {
    let (db, registry) = setup().await;
    let alice = create(
        &registry,
        &db,
        json!({"type": "Entity", "kind": "person", "name": "Alice", "reason": "fixture"}),
    )
    .await;
    let bea = create(
        &registry,
        &db,
        json!({"type": "Entity", "kind": "person", "name": "Bea", "reason": "fixture"}),
    )
    .await;
    bind_account(&db, alice["id"].as_str().unwrap(), "acct:alice").await;
    bind_account(&db, bea["id"].as_str().unwrap(), "acct:bea").await;

    // Two records share the target name exactly. One is visible to alice only;
    // the other is visible to bea. Both qualify on name before authorization.
    let secret = create(
        &registry,
        &db,
        json!({"type": "Document", "kind": "note", "name": "Quarterly logistics manifest", "reason": "fixture"}),
    )
    .await;
    let visible = create(
        &registry,
        &db,
        json!({"type": "Document", "kind": "note", "name": "Quarterly logistics manifest", "reason": "fixture"}),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:similar-secret",
        secret["id"].as_str().unwrap(),
        vec![AllowEntry::account("acct:alice", Capability::View)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:similar-visible",
        visible["id"].as_str().unwrap(),
        vec![AllowEntry::account("acct:bea", Capability::View)],
    )
    .await
    .unwrap();

    let bea_caller = Caller::authenticated("acct:bea").with_hosting_context("host:bea", "db:test");
    let receipt = registry
        .call(
            db.clone(),
            bea_caller,
            "create_record",
            json!({
                "type": "Document",
                "kind": "note",
                "name": "Quarterly logistics manifest",
                "reason": "exercise the visibility boundary",
            }),
        )
        .await
        .unwrap();

    let items = receipt["similar_existing"]["items"]
        .as_array()
        .expect("bea still gets the notice for the record she can see");
    let matched_ids = items
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect::<Vec<_>>();
    assert!(
        matched_ids.contains(&visible["id"].as_str().unwrap()),
        "the visible match must be reported: {receipt}"
    );
    assert!(
        !matched_ids.contains(&secret["id"].as_str().unwrap()),
        "an unviewable match must never be reported: {receipt}"
    );

    // The same must hold in the rendered prose, not only the structured items.
    let prose = render::render("create_record", &receipt).expect("create_record renders");
    assert!(
        prose.contains(visible["id"].as_str().unwrap()),
        "visible match missing from prose: {prose}"
    );
    assert!(
        !prose.contains(secret["id"].as_str().unwrap()),
        "unviewable match leaked into prose: {prose}"
    );
    db.close().await;
}

/// The notice is outside the replayed identity of a keyed command. A keyed
/// create must carry no `similar_existing` on its first call, because the
/// idempotency contract requires a later replay — which reconstructs from the
/// pinned event prefix and cannot reproduce a live-workspace advisory — to
/// return a byte-identical receipt. This pins that decision so it cannot be
/// silently reversed into a replay-identity break.
#[tokio::test]
async fn keyed_creates_suppress_the_notice_so_replays_stay_identical() {
    let (db, registry) = setup().await;
    // A matching record exists, so the notice would otherwise fire.
    create(
        &registry,
        &db,
        json!({
            "type": "Document",
            "kind": "note",
            "name": "Quarterly logistics manifest",
            "reason": "pre-existing match",
        }),
    )
    .await;
    let args = json!({
        "type": "Document",
        "kind": "note",
        "name": "Quarterly logistics manifest",
        "body": "keyed prose",
        "reason": "keyed create",
        "idempotency_key": "similar-replay-key",
    });
    let first = create(&registry, &db, args.clone()).await;
    assert!(
        first.get("similar_existing").is_none(),
        "a keyed create must not carry the notice: {first}"
    );
    let retry = create(&registry, &db, args).await;
    // de24703: the first keyed create returns its act; the replay returns that
    // same act, so the receipts are byte-identical.
    assert!(
        first["act"].is_i64(),
        "first keyed create must return its act: {first}"
    );
    assert_eq!(retry, first, "a keyed replay must be byte-identical");
    db.close().await;
}
