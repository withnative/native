use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};

use native_ce::mcp::{
    register_builtin_tools, register_surface_tools, render, AuthorizationDisposition, Caller,
    ToolKind, ToolRegistry,
};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sqlx::Row;

// Fixture record ids. A record id must be a canonical lowercase v4/v7 UUID,
// so these pinned literals stand in for the readable slugs they name.
// Hardcoded, never generated, so assertions stay deterministic.
/// `visible-comment-root`
const VISIBLE_COMMENT_ROOT: &str = "a0700000-0000-4000-8000-000000000001";
/// `visible-comment-reply`
const VISIBLE_COMMENT_REPLY: &str = "a0700000-0000-4000-8000-000000000002";
/// `moved-comment-root`
const MOVED_COMMENT_ROOT: &str = "a0700000-0000-4000-8000-000000000003";
/// `moved-comment-reply`
const MOVED_COMMENT_REPLY: &str = "a0700000-0000-4000-8000-000000000004";
/// `hidden-comment-root`
const HIDDEN_COMMENT_ROOT: &str = "a0700000-0000-4000-8000-000000000005";
/// `hidden-comment-reply`
const HIDDEN_COMMENT_REPLY: &str = "a0700000-0000-4000-8000-000000000006";
/// `later-comment-root`
const LATER_COMMENT_ROOT: &str = "a0700000-0000-4000-8000-000000000007";

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    mut arguments: Value,
) -> native_ce::Result<Value> {
    if matches!(
        tool,
        "create_record" | "update_record" | "archive_record" | "delete_record"
    ) {
        arguments
            .as_object_mut()
            .expect("tool arguments")
            .entry("reason")
            .or_insert_with(|| json!("authorization integration test"));
    }
    registry.call(db.clone(), caller, tool, arguments).await
}

async fn create_local(registry: &ToolRegistry, db: &Db, arguments: Value) -> String {
    call_as(registry, db, Caller::local(), "create_record", arguments)
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
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

async fn content_event_count(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap()
}

async fn projected_owner(db: &Db, record_id: &str) -> Option<String> {
    sqlx::query_scalar("SELECT owner_id FROM records WHERE id = ?")
        .bind(record_id)
        .fetch_one(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap()
}

async fn projected_home_and_policy_anchor(db: &Db, record_id: &str) -> (Option<String>, String) {
    let row = sqlx::query("SELECT home_id, policy_anchor_id FROM records WHERE id = ?")
        .bind(record_id)
        .fetch_one(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap();
    (
        row.try_get("home_id").unwrap(),
        row.try_get("policy_anchor_id").unwrap(),
    )
}

async fn fixture() -> (Db, ToolRegistry, String, String) {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let alice = create_local(
        &registry,
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "Alice" }),
    )
    .await;
    let bea = create_local(
        &registry,
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "Bea" }),
    )
    .await;
    bind_account(&db, &alice, "acct:alice").await;
    bind_account(&db, &bea, "acct:bea").await;
    (db, registry, alice, bea)
}

#[tokio::test]
async fn update_timestamp_precondition_runs_after_authorization_and_accepts_an_authorized_match() {
    let (db, registry, _alice, _) = fixture().await;
    let record = create_local(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Protected" }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &record,
        vec![AllowEntry::account("acct:alice", Capability::Edit)],
    )
    .await
    .unwrap();
    let read = call_as(
        &registry,
        &db,
        Caller::local(),
        "get_record",
        json!({ "ids": [record.clone()] }),
    )
    .await
    .unwrap();
    let updated_at = read["records"][0]["updated_at"].as_str().unwrap();

    let denied = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:bea")
            .with_hosting_context("host:bea", "db:test")
            .with_hosting_owner(false),
        "update_record",
        json!({
            "id": record,
            "name": "must not land",
            "if_unmodified_since": "not-a-timestamp"
        }),
    )
    .await
    .unwrap_err();
    assert!(denied.to_string().contains("does not exist"), "{denied}");
    assert!(!denied.to_string().contains("RFC3339"), "{denied}");

    let allowed = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:alice")
            .with_hosting_context("host:alice", "db:test")
            .with_hosting_owner(false),
        "update_record",
        json!({
            "id": record,
            "name": "authorized",
            "if_unmodified_since": updated_at
        }),
    )
    .await
    .unwrap();
    assert_eq!(allowed["name"], "authorized");
}

#[tokio::test]
async fn direct_query_tree_and_history_agree_on_visibility_and_redaction() {
    let (db, registry, alice, _) = fixture().await;
    let private = create_local(
        &registry,
        &db,
        json!({
            "type": "Collection", "kind": "folder", "name": "Private",
            "owner_id": alice
        }),
    )
    .await;
    let broad_child = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Shared exception",
            "home_id": private, "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &private,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &broad_child,
        vec![AllowEntry::account("acct:bea", Capability::View)],
    )
    .await
    .unwrap();

    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    let direct = call_as(
        &registry,
        &db,
        bea.clone(),
        "get_record",
        json!({ "ids": [private, broad_child] }),
    )
    .await
    .unwrap();
    assert_eq!(direct["records"][0]["status"], "not_found");
    assert_eq!(direct["records"][1]["status"], "found");
    assert_eq!(direct["records"][1]["home_id"], Value::Null);
    assert!(direct["records"][1]["ancestors"]
        .as_array()
        .unwrap()
        .iter()
        .all(|ancestor| ancestor["id"] != private));

    let query = call_as(
        &registry,
        &db,
        bea.clone(),
        "query_record",
        json!({ "steps": [{ "step": "filter", "ids": [private, broad_child] }] }),
    )
    .await
    .unwrap();
    assert_eq!(query["total"], 1);
    assert_eq!(query["records"][0]["id"], broad_child);
    assert_eq!(query["records"][0]["home_id"], Value::Null);

    let structure = call_as(
        &registry,
        &db,
        bea.clone(),
        "get_structure",
        json!({ "root_id": native_ce::schema::ROOT_RECORD_ID, "max_depth": 8 }),
    )
    .await
    .unwrap();
    let rendered = structure.to_string();
    assert!(!rendered.contains(&private));
    assert!(!rendered.contains(&broad_child));

    let history = call_as(
        &registry,
        &db,
        bea.clone(),
        "get_history",
        json!({ "limit": 1000 }),
    )
    .await
    .unwrap();
    let rendered = history.to_string();
    assert!(!rendered.contains(&private));
    assert!(rendered.contains(&broad_child));
    assert!(history["events"]
        .as_array()
        .unwrap()
        .iter()
        .all(|event| event["actor"].is_null()));

    let hidden = call_as(
        &registry,
        &db,
        bea,
        "get_history",
        json!({ "record_id": private }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(hidden.contains("does not exist"), "{hidden}");

    sqlx::query(
        "INSERT INTO schema_config
            (id, layer, name, data, applies_to_collection_id)
         VALUES ('hidden-schema', 'user', 'Hidden shape', ?, ?)",
    )
    .bind(
        json!({
            "shapes": { "WorkItem": { "facets": {
                "hidden_collection_secret": { "values": ["classified"] }
            } } }
        })
        .to_string(),
    )
    .bind(&private)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    for (tool, arguments) in [
        ("bootstrap", json!({})),
        ("describe_schema", json!({})),
        ("resolve_facets", json!({ "type": "WorkItem" })),
    ] {
        let response = call_as(
            &registry,
            &db,
            Caller::authenticated("acct:bea")
                .with_hosting_context("host:bea", "db:test")
                .with_hosting_owner(false),
            tool,
            arguments,
        )
        .await
        .unwrap();
        assert!(
            !response.to_string().contains("hidden_collection_secret"),
            "{tool} leaked collection-scoped schema from a hidden collection"
        );
    }
    db.close().await;
}

#[tokio::test]
async fn query_reference_selectors_require_view_on_their_roots_across_execution_paths() {
    let (db, registry, alice, _) = fixture().await;
    let hidden_parent = create_local(
        &registry,
        &db,
        json!({
            "type": "Collection", "kind": "folder", "name": "Hidden selector root",
            "owner_id": alice
        }),
    )
    .await;
    let visible_child = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task",
            "name": "Selector override needle",
            "body": "selector-override-search-needle",
            "home_id": hidden_parent, "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &alice,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden_parent,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &visible_child,
        vec![AllowEntry::account("acct:bea", Capability::View)],
    )
    .await
    .unwrap();

    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    let selectors = [
        ("home_id", hidden_parent.as_str()),
        ("ancestor_id", hidden_parent.as_str()),
        ("owner_id", alice.as_str()),
    ];
    for (field, reference) in selectors {
        let mut filter = json!({ "step": "filter" });
        filter[field] = json!(reference);
        let error = call_as(
            &registry,
            &db,
            bea.clone(),
            "query_record",
            json!({ "steps": [filter] }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("does not exist"), "{field}: {error}");
        assert!(error.contains(reference), "{field}: {error}");
    }

    let search_error = call_as(
        &registry,
        &db,
        bea.clone(),
        "search",
        json!({ "query": "selector override needle", "scope": hidden_parent }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(search_error.contains("does not exist"), "{search_error}");
    assert!(search_error.contains(&hidden_parent), "{search_error}");

    let mut saved = Vec::new();
    for (index, (field, reference)) in selectors.into_iter().enumerate() {
        let mut filter = json!({ "step": "filter" });
        filter[field] = json!(reference);
        let envelope = json!({
            "v": "0.2",
            "query": { "steps": [filter] }
        })
        .to_string();
        let carrier = create_local(
            &registry,
            &db,
            json!({
                "type": if index == 0 { "Collection" } else { "Document" },
                "kind": if index == 0 { "query" } else { "note" },
                "name": format!("Saved hidden {field}"),
                "facets": { "query": envelope }
            }),
        )
        .await;
        replace_explicit_policy(
            &db,
            "test:policy",
            &carrier,
            vec![AllowEntry::account("acct:bea", Capability::View)],
        )
        .await
        .unwrap();
        saved.push((field, reference, carrier));
    }
    let resolved = call_as(
        &registry,
        &db,
        bea.clone(),
        "get_record",
        json!({ "ids": saved.iter().map(|(_, _, id)| id).collect::<Vec<_>>() }),
    )
    .await
    .unwrap();
    for (index, (field, reference, _)) in saved.iter().enumerate() {
        let resolution = &resolved["records"][index]["query_resolution"];
        assert_eq!(resolution["status"], "execution_error", "{field}");
        assert!(
            resolution["diagnostic"]
                .as_str()
                .is_some_and(|diagnostic| diagnostic.contains(reference)),
            "{field}: {resolution}"
        );
    }

    let collection_error = call_as(
        &registry,
        &db,
        bea.clone(),
        "open_collection",
        json!({ "id": saved[0].2 }),
    )
    .await
    .unwrap();
    assert_eq!(collection_error["status"], "error");
    assert_eq!(
        collection_error["diagnostic"]["code"],
        "input_resolution_failed"
    );
    assert!(
        collection_error["diagnostic"]["message"]
            .as_str()
            .is_some_and(|message| message.contains(&hidden_parent)),
        "{collection_error}"
    );

    let rollup = create_local(
        &registry,
        &db,
        json!({
            "type": "Document", "kind": "note", "name": "Hidden owner rollup",
            "facets": { "rollup": json!({
                "v": "0.1",
                "outputs": { "count": {
                    "query": { "steps": [{ "step": "filter", "owner_id": alice }] },
                    "fold": { "op": "count" }
                }}
            }).to_string() }
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &rollup,
        vec![AllowEntry::account("acct:bea", Capability::View)],
    )
    .await
    .unwrap();
    let rollup_error = call_as(
        &registry,
        &db,
        bea,
        "resolve_rollup",
        json!({ "record_id": rollup, "rollup_name": "count" }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(rollup_error.contains(&alice), "{rollup_error}");

    for (field, reference) in selectors {
        let mut filter = json!({ "step": "filter" });
        filter[field] = json!(reference);
        let trusted = call_as(
            &registry,
            &db,
            Caller::local(),
            "query_record",
            json!({ "steps": [filter] }),
        )
        .await
        .unwrap();
        assert!(trusted["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["id"] == visible_child));
    }
    db.close().await;
}

#[tokio::test]
async fn visible_totals_are_computed_before_windows_and_link_endpoints_are_guarded() {
    let (db, registry, alice, _) = fixture().await;
    let folder = create_local(
        &registry,
        &db,
        json!({
            "type": "Collection", "kind": "folder", "name": "Visible folder",
            "owner_id": alice
        }),
    )
    .await;
    let hidden = create_local(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "A hidden", "home_id": folder }),
    )
    .await;
    let visible_b = create_local(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "B visible", "home_id": folder }),
    )
    .await;
    let visible_c = create_local(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "C visible", "home_id": folder }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &folder,
        vec![AllowEntry::account("acct:bea", Capability::Edit)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();

    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    let out = call_as(
        &registry,
        &db,
        bea.clone(),
        "get_record",
        json!({ "ids": [folder], "children_limit": 1 }),
    )
    .await
    .unwrap();
    assert_eq!(out["records"][0]["child_count"], 2);
    assert_eq!(out["records"][0]["children"].as_array().unwrap().len(), 1);
    assert_eq!(out["records"][0]["children"][0]["id"], visible_b);

    // More hidden siblings than the raw tree ceiling must not crowd the first
    // visible child out of a one-row structure window.
    sqlx::query(
        "WITH RECURSIVE n(value) AS (
             SELECT 0 UNION ALL SELECT value + 1 FROM n WHERE value < 1000
         )
         INSERT INTO records
             (id, type, kind, name, home_id, policy_anchor_id, persistence)
         SELECT printf('wide-hidden-%04d', value), 'WorkItem', 'task',
                printf('A hidden %04d', value), ?,
                printf('wide-hidden-%04d', value), 'enduring'
           FROM n",
    )
    .bind(&folder)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO record_policies (record_id)
         SELECT id FROM records WHERE id LIKE 'wide-hidden-%'",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO policy_entries
             (policy_anchor_id, subject_kind, subject_id, effect, capability)
         SELECT id, 'account', 'acct:alice', 'allow', 'manage'
           FROM records WHERE id LIKE 'wide-hidden-%'",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let structure = call_as(
        &registry,
        &db,
        bea.clone(),
        "get_structure",
        json!({
            "root_id": folder, "max_depth": 1,
            "max_children_per_node": 1
        }),
    )
    .await
    .unwrap();
    assert_eq!(structure["nodes"].as_array().unwrap().len(), 2);
    assert_eq!(structure["nodes"][1]["id"], visible_b);

    let denied = call_as(
        &registry,
        &db,
        bea.clone(),
        "manage_links",
        json!({
            "action": "add", "source_id": folder, "target_id": hidden,
            "relationship": "a_hidden_first"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(denied.contains("does not exist"), "{denied}");

    call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_links",
        json!({
            "action": "add", "source_id": folder, "target_id": hidden,
            "relationship": "a_hidden_first"
        }),
    )
    .await
    .unwrap();
    call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_links",
        json!({
            "action": "add", "source_id": folder, "target_id": visible_c,
            "relationship": "z_visible_second"
        }),
    )
    .await
    .unwrap();
    let visible_links = call_as(
        &registry,
        &db,
        bea.clone(),
        "manage_links",
        json!({ "action": "list", "record_id": folder, "limit": 1 }),
    )
    .await
    .unwrap();
    assert_eq!(visible_links["action"], "list");
    assert_eq!(visible_links["format"], "native.manage-links-list.v1");
    assert_eq!(visible_links["viewer_relative"], true);
    assert_eq!(visible_links["query_basis"], "live_at_each_page_read");
    assert_eq!(
        visible_links["scope"],
        "opposite_endpoint_viewable_at_read_time"
    );
    assert_eq!(visible_links["limit"], 1);
    assert!(visible_links.get("candidate_window_returned").is_none());
    assert!(visible_links.get("candidates_evaluated").is_none());
    assert_eq!(visible_links["returned"], 0);
    assert_eq!(visible_links["has_more"], true);
    let visible_cursor = visible_links["next_cursor"].as_str().unwrap();
    assert_eq!(visible_links["next_call"]["action"], "list");
    assert_eq!(visible_links["next_call"]["record_id"], folder);
    assert_eq!(visible_links["next_call"]["limit"], 1);
    assert_eq!(visible_links["next_call"]["cursor"], visible_cursor);
    assert!(visible_links["links_out"].as_array().unwrap().is_empty());
    assert!(visible_links["links_in"].as_array().unwrap().is_empty());
    assert!(
        !visible_links.to_string().contains(&hidden),
        "a viewer-relative page disclosed a hidden opposite endpoint: {visible_links}"
    );
    let rendered_visible_links = render::render("manage_links", &visible_links).unwrap();
    assert!(
        rendered_visible_links.starts_with("Link list returned 0 caller-visible row(s)"),
        "{rendered_visible_links}"
    );
    assert!(
        rendered_visible_links.contains("Next manage_links request:"),
        "{rendered_visible_links}"
    );
    assert!(
        !rendered_visible_links.contains(&hidden),
        "hidden opposite endpoint entered rendered text: {rendered_visible_links}"
    );
    assert!(
        rendered_visible_links.contains(
            "Rows are authorization-filtered by opposite-endpoint visibility at this read"
        ),
        "{rendered_visible_links}"
    );
    let continued_visible_links = call_as(
        &registry,
        &db,
        bea.clone(),
        "manage_links",
        json!({
            "action": "list", "record_id": folder, "limit": 1,
            "cursor": visible_cursor
        }),
    )
    .await
    .unwrap();
    assert_eq!(continued_visible_links["action"], "list");
    assert_eq!(continued_visible_links["cursor"], visible_cursor);
    assert!(continued_visible_links
        .get("candidate_window_returned")
        .is_none());
    assert!(continued_visible_links
        .get("candidates_evaluated")
        .is_none());
    assert_eq!(continued_visible_links["returned"], 1);
    assert_eq!(continued_visible_links["has_more"], false);
    assert!(continued_visible_links["next_cursor"].is_null());
    assert_eq!(
        continued_visible_links["links_out"][0]["target_id"],
        visible_c
    );
    assert!(
        !continued_visible_links.to_string().contains(&hidden),
        "a continued viewer-relative page disclosed a hidden endpoint: {continued_visible_links}"
    );
    let rendered_continued_links =
        render::render("manage_links", &continued_visible_links).unwrap();
    assert!(
        rendered_continued_links.starts_with("Link list returned 1 caller-visible row(s)"),
        "{rendered_continued_links}"
    );
    assert!(
        rendered_continued_links.contains(&visible_c),
        "{rendered_continued_links}"
    );
    assert!(
        !rendered_continued_links.contains(&hidden),
        "hidden endpoint entered continued rendered text: {rendered_continued_links}"
    );
    assert!(
        rendered_continued_links
            .contains("No continuation cursor was issued; this live candidate scan is exhausted."),
        "{rendered_continued_links}"
    );
    let out = call_as(
        &registry,
        &db,
        bea,
        "get_record",
        json!({ "ids": [folder], "links_limit": 1 }),
    )
    .await
    .unwrap();
    assert_eq!(out["records"][0]["links_out_count"], 1);
    assert_eq!(out["records"][0]["links_out"].as_array().unwrap().len(), 1);
    assert_eq!(out["records"][0]["links_out"][0]["target_id"], visible_c);
    db.close().await;
}

#[tokio::test]
async fn structure_live_and_as_of_redact_parent_and_count_only_visible_children() {
    let (db, registry, alice, _) = fixture().await;
    let hidden_parent = create_local(
        &registry,
        &db,
        json!({
            "type": "Collection", "kind": "folder", "name": "Hidden parent",
            "owner_id": alice
        }),
    )
    .await;
    let visible_root = create_local(
        &registry,
        &db,
        json!({
            "type": "Collection", "kind": "folder", "name": "Visible root",
            "home_id": hidden_parent, "owner_id": alice
        }),
    )
    .await;
    let hidden_child = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "A hidden child",
            "home_id": visible_root, "owner_id": alice
        }),
    )
    .await;
    let visible_child = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "B visible child",
            "home_id": visible_root, "owner_id": alice
        }),
    )
    .await;
    let excluded_child = create_local(
        &registry,
        &db,
        json!({
            "type": "Document", "kind": "note", "name": "C excluded child",
            "home_id": visible_root, "owner_id": alice
        }),
    )
    .await;
    let as_of: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden_parent,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &visible_root,
        vec![AllowEntry::account("acct:bea", Capability::View)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden_child,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();

    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    for arguments in [
        json!({
            "root_id": visible_root, "max_depth": 1,
            "max_children_per_node": 1
        }),
        json!({
            "root_id": visible_root, "max_depth": 1,
            "max_children_per_node": 1,
            "as_of": { "content_seq": as_of }
        }),
    ] {
        let structure = call_as(&registry, &db, bea.clone(), "get_structure", arguments)
            .await
            .unwrap();
        assert_eq!(structure["nodes"][0]["home_id"], Value::Null);
        assert_eq!(structure["nodes"][0]["child_count"], 2);
        assert_eq!(structure["nodes"].as_array().unwrap().len(), 2);
        assert_eq!(structure["nodes"][1]["id"], visible_child);
        assert!(!structure.to_string().contains(&hidden_parent));
        assert!(!structure.to_string().contains(&hidden_child));
    }
    for arguments in [
        json!({
            "root_id": visible_root, "max_depth": 1,
            "max_children_per_node": 1, "exclude_types": ["Document"]
        }),
        json!({
            "root_id": visible_root, "max_depth": 1,
            "max_children_per_node": 1, "exclude_types": ["Document"],
            "as_of": { "content_seq": as_of }
        }),
    ] {
        let structure = call_as(&registry, &db, bea.clone(), "get_structure", arguments)
            .await
            .unwrap();
        assert_eq!(structure["nodes"][0]["child_count"], 1);
        assert_eq!(structure["nodes"].as_array().unwrap().len(), 2);
        assert_eq!(structure["nodes"][1]["id"], visible_child);
        assert!(!structure.to_string().contains(&hidden_child));
        assert!(!structure.to_string().contains(&excluded_child));
    }
    db.close().await;
}

#[tokio::test]
async fn disconnected_direct_grant_exposes_safe_home_facts_without_hidden_ancestry() {
    let (db, registry, alice, _) = fixture().await;
    let hidden = create_local(
        &registry,
        &db,
        json!({
            "type": "Collection", "kind": "folder", "name": "Hidden ancestor",
            "owner_id": alice
        }),
    )
    .await;
    let granted_folder = create_local(
        &registry,
        &db,
        json!({
            "type": "Collection", "kind": "folder", "name": "Granted folder",
            "home_id": hidden, "owner_id": alice
        }),
    )
    .await;
    let granted_record = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Granted task",
            "home_id": granted_folder, "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &granted_folder,
        vec![AllowEntry::account("acct:bea", Capability::View)],
    )
    .await
    .unwrap();

    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    let root = call_as(
        &registry,
        &db,
        bea.clone(),
        "get_structure",
        json!({ "root_id": native_ce::schema::ROOT_RECORD_ID, "max_depth": 8 }),
    )
    .await
    .unwrap();
    assert!(!root.to_string().contains(&hidden));
    assert!(!root.to_string().contains(&granted_folder));
    assert!(!root.to_string().contains(&granted_record));

    let direct = call_as(
        &registry,
        &db,
        bea.clone(),
        "get_record",
        json!({ "ids": [granted_folder.clone(), granted_record.clone()] }),
    )
    .await
    .unwrap();
    assert_eq!(direct["records"][0]["custody_boundary"], true);
    assert_eq!(direct["records"][0]["containment_path_visible"], false);
    assert_eq!(direct["records"][0]["home_id"], Value::Null);
    assert_eq!(direct["records"][1]["containment_path_visible"], false);
    assert_eq!(direct["records"][1]["home_id"], granted_folder);
    assert!(!direct.to_string().contains(&hidden));
    assert!(!direct.to_string().contains("policy_anchor_id"));

    let isolated_tree = call_as(
        &registry,
        &db,
        bea.clone(),
        "get_structure",
        json!({ "root_id": granted_folder, "max_depth": 1 }),
    )
    .await
    .unwrap();
    assert_eq!(isolated_tree["nodes"][0]["custody_boundary"], true);
    assert_eq!(isolated_tree["nodes"][0]["containment_path_visible"], false);
    assert!(isolated_tree["nodes"][0]["last_activity_at"].is_string());
    assert!(!isolated_tree.to_string().contains(&hidden));
    assert!(!isolated_tree.to_string().contains("policy_anchor_id"));

    let rows = call_as(
        &registry,
        &db,
        bea.clone(),
        "query_record",
        json!({ "steps": [{ "step": "filter", "ids": [granted_record.clone()] }] }),
    )
    .await
    .unwrap();
    assert_eq!(rows["records"][0]["id"], granted_record);
    assert_eq!(rows["records"][0]["containment_path_visible"], false);
    assert!(!rows.to_string().contains(&hidden));
    assert!(!rows.to_string().contains("policy_anchor_id"));

    let counts = call_as(
        &registry,
        &db,
        bea,
        "query_record",
        json!({ "steps": [{ "step": "filter", "ids": [granted_record] }], "count_by": "kind" }),
    )
    .await
    .unwrap();
    assert_eq!(counts["shape"], "counts");
    assert_eq!(counts["total"], 1);
    assert_eq!(counts["buckets"][0], json!({ "key": "task", "count": 1 }));
    db.close().await;
}

#[tokio::test]
async fn historical_artifact_windows_use_current_bearer_authorization_before_paging() {
    let (db, registry, alice, _) = fixture().await;
    let visible_bearer = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Visible bearer",
            "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &visible_bearer,
        vec![AllowEntry::account("acct:bea", Capability::View)],
    )
    .await
    .unwrap();
    let hidden_bearer = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Hidden bearer",
            "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden_bearer,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let tombstoned_bearer = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Tombstoned bearer",
            "owner_id": alice
        }),
    )
    .await;
    let source = create_local(
        &registry,
        &db,
        json!({
            "type": "Document", "kind": "note", "name": "Source",
            "body": "quoted evidence"
        }),
    )
    .await;
    let moved_suggestion = create_local(
        &registry,
        &db,
        json!({
            "type": "Annotation", "kind": "suggestion", "lifecycle": "open", "name": "Moved suggestion",
            "body": "hidden now", "facets": { "proposal.precondition": "none" },
            "links": [{ "target_id": visible_bearer, "relationship": "part_of" }]
        }),
    )
    .await;
    let visible_suggestion = create_local(
        &registry,
        &db,
        json!({
            "type": "Annotation", "kind": "suggestion", "lifecycle": "open", "name": "Visible suggestion",
            "body": "still visible", "facets": { "proposal.precondition": "none" },
            "links": [{ "target_id": visible_bearer, "relationship": "part_of" }]
        }),
    )
    .await;
    let malformed_suggestion = create_local(
        &registry,
        &db,
        json!({
            "type": "Annotation", "kind": "suggestion", "lifecycle": "open", "name": "Malformed suggestion",
            "body": "two bearers now", "facets": { "proposal.precondition": "none" },
            "links": [{ "target_id": visible_bearer, "relationship": "part_of" }]
        }),
    )
    .await;
    let moved_citation = create_local(
        &registry,
        &db,
        json!({
            "type": "Annotation", "kind": "citation", "name": "Moved citation",
            "body": "citation", "links": [{
                "target_id": visible_bearer, "relationship": "part_of"
            }],
            "target": {
                "target_record_id": source, "source_slot": "body",
                "purpose": "extracted_from",
                "selectors": [{ "type": "text_quote", "exact": "quoted evidence" }]
            }
        }),
    )
    .await;
    let as_of: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();

    sqlx::query(
        "UPDATE links SET target_id = ?
          WHERE source_id = ? AND relationship = 'part_of'",
    )
    .bind(&hidden_bearer)
    .bind(&moved_suggestion)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE links SET target_id = ?
          WHERE source_id = ? AND relationship = 'part_of'",
    )
    .bind(&tombstoned_bearer)
    .bind(&moved_citation)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE records SET deleted_at = '2026-08-02T00:00:00.000Z'
          WHERE id = ?",
    )
    .bind(&tombstoned_bearer)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO links (id, source_id, target_id, relationship)
         VALUES ('malformed-current-bearer', ?, ?, 'part_of')",
    )
    .bind(&malformed_suggestion)
    .bind(&hidden_bearer)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    let historical = call_as(
        &registry,
        &db,
        bea,
        "get_record",
        json!({
            "ids": [visible_bearer],
            "as_of": { "content_seq": as_of },
            "include_suggestions": true, "suggestions_limit": 1,
            "include_citations": true, "citations_limit": 1
        }),
    )
    .await
    .unwrap();
    let record = &historical["records"][0];
    assert_eq!(record["suggestion_count"], 1);
    assert_eq!(record["suggestions"].as_array().unwrap().len(), 1);
    assert_eq!(record["suggestions"][0]["id"], visible_suggestion);
    assert_eq!(record["citation_count"], 0);
    assert!(record["citations"].as_array().unwrap().is_empty());
    assert!(!historical.to_string().contains(&moved_suggestion));
    assert!(!historical.to_string().contains(&malformed_suggestion));
    assert!(!historical.to_string().contains(&moved_citation));
    db.close().await;
}

#[tokio::test]
async fn comment_roots_replies_and_history_follow_their_current_live_bearer_policy() {
    let (db, registry, alice, _) = fixture().await;
    let visible_bearer = create_local(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Visible comments", "body": "Visible anchored passage" }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &visible_bearer,
        vec![AllowEntry::account("acct:bea", Capability::View)],
    )
    .await
    .unwrap();
    let hidden_bearer = create_local(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Hidden comments" }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden_bearer,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let make_comment = |id: &str, bearer: &str, body: &str| {
        json!({
            "id": id, "type": "Annotation", "kind": "comment", "body": body,
            "lifecycle": "open",
            "links": [{ "target_id": bearer, "relationship": "part_of" }]
        })
    };
    let stable_root = create_local(
        &registry,
        &db,
        json!({
            "id": VISIBLE_COMMENT_ROOT, "type": "Annotation", "kind": "comment",
            "body": "Stable root", "lifecycle": "open",
            "links": [{ "target_id": visible_bearer, "relationship": "part_of" }],
            "target": {
                "target_record_id": visible_bearer, "source_slot": "body",
                "selectors": [{ "type": "text_quote", "exact": "anchored passage" }]
            }
        }),
    )
    .await;
    let stable_reply = create_local(
        &registry,
        &db,
        json!({
            "id": VISIBLE_COMMENT_REPLY, "type": "Annotation", "kind": "comment",
            "body": "Stable reply",
            "links": [{ "target_id": stable_root, "relationship": "part_of" }]
        }),
    )
    .await;
    let moved_root = create_local(
        &registry,
        &db,
        make_comment(MOVED_COMMENT_ROOT, &visible_bearer, "Moved root"),
    )
    .await;
    let moved_reply = create_local(
        &registry,
        &db,
        json!({
            "id": MOVED_COMMENT_REPLY, "type": "Annotation", "kind": "comment",
            "body": "Moved reply",
            "links": [{ "target_id": moved_root, "relationship": "part_of" }]
        }),
    )
    .await;
    let hidden_root = create_local(
        &registry,
        &db,
        make_comment(HIDDEN_COMMENT_ROOT, &hidden_bearer, "Hidden root"),
    )
    .await;
    let hidden_reply = create_local(
        &registry,
        &db,
        json!({
            "id": HIDDEN_COMMENT_REPLY, "type": "Annotation", "kind": "comment",
            "body": "Hidden reply",
            "links": [{ "target_id": hidden_root, "relationship": "part_of" }]
        }),
    )
    .await;
    let as_of: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let later_root = create_local(
        &registry,
        &db,
        make_comment(LATER_COMMENT_ROOT, &visible_bearer, "Later root"),
    )
    .await;
    sqlx::query(
        "UPDATE links SET target_id = ?
          WHERE source_id = ? AND relationship = 'part_of'",
    )
    .bind(&hidden_bearer)
    .bind(&moved_root)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    let direct = call_as(
        &registry,
        &db,
        bea.clone(),
        "get_record",
        json!({ "ids": [stable_root, stable_reply, hidden_root, hidden_reply] }),
    )
    .await
    .unwrap();
    assert_eq!(direct["records"][0]["status"], "found");
    assert_eq!(
        direct["records"][0]["target"]["anchored"]["excerpt"]["text"],
        "anchored passage"
    );
    assert_eq!(direct["records"][1]["status"], "found");
    assert_eq!(direct["records"][1]["target"]["annotation_id"], stable_root);
    assert_eq!(
        direct["records"][1]["target"]["anchored"]["excerpt"]["text"],
        "anchored passage"
    );
    assert_eq!(direct["records"][2]["status"], "not_found");
    assert_eq!(direct["records"][3]["status"], "not_found");

    let historical = call_as(
        &registry,
        &db,
        bea.clone(),
        "get_record",
        json!({
            "ids": [visible_bearer],
            "as_of": { "content_seq": as_of },
            "include_comments": true, "comments_limit": 10
        }),
    )
    .await
    .unwrap();
    assert_eq!(historical["records"][0]["comment_count"], 1);
    assert_eq!(historical["records"][0]["comments"][0]["id"], stable_root);
    assert_eq!(
        historical["records"][0]["comments"][0]["target"]["anchored"]["excerpt"]["text"],
        "anchored passage"
    );
    assert!(!historical.to_string().contains(&moved_root));
    assert!(!historical.to_string().contains(&later_root));

    let historical_replies = call_as(
        &registry,
        &db,
        bea.clone(),
        "get_record",
        json!({
            "ids": [stable_root],
            "as_of": { "content_seq": as_of },
            "include_comments": true
        }),
    )
    .await
    .unwrap();
    assert_eq!(historical_replies["records"][0]["comment_count"], 1);
    assert_eq!(
        historical_replies["records"][0]["comments"][0]["id"],
        stable_reply
    );
    assert_eq!(
        historical_replies["records"][0]["comments"][0]["target"]["annotation_id"],
        stable_root
    );

    let historical_direct_reply = call_as(
        &registry,
        &db,
        bea.clone(),
        "get_record",
        json!({
            "ids": [stable_reply],
            "as_of": { "content_seq": as_of }
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        historical_direct_reply["records"][0]["target"]["annotation_id"],
        stable_root
    );
    assert_eq!(
        historical_direct_reply["records"][0]["target"]["anchored"]["excerpt"]["text"],
        "anchored passage"
    );

    let explicit = call_as(
        &registry,
        &db,
        bea,
        "query_record",
        json!({ "steps": [{ "step": "filter", "kinds": ["comment"] }] }),
    )
    .await
    .unwrap();
    assert_eq!(explicit["total"], 3);
    let rendered = explicit.to_string();
    assert!(rendered.contains(&stable_root));
    assert!(rendered.contains(&stable_reply));
    assert!(rendered.contains(&later_root));
    assert!(!rendered.contains(&moved_root));
    assert!(!rendered.contains(&moved_reply));
    assert!(!rendered.contains(&hidden_root));
    assert!(!rendered.contains(&hidden_reply));
    assert!(!rendered.contains(&alice));
    db.close().await;
}

#[tokio::test]
async fn run_activity_authorizes_derived_touches_through_their_current_bearer() {
    const RUN: &str = "heron-river-c748b2";

    let (db, registry, alice, _) = fixture().await;
    let hidden_bearer = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Hidden bearer",
            "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden_bearer,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let visible_bearer = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Visible bearer",
            "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &visible_bearer,
        vec![AllowEntry::account("acct:bea", Capability::View)],
    )
    .await
    .unwrap();

    let hidden_annotation = create_local(
        &registry,
        &db,
        json!({
            "type": "Annotation", "kind": "suggestion", "lifecycle": "open", "name": "Hidden annotation",
            "body": "hidden", "facets": { "proposal.precondition": "none" },
            "links": [{ "target_id": hidden_bearer, "relationship": "part_of" }]
        }),
    )
    .await;
    let visible_annotation = create_local(
        &registry,
        &db,
        json!({
            "type": "Annotation", "kind": "suggestion", "lifecycle": "open", "name": "Visible annotation",
            "body": "visible", "facets": { "proposal.precondition": "none" },
            "links": [{ "target_id": visible_bearer, "relationship": "part_of" }]
        }),
    )
    .await;
    let malformed_annotation = create_local(
        &registry,
        &db,
        json!({
            "type": "Annotation", "kind": "suggestion", "lifecycle": "open", "name": "Malformed annotation",
            "body": "malformed", "facets": { "proposal.precondition": "none" },
            "links": [{ "target_id": hidden_bearer, "relationship": "part_of" }]
        }),
    )
    .await;
    let attachment = call_as(
        &registry,
        &db,
        Caller::local(),
        "attach_text",
        json!({ "record_id": hidden_bearer, "text": "hidden attachment" }),
    )
    .await
    .unwrap()["attachment_id"]
        .as_str()
        .unwrap()
        .to_string();
    for artifact in [&hidden_annotation, &malformed_annotation, &attachment] {
        replace_explicit_policy(
            &db,
            "test:policy",
            artifact,
            vec![AllowEntry::account("acct:bea", Capability::Manage)],
        )
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO links (id, source_id, target_id, relationship)
         VALUES ('run-activity-malformed-bearer', ?, ?, 'part_of')",
    )
    .bind(&malformed_annotation)
    .bind(&visible_bearer)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let call_seq: i64 = sqlx::query_scalar(
        "INSERT INTO read_log_calls
            (id, tool, run_key, actor, outcome, started_at, ended_at)
         VALUES ('run-activity-derived-touch', 'query_record', ?, 'acct:bea', 'ok',
                 '2026-08-02T00:00:00.000Z', '2026-08-02T00:00:00.001Z')
         RETURNING seq",
    )
    .bind(RUN)
    .fetch_one(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    for record_id in [
        &hidden_annotation,
        &visible_annotation,
        &malformed_annotation,
        &attachment,
    ] {
        sqlx::query(
            "INSERT INTO read_log_touches (call_seq, record_id, interaction)
             VALUES (?, ?, 'surfaced')",
        )
        .bind(call_seq)
        .bind(record_id)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    }

    let activity = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:bea")
            .with_hosting_context("host:bea", "db:test")
            .with_hosting_owner(false),
        "get_run_activity",
        json!({ "for_run": RUN }),
    )
    .await
    .unwrap();
    assert_eq!(activity["read_activity"].as_array().unwrap().len(), 1);
    assert_eq!(activity["read_activity"][0]["run_key"], RUN);
    assert_eq!(activity["read_activity"][0]["searches"], 0);
    assert_eq!(activity["read_activity"][0]["surfaced"], 1);
    assert_eq!(activity["read_activity"][0]["opened"], 0);
    assert_eq!(activity["read_activity"][0]["mutated"], 0);
    db.close().await;
}

#[tokio::test]
async fn claim_unowned_record_enforces_host_owner_view_and_self_claim_boundaries() {
    let (db, registry, alice, _) = fixture().await;
    let claimable = create_local(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Ownerless" }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &claimable,
        vec![AllowEntry::account("acct:alice", Capability::View)],
    )
    .await
    .unwrap();
    let hosted_owner = Caller::authenticated("acct:alice")
        .with_hosting_context("host:alice", "db:test")
        .with_hosting_owner(true);
    let before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id = ? AND type = 'record.updated'",
    )
    .bind(&claimable)
    .fetch_one(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let claimed = call_as(
        &registry,
        &db,
        hosted_owner.clone(),
        "claim_unowned_record",
        json!({ "record_id": claimable, "reason": "Recover abandoned work" }),
    )
    .await
    .unwrap();
    assert_eq!(claimed["id"], claimable);
    assert_eq!(claimed["owner_id"], alice);
    assert!(claimed["event_id"].is_string());
    assert!(claimed["event_seq"].is_number());
    assert!(claimed["previous_seq"].is_number());
    let event = sqlx::query(
        "SELECT payload, actor FROM content_events WHERE record_id = ? AND type = 'record.updated' ORDER BY seq DESC LIMIT 1",
    )
    .bind(&claimable)
    .fetch_one(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let payload: Value =
        serde_json::from_str(event.try_get::<String, _>("payload").unwrap().as_str()).unwrap();
    assert_eq!(payload["owner_id"], alice);
    assert_eq!(payload["reason"], "Recover abandoned work");
    assert_eq!(payload["ownership_recovery"], "host_owner_self_claim.v1");
    assert_eq!(event.try_get::<String, _>("actor").unwrap(), "acct:alice");
    let after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id = ? AND type = 'record.updated'",
    )
    .bind(&claimable)
    .fetch_one(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    assert_eq!(after, before + 1);
    assert_eq!(
        native_ce::authorization::effective_capability(
            &db,
            native_ce::authorization::Principal::bound("acct:alice", true),
            &claimable,
        )
        .await
        .unwrap(),
        Capability::Manage
    );
    let replay = native_ce::conformance::rebuild_and_diff(&db).await.unwrap();
    assert!(
        replay.equal,
        "claim diverged on replay: {:?}",
        replay.tables
    );
    call_as(
        &registry,
        &db,
        hosted_owner.clone(),
        "archive_record",
        json!({ "id": claimable, "reason": "Prove owner-derived Manage" }),
    )
    .await
    .unwrap();

    let managed_but_not_host_owner = create_local(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Manager cannot claim" }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &managed_but_not_host_owner,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let before_non_owner_denial = content_event_count(&db).await;
    let denied = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:alice")
            .with_hosting_context("host:alice", "db:test")
            .with_hosting_owner(false),
        "claim_unowned_record",
        json!({ "record_id": managed_but_not_host_owner, "reason": "Must fail" }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(
        denied,
        "claim_unowned_record: host-owner authority is required"
    );
    assert_eq!(content_event_count(&db).await, before_non_owner_denial);
    assert_eq!(
        projected_owner(&db, &managed_but_not_host_owner).await,
        None
    );

    for id in [
        "abc12300-0000-4000-8000-000000000001",
        "abc12300-0000-4000-8000-000000000002",
    ] {
        create_local(
            &registry,
            &db,
            json!({ "id": id, "type": "Document", "kind": "note", "name": "Ambiguous" }),
        )
        .await;
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            vec![AllowEntry::account("acct:alice", Capability::Manage)],
        )
        .await
        .unwrap();
    }
    let before_prefix_denial = content_event_count(&db).await;
    let prefix_denial = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:alice")
            .with_hosting_context("host:alice", "db:test")
            .with_hosting_owner(false),
        "claim_unowned_record",
        json!({ "record_id": "abc123", "reason": "Must fail before resolution" }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(
        prefix_denial,
        "claim_unowned_record: host-owner authority is required"
    );
    assert_eq!(content_event_count(&db).await, before_prefix_denial);
    let exact_id_denial = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:alice")
            .with_hosting_context("host:alice", "db:test")
            .with_hosting_owner(true),
        "claim_unowned_record",
        json!({ "record_id": "abc123", "reason": "Exact ids only" }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(
        exact_id_denial,
        "claim_unowned_record: record_id must be an exact canonical lowercase UUID of version 4 or 7"
    );
    assert_eq!(content_event_count(&db).await, before_prefix_denial);

    let hidden = create_local(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Hidden ownerless" }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden,
        vec![AllowEntry::account("acct:bea", Capability::View)],
    )
    .await
    .unwrap();
    let before_hidden_and_missing = content_event_count(&db).await;
    let hidden_error = call_as(
        &registry,
        &db,
        hosted_owner,
        "claim_unowned_record",
        json!({ "record_id": hidden, "reason": "Must stay hidden" }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(
        hidden_error,
        format!("claim_unowned_record: record {hidden} does not exist")
    );
    let missing = "a0700000-0000-4000-8000-000000000098";
    let missing_error = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:alice")
            .with_hosting_context("host:alice", "db:test")
            .with_hosting_owner(true),
        "claim_unowned_record",
        json!({ "record_id": missing, "reason": "Must stay missing" }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(
        missing_error,
        format!("claim_unowned_record: record {missing} does not exist")
    );
    assert_eq!(content_event_count(&db).await, before_hidden_and_missing);
    assert_eq!(projected_owner(&db, &hidden).await, None);

    let standalone = create_local(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Standalone claim" }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &standalone,
        vec![AllowEntry::account("acct:alice", Capability::View)],
    )
    .await
    .unwrap();
    call_as(
        &registry,
        &db,
        Caller::authenticated("acct:alice"),
        "claim_unowned_record",
        json!({ "record_id": standalone, "reason": "Standalone recovery" }),
    )
    .await
    .unwrap();

    let unbound = create_local(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "No binding" }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &unbound,
        vec![AllowEntry::account("acct:unbound", Capability::View)],
    )
    .await
    .unwrap();
    let before_unbound_denial = content_event_count(&db).await;
    let unbound_error = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:unbound"),
        "claim_unowned_record",
        json!({ "record_id": unbound, "reason": "No identity" }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(unbound_error.contains("exactly one live canonical person binding"));
    assert_eq!(content_event_count(&db).await, before_unbound_denial);
    assert_eq!(projected_owner(&db, &unbound).await, None);

    let ownerless_update = create_local(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "No update adoption" }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &ownerless_update,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let before_update_denial = content_event_count(&db).await;
    let update_error = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:alice"),
        "update_record",
        json!({ "id": ownerless_update, "owner_id": alice }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(update_error.contains("reserved to the record's current owner"));
    assert_eq!(content_event_count(&db).await, before_update_denial);
    assert_eq!(projected_owner(&db, &ownerless_update).await, None);
    db.close().await;
}

#[tokio::test]
async fn claim_unowned_record_refuses_owned_and_derived_records_without_writing() {
    let (db, registry, alice, _) = fixture().await;
    let bearer = create_local(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Bearer" }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &bearer,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let owned = create_local(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Owned", "owner_id": alice }),
    )
    .await;
    let message = native_ce::store::create_record(
        &db,
        json!({
            "type": "Message", "kind": "message", "name": "Message",
            "body": "Body", "owner_id": alice
        }),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE records SET owner_id = NULL WHERE id = ?")
        .bind(&message)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &message,
        vec![AllowEntry::account("acct:alice", Capability::View)],
    )
    .await
    .unwrap();
    let annotation = create_local(
        &registry,
        &db,
        json!({
            "type": "Annotation", "kind": "comment", "name": "Comment", "body": "Comment",
            "links": [{ "target_id": bearer, "relationship": "part_of" }]
        }),
    )
    .await;
    let attachment = call_as(
        &registry,
        &db,
        Caller::local(),
        "attach_text",
        json!({ "record_id": bearer, "text": "attachment" }),
    )
    .await
    .unwrap()["attachment_id"]
        .as_str()
        .unwrap()
        .to_string();
    let unit = create_local(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Unit envelope" }),
    )
    .await;
    let creation = sqlx::query(
        "SELECT id, seq, created_at FROM content_events WHERE record_id = ? AND type = 'record.created'",
    )
    .bind(&unit)
    .fetch_one(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO semantic_units
            (unit_id, authority_bearer_record_id, creation_event_id, creation_event_seq, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&unit)
    .bind(&bearer)
    .bind(creation.try_get::<String, _>("id").unwrap())
    .bind(creation.try_get::<i64, _>("seq").unwrap())
    .bind(creation.try_get::<String, _>("created_at").unwrap())
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let caller = Caller::authenticated("acct:alice")
        .with_hosting_context("host:alice", "db:test")
        .with_hosting_owner(true);
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    for id in [
        native_ce::schema::ROOT_RECORD_ID,
        native_ce::schema::UNFILED_RECORD_ID,
    ] {
        let error = call_as(
            &registry,
            &db,
            caller.clone(),
            "claim_unowned_record",
            json!({ "record_id": id, "reason": "Must be refused" }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("exact canonical lowercase UUID"),
            "{id}: {error}"
        );
    }
    for id in [
        owned.as_str(),
        message.as_str(),
        annotation.as_str(),
        attachment.as_str(),
        unit.as_str(),
    ] {
        let error = call_as(
            &registry,
            &db,
            caller.clone(),
            "claim_unowned_record",
            json!({ "record_id": id, "reason": "Must be refused" }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("not eligible for ownership recovery"),
            "{id}: {error}"
        );
    }
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    assert_eq!(after, before);
    db.close().await;
}

#[tokio::test]
async fn concurrent_unowned_record_claims_have_exactly_one_winner() {
    let (db, registry, _, _) = fixture().await;
    let record = create_local(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Concurrent claim" }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &record,
        vec![
            AllowEntry::account("acct:alice", Capability::View),
            AllowEntry::account("acct:bea", Capability::View),
        ],
    )
    .await
    .unwrap();
    let alice = Caller::authenticated("acct:alice")
        .with_hosting_context("host:alice", "db:test")
        .with_hosting_owner(true);
    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(true);
    let (first, second) = tokio::join!(
        call_as(
            &registry,
            &db,
            alice,
            "claim_unowned_record",
            json!({ "record_id": record, "reason": "Alice claim" }),
        ),
        call_as(
            &registry,
            &db,
            bea,
            "claim_unowned_record",
            json!({ "record_id": record, "reason": "Bea claim" }),
        )
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let loser = first.err().or_else(|| second.err()).unwrap().to_string();
    assert!(
        loser.contains("not eligible for ownership recovery"),
        "{loser}"
    );
    let updates: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id = ? AND type = 'record.updated'",
    )
    .bind(&record)
    .fetch_one(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    assert_eq!(updates, 1);
    let owner: Option<String> = sqlx::query_scalar("SELECT owner_id FROM records WHERE id = ?")
        .bind(&record)
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    assert!(owner.is_some());
    db.close().await;
}

#[tokio::test]
async fn visible_write_denials_name_capabilities_without_mutating_records() {
    const MISSING: &str = "a0700000-0000-4000-8000-000000000099";

    let (db, registry, alice, _) = fixture().await;
    let record = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Capability threshold",
            "owner_id": alice
        }),
    )
    .await;
    let hidden = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Hidden threshold",
            "owner_id": alice
        }),
    )
    .await;
    let tombstoned = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Tombstoned threshold",
            "owner_id": alice
        }),
    )
    .await;
    call_as(
        &registry,
        &db,
        Caller::local(),
        "delete_record",
        json!({ "id": tombstoned }),
    )
    .await
    .unwrap();
    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);

    replace_explicit_policy(
        &db,
        "test:policy",
        &record,
        vec![AllowEntry::account("acct:bea", Capability::View)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();

    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let view_denial = call_as(
        &registry,
        &db,
        bea.clone(),
        "update_record",
        json!({ "id": record, "name": "must not land" }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(
        view_denial,
        format!(
            "update_record: record {record} requires edit capability; caller has view capability"
        )
    );

    replace_explicit_policy(
        &db,
        "test:policy",
        &record,
        vec![AllowEntry::account("acct:bea", Capability::Edit)],
    )
    .await
    .unwrap();
    let edit_denial = call_as(
        &registry,
        &db,
        bea.clone(),
        "archive_record",
        json!({ "id": record }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(
        edit_denial,
        format!(
            "archive_record: record {record} requires manage capability; caller has edit capability"
        )
    );

    for id in [hidden.as_str(), tombstoned.as_str(), MISSING] {
        let denial = call_as(
            &registry,
            &db,
            bea.clone(),
            "update_record",
            json!({ "id": id, "name": "must not land" }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            denial.contains(&format!("record {id} does not exist")),
            "{denial}"
        );
        assert!(!denial.contains("capability"), "{denial}");
    }

    let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    assert_eq!(events_after, events_before, "denials must append no events");
    let stored_name: String = sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
        .bind(&record)
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    assert_eq!(stored_name, "Capability threshold");
    db.close().await;
}

#[tokio::test]
async fn mutation_thresholds_and_owner_transfer_are_enforced() {
    let (db, registry, alice, bea_person) = fixture().await;
    let record = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Threshold",
            "owner_id": alice
        }),
    )
    .await;
    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);

    replace_explicit_policy(
        &db,
        "test:policy",
        &record,
        vec![AllowEntry::account("acct:bea", Capability::View)],
    )
    .await
    .unwrap();
    assert!(call_as(
        &registry,
        &db,
        bea.clone(),
        "update_record",
        json!({ "id": record, "summary": "no" }),
    )
    .await
    .is_err());

    replace_explicit_policy(
        &db,
        "test:policy",
        &record,
        vec![AllowEntry::account("acct:bea", Capability::Edit)],
    )
    .await
    .unwrap();
    call_as(
        &registry,
        &db,
        bea.clone(),
        "update_record",
        json!({ "id": record, "summary": "yes" }),
    )
    .await
    .unwrap();
    assert!(call_as(
        &registry,
        &db,
        bea.clone(),
        "archive_record",
        json!({ "id": record }),
    )
    .await
    .is_err());

    replace_explicit_policy(
        &db,
        "test:policy",
        &record,
        vec![AllowEntry::account("acct:bea", Capability::Manage)],
    )
    .await
    .unwrap();
    let events_before_transfer: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let transfer = call_as(
        &registry,
        &db,
        bea.clone(),
        "update_record",
        json!({ "id": record, "owner_id": bea_person }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(
        transfer,
        "update_record: changing owner_id is reserved to the record's current owner"
    );
    let events_after_transfer: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    assert_eq!(events_after_transfer, events_before_transfer);
    let stored_owner: Option<String> =
        sqlx::query_scalar("SELECT owner_id FROM records WHERE id = ?")
            .bind(&record)
            .fetch_one(&crate::common::fixture_write_pool(&db).await)
            .await
            .unwrap();
    assert_eq!(stored_owner.as_deref(), Some(alice.as_str()));
    call_as(
        &registry,
        &db,
        bea,
        "archive_record",
        json!({ "id": record }),
    )
    .await
    .unwrap();
    db.close().await;
}

#[tokio::test]
async fn authenticated_local_cannot_forge_the_trusted_local_boundary() {
    let (db, registry, alice, bea_person) = fixture().await;
    let private = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Private local-marker check",
            "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &private,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();

    let forged = Caller::authenticated("local");
    let denied = call_as(
        &registry,
        &db,
        forged.clone(),
        "get_record",
        json!({ "ids": [private] }),
    )
    .await
    .unwrap();
    assert_eq!(denied["records"][0]["status"], "not_found");
    let trusted = call_as(
        &registry,
        &db,
        Caller::local(),
        "get_record",
        json!({ "ids": [private] }),
    )
    .await
    .unwrap();
    assert_eq!(trusted["records"][0]["status"], "found");

    let managed = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Managed local-marker check",
            "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &managed,
        vec![
            AllowEntry::account("acct:alice", Capability::Manage),
            AllowEntry::account("local", Capability::Manage),
        ],
    )
    .await
    .unwrap();
    call_as(
        &registry,
        &db,
        Caller::authenticated("acct:alice")
            .with_hosting_context("host:alice", "db:test")
            .with_hosting_owner(false),
        "update_record",
        json!({ "id": managed, "summary": "Alice-authored event" }),
    )
    .await
    .unwrap();
    // Actor disclosure follows `View` of the person, so close Alice's person
    // record to make the contrast below about the local marker and nothing
    // else: the forged caller is refused the bypass, while trusted local still
    // reads straight through it.
    replace_explicit_policy(
        &db,
        "test:policy",
        &alice,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();

    let forged_history = call_as(
        &registry,
        &db,
        forged.clone(),
        "get_history",
        json!({ "record_id": managed, "limit": 100 }),
    )
    .await
    .unwrap();
    assert!(forged_history["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|event| event["actor"].is_null()));
    let trusted_history = call_as(
        &registry,
        &db,
        Caller::local(),
        "get_history",
        json!({ "record_id": managed, "limit": 100 }),
    )
    .await
    .unwrap();
    assert!(trusted_history["events"]
        .as_array()
        .unwrap()
        .iter()
        .all(|event| !event["actor"].is_null()));

    let forged_transfer = call_as(
        &registry,
        &db,
        forged,
        "update_record",
        json!({ "id": managed, "owner_id": bea_person }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(
        forged_transfer,
        "update_record: changing owner_id is reserved to the record's current owner"
    );
    call_as(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({ "id": managed, "owner_id": bea_person }),
    )
    .await
    .unwrap();
    db.close().await;
}

#[tokio::test]
async fn dashboard_lifecycle_census_matches_rows_at_the_trusted_local_boundary() {
    let (db, registry, alice, _) = fixture().await;
    let private = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Private dashboard item",
            "lifecycle": "in_progress", "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &private,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();

    let lifecycle_count = |dashboard: &Value, lifecycle: &str| -> i64 {
        dashboard["lifecycle_census"]["buckets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|bucket| bucket["key"] == lifecycle)
            .and_then(|bucket| bucket["count"].as_i64())
            .unwrap_or_default()
    };

    let trusted = call_as(&registry, &db, Caller::local(), "get_dashboard", json!({}))
        .await
        .unwrap();
    assert!(trusted["active"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["id"] == private));
    assert_eq!(trusted["active_total"], 1);
    assert_eq!(trusted["stale_total"], 0);
    assert_eq!(lifecycle_count(&trusted, "in_progress"), 1);
    assert_eq!(
        lifecycle_count(&trusted, "in_progress"),
        trusted["active_total"].as_i64().unwrap() + trusted["stale_total"].as_i64().unwrap()
    );

    let forged = call_as(
        &registry,
        &db,
        Caller::authenticated("local"),
        "get_dashboard",
        json!({}),
    )
    .await
    .unwrap();
    assert!(!forged.to_string().contains(&private));
    assert_eq!(forged["active_total"], 0);
    assert_eq!(forged["stale_total"], 0);
    assert_eq!(lifecycle_count(&forged, "in_progress"), 0);
    db.close().await;
}

/// The unclassified census is a second place a record's id reaches the
/// response, so it is a second way an unreadable row could escape. It is
/// filtered by the same per-row viewer check as `active` and `stale`.
#[tokio::test]
async fn dashboard_unclassified_lifecycle_is_filtered_by_the_same_viewer_check() {
    let (db, registry, alice, _) = fixture().await;
    // A Collection kind has no governing lifecycle vocabulary. Ordinary
    // authoring refuses that lifecycle, so retain it through the explicit raw
    // fixture seam to model imported/historical evidence.
    let private = create_local(
        &registry,
        &db,
        json!({
            "type": "Collection", "kind": "folder", "name": "Private ungoverned lifecycle",
            "owner_id": alice
        }),
    )
    .await;
    sqlx::query("UPDATE records SET lifecycle = 'ready' WHERE id = ?")
        .bind(&private)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &private,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();

    let trusted = call_as(&registry, &db, Caller::local(), "get_dashboard", json!({}))
        .await
        .unwrap();
    assert!(trusted["unclassified_lifecycle"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["id"] == private));
    // And it is genuinely in attention, not diverted into the census.
    assert!(trusted["active"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["id"] == private));

    let forged = call_as(
        &registry,
        &db,
        Caller::authenticated("local"),
        "get_dashboard",
        json!({}),
    )
    .await
    .unwrap();
    assert!(!forged.to_string().contains(&private));
    assert_eq!(forged["unclassified_lifecycle"]["total_count"], 0);
    db.close().await;
}

#[tokio::test]
async fn derived_artifacts_inherit_only_their_live_bearer_on_generic_and_attachment_paths() {
    let (db, registry, alice, _) = fixture().await;
    let hidden_parent = create_local(
        &registry,
        &db,
        json!({
            "type": "Collection", "kind": "folder", "name": "Hidden filing",
            "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden_parent,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let hidden_bearer = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Hidden bearer",
            "home_id": hidden_parent, "owner_id": alice
        }),
    )
    .await;
    let visible_bearer = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Visible exception bearer",
            "home_id": hidden_parent, "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &visible_bearer,
        vec![AllowEntry::account("acct:bea", Capability::Manage)],
    )
    .await
    .unwrap();

    let broad_artifact = create_local(
        &registry,
        &db,
        json!({
            "type": "Annotation", "kind": "suggestion", "lifecycle": "open", "name": "Broad artifact",
            "body": "hidden", "facets": { "proposal.precondition": "none" }, "links": [{
                "target_id": hidden_bearer, "relationship": "part_of"
            }]
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &broad_artifact,
        vec![AllowEntry::account("acct:bea", Capability::Manage)],
    )
    .await
    .unwrap();
    let hidden_filed_artifact = create_local(
        &registry,
        &db,
        json!({
            "type": "Annotation", "kind": "suggestion", "lifecycle": "open", "name": "Hidden-filed artifact",
            "home_id": hidden_parent, "body": "visible",
            "facets": { "proposal.precondition": "none" }, "links": [{
                "target_id": visible_bearer, "relationship": "part_of"
            }]
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden_filed_artifact,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();

    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    let direct = call_as(
        &registry,
        &db,
        bea.clone(),
        "get_record",
        json!({ "ids": [broad_artifact, hidden_filed_artifact] }),
    )
    .await
    .unwrap();
    assert_eq!(direct["records"][0]["status"], "not_found");
    assert_eq!(direct["records"][1]["status"], "found");
    assert_eq!(direct["records"][1]["home_id"], Value::Null);

    let query = call_as(
        &registry,
        &db,
        bea.clone(),
        "query_record",
        json!({ "steps": [{
            "step": "filter", "ids": [broad_artifact, hidden_filed_artifact],
            "kinds": ["suggestion"]
        }] }),
    )
    .await
    .unwrap();
    assert_eq!(query["total"], 1);
    assert_eq!(query["records"][0]["id"], hidden_filed_artifact);

    assert!(call_as(
        &registry,
        &db,
        bea.clone(),
        "get_history",
        json!({ "record_id": broad_artifact }),
    )
    .await
    .is_err());
    let history = call_as(
        &registry,
        &db,
        bea.clone(),
        "get_history",
        json!({ "record_id": hidden_filed_artifact }),
    )
    .await
    .unwrap();
    assert!(!history["events"].as_array().unwrap().is_empty());
    let seq: i64 = sqlx::query_scalar("SELECT MIN(seq) FROM content_events WHERE record_id = ?")
        .bind(&hidden_filed_artifact)
        .fetch_one(db.pool())
        .await
        .unwrap();
    call_as(
        &registry,
        &db,
        bea.clone(),
        "get_record",
        json!({
            "ids": [hidden_filed_artifact],
            "as_of": { "content_seq": seq }
        }),
    )
    .await
    .unwrap();

    let created = call_as(
        &registry,
        &db,
        bea.clone(),
        "attach_text",
        json!({ "record_id": visible_bearer, "text": "bearer-derived bytes" }),
    )
    .await
    .unwrap();
    let attachment = created["attachment_id"].as_str().unwrap().to_string();
    let page = call_as(
        &registry,
        &db,
        bea.clone(),
        "read_attachment",
        json!({ "attachment_id": attachment }),
    )
    .await
    .unwrap();
    assert_eq!(page["content"], "bearer-derived bytes");

    replace_explicit_policy(
        &db,
        "test:policy",
        &visible_bearer,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    for (tool, arguments) in [
        ("read_attachment", json!({ "attachment_id": attachment })),
        (
            "manage_attachments",
            json!({ "action": "inspect", "attachment_id": attachment }),
        ),
    ] {
        let error = call_as(&registry, &db, bea.clone(), tool, arguments)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(&attachment));
        assert!(!error.contains(&visible_bearer));
    }
    let blob_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blobs")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(call_as(
        &registry,
        &db,
        bea,
        "attach_text",
        json!({ "record_id": visible_bearer, "text": "denied orphan" }),
    )
    .await
    .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM blobs")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        blob_count
    );
    db.close().await;
}

#[tokio::test]
async fn mutation_and_version_diff_responses_redact_hidden_related_records() {
    let (db, registry, alice, _) = fixture().await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &alice,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let hidden_parent = create_local(
        &registry,
        &db,
        json!({
            "type": "Collection", "kind": "folder", "name": "Hidden parent",
            "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden_parent,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let visible = create_local(
        &registry,
        &db,
        json!({
            "type": "Collection", "kind": "folder", "name": "Visible exception",
            "home_id": hidden_parent, "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &visible,
        vec![AllowEntry::account("acct:bea", Capability::Manage)],
    )
    .await
    .unwrap();
    let hidden_child = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Hidden child",
            "home_id": visible, "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden_child,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_links",
        json!({
            "action": "add", "source_id": visible, "target_id": hidden_child,
            "relationship": "relates_to"
        }),
    )
    .await
    .unwrap();

    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    let updated = call_as(
        &registry,
        &db,
        bea.clone(),
        "update_record",
        json!({ "id": visible, "summary": "safe response" }),
    )
    .await
    .unwrap();
    assert_eq!(updated["home_id"], Value::Null);
    assert_eq!(updated["child_count"], 0);
    assert_eq!(updated["links_out_count"], 0);
    assert!(!updated.to_string().contains(&hidden_parent));
    assert!(!updated.to_string().contains(&hidden_child));

    let created = call_as(
        &registry,
        &db,
        bea.clone(),
        "create_record",
        json!({
            "type": "WorkItem", "kind": "task", "name": "Created safely",
            "home_id": visible
        }),
    )
    .await
    .unwrap();
    assert!(!created.to_string().contains(&hidden_parent));

    let before_seq: i64 =
        sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id = ?")
            .bind(&visible)
            .fetch_one(db.pool())
            .await
            .unwrap();
    call_as(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({ "id": visible, "owner_id": alice }),
    )
    .await
    .unwrap();
    let diff = call_as(
        &registry,
        &db,
        bea,
        "render_record_version_diff",
        json!({ "record_id": visible, "before_seq": before_seq }),
    )
    .await
    .unwrap();
    assert!(!diff.to_string().contains(&hidden_parent));
    assert!(!diff.to_string().contains(&hidden_child));
    assert!(!diff.to_string().contains(&alice));
    assert!(diff["events"]
        .as_array()
        .unwrap()
        .iter()
        .all(|event| event["actor"].is_null() && event["run_key"].is_null()));
    assert!(diff["events"]
        .as_array()
        .unwrap()
        .iter()
        .all(|event| event["payload"]["owner_id"].is_null()));
    db.close().await;
}

#[tokio::test]
async fn diagnostics_scan_facets_and_work_context_use_only_visible_related_rows() {
    let (db, registry, alice, _) = fixture().await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &alice,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let bearer = create_local(
        &registry,
        &db,
        json!({
            "type": "Collection", "kind": "folder", "name": "Visible work",
            "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &bearer,
        vec![
            AllowEntry::account("acct:alice", Capability::Manage),
            AllowEntry::account("acct:bea", Capability::Manage),
        ],
    )
    .await
    .unwrap();
    let hidden = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Hidden metric row",
            "home_id": bearer, "owner_id": alice,
            "facets": { "estimate": "not-a-number" }
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_links",
        json!({
            "action": "add", "source_id": bearer, "target_id": hidden,
            "relationship": "relates_to"
        }),
    )
    .await
    .unwrap();

    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    let query = call_as(
        &registry,
        &db,
        bea.clone(),
        "query_record",
        json!({ "steps": [{
            "step": "filter", "ids": [hidden],
            "facets": [{ "key": "estimate", "gt": 0 }]
        }] }),
    )
    .await
    .unwrap();
    assert_eq!(query["total"], 0);
    assert_eq!(query.get("messages"), None);

    let scan = call_as(
        &registry,
        &db,
        bea.clone(),
        "scan",
        json!({ "scope": bearer, "high_degree_min": 1 }),
    )
    .await
    .unwrap();
    assert_eq!(scan["axes"]["high_degree"]["count"], 0);
    assert_eq!(scan["axes"]["containers"]["count"], 0);

    let facets = call_as(
        &registry,
        &db,
        bea.clone(),
        "resolve_facets",
        json!({ "record_id": bearer }),
    )
    .await
    .unwrap();
    assert_eq!(facets["spine"]["owner"], Value::Null);

    let context = call_as(
        &registry,
        &db,
        bea.clone(),
        "start_work",
        json!({ "record_id": bearer, "action": "preview" }),
    )
    .await
    .unwrap();
    assert_eq!(context["context"]["record"]["child_count"], 0);
    assert_eq!(context["context"]["record"]["links_out_count"], 0);
    assert_eq!(context["context"]["dependencies"]["ready"], true);

    call_as(
        &registry,
        &db,
        Caller::authenticated("acct:alice")
            .with_hosting_context("host:alice", "db:test")
            .with_hosting_owner(false),
        "start_work",
        json!({ "record_id": bearer, "action": "claim" }),
    )
    .await
    .unwrap();
    let conflict = call_as(
        &registry,
        &db,
        bea,
        "start_work",
        json!({ "record_id": bearer, "action": "claim" }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(conflict.contains("already claimed"), "{conflict}");
    assert!(!conflict.contains("acct:alice"), "{conflict}");
    db.close().await;
}

#[test]
fn every_registered_tool_kind_has_an_authorization_disposition() {
    assert_eq!(ToolKind::ALL.len(), 75);
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    let registered = registry
        .specs()
        .map(|spec| spec.kind.expect("shipped tool kind"))
        .collect::<std::collections::HashSet<_>>();
    let missing = ToolKind::ALL
        .into_iter()
        .filter(|kind| !registered.contains(kind))
        .collect::<Vec<_>>();
    assert_eq!(
        missing,
        vec![
            ToolKind::StandbyStatus,
            ToolKind::ExportSnapshot,
            ToolKind::ManageMemberships,
        ]
    );
    assert_eq!(
        ToolKind::StandbyStatus.authorization(),
        AuthorizationDisposition::NoRecord
    );
    assert_eq!(
        ToolKind::ReadGuide.authorization(),
        AuthorizationDisposition::NoRecord
    );
    assert_eq!(
        ToolKind::DescribeSchema.authorization(),
        AuthorizationDisposition::Specialized
    );
    assert_eq!(
        ToolKind::QuerySql.authorization(),
        AuthorizationDisposition::Specialized
    );
    assert_eq!(
        ToolKind::Search.authorization(),
        AuthorizationDisposition::CallerFilteredRead
    );
    assert_eq!(
        ToolKind::WhatsChanged.authorization(),
        AuthorizationDisposition::CallerFilteredRead
    );
    assert_eq!(
        ToolKind::ManageInterventions.authorization(),
        AuthorizationDisposition::Specialized
    );
    for kind in [
        ToolKind::InstantiateArtifact,
        ToolKind::ManageRendererBinding,
        ToolKind::ManageMdxModules,
        ToolKind::ManageArtifactInputs,
        ToolKind::ManageArtifactModuleGrants,
        ToolKind::RenderArtifact,
        ToolKind::VerifyArtifact,
        ToolKind::OpenCollection,
    ] {
        assert_eq!(kind.authorization(), AuthorizationDisposition::Specialized);
    }
    for kind in ToolKind::ALL {
        let _declared = kind.authorization();
    }
}

/// A name is identity, so it is disclosed on the same terms as any other
/// record. Attribution used to be self-only: a member saw their own actor and
/// nothing for anyone else, which made a shared workspace unreadable exactly
/// when shared attribution started to matter. The run and intent travel with
/// the name because knowing *who* acted without knowing what they were trying
/// to do does not let one member pick up another's work.
#[tokio::test]
async fn another_members_actor_run_and_intent_resolve_only_with_view_of_their_person() {
    const RUN: &str = "scout-chair-a748b2";
    let (db, registry, alice, _bea) = fixture().await;
    let alice_caller = Caller::authenticated("acct:alice")
        .with_hosting_context("host:alice", "db:test")
        .with_hosting_owner(false);
    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);

    let shared = create_local(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Shared work" }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &shared,
        vec![
            AllowEntry::account("acct:alice", Capability::Manage),
            AllowEntry::account("acct:bea", Capability::View),
        ],
    )
    .await
    .unwrap();
    // Granted explicitly rather than leaned on by inheritance: whether a person
    // record is members-View by default is a separate question about placement,
    // and this test is about the rule that View governs disclosure at all.
    replace_explicit_policy(
        &db,
        "test:policy",
        &alice,
        vec![
            AllowEntry::account("acct:alice", Capability::Manage),
            AllowEntry::account("acct:bea", Capability::View),
        ],
    )
    .await
    .unwrap();
    call_as(
        &registry,
        &db,
        alice_caller,
        "update_record",
        json!({ "id": shared, "summary": "Alice moved this along", "run_key": RUN }),
    )
    .await
    .unwrap();

    let alice_event = |history: &Value| -> Option<Value> {
        history["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["type"] == "record.updated")
            .cloned()
    };

    let history = call_as(
        &registry,
        &db,
        bea.clone(),
        "get_history",
        json!({ "record_id": shared }),
    )
    .await
    .unwrap();
    let event = alice_event(&history).expect("alice's update is visible to bea");
    assert_eq!(event["actor"], "acct:alice");
    assert_eq!(
        event["actor_name"], "Alice",
        "the byline resolves through the person record, not the account token"
    );
    assert_eq!(event["run_key"], RUN, "the run travels with the name");

    // Same caller, same record, same grant on that record — only View of the
    // person is withdrawn. Attribution has to disappear with it, or the person
    // record's policy would not be what governs disclosure.
    replace_explicit_policy(
        &db,
        "test:policy",
        &alice,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let history = call_as(
        &registry,
        &db,
        bea,
        "get_history",
        json!({ "record_id": shared }),
    )
    .await
    .unwrap();
    let event = alice_event(&history).expect("the event itself stays visible");
    assert!(event["actor"].is_null());
    assert!(event["run_key"].is_null());
    assert!(event["parent_key"].is_null());
    assert!(event["intent"].is_null());
    db.close().await;
}

#[tokio::test]
async fn multi_target_relocation_uses_snapshot_authority_and_exact_capability_thresholds() {
    let (db, registry, alice, _) = fixture().await;
    let source = create_local(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Managed source", "owner_id": alice }),
    )
    .await;
    let destination = create_local(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Editable destination", "owner_id": alice }),
    )
    .await;
    let hidden_destination = create_local(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Hidden destination", "owner_id": alice }),
    )
    .await;
    let edit_only_source = create_local(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Edit-only source", "owner_id": alice }),
    )
    .await;
    let edit_only_target = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Needs Manage to move",
            "home_id": edit_only_source, "owner_id": alice
        }),
    )
    .await;
    let parent = create_local(
        &registry,
        &db,
        json!({
            "type": "Collection", "kind": "folder", "name": "Related parent",
            "home_id": source, "owner_id": alice
        }),
    )
    .await;
    let child = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Related child",
            "home_id": parent, "owner_id": alice
        }),
    )
    .await;
    let already_homed = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Already filed",
            "home_id": destination, "owner_id": alice
        }),
    )
    .await;

    replace_explicit_policy(
        &db,
        "test:policy",
        &source,
        vec![AllowEntry::account("acct:bea", Capability::Manage)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &destination,
        vec![AllowEntry::account("acct:bea", Capability::Edit)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden_destination,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &edit_only_source,
        vec![AllowEntry::account("acct:bea", Capability::Edit)],
    )
    .await
    .unwrap();

    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);

    let edit_is_not_manage = call_as(
        &registry,
        &db,
        bea.clone(),
        "update_record",
        json!({ "ids": [edit_only_target], "home_id": destination }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(edit_is_not_manage.contains("[0]"), "{edit_is_not_manage}");
    assert!(
        edit_is_not_manage.contains("unavailable: record is unavailable"),
        "{edit_is_not_manage}"
    );
    assert_eq!(
        projected_home_and_policy_anchor(&db, &edit_only_target)
            .await
            .0
            .as_deref(),
        Some(edit_only_source.as_str())
    );

    let destination_denial = call_as(
        &registry,
        &db,
        bea.clone(),
        "update_record",
        json!({ "ids": [parent], "home_id": hidden_destination }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        destination_denial.contains("relocation home")
            && destination_denial.contains("is unavailable")
            && destination_denial.contains("nothing was written"),
        "{destination_denial}"
    );
    assert_eq!(
        projected_home_and_policy_anchor(&db, &parent)
            .await
            .0
            .as_deref(),
        Some(source.as_str())
    );

    let receipt = call_as(
        &registry,
        &db,
        bea,
        "update_record",
        json!({ "ids": [parent, child, already_homed], "home_id": destination }),
    )
    .await
    .unwrap();
    assert_eq!(receipt["requested"], 3);
    assert_eq!(receipt["changed"], 2);
    assert_eq!(receipt["unchanged"], 1);
    assert_eq!(receipt["results"][0]["id"], parent);
    assert_eq!(receipt["results"][1]["id"], child);
    assert_eq!(receipt["results"][2]["id"], already_homed);
    assert_eq!(receipt["results"][2]["status"], "unchanged");
    for id in [&parent, &child, &already_homed] {
        assert_eq!(
            projected_home_and_policy_anchor(&db, id).await.0.as_deref(),
            Some(destination.as_str())
        );
    }
    db.close().await;
}

#[tokio::test]
async fn multi_target_rejection_bounds_and_equates_hidden_and_missing_targets() {
    let (db, registry, alice, _) = fixture().await;
    let hidden = create_local(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Secret target name",
            "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let missing = (1..=21)
        .map(|index| format!("a0720000-0000-4000-8000-{index:012x}"))
        .collect::<Vec<_>>();
    let mut ids = vec![hidden.clone()];
    ids.extend(missing.iter().cloned());
    let events_before = content_event_count(&db).await;

    let error = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:bea")
            .with_hosting_context("host:bea", "db:test")
            .with_hosting_owner(false),
        "update_record",
        json!({ "ids": ids, "maturity": "reviewed" }),
    )
    .await
    .unwrap_err()
    .to_string();

    assert!(
        error.contains("requested=22, changed=0, unchanged=0, conflicted=0, failed=22"),
        "{error}"
    );
    let hidden_detail = format!("[0] {hidden} unavailable: record is unavailable");
    let missing_detail = format!("[1] {} unavailable: record is unavailable", missing[0]);
    assert!(error.contains(&hidden_detail), "{error}");
    assert!(error.contains(&missing_detail), "{error}");
    assert_eq!(
        error.matches("unavailable: record is unavailable").count(),
        20
    );
    assert!(
        error.contains("details truncated; omitted_detail_count=2"),
        "{error}"
    );
    assert!(!error.contains("Secret target name"), "{error}");
    assert!(!error.contains("capability"), "{error}");
    assert!(!error.contains("does not exist"), "{error}");
    assert_eq!(content_event_count(&db).await, events_before);
    db.close().await;
}

#[tokio::test]
async fn related_multi_target_moves_refresh_final_policy_anchors_independently_of_input_order() {
    let (db, registry, alice, _) = fixture().await;
    let destination = create_local(
        &registry,
        &db,
        json!({
            "type": "Collection", "kind": "folder", "name": "Shared destination",
            "owner_id": alice
        }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &destination,
        vec![AllowEntry::account("acct:bea", Capability::Edit)],
    )
    .await
    .unwrap();
    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);

    for reverse in [false, true] {
        let source = create_local(
            &registry,
            &db,
            json!({
                "type": "Collection", "kind": "folder",
                "name": format!("Source {reverse}"), "owner_id": alice
            }),
        )
        .await;
        let parent = create_local(
            &registry,
            &db,
            json!({
                "type": "Collection", "kind": "folder",
                "name": format!("Parent {reverse}"), "home_id": source, "owner_id": alice
            }),
        )
        .await;
        let child = create_local(
            &registry,
            &db,
            json!({
                "type": "Collection", "kind": "folder",
                "name": format!("Child {reverse}"), "home_id": parent, "owner_id": alice
            }),
        )
        .await;
        let parent_leaf = create_local(
            &registry,
            &db,
            json!({
                "type": "WorkItem", "kind": "task",
                "name": format!("Parent leaf {reverse}"), "home_id": parent, "owner_id": alice
            }),
        )
        .await;
        let child_leaf = create_local(
            &registry,
            &db,
            json!({
                "type": "WorkItem", "kind": "task",
                "name": format!("Child leaf {reverse}"), "home_id": child, "owner_id": alice
            }),
        )
        .await;
        let explicit_boundary = create_local(
            &registry,
            &db,
            json!({
                "type": "Collection", "kind": "folder",
                "name": format!("Explicit boundary {reverse}"),
                "home_id": child, "owner_id": alice
            }),
        )
        .await;
        let boundary_leaf = create_local(
            &registry,
            &db,
            json!({
                "type": "WorkItem", "kind": "task",
                "name": format!("Boundary leaf {reverse}"),
                "home_id": explicit_boundary, "owner_id": alice
            }),
        )
        .await;
        replace_explicit_policy(
            &db,
            "test:policy",
            &source,
            vec![AllowEntry::account("acct:bea", Capability::Manage)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            &explicit_boundary,
            vec![AllowEntry::account("acct:alice", Capability::Manage)],
        )
        .await
        .unwrap();

        let ids = if reverse {
            vec![child.clone(), parent.clone()]
        } else {
            vec![parent.clone(), child.clone()]
        };
        let receipt = call_as(
            &registry,
            &db,
            bea.clone(),
            "update_record",
            json!({ "ids": ids, "home_id": destination }),
        )
        .await
        .unwrap();
        assert_eq!(receipt["changed"], 2);

        for target in [&parent, &child] {
            let (home, anchor) = projected_home_and_policy_anchor(&db, target).await;
            assert_eq!(home.as_deref(), Some(destination.as_str()));
            assert_eq!(anchor, destination);
        }
        for inherited_descendant in [&parent_leaf, &child_leaf] {
            let (_, anchor) = projected_home_and_policy_anchor(&db, inherited_descendant).await;
            assert_eq!(anchor, destination);
        }
        let (_, boundary_anchor) = projected_home_and_policy_anchor(&db, &explicit_boundary).await;
        let (_, boundary_leaf_anchor) = projected_home_and_policy_anchor(&db, &boundary_leaf).await;
        assert_eq!(boundary_anchor, explicit_boundary);
        assert_eq!(boundary_leaf_anchor, explicit_boundary);
    }
    db.close().await;
}
