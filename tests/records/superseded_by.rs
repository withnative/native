//! The `superseded_by` read-path disclosure: an incoming `supersedes` link is
//! named in read headers without the reader inspecting links.
//!
//! Disclosure, not archival: the superseded record stays readable and
//! otherwise unchanged. An invisible successor is counted in `total_count`
//! but never named in `items`.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::render::{self};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    registry
        .call(db.clone(), Caller::local(), tool, args)
        .await
        .unwrap()
}

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    args: Value,
) -> Value {
    registry.call(db.clone(), caller, tool, args).await.unwrap()
}

async fn create(registry: &ToolRegistry, db: &Db, args: Value) -> String {
    let mut args = args;
    if let Some(object) = args.as_object_mut() {
        object
            .entry("reason")
            .or_insert_with(|| json!("superseded_by test fixture"));
    }
    call(registry, db, "create_record", args).await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn link_supersedes(registry: &ToolRegistry, db: &Db, source: &str, target: &str) {
    call(
        registry,
        db,
        "manage_links",
        json!({
            "action": "add",
            "source_id": source,
            "target_id": target,
            "relationship": "supersedes",
        }),
    )
    .await;
}

/// One superseded record plus its successor, both plain Documents.
async fn superseded_pair(registry: &ToolRegistry, db: &Db) -> (String, String) {
    let old = create(
        registry,
        db,
        json!({ "type": "Document", "kind": "note", "name": "Superseded charter" }),
    )
    .await;
    let new = create(
        registry,
        db,
        json!({ "type": "Document", "kind": "note", "name": "Replacement charter" }),
    )
    .await;
    link_supersedes(registry, db, &new, &old).await;
    (old, new)
}

fn bea() -> Caller {
    Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false)
}

#[tokio::test]
async fn get_record_names_the_successor_in_the_header() {
    let db = db().await;
    let registry = registry();
    let (old, new) = superseded_pair(&registry, &db).await;

    let payload = call(&registry, &db, "get_record", json!({ "ids": [old] })).await;
    let record = &payload["records"][0];
    assert_eq!(record["status"], "found");
    let superseded = &record["superseded_by"];
    assert_eq!(superseded["total_count"], 1);
    assert_eq!(superseded["items"].as_array().unwrap().len(), 1);
    assert_eq!(superseded["items"][0]["id"], json!(new));
    assert_eq!(superseded["items"][0]["name"], "Replacement charter");
    let reference = superseded["items"][0]["display_reference"]
        .as_str()
        .expect("successor carries a short reference")
        .to_string();
    // The incoming link itself is unchanged: disclosure adds, never moves.
    assert!(
        record["links_in"]
            .as_array()
            .unwrap()
            .iter()
            .any(|link| link["source_id"] == json!(new)
                && link["relationship"] == json!("supersedes")),
        "{record:#}"
    );

    let text = render::render("get_record", &payload).unwrap();
    assert!(
        text.contains(&format!("superseded by Replacement charter ({reference})")),
        "{text}"
    );
}

#[tokio::test]
async fn record_without_a_successor_has_no_superseded_field_or_line() {
    let db = db().await;
    let registry = registry();
    let plain = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Standalone note" }),
    )
    .await;

    let payload = call(&registry, &db, "get_record", json!({ "ids": [plain] })).await;
    let record = &payload["records"][0];
    assert!(record.get("superseded_by").is_none(), "{record:#}");

    let text = render::render("get_record", &payload).unwrap();
    assert!(!text.contains("superseded"), "{text}");
}

#[tokio::test]
async fn successor_window_names_three_and_counts_all() {
    let db = db().await;
    let registry = registry();
    let old = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Charter v1" }),
    )
    .await;
    for name in ["Charter v2", "Charter v3", "Charter v4", "Charter v5"] {
        let successor = create(
            &registry,
            &db,
            json!({ "type": "Document", "kind": "note", "name": name }),
        )
        .await;
        link_supersedes(&registry, &db, &successor, &old).await;
    }

    let payload = call(&registry, &db, "get_record", json!({ "ids": [old] })).await;
    let superseded = &payload["records"][0]["superseded_by"];
    assert_eq!(superseded["total_count"], 4);
    assert_eq!(superseded["items"].as_array().unwrap().len(), 3);

    let text = render::render("get_record", &payload).unwrap();
    assert!(text.contains("and 1 more"), "{text}");
}

#[tokio::test]
async fn tombstoned_successor_is_not_disclosed() {
    let db = db().await;
    let registry = registry();
    let (old, new) = superseded_pair(&registry, &db).await;
    call(
        &registry,
        &db,
        "delete_record",
        json!({ "id": new, "reason": "withdraw the replacement" }),
    )
    .await;

    let payload = call(&registry, &db, "get_record", json!({ "ids": [old] })).await;
    let record = &payload["records"][0];
    assert!(record.get("superseded_by").is_none(), "{record:#}");
    let text = render::render("get_record", &payload).unwrap();
    assert!(!text.contains("superseded"), "{text}");
}

#[tokio::test]
async fn invisible_successor_is_counted_not_named() {
    let db = db().await;
    let registry = registry();
    let (old, new) = superseded_pair(&registry, &db).await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &new,
        vec![AllowEntry::account("acct:alice", Capability::View)],
    )
    .await
    .unwrap();

    let payload = call_as(&registry, &db, bea(), "get_record", json!({ "ids": [old] })).await;
    let record = &payload["records"][0];
    assert_eq!(record["status"], "found");
    let superseded = &record["superseded_by"];
    assert_eq!(superseded["total_count"], 1);
    assert_eq!(superseded["items"], json!([]), "{record:#}");

    let text = render::render("get_record", &payload).unwrap();
    assert!(text.contains("superseded by 1 record"), "{text}");
    assert!(!text.contains("Replacement charter"), "{text}");
    assert!(!text.contains(&new), "{text}");
}

#[tokio::test]
async fn query_record_rows_carry_superseded_by() {
    let db = db().await;
    let registry = registry();
    let (old, _) = superseded_pair(&registry, &db).await;

    let payload = call(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "types": ["Document"] }] }),
    )
    .await;
    let row = payload["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == json!(old))
        .expect("superseded record in results")
        .clone();
    assert_eq!(row["superseded_by"]["total_count"], 1);
    assert_eq!(
        row["superseded_by"]["items"][0]["name"],
        "Replacement charter"
    );

    let text = render::render("query_record", &payload).unwrap();
    assert!(
        text.contains("[superseded by Replacement charter"),
        "{text}"
    );
}

#[tokio::test]
async fn search_hits_carry_superseded_by() {
    let db = db().await;
    let registry = registry();
    superseded_pair(&registry, &db).await;

    let payload = call(
        &registry,
        &db,
        "search",
        json!({ "query": "Superseded charter" }),
    )
    .await;
    let hit = payload["hits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|hit| hit["name"] == json!("Superseded charter"))
        .expect("superseded record among hits")
        .clone();
    assert_eq!(hit["superseded_by"]["total_count"], 1);

    let text = render::render("search", &payload).unwrap();
    assert!(text.contains("superseded by Replacement charter"), "{text}");
}

#[tokio::test]
async fn structure_nodes_carry_superseded_by() {
    let db = db().await;
    let registry = registry();
    let home = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Decisions" }),
    )
    .await;
    let old = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Old decision", "home_id": home }),
    )
    .await;
    let new = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "New decision", "home_id": home }),
    )
    .await;
    link_supersedes(&registry, &db, &new, &old).await;

    let payload = call(&registry, &db, "get_structure", json!({ "root_id": home })).await;
    let node = payload["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["id"] == json!(old))
        .expect("superseded record among nodes")
        .clone();
    assert_eq!(node["superseded_by"]["total_count"], 1);
    assert_eq!(node["superseded_by"]["items"][0]["id"], json!(new));

    let text = render::render("get_structure", &payload).unwrap();
    assert!(text.contains("superseded_by"), "{text}");
    assert!(text.contains("New decision"), "{text}");
}

#[tokio::test]
async fn render_record_markdown_names_the_successor() {
    let db = db().await;
    let registry = registry();
    let (old, _) = superseded_pair(&registry, &db).await;

    let payload = call(&registry, &db, "render_record", json!({ "id": old })).await;
    let markdown = payload["markdown"].as_str().unwrap();
    assert!(
        markdown.contains("superseded by Replacement charter"),
        "{markdown}"
    );
}

#[tokio::test]
async fn dashboard_rows_carry_superseded_by() {
    let db = db().await;
    let registry = registry();
    let old = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Stale plan", "lifecycle": "open" }),
    )
    .await;
    let new = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Fresh plan", "lifecycle": "open" }),
    )
    .await;
    link_supersedes(&registry, &db, &new, &old).await;

    let payload = call(&registry, &db, "get_dashboard", json!({})).await;
    let buckets = ["active", "stale"]
        .into_iter()
        .flat_map(|bucket| payload[bucket].as_array().unwrap().to_vec())
        .collect::<Vec<_>>();
    let row = buckets
        .iter()
        .find(|row| row["id"] == json!(old))
        .expect("superseded record on the dashboard")
        .clone();
    assert_eq!(row["superseded_by"]["total_count"], 1);

    let text = render::render("get_dashboard", &payload).unwrap();
    assert!(text.contains("[superseded by Fresh plan"), "{text}");
}

#[tokio::test]
async fn bootstrap_world_items_annotate_superseded_without_titles() {
    let db = db().await;
    let registry = registry();
    let (old, new) = superseded_pair(&registry, &db).await;

    let payload = call(&registry, &db, "bootstrap", json!({})).await;
    let items = payload["current_world"]["recent_activity"]["items"]
        .as_array()
        .unwrap()
        .clone();
    let item = items
        .iter()
        .find(|item| item["id"] == json!(old))
        .expect("superseded record in recent activity")
        .clone();
    let superseded = &item["superseded_by"];
    assert_eq!(superseded["total_count"], 1);
    assert_eq!(superseded["items"][0]["id"], json!(new));
    // World items carry id plus short reference, never the title.
    assert!(superseded["items"][0].get("name").is_none(), "{item:#}");
    assert!(
        superseded["items"][0]["display_reference"].is_string(),
        "{item:#}"
    );

    let text = render::render("bootstrap", &payload).unwrap();
    assert!(text.contains("superseded by"), "{text}");
}

#[tokio::test]
async fn scan_samples_carry_superseded_by() {
    let db = db().await;
    let registry = registry();
    let (old, _) = superseded_pair(&registry, &db).await;

    let payload = call(&registry, &db, "scan", json!({})).await;
    let mut found = false;
    for axis in payload["axes"].as_object().unwrap().values() {
        for sample in axis["samples"].as_array().unwrap() {
            if sample["id"] == json!(old) {
                assert_eq!(sample["superseded_by"]["total_count"], 1);
                found = true;
            }
        }
    }
    assert!(found, "superseded record sampled by scan: {payload:#}");
}

#[tokio::test]
async fn query_record_redacts_an_invisible_successor_but_counts_it() {
    let db = db().await;
    let registry = registry();
    let old = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Shared charter" }),
    )
    .await;
    let visible = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Open revision" }),
    )
    .await;
    let hidden = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Sealed revision" }),
    )
    .await;
    link_supersedes(&registry, &db, &visible, &old).await;
    link_supersedes(&registry, &db, &hidden, &old).await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden,
        vec![AllowEntry::account("acct:alice", Capability::View)],
    )
    .await
    .unwrap();

    // The annotator path (not the enriched-record filter) applies the same
    // counted-not-named rule to bulk rows.
    let payload = call_as(
        &registry,
        &db,
        bea(),
        "query_record",
        json!({ "steps": [{ "step": "filter", "types": ["Document"] }] }),
    )
    .await;
    let row = payload["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == json!(old))
        .expect("superseded record in results")
        .clone();
    assert_eq!(row["superseded_by"]["total_count"], 2);
    assert_eq!(row["superseded_by"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(row["superseded_by"]["items"][0]["id"], json!(visible));

    let text = render::render("query_record", &payload).unwrap();
    assert!(text.contains("Open revision"), "{text}");
    assert!(!text.contains("Sealed revision"), "{text}");
}

#[tokio::test]
async fn invisible_head_does_not_hide_a_nameable_tail() {
    let db = db().await;
    let registry = registry();
    let old = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Charter v1" }),
    )
    .await;
    let mut successors = Vec::new();
    for name in ["Charter v2", "Charter v3", "Charter v4", "Charter v5"] {
        let successor = create(
            &registry,
            &db,
            json!({ "type": "Document", "kind": "note", "name": name }),
        )
        .await;
        link_supersedes(&registry, &db, &successor, &old).await;
        successors.push(successor);
    }
    // Force the disclosure order: the first three links sort before the
    // fourth, so the capped window the read path carries is exactly the
    // invisible head. Truncation must run after visibility, not before.
    let pool = crate::common::fixture_write_pool(&db).await;
    for (index, successor) in successors.iter().enumerate() {
        sqlx::query("UPDATE links SET created_at = ? WHERE source_id = ? AND target_id = ?")
            .bind(format!("2026-01-01T00:00:0{}Z", index + 1))
            .bind(successor)
            .bind(&old)
            .execute(&pool)
            .await
            .unwrap();
    }
    for successor in &successors[..3] {
        replace_explicit_policy(
            &db,
            "test:policy",
            successor,
            vec![AllowEntry::account("acct:alice", Capability::View)],
        )
        .await
        .unwrap();
    }
    let nameable = successors[3].clone();

    let payload = call_as(&registry, &db, bea(), "get_record", json!({ "ids": [old] })).await;
    let superseded = &payload["records"][0]["superseded_by"];
    assert_eq!(superseded["total_count"], 4);
    assert_eq!(superseded["items"].as_array().unwrap().len(), 1);
    assert_eq!(superseded["items"][0]["id"], json!(nameable));

    let text = render::render("get_record", &payload).unwrap();
    assert!(text.contains("Charter v5"), "{text}");
    assert!(text.contains("and 3 more"), "{text}");
}

#[tokio::test]
async fn non_superseded_rows_render_without_superseded_on_query_and_search() {
    let db = db().await;
    let registry = registry();
    let plain = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Plain narrative" }),
    )
    .await;

    let queried = call(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "types": ["Document"] }] }),
    )
    .await;
    let row = queried["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == json!(plain))
        .expect("plain record in results");
    assert!(row.get("superseded_by").is_none(), "{row:#}");
    let text = render::render("query_record", &queried).unwrap();
    assert!(!text.contains("superseded"), "{text}");

    let searched = call(
        &registry,
        &db,
        "search",
        json!({ "query": "Plain narrative" }),
    )
    .await;
    let hit = searched["hits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|hit| hit["id"] == json!(plain))
        .expect("plain record among hits");
    assert!(hit.get("superseded_by").is_none(), "{hit:#}");
    let text = render::render("search", &searched).unwrap();
    assert!(!text.contains("superseded"), "{text}");
}

#[tokio::test]
async fn bootstrap_keeps_a_budget_capped_item_and_degrades_its_annotation() {
    let db = db().await;
    let registry = registry();
    // A 160-char non-ASCII name at mixed widths (100 three-byte + 60
    // two-byte = 420 name bytes on a ~426-byte fixed overhead): the bare
    // item (~850 bytes) fits the 1024 budget, the full three-successor
    // annotation does not, the count-only degradation does. Bootstrap must
    // list the item regardless.
    let long_name = format!("{}{}", "€".repeat(100), "é".repeat(60));
    assert_eq!(long_name.chars().count(), 160);
    let mut successors = Vec::new();
    for name in ["Alpha revision", "Beta revision", "Gamma revision"] {
        successors.push(
            create(
                &registry,
                &db,
                json!({ "type": "Document", "kind": "note", "name": name }),
            )
            .await,
        );
    }
    let old = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": long_name, "lifecycle": "open" }),
    )
    .await;
    for successor in &successors {
        link_supersedes(&registry, &db, successor, &old).await;
    }

    let payload = call(&registry, &db, "bootstrap", json!({})).await;
    let items = payload["current_world"]["open_work"]["items"]
        .as_array()
        .unwrap()
        .clone();
    let item = items
        .iter()
        .find(|item| item["id"] == json!(old))
        .expect("long-named superseded record still listed in open work")
        .clone();
    assert_eq!(item["superseded_by"]["total_count"], 3);
    assert_eq!(
        item["superseded_by"]["items"],
        json!([]),
        "full annotation cannot fit beside a 420-byte name: {item:#}"
    );

    let text = render::render("bootstrap", &payload).unwrap();
    assert!(text.contains("superseded by 3 records"), "{text}");
}
