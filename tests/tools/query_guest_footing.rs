//! Guest footing across the query layer: `search`, `scan`, and `query_sql`
//! build dedicated principal types (`SearchPrincipal`, `QueryPrincipal`)
//! rather than the portable `Principal`, so the `Caller` audit could not
//! reach them. A guest must resolve without the `native:members` baseline
//! on all three — names, snippets, counts, samples, and bodies alike.

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

async fn call(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    arguments: Value,
) -> Value {
    registry
        .call(db.clone(), caller, tool, arguments)
        .await
        .unwrap()
}

fn guest_caller() -> Caller {
    Caller::authenticated("acct:guest")
        .with_hosting_context("host:guest", "db:test")
        .with_hosting_owner(false)
        .with_hosting_member(false)
}

fn member_caller() -> Caller {
    Caller::authenticated("acct:member")
        .with_hosting_context("host:member", "db:test")
        .with_hosting_owner(false)
        .with_hosting_member(true)
}

async fn fixture() -> (ToolRegistry, Db) {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let db = create_database(":memory:").await.unwrap();
    // A plain workspace document inherits the genesis members baseline:
    // members resolve it, guests must not — on any query surface.
    native_ce::store::create_record(
        &db,
        json!({
            "type": "Document",
            "kind": "note",
            "name": "Quarterly synergy report",
            "body": "classified synergy body text",
            "home_id": "native:root",
        }),
    )
    .await
    .unwrap();
    (registry, db)
}

/// `search` must not return member-baseline names or snippets to guests.
#[tokio::test]
async fn guest_search_sees_no_member_baseline_hits() {
    let (registry, db) = fixture().await;
    let member = call(
        &registry,
        &db,
        member_caller(),
        "search",
        json!({ "query": "synergy" }),
    )
    .await;
    assert_eq!(member["hits"].as_array().unwrap().len(), 1);
    assert!(member.to_string().contains("synergy"));

    let guest = call(
        &registry,
        &db,
        guest_caller(),
        "search",
        json!({ "query": "synergy" }),
    )
    .await;
    assert_eq!(guest["hits"], json!([]), "guest search leaked: {guest}");
    assert!(
        !guest.to_string().contains("classified"),
        "guest search leaked snippets: {guest}"
    );
}

/// `scan` must report a zero lexical pool (and no samples) to guests.
#[tokio::test]
async fn guest_scan_reports_zero_member_baseline_pool() {
    let (registry, db) = fixture().await;
    let member = call(
        &registry,
        &db,
        member_caller(),
        "scan",
        json!({ "query": "synergy" }),
    )
    .await;
    assert_eq!(member["axes"]["lexical"]["count"], json!(1));

    let guest = call(
        &registry,
        &db,
        guest_caller(),
        "scan",
        json!({ "query": "synergy" }),
    )
    .await;
    assert_eq!(
        guest["axes"]["lexical"]["count"],
        json!(0),
        "guest scan leaked count: {guest}"
    );
    assert_eq!(guest["axes"]["lexical"]["samples"], json!([]));
}

/// `query_sql` must not return member-baseline record bodies to guests.
#[tokio::test]
async fn guest_query_sql_sees_no_member_baseline_rows() {
    let (registry, db) = fixture().await;
    let sql = "SELECT id, name, body FROM records WHERE name LIKE '%synergy%'";
    let member = call(
        &registry,
        &db,
        member_caller(),
        "query_sql",
        json!({ "sql": sql }),
    )
    .await;
    assert_eq!(member["row_count"], json!(1));

    let guest = call(
        &registry,
        &db,
        guest_caller(),
        "query_sql",
        json!({ "sql": sql }),
    )
    .await;
    assert_eq!(
        guest["row_count"],
        json!(0),
        "guest query_sql leaked: {guest}"
    );
    assert_eq!(guest["rows"], json!([]));
}
