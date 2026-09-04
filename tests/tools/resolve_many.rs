//! Exact batch record-name resolution: positional results and anti-oracle
//! ambiguity semantics. Wired into `tests/tools.rs` with the operation.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

const ALPHA: &str = "2ea00000-0000-4000-8000-000000000001";
const DUPLICATE_A: &str = "2ea00000-0000-4000-8000-000000000002";
const DUPLICATE_B: &str = "2ea00000-0000-4000-8000-000000000003";
const HIDDEN_DUPLICATE: &str = "2ea00000-0000-4000-8000-000000000004";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    arguments: Value,
) -> Value {
    registry
        .call(
            db.clone(),
            caller,
            tool,
            crate::common::with_test_reason(tool, arguments),
        )
        .await
        .unwrap()
}

async fn create(registry: &ToolRegistry, db: &Db, arguments: Value) -> String {
    call_as(registry, db, Caller::local(), "create_record", arguments).await["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn mixed_exact_results_preserve_indexes_duplicates_and_candidate_order() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create(
        &registry,
        &db,
        json!({"id":ALPHA,"type":"Entity","kind":"person","name":"Zoë Hitzig"}),
    )
    .await;
    // Create in reverse id order: response order is identity order, not row
    // insertion order.
    create(
        &registry,
        &db,
        json!({"id":DUPLICATE_B,"type":"Entity","kind":"person","name":"Same Name"}),
    )
    .await;
    create(
        &registry,
        &db,
        json!({"id":DUPLICATE_A,"type":"Entity","kind":"person","name":"Same Name"}),
    )
    .await;

    let out = call_as(
        &registry,
        &db,
        Caller::local(),
        "resolve_many",
        json!({
            "type":"Entity",
            "kind":"person",
            "names":["Zoë Hitzig","Missing","Same Name","Zoë Hitzig"]
        }),
    )
    .await;
    let rows = out["results"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0]["index"], 0);
    assert_eq!(rows[0]["status"], "resolved");
    assert_eq!(rows[0]["match"]["id"], ALPHA);
    assert_eq!(rows[1]["index"], 1);
    assert_eq!(rows[1]["status"], "not_found");
    assert_eq!(rows[2]["index"], 2);
    assert_eq!(rows[2]["status"], "ambiguous");
    assert_eq!(rows[2]["match_count"], 2);
    assert_eq!(rows[2]["matches"][0]["id"], DUPLICATE_A);
    assert_eq!(rows[2]["matches"][1]["id"], DUPLICATE_B);
    assert_eq!(rows[3]["index"], 3);
    assert_eq!(rows[3]["match"]["id"], ALPHA);
    assert_eq!(
        out["counts"],
        json!({"resolved":2,"not_found":1,"ambiguous":1})
    );
}

#[tokio::test]
async fn type_kind_and_exact_case_are_constraints_not_fuzzy_search() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create(
        &registry,
        &db,
        json!({"type":"Entity","kind":"person","name":"Case Sensitive"}),
    )
    .await;
    create(
        &registry,
        &db,
        json!({"type":"Document","kind":"note","name":"Case Sensitive"}),
    )
    .await;

    let out = call_as(
        &registry,
        &db,
        Caller::local(),
        "resolve_many",
        json!({"type":"Entity","kind":"person","names":["Case Sensitive","case sensitive"]}),
    )
    .await;
    assert_eq!(out["results"][0]["status"], "resolved");
    assert_eq!(out["results"][0]["match"]["type"], "Entity");
    assert_eq!(out["results"][1]["status"], "not_found");
}

#[tokio::test]
async fn hidden_matches_do_not_change_visible_ambiguity_or_disclose_cardinality() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create(
        &registry,
        &db,
        json!({"id":DUPLICATE_A,"type":"Entity","kind":"person","name":"Visible singleton"}),
    )
    .await;
    create(
        &registry,
        &db,
        json!({"id":HIDDEN_DUPLICATE,"type":"Entity","kind":"person","name":"Visible singleton"}),
    )
    .await;
    replace_explicit_policy(
        &db,
        "resolve-many:test",
        HIDDEN_DUPLICATE,
        vec![AllowEntry::account("acct:owner", Capability::Manage)],
    )
    .await
    .unwrap();

    let out = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:viewer"),
        "resolve_many",
        json!({"type":"Entity","kind":"person","names":["Visible singleton"]}),
    )
    .await;
    assert_eq!(out["results"][0]["status"], "resolved");
    assert_eq!(out["results"][0]["match"]["id"], DUPLICATE_A);
    assert!(out["results"][0].get("match_count").is_none());
}
